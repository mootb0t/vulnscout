"""Fact-driven task scheduler.

The scheduler subscribes to the FactStore. Whenever a new fact lands, it
walks the registered tasks and queues any whose `requires` matches that
fact's kind, gated by:

  - the policy's allow/deny rules
  - the task's optional `condition(store, policy)` predicate
  - the task's `multiplicity` (once / per_fact / per_key)

Queued tasks run in parallel up to `policy.max_parallel`. Each task gets
its own TaskCtx with the parent fact ids that triggered it — this is
how provenance flows through the graph.

The scan is "done" when the queue is drained and no task is running.
We give a short grace window before declaring done in case a late
emission queues another task.
"""

# The scheduler is the FactStore's primary subscriber; every other consumer
# (the TUI, synthesis tasks) sits downstream of the facts it reacts to.

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .events import (
    EventBus, ScanFinished, ScanStarted, Status, TaskFailed, TaskFinished,
    TaskSkipped, TaskStarted,
)
from .facts import Fact, ScanSettled, Target
from .policy import Policy
from .store import FactStore
from .tasks import Task, TaskCtx, all_tasks


@dataclass
class _RunRecord:
    """Internal accounting for a single task instance scheduled."""
    task: Task
    parents: Tuple[int, ...]
    trigger_id: Any
    ctx: Optional[TaskCtx] = None
    started_at: float = 0.0


class Scheduler:
    """Owns the run loop. One instance per scan.

    Lifecycle:
      sched = Scheduler(store, policy, bus, opsec)
      await sched.run(target=Target(...))
      # ... target fact emitted, scheduler queues tasks, runs them,
      # waits for the graph to drain, publishes ScanFinished.

    `run()` returns when:
      - the queue is empty and no tasks are running, OR
      - cancel() was called (returns the partial state).
    """

    def __init__(self, store: FactStore, policy: Policy, bus: EventBus, opsec: Any) -> None:
        self.store = store
        self.policy = policy
        self.bus = bus
        self.opsec = opsec

        # Tracks which (task_id, trigger_id) tuples have been scheduled,
        # so multiplicity rules don't double-fire.
        self._scheduled: Set[Tuple[str, Any]] = set()
        # Outstanding task coroutines.
        self._running: Set[asyncio.Task] = set()
        # Pending records waiting for a parallelism slot.
        self._pending: List[_RunRecord] = []
        self._sem: Optional[asyncio.Semaphore] = None
        # Ctx objects for each running task — exposed so cancel() can
        # SIGKILL their subprocesses immediately.
        # TaskCtx isn't hashable (it carries a mutable list), so use a
        # list — order doesn't matter; we only iterate for cancellation.
        self._ctxs: List[TaskCtx] = []

        self._cancel_event = asyncio.Event()
        self._unsub = None
        self._activity = asyncio.Event()    # set whenever something changes

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self, target: Target) -> None:
        """Kick off the scan with a Target seed fact and pump until done."""
        self._sem = asyncio.Semaphore(max(1, self.policy.max_parallel))

        # Subscribe BEFORE emitting the target so the seed fact triggers tasks.
        self._unsub = self.store.subscribe(self._on_new_fact)

        await self.bus.publish(ScanStarted(target=target.target))
        for w in self.policy.runtime_warnings:
            await self.bus.publish(Status(text=w, severity="warning"))

        start_ts = time.time()
        await self.store.emit(target)

        # Pump loop: keep running while there's work outstanding. We watch
        # the activity event so we wake up the moment a new fact lands.
        # When the queue drains and no tasks are running, we emit a
        # ScanSettled fact so synthesis tasks (intel summary, analysis)
        # can trigger with the full fact log available. If those queue
        # work, we loop again. Once a settled pass produces no new work,
        # we exit.
        settled_emitted = False
        while not self._cancel_event.is_set():
            await self._drain_pending()
            if not self._running and not self._pending:
                # Give late emitters a tiny window — a finishing task may
                # publish a fact via emit() right after its run returns.
                try:
                    await asyncio.wait_for(self._activity.wait(), timeout=0.25)
                except asyncio.TimeoutError:
                    pass
                else:
                    self._activity.clear()
                    continue

                if not settled_emitted:
                    settled_emitted = True
                    await self.store.emit(ScanSettled())
                    # Loop again so any tasks gated on scan.settled get a
                    # chance to be scheduled and to run.
                    continue
                break

            self._activity.clear()
            if self._running:
                # Wait for any task to finish or for activity (new fact).
                done, _ = await asyncio.wait(
                    [*self._running, asyncio.create_task(self._activity.wait())],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                # The activity-wait task may be in done; ignore it explicitly.
                for t in done:
                    if t in self._running:
                        self._running.discard(t)
                self._activity.clear()
                # If anything queued up after settled, allow another
                # settle-pass when the queue empties again.
                if self._pending:
                    settled_emitted = False

        if self._unsub:
            self._unsub()
            self._unsub = None

        # Tear down any still-pending coroutines (cancellation).
        for t in list(self._running):
            t.cancel()
        for c in list(self._ctxs):
            c.kill_running()

        await self.bus.publish(ScanFinished(
            duration_s=time.time() - start_ts,
            cancelled=self._cancel_event.is_set(),
        ))

    def cancel(self) -> None:
        """Signal cancellation. Running tasks observe via ctx.cancelled."""
        self._cancel_event.set()
        for c in list(self._ctxs):
            c.kill_running()
        self._activity.set()

    # ------------------------------------------------------------------
    # Fact subscription -> task scheduling
    # ------------------------------------------------------------------

    async def _on_new_fact(self, fact: Fact) -> None:
        """Called by FactStore on every emit. Queues matching tasks."""
        if self._cancel_event.is_set():
            return
        for task in all_tasks():
            if not task.matches_trigger(fact):
                continue
            if not self._policy_allows(task):
                continue

            tid = task.trigger_id(fact)
            key = (task.id, tid)
            if key in self._scheduled:
                continue

            # requires_all gate — every named kind must have at least one fact.
            if task.requires_all and not all(
                self.store.has(k) for k in task.requires_all
            ):
                continue

            # Custom condition (predicate against the whole store).
            if task.condition is not None:
                try:
                    if not task.condition(self.store, self.policy):
                        await self.bus.publish(TaskSkipped(
                            task=task.id, reason="condition false"
                        ))
                        # Don't mark scheduled — a future fact may flip it.
                        continue
                except Exception as e:
                    await self.bus.publish(TaskFailed(
                        task=task.id, error=f"condition error: {e}"
                    ))
                    continue

            self._scheduled.add(key)
            parents = (fact.id,) if fact.id else ()
            self._pending.append(_RunRecord(
                task=task, parents=parents, trigger_id=tid,
            ))
            self._activity.set()

    def _policy_allows(self, task: Task) -> bool:
        return self.policy.task_allowed(task.id, set(task.tags))

    # ------------------------------------------------------------------
    # Pending → running pump
    # ------------------------------------------------------------------

    async def _drain_pending(self) -> None:
        """Kick off any pending tasks that fit under the parallelism cap."""
        assert self._sem is not None
        while self._pending and self._sem._value > 0:
            rec = self._pending.pop(0)
            ctx = TaskCtx(
                task_id=rec.task.id,
                label=rec.task.label,
                store=self.store,
                policy=self.policy,
                bus=self.bus,
                opsec=self.opsec,
                parents=rec.parents,
                cancel_event=self._cancel_event,
            )
            rec.ctx = ctx
            self._ctxs.append(ctx)
            self._activity.set()
            self._running.add(asyncio.create_task(self._run_one(rec)))

    async def _run_one(self, rec: _RunRecord) -> None:
        """Run one task with semaphore + lifecycle events + timeout."""
        assert self._sem is not None
        ctx = rec.ctx
        if ctx is None:
            return

        await self._sem.acquire()
        if self._cancel_event.is_set():
            self._sem.release()
            self._drop_ctx(ctx)
            return

        rec.started_at = time.time()
        await self.bus.publish(TaskStarted(task=rec.task.id, label=rec.task.label))

        facts_before = len(self.store)
        timeout_s = self.policy.timeout_for(rec.task.id)

        try:
            await asyncio.wait_for(rec.task.run(ctx), timeout=timeout_s)
        except asyncio.TimeoutError:
            ctx.kill_running()
            await self.bus.publish(TaskFailed(
                task=rec.task.id, error=f"timeout after {timeout_s:.0f}s"
            ))
        except asyncio.CancelledError:
            ctx.kill_running()
            await self.bus.publish(TaskSkipped(
                task=rec.task.id, reason="cancelled"
            ))
        except Exception as e:
            ctx.kill_running()
            await self.bus.publish(TaskFailed(task=rec.task.id, error=str(e)))
        else:
            await self.bus.publish(TaskFinished(
                task=rec.task.id,
                duration_s=time.time() - rec.started_at,
                facts_emitted=len(self.store) - facts_before,
            ))
        finally:
            self._sem.release()
            self._drop_ctx(ctx)
            self._activity.set()

    def _drop_ctx(self, ctx: TaskCtx) -> None:
        """Remove a TaskCtx from the active list, idempotent."""
        try:
            self._ctxs.remove(ctx)
        except ValueError:
            pass
