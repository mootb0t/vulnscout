"""Task descriptors and the registry.

A Task is one unit of work — a single tool invocation, an LLM call, a
deterministic synthesis pass. Each Task declares:

  - id          : unique string ("nmap", "nuclei", "wpscan", ...)
  - label       : short human-readable name for the TUI
  - tags        : tag set for policy filtering ("network", "web", "loud", ...)
  - requires    : fact kinds the task consumes; the scheduler waits for
                  at least one matching fact before queuing.
  - produces    : fact kinds the task may emit (informational; used by
                  the planner + the "why did this run?" trace).
  - condition   : optional predicate run against the FactStore + Policy
                  before scheduling. Returns False to skip.
  - run         : async callable doing the actual work. Receives a TaskCtx
                  with the store, policy, opsec, event bus, and a parents
                  tuple of fact ids that triggered scheduling.

Tasks register themselves at import time via @register. The plugins/
package's __init__.py imports every plugin module so the registry is
populated by the time the scheduler asks for it.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import (
    Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple,
)

from .events import (
    Event, EventBus, FactEmitted, TaskFailed, TaskFinished, TaskOutput,
    TaskProgress, TaskSkipped, TaskStarted,
)
from .facts import Fact
from .policy import Policy
from .store import FactStore


# ---------------------------------------------------------------------------
# Context passed into every task's run()
# ---------------------------------------------------------------------------


@dataclass
class TaskCtx:
    """Everything a task needs to do its work.

    The task should:
      - read facts via `ctx.store.by_kind(...)` / `.one(...)` / `.all_of(...)`
      - emit facts via `await ctx.emit(SomeFact(..., source=ctx.task_id, parents=ctx.parents))`
      - stream subprocess output via `ctx.shell(tool, cmd)` (yields lines)
      - watch for cancellation via `ctx.cancelled`
    """

    task_id: str
    label: str
    store: FactStore
    policy: Policy
    bus: EventBus
    opsec: Any                       # OpsecSettings — kept Any to avoid cycle
    parents: Tuple[int, ...]         # ids of facts that triggered scheduling
    cancel_event: asyncio.Event
    procs: List[asyncio.subprocess.Process] = field(default_factory=list)

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    async def emit(self, fact: Fact) -> Fact:
        """Stamp source + parents + push to the store, mirror to the bus."""
        if not fact.source:
            fact.source = self.task_id
        if not fact.parents:
            fact.parents = self.parents
        f = await self.store.emit(fact)
        await self.bus.publish(FactEmitted(fact=f))
        return f

    async def output(self, line: str) -> None:
        """Surface a tool-output line to the live feed (no fact emitted)."""
        await self.bus.publish(TaskOutput(task=self.task_id, text=line))

    async def progress(self, percent: float, etc: str = "") -> None:
        await self.bus.publish(
            TaskProgress(task=self.task_id, percent=percent, etc=etc)
        )

    async def shell(self, tool: str, cmd: List[str],
                    env_overrides: Optional[Dict[str, str]] = None):
        """Stream a subprocess. Async iterator over decoded stdout/stderr.

        Routes through opsec.apply_to_command + the random delay. Tracks
        the spawned process for cancellation.
        """
        # Local import — opsec lives at the top of the package and we want
        # core/ to stay free of package-level cycles when only used by tests.
        from ..opsec import apply_to_command, random_delay
        if self.cancelled:
            return
        await random_delay(self.opsec)
        if self.cancelled:
            return
        cmd = apply_to_command(tool, list(cmd), self.opsec)
        env = None
        if env_overrides:
            env = {**os.environ, **env_overrides}
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
        except FileNotFoundError:
            return
        self.procs.append(proc)
        try:
            assert proc.stdout is not None
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                yield line.decode(errors="replace").rstrip()
                if self.cancelled:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                    break
            await proc.wait()
        finally:
            if proc in self.procs:
                self.procs.remove(proc)

    def kill_running(self) -> None:
        for p in list(self.procs):
            if p.returncode is None:
                try:
                    p.kill()
                except ProcessLookupError:
                    pass


# ---------------------------------------------------------------------------
# Task descriptor
# ---------------------------------------------------------------------------


RunFn = Callable[[TaskCtx], Awaitable[None]]
ConditionFn = Callable[[FactStore, Policy], bool]
TriggerKeyFn = Callable[[Fact], Any]


@dataclass
class Task:
    """A registered task. Created via @register; mostly read-only afterwards."""

    id: str
    label: str
    run: RunFn
    requires: Set[str] = field(default_factory=set)
    produces: Set[str] = field(default_factory=set)
    tags: Set[str] = field(default_factory=set)
    condition: Optional[ConditionFn] = None

    # Multiplicity control:
    # - "once"        : run once per scan (default). The first matching fact
    #                   triggers scheduling; later facts are ignored.
    # - "per_fact"    : run once per matching fact. Used for per-port web
    #                   scans where each new HTTP endpoint is its own job.
    # - "per_key"     : run once per unique key derived from the trigger
    #                   fact via `trigger_key(fact)`. Used for "per host"
    #                   semantics where multiple ports on one host should
    #                   coalesce into a single run.
    multiplicity: str = "once"
    trigger_key: Optional[TriggerKeyFn] = None

    # Optional: only schedule if every kind in `requires_all` has *some*
    # fact. Useful for tasks that need both a port and a target — without
    # this, the task could schedule the moment the target fact arrives.
    requires_all: Set[str] = field(default_factory=set)

    def matches_trigger(self, fact: Fact) -> bool:
        return fact.kind in self.requires

    def trigger_id(self, fact: Fact) -> Any:
        """Return a stable hashable id for multiplicity tracking."""
        if self.multiplicity == "once":
            return None
        if self.multiplicity == "per_key" and self.trigger_key is not None:
            return self.trigger_key(fact)
        return fact.id


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


_REGISTRY: Dict[str, Task] = {}


def register(task: Task) -> Task:
    """Add a task to the global registry. Used as a decorator-like call:

        register(Task(id="nmap", label="nmap port scan", run=_run_nmap, ...))

    Re-registering an id replaces the previous definition (handy for
    tests / reloads).
    """
    _REGISTRY[task.id] = task
    return task


def all_tasks() -> List[Task]:
    return list(_REGISTRY.values())


def get_task(task_id: str) -> Optional[Task]:
    return _REGISTRY.get(task_id)


def clear_registry() -> None:
    """Reset the registry — used by tests."""
    _REGISTRY.clear()
