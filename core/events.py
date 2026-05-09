"""Event bus the TUI subscribes to.

Tasks emit Facts (which live in the FactStore); the scheduler emits
*lifecycle* events (TaskStarted / TaskOutput / TaskFinished / etc.).
The TUI cares about both. This module gives them a single bus so the
TUI doesn't poll and the scheduler doesn't know what a screen is.

Why not just subscribe everyone to FactStore? Because tool *output*
lines (the live scrollback in the TUI) aren't facts — they're transient
chatter. And task lifecycle (started / cancelled / failed) isn't a
fact either. The bus carries those alongside fact-emit events so the
TUI gets one monotonic stream.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, List, Optional

from .facts import Fact


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------


@dataclass
class Event:
    """Base — every event has a kind for switch/dispatch in the TUI."""
    kind: str = ""


@dataclass
class TaskStarted(Event):
    kind: str = "task.started"
    task: str = ""
    label: str = ""             # human-readable label
    cmd: List[str] = field(default_factory=list)


@dataclass
class TaskOutput(Event):
    """A line of streaming output from a running task."""
    kind: str = "task.output"
    task: str = ""
    text: str = ""


@dataclass
class TaskProgress(Event):
    """nmap-style progress hint — drives the progress bar in the TUI."""
    kind: str = "task.progress"
    task: str = ""
    percent: float = 0.0
    etc: str = ""


@dataclass
class TaskFinished(Event):
    kind: str = "task.finished"
    task: str = ""
    duration_s: float = 0.0
    facts_emitted: int = 0


@dataclass
class TaskSkipped(Event):
    """Task didn't run because its condition() returned False or the
    binary was missing or the policy excluded it."""
    kind: str = "task.skipped"
    task: str = ""
    reason: str = ""


@dataclass
class TaskFailed(Event):
    kind: str = "task.failed"
    task: str = ""
    error: str = ""


@dataclass
class FactEmitted(Event):
    """Mirror of FactStore.emit(). Lets the TUI maintain a live findings
    panel without subscribing to the store directly."""
    kind: str = "fact.emitted"
    fact: Optional[Fact] = None


@dataclass
class Status(Event):
    """High-level milestone — 'starting scan', 'all done', warnings, ...'"""
    kind: str = "status"
    text: str = ""
    severity: str = "info"      # info | warning | error


@dataclass
class ScanStarted(Event):
    kind: str = "scan.started"
    target: str = ""


@dataclass
class ScanFinished(Event):
    kind: str = "scan.finished"
    duration_s: float = 0.0
    cancelled: bool = False


# ---------------------------------------------------------------------------
# Bus
# ---------------------------------------------------------------------------


Subscriber = Callable[[Event], Awaitable[None]]


class EventBus:
    """Tiny pub/sub. Subscribers are coroutines.

    Order of delivery matches order of publish. We invoke subscribers
    sequentially so the TUI can rely on monotonic ordering when
    rendering the live feed.
    """

    def __init__(self) -> None:
        self._subs: List[Subscriber] = []
        self._lock = asyncio.Lock()

    def subscribe(self, fn: Subscriber) -> Callable[[], None]:
        self._subs.append(fn)
        def _unsub() -> None:
            try:
                self._subs.remove(fn)
            except ValueError:
                pass
        return _unsub

    async def publish(self, ev: Event) -> None:
        # Snapshot under the lock so subscribe/unsubscribe during dispatch
        # is safe — we deliver to whoever was subscribed at publish time.
        async with self._lock:
            subs = list(self._subs)
        for fn in subs:
            try:
                await fn(ev)
            except Exception:
                # Swallow subscriber errors — a broken TUI handler must
                # not break the scan.
                pass
