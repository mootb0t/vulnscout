"""Append-only fact store with kind-indexed queries and subscriptions.

Every Fact emitted during a scan lands here. Tasks consume the store
through .by_kind() / .one() / .all_of(); the scheduler consumes it
through .subscribe() so it can wake up tasks when new facts of the
required kinds arrive.

Thread-safety: a single asyncio.Lock guards both writes and the
subscriber list. All public methods are coroutine-safe.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import (
    Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Type, TypeVar,
)

from .facts import Fact, FactStoreLike


T = TypeVar("T", bound=Fact)


SubscriberFn = Callable[[Fact], Awaitable[None]]


class FactStore(FactStoreLike):
    """Single source of truth for everything learned during a scan.

    Internal layout:
      - `_log`     : list of facts in emit order (canonical for replay/report)
      - `_by_kind` : dict[str, list[Fact]] — fast kind-scoped queries
      - `_by_id`   : dict[int, Fact]       — provenance lookups

    Subscribers are coroutines invoked on every new fact. The scheduler
    is the primary subscriber; the TUI wires its own indirectly via the
    EventBus.
    """

    def __init__(self) -> None:
        self._log: List[Fact] = []
        self._by_kind: Dict[str, List[Fact]] = defaultdict(list)
        self._by_id: Dict[int, Fact] = {}
        self._lock = asyncio.Lock()
        self._subs: List[SubscriberFn] = []

    # -- Writes -----------------------------------------------------------

    async def emit(self, fact: Fact) -> Fact:
        """Append a fact to the store and notify subscribers.

        Returns the same fact (id already populated by Fact's default
        factory), so callers can chain: `f = await store.emit(Port(...))`.
        """
        async with self._lock:
            self._log.append(fact)
            self._by_kind[fact.kind].append(fact)
            self._by_id[fact.id] = fact
            subs = list(self._subs)
        # Fire subscribers outside the lock so a slow subscriber can't
        # block emit. Subscribers are awaited sequentially to preserve
        # event ordering — they're cheap (mostly enqueueing).
        for fn in subs:
            try:
                await fn(fact)
            except Exception:
                # A misbehaving subscriber must not break the scan. The
                # scheduler logs its own errors via the event bus.
                pass
        return fact

    async def emit_many(self, facts: Iterable[Fact]) -> List[Fact]:
        out = []
        for f in facts:
            out.append(await self.emit(f))
        return out

    # -- Reads ------------------------------------------------------------

    def by_id(self, fact_id: int) -> Optional[Fact]:
        return self._by_id.get(fact_id)

    def by_kind(self, kind: str) -> List[Fact]:
        """Return a *copy* of the per-kind list — callers can iterate
        without worrying about concurrent mutation."""
        return list(self._by_kind.get(kind, ()))

    def all_of(self, cls: Type[T]) -> List[T]:
        """Return all facts whose runtime class matches `cls` (or a
        subclass). Convenience for typed iteration."""
        return [f for f in self._log if isinstance(f, cls)]

    def one(self, kind: str) -> Optional[Fact]:
        """Return the most recent fact of `kind`, or None."""
        bucket = self._by_kind.get(kind)
        return bucket[-1] if bucket else None

    def has(self, kind: str) -> bool:
        return bool(self._by_kind.get(kind))

    def kinds(self) -> Set[str]:
        return set(self._by_kind.keys())

    def log(self) -> List[Fact]:
        """Append-order log. Caller-immutable copy."""
        return list(self._log)

    def __len__(self) -> int:
        return len(self._log)

    # -- Subscriptions ----------------------------------------------------

    def subscribe(self, fn: SubscriberFn) -> Callable[[], None]:
        """Register a coroutine to be invoked on every new fact.

        Returns an unsubscribe callable. The scheduler subscribes once
        per run; tests can subscribe ad-hoc.
        """
        self._subs.append(fn)
        def _unsub() -> None:
            try:
                self._subs.remove(fn)
            except ValueError:
                pass
        return _unsub

    # -- Convenience views used by report.py + TUI -----------------------

    def findings(self) -> List[Fact]:
        """All Finding facts, sorted by severity then emission time."""
        from .facts import Finding, SEVERITY_RANK
        out = self.all_of(Finding)
        out.sort(key=lambda f: (SEVERITY_RANK.get(f.severity.upper(), 4), f.id))
        return out

    def loot_summary(self) -> Dict[str, List[Any]]:
        """Aggregate every loot.* fact into the structure report.py wants."""
        from .facts import (
            ConfirmedCred, DiscoveredHash, DiscoveredCredential,
            DiscoveredUsername, Email, DiscoveredHost, VersionString,
            FurtherPath, GitExposed,
        )
        return {
            "confirmed_creds":  self.all_of(ConfirmedCred),
            "hashes":           self.all_of(DiscoveredHash),
            "credentials":      self.all_of(DiscoveredCredential),
            "usernames":        self.all_of(DiscoveredUsername),
            "emails":           self.all_of(Email),
            "hosts":            self.all_of(DiscoveredHost),
            "versions":         self.all_of(VersionString),
            "paths":            self.all_of(FurtherPath),
            "git":              self.all_of(GitExposed),
        }
