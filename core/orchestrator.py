"""High-level scan driver — what the TUI actually calls.

Wires together: FactStore + EventBus + Scheduler + plugin imports.
Returns a handle the TUI can use to subscribe / cancel.

  orch = Orchestrator(opsec_settings, policy)
  await orch.run("example.com", target_type="domain")
  # ... later ...
  orch.cancel()
"""

from __future__ import annotations

import asyncio
from typing import Optional

from .events import EventBus
from .facts import Target
from .policy import POLICIES, Policy, get_policy
from .scheduler import Scheduler
from .store import FactStore


class Orchestrator:
    """One per scan. Re-instantiate to start over with a clean slate."""

    def __init__(self, opsec, policy_key: str = "quick", *,
                 hunter_api_key: str = "", model: str = "gemma3:3b") -> None:
        # Plugin imports happen here so a fresh process picks up any new
        # tasks without requiring a manual call. Importing plugins more
        # than once is fine — the registry overwrites prior ids.
        from .. import plugins  # noqa: F401  (registers tasks)

        self.policy = get_policy(policy_key)
        # Fold ergonomic knobs from settings into the policy.
        self.policy.knobs.setdefault("hunter", {})["api_key"] = hunter_api_key
        self.policy.knobs.setdefault("llm", {})["model"] = model

        self.opsec = opsec
        self.store = FactStore()
        self.bus = EventBus()
        self.scheduler = Scheduler(self.store, self.policy, self.bus, self.opsec)
        self._task: Optional[asyncio.Task] = None

    async def run(self, target: str, target_type: str = "domain",
                   domain: str = "") -> None:
        """Kick off the scan. Returns when the task graph drains.

        `target_type` is one of: "ip" / "cidr" / "domain" / "url".
        `domain` is the bare hostname (used for URL targets); when empty
        we derive it from the target string.
        """
        if not domain:
            domain = self._extract_domain(target, target_type)
        seed = Target(target=target, target_type=target_type, domain=domain)
        await self.scheduler.run(seed)

    def cancel(self) -> None:
        self.scheduler.cancel()

    @staticmethod
    def _extract_domain(target: str, target_type: str) -> str:
        if target_type == "url":
            from urllib.parse import urlparse
            host = urlparse(target).netloc.split(":")[0]
            return host
        return target
