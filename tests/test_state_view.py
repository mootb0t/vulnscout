"""Engagement → FactStore echo bridge (keeps the report complete)."""

import asyncio
import unittest

from vulnscout.core.facts import ConfirmedCred, Finding
from vulnscout.core.state_view import echo_state_change, snapshot_state
from vulnscout.core.store import FactStore
from vulnscout.llm import Finding as LegacyFinding
from vulnscout.tools.runner import ScanState


def _run(coro):
    return asyncio.run(coro)


def _state():
    return ScanState(target="10.0.0.5", target_type="ip", profile_key="quick")


class EchoStateChangeTest(unittest.TestCase):
    def test_engagement_findings_become_facts(self):
        """Regression: engagement findings used to never reach the report."""
        store, state = FactStore(), _state()
        prev = snapshot_state(state)
        state.findings_phase4.append(LegacyFinding(
            severity="high", summary="popped a shell via sudo find",
            tool="engagement", detail="d", raw="r"))
        _run(echo_state_change(store, state, prev))
        findings = store.all_of(Finding)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].summary, "popped a shell via sudo find")
        self.assertEqual(findings[0].source, "engagement")

    def test_confirmed_creds_echoed(self):
        store, state = FactStore(), _state()
        prev = snapshot_state(state)
        state.confirmed_creds.append(("bob", "hunter2", "ssh"))
        _run(echo_state_change(store, state, prev))
        creds = store.all_of(ConfirmedCred)
        self.assertEqual(len(creds), 1)
        self.assertEqual(
            (creds[0].user, creds[0].password, creds[0].service),
            ("bob", "hunter2", "ssh"))

    def test_unchanged_state_emits_nothing(self):
        store, state = FactStore(), _state()
        state.findings_phase4.append(LegacyFinding(severity="low", summary="x"))
        snap = snapshot_state(state)            # snapshot already has the finding
        _run(echo_state_change(store, state, snap))
        self.assertEqual(len(store.all_of(Finding)), 0)


if __name__ == "__main__":
    unittest.main()
