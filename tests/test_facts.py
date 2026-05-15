"""FactStore + Fact dataclass behaviour."""

import asyncio
import unittest

from vulnscout.core.facts import Finding, Port, WordPressDetected
from vulnscout.core.store import FactStore


def _run(coro):
    return asyncio.run(coro)


class FactsTest(unittest.TestCase):
    def test_wordpressdetected_uses_on_url(self):
        """Regression: field was `url`; whatweb/wpscan use `on_url`."""
        w = WordPressDetected(on_url="http://x")
        self.assertEqual(w.on_url, "http://x")
        self.assertEqual(w.kind, "site.is_wordpress")

    def test_finding_rank_orders_by_severity(self):
        self.assertLess(
            Finding(severity="CRITICAL", summary="a").rank,
            Finding(severity="INFO", summary="b").rank,
        )

    def test_store_emit_index_and_findings_sorted(self):
        store = FactStore()

        async def go():
            await store.emit(Port(host="h", port=22, service="ssh"))
            await store.emit(Finding(severity="HIGH", summary="x", tool="t"))
            await store.emit(Finding(severity="CRITICAL", summary="y", tool="t"))

        _run(go())
        self.assertEqual(len(store.by_kind("port.open")), 1)
        self.assertTrue(store.has("finding"))
        findings = store.findings()
        self.assertEqual(findings[0].severity, "CRITICAL")  # severity-sorted
        self.assertEqual(findings[-1].severity, "HIGH")

    def test_provenance_trace(self):
        store = FactStore()

        async def go():
            t = await store.emit(Port(host="h", port=80, source="nmap"))
            child = await store.emit(
                Finding(severity="LOW", summary="z", parents=(t.id,)))
            return child

        child = _run(go())
        trace = child.trace(store)
        self.assertEqual([f.kind for f in trace], ["port.open"])

    def test_subscriber_exception_does_not_break_emit(self):
        store = FactStore()

        async def bad_sub(_f):
            raise RuntimeError("boom")

        store.subscribe(bad_sub)

        async def go():
            await store.emit(Port(host="h", port=1))

        _run(go())  # must not raise
        self.assertEqual(len(store), 1)


if __name__ == "__main__":
    unittest.main()
