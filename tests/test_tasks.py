"""Task-registry contract tests.

These guard the two classes of bug that shipped silently before:

  1. A per_key task whose ``trigger_key`` lambda referenced a name the
     module never imported — file_discovery used ``web_endpoint_key``
     without importing it, so the scheduler hit ``NameError`` the moment a
     ``port.open`` / ``http.live`` fact arrived and the task never ran.

  2. A fact constructed with a kwarg that isn't a field of its dataclass —
     ``WordPressDetected(on_url=...)`` while the field was ``url`` → the
     emit raised ``TypeError`` whenever WordPress was detected.

Both are invisible to a plain import and only blow up mid-scan, so we
assert the contract directly.
"""

import dataclasses
import glob
import os
import re
import unittest

from vulnscout import plugins  # noqa: F401  (import registers every task)
from vulnscout.core import facts as F
from vulnscout.core.facts import (
    CVEHit, FormsDetected, HTTPLive, HostUp, IPAddress, IntelSummary, Port,
    ScanSettled, Subdomain, Target, Tech, VersionString, WordPressDetected,
)
from vulnscout.core.tasks import all_tasks

_VULNSCOUT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# One representative fact per kind that any task triggers on.
_SAMPLE_FACTS = [
    Target(target="example.com", target_type="domain", domain="example.com"),
    HostUp(host="10.0.0.5"),
    IPAddress(address="10.0.0.5"),
    Port(host="10.0.0.5", port=80, service="http"),
    HTTPLive(url="http://10.0.0.5:80", status=200),
    Tech(name="nginx", version="1.18.0", on_url="http://10.0.0.5"),
    VersionString(text="OpenSSH 8.2", source_file="leak.env"),
    FormsDetected(url="http://10.0.0.5/login?next=1"),
    WordPressDetected(on_url="http://10.0.0.5"),
    CVEHit(cve="CVE-2021-41773"),
    Subdomain(name="dev.example.com"),
    ScanSettled(),
    IntelSummary(text="summary"),
]


def _call_kwargs(src: str, open_paren_idx: int) -> set:
    """Return the top-level kwarg names of a call whose '(' is at the index."""
    depth, i, buf = 1, open_paren_idx, []
    while i < len(src) and depth:
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if depth:
            buf.append(c)
        i += 1
    call = "".join(buf)
    kwargs, d, cur = set(), 0, ""
    for c in call + ",":
        if c in "([{":
            d += 1
        elif c in ")]}":
            d -= 1
        if c == "," and d == 0:
            m = re.match(r"\s*([A-Za-z_]\w*)\s*=", cur)
            if m:
                kwargs.add(m.group(1))
            cur = ""
        else:
            cur += c
    return kwargs


class TaskContractTest(unittest.TestCase):
    def test_expected_tasks_registered(self):
        ids = {t.id for t in all_tasks()}
        self.assertGreaterEqual(len(ids), 30)
        for must in ("nmap", "httpx", "nuclei", "searchsploit",
                     "file_discovery", "whatweb", "wpscan", "analysis"):
            self.assertIn(must, ids)

    def test_requires_and_produces_are_string_sets(self):
        for t in all_tasks():
            self.assertIsInstance(t.requires, set, t.id)
            self.assertIsInstance(t.produces, set, t.id)
            for kind in t.requires | t.produces:
                self.assertIsInstance(kind, str, f"{t.id}: non-str kind {kind!r}")

    def test_trigger_id_never_raises(self):
        """Regression: file_discovery's trigger_key called an un-imported name."""
        for t in all_tasks():
            for fact in _SAMPLE_FACTS:
                if t.matches_trigger(fact):
                    try:
                        t.trigger_id(fact)
                    except Exception as e:  # noqa: BLE001
                        self.fail(f"{t.id}.trigger_id({fact.kind}) raised {e!r}")

    def test_per_key_tasks_define_trigger_key(self):
        for t in all_tasks():
            if t.multiplicity == "per_key":
                self.assertIsNotNone(
                    t.trigger_key, f"{t.id} is per_key but has no trigger_key")

    def test_fact_constructor_kwargs_are_valid_fields(self):
        """Regression: WordPressDetected(on_url=...) when the field was `url`.

        Statically scans every fact construction in plugins/ + state_view.py
        and asserts each keyword argument is a real dataclass field.
        """
        classes = {
            name: {fld.name for fld in dataclasses.fields(obj)}
            for name, obj in vars(F).items()
            if isinstance(obj, type) and dataclasses.is_dataclass(obj)
            and issubclass(obj, F.Fact)
        }
        targets = sorted(glob.glob(os.path.join(_VULNSCOUT_DIR, "plugins", "*.py")))
        targets.append(os.path.join(_VULNSCOUT_DIR, "core", "state_view.py"))
        bad = []
        for path in targets:
            with open(path) as fh:
                src = fh.read()
            for cls, fields in classes.items():
                for m in re.finditer(rf"\b{cls}\(", src):
                    for kw in _call_kwargs(src, m.end()) - fields:
                        bad.append(f"{os.path.basename(path)}: {cls}({kw}=...)")
        self.assertEqual(bad, [], "fact kwargs not in dataclass fields: " + "; ".join(bad))


if __name__ == "__main__":
    unittest.main()
