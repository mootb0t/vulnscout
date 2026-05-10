"""CVE / exploit cross-reference passes.

  - searchsploit : queries local exploit-db for product+version strings
                   harvested from Port and Tech facts
  - msf_xref     : looks up confirmed CVEs against `msfconsole -q -x`
                   to surface ready-to-go modules (suggestions only —
                   never auto-runs anything)
"""

from __future__ import annotations

import asyncio
import re
from typing import List, Set

from ..core.facts import (
    CVEHit, Finding, MSFModule, Port, SearchsploitHit, Tech, VersionString,
)
from ..core.tasks import Task, TaskCtx, register
from ..tools.parser import parse_searchsploit_table

from ._helpers import have


# ---------------------------------------------------------------------------
# searchsploit
# ---------------------------------------------------------------------------


_CVE_IN_TITLE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# Tech-name-only queries against these terms produce thousands of
# irrelevant hits (every Linux exploit, every Apache module ever) — skip
# them unless we also have a version string to narrow the search.
_GENERIC_TECH = {
    "linux", "ubuntu", "debian", "centos", "redhat", "windows",
    "unix", "freebsd", "openbsd", "macos", "darwin",
    "apache", "nginx", "iis",        # too broad without version
    "ok", "yes", "no", "true", "false",
    "http", "https", "tcp", "udp",
    "x", "y", "n",
}


def _is_useful_tech_query(name: str, version: str) -> bool:
    """A bare Tech name without a version should not be searchsploit-queried
    if it's a generic OS/server label. With a version, it's specific enough
    (e.g. `Apache 2.4.49` is a valid query)."""
    if version:
        return True
    n = name.strip().lower()
    if len(n) < 4:
        return False
    return n not in _GENERIC_TECH


def _searchsploit_queries(store) -> List[str]:
    """Build a deduplicated list of fingerprint strings worth querying.

    Each entry is one searchsploit -t invocation. We dedupe to avoid
    burning seconds repeating identical queries when a host has many
    ports running the same banner.
    """
    seen: Set[str] = set()
    out: List[str] = []
    for p in store.by_kind("port.open"):
        if not isinstance(p, Port):
            continue
        if p.product:
            q = (p.product + (f" {p.version}" if p.version else "")).strip()
            if q.lower() not in seen:
                seen.add(q.lower())
                out.append(q)
    for t in store.by_kind("tech"):
        if not isinstance(t, Tech):
            continue
        if not t.name or not _is_useful_tech_query(t.name, t.version):
            continue
        q = f"{t.name} {t.version}".strip()
        if q.lower() in seen:
            continue
        seen.add(q.lower())
        out.append(q)
    for v in store.by_kind("loot.version"):
        if not isinstance(v, VersionString):
            continue
        q = v.text.strip()
        if q and q.lower() not in seen:
            seen.add(q.lower())
            out.append(q)
    return out


async def _run_searchsploit(ctx: TaskCtx) -> None:
    if not have("searchsploit"):
        return
    queries = _searchsploit_queries(ctx.store)
    if not queries:
        return
    for q in queries:
        cmd = ["searchsploit", "-t", q]
        buf: List[str] = []
        async for line in ctx.shell("searchsploit", cmd):
            buf.append(line)
        rows = parse_searchsploit_table("\n".join(buf))
        if not rows:
            continue
        await ctx.output(f"searchsploit: {len(rows)} hit(s) for '{q}'")
        # If a query returned a flood of hits, treat it as too generic —
        # the result list is dominated by unrelated exploits (e.g. all
        # "Linux" exploits). Don't emit individual hits or a finding.
        too_broad = len(rows) > 200
        if too_broad:
            await ctx.output(
                f"searchsploit: '{q}' is too generic ({len(rows)} hits) — skipping"
            )
            continue
        for r in rows[:30]:
            cves = _CVE_IN_TITLE.findall(r["title"]) or []
            await ctx.emit(SearchsploitHit(
                title=r["title"],
                edb_id=r.get("edb_id") or "",
                url=r.get("url") or "",
                query=q,
                cves=cves,
            ))
            for cve in cves:
                await ctx.emit(CVEHit(cve=cve, on=q))
        if rows:
            sev = "MEDIUM" if len(rows) <= 50 else "LOW"
            await ctx.emit(Finding(
                severity=sev,
                summary=f"searchsploit: {len(rows)} potential exploit(s) for '{q}'",
                detail="\n".join(
                    f"- {r['title']}" + (f" ({r['url']})" if r.get('url') else "")
                    for r in rows[:20]
                ) + (f"\n… and {len(rows) - 20} more" if len(rows) > 20 else ""),
                tool="searchsploit",
            ))


register(Task(
    id="searchsploit",
    label="searchsploit cross-ref",
    run=_run_searchsploit,
    # Trigger on scan.settled (not the raw fact kinds) so every fingerprint
    # source has already emitted: nmap product/version banners, whatweb tech
    # facts, AND version strings lifted from leaked files. Triggering on the
    # first port.open used to fire before whatweb ran, silently skipping all
    # tech-derived exploit queries.
    requires={"scan.settled"},
    produces={"searchsploit", "cve", "finding"},
    tags={"core"},
    multiplicity="once",
    condition=lambda store, policy: bool(_searchsploit_queries(store)),
))


# ---------------------------------------------------------------------------
# Metasploit cross-reference (suggestions only)
# ---------------------------------------------------------------------------


async def _run_msf_xref(ctx: TaskCtx) -> None:
    if not have("msfconsole"):
        return
    cves = sorted({c.cve for c in ctx.store.all_of(CVEHit) if c.cve})
    if not cves:
        return
    # Build one msfconsole command that searches all CVEs in a single
    # invocation — startup is the slow part.
    search_cmds = "; ".join(f"search cve:{cve}" for cve in cves[:30])
    cmd = ["msfconsole", "-q", "-x", f"{search_cmds}; exit"]
    current_cve = ""
    seen: Set[str] = set()
    async for line in ctx.shell("msfconsole", cmd):
        await ctx.output(line)
        # Each `search` block is preceded by msf6 prompts — track which CVE
        # the current results belong to by watching for the matching line.
        m = re.search(r"search cve:(CVE-\d{4}-\d{4,7})", line, re.IGNORECASE)
        if m:
            current_cve = m.group(1).upper()
            continue
        # Module rows typically start with a number then category/path:
        #   1   exploit/multi/http/struts2_content_type_ognl
        m = re.match(r"\s*\d+\s+([a-z]+/\S+)", line)
        if m and current_cve:
            mod = m.group(1)
            if mod in seen:
                continue
            seen.add(mod)
            await ctx.emit(MSFModule(cve=current_cve, module=mod))


register(Task(
    id="msf_xref",
    label="metasploit cross-ref",
    run=_run_msf_xref,
    requires={"cve"},
    produces={"msf"},
    tags={"core"},
    multiplicity="once",
))
