"""Web vulnerability scanners: nuclei, nikto, sslscan.

These run once per HTTP endpoint (multiplicity per_key on URL). nuclei
also runs against ports to catch non-HTTP CVEs (ssh, rsync, ...) — its
templates are protocol-agnostic.
"""

from __future__ import annotations

import json
import re
from typing import List

from ..auth import inject_web_auth
from ..core.facts import CVEHit, Finding, HTTPLive, Port
from ..core.tasks import Task, TaskCtx, register
from ..tools.parser import derive_severity, parse_nuclei_jsonl
from ..tools.runner import INSECURE_TLS_ENV

from ._helpers import have, web_endpoint_key


# ---------------------------------------------------------------------------
# nuclei
# ---------------------------------------------------------------------------


async def _run_nuclei(ctx: TaskCtx) -> None:
    if not have("nuclei"):
        return
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    target = ""
    if isinstance(parent, HTTPLive):
        target = parent.url
    elif isinstance(parent, Port):
        if not parent.is_http:
            return        # non-HTTP ports — let other tasks handle them
        target = parent.url()
    if not target:
        return

    tags = ctx.policy.knob("nuclei", "tags", ["cve"]) or []
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-no-color"]
    if tags and tags != ["all"]:
        cmd += ["-tags", ",".join(tags)]
    cmd = inject_web_auth("nuclei", cmd, ctx.opsec)

    raw_lines: List[str] = []
    async for line in ctx.shell("nuclei", cmd, env_overrides=INSECURE_TLS_ENV):
        raw_lines.append(line)
        if line.strip():
            await ctx.output(line)

    blob = "\n".join(raw_lines)
    findings = parse_nuclei_jsonl(blob)
    for f in findings:
        info = f.get("info", {}) or {}
        sev = (info.get("severity") or "").upper() or derive_severity("nuclei", json.dumps(f))
        title = info.get("name") or f.get("template", "(unknown template)")
        matched = f.get("matched-at") or target
        cves = (info.get("classification") or {}).get("cve-id", []) or []
        if isinstance(cves, str):
            cves = [cves]
        await ctx.emit(Finding(
            severity=sev or "INFO",
            summary=f"{title} on {matched}",
            detail=info.get("description", "") or "",
            tool="nuclei",
            raw=json.dumps(f)[:2000],
        ))
        for cve in cves:
            await ctx.emit(CVEHit(cve=cve, on=title))


register(Task(
    id="nuclei",
    label="nuclei",
    run=_run_nuclei,
    # Trigger off both http.live (preferred) AND port.open on web ports —
    # if httpx fails or never confirmed liveness, we still scan based on
    # the bare port. Per-key dedup prevents double-runs against the same
    # endpoint when both facts arrive.
    requires={"http.live", "port.open"},
    produces={"finding", "cve"},
    tags={"web", "fuzzing"},
    multiplicity="per_key",
    trigger_key=lambda f: web_endpoint_key(f),
    condition=lambda store, policy: True,
))


# ---------------------------------------------------------------------------
# nikto
# ---------------------------------------------------------------------------


async def _run_nikto(ctx: TaskCtx) -> None:
    if not have("nikto"):
        return
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    url = ""
    if isinstance(parent, HTTPLive):
        url = parent.url
    elif isinstance(parent, Port) and parent.is_http:
        url = parent.url()
    if not url:
        return
    extra = list(ctx.policy.knob("nikto", "extra_args", []) or [])
    cmd = ["nikto", "-h", url, "-ask", "no", "-Display", "1234EP", *extra]
    cmd = inject_web_auth("nikto", cmd, ctx.opsec)
    buf: List[str] = []
    forms_seen = False
    async for line in ctx.shell("nikto", cmd, env_overrides=INSECURE_TLS_ENV):
        buf.append(line)
        await ctx.output(line)
        if not forms_seen and ("form" in line.lower() and "method" in line.lower()):
            from ..core.facts import FormsDetected
            await ctx.emit(FormsDetected(url=url))
            forms_seen = True
    blob = "\n".join(buf)
    if blob.strip():
        sev = derive_severity("nikto", blob)
        await ctx.emit(Finding(
            severity=sev,
            summary=f"nikto sweep of {url}",
            detail=blob[:1500],
            tool="nikto",
            raw=blob[:8000],
        ))


register(Task(
    id="nikto",
    label="nikto",
    run=_run_nikto,
    requires={"http.live", "port.open"},
    produces={"finding", "site.has_forms"},
    tags={"web", "loud"},
    multiplicity="per_key",
    trigger_key=lambda f: web_endpoint_key(f),
))


# ---------------------------------------------------------------------------
# sslscan
# ---------------------------------------------------------------------------


async def _run_sslscan(ctx: TaskCtx) -> None:
    if not have("sslscan"):
        return
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    if not isinstance(parent, Port) or not parent.is_https:
        return
    cmd = ["sslscan", f"{parent.host}:{parent.port}"]
    buf: List[str] = []
    async for line in ctx.shell("sslscan", cmd):
        buf.append(line)
        await ctx.output(line)
    blob = "\n".join(buf)
    if not blob.strip():
        return
    sev = derive_severity("sslscan", blob)
    await ctx.emit(Finding(
        severity=sev,
        summary=f"TLS audit on {parent.host}:{parent.port}",
        detail=blob[:1200],
        tool="sslscan",
        raw=blob[:6000],
    ))


register(Task(
    id="sslscan",
    label="sslscan",
    run=_run_sslscan,
    requires={"port.open"},
    produces={"finding"},
    tags={"web"},
    multiplicity="per_key",
    trigger_key=lambda f: f"{getattr(f, 'host', '')}:{getattr(f, 'port', 0)}",
    condition=lambda store, policy: True,   # fact-level filter is_https
))
