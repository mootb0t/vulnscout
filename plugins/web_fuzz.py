"""Directory / parameter fuzzers + tech-conditional scanners.

  - ffuf      : primary directory fuzzer (preferred over gobuster)
  - gobuster  : fallback when ffuf missing
  - sqlmap    : runs when forms detected OR target is a URL
  - wpscan    : runs only when WordPress detected
"""

from __future__ import annotations

import os
from typing import List, Optional

from ..auth import inject_web_auth
from ..core.facts import (
    Finding, FormsDetected, HTTPLive, Port, WordPressDetected,
)
from ..core.tasks import Task, TaskCtx, register
from ..tools.parser import derive_severity
from ..tools.runner import INSECURE_TLS_ENV

from ._helpers import have, web_endpoint_key


# ---------------------------------------------------------------------------
# Wordlist resolution (centralised so adding a tier is one edit)
# ---------------------------------------------------------------------------

_WORDLIST_BY_TIER = {
    "common": [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/opt/homebrew/share/wordlists/dirb/common.txt",
    ],
    "medium": [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/opt/homebrew/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
    "big": [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
        "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "/opt/homebrew/share/wordlists/dirbuster/directory-list-2.3-big.txt",
    ],
}


def _resolve_wordlist(policy, override: str = "") -> Optional[str]:
    if override:
        return override if os.path.exists(override) else None
    tier = policy.knob("_default", "wordlist_tier", "common")
    for c in _WORDLIST_BY_TIER.get(tier, []):
        if os.path.exists(c):
            return c
    return None


# ---------------------------------------------------------------------------
# ffuf
# ---------------------------------------------------------------------------


async def _run_ffuf(ctx: TaskCtx) -> None:
    if not have("ffuf"):
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
    wl = _resolve_wordlist(ctx.policy)
    if not wl:
        await ctx.output("ffuf: no wordlist installed under common paths — skipping")
        return
    cmd = [
        "ffuf", "-u", url + "/FUZZ", "-w", wl,
        "-mc", "200,204,301,302,307,401,403", "-of", "csv",
    ]
    cmd = inject_web_auth("ffuf", cmd, ctx.opsec)
    interesting: List[str] = []
    async for line in ctx.shell("ffuf", cmd, env_overrides=INSECURE_TLS_ENV):
        await ctx.output(line)
        if "/" in line and "200" in line:
            interesting.append(line.strip())
    if interesting:
        sev = "INFO"
        for path in interesting:
            low = path.lower()
            if any(k in low for k in (".git", ".env", ".svn", "backup", "config")):
                sev = "HIGH"
                break
        await ctx.emit(Finding(
            severity=sev,
            summary=f"ffuf discovered {len(interesting)} response(s) on {url}",
            detail="\n".join(interesting[:30]),
            tool="ffuf",
            raw="\n".join(interesting)[:6000],
        ))


register(Task(
    id="ffuf",
    label="ffuf directory fuzz",
    run=_run_ffuf,
    requires={"http.live", "port.open"},
    produces={"finding"},
    tags={"web", "fuzzing", "loud"},
    multiplicity="per_key",
    trigger_key=lambda f: web_endpoint_key(f),
))


# ---------------------------------------------------------------------------
# gobuster (fallback when ffuf missing)
# ---------------------------------------------------------------------------


async def _run_gobuster(ctx: TaskCtx) -> None:
    if have("ffuf") or not have("gobuster"):
        # ffuf wins; only run gobuster as fallback.
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
    wl = _resolve_wordlist(ctx.policy)
    if not wl:
        return
    cmd = ["gobuster", "dir", "-u", url, "-w", wl, "-q", "-k"]
    cmd = inject_web_auth("gobuster", cmd, ctx.opsec)
    buf: List[str] = []
    async for line in ctx.shell("gobuster", cmd, env_overrides=INSECURE_TLS_ENV):
        buf.append(line)
        await ctx.output(line)
    blob = "\n".join(buf)
    if blob.strip():
        sev = derive_severity("gobuster", blob)
        await ctx.emit(Finding(
            severity=sev,
            summary=f"gobuster on {url}",
            detail=blob[:1500],
            tool="gobuster",
            raw=blob[:6000],
        ))


register(Task(
    id="gobuster",
    label="gobuster fallback",
    run=_run_gobuster,
    requires={"http.live", "port.open"},
    produces={"finding"},
    tags={"web", "fuzzing", "loud"},
    multiplicity="per_key",
    trigger_key=lambda f: web_endpoint_key(f),
))


# ---------------------------------------------------------------------------
# sqlmap — fires when forms confirmed or target is a URL with params
# ---------------------------------------------------------------------------


async def _run_sqlmap(ctx: TaskCtx) -> None:
    if not have("sqlmap"):
        return
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    url = ""
    if isinstance(parent, FormsDetected):
        url = parent.url
    elif isinstance(parent, HTTPLive):
        # Only auto-fire on full-URL targets (with query-string params).
        if "?" not in parent.url:
            return
        url = parent.url
    if not url:
        return
    cmd = [
        "sqlmap", "-u", url, "--batch", "--level=1", "--risk=1",
        "--passwords", "false",   # never extract creds in scanning mode
    ]
    cmd = inject_web_auth("sqlmap", cmd, ctx.opsec)
    buf: List[str] = []
    async for line in ctx.shell("sqlmap", cmd, env_overrides=INSECURE_TLS_ENV):
        buf.append(line)
        await ctx.output(line)
    blob = "\n".join(buf)
    if blob.strip():
        sev = derive_severity("sqlmap", blob)
        await ctx.emit(Finding(
            severity=sev,
            summary=f"sqlmap probe of {url}",
            detail=blob[:1500],
            tool="sqlmap",
            raw=blob[:6000],
        ))


register(Task(
    id="sqlmap",
    label="sqlmap",
    run=_run_sqlmap,
    requires={"site.has_forms", "http.live"},
    produces={"finding"},
    tags={"web", "loud"},
    multiplicity="per_key",
    trigger_key=lambda f: getattr(f, "url", ""),
))


# ---------------------------------------------------------------------------
# wpscan (only when WordPress detected)
# ---------------------------------------------------------------------------


async def _run_wpscan(ctx: TaskCtx) -> None:
    if not have("wpscan"):
        return
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    if not isinstance(parent, WordPressDetected):
        return
    url = parent.on_url
    cmd = [
        "wpscan", "--url", url, "--no-banner", "--random-user-agent",
        "--disable-tls-checks",
    ]
    cmd = inject_web_auth("wpscan", cmd, ctx.opsec)
    buf: List[str] = []
    async for line in ctx.shell("wpscan", cmd):
        buf.append(line)
        await ctx.output(line)
    blob = "\n".join(buf)
    if blob.strip():
        sev = derive_severity("wpscan", blob)
        await ctx.emit(Finding(
            severity=sev,
            summary=f"wpscan WordPress audit of {url}",
            detail=blob[:1500],
            tool="wpscan",
            raw=blob[:8000],
        ))


register(Task(
    id="wpscan",
    label="wpscan",
    run=_run_wpscan,
    requires={"site.is_wordpress"},
    produces={"finding"},
    tags={"web"},
    multiplicity="per_key",
    trigger_key=lambda f: getattr(f, "on_url", ""),
))
