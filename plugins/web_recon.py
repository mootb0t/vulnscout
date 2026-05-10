"""Web fingerprinting that runs once we have an HTTP endpoint.

  - whatweb : tech fingerprint; emits Tech facts (and WordPressDetected
              when relevant)
  - wafw00f : WAF detection
  - katana  : headless crawler that surfaces JS-rendered routes for ffuf

These tasks are `per_key` on the URL of the HTTPLive (or Port) trigger,
so a target with multiple HTTP services gets one whatweb / wafw00f per
URL, not one giant invocation.
"""

from __future__ import annotations

import re
from typing import List

from ..auth import inject_web_auth
from ..core.facts import (
    Fact, FormsDetected, HTTPLive, Port, Tech, WAF, WordPressDetected,
)
from ..core.tasks import Task, TaskCtx, register
from ..tools.runner import INSECURE_TLS_ENV

from ._helpers import have, web_endpoint_key


# ---------------------------------------------------------------------------
# whatweb
# ---------------------------------------------------------------------------


_WHATWEB_TECH_RE = re.compile(r"\b([A-Z][\w\-]+)(?:\[([^\]]+)\])?")


async def _run_whatweb(ctx: TaskCtx) -> None:
    if not have("whatweb"):
        return
    # The trigger fact is either http.live (preferred) or port.open.
    # Walk parents to get the URL; in practice we always trigger off
    # http.live thanks to the requires set.
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

    cmd = ["whatweb", "--no-errors", "-a", "3", url]
    cmd = inject_web_auth("whatweb", cmd, ctx.opsec)

    techs_seen: set = set()
    is_wordpress = False
    async for line in ctx.shell("whatweb", cmd, env_overrides=INSECURE_TLS_ENV):
        await ctx.output(line)
        for m in _WHATWEB_TECH_RE.finditer(line):
            name = m.group(1)
            ver = m.group(2) or ""
            # Filter out HTTP-status-code-like tokens.
            if name.isdigit() or len(name) <= 1:
                continue
            key = (name, ver)
            if key in techs_seen:
                continue
            techs_seen.add(key)
            await ctx.emit(Tech(name=name, version=ver, on_url=url))
            if name.lower() == "wordpress":
                is_wordpress = True
    if is_wordpress:
        await ctx.emit(WordPressDetected(on_url=url))


register(Task(
    id="whatweb",
    label="whatweb",
    run=_run_whatweb,
    requires={"http.live", "port.open"},
    produces={"tech", "site.is_wordpress"},
    tags={"web"},
    multiplicity="per_key",
    trigger_key=lambda f: web_endpoint_key(f),
))


# ---------------------------------------------------------------------------
# wafw00f
# ---------------------------------------------------------------------------


async def _run_wafw00f(ctx: TaskCtx) -> None:
    if not have("wafw00f"):
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
    cmd = ["wafw00f", "-a", url]
    waf_name = ""
    async for line in ctx.shell("wafw00f", cmd, env_overrides=INSECURE_TLS_ENV):
        await ctx.output(line)
        m = re.search(r"is behind\s+(.+?)(?:\s|$)", line, re.IGNORECASE)
        if m:
            waf_name = m.group(1).strip().rstrip(".")
        elif "no waf detected" in line.lower():
            waf_name = ""
    await ctx.emit(WAF(name=waf_name, on_url=url))


register(Task(
    id="wafw00f",
    label="wafw00f",
    run=_run_wafw00f,
    requires={"http.live", "port.open"},
    produces={"waf"},
    tags={"web"},
    multiplicity="per_key",
    trigger_key=lambda f: web_endpoint_key(f),
))


# ---------------------------------------------------------------------------
# katana — headless crawl for JS-rendered routes
# ---------------------------------------------------------------------------


async def _run_katana(ctx: TaskCtx) -> None:
    if not have("katana"):
        return
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    if not isinstance(parent, HTTPLive):
        return
    url = parent.url
    cmd = ["katana", "-silent", "-jc", "-d", "2", "-u", url]
    cmd = inject_web_auth("katana", cmd, ctx.opsec)
    seen_forms = False
    async for line in ctx.shell("katana", cmd, env_overrides=INSECURE_TLS_ENV):
        await ctx.output(line)
        if "?" in line and not seen_forms:
            # Querystring URL — implies forms / parameters → sqlmap candidate.
            from ..core.facts import FormsDetected as _F
            await ctx.emit(_F(url=line.strip()))
            seen_forms = True


register(Task(
    id="katana",
    label="katana crawler",
    run=_run_katana,
    requires={"http.live"},
    produces={"site.has_forms"},
    tags={"web"},
    multiplicity="per_key",
    trigger_key=lambda f: getattr(f, "url", ""),
))
