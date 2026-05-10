"""Active host + port discovery.

  - nmap     : the canonical port scan; emits Port + OSGuess facts
  - masscan  : fast pre-scan for CIDR targets, emits HostUp facts that
               nmap consumes
  - naabu    : projectdiscovery alternative for non-CIDR sweeps
  - httpx    : confirms which open ports actually respond as HTTP, emits
               HTTPLive facts that web tools consume

The split lets the scheduler run nmap immediately on single-host targets
while CIDR targets get masscan first → live IPs → nmap (per host).
"""

from __future__ import annotations

import json
import os
import re
import socket
import tempfile
from typing import List, Optional

from ..core.facts import (
    Fact, HTTPLive, HostUp, IPAddress, OSGuess, Port, Target, Tech,
)
from ..core.tasks import Task, TaskCtx, register
from ..tools.parser import parse_nmap_xml
from ..tools.runner import adapt_nmap_args, running_as_root

from ._helpers import get_target, have, http_ports, open_ports


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------


async def _run_nmap(ctx: TaskCtx) -> None:
    if not have("nmap"):
        return
    t = get_target(ctx.store)
    if t is None:
        return
    base_args = list(ctx.policy.knob("nmap", "args",
                                       ["--top-ports", "1000", "-T4", "-Pn"]))

    # Pre-resolve so adapt_nmap_args can apply the privileged-tier rules.
    target_ip = ""
    if t.target_type == "ip":
        target_ip = t.target
    else:
        try:
            target_ip = socket.gethostbyname(t.domain or t.target)
        except OSError:
            pass

    args, notes = adapt_nmap_args(base_args, running_as_root(), target_ip)
    for n in notes:
        await ctx.output(f"nmap: {n}")

    # Add OPSEC nmap-specific flags.
    from ..opsec import apply_nmap_opsec_args
    args = apply_nmap_opsec_args(args, ctx.opsec)

    target_arg = t.target
    # CIDR + masscan: if HostUp facts already exist, restrict to those hosts.
    host_facts = ctx.store.by_kind("host.up")
    if t.target_type == "cidr" and host_facts:
        target_arg = ",".join(sorted({h.host for h in host_facts}))    # type: ignore[attr-defined]

    # Always emit XML so the parser can pick up structured ports/OS guess.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        xml_path = f.name

    cmd = ["nmap", *args, "-oX", xml_path, target_arg]
    progress_re = re.compile(r"About\s+([\d.]+)%\s+done.*ETC:\s*(\d+:\d+)?")
    try:
        async for line in ctx.shell("nmap", cmd):
            m = progress_re.search(line)
            if m:
                try:
                    await ctx.progress(float(m.group(1)), m.group(2) or "")
                except ValueError:
                    pass
            await ctx.output(line)

        # Parse the XML.
        try:
            with open(xml_path) as f:
                xml_text = f.read()
        except OSError:
            xml_text = ""
        result = parse_nmap_xml(xml_text)
        for p in result.ports:
            await ctx.emit(Port(
                host=p.host, port=p.port, protocol=p.protocol,
                service=p.service, product=p.product, version=p.version,
            ))
        if result.os_guess:
            await ctx.emit(OSGuess(name=result.os_guess))
        if target_ip and not ctx.store.has("ip"):
            await ctx.emit(IPAddress(address=target_ip))
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def _nmap_condition(store, policy) -> bool:
    """nmap waits for masscan when CIDR targets are involved."""
    t = store.one("target")
    if t is None:
        return False
    if t.target_type != "cidr":  # type: ignore[attr-defined]
        return True
    # CIDR: only schedule once at least one host is up. The HostUp fact
    # arrival re-triggers `_on_new_fact`, which re-evaluates condition().
    return store.has("host.up")


register(Task(
    id="nmap",
    label="nmap port scan",
    run=_run_nmap,
    requires={"target", "host.up"},
    produces={"port.open", "os.guess", "ip"},
    tags={"network"},
    condition=_nmap_condition,
    multiplicity="once",
))


# ---------------------------------------------------------------------------
# masscan (CIDR pre-scan)
# ---------------------------------------------------------------------------


_MASSCAN_LINE_RE = re.compile(
    r"Discovered open port \d+/\w+ on (\d+\.\d+\.\d+\.\d+)"
)


async def _run_masscan(ctx: TaskCtx) -> None:
    if not have("masscan"):
        return
    t = get_target(ctx.store)
    if t is None or t.target_type != "cidr":
        return
    # Top 100 ports for the discovery sweep — finer scan handed to nmap.
    cmd = ["masscan", "-p1-1000", "--rate", "1000", t.target]
    seen: set = set()
    async for line in ctx.shell("masscan", cmd):
        await ctx.output(line)
        m = _MASSCAN_LINE_RE.search(line)
        if m:
            ip = m.group(1)
            if ip not in seen:
                seen.add(ip)
                await ctx.emit(HostUp(host=ip))


register(Task(
    id="masscan",
    label="masscan CIDR pre-scan",
    run=_run_masscan,
    requires={"target"},
    produces={"host.up"},
    tags={"network", "loud"},
))


# ---------------------------------------------------------------------------
# naabu (projectdiscovery; lighter than masscan for non-CIDR sweeps)
# ---------------------------------------------------------------------------


async def _run_naabu(ctx: TaskCtx) -> None:
    if not have("naabu"):
        return
    t = get_target(ctx.store)
    if t is None or t.target_type in ("cidr",):
        return
    # naabu: silent mode prints just host:port lines.
    target = t.domain or t.target
    cmd = ["naabu", "-silent", "-host", target, "-top-ports", "1000"]
    async for line in ctx.shell("naabu", cmd):
        # Format: host:port — feed nmap a HostUp fact so it can refine.
        if ":" in line:
            host = line.split(":", 1)[0]
            if host:
                await ctx.emit(HostUp(host=host))


register(Task(
    id="naabu",
    label="naabu sweep",
    run=_run_naabu,
    requires={"target"},
    produces={"host.up"},
    tags={"network"},
))


# ---------------------------------------------------------------------------
# httpx — confirm which open ports actually serve HTTP
# ---------------------------------------------------------------------------


async def _run_httpx(ctx: TaskCtx) -> None:
    """Probe each open HTTP-class port to confirm it speaks HTTP.

    Runs httpx when available (uses JSON output for stable parsing); if
    httpx is missing, returns without crashing. Either way, every URL we
    wanted to probe gets at least one HTTPLive fact emitted — when httpx
    confirms with a real status, we use that, otherwise we synthesize
    `status=0` so downstream web tools still trigger. The web tools
    don't truly require liveness — they probe themselves — so this
    "best-effort" trigger keeps the chain alive.
    """
    ports = http_ports(ctx.store)
    if not ports:
        return
    urls = sorted({p.url() for p in ports})
    if not urls:
        return

    seen: set = set()
    if have("httpx"):
        cmd = ["httpx", "-silent", "-json", "-status-code", "-title",
               "-tech-detect", "-no-color"]
        for url in urls:
            async for line in ctx.shell("httpx", cmd + ["-u", url]):
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                u = obj.get("url") or obj.get("input") or url
                status = int(obj.get("status_code", 0) or 0)
                title = obj.get("title", "") or ""
                techs = obj.get("tech") or obj.get("technologies") or []
                if isinstance(techs, str):
                    techs = [techs]
                if u in seen:
                    continue
                seen.add(u)
                await ctx.output(
                    f"httpx: {u} [{status}]"
                    + (f" \"{title}\"" if title else "")
                    + (f" {','.join(techs[:5])}" if techs else "")
                )
                await ctx.emit(HTTPLive(url=u, status=status, title=title))
                for tech in techs:
                    if isinstance(tech, str) and tech.strip():
                        await ctx.emit(Tech(name=tech.strip(), on_url=u))

    # Synthesise an HTTPLive for any URL httpx didn't confirm — keeps
    # nuclei/nikto/file_discovery/sqlmap firing even when httpx is missing,
    # silent, or rejected the URL. status=0 signals "unconfirmed".
    for url in urls:
        if url in seen:
            continue
        await ctx.emit(HTTPLive(url=url, status=0, title=""))


register(Task(
    id="httpx",
    label="httpx live HTTP probe",
    run=_run_httpx,
    requires={"port.open"},
    produces={"http.live", "tech"},
    tags={"web", "network"},
    multiplicity="once",
))
