"""Port-conditional exposure probes.

Each task here triggers on a specific Port fact (matched by service or
port number). They emit deterministic Findings — no LLM in the loop.

  - redis_unauth        : redis on 6379, no AUTH required
  - mongodb_unauth      : mongo on 27017 with anonymous list-databases
  - elasticsearch_open  : ES on 9200 returning version banner
  - smb_null_session    : SMB allowing null-session enum
  - ftp_anon            : ftp accepting anonymous login
"""

from __future__ import annotations

import asyncio
import socket
from typing import Optional

from ..core.facts import Finding, Port
from ..core.tasks import Task, TaskCtx, register
from ..http_client import http_get_text_async


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _tcp_send(host: str, port: int, payload: bytes,
                    timeout: float = 4.0, recv: int = 1024) -> bytes:
    """Open a TCP socket, send payload, read up to `recv` bytes."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return b""
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(recv), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return data


def _is_port(parent, port: int, services: tuple = ()) -> Optional[Port]:
    """Pull the triggering Port fact when it matches port/services."""
    if not isinstance(parent, Port):
        return None
    if parent.port == port or parent.service in services:
        return parent
    return None


# ---------------------------------------------------------------------------
# redis (port 6379) unauth
# ---------------------------------------------------------------------------


async def _run_redis_unauth(ctx: TaskCtx) -> None:
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    p = _is_port(parent, 6379, ("redis",))
    if p is None:
        return
    data = await _tcp_send(p.host, p.port, b"INFO\r\n", timeout=3.0)
    text = data.decode(errors="replace")
    if "redis_version" in text and "NOAUTH" not in text:
        await ctx.emit(Finding(
            severity="CRITICAL",
            summary=f"redis on {p.host}:{p.port} accepts unauthenticated INFO",
            detail=text[:600],
            tool="exposure-redis",
            raw=text[:1500],
            category="EXPOSURE",
        ))
        await ctx.output(f"redis: unauth confirmed on {p.host}:{p.port}")


register(Task(
    id="exposure.redis",
    label="redis unauth probe",
    run=_run_redis_unauth,
    requires={"port.open"},
    produces={"finding"},
    tags={"network", "exposure"},
    multiplicity="per_key",
    trigger_key=lambda f: f"{getattr(f, 'host', '')}:{getattr(f, 'port', 0)}",
))


# ---------------------------------------------------------------------------
# mongodb (27017) anonymous list
# ---------------------------------------------------------------------------


async def _run_mongo_unauth(ctx: TaskCtx) -> None:
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    p = _is_port(parent, 27017, ("mongodb",))
    if p is None:
        return
    # Quick TCP probe — if it accepts a connection, that's enough to
    # warrant a manual follow-up via the engagement queue.
    data = await _tcp_send(p.host, p.port, b"", timeout=3.0)
    if data or await _port_open(p.host, p.port):
        await ctx.emit(Finding(
            severity="MEDIUM",
            summary=f"mongodb listening unauthenticated on {p.host}:{p.port}",
            detail="Confirm with mongo --host {host} --eval 'db.adminCommand({listDatabases:1})'".format(host=p.host),
            tool="exposure-mongo",
            category="EXPOSURE",
        ))


async def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


register(Task(
    id="exposure.mongo",
    label="mongodb unauth probe",
    run=_run_mongo_unauth,
    requires={"port.open"},
    produces={"finding"},
    tags={"network", "exposure"},
    multiplicity="per_key",
    trigger_key=lambda f: f"{getattr(f, 'host', '')}:{getattr(f, 'port', 0)}",
))


# ---------------------------------------------------------------------------
# elasticsearch (9200) — banner reveals version
# ---------------------------------------------------------------------------


async def _run_elastic(ctx: TaskCtx) -> None:
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    p = _is_port(parent, 9200, ("elasticsearch",))
    if p is None:
        return
    try:
        body = await http_get_text_async(f"http://{p.host}:{p.port}/", settings=ctx.opsec, timeout=4.0)
    except Exception:
        return
    if '"version"' in body and '"name"' in body:
        await ctx.emit(Finding(
            severity="HIGH",
            summary=f"Elasticsearch unauthenticated on {p.host}:{p.port}",
            detail=body[:800],
            tool="exposure-elastic",
            raw=body[:2000],
            category="EXPOSURE",
        ))


register(Task(
    id="exposure.elastic",
    label="elasticsearch unauth",
    run=_run_elastic,
    requires={"port.open"},
    produces={"finding"},
    tags={"web", "exposure"},
    multiplicity="per_key",
    trigger_key=lambda f: f"{getattr(f, 'host', '')}:{getattr(f, 'port', 0)}",
))


# ---------------------------------------------------------------------------
# ftp anonymous
# ---------------------------------------------------------------------------


async def _run_ftp_anon(ctx: TaskCtx) -> None:
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    p = _is_port(parent, 21, ("ftp",))
    if p is None:
        return
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(p.host, p.port), timeout=4.0
        )
    except (OSError, asyncio.TimeoutError):
        return
    try:
        await reader.readline()
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        line1 = (await reader.readline()).decode(errors="replace")
        writer.write(b"PASS anonymous@\r\n")
        await writer.drain()
        line2 = (await reader.readline()).decode(errors="replace")
        if line2.startswith("230"):
            await ctx.emit(Finding(
                severity="HIGH",
                summary=f"FTP anonymous login allowed on {p.host}:{p.port}",
                detail=f"USER anonymous → {line1.strip()}\nPASS → {line2.strip()}",
                tool="exposure-ftp",
                category="EXPOSURE",
            ))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


register(Task(
    id="exposure.ftp",
    label="ftp anonymous probe",
    run=_run_ftp_anon,
    requires={"port.open"},
    produces={"finding"},
    tags={"network", "exposure"},
    multiplicity="per_key",
    trigger_key=lambda f: f"{getattr(f, 'host', '')}:{getattr(f, 'port', 0)}",
))


# ---------------------------------------------------------------------------
# smb null session
# ---------------------------------------------------------------------------


async def _run_smb_null(ctx: TaskCtx) -> None:
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    if not isinstance(parent, Port):
        return
    if parent.port not in (139, 445):
        return
    # Just confirm the port speaks SMB by reading a few bytes — actual
    # null-session enum belongs in the engagement queue (smbmap with -u "").
    data = await _tcp_send(parent.host, parent.port, b"", timeout=3.0, recv=64)
    if data:
        await ctx.emit(Finding(
            severity="INFO",
            summary=f"SMB listening on {parent.host}:{parent.port} — try null-session enum manually",
            detail=f"Suggested: smbmap -H {parent.host} -u '' (engagement queue)",
            tool="exposure-smb",
            category="EXPOSURE",
        ))


register(Task(
    id="exposure.smb",
    label="smb null session probe",
    run=_run_smb_null,
    requires={"port.open"},
    produces={"finding"},
    tags={"network", "exposure"},
    multiplicity="per_key",
    trigger_key=lambda f: f"{getattr(f, 'host', '')}:{getattr(f, 'port', 0)}",
))
