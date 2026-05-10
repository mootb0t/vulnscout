"""Shared helpers for plugin tasks.

Keeps individual plugin files small and consistent.
"""

from __future__ import annotations

import shutil
from typing import List, Optional, Set

from ..core.facts import Port, Target
from ..core.store import FactStore


def have(binary: str) -> bool:
    """Cheap PATH lookup. Tasks should bail early if the binary is gone
    rather than spawning and getting FileNotFoundError, because the
    failure mode is silent (stream() returns nothing)."""
    return shutil.which(binary) is not None


def get_target(store: FactStore) -> Optional[Target]:
    return store.one("target")


def open_ports(store: FactStore) -> List[Port]:
    """All Port facts emitted so far. Returned in emit order."""
    return store.by_kind("port.open")


def http_ports(store: FactStore) -> List[Port]:
    """Open HTTP/HTTPS ports — drives every web-tool task."""
    out: List[Port] = []
    for p in open_ports(store):
        if isinstance(p, Port) and p.is_http:
            out.append(p)
    return out


def has_kind(store: FactStore, kind: str) -> bool:
    return store.has(kind)


def truncate(s: str, n: int = 8000) -> str:
    if len(s) <= n:
        return s
    return s[:n] + "\n... [truncated]"


# ---------------------------------------------------------------------------
# Output filters
# ---------------------------------------------------------------------------
#
# Some tools dump 10-20 lines of decorative banner / metadata before any
# real output. Surfacing all of it in the live feed buries the actual
# results. Each filter returns True when a line should be SUPPRESSED from
# the feed (the parser still sees it).


def is_whois_noise(line: str) -> bool:
    """whois output lines that aren't useful in the feed."""
    s = line.strip()
    if not s:
        return True
    return (
        s.startswith("%")               # comment lines
        or s.startswith(">>>")          # update timestamps
        or s.startswith("<<<")
        or s.startswith("NOTICE:")
        or s.startswith("TERMS OF USE:")
        or s.startswith("by the following terms")
        or "WHOIS database" in s
        or s.lower().startswith("malformed request")
    )


def is_harvester_banner(line: str) -> bool:
    """theHarvester ASCII banner + decorative header. ~14 lines per run."""
    s = line.rstrip()
    if not s:
        return False
    if set(s) <= set("* "):
        return True
    if s.lstrip().startswith("*") and s.rstrip().endswith("*"):
        return True
    if "theHarvester" in s and ("Coded by" in s or "Edge-Security" in s):
        return True
    if s.startswith("[*]") and ("Target:" in s or "Searching" in s):
        return False                    # keep — actual progress
    return False


def is_dnsrecon_decoration(line: str) -> bool:
    """dnsrecon header banner — the `***` rule and the start-of-run note."""
    s = line.rstrip()
    if not s:
        return True
    return set(s) <= set("* ")


def collect_lines(lines, limit: int = 4000) -> str:
    """Buffer up to `limit` chars of streamed lines into one blob.

    Used by tasks that want to feed cumulative output into the LLM
    translator — the LLM sees one summary, the user sees the live feed
    via ctx.output() as lines arrive.
    """
    buf: List[str] = []
    used = 0
    for line in lines:
        if used >= limit:
            break
        buf.append(line)
        used += len(line) + 1
    return "\n".join(buf)


def web_endpoint_key(fact) -> str:
    """Canonical "host:port" key for any web-target fact.

    The web tools accept both HTTPLive and Port facts as triggers; without
    canonicalisation the same endpoint produces two different trigger keys
    (URL vs host:port) and the task fires twice. This collapses both shapes
    to the same string so per_key multiplicity dedups cleanly.
    """
    url = getattr(fact, "url", None) or getattr(fact, "on_url", None)
    if url:
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            host = p.hostname or ""
            port = p.port or (443 if p.scheme == "https" else 80)
            return f"{host}:{port}"
        except Exception:
            return url
    host = getattr(fact, "host", "")
    port = getattr(fact, "port", 0)
    return f"{host}:{port}"


def url_for_target(store: FactStore) -> Optional[str]:
    """Best-effort URL we can hand to web tools.

    Priority: explicit URL target → a confirmed http.live fact → first
    HTTP port → bare https://target. Returns None if we can't synthesize
    anything meaningful (e.g. no target yet).
    """
    t = get_target(store)
    if t is None:
        return None
    if t.target_type == "url":
        return t.target

    # Prefer a fact-confirmed live URL.
    live = store.by_kind("http.live")
    if live:
        return live[0].url   # type: ignore[attr-defined]

    # Fall back to the first HTTP port.
    for p in http_ports(store):
        return p.url()

    # Last resort.
    return f"https://{t.domain or t.target}"


def domain_of(store: FactStore) -> str:
    t = get_target(store)
    if t is None:
        return ""
    return t.domain or t.target
