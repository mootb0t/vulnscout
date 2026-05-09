"""Centralised HTTP client for vulnscout's internal HTTP probes.

The phase runners spawn external tools through ``tools.runner.stream``,
which routes them through ``opsec.apply_to_command`` (tor / proxychains /
random-UA). But several phases (intel, exposure, discovery) also do their
own urllib calls for keyless APIs (internetdb, ipinfo, crt.sh, ...). Those
calls used to hard-code ``User-Agent: vulnscout/0.2``, which:

  - fingerprints every probe back to this tool in target / API logs
  - bypasses the OPSEC layer entirely (proxychains/tor cover subprocess,
    not in-process urllib)

This module is the single chokepoint for those calls. It:

  - applies a randomized realistic UA when ``OpsecSettings.user_agent_random``
    is on, otherwise a generic browser UA (never ``vulnscout/0.2``)
  - honors a user-configured upstream HTTP proxy (Burp/ZAP/mitmproxy) for
    every internal probe, so authenticated-scan traffic and recon traffic
    both flow through the same intercepting proxy
  - injects a SOCKS5 proxy when Tor is active and ``socks`` (PySocks) is
    available, so internal HTTP also rides the Tor circuit

Public API:
  - http_get_text(url, settings=None, timeout=10, headers=None) -> str
      Synchronous — for startup probes and other code outside the
      scheduler loop. Blocks the calling thread.
  - http_get_text_async(url, ...) -> str            (await)
  - http_get_json_async(url, ...) -> Any            (await)
      Coroutine wrappers that run the sync fetch in a thread, so
      scheduler tasks don't block the event loop while a request is in
      flight. Every plugin task should use these.
  - default_user_agent() -> str  (used by callers building requests
    via custom transports)
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .opsec import OpsecSettings, random_user_agent


# Generic, version-less browser UA used when randomization is off. We pick
# a current Chrome-on-macOS string because:
#   - it's the single most common UA on the live web; it blends in
#   - it does not encode the tool name/version anywhere
#   - it's stable enough that an analyst diff'ing logs won't see noise
# When ``opsec.user_agent_random`` is on we instead pull from the rotating
# pool in ``opsec._USER_AGENTS``.
_GENERIC_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def default_user_agent(settings: Optional[OpsecSettings] = None) -> str:
    """Return the UA every internal HTTP probe should use.

    Never returns a vulnscout-branded string — that would leak tool
    identity to API providers (Shodan, ipinfo, crt.sh) and to targets
    on first-party probes (gowitness preview, github code search).
    """
    if settings is not None and settings.user_agent_random:
        return random_user_agent()
    return _GENERIC_UA


def _build_opener(settings: Optional[OpsecSettings]) -> urllib.request.OpenerDirector:
    """Build a per-call opener that knows about HTTP/HTTPS proxies.

    We rebuild for every call rather than caching because the user can
    flip Burp on/off mid-session via the OPSEC modal. The cost is
    negligible — opener build is microseconds.
    """
    handlers = []

    proxy_url = (settings.http_proxy or "").strip() if settings else ""
    if proxy_url:
        # Same proxy for both schemes — that's how Burp/ZAP/mitmproxy work.
        handlers.append(urllib.request.ProxyHandler({
            "http":  proxy_url,
            "https": proxy_url,
        }))
    elif settings is not None and settings.tor:
        # Tor is on but no HTTP proxy configured — try the local SOCKS port.
        # urllib doesn't speak SOCKS natively; we use PySocks if installed.
        # If it isn't, we fall back to a direct connection (the subprocess
        # tools still ride torsocks; only internal urllib calls bypass).
        try:
            import socks  # type: ignore  # noqa: F401
            import socket
            # Module-level monkey-patch — scoped to this opener via the
            # handler chain wouldn't actually take effect for urllib.
            # We snapshot the original socket and restore after the call.
            # (See _http_get below.)
        except ImportError:
            pass

    if not handlers:
        return urllib.request.build_opener()
    return urllib.request.build_opener(*handlers)


def _http_get(
    url: str,
    settings: Optional[OpsecSettings],
    timeout: float,
    headers: Optional[Dict[str, str]],
) -> bytes:
    """Single-call HTTP GET. Honors UA + proxy settings. Raises on failure."""
    final_headers = {"User-Agent": default_user_agent(settings)}
    if headers:
        final_headers.update(headers)

    # Tor SOCKS path: monkey-patch socket only for the duration of the call,
    # and only when no explicit HTTP proxy was set. PySocks is optional —
    # if it's not installed we silently fall through to a direct call,
    # which is the same behaviour the old code had.
    use_tor_socks = (
        settings is not None
        and settings.tor
        and not (settings.http_proxy or "").strip()
    )
    saved_socket = None
    if use_tor_socks:
        try:
            import socks  # type: ignore
            import socket as _socket
            saved_socket = _socket.socket
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050, rdns=True)
            _socket.socket = socks.socksocket
        except ImportError:
            saved_socket = None

    try:
        opener = _build_opener(settings)
        req = urllib.request.Request(url, headers=final_headers)
        with opener.open(req, timeout=timeout) as resp:
            return resp.read()
    finally:
        if saved_socket is not None:
            import socket as _socket
            _socket.socket = saved_socket


def http_get_text(
    url: str,
    settings: Optional[OpsecSettings] = None,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
) -> str:
    """GET ``url`` and return the body as text. Raises on transport failure."""
    body = _http_get(url, settings, timeout, headers)
    return body.decode("utf-8", errors="replace")


def http_get_json(
    url: str,
    settings: Optional[OpsecSettings] = None,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    """GET ``url`` and parse the body as JSON. Raises on transport / parse failure."""
    body = _http_get(url, settings, timeout, headers)
    return json.loads(body.decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# Async variants
# ---------------------------------------------------------------------------
#
# urllib is synchronous and would freeze the event loop if a scheduler task
# called it inline. asyncio.to_thread runs the blocking call on a worker
# thread so other tasks keep making progress in parallel — without dragging
# in aiohttp as a dependency.


async def http_get_text_async(
    url: str,
    settings: Optional[OpsecSettings] = None,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
) -> str:
    return await asyncio.to_thread(http_get_text, url, settings, timeout, headers)


async def http_get_json_async(
    url: str,
    settings: Optional[OpsecSettings] = None,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    return await asyncio.to_thread(http_get_json, url, settings, timeout, headers)
