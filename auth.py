"""Authenticated-scan + upstream-proxy injection for web tools.

When the operator has set a session cookie, bearer token, basic auth pair,
arbitrary extra header, or HTTP proxy URL in OPSEC settings, web-tool
command builders call into ``inject_web_auth`` here to splice the right
flags into their ``cmd`` array.

This is the single source of truth for "how does <tool> accept auth /
proxy" — adding a new tool means one entry in ``_FLAGS``, not a tour of
phases/exploits.py + phases/discovery.py + every engagement runner.

Why per-tool flag tables instead of env-var injection:

  * Most of these tools do NOT honor HTTP_PROXY / HTTPS_PROXY. ffuf,
    nuclei, gobuster, wpscan, nikto each have their own ``--proxy``
    flag — env vars get silently ignored.
  * Cookies + custom headers don't have a standard env-var convention
    in the first place. Header injection is per-tool too.
  * Some tools (sqlmap) take very different syntax (``--cookie="..."``
    rather than ``-H "Cookie: ..."``). One central mapping keeps callers
    from having to know.

Public API:
  - inject_web_auth(tool, cmd, settings) -> List[str]
  - has_any_auth(settings) -> bool
"""

from __future__ import annotations

from typing import Callable, Dict, List

from .opsec import OpsecSettings


# ----------------------------------------------------------------------
# Flag adapters per tool
# ----------------------------------------------------------------------
#
# Each adapter takes (cmd, value) and returns a new cmd list with the
# right flags appended. Returning a fresh list (vs mutating) keeps the
# call site safe against shared cmd templates.


def _ffuf_header(cmd: List[str], header: str) -> List[str]:
    """ffuf's ``-H "Name: value"`` accepts arbitrary headers."""
    return [*cmd, "-H", header]


def _ffuf_cookie(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "-b", value]


def _ffuf_proxy(cmd: List[str], value: str) -> List[str]:
    # ffuf uses -x for the proxy URL.
    return [*cmd, "-x", value]


def _nuclei_header(cmd: List[str], header: str) -> List[str]:
    return [*cmd, "-H", header]


def _nuclei_proxy(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "-proxy", value]


def _nikto_header(cmd: List[str], header: str) -> List[str]:
    # nikto: -evasion has no auth bearing — auth is via -id user:pass for
    # basic auth, and arbitrary headers via -H "Name: value"
    return [*cmd, "-H", header]


def _nikto_basic(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "-id", value]


def _nikto_proxy(cmd: List[str], value: str) -> List[str]:
    # nikto: -useproxy http://host:port  (no auth in the flag itself)
    return [*cmd, "-useproxy", value]


def _sqlmap_cookie(cmd: List[str], value: str) -> List[str]:
    # sqlmap takes the cookie as a single arg, not via -H.
    return [*cmd, "--cookie", value]


def _sqlmap_header(cmd: List[str], header: str) -> List[str]:
    # sqlmap uses --header="Name: value" — repeating supported.
    return [*cmd, "--header", header]


def _sqlmap_basic(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "--auth-type", "Basic", "--auth-cred", value]


def _sqlmap_proxy(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "--proxy", value]


def _gobuster_header(cmd: List[str], header: str) -> List[str]:
    return [*cmd, "-H", header]


def _gobuster_cookie(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "-c", value]


def _gobuster_basic(cmd: List[str], value: str) -> List[str]:
    user, _, pw = value.partition(":")
    return [*cmd, "-U", user, "-P", pw]


def _gobuster_proxy(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "--proxy", value]


def _wpscan_header(cmd: List[str], header: str) -> List[str]:
    return [*cmd, "--headers", header]


def _wpscan_cookie(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "--cookie-string", value]


def _wpscan_proxy(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "--proxy", value]


def _whatweb_header(cmd: List[str], header: str) -> List[str]:
    # whatweb takes headers via --header; multiple invocations supported.
    return [*cmd, f"--header={header}"]


def _whatweb_cookie(cmd: List[str], value: str) -> List[str]:
    return [*cmd, f"--cookie={value}"]


def _whatweb_proxy(cmd: List[str], value: str) -> List[str]:
    return [*cmd, f"--proxy={value}"]


def _httpx_header(cmd: List[str], header: str) -> List[str]:
    return [*cmd, "-H", header]


def _httpx_proxy(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "-http-proxy", value]


def _katana_header(cmd: List[str], header: str) -> List[str]:
    return [*cmd, "-H", header]


def _katana_proxy(cmd: List[str], value: str) -> List[str]:
    return [*cmd, "-proxy", value]


# Each tool entry is a dict of capability → adapter. Tools missing a
# capability simply don't get that injection (best-effort) — for example,
# gowitness doesn't have a way to add an arbitrary cookie in older
# versions, so we silently skip it rather than refuse to run.
_FLAGS: Dict[str, Dict[str, Callable[[List[str], str], List[str]]]] = {
    "ffuf": {
        "header": _ffuf_header,
        "cookie": _ffuf_cookie,
        "proxy":  _ffuf_proxy,
    },
    "nuclei": {
        "header": _nuclei_header,
        # nuclei has no dedicated cookie flag — fold into a header.
        "cookie": lambda cmd, v: _nuclei_header(cmd, f"Cookie: {v}"),
        "proxy":  _nuclei_proxy,
    },
    "nikto": {
        "header": _nikto_header,
        "cookie": lambda cmd, v: _nikto_header(cmd, f"Cookie: {v}"),
        "basic":  _nikto_basic,
        "proxy":  _nikto_proxy,
    },
    "sqlmap": {
        "header": _sqlmap_header,
        "cookie": _sqlmap_cookie,
        "basic":  _sqlmap_basic,
        "proxy":  _sqlmap_proxy,
    },
    "gobuster": {
        "header": _gobuster_header,
        "cookie": _gobuster_cookie,
        "basic":  _gobuster_basic,
        "proxy":  _gobuster_proxy,
    },
    "wpscan": {
        "header": _wpscan_header,
        "cookie": _wpscan_cookie,
        # wpscan basic auth: --http-auth user:pass
        "basic":  lambda cmd, v: [*cmd, "--http-auth", v],
        "proxy":  _wpscan_proxy,
    },
    "whatweb": {
        "header": _whatweb_header,
        "cookie": _whatweb_cookie,
        "proxy":  _whatweb_proxy,
    },
    "httpx": {
        "header": _httpx_header,
        "cookie": lambda cmd, v: _httpx_header(cmd, f"Cookie: {v}"),
        "proxy":  _httpx_proxy,
    },
    "katana": {
        "header": _katana_header,
        "cookie": lambda cmd, v: _katana_header(cmd, f"Cookie: {v}"),
        "proxy":  _katana_proxy,
    },
}


def has_any_auth(settings: OpsecSettings) -> bool:
    """True if any auth/proxy knob is non-empty — used to decide whether
    to surface "running authenticated" status banners."""
    return bool(
        settings.auth_cookie
        or settings.auth_bearer
        or settings.auth_basic
        or settings.auth_header
        or settings.http_proxy
    )


def inject_web_auth(
    tool: str, cmd: List[str], settings: OpsecSettings
) -> List[str]:
    """Splice authenticated-scan + proxy flags into ``cmd`` for ``tool``.

    Returns a new list. Tools without a known flag mapping pass through
    unchanged so callers don't have to gate the call on tool name.
    Adapters silently skip any capability the target tool doesn't expose.
    """
    if tool not in _FLAGS:
        return cmd
    if not has_any_auth(settings):
        return cmd

    adapters = _FLAGS[tool]
    out = list(cmd)

    # Order matters: cookie before bearer before custom header — that way
    # an explicit ``auth_header`` set by the user wins (it appears last).
    if settings.auth_cookie and "cookie" in adapters:
        out = adapters["cookie"](out, settings.auth_cookie)

    if settings.auth_bearer:
        # No tool has a dedicated bearer flag — they all consume it as a
        # plain Authorization header. Use the header adapter if present.
        if "header" in adapters:
            out = adapters["header"](out, f"Authorization: Bearer {settings.auth_bearer}")

    if settings.auth_basic and "basic" in adapters:
        out = adapters["basic"](out, settings.auth_basic)
    elif settings.auth_basic and "header" in adapters:
        # Fallback: synthesize the Authorization header ourselves so even
        # tools without a dedicated --auth-cred flag get basic auth.
        import base64
        token = base64.b64encode(settings.auth_basic.encode()).decode()
        out = adapters["header"](out, f"Authorization: Basic {token}")

    if settings.auth_header and "header" in adapters:
        out = adapters["header"](out, settings.auth_header)

    if settings.http_proxy and "proxy" in adapters:
        out = adapters["proxy"](out, settings.http_proxy)

    return out
