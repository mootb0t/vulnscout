"""Operational security knobs.

Centralises every "how do I look on the wire" decision so the rest of the
codebase doesn't have to know:

  - Tor / proxychains command wrapping
  - Inter-tool randomized delays
  - Per-tool user-agent randomization
  - nmap source-port / fragmentation flags
  - External-IP + Tor + VPN detection (Identity panel)
  - Stealth/Paranoid profile auto-enable

The single chokepoint for command rewriting is ``apply_to_command``. Every
subprocess launched by ``tools/runner.stream`` runs through it, so adding
a new evasion knob is one edit here, not N edits across phase runners.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import shutil
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------


# Persisted under these keys in config.DEFAULTS — string values to match
# the existing schema. Booleans are stored as "1"/"0".
SETTINGS_KEYS = (
    "opsec_tor",
    "opsec_proxychains",
    "opsec_delay_enabled",
    "opsec_delay_min",
    "opsec_delay_max",
    "opsec_user_agent_random",
    "opsec_nmap_source_port",
    "opsec_nmap_fragment",
    # Auth + upstream proxy — used by web-tool runners and the internal
    # http_client. Empty strings disable; setting any one of them turns
    # the corresponding feature on.
    "auth_cookie",
    "auth_bearer",
    "auth_basic",
    "auth_header",
    "http_proxy",
)

SETTINGS_DEFAULTS: Dict[str, str] = {
    "opsec_tor":                "0",
    "opsec_proxychains":        "0",
    "opsec_delay_enabled":      "0",
    "opsec_delay_min":          "5",
    "opsec_delay_max":          "30",
    "opsec_user_agent_random":  "0",
    "opsec_nmap_source_port":   "0",
    "opsec_nmap_fragment":      "0",
    # Auth + proxy.
    "auth_cookie":              "",   # raw "Cookie:" header value, e.g. "session=abc; token=xyz"
    "auth_bearer":              "",   # bare bearer token (no "Bearer " prefix)
    "auth_basic":               "",   # "user:pass"
    "auth_header":              "",   # arbitrary extra header, e.g. "X-API-Key: abcd"
    "http_proxy":               "",   # http://127.0.0.1:8080 for Burp / ZAP / mitmproxy
}


@dataclass
class OpsecSettings:
    tor: bool = False
    proxychains: bool = False
    delay_enabled: bool = False
    delay_min: float = 5.0
    delay_max: float = 30.0
    user_agent_random: bool = False
    nmap_source_port: bool = False
    nmap_fragment: bool = False
    # Authenticated-scan + upstream-proxy state. Web-tool command builders
    # consume these via ``auth.inject_web_auth``; the internal HTTP client
    # consumes them directly. Empty strings = feature off.
    auth_cookie: str = ""
    auth_bearer: str = ""
    auth_basic: str = ""
    auth_header: str = ""
    http_proxy: str = ""

    @classmethod
    def from_settings(cls, settings: Dict[str, str]) -> "OpsecSettings":
        def _b(k: str) -> bool:
            return settings.get(k, SETTINGS_DEFAULTS[k]) == "1"

        def _f(k: str, fallback: float) -> float:
            try:
                v = float(settings.get(k, SETTINGS_DEFAULTS[k]))
                return v if v >= 0 else fallback
            except (TypeError, ValueError):
                return fallback

        def _s(k: str) -> str:
            return str(settings.get(k, SETTINGS_DEFAULTS[k])).strip()

        return cls(
            tor=_b("opsec_tor"),
            proxychains=_b("opsec_proxychains"),
            delay_enabled=_b("opsec_delay_enabled"),
            delay_min=_f("opsec_delay_min", 5.0),
            delay_max=_f("opsec_delay_max", 30.0),
            user_agent_random=_b("opsec_user_agent_random"),
            nmap_source_port=_b("opsec_nmap_source_port"),
            nmap_fragment=_b("opsec_nmap_fragment"),
            auth_cookie=_s("auth_cookie"),
            auth_bearer=_s("auth_bearer"),
            auth_basic=_s("auth_basic"),
            auth_header=_s("auth_header"),
            http_proxy=_s("http_proxy"),
        )

    def merged_with_profile(self, profile_key: str) -> "OpsecSettings":
        """Return a copy with stealth/paranoid auto-enables layered on.

        The persisted toggles are still respected — profile-driven knobs
        only add capability, never disable user-enabled ones.
        """
        if profile_key not in ("stealth", "paranoid"):
            return self
        return replace(
            self,
            delay_enabled=True,
            delay_min=max(self.delay_min, 5.0) if self.delay_enabled else 5.0,
            delay_max=max(self.delay_max, 30.0) if self.delay_enabled else 30.0,
            user_agent_random=True,
            nmap_source_port=True,
            nmap_fragment=True,
        )

    @property
    def any_anonymizer_enabled(self) -> bool:
        return self.tor or self.proxychains


# ----------------------------------------------------------------------
# User-agent pool
# ----------------------------------------------------------------------


# Realistic, current-ish browser UAs. Hand-picked rather than generated so
# there are no obviously bogus combinations (e.g. Chrome/15 on Windows 11).
_USER_AGENTS: List[str] = [
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]


def random_user_agent() -> str:
    return random.choice(_USER_AGENTS)


# Per-tool flag for setting a user-agent. Tools missing from this map
# either have no UA flag (wafw00f, sslscan) or already randomize their
# own UA (wpscan uses --random-user-agent).
_UA_FLAGS: Dict[str, str] = {
    "nikto":    "-useragent",
    "gobuster": "-a",
    "ffuf":     "-H",          # ffuf takes "Header: value" via -H
    "whatweb":  "--user-agent",
}


def apply_user_agent(tool: str, cmd: List[str]) -> List[str]:
    """Inject a randomized UA flag for the given tool. Returns a new list.

    No-op for tools we don't know how to flag — the caller can always
    enable randomization globally without worrying about which tools
    actually pick it up.
    """
    flag = _UA_FLAGS.get(tool)
    if flag is None:
        return cmd
    ua = random_user_agent()
    if tool == "ffuf":
        return [*cmd, flag, f"User-Agent: {ua}"]
    return [*cmd, flag, ua]


# ----------------------------------------------------------------------
# Command wrapping (tor / proxychains)
# ----------------------------------------------------------------------


# Tools that should *not* be wrapped in torsocks/proxychains. Local-only
# binaries, nothing on the wire, or tools that would break the chain.
_NEVER_WRAP = frozenset({
    "searchsploit",   # local DB lookup
    "msfconsole",     # we only ever run it for local search
    "msfdb",
})


def apply_to_command(
    tool: str, cmd: List[str], settings: OpsecSettings
) -> List[str]:
    """Apply every command-mutating OPSEC knob in the right order.

    Order matters: UA injection first (so the wrapper doesn't get the
    UA flag confused with its own args), then proxychains, then torsocks
    on the outside — torsocks is the most general-purpose wrapper and
    benefits from being the outermost layer.
    """
    if not cmd:
        return cmd

    out = cmd
    if settings.user_agent_random:
        out = apply_user_agent(tool, out)

    if tool in _NEVER_WRAP:
        return out

    if settings.proxychains and shutil.which("proxychains4"):
        # -q silences proxychains' own banner so it doesn't pollute the feed.
        out = ["proxychains4", "-q", *out]

    if settings.tor and shutil.which("torsocks"):
        out = ["torsocks", *out]

    return out


def apply_nmap_opsec_args(args: List[str], settings: OpsecSettings) -> List[str]:
    """Add nmap-specific evasion flags. Idempotent — won't double-add."""
    out = list(args)
    if settings.nmap_source_port and "--source-port" not in out and "-g" not in out:
        out += ["--source-port", "53"]
    if settings.nmap_fragment and "-f" not in out and "--mtu" not in out:
        out += ["-f"]
    return out


async def random_delay(settings: OpsecSettings) -> None:
    """Sleep a uniform random interval if delays are enabled. Always safe."""
    if not settings.delay_enabled:
        return
    lo, hi = settings.delay_min, settings.delay_max
    if hi < lo:
        lo, hi = hi, lo
    if hi <= 0:
        return
    await asyncio.sleep(random.uniform(lo, hi))


# ----------------------------------------------------------------------
# Identity check (external IP + Tor/VPN detection)
# ----------------------------------------------------------------------


@dataclass
class IdentityInfo:
    ip: str = ""
    tor: bool = False
    vpn: bool = False
    # Short human-readable label for *why* VPN was detected — one of:
    #   "iface:<name>"   (interface heuristic)
    #   "asn:<keyword>"  (ipinfo org field matched a known VPN provider)
    #   "ip-changed (was <prev>)"  (cached previous IP differs)
    # Multiple signals are joined with "; ".
    vpn_reason: str = ""
    asn: str = ""               # raw ipinfo "org" string (e.g. "AS12345 Mullvad VPN AB")
    error: str = ""

    @property
    def anonymized(self) -> bool:
        return self.tor or self.vpn


_TOR_CHECK_URL = "https://check.torproject.org/api/ip"
_IPINFO_JSON_URL = "https://ipinfo.io/json"
_IPINFO_PLAIN_URL = "https://ipinfo.io/ip"


# Known commercial VPN providers — substring matched against ipinfo's
# `org` field (case-insensitive). Order doesn't matter; first hit wins.
# Keep these as substrings, not whole-token regexes — providers re-brand
# themselves under subsidiary AS names ("Mullvad VPN AB", "31173 Services AB"
# etc.) and we want to catch the obvious cases without an arms race.
_VPN_PROVIDER_KEYWORDS: Tuple[str, ...] = (
    "mullvad",
    "nordvpn", "nord vpn",
    "expressvpn", "express vpn",
    "protonvpn", "proton vpn", "proton ag",
    "torguard",
    "privateinternetaccess", "private internet access",
    "hide.me", "hideme",
    "surfshark",
    "cyberghost",
    "ipvanish",
    "windscribe",
    "tunnelbear",
    "perfect privacy",
    "vyprvpn",
    "airvpn",
    "ivpn",
    "azirevpn",
    "ovpn.com", " ovpn ",
    "purevpn",
    "fastestvpn",
    "atlas vpn",
    "trust.zone",
)


def _http_get_text(url: str, timeout: float = 4.0) -> str:
    # Identity probe runs before any settings exist (we're checking who the
    # operator looks like to the world right now), so we pass settings=None
    # and accept the generic browser UA. Importantly: NOT "vulnscout/0.2".
    from .http_client import http_get_text as _hgt
    return _hgt(url, settings=None, timeout=timeout).strip()


def _detect_vpn_interface() -> Optional[str]:
    """Return the name of an active VPN interface, or None.

    "Active" means: name matches the VPN heuristic AND the iface has at
    least one routable address. macOS ships several `utun*` interfaces by
    default with only IPv6 link-local addresses (`fe80::%utunN`) — those
    do NOT indicate a VPN. Mullvad / WireGuard add a real IPv4 (10.x) and
    a routable IPv6, which is what we look for.

    Prefers psutil when available; falls back to a stdlib `ifconfig` parse
    on macOS/Linux.
    """
    try:
        import psutil  # type: ignore
        for name, addrs in psutil.net_if_addrs().items():
            if not _looks_like_vpn_iface(name):
                continue
            for a in addrs:
                fam = getattr(a, "family", None)
                if _is_routable_address(fam, a.address or ""):
                    return name
        return None
    except ImportError:
        pass

    # Fallback: parse `ifconfig`. Both macOS and Linux print the iface
    # name unindented, followed by indented `inet`/`inet6` lines.
    try:
        import subprocess
        out = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=2.0
        ).stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return None

    current = ""
    for line in out.splitlines():
        if line and not line[0].isspace():
            # macOS:   "utun3: flags=8051<...> mtu 1420"
            # Linux:   "wg0: flags=...<...> mtu 1420"
            current = line.split(":", 1)[0].split()[0]
            continue
        if not _looks_like_vpn_iface(current):
            continue
        stripped = line.strip()
        if stripped.startswith("inet "):
            parts = stripped.split()
            if len(parts) >= 2 and _is_routable_address(socket.AF_INET, parts[1]):
                return current
        elif stripped.startswith("inet6 "):
            parts = stripped.split()
            if len(parts) >= 2 and _is_routable_address(socket.AF_INET6, parts[1]):
                return current
    return None


def _looks_like_vpn_iface(name: str) -> bool:
    """Match the VPN iface naming conventions across macOS / Linux / WireGuard.

      * tun*  / utun*  — generic tunnel + macOS PPP/IPSec/WireGuard.
      * tap*           — bridged tunnels (OpenVPN tap mode).
      * ppp*           — legacy point-to-point (some commercial VPNs).
      * wg*            — WireGuard generic (wg0, wg-mullvad, …).
      * any name containing "mullvad" — covers user-named ifaces.

    macOS note: every Mac has utun0..utunN by default for OS services
    (CarPlay, AirDrop, Personal Hotspot, IPSec). Those have only an IPv6
    link-local — `_is_routable_address` rejects them, so this name match
    alone is not enough to flag VPN; the address check is the gate.
    """
    n = name.lower()
    if "mullvad" in n:
        return True
    return n.startswith(("tun", "utun", "tap", "ppp", "wg"))


def _is_routable_address(family, addr: str) -> bool:
    """True for a non-link-local, non-loopback address on this iface.

    We deliberately accept RFC1918 / CGNAT IPv4 here: WireGuard hands out
    private-range addresses (10.x.x.x for Mullvad) and that is the most
    important signal that a tunnel is actually carrying traffic.
    """
    if not addr:
        return False
    if family == socket.AF_INET:
        if addr.startswith("169.254.") or addr.startswith("127."):
            return False
        return True
    if family == socket.AF_INET6:
        # Strip the zone-id suffix some platforms append: "fe80::1%utun3"
        a = addr.lower().split("%", 1)[0]
        if a in ("::1", "::"):
            return False
        if a.startswith("fe80:") or a.startswith("fe80::"):
            return False
        return True
    return False


def _matches_vpn_provider(blob: str) -> Optional[str]:
    """Return the matching keyword if `blob` mentions a known VPN provider."""
    if not blob:
        return None
    low = blob.lower()
    for kw in _VPN_PROVIDER_KEYWORDS:
        if kw in low:
            return kw.strip()
    return None


# ----------------------------------------------------------------------
# External-IP cache (used for the IP-change VPN signal)
# ----------------------------------------------------------------------
#
# We persist only the last externally-observed IP. The file lives next to
# settings.json so it inherits the same XDG-style location and is wiped
# automatically when a user removes their config dir.


def _identity_cache_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "vulnscout" / "identity_cache.json"


def _load_cached_ip() -> str:
    try:
        with open(_identity_cache_path()) as f:
            data = json.load(f)
        return str(data.get("last_ip", "")) or ""
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return ""


def _save_cached_ip(ip: str) -> None:
    if not ip:
        return
    p = _identity_cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        with open(tmp, "w") as f:
            json.dump({"last_ip": ip}, f)
        os.replace(tmp, p)
    except OSError:
        pass


def _fetch_ipinfo(timeout: float) -> Tuple[str, str]:
    """GET https://ipinfo.io/json — returns (ip, org).

    Falls back to the plain-text `/ip` endpoint if `/json` fails so the
    Identity panel still shows *something* when the JSON API is throttled.
    """
    try:
        body = _http_get_text(_IPINFO_JSON_URL, timeout=timeout)
        data = json.loads(body)
        ip = (data.get("ip") or "").strip()
        org = (data.get("org") or "").strip()
        return ip, org
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
        try:
            return _http_get_text(_IPINFO_PLAIN_URL, timeout=timeout), ""
        except (urllib.error.URLError, OSError, TimeoutError):
            return "", ""


def is_tor_running() -> bool:
    """Quick TCP probe to the default Tor SOCKS port."""
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=0.4):
            return True
    except OSError:
        return False


def tor_install_hint() -> str:
    """Platform-aware install command. macOS-first since that's our default."""
    import sys
    if sys.platform == "darwin":
        return "brew install tor && brew services start tor"
    return "sudo apt install tor && sudo systemctl start tor  (Debian/Ubuntu)"


def is_proxychains_installed() -> bool:
    return shutil.which("proxychains4") is not None or shutil.which("proxychains") is not None


def proxychains_install_hint() -> str:
    import sys
    if sys.platform == "darwin":
        return "brew install proxychains-ng  (then edit /opt/homebrew/etc/proxychains.conf)"
    return "sudo apt install proxychains4  (then edit /etc/proxychains4.conf)"


def check_identity(timeout: float = 4.0) -> IdentityInfo:
    """Probe external IP + Tor + VPN. Never raises — returns best-effort info.

    VPN detection combines three independent signals (any one trips it):

      1. Network-interface heuristic. utun*/wg*/tun*/tap*/ppp* (or any iface
         with "mullvad" in the name) carrying a routable address. macOS-style
         IPv6-link-local-only utun ifaces are filtered out so this doesn't
         false-positive on a clean Mac.
      2. ASN / org match. ipinfo's `org` field is searched for known
         commercial-VPN provider keywords (Mullvad, Proton, Nord, Express,
         …). Catches setups where the iface heuristic misses (e.g. browser
         extensions, system-level VPN clients that use exotic iface names).
      3. External-IP change. We persist the last-seen external IP at
         ~/.config/vulnscout/identity_cache.json — if the current IP differs
         from cache and signals 1 + 2 are silent, that's still a strong
         "you turned a VPN on/off" indicator. The cache is only refreshed
         when no other VPN signal is active, so it accumulates the user's
         baseline non-VPN IP rather than drifting onto VPN exit IPs.
    """
    info = IdentityInfo()

    # ---- Tor probe (authoritative when reachable) ----
    try:
        body = _http_get_text(_TOR_CHECK_URL, timeout=timeout)
        try:
            data = json.loads(body)
            info.tor = bool(data.get("IsTor"))
            ip = data.get("IP")
            if ip:
                info.ip = ip
        except json.JSONDecodeError:
            pass
    except (urllib.error.URLError, OSError, TimeoutError):
        pass

    # ---- External IP + ASN/org via ipinfo ----
    org_blob = ""
    try:
        ip_via_ipinfo, org_blob = _fetch_ipinfo(timeout=timeout)
        if not info.ip and ip_via_ipinfo:
            info.ip = ip_via_ipinfo
        info.asn = org_blob
    except Exception as e:  # paranoia — _fetch_ipinfo already swallows
        info.error = f"ip lookup failed: {e}"

    if not info.ip and not info.error:
        info.error = "ip lookup failed"

    # ---- Combine VPN signals ----
    reasons: List[str] = []

    iface = _detect_vpn_interface()
    if iface:
        reasons.append(f"iface:{iface}")

    provider = _matches_vpn_provider(org_blob)
    if provider:
        reasons.append(f"asn:{provider}")

    cached_ip = _load_cached_ip()
    if info.ip and cached_ip and cached_ip != info.ip:
        reasons.append(f"ip-changed (was {cached_ip})")

    if reasons:
        info.vpn = True
        info.vpn_reason = "; ".join(reasons)

    # Refresh the baseline cache only when we believe we're seeing the
    # user's "real" IP — i.e. neither iface nor ASN flagged VPN. This
    # keeps the cache sticky to the home/office IP so a future VPN
    # connection trips the ip-changed signal cleanly.
    if info.ip and not (iface or provider):
        _save_cached_ip(info.ip)

    return info


# ----------------------------------------------------------------------
# Pre-scan anonymization warning
# ----------------------------------------------------------------------


def is_external_target(target: str, target_type: str) -> bool:
    """True for anything that looks like it'll leave the local network.

    Conservative: an unreachable IP literal is still treated as external
    here — the warning is informational, not a gate.
    """
    if target_type == "domain" or target_type == "url":
        return True
    if target_type in ("ip", "cidr"):
        return not _is_private_ip_or_cidr(target)
    return True


def _is_private_ip_or_cidr(target: str) -> bool:
    import ipaddress
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return net.is_private or net.is_loopback or net.is_link_local
        ip = ipaddress.ip_address(target.split("/")[0])
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def anonymization_warning(
    target: str, target_type: str,
    settings: OpsecSettings, identity: Optional[IdentityInfo],
) -> Optional[str]:
    """Return a warning string if the user is about to hit an external
    target with no anonymization in place. None means no warning needed.
    """
    if not is_external_target(target, target_type):
        return None
    if settings.tor or settings.proxychains:
        return None
    if identity is not None and identity.anonymized:
        return None
    return ("no anonymization detected — your IP will appear in target logs")
