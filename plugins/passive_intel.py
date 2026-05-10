"""Passive OSINT — no packets to the target.

Each task is fact-driven: triggers on the Target seed fact, runs
independently, emits its own typed Facts. They run in parallel up to
the policy's max_parallel cap.

Tasks here:
  - whois          : domain registration / nameservers
  - internetdb     : Shodan InternetDB lookup (free, no key)
  - ipinfo         : ASN + geolocation
  - crtsh          : cert-transparency subdomains
  - reverse_ip     : other domains on the same IP
  - hunter         : hunter.io email enumeration (needs API key)
  - wayback        : historical URL surface
  - github         : code-search hits referencing the target
  - theharvester   : email / subdomain / host OSINT
  - subfinder      : passive subdomain enumeration
  - dnsrecon       : DNS records + zone transfer attempt
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
from typing import List, Optional, Tuple

from ..core.facts import (
    CVEHit, CrtSh, Email, Fact, Finding, GitHubData, IPAddress, IPInfo,
    InternetDB, Port, ReverseIP, Subdomain, Target, WaybackData, WhoisInfo,
)
from ..core.tasks import Task, TaskCtx, register
from ..http_client import http_get_json_async, http_get_text_async

from ._helpers import (
    collect_lines, domain_of, get_target, have, is_dnsrecon_decoration,
    is_harvester_banner, is_whois_noise,
)


# ---------------------------------------------------------------------------
# whois
# ---------------------------------------------------------------------------


def _parse_whois(text: str) -> dict:
    """Extract a few well-known keys from raw whois output."""
    out: dict = {}
    keys = {
        "registrant":   ["Registrant Organization", "Registrant Name", "registrant"],
        "org":          ["Organization", "OrgName"],
        "email":        ["Registrant Email"],
        "created":      ["Creation Date", "created"],
        "expires":      ["Registry Expiry Date", "Expiration Date", "expires"],
        "nameservers":  ["Name Server", "nserver"],
    }
    nameservers: List[str] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        v = v.strip()
        if not v:
            continue
        if k in keys["nameservers"]:
            nameservers.append(v.lower())
        for canon, variants in keys.items():
            if canon == "nameservers":
                continue
            if k in variants and canon not in out:
                out[canon] = v
    if nameservers:
        out["nameservers"] = ", ".join(sorted(set(nameservers))[:6])
    return out


async def _run_whois(ctx: TaskCtx) -> None:
    t = get_target(ctx.store)
    if t is None or t.target_type in ("ip", "cidr"):
        return
    if not have("whois"):
        return
    domain = t.domain or t.target
    buf: List[str] = []
    async for line in ctx.shell("whois", ["whois", domain]):
        buf.append(line)
        # Suppress the IANA boilerplate / "Malformed request" / TOS lines
        # — keep the feed legible. The parser still sees the full buffer.
        if not is_whois_noise(line):
            await ctx.output(line)
    data = _parse_whois("\n".join(buf))
    if data:
        await ctx.emit(WhoisInfo(data=data))
        bits = ", ".join(f"{k}={v}" for k, v in list(data.items())[:5])
        if bits:
            await ctx.output(f"whois: {bits}")


register(Task(
    id="whois",
    label="whois",
    run=_run_whois,
    requires={"target"},
    produces={"whois"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# Shodan InternetDB (free, no key — same as old phase did)
# ---------------------------------------------------------------------------


async def _resolve_ip(host: str) -> str:
    """Run blocking gethostbyname off-thread so the event loop stays free."""
    try:
        return await asyncio.to_thread(socket.gethostbyname, host)
    except OSError:
        return ""


async def _run_internetdb(ctx: TaskCtx) -> None:
    t = get_target(ctx.store)
    if t is None:
        return
    # Need an IP — resolve domain if needed.
    ip = ""
    if t.target_type == "ip":
        ip = t.target
    else:
        ip = await _resolve_ip(t.domain or t.target)
    if not ip:
        return
    await ctx.emit(IPAddress(address=ip))
    try:
        data = await http_get_json_async(
            f"https://internetdb.shodan.io/{ip}",
            settings=ctx.opsec, timeout=8.0,
        )
    except Exception:
        return
    if not isinstance(data, dict):
        return
    await ctx.emit(InternetDB(data=data))

    # Decompose the data we just got: emit Port facts for every port
    # Shodan already saw open + CVEHit facts for every referenced CVE.
    # This lets nuclei + searchsploit kick off without waiting for nmap,
    # and the emitted Ports re-trigger every per-port task downstream.
    target_host = t.domain or t.target
    ports = data.get("ports") or []
    for p in ports:
        try:
            port_num = int(p)
        except (TypeError, ValueError):
            continue
        await ctx.emit(Port(host=target_host, port=port_num,
                            protocol="tcp", service=""))
    cves = [c.upper() for c in (data.get("vulns") or [])
             if isinstance(c, str) and c.upper().startswith("CVE-")]
    for cve in cves:
        await ctx.emit(CVEHit(cve=cve, on=f"{target_host} (Shodan)"))

    # Surface the CVE pile as a Finding so it shows up in the panel.
    # One aggregate row (top severity by year heuristic) + the full list
    # in detail. Per-CVE Findings would flood the panel.
    if cves:
        recent = [c for c in cves if _cve_year(c) >= 2022]
        very_recent = [c for c in cves if _cve_year(c) >= 2024]
        if very_recent:
            sev = "CRITICAL"
        elif recent:
            sev = "HIGH"
        elif any(_cve_year(c) >= 2020 for c in cves):
            sev = "MEDIUM"
        else:
            sev = "LOW"
        cves_sorted = sorted(cves, key=lambda c: -_cve_year(c))
        await ctx.emit(Finding(
            severity=sev,
            summary=(
                f"Shodan InternetDB references {len(cves)} CVE(s) for "
                f"{target_host}"
                + (f" — {len(very_recent)} from 2024+" if very_recent else "")
                + (f" — {len(recent)} from 2022+" if recent and not very_recent else "")
            ),
            detail="CVEs (most recent first):\n" + "\n".join(
                f"  - {c}" for c in cves_sorted[:60]
            ) + (f"\n  … and {len(cves) - 60} more" if len(cves) > 60 else ""),
            tool="shodan-internetdb",
            raw="\n".join(cves_sorted),
        ))

    await ctx.output(
        f"InternetDB: {len(ports)} port(s), {len(cves)} CVE(s) referenced"
    )


def _cve_year(cve: str) -> int:
    """Extract the year from `CVE-YYYY-NNNN`. 0 if unparseable."""
    try:
        return int(cve.split("-")[1])
    except (IndexError, ValueError):
        return 0


register(Task(
    id="internetdb",
    label="Shodan InternetDB",
    run=_run_internetdb,
    requires={"target"},
    produces={"ip", "internetdb", "port.open", "cve", "finding"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# ipinfo (asn + geo)
# ---------------------------------------------------------------------------


async def _run_ipinfo(ctx: TaskCtx) -> None:
    t = get_target(ctx.store)
    if t is None:
        return
    ip = ""
    if t.target_type == "ip":
        ip = t.target
    else:
        # Wait for an IPAddress fact if internetdb already resolved one.
        ip_fact = ctx.store.one("ip")
        if ip_fact is not None:
            ip = ip_fact.address  # type: ignore[attr-defined]
        else:
            ip = await _resolve_ip(t.domain or t.target)
    if not ip:
        return
    try:
        data = await http_get_json_async(
            f"https://ipinfo.io/{ip}/json",
            settings=ctx.opsec, timeout=6.0,
        )
    except Exception:
        return
    if not isinstance(data, dict):
        return
    pruned = {
        k: data.get(k, "")
        for k in ("ip", "hostname", "city", "region", "country", "org")
        if data.get(k)
    }
    if "org" in pruned:
        # ipinfo returns "AS12345 Provider Name"
        m = re.match(r"^(AS\d+)\s+(.+)$", pruned["org"])
        if m:
            pruned["asn"] = m.group(1)
            pruned["org"] = m.group(2)
    await ctx.emit(IPInfo(data=pruned))
    if pruned:
        await ctx.output(
            "ipinfo: "
            + ", ".join(f"{k}={v}" for k, v in list(pruned.items())[:5])
        )


register(Task(
    id="ipinfo",
    label="ipinfo.io",
    run=_run_ipinfo,
    requires={"target"},
    produces={"ipinfo"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# crt.sh (cert transparency → subdomains)
# ---------------------------------------------------------------------------


async def _run_crtsh(ctx: TaskCtx) -> None:
    t = get_target(ctx.store)
    if t is None or t.target_type in ("ip", "cidr"):
        return
    domain = t.domain or t.target
    try:
        rows = await http_get_json_async(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            settings=ctx.opsec, timeout=12.0,
        )
    except Exception:
        return
    if not isinstance(rows, list):
        return
    subs = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        for n in str(r.get("name_value", "")).split("\n"):
            n = n.strip().lower()
            if not n or n.startswith("*"):
                continue
            if n == domain or n.endswith("." + domain):
                subs.add(n)
    if not subs:
        return
    capped = sorted(subs)
    await ctx.emit(CrtSh(certs=capped))
    for s in capped[:200]:
        await ctx.emit(Subdomain(name=s))
    await ctx.output(f"crt.sh: {len(capped)} unique subdomain(s)")


register(Task(
    id="crtsh",
    label="crt.sh",
    run=_run_crtsh,
    requires={"target"},
    produces={"crtsh", "subdomain"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# hackertarget reverse-IP
# ---------------------------------------------------------------------------


async def _run_reverse_ip(ctx: TaskCtx) -> None:
    ip_fact = ctx.store.one("ip")
    if ip_fact is None:
        return
    ip = ip_fact.address  # type: ignore[attr-defined]
    try:
        text = await http_get_text_async(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            settings=ctx.opsec, timeout=8.0,
        )
    except Exception:
        return
    domains = [
        l.strip().lower() for l in text.splitlines()
        if l.strip() and not l.startswith("error")
    ]
    domains = sorted(set(domains))
    if domains:
        await ctx.emit(ReverseIP(domains=domains))
        await ctx.output(f"reverse-ip: {len(domains)} other domain(s)")


register(Task(
    id="reverse_ip",
    label="reverse-IP",
    run=_run_reverse_ip,
    requires={"ip"},
    produces={"reverse_ip"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# hunter.io (email enumeration; needs API key)
# ---------------------------------------------------------------------------


async def _run_hunter(ctx: TaskCtx) -> None:
    api_key = (ctx.policy.knob("hunter", "api_key", "") or "").strip()
    if not api_key:
        return
    t = get_target(ctx.store)
    if t is None or t.target_type in ("ip", "cidr"):
        return
    domain = t.domain or t.target
    try:
        data = await http_get_json_async(
            f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}",
            settings=ctx.opsec, timeout=10.0,
        )
    except Exception:
        return
    emails = []
    if isinstance(data, dict):
        for e in (data.get("data") or {}).get("emails", []) or []:
            addr = e.get("value")
            if addr:
                emails.append(addr.lower())
    if emails:
        for e in sorted(set(emails)):
            await ctx.emit(Email(address=e, found_via="hunter"))
        await ctx.output(f"hunter.io: {len(set(emails))} email(s)")


register(Task(
    id="hunter",
    label="hunter.io",
    run=_run_hunter,
    requires={"target"},
    produces={"email"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# wayback machine
# ---------------------------------------------------------------------------


_WAYBACK_INTERESTING = re.compile(
    r"/(admin|login|api|backup|config|upload|wp-admin|phpmyadmin|debug|"
    r"old|test|dev|staging|\.env|\.git)",
    re.IGNORECASE,
)


async def _run_wayback(ctx: TaskCtx) -> None:
    if not have("waybackurls"):
        return
    t = get_target(ctx.store)
    if t is None or t.target_type in ("ip", "cidr"):
        return
    domain = t.domain or t.target
    urls: List[str] = []
    async for line in ctx.shell("waybackurls", ["waybackurls", domain]):
        urls.append(line)
        if len(urls) >= 5000:    # cap; archives can be huge
            break
    interesting = [u for u in urls if _WAYBACK_INTERESTING.search(u)]
    if urls:
        await ctx.emit(WaybackData(total=len(urls), interesting=interesting[:50]))
        await ctx.output(
            f"wayback: {len(urls)} url(s), {len(interesting)} interesting"
        )


register(Task(
    id="wayback",
    label="wayback URLs",
    run=_run_wayback,
    requires={"target"},
    produces={"wayback"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# github code search (api, no auth — limited but usable)
# ---------------------------------------------------------------------------


_GITHUB_SECRET_RE = re.compile(
    r"(api[_-]?key|secret|token|password|aws_access|aws_secret|private[_-]key)",
    re.IGNORECASE,
)


async def _run_github(ctx: TaskCtx) -> None:
    t = get_target(ctx.store)
    if t is None or t.target_type in ("ip", "cidr"):
        return
    domain = t.domain or t.target
    try:
        data = await http_get_json_async(
            f"https://api.github.com/search/code?q={domain}",
            settings=ctx.opsec, timeout=10.0,
            headers={"Accept": "application/vnd.github.v3+json"},
        )
    except Exception:
        return
    if not isinstance(data, dict):
        return
    total = int(data.get("total_count", 0) or 0)
    items = data.get("items") or []
    secret_hits = sum(
        1 for it in items if _GITHUB_SECRET_RE.search(
            (it.get("path", "") + " " + it.get("name", ""))
        )
    )
    if total:
        await ctx.emit(GitHubData(total=total, secret_hits=secret_hits))
        await ctx.output(
            f"github: {total} code result(s){'; '+str(secret_hits)+' mention secrets' if secret_hits else ''}"
        )


register(Task(
    id="github",
    label="GitHub code search",
    run=_run_github,
    requires={"target"},
    produces={"github"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# theHarvester
# ---------------------------------------------------------------------------


_HARVESTER_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
_HARVESTER_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]+\.[a-z]{2,}$", re.IGNORECASE)


async def _run_theharvester(ctx: TaskCtx) -> None:
    if not have("theHarvester") and not have("theharvester"):
        return
    t = get_target(ctx.store)
    if t is None or t.target_type in ("ip", "cidr"):
        return
    domain = t.domain or t.target
    sources = ctx.policy.knob("theharvester", "sources",
                               ["google", "bing", "crtsh"]) or []
    if not sources:
        return
    binary = "theHarvester" if have("theHarvester") else "theharvester"
    cmd = [binary, "-d", domain, "-l", "300", "-b", ",".join(sources)]
    emails: set = set()
    hosts: set = set()
    async for line in ctx.shell(binary, cmd):
        # Suppress the 14-line ASCII banner; show actual progress.
        if not is_harvester_banner(line):
            await ctx.output(line)
        for m in _HARVESTER_EMAIL_RE.finditer(line):
            emails.add(m.group(0).lower())
        bare = line.strip().lower()
        if (bare.endswith("." + domain) or bare == domain) and _HARVESTER_HOST_RE.match(bare):
            hosts.add(bare)
    for e in sorted(emails):
        await ctx.emit(Email(address=e, found_via="theharvester"))
    for h in sorted(hosts):
        await ctx.emit(Subdomain(name=h))


register(Task(
    id="theharvester",
    label="theHarvester",
    run=_run_theharvester,
    requires={"target"},
    produces={"email", "subdomain"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# subfinder (passive subdomains, projectdiscovery)
# ---------------------------------------------------------------------------


async def _run_subfinder(ctx: TaskCtx) -> None:
    if not have("subfinder"):
        return
    t = get_target(ctx.store)
    if t is None or t.target_type in ("ip", "cidr"):
        return
    domain = t.domain or t.target
    async for line in ctx.shell("subfinder", ["subfinder", "-silent", "-d", domain]):
        bare = line.strip().lower()
        if bare and (bare.endswith("." + domain) or bare == domain):
            await ctx.emit(Subdomain(name=bare))


register(Task(
    id="subfinder",
    label="subfinder",
    run=_run_subfinder,
    requires={"target"},
    produces={"subdomain"},
    tags={"passive-osint", "public-osint"},
))


# ---------------------------------------------------------------------------
# dnsrecon (DNS enum + zone transfer attempt → DNSSEC fact)
# ---------------------------------------------------------------------------


# dnsrecon record-line shape:
#     [*] A scanme.nmap.org 45.33.32.156
#     [*] AAAA scanme.nmap.org 2600:3c01::f03c:91ff:fe18:bb2f
#     [*] CNAME www.example.com → example.com
#     [*] MX example.com mail.example.com
# We capture A/AAAA → IPAddress + Subdomain facts so downstream tasks
# (nmap, ipinfo, internetdb) can act on them without re-resolving.
_DNSRECON_RECORD_RE = re.compile(
    r"^\s*\[\*\]\s+(?P<rtype>A|AAAA|CNAME|MX|NS)\s+(?P<host>\S+)\s+(?P<value>\S+)"
)


async def _run_dnsrecon(ctx: TaskCtx) -> None:
    if not have("dnsrecon"):
        return
    t = get_target(ctx.store)
    if t is None or t.target_type in ("ip", "cidr"):
        return
    domain = t.domain or t.target
    dnssec_seen: Optional[bool] = None
    seen_ips: set = set()
    seen_subs: set = set()
    async for line in ctx.shell("dnsrecon", ["dnsrecon", "-d", domain, "-t", "std"]):
        if not is_dnsrecon_decoration(line):
            await ctx.output(line)
        low = line.lower()
        if "dnssec is configured" in low or "rrsig" in low or "dnskey" in low:
            dnssec_seen = True
        elif "no dnssec" in low or "is not configured" in low:
            dnssec_seen = False
        m = _DNSRECON_RECORD_RE.match(line)
        if m:
            rtype = m.group("rtype")
            host = m.group("host").lower().rstrip(".")
            value = m.group("value").rstrip(".")
            if rtype in ("A", "AAAA"):
                if value not in seen_ips:
                    seen_ips.add(value)
                    await ctx.emit(IPAddress(address=value))
                if host and host != domain and host not in seen_subs:
                    seen_subs.add(host)
                    await ctx.emit(Subdomain(name=host))
            elif rtype == "CNAME":
                # Both sides may be subdomains of `domain`.
                for h in (host, value):
                    h = h.lower().rstrip(".")
                    if h and h.endswith("." + domain) and h not in seen_subs:
                        seen_subs.add(h)
                        await ctx.emit(Subdomain(name=h))
    if dnssec_seen is not None:
        from ..core.facts import DNSSEC
        await ctx.emit(DNSSEC(configured=dnssec_seen))


register(Task(
    id="dnsrecon",
    label="dnsrecon",
    run=_run_dnsrecon,
    requires={"target"},
    produces={"dnssec", "ip", "subdomain"},
    tags={"passive-osint", "public-osint"},
))
