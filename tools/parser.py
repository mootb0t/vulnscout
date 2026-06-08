"""Parsers and formatters used across phases.

Owns:
  - nmap XML parsing (python-nmap with stdlib ElementTree fallback)
  - searchsploit table → list of {title, path, edb_id, url}
  - nuclei JSONL → list of finding dicts
  - target type detection (ip / cidr / domain / url) + validation
  - severity derivation per tool
  - format_nmap_summary — render nmap result as plain English for the LLM
  - format_intel_summary — Phase 1 → Phase 2/3 handoff block
  - looks_like_xml — sentinel for the LLM XML guard
"""

# Severity is derived deterministically here (derive_severity) from raw tool
# output — the LLM only ever summarizes a finding, it never grades it.

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from xml.etree import ElementTree as ET


# ----------------------------------------------------------------------
# nmap
# ----------------------------------------------------------------------


@dataclass
class NmapPort:
    host: str
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str

    @property
    def service_query(self) -> str:
        bits = [b for b in (self.product, self.version) if b]
        return " ".join(bits) or self.service


@dataclass
class NmapResult:
    hosts_up: List[str]
    ports: List[NmapPort]
    os_guess: Optional[str]


def parse_nmap_xml(xml_text: str) -> NmapResult:
    """Parse nmap -oX output. Returns an empty result on failure rather
    than raising — partial scans (interrupted runs) are common."""
    try:
        import nmap as nmaplib
        nm = nmaplib.PortScanner()
        nm.analyse_nmap_xml_scan(nmap_xml_output=xml_text)
        return _from_python_nmap(nm)
    except ImportError:
        pass
    except Exception:
        pass
    return _parse_with_et(xml_text)


def _from_python_nmap(nm) -> NmapResult:
    hosts_up: List[str] = []
    ports: List[NmapPort] = []
    os_guess: Optional[str] = None
    try:
        all_hosts = nm.all_hosts()
    except Exception:
        return NmapResult([], [], None)

    for host in all_hosts:
        try:
            if nm[host].state() != "up":
                continue
            hosts_up.append(host)
            os_data = nm[host].get("osmatch", []) if hasattr(nm[host], "get") else []
            if os_data and os_guess is None:
                os_guess = os_data[0].get("name")
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    info = nm[host][proto][port]
                    if info.get("state") != "open":
                        continue
                    ports.append(
                        NmapPort(
                            host=host,
                            port=int(port),
                            protocol=proto,
                            state=info.get("state", ""),
                            service=info.get("name", ""),
                            product=info.get("product", ""),
                            version=info.get("version", ""),
                        )
                    )
        except Exception:
            continue
    return NmapResult(hosts_up, ports, os_guess)


def _parse_with_et(xml_text: str) -> NmapResult:
    """stdlib fallback when python-nmap is missing or unhappy."""
    hosts_up: List[str] = []
    ports: List[NmapPort] = []
    os_guess: Optional[str] = None

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return NmapResult(hosts_up, ports, os_guess)

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        hosts_up.append(addr)

        os_el = host.find("./os/osmatch")
        if os_el is not None and os_guess is None:
            os_guess = os_el.get("name")

        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            svc_el = port.find("service")
            if state_el is None or state_el.get("state") != "open":
                continue
            ports.append(
                NmapPort(
                    host=addr,
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    state=state_el.get("state", ""),
                    service=svc_el.get("name", "") if svc_el is not None else "",
                    product=svc_el.get("product", "") if svc_el is not None else "",
                    version=svc_el.get("version", "") if svc_el is not None else "",
                )
            )
    return NmapResult(hosts_up, ports, os_guess)


# ----------------------------------------------------------------------
# searchsploit / nuclei
# ----------------------------------------------------------------------


_EDB_ID_RE = re.compile(r"/(\d+)\.\w+$")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def parse_searchsploit_table(text: str) -> List[dict]:
    """Parse searchsploit's ASCII table into structured records.

    Returns `[{title, path, edb_id, url}, ...]`. The Shellcodes / Papers
    sections at the bottom are skipped — only the Exploits section
    matters for triage.
    """
    text = _ANSI_RE.sub("", text)

    out: List[dict] = []
    in_table = False
    saw_header = False

    for line in text.splitlines():
        if "Shellcodes:" in line or "Papers:" in line:
            break
        if "Exploit Title" in line and "Path" in line:
            in_table = True
            saw_header = True
            continue
        if not in_table:
            continue
        if line.lstrip().startswith("-") or not line.strip():
            continue
        if "|" not in line:
            continue

        title_part, _, path_part = line.rpartition("|")
        title = title_part.strip()
        path = path_part.strip()
        if not title or not path or title == "Exploit Title":
            continue

        m = _EDB_ID_RE.search(path)
        edb_id = m.group(1) if m else None
        url = f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else ""
        out.append({
            "title": title,
            "path": path,
            "edb_id": edb_id,
            "url": url,
        })

    if not saw_header:
        return []
    return out


def parse_nuclei_jsonl(text: str) -> List[dict]:
    """Each non-empty line of `nuclei -jsonl` output is one finding."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


# ----------------------------------------------------------------------
# Target validation / type detection
# ----------------------------------------------------------------------


_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
_URL_RE = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.IGNORECASE)


def detect_target_type(target: str) -> str:
    """Auto-detect: 'ip' | 'cidr' | 'domain' | 'url'. Defaults to 'domain'."""
    t = target.strip()
    if t.lower().startswith(("http://", "https://")):
        return "url"
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
            return "cidr"
        except ValueError:
            pass
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.match(t):
        return "domain"
    return "domain"


def validate_target(target: str) -> Tuple[bool, str]:
    """Returns (is_valid, error_message)."""
    t = target.strip()
    if not t:
        return False, "target is empty"
    if t.lower().startswith(("http://", "https://")):
        return (True, "") if _URL_RE.match(t) else (False, "malformed URL")
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
            return True, ""
        except ValueError:
            return False, "invalid CIDR range"
    try:
        ipaddress.ip_address(t)
        return True, ""
    except ValueError:
        pass
    if _DOMAIN_RE.match(t):
        return True, ""
    return False, "not a valid IP, CIDR, domain, or URL"


def extract_domain(target: str) -> str:
    """Strip scheme, port, and path from a URL → bare domain."""
    if target.lower().startswith(("http://", "https://")):
        host = urlparse(target).netloc
        return host.split(":")[0]
    return target


# ----------------------------------------------------------------------
# Summary formatters
# ----------------------------------------------------------------------


def looks_like_xml(s: str) -> bool:
    """Sentinel for the LLM XML guard. Only inspects the first 200 chars
    because well-formed XML declares itself up front."""
    head = s[:200].lstrip()
    return (
        head.startswith("<?xml")
        or head.startswith("<nmaprun")
        or "<nmaprun " in head
    )


def format_nmap_summary(
    ports: List[NmapPort], os_guess: Optional[str], hosts_up: int
) -> str:
    """Render an nmap result as plain English for the LLM.

    The LLM never sees raw XML — small models hallucinate ports, miss
    services, and frequently refuse to summarise XML at all. Pre-formatting
    into sentence-style text gets dramatically better Findings.
    """
    if not ports:
        return f"Nmap scan complete. {hosts_up} host(s) up, no open ports detected."

    parts = [
        f"Nmap scan complete. {hosts_up} host(s) up, {len(ports)} open port(s).",
    ]
    if os_guess:
        parts.append(f"OS guess: {os_guess}.")

    parts.append("Open ports:")
    for p in ports:
        line = f"  - {p.host}:{p.port}/{p.protocol}"
        if p.service:
            line += f" {p.service}"
        product_bits = " ".join(b for b in (p.product, p.version) if b)
        if product_bits:
            line += f" ({product_bits})"
        parts.append(line)
    return "\n".join(parts)


def format_intel_summary(
    target: str,
    ip_addresses: List[str],
    open_ports: List[NmapPort],
    os_guess: str,
    subdomains: List[str],
    technologies: List[str],
    waf: str,
    dnssec_configured: Optional[bool],
    whois_data: Optional[dict] = None,
    ipinfo_data: Optional[dict] = None,
    reverse_ip_domains: Optional[List[str]] = None,
    hunter_emails: Optional[List[str]] = None,
    wayback_total: int = 0,
    wayback_urls: Optional[List[str]] = None,
    github_total: int = 0,
    github_secret_hits: int = 0,
    osint_emails: Optional[List[str]] = None,
    org_name: str = "",
) -> str:
    """Build the Phase 1 → Phase 2/3 handoff summary block.

    This is the single source of truth that flows into the LLM in Phase 2
    (per-tool translation context) and Phase 3 (full synthesis). Phases 2
    and 3 must NEVER see raw tool output of Phase 1 — only this block.
    """
    lines = []
    target_line = f"TARGET: {target}"
    if ip_addresses:
        # First IP is canonical for IP/domain targets
        target_line += f" ({ip_addresses[0]})" if len(ip_addresses) == 1 else \
                       f" ({', '.join(ip_addresses[:5])})"
    lines.append(target_line)

    lines.append(f"OS: {os_guess or 'unknown'}")

    if open_ports:
        port_strs = []
        for p in open_ports:
            label = p.port_label() if hasattr(p, "port_label") else None
            if label is None:
                bits = []
                if p.service:
                    bits.append(p.service.upper())
                if p.product:
                    pv = p.product
                    if p.version:
                        pv += f" {p.version}"
                    bits.append(pv)
                inner = " — ".join(bits) if bits else "unknown"
                label = f"{p.port} ({inner})"
            port_strs.append(label)
        lines.append("OPEN PORTS: " + ", ".join(port_strs))
    else:
        lines.append("OPEN PORTS: none detected")

    if subdomains:
        capped = subdomains[:20]
        suffix = f" (+{len(subdomains) - 20} more)" if len(subdomains) > 20 else ""
        lines.append(f"SUBDOMAINS: {', '.join(capped)}{suffix}")
    else:
        lines.append("SUBDOMAINS: none found")

    lines.append(f"TECHNOLOGIES: {', '.join(technologies) if technologies else 'unknown'}")
    lines.append(f"WAF: {waf or 'none detected'}")

    dns_label = (
        "configured" if dnssec_configured is True
        else "not configured" if dnssec_configured is False
        else "unknown"
    )
    lines.append(f"DNSSEC: {dns_label}")

    # ---- Extended passive intel ----
    if whois_data:
        bits = []
        for k in ("registrant", "org", "email", "created", "expires"):
            v = whois_data.get(k)
            if v:
                bits.append(f"{k}={v}")
        ns = whois_data.get("nameservers", "")
        if ns:
            bits.append(f"ns={ns}")
        if bits:
            lines.append("WHOIS: " + ", ".join(bits))

    if ipinfo_data:
        bits = []
        for k in ("asn", "org", "city", "country", "hostname"):
            v = ipinfo_data.get(k)
            if v:
                bits.append(f"{k}={v}")
        if bits:
            lines.append("IPINFO: " + ", ".join(bits))

    if reverse_ip_domains is not None:
        n = len(reverse_ip_domains)
        if n:
            sample = ", ".join(reverse_ip_domains[:5])
            extra = f" (+{n - 5} more)" if n > 5 else ""
            lines.append(f"REVERSE IP: {n} other domain(s) sharing this IP — {sample}{extra}")
        else:
            lines.append("REVERSE IP: no other domains found on this IP")

    if hunter_emails is not None:
        if hunter_emails:
            sample = ", ".join(hunter_emails[:5])
            extra = f" (+{len(hunter_emails) - 5} more)" if len(hunter_emails) > 5 else ""
            lines.append(f"HUNTER.IO: {len(hunter_emails)} email(s) — {sample}{extra}")
        # An empty list with a set api key still yields no line — avoids noise.

    if wayback_total or (wayback_urls and len(wayback_urls)):
        interesting = wayback_urls or []
        sample = ""
        if interesting:
            top = ", ".join(interesting[:3])
            sample = f" — e.g. {top}"
        lines.append(
            f"WAYBACK: {wayback_total} historical URL(s), "
            f"{len(interesting)} potentially interesting{sample}"
        )

    if github_total:
        secret_note = (
            f" — {github_secret_hits} mention secrets/keys/tokens"
            if github_secret_hits else ""
        )
        lines.append(f"GITHUB: {github_total} code result(s) referencing target{secret_note}")

    # Social-OSINT next-step hint — surfaced after theHarvester / hunter
    # finds employee names or emails. Does not automate ToS-bound platforms.
    have_people = bool(osint_emails) or bool(hunter_emails)
    if have_people:
        org_label = org_name or extract_domain(target)
        domain_label = extract_domain(target)
        lines.append(
            f"OSINT NEXT STEPS: Manual: search LinkedIn for '{org_label}' employees, "
            f"check GitHub for '{domain_label}' repositories"
        )

    return "\n".join(lines)


# ----------------------------------------------------------------------
# Severity derivation per tool (deterministic, not LLM-driven)
# ----------------------------------------------------------------------


_CVSS_RE = re.compile(r'"cvss[-_]score"\s*:\s*([0-9]+(?:\.[0-9]+)?)', re.IGNORECASE)


def _max_cvss(output: str) -> Optional[float]:
    """Extract the highest cvss-score value from nuclei JSONL output.

    Returns None if no parseable score is present. nuclei emits the score
    under `info.classification.cvss-score`; the regex is loose enough to
    survive minor key-name drift across template versions.
    """
    scores = []
    for m in _CVSS_RE.finditer(output):
        try:
            scores.append(float(m.group(1)))
        except ValueError:
            continue
    return max(scores) if scores else None


def _cvss_to_severity(score: float) -> str:
    """Map a CVSS base score to our severity buckets."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def derive_severity(tool: str, output: str) -> str:
    """Map a tool's raw output to one of CRITICAL / HIGH / MEDIUM / LOW / INFO.

    Severity is deterministic. The LLM is a translator only — small models
    (3B-class) routinely ignore severity guides and over-rate trivial
    findings, so we never let them rate.

    Bucket definitions:
      CRITICAL — confirmed RCE / auth bypass, or CVE with CVSS >= 9.0
      HIGH     — CVE with CVSS 7.0-8.9, confirmed SQL injection, credential exposure
      MEDIUM   — outdated version, CVE 4.0-6.9, conditional misconfigurations
      LOW      — missing headers, cert issues, minor misconfigs, TLS 1.0/1.1
      INFO     — open ports, fingerprints, metadata — anything that is not a vulnerability
    """
    lower = output.lower()

    if tool == "searchsploit":
        # Exploits exist for the version → MEDIUM by default. We have no
        # CVSS data here, so we never auto-promote past MEDIUM; the nuclei
        # pass and CVE cross-reference are responsible for HIGH/CRITICAL.
        rows = sum(1 for line in output.splitlines()
                   if "|" in line and "Exploit Title" not in line)
        return "MEDIUM" if rows > 0 else "INFO"

    if tool == "nuclei":
        # Prefer the actual CVSS number when nuclei emits one; fall back
        # to the textual severity tag for templates that lack scores.
        cvss = _max_cvss(output)
        if cvss is not None:
            return _cvss_to_severity(cvss)
        if "[critical]" in lower or '"critical"' in lower:
            return "CRITICAL"
        if "[high]" in lower or '"high"' in lower:
            return "HIGH"
        if "[medium]" in lower or '"medium"' in lower:
            return "MEDIUM"
        if "[low]" in lower or '"low"' in lower:
            return "LOW"
        return "INFO"

    if tool == "nikto":
        # Confirmed exploitation paths first — these override the
        # "header-only" downgrade below.
        critical_kw = ("rce", "remote code", "shellshock",
                       "remote file inclusion")
        if any(k in lower for k in critical_kw):
            return "CRITICAL"
        if "sqli" in lower or "sql injection" in lower:
            return "HIGH"
        if "directory traversal" in lower:
            return "HIGH"

        # Header / cookie / hostname-only findings are LOW even when
        # nikto words them dramatically.
        header_only_kw = ("missing header", "x-frame-options",
                          "x-content-type-options", "strict-transport",
                          "content-security-policy", "cookie",
                          "hostname mismatch")
        has_header_only = any(k in lower for k in header_only_kw)
        has_outdated = "outdated" in lower or "vulnerable" in lower
        if has_outdated and not has_header_only:
            return "MEDIUM"
        return "LOW"

    if tool == "sslscan":
        # Per-spec: TLS version support is LOW. Legacy SSL (SSLv2/SSLv3)
        # is treated as a confirmed vulnerability class.
        if any(k in lower for k in ("sslv2 ", "sslv3 ",
                                     "poodle", "drown", "logjam", "freak")):
            return "HIGH"
        return "LOW"

    if tool == "sqlmap":
        # Confirmed SQL injection → HIGH per spec (credential exposure
        # tier). CRITICAL is reserved for confirmed RCE / auth bypass.
        # The negated phrasings ("do not appear to be injectable") must
        # not match — sqlmap prints them on every clean parameter.
        confirmed = (
            "is vulnerable",
            "appears to be injectable",
            "parameter is vulnerable",
            "the back-end dbms is",
        )
        if any(k in lower for k in confirmed):
            return "HIGH"
        return "INFO"

    if tool == "wpscan":
        # wpscan prefixes confirmed findings with `[!]`. Plain "vulnerab"
        # substring matching false-positives on "no vulnerabilities found".
        if "[!]" in output and "vulnerab" in lower:
            return "MEDIUM"
        return "INFO"

    if tool == "gobuster":
        # Per-spec: VCS/secret artefacts are HIGH; ordinary directory
        # discoveries are INFO.
        sensitive = (
            "/.git", "/.svn", "/.env", "/.hg", "/.bzr",
            "/.git/", "/.svn/", "/.env.", " .git/", " .svn/", " .env",
        )
        if any(s in lower for s in sensitive):
            return "HIGH"
        return "INFO"

    if tool == "ffuf":
        return "INFO"

    if tool == "wafw00f":
        return "INFO"

    return "INFO"
