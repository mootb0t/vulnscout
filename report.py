"""Markdown report exporter.

Reads from the FactStore directly. The legacy ScanState materializer
gives us the fields engagement writes back into (confirmed creds added
mid-engagement) without forcing the report to know about engagement's
internals.

Output:  ./reports/YYYY-MM-DD_HH-MM_<target>.md
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, List, Optional

from .core.facts import (
    Analysis, ConfirmedCred, DiscoveredCredential, DiscoveredHash,
    DiscoveredHost, DiscoveredUsername, Email, Finding, FurtherPath,
    GitExposed, IntelSummary, MSFModule, Port, SearchsploitHit, Target,
    Tech, VersionString,
)
from .core.store import FactStore


SEVERITY_BADGE = {
    "CRITICAL": "🔴 **CRITICAL**",
    "HIGH":     "🟠 **HIGH**",
    "MEDIUM":   "🟡 **MEDIUM**",
    "LOW":      "🔵 **LOW**",
    "INFO":     "⚪ **INFO**",
}


def export_report(
    store: FactStore, total_duration: float, profile_key: str = "",
    out_dir: str = "./reports",
) -> str:
    """Write a markdown report and return its absolute path."""
    target_fact = store.one("target")
    target = target_fact.target if target_fact else "unknown"
    target_type = target_fact.target_type if target_fact else ""

    os.makedirs(out_dir, exist_ok=True)
    safe_target = re.sub(r"[^\w.-]+", "_", target)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    path = os.path.join(out_dir, f"{ts}_{safe_target}.md")
    with open(path, "w") as f:
        f.write(_render(store, target, target_type, profile_key, total_duration))
    return os.path.abspath(path)


def _render(store: FactStore, target: str, target_type: str,
             profile_key: str, total_duration: float) -> str:
    lines: List[str] = []

    # ---- Header / metadata ----
    lines += [
        f"# vulnscout report — `{target}`",
        "",
        "## Metadata",
        "",
        f"- **Target:** `{target}`",
        f"- **Target type:** {target_type}",
        f"- **Policy:** {profile_key}",
        f"- **Generated:** {datetime.now().isoformat(timespec='seconds')}",
        f"- **Total duration:** {total_duration:.1f}s",
    ]
    tools = sorted({f.source for f in store.log() if f.source})
    if tools:
        lines.append(f"- **Tasks run:** {', '.join(tools)}")
    lines.append("")

    # ---- Intel summary ----
    intel = store.one("intel.summary")
    lines += ["## Intel Summary", ""]
    if intel:
        lines += ["```", intel.text, "```", ""]
    else:
        lines += ["_No intel summary produced._", ""]

    # Subdomains
    subs = sorted({s.name for s in store.by_kind("subdomain")
                    if getattr(s, "name", "")})
    if subs:
        lines += ["### Subdomains discovered", ""]
        for s in subs[:100]:
            lines.append(f"- `{s}`")
        if len(subs) > 100:
            lines.append(f"- _… and {len(subs) - 100} more_")
        lines.append("")

    # OSINT emails (non-file)
    osint_emails = sorted({
        e.address for e in store.all_of(Email)
        if e.address and e.found_via != "file"
    })
    if osint_emails:
        lines += ["### OSINT emails", ""]
        for e in osint_emails[:50]:
            lines.append(f"- `{e}`")
        lines.append("")

    # Open ports table
    ports = store.all_of(Port)
    if ports:
        lines += [
            "### Open ports", "",
            "| Host | Port | Proto | Service | Product | Version |",
            "|------|------|-------|---------|---------|---------|",
        ]
        for p in ports:
            lines.append(
                f"| {p.host} | {p.port} | {p.protocol} | {p.service} | "
                f"{p.product} | {p.version} |"
            )
        lines.append("")

    # ---- Findings ----
    findings = store.findings()
    lines += ["## Findings", ""]
    if not findings:
        lines += ["_No findings produced._", ""]
    else:
        for f in findings:
            lines += _render_finding(f)

    # ---- Loot inventory ----
    lines += _render_loot(store)

    # ---- Analysis ----
    analysis = store.one("analysis")
    lines += ["## Analysis", ""]
    lines += [
        "_Verify manually before acting. The model can be wrong._", "",
    ]
    if analysis:
        lines += [analysis.text, ""]
    else:
        lines += ["_No analysis produced._", ""]

    # ---- MSF modules ----
    msf = store.all_of(MSFModule)
    if msf:
        lines += [
            "### Available MSF Modules for Detected CVEs", "",
            "_Suggestions only — vulnscout never auto-runs anything._", "",
            "| CVE | Module |",
            "|-----|--------|",
        ]
        for m in msf:
            lines.append(f"| {m.cve} | `{m.module}` |")
        lines.append("")

    # ---- Footer ----
    lines += [
        "---", "",
        "_This report is for systems you own or have explicit written "
        "authorization to test. Exploit references (CVE / exploit-db) are "
        "informational only — vulnscout does not run or weaponise exploits._",
    ]
    return "\n".join(lines) + "\n"


def _render_finding(f: Finding) -> List[str]:
    badge = SEVERITY_BADGE.get(f.severity.upper(), f.severity)
    out = [
        f"### {badge} — `{f.tool}`",
        "",
        f.summary,
        "",
    ]
    if f.detail and f.detail != f.summary:
        out += [f.detail, ""]
    if f.raw and f.raw != f.detail:
        out += [
            "<details><summary>Raw output</summary>",
            "",
            "```",
            f.raw[:8000].rstrip() or "(empty)",
            "```",
            "",
            "</details>",
            "",
        ]
    return out


def _render_loot(store: FactStore) -> List[str]:
    confirmed = store.all_of(ConfirmedCred)
    hashes = store.all_of(DiscoveredHash)
    creds = store.all_of(DiscoveredCredential)
    usernames = store.all_of(DiscoveredUsername)
    file_emails = sorted({
        e.address for e in store.all_of(Email)
        if e.address and e.found_via == "file"
    })
    hosts = sorted({h.host for h in store.all_of(DiscoveredHost) if h.host})
    versions = sorted({v.text for v in store.all_of(VersionString) if v.text})
    paths = sorted({p.path for p in store.all_of(FurtherPath) if p.path})
    git = store.one("loot.git_exposed")

    if not any([confirmed, hashes, creds, usernames, file_emails, hosts,
                versions, paths, git]):
        return []

    out = ["## Loot Inventory", ""]
    out += [
        "_Pivot data extracted from the target — credentials, hashes, "
        "secrets, usernames, internal hosts, version strings, leaked "
        "endpoints._",
        "",
    ]

    if confirmed:
        out += [
            "### Confirmed credentials (verified login)", "",
            "| User | Password | Service |",
            "|------|----------|---------|",
        ]
        for c in confirmed:
            out.append(
                f"| `{_md_quote(c.user)}` | `{_md_quote(c.password)}` | "
                f"{_md_quote(c.service)} |"
            )
        out.append("")

    if hashes:
        out += [
            "### Hashes harvested", "",
            "| User | Type | Hash |",
            "|------|------|------|",
        ]
        for h in hashes[:50]:
            shown = h.hash_value if len(h.hash_value) <= 64 else h.hash_value[:60] + "…"
            out.append(
                f"| `{_md_quote(h.user)}` | {_md_quote(h.hash_type)} | "
                f"`{_md_quote(shown)}` |"
            )
        if len(hashes) > 50:
            out.append(f"| _… and {len(hashes) - 50} more_ |  |  |")
        out.append("")

    if creds:
        critical = [c for c in creds if c.is_critical]
        regular = [c for c in creds if not c.is_critical]
        out += [
            "### Secrets in fetched files", "",
            f"_{len(critical)} critical, {len(regular)} other — non-critical "
            "values truncated for display._",
            "",
            "| Label | Value | Source | Line |",
            "|-------|-------|--------|------|",
        ]
        for c in (critical + regular)[:80]:
            tag = f"**{c.label}**" if c.is_critical else c.label
            shown = c.value if c.is_critical else c.truncated_value()
            out.append(
                f"| {tag} | `{_md_quote(shown)}` | "
                f"`{_md_quote(c.source_file)}` | "
                f"`{_md_quote((c.line_context or '')[:80])}` |"
            )
        if len(creds) > 80:
            out.append(f"| _… and {len(creds) - 80} more_ |  |  |  |")
        out.append("")

    if usernames:
        rows = sorted(usernames, key=lambda u: -float(u.confidence or 0))
        out += [
            "### Usernames harvested", "",
            "| Username | Source | Confidence |",
            "|----------|--------|------------|",
        ]
        for u in rows[:80]:
            out.append(
                f"| `{_md_quote(u.username)}` | `{_md_quote(u.source_file)}` | "
                f"{u.confidence:.2f} |"
            )
        if len(rows) > 80:
            out.append(f"| _… and {len(rows) - 80} more_ |  |  |")
        out.append("")

    if file_emails:
        out += ["### Emails in fetched files", ""]
        for e in file_emails[:50]:
            out.append(f"- `{e}`")
        if len(file_emails) > 50:
            out.append(f"- _… and {len(file_emails) - 50} more_")
        out.append("")

    if hosts:
        out += [
            "### Internal hosts surfaced from leaked files", "",
            "_RFC1918 / link-local / `*.local|.internal|.corp|.lan` addresses._",
            "",
        ]
        for h in hosts[:50]:
            out.append(f"- `{h}`")
        if len(hosts) > 50:
            out.append(f"- _… and {len(hosts) - 50} more_")
        out.append("")

    if versions:
        out += [
            "### Software versions surfaced from leaked files", "",
            "_Re-run searchsploit / nuclei against these — Phase 1 may have "
            "missed them because they live in package manifests._", "",
        ]
        for v in versions[:60]:
            out.append(f"- `{v}`")
        if len(versions) > 60:
            out.append(f"- _… and {len(versions) - 60} more_")
        out.append("")

    if git:
        out += [
            "### Exposed git directory", "",
            f"`{git.url}` — full repository likely downloadable. "
            "Recommended: `git-dumper <url> ./loot/git` then `gitleaks detect "
            "-s ./loot/git`.",
            "",
        ]

    if paths:
        out += [
            "### Additional URL paths to follow up", "",
            f"_{len(paths)} path(s) extracted from fetched file content._", "",
        ]
        for p in paths[:40]:
            out.append(f"- `{p}`")
        if len(paths) > 40:
            out.append(f"- _… and {len(paths) - 40} more_")
        out.append("")

    return out


def _md_quote(arg: str) -> str:
    return (
        str(arg).replace("\\", "\\\\")
              .replace("`", "\\`")
              .replace("|", "\\|")
              .replace("\n", " ")
    )
