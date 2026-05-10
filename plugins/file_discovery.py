"""Sensitive-file discovery + loot extraction.

For each live HTTP endpoint, fetch a curated list of high-signal paths
(.env, .git/HEAD, robots.txt, configs, backups, ...). Successful 200s
are emitted as Findings; the body is scanned for credentials, hashes,
internal hostnames, version strings, URL paths.

The path list is intentionally small and high-precision — this is a
focused probe, not a wordlist fuzz. ffuf handles directory bruteforce
elsewhere.
"""

from __future__ import annotations

import re
import urllib.error
from typing import List, Optional, Tuple

from ..core.facts import (
    DiscoveredCredential, DiscoveredHost, Email, Finding, FurtherPath,
    GitExposed, HTTPLive, VersionString,
)
from ..core.tasks import Task, TaskCtx, register
from ..http_client import http_get_text_async

from ._helpers import web_endpoint_key


# Paths fetched against every HTTP endpoint. Order matters — high-value
# items first so an early hit makes follow-up obvious.
_PATHS = [
    ".env",
    ".env.production",
    ".env.local",
    ".git/HEAD",
    ".git/config",
    ".gitconfig",
    "robots.txt",
    "sitemap.xml",
    "phpinfo.php",
    "info.php",
    "server-status",
    "server-info",
    "wp-config.php",
    "wp-config.php.bak",
    "config.json",
    "config.yml",
    "config.yaml",
    "backup.zip",
    "db.sql",
    "dump.sql",
    "users.csv",
    ".aws/credentials",
    ".ssh/id_rsa",
    "id_rsa",
    "swagger.json",
    "openapi.json",
    "actuator/env",          # spring boot
    "console",                # Werkzeug debugger
    "secrets.yml",
    "credentials.xml",
]


# Patterns that, when matched in a fetched body, mark the file as
# "critical" — i.e. the credential is severe enough to flag CRITICAL.
_CRITICAL_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private_key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}"), "aws_secret"),
    (re.compile(r"ya29\.[0-9A-Za-z\-_]+"), "google_oauth"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api"),
    (re.compile(r"xox[abprs]-[0-9A-Za-z-]{10,}"), "slack_token"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github_pat"),
]

# Lower-tier (still secret, but auto-truncated in display).
_SECRET_PATTERNS = [
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\'\n]{6,})'), "password"),
    (re.compile(r'(?i)api[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})'), "api_key"),
    (re.compile(r'(?i)(?:secret|token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})'), "token"),
    (re.compile(r'(?i)bearer\s+([A-Za-z0-9_\-\.]+)'), "bearer"),
]

_INTERNAL_HOST_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|[a-z0-9.-]+\.(?:local|internal|corp|lan))\b",
    re.IGNORECASE,
)

_VERSION_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_-]+)[/\s]+v?(\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)?)\b"
)

_PATH_LINE_RE = re.compile(r"(?:Disallow|Allow):\s*(/\S+)")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")


def _scan_body(ctx: TaskCtx, source_url: str, body: str):
    """Return facts to emit for one fetched file body."""
    facts: List = []
    if not body:
        return facts
    seen_value = set()
    for rx, label in _CRITICAL_PATTERNS:
        for m in rx.finditer(body):
            v = m.group(0)
            if v in seen_value:
                continue
            seen_value.add(v)
            line = _line_around(body, m.start())
            facts.append(DiscoveredCredential(
                label=label, value=v, source_file=source_url,
                line_context=line, is_critical=True,
            ))
    for rx, label in _SECRET_PATTERNS:
        for m in rx.finditer(body):
            v = m.group(1) if m.groups() else m.group(0)
            if not v or v in seen_value:
                continue
            seen_value.add(v)
            line = _line_around(body, m.start())
            facts.append(DiscoveredCredential(
                label=label, value=v, source_file=source_url,
                line_context=line, is_critical=False,
            ))
    for m in _INTERNAL_HOST_RE.finditer(body):
        facts.append(DiscoveredHost(host=m.group(0)))
    for m in _VERSION_RE.finditer(body):
        text = f"{m.group(1)} {m.group(2)}"
        facts.append(VersionString(text=text, source_file=source_url))
    for m in _PATH_LINE_RE.finditer(body):
        facts.append(FurtherPath(path=m.group(1), source_file=source_url))
    for m in _EMAIL_RE.finditer(body):
        facts.append(Email(address=m.group(0).lower(), found_via="file"))
    return facts


def _line_around(body: str, idx: int, span: int = 80) -> str:
    """Return up to `span` chars of the line containing the match."""
    line_start = body.rfind("\n", 0, idx) + 1
    line_end = body.find("\n", idx)
    if line_end == -1:
        line_end = min(len(body), idx + span)
    return body[line_start:line_end][:span]


async def _run_file_discovery(ctx: TaskCtx) -> None:
    if not ctx.parents:
        return
    parent = ctx.store.by_id(ctx.parents[0])
    base = ""
    if isinstance(parent, HTTPLive):
        base = parent.url.rstrip("/")
    else:
        from ..core.facts import Port as _Port
        if isinstance(parent, _Port) and parent.is_http:
            base = parent.url().rstrip("/")
    if not base:
        return
    git_seen = False
    hits = 0
    seen_keys = set()
    for path in _PATHS:
        url = f"{base}/{path}"
        try:
            body = await http_get_text_async(url, settings=ctx.opsec, timeout=4.0)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError):
            continue
        # urllib raises on 4xx; if we got here body is a 200 response.
        if not body:
            continue
        # Skip canned 'soft 404' pages — many sites return 200 + a
        # generic page for unknown paths. Cheap heuristic: if the
        # body is HTML and contains "not found", drop it.
        low = body.lower()
        if "<html" in low and ("not found" in low or "404" in low):
            continue
        hits += 1
        await ctx.output(f"discovery: 200 {url}")
        sev = "HIGH" if path in (".env", ".git/HEAD", ".git/config",
                                  "wp-config.php", ".aws/credentials",
                                  "id_rsa") else "MEDIUM"
        await ctx.emit(Finding(
            severity=sev,
            summary=f"sensitive file accessible: {url}",
            detail=body[:600],
            tool="discovery",
            raw=body[:4000],
        ))
        if path.startswith(".git/") and not git_seen:
            git_seen = True
            await ctx.emit(GitExposed(url=base + "/.git/"))
        for fact in _scan_body(ctx, url, body):
            # Dedup by (kind, label-or-value) — the same key showing up
            # in multiple files would clutter the loot panel.
            k = (fact.kind, getattr(fact, "value", "")
                 or getattr(fact, "host", "")
                 or getattr(fact, "path", "")
                 or getattr(fact, "text", "")
                 or getattr(fact, "address", ""))
            if k in seen_keys:
                continue
            seen_keys.add(k)
            await ctx.emit(fact)


register(Task(
    id="file_discovery",
    label="sensitive-file probe",
    run=_run_file_discovery,
    requires={"http.live", "port.open"},
    produces={"finding", "loot.credential", "loot.host", "loot.version",
              "loot.path", "loot.git_exposed", "email"},
    tags={"web"},
    multiplicity="per_key",
    trigger_key=lambda f: web_endpoint_key(f),
))
