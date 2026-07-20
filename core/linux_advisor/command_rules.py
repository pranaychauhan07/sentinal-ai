"""Default dangerous-command `Rule` data set — `command_analyzer.py` runs
these against every raw command line via `rule_engine.RuleEngine`. Adding a
new detection means appending a `Rule` here (or registering one elsewhere);
`rule_engine.py`'s code never changes.
"""

from __future__ import annotations

import re

from core.linux_advisor.models import LinuxAdvisorSeverity, MatcherKind
from core.linux_advisor.rule_engine import Matcher, Rule, register_callable

#: `mkdir <path> && chmod ... 777 <same-or-any-path>` — a world-writable
#: directory created and immediately opened up. Expressed as a named
#: callable predicate (rather than a single regex) since it reasons about
#: two related sub-commands joined by a shell operator, the kind of
#: cross-field check the task brief calls out `callable_signature` for.
_MKDIR_THEN_CHMOD_777 = re.compile(r"mkdir\b.*?(?:&&|;)\s*chmod\s+(-R\s+)?0?777\b", re.IGNORECASE)


def _mkdir_then_chmod_777(text: str) -> str | None:
    found = _MKDIR_THEN_CHMOD_777.search(text)
    return found.group(0) if found else None


register_callable("mkdir_then_chmod_777", _mkdir_then_chmod_777)


DEFAULT_COMMAND_RULES: list[Rule] = [
    Rule(
        id="rm_rf_root",
        name="Recursive forced delete targeting root or an unguarded path",
        category="destructive_command",
        severity=LinuxAdvisorSeverity.CRITICAL,
        confidence=0.95,
        matcher=Matcher(
            kind=MatcherKind.REGEX, pattern=r"rm\s+(-\w*\s+)*-?-[a-z]*r[a-z]*f[a-z]*\s+/(\s|$)"
        ),
        explanation=(
            "This command recursively and forcibly deletes the root filesystem "
            "(or another absolute path with no confirmation), which is "
            "unrecoverable and will destroy the system."
        ),
        safer_alternative=(
            "Add an explicit, narrow path (never bare '/'), drop -f to get a "
            "confirmation prompt, avoid running as root, or use 'rm -i' for "
            "interactive confirmation before each deletion."
        ),
        priority=100,
    ),
    Rule(
        id="rm_rf_generic",
        name="Recursive forced delete",
        category="destructive_command",
        severity=LinuxAdvisorSeverity.HIGH,
        confidence=0.7,
        matcher=Matcher(
            kind=MatcherKind.REGEX, pattern=r"rm\s+(-\w*\s+)*-?-[a-z]*r[a-z]*f[a-z]*\b"
        ),
        explanation=(
            "Recursive, forced deletion with no confirmation step — a typo in "
            "the target path can destroy far more than intended."
        ),
        safer_alternative=(
            "Double-check the target path, consider 'rm -i' for confirmation, "
            "or move to a quarantine directory instead of deleting outright."
        ),
        priority=50,
    ),
    Rule(
        id="chmod_777",
        name="World-writable-and-executable permission grant (777)",
        category="insecure_permission_change",
        severity=LinuxAdvisorSeverity.HIGH,
        confidence=0.9,
        matcher=Matcher(kind=MatcherKind.REGEX, pattern=r"chmod\s+(-R\s+)?0?777\b"),
        explanation=(
            "chmod 777 grants read/write/execute to owner, group, and everyone "
            "else — any local user (or, for web-exposed paths, potentially any "
            "remote request) can modify or replace this file/directory."
        ),
        safer_alternative=(
            "Grant only the minimum permission the use case needs (e.g. 750 for "
            "an executable only its owner/group should run, 644 for a "
            "world-readable-only file); never grant world-write."
        ),
        priority=90,
    ),
    Rule(
        id="chmod_666",
        name="World-writable permission grant (666)",
        category="insecure_permission_change",
        severity=LinuxAdvisorSeverity.MEDIUM,
        confidence=0.85,
        matcher=Matcher(kind=MatcherKind.REGEX, pattern=r"chmod\s+(-R\s+)?0?666\b"),
        explanation=(
            "chmod 666 grants world write access to a file — any local user can "
            "modify its contents."
        ),
        safer_alternative=(
            "Grant write access only to the owner/group that needs it (e.g. 644 or 664)."
        ),
        priority=60,
    ),
    Rule(
        id="curl_pipe_shell",
        name="Piping a downloaded script directly into a shell",
        category="untrusted_execution",
        severity=LinuxAdvisorSeverity.CRITICAL,
        confidence=0.9,
        matcher=Matcher(
            kind=MatcherKind.REGEX, pattern=r"curl\b[^|;\n]*\|\s*(sudo\s+)?(bash|sh|zsh)\b"
        ),
        explanation=(
            "Downloading a script with curl and piping it straight into a shell "
            "executes unreviewed, unverified remote content with the current "
            "user's (or root's, if sudo'd) privileges."
        ),
        safer_alternative=(
            "Download the script first, read/inspect it, verify a checksum or "
            "signature against a trusted source, then run it explicitly."
        ),
        priority=95,
    ),
    Rule(
        id="wget_pipe_shell",
        name="Piping a downloaded script directly into a shell (wget)",
        category="untrusted_execution",
        severity=LinuxAdvisorSeverity.CRITICAL,
        confidence=0.9,
        matcher=Matcher(
            kind=MatcherKind.REGEX,
            pattern=r"wget\b[^|;\n]*\|\s*(sudo\s+)?(bash|sh|zsh)\b",
        ),
        explanation=(
            "Downloading a script with wget and piping it straight into a shell "
            "executes unreviewed, unverified remote content."
        ),
        safer_alternative=(
            "Download the script first, read/inspect it, verify a checksum or "
            "signature, then run it explicitly."
        ),
        priority=95,
    ),
    Rule(
        id="sudo_nopasswd_all",
        name="Unrestricted passwordless sudo grant",
        category="unrestricted_sudo",
        severity=LinuxAdvisorSeverity.CRITICAL,
        confidence=0.9,
        matcher=Matcher(kind=MatcherKind.REGEX, pattern=r"nopasswd\s*:\s*all\b"),
        explanation=(
            "A sudoers entry granting NOPASSWD: ALL lets the named user/group "
            "run any command as root with no password prompt — a full "
            "privilege-escalation path if that account is ever compromised."
        ),
        safer_alternative=(
            "Grant only the specific commands the task needs "
            "(e.g. 'alice ALL=(root) NOPASSWD: /usr/bin/systemctl restart myapp'), "
            "never a blanket ALL=(ALL) NOPASSWD: ALL."
        ),
        priority=90,
    ),
    Rule(
        id="sudo_su_root",
        name="Escalating to an interactive root shell",
        category="unrestricted_sudo",
        severity=LinuxAdvisorSeverity.MEDIUM,
        confidence=0.8,
        matcher=Matcher(kind=MatcherKind.REGEX, pattern=r"sudo\s+su\s*-?\s*$"),
        explanation=(
            "'sudo su -' drops into a full interactive root shell rather than "
            "running one specific command with elevated privileges, widening "
            "the blast radius of any mistake or compromised session."
        ),
        safer_alternative=(
            "Run the specific command needed via 'sudo <command>' instead of "
            "opening a persistent root shell."
        ),
        priority=55,
    ),
    Rule(
        id="chown_sensitive_away_from_root",
        name="Changing ownership of a sensitive system file away from root",
        category="insecure_ownership_change",
        severity=LinuxAdvisorSeverity.CRITICAL,
        confidence=0.85,
        matcher=Matcher(
            kind=MatcherKind.REGEX,
            pattern=(
                r"\b(chown|chgrp)\s+(?!root\b)\S+\s+"
                r"(/etc/shadow|/etc/passwd|/etc/sudoers)\b"
            ),
        ),
        explanation=(
            "Changing the owner/group of /etc/shadow, /etc/passwd, or "
            "/etc/sudoers away from root lets a non-root account read or "
            "modify credentials and privilege configuration."
        ),
        safer_alternative=(
            "Sensitive system files must remain owned by root:root (or "
            "root:shadow for /etc/shadow) with restrictive permissions "
            "(0600/0640) — never re-owned to another account."
        ),
        priority=98,
    ),
    Rule(
        id="mkdir_then_chmod_777",
        name="World-writable directory created and immediately opened up",
        category="insecure_permission_change",
        severity=LinuxAdvisorSeverity.HIGH,
        confidence=0.75,
        matcher=Matcher(kind=MatcherKind.CALLABLE_SIGNATURE, callable_name="mkdir_then_chmod_777"),
        explanation=(
            "A directory is created and then chmod'd to 777 in the same "
            "command sequence — any local user can write into (and any "
            "web-server process serve/execute from) this directory."
        ),
        safer_alternative=(
            "Create the directory with the narrowest mode the use case needs "
            "(e.g. 'mkdir -m 750 <dir>') instead of opening it up to everyone."
        ),
        priority=70,
    ),
]
