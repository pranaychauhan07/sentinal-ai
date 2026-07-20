"""``PermissionAnalyzer`` — takes an already-parsed `PermissionAnalysis`
(from `permission_parser.py`) and flags risks. `severity=INFO` with no
matched rule is a real, explicit "no risk found" outcome, matching
`command_analyzer.CommandAnalyzer`'s identical contract.
"""

from __future__ import annotations

from core.linux_advisor.models import LinuxAdvisorSeverity, PermissionAnalysis, PermissionRisk

#: Sensitive system files that must remain root-owned with restrictive
#: modes — a world-readable/writable mode or non-root ownership on any of
#: these is a critical finding.
SENSITIVE_SYSTEM_FILES: frozenset[str] = frozenset(
    {"/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config"}
)

#: Filenames whose SUID/SGID bit is especially dangerous — a shell or
#: general-purpose interpreter running as another user's identity is a
#: near-guaranteed privilege-escalation primitive.
_SHELL_INTERPRETER_NAMES: frozenset[str] = frozenset(
    {"bash", "sh", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "nc", "ncat"}
)


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.rstrip("/").rsplit("/", maxsplit=1)[-1]


class PermissionAnalyzer:
    """Deterministic, rule-based permission risk flagging — no `RuleEngine`
    needed here (the checks are structural field comparisons on an already-
    parsed `PermissionAnalysis`, not text pattern matching)."""

    def analyze(self, permission: PermissionAnalysis) -> PermissionRisk:
        filename = permission.filename
        is_sensitive_file = filename in SENSITIVE_SYSTEM_FILES

        if is_sensitive_file:
            if permission.owner is not None and permission.owner != "root":
                return PermissionRisk(
                    permission=permission,
                    severity=LinuxAdvisorSeverity.CRITICAL,
                    confidence=0.95,
                    explanation=(
                        f"{filename} is a sensitive system file but is owned by "
                        f"'{permission.owner}', not root."
                    ),
                    recommended_action=f"Restore root ownership of {filename} immediately.",
                    matched_rule_ids=("sensitive_file_not_root_owned",),
                )
            if permission.other_perms != "---":
                return PermissionRisk(
                    permission=permission,
                    severity=LinuxAdvisorSeverity.CRITICAL,
                    confidence=0.9,
                    explanation=(
                        f"{filename} is a sensitive system file but grants "
                        f"'{permission.other_perms}' access to all other users "
                        "(should grant none)."
                    ),
                    recommended_action=(
                        f"Restrict {filename} to mode 0600/0640 with no permissions "
                        "for other users."
                    ),
                    matched_rule_ids=("sensitive_file_overly_permissive",),
                )

        if permission.world_writable and permission.file_type == "d" and not permission.sticky:
            return PermissionRisk(
                permission=permission,
                severity=LinuxAdvisorSeverity.HIGH,
                confidence=0.85,
                explanation=(
                    "This directory is world-writable but does not have the "
                    "sticky bit set — any user can rename or delete files owned "
                    "by other users inside it (the classic unprotected shared-"
                    "directory risk, e.g. an insecure /tmp)."
                ),
                recommended_action=(
                    "Set the sticky bit (chmod +t) on this world-writable directory."
                ),
                matched_rule_ids=("world_writable_dir_no_sticky_bit",),
            )

        if (permission.setuid or permission.setgid) and _basename(
            permission.filename
        ) in _SHELL_INTERPRETER_NAMES:
            return PermissionRisk(
                permission=permission,
                severity=LinuxAdvisorSeverity.CRITICAL,
                confidence=0.9,
                explanation=(
                    f"SUID/SGID is set on {permission.filename or 'this file'}, a "
                    "shell or general-purpose interpreter — running it grants "
                    "the owner's/group's identity to anyone who can execute it, "
                    "a near-guaranteed privilege-escalation primitive."
                ),
                recommended_action=(
                    "Remove the SUID/SGID bit from this interpreter unless there "
                    "is a specific, reviewed reason it must run as another "
                    "identity."
                ),
                matched_rule_ids=("suid_sgid_on_shell_interpreter",),
            )

        if permission.setuid or permission.setgid:
            return PermissionRisk(
                permission=permission,
                severity=LinuxAdvisorSeverity.MEDIUM,
                confidence=0.6,
                explanation=(
                    "SUID/SGID is set on this file — it runs with its owner's/"
                    "group's identity rather than the invoking user's, which is "
                    "only appropriate for a small, well-reviewed set of binaries."
                ),
                recommended_action=(
                    "Confirm this file genuinely needs SUID/SGID; remove the bit if not."
                ),
                matched_rule_ids=("suid_sgid_set",),
            )

        if permission.world_writable:
            severity = (
                LinuxAdvisorSeverity.HIGH
                if permission.other_perms == "rwx"
                else LinuxAdvisorSeverity.MEDIUM
            )
            return PermissionRisk(
                permission=permission,
                severity=severity,
                confidence=0.75,
                explanation=(
                    "This file/directory grants write access to all other "
                    "users, not just its owner/group."
                ),
                recommended_action=(
                    "Remove world-write access unless there is a specific, "
                    "reviewed reason every user needs write access."
                ),
                matched_rule_ids=("world_writable",),
            )

        return PermissionRisk(
            permission=permission,
            severity=LinuxAdvisorSeverity.INFO,
            confidence=1.0,
            explanation="No permission risk found for this entry.",
            matched_rule_ids=(),
        )
