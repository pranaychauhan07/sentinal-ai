"""``HardeningAdvisor`` — deterministic, rule-based recommendations across
the task's eight named categories. Two kinds of recommendation, clearly
distinguished via `HardeningRecommendation.is_baseline`:

- **Finding-triggered** — produced because a specific `CommandRisk`/
  `PermissionRisk` matched something (e.g. a `chmod 777` finding on a
  specific path names that path in the recommendation).
- **Baseline** — always included regardless of findings (e.g. "disable SSH
  root login"), so an analyst always sees the minimum hardening posture
  even when nothing was flagged.
"""

from __future__ import annotations

from core.linux_advisor.models import (
    CommandRisk,
    HardeningCategory,
    HardeningRecommendation,
    PermissionRisk,
)

#: Always-included baseline recommendations, one or more per category —
#: these never depend on what was actually found in this artifact.
BASELINE_RECOMMENDATIONS: tuple[HardeningRecommendation, ...] = (
    HardeningRecommendation(
        category=HardeningCategory.SSH_CONFIGURATION,
        recommendation="Disable SSH root login (PermitRootLogin no in sshd_config).",
        rationale=(
            "A compromised root SSH credential is a full system takeover with "
            "no privilege-escalation step needed."
        ),
        priority=2,
        is_baseline=True,
    ),
    HardeningRecommendation(
        category=HardeningCategory.SSH_CONFIGURATION,
        recommendation="Use key-based SSH authentication instead of passwords.",
        rationale=(
            "Password authentication is vulnerable to brute-force and "
            "credential-stuffing attacks that key-based auth is not."
        ),
        priority=2,
        is_baseline=True,
    ),
    HardeningRecommendation(
        category=HardeningCategory.SUDO_CONFIGURATION,
        recommendation=(
            "Apply least-privilege sudoers entries scoped to specific commands "
            "instead of blanket ALL=(ALL) NOPASSWD: ALL."
        ),
        rationale=(
            "A blanket sudo grant turns any compromise of that account into full root compromise."
        ),
        priority=2,
        is_baseline=True,
    ),
    HardeningRecommendation(
        category=HardeningCategory.FILE_PERMISSIONS,
        recommendation=(
            "Apply the principle of least privilege to file permissions — "
            "grant only the access a use case actually needs."
        ),
        rationale=(
            "Overly permissive modes (777, 666) are one of the most common "
            "local-privilege-escalation and tampering vectors."
        ),
        priority=3,
        is_baseline=True,
    ),
    HardeningRecommendation(
        category=HardeningCategory.OWNERSHIP,
        recommendation=(
            "Keep sensitive system files (/etc/shadow, /etc/passwd, "
            "/etc/sudoers) owned by root with no ownership changes."
        ),
        rationale=(
            "Ownership changes on these files are a direct path to credential/privilege tampering."
        ),
        priority=2,
        is_baseline=True,
    ),
    HardeningRecommendation(
        category=HardeningCategory.SERVICES,
        recommendation="Disable and remove services that are not required for this host's role.",
        rationale=(
            "Every running service is additional attack surface; unused "
            "services are rarely patched promptly."
        ),
        priority=3,
        is_baseline=True,
    ),
    HardeningRecommendation(
        category=HardeningCategory.LEAST_PRIVILEGE,
        recommendation=(
            "Run services and scripts under a dedicated, unprivileged "
            "service account rather than root."
        ),
        rationale=(
            "Limits the blast radius of a compromised process to that account's own permissions."
        ),
        priority=3,
        is_baseline=True,
    ),
    HardeningRecommendation(
        category=HardeningCategory.FILESYSTEM_SECURITY,
        recommendation="Set the sticky bit on any world-writable shared directory (e.g. /tmp).",
        rationale=(
            "Prevents one user from deleting or renaming another user's "
            "files in a shared directory."
        ),
        priority=3,
        is_baseline=True,
    ),
    HardeningRecommendation(
        category=HardeningCategory.ACCOUNT_SECURITY,
        recommendation=(
            "Enforce a password policy (minimum length/complexity, expiry) "
            "and remove unused accounts."
        ),
        rationale="Weak or stale accounts are a common initial-access vector.",
        priority=3,
        is_baseline=True,
    ),
)


class HardeningAdvisor:
    """Generates finding-triggered recommendations from the analyzer
    results, then appends the baseline set."""

    def advise(
        self,
        *,
        command_risks: list[CommandRisk],
        permission_risks: list[PermissionRisk],
    ) -> list[HardeningRecommendation]:
        recommendations: list[HardeningRecommendation] = []

        for command_risk in command_risks:
            recommendations.extend(self._from_command_risk(command_risk))
        for permission_risk in permission_risks:
            recommendations.extend(self._from_permission_risk(permission_risk))

        recommendations.extend(BASELINE_RECOMMENDATIONS)
        return recommendations

    def _from_command_risk(self, risk: CommandRisk) -> list[HardeningRecommendation]:
        if not risk.matched_rule_ids:
            return []
        subject = risk.command.command_name or risk.command.raw_text
        recs: list[HardeningRecommendation] = []
        rule_ids = set(risk.matched_rule_ids)

        if "sudo_nopasswd_all" in rule_ids or "sudo_su_root" in rule_ids:
            recs.append(
                HardeningRecommendation(
                    category=HardeningCategory.SUDO_CONFIGURATION,
                    recommendation=(
                        f"Replace the unrestricted sudo grant seen in '{subject}' with a "
                        "narrowly-scoped sudoers entry for the specific command needed."
                    ),
                    rationale=risk.explanation,
                    priority=1,
                    related_subject=subject,
                )
            )
        if {"chmod_777", "chmod_666", "mkdir_then_chmod_777"} & rule_ids:
            target = risk.command.target_paths[0] if risk.command.target_paths else subject
            recs.append(
                HardeningRecommendation(
                    category=HardeningCategory.FILE_PERMISSIONS,
                    recommendation=(
                        f"Tighten the permissions granted to '{target}' — avoid world-"
                        "writable/executable modes."
                    ),
                    rationale=risk.explanation,
                    priority=1,
                    related_subject=target,
                )
            )
        if "chown_sensitive_away_from_root" in rule_ids:
            target = risk.command.target_paths[0] if risk.command.target_paths else subject
            recs.append(
                HardeningRecommendation(
                    category=HardeningCategory.OWNERSHIP,
                    recommendation=f"Restore root ownership of '{target}' immediately.",
                    rationale=risk.explanation,
                    priority=1,
                    related_subject=target,
                )
            )
        if {"curl_pipe_shell", "wget_pipe_shell"} & rule_ids:
            recs.append(
                HardeningRecommendation(
                    category=HardeningCategory.LEAST_PRIVILEGE,
                    recommendation=(
                        f"Review and replace the pattern in '{subject}' with a download-"
                        "then-inspect-then-run workflow."
                    ),
                    rationale=risk.explanation,
                    priority=1,
                    related_subject=subject,
                )
            )
        if {"rm_rf_root", "rm_rf_generic"} & rule_ids:
            recs.append(
                HardeningRecommendation(
                    category=HardeningCategory.LEAST_PRIVILEGE,
                    recommendation=(
                        f"Add a path guard/confirmation step around '{subject}' before it "
                        "runs in any automated context."
                    ),
                    rationale=risk.explanation,
                    priority=1,
                    related_subject=subject,
                )
            )
        return recs

    def _from_permission_risk(self, risk: PermissionRisk) -> list[HardeningRecommendation]:
        if not risk.matched_rule_ids:
            return []
        subject = risk.permission.filename or risk.permission.raw_text
        rule_ids = set(risk.matched_rule_ids)
        recs: list[HardeningRecommendation] = []

        if (
            "sensitive_file_not_root_owned" in rule_ids
            or "sensitive_file_overly_permissive" in rule_ids
        ):
            recs.append(
                HardeningRecommendation(
                    category=HardeningCategory.OWNERSHIP,
                    recommendation=(
                        f"Restore root ownership and restrictive mode (0600/0640) on '{subject}'."
                    ),
                    rationale=risk.explanation,
                    priority=1,
                    related_subject=subject,
                )
            )
        if "world_writable_dir_no_sticky_bit" in rule_ids:
            recs.append(
                HardeningRecommendation(
                    category=HardeningCategory.FILESYSTEM_SECURITY,
                    recommendation=f"Set the sticky bit on '{subject}'.",
                    rationale=risk.explanation,
                    priority=1,
                    related_subject=subject,
                )
            )
        if {"suid_sgid_on_shell_interpreter", "suid_sgid_set"} & rule_ids:
            recs.append(
                HardeningRecommendation(
                    category=HardeningCategory.ACCOUNT_SECURITY,
                    recommendation=(
                        f"Remove the SUID/SGID bit from '{subject}' unless explicitly required."
                    ),
                    rationale=risk.explanation,
                    priority=1,
                    related_subject=subject,
                )
            )
        if "world_writable" in rule_ids:
            recs.append(
                HardeningRecommendation(
                    category=HardeningCategory.FILE_PERMISSIONS,
                    recommendation=f"Remove world-write access from '{subject}'.",
                    rationale=risk.explanation,
                    priority=1,
                    related_subject=subject,
                )
            )
        return recs
