"""``SecureCodingAdvisor`` — the task's named "Secure Coding Advisor"
capability. Mirrors `core.linux_advisor.hardening_advisor.HardeningAdvisor`'s
established shape: one baseline recommendation per vulnerability category
(always surfaced, `is_baseline=True`) plus finding-triggered recommendations
naming the specific file/line that triggered them (`is_baseline=False`).
"""

from __future__ import annotations

from core.owasp_security.models import (
    SecureCodingRecommendation,
    SourceFinding,
    VulnerabilityCategory,
    severity_rank,
)

#: One baseline secure-coding tip per task-named category, surfaced
#: regardless of whether that category produced a finding in this file.
_BASELINE_RECOMMENDATIONS: dict[VulnerabilityCategory, str] = {
    VulnerabilityCategory.SQL_INJECTION: (
        "Always use parameterized queries/prepared statements, never string-built SQL."
    ),
    VulnerabilityCategory.XSS: (
        "Rely on your templating engine's default auto-escaping; never disable it "
        "for dynamic content."
    ),
    VulnerabilityCategory.COMMAND_INJECTION: (
        "Never build shell command strings from dynamic input; use argument-list "
        "APIs with shell disabled."
    ),
    VulnerabilityCategory.PATH_TRAVERSAL: (
        "Validate/normalize every file path against an allowed base directory before use."
    ),
    VulnerabilityCategory.SSRF: (
        "Validate every outbound request URL against an allowlist of trusted hosts."
    ),
    VulnerabilityCategory.HARDCODED_SECRETS: (
        "Load all secrets from environment variables or a secrets manager, never from source."
    ),
    VulnerabilityCategory.WEAK_CRYPTOGRAPHY: (
        "Use SHA-256+ for hashing and a dedicated KDF (bcrypt/argon2) for passwords."
    ),
    VulnerabilityCategory.INSECURE_RANDOMNESS: (
        "Use a cryptographically secure random source for any security-relevant value."
    ),
    VulnerabilityCategory.UNSAFE_DESERIALIZATION: (
        "Never deserialize untrusted data with pickle/native serialization/eval; use JSON."
    ),
    VulnerabilityCategory.BROKEN_AUTHENTICATION: (
        "Use constant-time comparison for any secret/credential check."
    ),
    VulnerabilityCategory.MISSING_INPUT_VALIDATION: (
        "Validate and sanitize all external input before it reaches a sensitive operation."
    ),
    VulnerabilityCategory.DANGEROUS_FILE_OPERATIONS: (
        "Confirm every deletion/permission-change target is validated and trusted."
    ),
    VulnerabilityCategory.OPEN_REDIRECT: (
        "Validate every redirect target against an allowlist of relative paths/trusted hosts."
    ),
    VulnerabilityCategory.SENSITIVE_INFORMATION_EXPOSURE: (
        "Never log or print secrets; mask/redact sensitive fields."
    ),
    VulnerabilityCategory.INSECURE_CONFIGURATION: (
        "Disable debug modes and TLS-verification bypasses before deploying to production."
    ),
}

_BASELINE_PRIORITY = 1


class SecureCodingAdvisor:
    def advise(self, findings: list[SourceFinding]) -> list[SecureCodingRecommendation]:
        recommendations: list[SecureCodingRecommendation] = []
        for category, tip in _BASELINE_RECOMMENDATIONS.items():
            recommendations.append(
                SecureCodingRecommendation(
                    category=category,
                    recommendation=tip,
                    rationale="Baseline secure-coding guidance, surfaced regardless of findings.",
                    priority=_BASELINE_PRIORITY,
                    is_baseline=True,
                )
            )
        for finding in findings:
            if finding.recommendation is None:
                continue
            recommendations.append(
                SecureCodingRecommendation(
                    category=finding.category,
                    recommendation=finding.recommendation,
                    rationale=finding.explanation,
                    priority=self._priority_for(finding),
                    is_baseline=False,
                    related_subject=f"{finding.file_path}:{finding.line_number}"
                    if finding.line_number
                    else finding.file_path,
                )
            )
        return recommendations

    @staticmethod
    def _priority_for(finding: SourceFinding) -> int:
        return min(5, max(2, severity_rank(finding.severity) + 1))
