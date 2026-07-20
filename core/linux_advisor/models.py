"""Domain models for `core/linux_advisor` — blueprint §7's Linux Security
Agent ("command/permission advisor... explain command, analyze permission
strings, recommend hardening").

Owns its own severity scale (`LinuxAdvisorSeverity`) rather than reusing
`core.parsers.models.Severity` or any sibling leaf's — matching the
already-established "each leaf owns its own severity scale" precedent from
`docs/adr/0017-vulnerability-assessment-framework.md` point 2 /
`docs/adr/0018-linux-security-threat-hunting-framework.md` point 2.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field


class LinuxAdvisorSeverity(StrEnum):
    """This package's own severity scale — never shared with
    `core.linux_security.models.LinuxSecuritySeverity` or
    `core.vulnerabilities.models.VulnerabilitySeverity`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Ordering for `max()`/comparison use, highest first-class severity last.
_SEVERITY_ORDER: dict[LinuxAdvisorSeverity, int] = {
    LinuxAdvisorSeverity.INFO: 0,
    LinuxAdvisorSeverity.LOW: 1,
    LinuxAdvisorSeverity.MEDIUM: 2,
    LinuxAdvisorSeverity.HIGH: 3,
    LinuxAdvisorSeverity.CRITICAL: 4,
}


def severity_rank(severity: LinuxAdvisorSeverity) -> int:
    """Deterministic ordinal for a `LinuxAdvisorSeverity` — the one place
    this ranking is defined (constitution §2, "a magic number that appears
    in two places will eventually be updated in only one")."""
    return _SEVERITY_ORDER[severity]


def highest_severity(severities: list[LinuxAdvisorSeverity]) -> LinuxAdvisorSeverity:
    if not severities:
        return LinuxAdvisorSeverity.INFO
    return max(severities, key=severity_rank)


class HardeningCategory(StrEnum):
    """The task's eight named hardening-recommendation categories."""

    SSH_CONFIGURATION = "ssh_configuration"
    SUDO_CONFIGURATION = "sudo_configuration"
    FILE_PERMISSIONS = "file_permissions"
    OWNERSHIP = "ownership"
    SERVICES = "services"
    LEAST_PRIVILEGE = "least_privilege"
    FILESYSTEM_SECURITY = "filesystem_security"
    ACCOUNT_SECURITY = "account_security"


class RuleMatch(BaseModel):
    """One `rule_engine.RuleEngine` match against a piece of text."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    category: str
    severity: LinuxAdvisorSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    safer_alternative: str | None = None
    matched_text: str = ""


class LinuxCommand(BaseModel):
    """One parsed command line — `command_analyzer.py`'s intermediate
    representation, built via `shlex.split` (never `eval`/`exec`/shell-out;
    this package performs pure text analysis, constitution §10)."""

    model_config = ConfigDict(frozen=True)

    raw_text: str
    command_name: str | None = None
    args: tuple[str, ...] = ()
    has_sudo: bool = False
    has_pipe_to_shell: bool = False
    target_paths: tuple[str, ...] = ()
    tokenization_failed: bool = False


class PermissionAnalysis(BaseModel):
    """One parsed `ls -l`-style permission entry (or a standalone octal/
    symbolic mode) — `permission_parser.py`'s output."""

    model_config = ConfigDict(frozen=True)

    raw_text: str
    file_type: str = "-"
    owner_perms: str = "---"
    group_perms: str = "---"
    other_perms: str = "---"
    numeric: str | None = None
    setuid: bool = False
    setgid: bool = False
    sticky: bool = False
    world_writable: bool = False
    filename: str | None = None
    owner: str | None = None
    group: str | None = None


class CommandRisk(BaseModel):
    """`command_analyzer.py`'s per-command verdict. `severity=INFO` with no
    matched rules is a real, reachable "safe command" outcome — not merely
    the absence of output (task brief requirement)."""

    model_config = ConfigDict(frozen=True)

    command: LinuxCommand
    severity: LinuxAdvisorSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommended_action: str | None = None
    purpose: str | None = None
    requires_privilege: bool = False
    matched_rule_ids: tuple[str, ...] = ()


class PermissionRisk(BaseModel):
    """`permission_analyzer.py`'s per-permission-entry verdict. Same
    "no risk found" reachable outcome as `CommandRisk`."""

    model_config = ConfigDict(frozen=True)

    permission: PermissionAnalysis
    severity: LinuxAdvisorSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    recommended_action: str | None = None
    matched_rule_ids: tuple[str, ...] = ()


class HardeningRecommendation(BaseModel):
    """One hardening recommendation — either triggered by a specific finding
    (`is_baseline=False`, `related_subject` names what triggered it) or a
    baseline recommendation surfaced regardless of findings
    (`is_baseline=True`)."""

    model_config = ConfigDict(frozen=True)

    category: HardeningCategory
    recommendation: str
    rationale: str
    priority: int = Field(ge=1, le=5)
    is_baseline: bool = False
    related_subject: str | None = None


class LinuxSecurityAdvice(BaseModel):
    """The aggregate output — blueprint §7's exact named type. A single
    request in, a single `LinuxSecurityAdvice` out; no persisted
    case-evidence lifecycle to track (unlike `core.vulnerabilities`/
    `core.linux_security`)."""

    model_config = ConfigDict(frozen=True)

    analyzed_commands: tuple[CommandRisk, ...] = ()
    permission_analyses: tuple[PermissionRisk, ...] = ()
    hardening_recommendations: tuple[HardeningRecommendation, ...] = ()
    overall_risk_level: LinuxAdvisorSeverity = LinuxAdvisorSeverity.INFO
    overall_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    overall_explanation: str = ""
    skipped_line_count: int = 0
    total_line_count: int = 0


class RiskDimensionScores(BaseModel):
    """The configurable, weighted dimensions `risk_assessment.py` combines
    into `LinuxSecurityAdvice.overall_risk_level`/`overall_confidence` —
    task brief: "No hardcoded business logic. Use configurable rules.""."""

    model_config = ConfigDict(frozen=True)

    highest_severity_score: float = Field(ge=0.0, le=1.0)
    highest_confidence_score: float = Field(ge=0.0, le=1.0)
    finding_count_score: float = Field(ge=0.0, le=1.0)
    critical_category_score: float = Field(ge=0.0, le=1.0)
    corroboration_score: float = Field(ge=0.0, le=1.0)


class MatcherKind(StrEnum):
    """The tagged-union discriminator for `rule_engine.Rule.matcher`."""

    REGEX = "regex"
    LITERAL_SUBSTRING = "literal_substring"
    CALLABLE_SIGNATURE = "callable_signature"


class RulePriority(IntEnum):
    """Illustrative named priority bands — rules may use any int; these are
    convenience constants, not an exhaustive enum of legal values."""

    LOWEST = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    HIGHEST = 100
