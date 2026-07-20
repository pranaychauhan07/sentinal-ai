"""`LinuxSecurityAdvisoryTool` — blueprint §7's named `linux_tools.py`: the
Linux Security Agent's deterministic aggregation tool.

Combines *already-computed* command/permission/hardening data (produced by
`core.services.linux_advisor_service.assess_linux_command_input`, never
recomputed here) into a case-level summary: counts by severity, hardening
recommendation counts (baseline vs. finding-triggered), and the overall risk
verdict. This tool never re-derives a severity, confidence, or risk score
itself (constitution §1.9) — it only aggregates.

Input is plain `dict`/primitive data, not typed
`core.linux_advisor.models.LinuxSecurityAdvice` objects: `core/tools` has no
dependency-rules.md import edge onto `core/linux_advisor` in the direction
that would matter here — matching `core/tools/vuln_tools.py`'s identical
"why input stays dict-shaped" precedent for
`core.agents.vulnerability_agent`.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.tools.base import BaseTool

#: Deterministic severity ranking, most severe first — matches
#: `core.linux_advisor.models.LinuxAdvisorSeverity`'s five values by string
#: value (duplicated here rather than imported, since `core/tools`'s
#: existing sibling `vuln_tools.py` already established this "duplicate a
#: small ranking table rather than import a leaf-sibling's enum" precedent).
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

DEFAULT_TOP_N = 5


class LinuxCommandSummaryInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    command_name: str | None = None
    raw_text: str = ""
    severity: str = "info"
    confidence: float = 1.0
    explanation: str = ""
    matched_rule_count: int = 0


class LinuxPermissionSummaryInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    filename: str | None = None
    raw_text: str = ""
    severity: str = "info"
    confidence: float = 1.0
    explanation: str = ""
    matched_rule_count: int = 0


class LinuxHardeningSummaryInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: str
    recommendation: str
    is_baseline: bool = False


class LinuxSecurityAdvisoryInput(BaseModel):
    """The evidence's full set of already-computed command/permission/
    hardening data, plus the already-computed overall verdict — every field
    here is a value `core.linux_advisor.advisory_engine.
    LinuxSecurityAdvisoryEngine` already computed."""

    model_config = ConfigDict(frozen=True)

    commands: list[LinuxCommandSummaryInput] = Field(default_factory=list)
    permissions: list[LinuxPermissionSummaryInput] = Field(default_factory=list)
    hardening_recommendations: list[LinuxHardeningSummaryInput] = Field(default_factory=list)
    overall_risk_level: str = "info"
    overall_confidence: float = 1.0
    overall_explanation: str = ""
    skipped_line_count: int = 0
    top_n: int = Field(default=DEFAULT_TOP_N, ge=1)


class LinuxSecurityAdvisoryOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    command_count: int = 0
    permission_count: int = 0
    flagged_command_count: int = 0
    flagged_permission_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    hardening_recommendation_count: int = 0
    baseline_recommendation_count: int = 0
    finding_triggered_recommendation_count: int = 0
    overall_risk_level: str = "info"
    overall_confidence: float = 1.0
    overall_explanation: str = ""
    skipped_line_count: int = 0
    top_command_findings: tuple[LinuxCommandSummaryInput, ...] = ()
    top_permission_findings: tuple[LinuxPermissionSummaryInput, ...] = ()


class LinuxSecurityAdvisoryTool(BaseTool[LinuxSecurityAdvisoryInput, LinuxSecurityAdvisoryOutput]):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input, always returns the same output."""

    name: ClassVar[str] = "linux_security_advisory_summary"
    description: ClassVar[str] = (
        "Aggregates already-analyzed Linux command/permission risk data and "
        "hardening recommendations into a case-level advisory summary."
    )
    is_io_bound: ClassVar[bool] = False

    def run(self, arguments: LinuxSecurityAdvisoryInput) -> LinuxSecurityAdvisoryOutput:
        flagged_commands = [c for c in arguments.commands if c.matched_rule_count > 0]
        flagged_permissions = [p for p in arguments.permissions if p.matched_rule_count > 0]

        severity_counts: dict[str, int] = {}
        for command in flagged_commands:
            severity_counts[command.severity] = severity_counts.get(command.severity, 0) + 1
        for permission in flagged_permissions:
            severity_counts[permission.severity] = severity_counts.get(permission.severity, 0) + 1

        baseline_count = sum(1 for r in arguments.hardening_recommendations if r.is_baseline)
        finding_triggered_count = len(arguments.hardening_recommendations) - baseline_count

        ranked_commands = sorted(
            flagged_commands, key=lambda c: (_SEVERITY_RANK.get(c.severity, 99), -c.confidence)
        )
        ranked_permissions = sorted(
            flagged_permissions, key=lambda p: (_SEVERITY_RANK.get(p.severity, 99), -p.confidence)
        )

        return LinuxSecurityAdvisoryOutput(
            command_count=len(arguments.commands),
            permission_count=len(arguments.permissions),
            flagged_command_count=len(flagged_commands),
            flagged_permission_count=len(flagged_permissions),
            severity_counts=severity_counts,
            hardening_recommendation_count=len(arguments.hardening_recommendations),
            baseline_recommendation_count=baseline_count,
            finding_triggered_recommendation_count=finding_triggered_count,
            overall_risk_level=arguments.overall_risk_level,
            overall_confidence=arguments.overall_confidence,
            overall_explanation=arguments.overall_explanation,
            skipped_line_count=arguments.skipped_line_count,
            top_command_findings=tuple(ranked_commands[: arguments.top_n]),
            top_permission_findings=tuple(ranked_permissions[: arguments.top_n]),
        )
