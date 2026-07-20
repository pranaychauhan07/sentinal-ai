"""`LinuxSecurityAssessmentTool` — the Threat Hunting Agent's deterministic
aggregation tool (mirrors `core.tools.vuln_tools.VulnerabilityAssessmentTool`
exactly).

Combines *already-computed* per-finding data (category, severity, composite
score — all produced by
`core.services.linux_security_service.LinuxSecurityPipeline`, never
recomputed here) into a case/evidence-level summary: counts by category and
severity, the highest composite score observed, and a top-N list. This tool
never re-derives a detection, confidence, or risk score itself (constitution
§1.9) — it only aggregates.

Input is plain `dict`/primitive data, not typed
`core.linux_security.models.LinuxSecurityFinding` objects: `core/tools` has
no dependency-rules.md import edge onto `core/linux_security` (the same
reasoning `core/tools/vuln_tools.py`'s docstring documents for why its input
stays dict-shaped rather than a typed `core.vulnerabilities.models.
VulnerabilityFinding`).
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.tools.base import BaseTool

#: Deterministic severity ranking, most urgent first — matches
#: `core.linux_security.models.LinuxSecuritySeverity`'s five values by
#: string value (duplicated here rather than imported, since `core/tools`
#: has no import edge onto `core/linux_security`).
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

#: Default number of highest-severity findings surfaced in the summary.
DEFAULT_TOP_N = 5


class LinuxSecurityFindingSummaryInput(BaseModel):
    """One already-generated finding's plain-dict view — every field here
    is a value `LinuxSecurityPipeline` already computed; this model performs
    no validation beyond typing (constitution §1.9: aggregation, not
    judgment)."""

    model_config = ConfigDict(frozen=True)

    category: str = "unauthorized_account_activity"
    subject: str = ""
    subject_type: str = "host"
    title: str = ""
    severity: str = "info"
    composite_score: float = 0.0
    occurrence_count: int = 1


class LinuxSecurityAssessmentInput(BaseModel):
    """The case/evidence's full set of already-generated findings."""

    model_config = ConfigDict(frozen=True)

    findings: list[LinuxSecurityFindingSummaryInput] = Field(default_factory=list)
    top_n: int = Field(default=DEFAULT_TOP_N, ge=1)


class LinuxSecurityAssessmentOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_count: int
    category_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    highest_composite_score: float = 0.0
    distinct_subject_count: int = 0
    top_findings: tuple[LinuxSecurityFindingSummaryInput, ...] = ()


class LinuxSecurityAssessmentTool(
    BaseTool[LinuxSecurityAssessmentInput, LinuxSecurityAssessmentOutput]
):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input, always returns the same output."""

    name: ClassVar[str] = "linux_security_assessment_summary"
    description: ClassVar[str] = (
        "Aggregates already-scored Linux security findings into a case-level "
        "summary: counts by category/severity, highest composite score, and "
        "the top-N highest-severity findings."
    )
    is_io_bound: ClassVar[bool] = False

    def run(self, arguments: LinuxSecurityAssessmentInput) -> LinuxSecurityAssessmentOutput:
        findings = arguments.findings
        if not findings:
            return LinuxSecurityAssessmentOutput(finding_count=0)

        category_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        for finding in findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        highest_score = max(f.composite_score for f in findings)
        distinct_subjects = {f.subject for f in findings if f.subject}

        ranked = sorted(
            findings,
            key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), -f.composite_score),
        )
        top_findings = tuple(ranked[: arguments.top_n])

        return LinuxSecurityAssessmentOutput(
            finding_count=len(findings),
            category_counts=category_counts,
            severity_counts=severity_counts,
            highest_composite_score=highest_score,
            distinct_subject_count=len(distinct_subjects),
            top_findings=top_findings,
        )
