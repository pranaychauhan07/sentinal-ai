"""`VulnerabilityAssessmentTool` — blueprint §7's named `vuln_tools.py`:
the Vulnerability Assessment Agent's deterministic aggregation tool.

Combines *already-computed* per-finding data (severity, priority, CVSS
score, composite score — all produced by
`core.services.vulnerability_service.VulnerabilityPipeline`, never
recomputed here) into a case/evidence-level summary: counts by severity,
the highest composite score observed, and a top-N list by priority. This
tool never re-derives CVSS, severity, or a threat score itself
(constitution §1.9) — it only aggregates.

Input is plain `dict`/primitive data, not typed
`core.vulnerabilities.models.VulnerabilityFinding` objects: `core/tools` has
no dependency-rules.md import edge onto `core/vulnerabilities` (the same
reasoning `core/agents/phishing_agent.py`'s docstring documents for why
`PhishingScoringTool`'s input stays dict-shaped rather than a typed
`core.threat_intel.models.ScoredIOC`).
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.tools.base import BaseTool

#: Deterministic priority ranking, most urgent first — matches
#: `core.vulnerabilities.models.VulnerabilityPriority`'s four values by
#: string value (duplicated here rather than imported, since `core/tools`
#: has no import edge onto `core/vulnerabilities`).
_PRIORITY_RANK: dict[str, int] = {
    "p1_critical": 0,
    "p2_high": 1,
    "p3_medium": 2,
    "p4_low": 3,
}

#: Default number of highest-priority findings surfaced in the summary.
DEFAULT_TOP_N = 5


class VulnerabilityFindingSummaryInput(BaseModel):
    """One already-generated finding's plain-dict view — every field here
    is a value `VulnerabilityPipeline` already computed; this model performs
    no validation beyond typing (constitution §1.9: aggregation, not
    judgment)."""

    model_config = ConfigDict(frozen=True)

    cve_id: str | None = None
    plugin_id: str | None = None
    title: str = ""
    severity: str = "info"
    priority: str = "p4_low"
    composite_score: float = 0.0
    affected_asset_ids: tuple[str, ...] = ()


class VulnerabilityAssessmentInput(BaseModel):
    """The case/evidence's full set of already-generated findings, plus how
    many raw findings were rejected/deduplicated upstream (for a complete,
    honest summary — constitution §1.7)."""

    model_config = ConfigDict(frozen=True)

    findings: list[VulnerabilityFindingSummaryInput] = Field(default_factory=list)
    top_n: int = Field(default=DEFAULT_TOP_N, ge=1)


class VulnerabilityAssessmentOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_count: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    highest_composite_score: float = 0.0
    distinct_asset_count: int = 0
    top_findings: tuple[VulnerabilityFindingSummaryInput, ...] = ()


class VulnerabilityAssessmentTool(
    BaseTool[VulnerabilityAssessmentInput, VulnerabilityAssessmentOutput]
):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input, always returns the same output."""

    name: ClassVar[str] = "vulnerability_assessment_summary"
    description: ClassVar[str] = (
        "Aggregates already-scored vulnerability findings into a case-level "
        "summary: counts by severity, highest composite score, and the "
        "top-N highest-priority findings."
    )
    is_io_bound: ClassVar[bool] = False

    def run(self, arguments: VulnerabilityAssessmentInput) -> VulnerabilityAssessmentOutput:
        findings = arguments.findings
        if not findings:
            return VulnerabilityAssessmentOutput(finding_count=0)

        severity_counts: dict[str, int] = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        highest_score = max(f.composite_score for f in findings)
        distinct_assets = {asset_id for f in findings for asset_id in f.affected_asset_ids}

        ranked = sorted(
            findings,
            key=lambda f: (_PRIORITY_RANK.get(f.priority, 99), -f.composite_score),
        )
        top_findings = tuple(ranked[: arguments.top_n])

        return VulnerabilityAssessmentOutput(
            finding_count=len(findings),
            severity_counts=severity_counts,
            highest_composite_score=highest_score,
            distinct_asset_count=len(distinct_assets),
            top_findings=top_findings,
        )
