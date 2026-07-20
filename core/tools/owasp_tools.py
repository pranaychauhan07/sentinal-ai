"""``OwaspSecurityAssessmentTool`` — blueprint §7's named `owasp_tools.py`:
the OWASP Security Agent's deterministic aggregation tool.

Combines *already-computed* `core.owasp_security.models.SastFinding` data
(produced by `core.services.owasp_security_service.assess_source_code`,
never recomputed here) into a case-level summary: counts by OWASP category/
CWE/severity, and the overall risk verdict. This tool never re-derives a
severity, confidence, or risk score itself (constitution §1.9) — it only
aggregates.

Input is plain `dict`/primitive data, not typed
`core.owasp_security.models.SastFinding` objects: `core/tools` has no
dependency-rules.md import edge onto `core/owasp_security` in the direction
that would matter here — matching `core/tools/web_security_tools.py`'s
identical "why input stays dict-shaped" precedent.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.tools.base import BaseTool

#: Deterministic severity ranking, most severe first — matches
#: `core.owasp_security.models.SastSeverity`'s five values by string value
#: (duplicated here rather than imported, mirroring
#: `core/tools/web_security_tools.py`'s established precedent).
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

DEFAULT_TOP_N = 5


class SastFindingSummaryInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: str
    owasp_category: str = ""
    cwe_id: str = ""
    severity: str = "info"
    confidence: float = 1.0
    explanation: str = ""
    evidence_reference: str = ""
    recommended_remediation: str = ""
    source: str = ""


class OwaspSecurityAssessmentInput(BaseModel):
    """The evidence's full set of already-computed `SastFinding` summaries,
    plus the already-computed overall verdict — every field here is a value
    `core.owasp_security.analysis_engine.SourceCodeAnalysisEngine` already
    computed."""

    model_config = ConfigDict(frozen=True)

    language: str = "unknown"
    findings: list[SastFindingSummaryInput] = Field(default_factory=list)
    overall_risk_level: str = "info"
    overall_confidence: float = 1.0
    overall_explanation: str = ""
    parse_degraded: bool = False
    top_n: int = Field(default=DEFAULT_TOP_N, ge=1)


class OwaspSecurityAssessmentOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    language: str = "unknown"
    finding_count: int = 0
    category_counts: dict[str, int] = Field(default_factory=dict)
    cwe_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    overall_risk_level: str = "info"
    overall_confidence: float = 1.0
    overall_explanation: str = ""
    parse_degraded: bool = False
    top_findings: tuple[SastFindingSummaryInput, ...] = ()


class OwaspSecurityAssessmentTool(
    BaseTool[OwaspSecurityAssessmentInput, OwaspSecurityAssessmentOutput]
):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input, always returns the same output."""

    name: ClassVar[str] = "owasp_security_assessment_summary"
    description: ClassVar[str] = (
        "Aggregates already-analyzed AST/pattern-based SAST findings into a "
        "case-level OWASP/CWE-mapped advisory summary."
    )
    is_io_bound: ClassVar[bool] = False

    def run(self, arguments: OwaspSecurityAssessmentInput) -> OwaspSecurityAssessmentOutput:
        category_counts: dict[str, int] = {}
        cwe_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        for finding in arguments.findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
            if finding.cwe_id:
                cwe_counts[finding.cwe_id] = cwe_counts.get(finding.cwe_id, 0) + 1
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        ranked = sorted(
            arguments.findings,
            key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), -f.confidence),
        )

        return OwaspSecurityAssessmentOutput(
            language=arguments.language,
            finding_count=len(arguments.findings),
            category_counts=category_counts,
            cwe_counts=cwe_counts,
            severity_counts=severity_counts,
            overall_risk_level=arguments.overall_risk_level,
            overall_confidence=arguments.overall_confidence,
            overall_explanation=arguments.overall_explanation,
            parse_degraded=arguments.parse_degraded,
            top_findings=tuple(ranked[: arguments.top_n]),
        )
