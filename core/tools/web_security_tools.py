"""``WebSecurityAdvisoryTool`` — the Web Security Agent's deterministic
aggregation tool (`docs/adr/0020-owasp-web-security-agent.md`).

Combines *already-computed* `core.owasp_web.models.OwaspFinding` data
(produced by `core.services.web_security_service.assess_http_transaction`,
never recomputed here) into a case-level summary: counts by OWASP category
and severity, and the overall risk verdict. This tool never re-derives a
severity, confidence, or risk score itself (constitution §1.9) — it only
aggregates.

Input is plain `dict`/primitive data, not typed
`core.owasp_web.models.OwaspFinding` objects: `core/tools` has no
dependency-rules.md import edge onto `core/owasp_web` in the direction that
would matter here — matching `core/tools/linux_tools.py`'s identical "why
input stays dict-shaped" precedent for `core.agents.linux_security_agent`.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from core.tools.base import BaseTool

#: Deterministic severity ranking, most severe first — matches
#: `core.owasp_web.models.WebSecuritySeverity`'s five values by string value
#: (duplicated here rather than imported, mirroring `core/tools/
#: linux_tools.py`'s established "duplicate a small ranking table rather
#: than import a leaf-sibling's enum" precedent).
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

DEFAULT_TOP_N = 5


class OwaspFindingSummaryInput(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: str
    severity: str = "info"
    confidence: float = 1.0
    explanation: str = ""
    evidence_reference: str = ""
    recommended_remediation: str = ""
    source: str = ""


class WebSecurityAdvisoryInput(BaseModel):
    """The evidence's full set of already-computed `OwaspFinding` summaries,
    plus the already-computed overall verdict — every field here is a value
    `core.owasp_web.advisory_engine.WebSecurityAdvisoryEngine` already
    computed."""

    model_config = ConfigDict(frozen=True)

    findings: list[OwaspFindingSummaryInput] = Field(default_factory=list)
    overall_risk_level: str = "info"
    overall_confidence: float = 1.0
    overall_explanation: str = ""
    skipped_line_count: int = 0
    top_n: int = Field(default=DEFAULT_TOP_N, ge=1)


class WebSecurityAdvisoryOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_count: int = 0
    category_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    overall_risk_level: str = "info"
    overall_confidence: float = 1.0
    overall_explanation: str = ""
    skipped_line_count: int = 0
    top_findings: tuple[OwaspFindingSummaryInput, ...] = ()


class WebSecurityAdvisoryTool(BaseTool[WebSecurityAdvisoryInput, WebSecurityAdvisoryOutput]):
    """Deterministic, no-I/O — never retried (constitution §5/§4.8). Given
    the same input, always returns the same output."""

    name: ClassVar[str] = "web_security_advisory_summary"
    description: ClassVar[str] = (
        "Aggregates already-analyzed OWASP-mapped HTTP security findings "
        "into a case-level advisory summary."
    )
    is_io_bound: ClassVar[bool] = False

    def run(self, arguments: WebSecurityAdvisoryInput) -> WebSecurityAdvisoryOutput:
        category_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        for finding in arguments.findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        ranked = sorted(
            arguments.findings,
            key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), -f.confidence),
        )

        return WebSecurityAdvisoryOutput(
            finding_count=len(arguments.findings),
            category_counts=category_counts,
            severity_counts=severity_counts,
            overall_risk_level=arguments.overall_risk_level,
            overall_confidence=arguments.overall_confidence,
            overall_explanation=arguments.overall_explanation,
            skipped_line_count=arguments.skipped_line_count,
            top_findings=tuple(ranked[: arguments.top_n]),
        )
