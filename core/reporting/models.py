"""Canonical Report schema — every module in `core/reporting` reads and
returns only these shapes (constitution §1.2). No dictionaries, no untyped
objects as a public contract (task requirement: "every report must be
strongly typed").

`ReportType` is this package's own enum (not a reuse of any sibling leaf's
concept) but is deliberately the *canonical* definition `core/db/models/
report.py` imports for column typing — the same "DB imports a sibling leaf's
model" precedent `core/db/models/finding.py`
(`core.findings.models.FindingSeverity`) and `core/db/models/
incident_response_plan.py` (`core.incident_response.models.IncidentSeverity`)
already set (docs/adr/0024-report-generator-agent.md, Decision 4).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ReportType(StrEnum):
    """The task's eight named report types, plus the two original
    placeholder values (`module`/`executive`) preserved byte-for-byte from
    this enum's first (schema-only) definition in `core/db/models/report.py`
    — migrations are additive-only (constitution §7); no prior value is ever
    renamed or removed. `EXECUTIVE` already covers "Executive Summary";
    `MODULE` is legacy and unused going forward."""

    MODULE = "module"
    EXECUTIVE = "executive"
    TECHNICAL_INVESTIGATION = "technical_investigation"
    INCIDENT_RESPONSE = "incident_response"
    IOC_SUMMARY = "ioc_summary"
    MITRE_ATTACK = "mitre_attack"
    TIMELINE = "timeline"
    THREAT_INTELLIGENCE = "threat_intelligence"
    EVIDENCE = "evidence"


class ReportFormat(StrEnum):
    """Output formats this pipeline's models are shaped to support
    (blueprint §10/§16 — "structured report models suitable for future
    export to PDF/HTML/Markdown/JSON"). No exporter for any of these exists
    yet (task instruction: "implement only the backend models and generation
    pipeline... do not build exporters yet") — this enum documents the
    contract a future `core/reporting/pdf_builder.py`/`charts.py`/Jinja2
    template set will target, it is not itself an export capability."""

    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"


#: Every format this pipeline's output is already structured to support —
#: a `GeneratedReport` is format-agnostic (a typed tree of sections/
#: statistics), so every report supports every format equally until a
#: concrete exporter is built.
ALL_REPORT_FORMATS: tuple[ReportFormat, ...] = tuple(ReportFormat)


class ReportSectionType(StrEnum):
    """The task's exact named report content sections."""

    EXECUTIVE_SUMMARY = "executive_summary"
    CASE_OVERVIEW = "case_overview"
    INVESTIGATION_TIMELINE = "investigation_timeline"
    EVIDENCE_SUMMARY = "evidence_summary"
    IOC_SUMMARY = "ioc_summary"
    THREAT_INTELLIGENCE_SUMMARY = "threat_intelligence_summary"
    MITRE_MAPPING = "mitre_mapping"
    FINDINGS = "findings"
    INCIDENT_RESPONSE_ACTIONS = "incident_response_actions"
    RISK_ASSESSMENT = "risk_assessment"
    RECOMMENDATIONS = "recommendations"
    APPENDIX = "appendix"


class ReportSection(BaseModel):
    """One generated section — a `section_type` (the task's named kind), a
    human-readable `title`, and a `content` payload. `content` stays a plain
    `dict[str, object]` (mirroring every other leaf package's `*_records`
    dict-shaped convention for aggregating already-computed, heterogeneous
    upstream data — constitution §1.9: this package never re-derives a
    severity/score/mapping, only aggregates values other subsystems already
    computed) rather than one bespoke Pydantic model per section type, which
    would multiply this package's type surface twelvefold for content that
    is fundamentally a display-oriented aggregation, not a new domain
    concept."""

    model_config = ConfigDict(frozen=True)

    section_type: ReportSectionType
    title: str
    content: dict[str, object] = Field(default_factory=dict)
    #: Explicit "nothing to show" flag — never fabricated placeholder
    #: content (constitution §1.7, "fail gracefully, not silently").
    is_empty: bool = False
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReportStatistics(BaseModel):
    """The task's named "Calculate Statistics" pipeline stage output —
    counts derived purely from the sections/context already assembled, never
    recomputed ad hoc by a caller (constitution §2, "a magic number/value
    that appears in two places will eventually be updated in only one")."""

    model_config = ConfigDict(frozen=True)

    finding_count: int = 0
    evidence_count: int = 0
    ioc_count: int = 0
    mitre_technique_count: int = 0
    vulnerability_count: int = 0
    linux_security_finding_count: int = 0
    linux_advisory_count: int = 0
    owasp_web_finding_count: int = 0
    owasp_security_finding_count: int = 0
    incident_response_recommendation_count: int = 0
    sections_generated_count: int = 0
    sections_empty_count: int = 0
    skipped_record_count: int = 0
    generation_duration_ms: float = 0.0


class ReportValidationResult(BaseModel):
    """The task's named "Validate Completeness" pipeline stage output.
    `is_complete` is `False` whenever a required section is missing/
    duplicated or every section came back empty — a degraded-but-returned
    report, never a silently-incomplete one masquerading as final
    (constitution §1.7)."""

    model_config = ConfigDict(frozen=True)

    is_complete: bool
    missing_section_types: tuple[ReportSectionType, ...] = ()
    duplicate_section_types: tuple[ReportSectionType, ...] = ()
    reasons: tuple[str, ...] = ()


class GeneratedReport(BaseModel):
    """The task's named `GeneratedReport` — this case's full, deterministic,
    reproducible report (blueprint §7's Report Generator Agent output). One
    canonical, ordered `sections` tuple is the single source of truth."""

    model_config = ConfigDict(frozen=True)

    report_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    case_id: str
    report_type: ReportType
    title: str
    sections: tuple[ReportSection, ...] = ()
    statistics: ReportStatistics = Field(default_factory=ReportStatistics)
    validation: ReportValidationResult
    supported_formats: tuple[ReportFormat, ...] = ALL_REPORT_FORMATS
    confidence: float = Field(ge=0.0, le=1.0)
    degraded: bool = False
    degraded_reasons: tuple[str, ...] = ()
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def section(self, section_type: ReportSectionType) -> ReportSection | None:
        """Look up one section by type — every `ReportSectionType` appears
        at most once per report (`completeness_validator.py` rejects a
        duplicate before a `GeneratedReport` is ever built), so this is
        never ambiguous."""
        for section in self.sections:
            if section.section_type is section_type:
                return section
        return None
