"""Canonical vulnerability schema — the Vulnerability Assessment Framework's
typed contracts (docs/adr/0017-vulnerability-assessment-framework.md). Every
extractor, validator, normalizer, dedup/correlation/scoring engine, and
finding generator in `core/vulnerabilities` reads and returns only these
shapes (constitution §1.2).

Deliberately its own `VulnerabilitySeverity`, not a reuse of
`core.parsers.models.Severity` or `core.threat_intel.models.ThreatSeverity`
— matching the identical, already-established precedent
`core.threat_intel.models.ThreatSeverity`'s and
`core.findings.models.FindingSeverity`'s own docstrings state: each leaf
package owns its own severity scale, mapped explicitly at translation
points (see `core.vulnerabilities.severity`).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.knowledge.cvss_calculator import CvssScore


class VulnerabilitySeverity(StrEnum):
    """This package's own severity scale (see module docstring)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityPriority(StrEnum):
    """Analyst triage priority — severity-dominant, asset-criticality-
    adjusted (mirrors `core.findings.models.FindingPriority`'s shape)."""

    P1_CRITICAL = "p1_critical"
    P2_HIGH = "p2_high"
    P3_MEDIUM = "p3_medium"
    P4_LOW = "p4_low"


class AssetCriticality(StrEnum):
    """How business-critical the affected asset is — one of the Threat
    Scoring Engine's required dimensions (task requirement: "Asset
    Criticality"). Defaults to `MEDIUM` when no case-specific asset
    inventory exists (no such inventory is built by this framework)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionSource(StrEnum):
    """Closed set of scan-report origins this framework parses."""

    NESSUS = "nessus"
    OPENVAS = "openvas"


class SourceReliability(StrEnum):
    """Admiralty-scale-inspired reliability of the scan-report source — one
    of the Threat Scoring Engine's required dimensions (task requirement:
    "Source Reliability"). Deliberately its own enum rather than reusing
    `core.threat_intel.models.SourceReliability` sideways (same leaf-
    ownership reasoning as `VulnerabilitySeverity`)."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class VulnerabilityRecord(BaseModel):
    """One extracted, (eventually) validated/normalized vulnerability
    finding from a scan report. Mirrors `core.threat_intel.models.IOCRecord`'s
    shape: one per-item model, immutable, carrying its own confidence and
    provenance so it never has to be re-derived from a container.

    A single scan-report row commonly carries *both* a CVSS v2 and a CVSS
    v3 score simultaneously (Nessus exports both `cvss_base_score` and
    `cvss3_base_score` columns unconditionally) — all three CVSS slots are
    therefore independent and optional, not a single "the" CVSS field.
    """

    model_config = ConfigDict(frozen=True)

    vuln_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    cve_id: str | None = None
    cwe_ids: tuple[str, ...] = ()
    plugin_id: str | None = None
    plugin_name: str = ""
    host: str | None = None
    asset_id: str | None = None
    ip_address: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    description: str = ""
    references: tuple[str, ...] = ()
    severity: VulnerabilitySeverity = VulnerabilitySeverity.INFO
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    detection_source: DetectionSource
    cvss_v2: CvssScore | None = None
    cvss_v3: CvssScore | None = None
    cvss_v4: CvssScore | None = None
    evidence_id: uuid.UUID | None = None
    source: str = ""
    line_number: int | None = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tags: tuple[str, ...] = ()
    context: dict[str, Any] = Field(default_factory=dict)

    @property
    def best_cvss(self) -> CvssScore | None:
        """Deterministic priority when more than one CVSS version is
        present: v3.x first (the industry-current standard), then v2, then
        v4.0 last (its `base_score` is always `None` in this framework —
        see `core.knowledge.cvss_calculator`'s module docstring — so it is
        only useful as a severity-tiebreak of last resort)."""
        return self.cvss_v3 or self.cvss_v2 or self.cvss_v4


class VulnerabilityScore(BaseModel):
    """The Threat Scoring Engine's output for one `VulnerabilityRecord` —
    every dimension the task requires (CVSS/severity/confidence/asset
    criticality/source reliability/evidence quality) plus the composite
    0-100 score every downstream consumer sorts/filters on. Mirrors
    `core.threat_intel.models.ThreatScore`'s shape."""

    model_config = ConfigDict(frozen=True)

    cvss_component: float = Field(ge=0.0, le=1.0)
    severity_weight: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    asset_criticality: float = Field(ge=0.0, le=1.0)
    source_reliability: float = Field(ge=0.0, le=1.0)
    evidence_quality: float = Field(ge=0.0, le=1.0)
    composite_score: float = Field(ge=0.0, le=100.0)


class AssetCorrelation(BaseModel):
    """Deterministic grouping of `VulnerabilityRecord`s that affect the same
    asset (task requirement: "Asset Correlation") — a pure aggregation, no
    LLM judgment involved in the grouping itself."""

    model_config = ConfigDict(frozen=True)

    asset_id: str
    host: str | None = None
    ip_address: str | None = None
    vuln_ids: tuple[uuid.UUID, ...] = ()
    highest_severity: VulnerabilitySeverity = VulnerabilitySeverity.INFO


class ScoredVulnerability(BaseModel):
    """One fully-processed vulnerability — the record every pipeline stage
    after `score` operates on, mirrors `core.threat_intel.models.ScoredIOC`."""

    model_config = ConfigDict(frozen=True)

    record: VulnerabilityRecord
    score: VulnerabilityScore
    priority: VulnerabilityPriority
    occurrence_count: int = 1


class VulnerabilityFinding(BaseModel):
    """A case-level aggregation of one or more `ScoredVulnerability`
    entries sharing the same CVE (or, absent a CVE, the same plugin) across
    however many assets it was observed on. Deliberately carries no
    remediation/recommendation field — remediation planning is explicitly
    out of scope for this framework (see module docstring / ADR-0017).

    Not persisted to the shared `findings` DB table — mirrors
    `core.agents.soc_analyst_agent.SocFinding`'s and
    `core.agents.phishing_agent.PhishingVerdict`'s identical, already-
    documented scoping decision (ADR-0014 point 4, reaffirmed ADR-0016).
    """

    model_config = ConfigDict(frozen=True)

    finding_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    cve_id: str | None = None
    plugin_id: str | None = None
    title: str
    description: str = ""
    severity: VulnerabilitySeverity
    priority: VulnerabilityPriority
    composite_score: float = Field(ge=0.0, le=100.0)
    affected_asset_ids: tuple[str, ...] = ()
    vuln_ids: tuple[uuid.UUID, ...] = ()
    references: tuple[str, ...] = ()


class NormalizedVulnerabilityIntel(BaseModel):
    """The Vulnerability Assessment Framework's one output contract for a
    single evidence artifact — mirrors
    `core.threat_intel.models.NormalizedThreatIntel`'s "per-artifact
    container" shape. Never silently drops a candidate: a candidate that
    failed validation is recorded in `rejected_candidates`, never discarded
    (constitution §1.7)."""

    model_config = ConfigDict(frozen=True)

    result_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    evidence_id: uuid.UUID | None
    source: str
    extractor_name: str
    extractor_version: str
    vulnerabilities: tuple[ScoredVulnerability, ...] = ()
    findings: tuple[VulnerabilityFinding, ...] = ()
    asset_correlations: tuple[AssetCorrelation, ...] = ()
    rejected_candidates: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities)
