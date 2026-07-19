"""Canonical Finding & MITRE mapping schema — the Finding & MITRE ATT&CK
Intelligence Engine's typed contracts
(docs/adr/0013-finding-mitre-intelligence-engine-shape.md). Every mapping
engine, aggregator, confidence engine, severity assigner, and dedup engine
in `core/findings` reads and returns only these shapes (constitution §1.2).

Deliberately its own `FindingSeverity` scale, not a reuse of
`core.threat_intel.models.ThreatSeverity` — a sibling leaf's model is a
genuinely different concept here (a Finding's assessed severity vs. a single
IOC's assessed severity) and constitution §3 forbids importing a shared
concept sideways between sibling leaves without a documented owner; each
package owns its own severity scale, matching the precedent
`core/threat_intel/models.py` already set relative to `core/parsers`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingSeverity(StrEnum):
    """Assessed severity of one Finding — this package's own severity scale
    (see module docstring for why it is not shared with
    `core.threat_intel.models.ThreatSeverity`)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    """Lifecycle state of one Finding — distinct from `FindingPriority`
    (a `CLOSED` finding still carries whatever priority it was assigned)."""

    OPEN = "open"
    MERGED = "merged"
    CLOSED = "closed"


class FindingPriority(StrEnum):
    """Analyst triage priority, derived from severity + confidence but kept
    as its own field (task requirement: "Priority" distinct from
    "Severity") — a HIGH-severity, low-confidence Finding may still triage
    below a MEDIUM-severity, high-confidence one."""

    P1_CRITICAL = "p1_critical"
    P2_HIGH = "p2_high"
    P3_MEDIUM = "p3_medium"
    P4_LOW = "p4_low"


class DedupDecision(StrEnum):
    """What the Deduplication Engine decided for one candidate Finding."""

    NEW = "new"
    MERGE = "merge"


class MappingConfidenceFactors(BaseModel):
    """The raw inputs the Confidence Engine folds into one `MitreMapping`'s
    confidence — kept as its own small model so a caller can inspect *why*
    a mapping scored the way it did without re-deriving the inputs
    (constitution §1.2, "explicit is better than implicit")."""

    model_config = ConfigDict(frozen=True)

    rule_strength: float = Field(ge=0.0, le=1.0)
    ioc_confidence: float = Field(ge=0.0, le=1.0)
    evidence_quality: float = Field(ge=0.0, le=1.0)
    supporting_indicator_count: int = Field(ge=0)


class MitreMapping(BaseModel):
    """One ATT&CK technique a Finding has been mapped to, with the
    confidence and provenance of that mapping. A single Finding may carry
    several of these (one-IOC-to-many-techniques or many-IOCs-to-one-
    technique, task requirement)."""

    model_config = ConfigDict(frozen=True)

    technique_id: str
    tactic_ids: tuple[str, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0)
    mapping_source: str
    attack_spec_version: str
    supporting_ioc_ids: tuple[uuid.UUID, ...] = ()
    factors: MappingConfidenceFactors


class TimelineEntry(BaseModel):
    """One chronological event in a Finding's reconstructed timeline —
    deliberately minimal (task requirement: "Timeline reconstruction"
    within one case's evidence, never cross-case correlation)."""

    model_config = ConfigDict(frozen=True)

    occurred_at: datetime
    ioc_id: uuid.UUID | None = None
    evidence_id: uuid.UUID | None = None
    description: str


class EvidenceBundle(BaseModel):
    """The aggregated evidence backing one candidate Finding — IOC/evidence
    references, the reconstructed timeline, and affected hosts. Preserves
    chain of custody by carrying forward IDs only; it never copies or
    re-derives the underlying `ScoredIOC`/`AttributionRecord` content
    (task requirement: "Chain of custody preservation")."""

    model_config = ConfigDict(frozen=True)

    ioc_ids: tuple[uuid.UUID, ...] = ()
    evidence_ids: tuple[uuid.UUID, ...] = ()
    affected_assets: tuple[str, ...] = ()
    timeline: tuple[TimelineEntry, ...] = ()
    first_seen: datetime
    last_seen: datetime


class FindingConfidence(BaseModel):
    """The Confidence Engine's output for one Finding — every dimension the
    task requires (IOC quality, evidence quality, supporting-indicator
    count, rule strength, mapping quality, source reliability, historical
    evidence) plus the composite 0.0-1.0 value every downstream consumer
    (UI, `FindingRecord.confidence`) actually reads."""

    model_config = ConfigDict(frozen=True)

    ioc_quality: float = Field(ge=0.0, le=1.0)
    evidence_quality: float = Field(ge=0.0, le=1.0)
    supporting_indicator_score: float = Field(ge=0.0, le=1.0)
    rule_strength: float = Field(ge=0.0, le=1.0)
    mapping_quality: float = Field(ge=0.0, le=1.0)
    source_reliability: float = Field(ge=0.0, le=1.0)
    historical_evidence: float = Field(ge=0.0, le=1.0)
    composite: float = Field(ge=0.0, le=1.0)


class DuplicateMatchResult(BaseModel):
    """The Deduplication Engine's decision for one candidate Finding against
    the case's existing open Findings."""

    model_config = ConfigDict(frozen=True)

    decision: DedupDecision
    matched_finding_id: uuid.UUID | None = None
    similarity_score: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_dimensions: dict[str, float] = Field(default_factory=dict)
    reason: str = ""


class FindingRecord(BaseModel):
    """One fully-generated Finding — the record every pipeline stage after
    `generate` operates on and what `finding_service.persist` writes."""

    model_config = ConfigDict(frozen=True)

    finding_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    case_id: uuid.UUID
    title: str
    description: str
    severity: FindingSeverity
    confidence: FindingConfidence
    status: FindingStatus = FindingStatus.OPEN
    priority: FindingPriority
    evidence_refs: tuple[uuid.UUID, ...] = ()
    ioc_refs: tuple[uuid.UUID, ...] = ()
    mitre_mappings: tuple[MitreMapping, ...] = ()
    timeline: tuple[TimelineEntry, ...] = ()
    affected_assets: tuple[str, ...] = ()
    risk_score: float = Field(ge=0.0, le=100.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def mapped_technique_ids(self) -> tuple[str, ...]:
        return tuple(mapping.technique_id for mapping in self.mitre_mappings)
