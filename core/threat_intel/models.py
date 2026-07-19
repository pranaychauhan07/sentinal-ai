"""Canonical threat-intelligence schema — the Threat Intelligence & IOC
Extraction Framework's typed contracts (docs/adr/0012-threat-intelligence-
ioc-extraction-framework-shape.md). Every extractor, validator, normalizer,
rule engine, scorer, and classifier in `core/threat_intel` reads and returns
only these shapes (constitution §1.2).

Deliberately its own `Severity`-equivalent (`ThreatSeverity`), not a reuse of
`core.parsers.models.Severity` — a sibling leaf's model is a genuinely
different concept here (an IOC's assessed threat severity vs. a single log
event's severity) and constitution §3 forbids importing a shared concept
sideways between sibling leaves without a documented owner; each package
owns its own severity scale.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IOCType(StrEnum):
    """Closed set of indicator-of-compromise types this framework extracts,
    validates, and scores (task requirement: twenty IOC types)."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL = "email"
    SHA1 = "sha1"
    SHA256 = "sha256"
    MD5 = "md5"
    FILE_NAME = "file_name"
    USERNAME = "username"
    PROCESS_NAME = "process_name"
    REGISTRY_KEY = "registry_key"
    PORT = "port"
    SERVICE = "service"
    MUTEX = "mutex"
    SCHEDULED_TASK = "scheduled_task"
    COMMAND_LINE = "command_line"
    USER_AGENT = "user_agent"
    CERTIFICATE_FINGERPRINT = "certificate_fingerprint"


class ThreatSeverity(StrEnum):
    """Assessed severity of one IOC/finding — the Threat Intelligence
    Layer's own severity scale (see module docstring for why it is not
    shared with `core.parsers.models.Severity`)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceReliability(StrEnum):
    """Admiralty-scale-inspired reliability of the evidence source an IOC
    was extracted from — one of the Threat Scoring Engine's required
    dimensions (task requirement: "Source Reliability")."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class ThreatCategory(StrEnum):
    """Closed set of classification outcomes the Threat Classification
    Engine assigns. Deliberately not a MITRE technique ID — MITRE mapping is
    explicitly out of scope for this framework (ADR-0012)."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class RuleType(StrEnum):
    """Closed set of detection-rule strategies the Detection Rule Engine
    supports (task requirement: pattern/regex/threshold/composable rules)."""

    PATTERN = "pattern"
    REGEX = "regex"
    THRESHOLD = "threshold"
    COMPOSITE = "composite"


class ThresholdOperator(StrEnum):
    """Comparison operator a `THRESHOLD`-type `DetectionRule` evaluates its
    observed count against."""

    GREATER_THAN_OR_EQUAL = "gte"
    GREATER_THAN = "gt"
    EQUAL = "eq"


class CompositeOperator(StrEnum):
    """Boolean combinator a `COMPOSITE`-type `DetectionRule` applies across
    its `composite_rule_ids`."""

    AND = "and"
    OR = "or"


class IOCRecord(BaseModel):
    """One extracted, (eventually) validated/normalized indicator of
    compromise. Mirrors `core.parsers.models.EvidenceRecord`'s shape: one
    per-item model, immutable, carrying its own confidence and provenance so
    it never has to be re-derived from a container."""

    model_config = ConfigDict(frozen=True)

    ioc_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    ioc_type: IOCType
    value: str
    raw_value: str
    evidence_id: uuid.UUID | None = None
    source: str
    line_number: int | None = None
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    severity: ThreatSeverity = ThreatSeverity.INFO
    context: dict[str, Any] = Field(default_factory=dict)
    tags: tuple[str, ...] = ()


class RuleMatchResult(BaseModel):
    """One `DetectionRule` evaluation outcome against one `IOCRecord` (or
    the whole candidate set, for `THRESHOLD`/`COMPOSITE` rules)."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_name: str
    matched: bool
    ioc_id: uuid.UUID | None = None
    matched_value: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    detail: str = ""


class ThreatScore(BaseModel):
    """The Threat Scoring Engine's output for one `IOCRecord` — every
    dimension the task requires (confidence/severity/impact/likelihood/
    evidence quality/source reliability/rule matches) plus the composite
    0-100 score every downstream consumer actually sorts/filters on."""

    model_config = ConfigDict(frozen=True)

    confidence: float = Field(ge=0.0, le=1.0)
    severity_weight: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=1.0)
    likelihood: float = Field(ge=0.0, le=1.0)
    evidence_quality: float = Field(ge=0.0, le=1.0)
    source_reliability: float = Field(ge=0.0, le=1.0)
    rule_match_score: float = Field(ge=0.0, le=1.0)
    composite_score: float = Field(ge=0.0, le=100.0)


class IOCClassification(BaseModel):
    """The Threat Classification Engine's output for one `IOCRecord`."""

    model_config = ConfigDict(frozen=True)

    category: ThreatCategory
    reason: str
    matched_rule_ids: tuple[str, ...] = ()


class AttributionRecord(BaseModel):
    """Evidence Attribution Layer output — ties one IOC back to the exact
    evidence artifact/line(s) it was observed in, the explainability trail
    blueprint §1 requires ("every step justified in plain language")."""

    model_config = ConfigDict(frozen=True)

    ioc_id: uuid.UUID
    evidence_id: uuid.UUID | None
    source: str
    line_numbers: tuple[int, ...] = ()
    occurrence_count: int = 1
    first_seen: datetime
    last_seen: datetime


class ScoredIOC(BaseModel):
    """One fully-processed IOC — the record every pipeline stage after
    `score` operates on and what `IOCExtractionPipeline.persist` writes."""

    model_config = ConfigDict(frozen=True)

    record: IOCRecord
    rule_matches: tuple[RuleMatchResult, ...] = ()
    score: ThreatScore
    classification: IOCClassification
    attribution: AttributionRecord


class NormalizedThreatIntel(BaseModel):
    """The Threat Intelligence Layer's one output contract for a single
    evidence artifact — mirrors `core.parsers.models.NormalizedEvidence`'s
    "per-artifact container" shape. Never silently drops a candidate: a
    candidate that failed validation is recorded in
    `rejected_candidates`, never discarded (constitution §1.7)."""

    model_config = ConfigDict(frozen=True)

    result_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    evidence_id: uuid.UUID | None
    source: str
    extractor_name: str
    extractor_version: str
    iocs: tuple[ScoredIOC, ...] = ()
    rejected_candidates: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def ioc_count(self) -> int:
        return len(self.iocs)


class DetectionRule(BaseModel):
    """One detection rule the Detection Rule Engine evaluates. Field naming
    is deliberately Sigma-adjacent (`rule_id`≈`id`, `name`≈`title`,
    `severity`≈`level`, `enabled`≈`status`) so a future Sigma-rule importer
    can map onto this shape without a redesign (task requirement: "Future
    Sigma rule compatibility"; ADR-0012 scopes this no further than that)."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    name: str
    description: str = ""
    rule_type: RuleType
    version: str = "1.0.0"
    priority: int = 0
    enabled: bool = True
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    tags: tuple[str, ...] = ()

    # PATTERN: a literal/glob-style substring matched against an IOC value
    #  or the evidence raw line.
    pattern: str | None = None
    # REGEX: validated for catastrophic-backtracking risk at registration
    #  time (core/threat_intel/rule_validation.py::validate_regex_safety).
    regex: str | None = None
    ioc_types: tuple[IOCType, ...] = ()

    # THRESHOLD: flag when the observed count of a given IOC type/value
    #  within one extraction run meets `threshold_operator threshold_value`.
    threshold_ioc_type: IOCType | None = None
    threshold_operator: ThresholdOperator | None = None
    threshold_value: int | None = None

    # COMPOSITE: boolean combination of other registered rules' results.
    composite_operator: CompositeOperator | None = None
    composite_rule_ids: tuple[str, ...] = ()

    metadata: dict[str, Any] = Field(default_factory=dict)


class IOCQuery(BaseModel):
    """The lookup key a `ThreatIntelProvider`/`IOCEnrichmentProvider`
    receives — a stable, minimal shape independent of `IOCRecord`'s full
    pipeline-internal fields (interfaces.py, unimplemented providers)."""

    model_config = ConfigDict(frozen=True)

    ioc_type: IOCType
    value: str


class ProviderLookupResult(BaseModel):
    """What a `ThreatIntelProvider.lookup()` would return, once a concrete
    provider exists (none does yet — ADR-0012 scope cut)."""

    model_config = ConfigDict(frozen=True)

    provider_name: str
    ioc_type: IOCType
    value: str
    found: bool
    reputation_score: float | None = Field(default=None, ge=0.0, le=100.0)
    tags: tuple[str, ...] = ()
    raw_response: dict[str, Any] = Field(default_factory=dict)
    looked_up_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EnrichmentResult(BaseModel):
    """What an `IOCEnrichmentProvider.enrich()` would return, once a
    concrete enrichment provider exists (none does yet — ADR-0012 scope
    cut)."""

    model_config = ConfigDict(frozen=True)

    provider_name: str
    ioc_id: uuid.UUID
    enrichment: dict[str, Any] = Field(default_factory=dict)
    enriched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
