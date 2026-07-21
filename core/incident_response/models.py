"""Canonical Incident Response schema — every module in `core/incident_response`
reads and returns only these shapes (constitution §1.2). No dictionaries, no
untyped objects (task requirement).

Deliberately its own `IncidentSeverity` scale, not a reuse of
`core.parsers.models.Severity` or `core.findings.models.FindingSeverity` — a
sibling leaf's model is a genuinely different concept here (an incident's
*response-worthiness*, derived from many findings, vs. one artifact's or one
Finding's assessed severity) and constitution §3 forbids importing a shared
concept sideways between sibling leaves without a documented owner; each
package owns its own severity scale, matching the precedent
`core/findings/models.py::FindingSeverity`'s docstring already set relative
to `core/threat_intel`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IncidentSeverity(StrEnum):
    """This case's overall, response-planning-relevant severity — derived
    from the aggregated findings this agent reads, never copied from any one
    Finding's own severity field."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Deterministic rank, most severe first — mirrors every other leaf's
#: `severity_rank`-shaped helper (`core.owasp_security.models.severity_rank`).
_SEVERITY_RANK: dict[IncidentSeverity, int] = {
    IncidentSeverity.CRITICAL: 4,
    IncidentSeverity.HIGH: 3,
    IncidentSeverity.MEDIUM: 2,
    IncidentSeverity.LOW: 1,
    IncidentSeverity.INFO: 0,
}


def severity_rank(severity: IncidentSeverity) -> int:
    return _SEVERITY_RANK[severity]


def highest_severity(severities: list[IncidentSeverity]) -> IncidentSeverity:
    if not severities:
        return IncidentSeverity.INFO
    return max(severities, key=severity_rank)


class ResponsePriority(StrEnum):
    """Analyst triage priority for one `ResponseRecommendation` — distinct
    from `IncidentSeverity` (a case-level rollup) the same way
    `core.findings.models.FindingPriority` is distinct from
    `FindingSeverity`: a HIGH-severity, low-confidence recommendation may
    still triage below a CRITICAL one."""

    P1_IMMEDIATE = "p1_immediate"
    P2_URGENT = "p2_urgent"
    P3_HIGH = "p3_high"
    P4_MEDIUM = "p4_medium"
    P5_LOW = "p5_low"


_PRIORITY_RANK: dict[ResponsePriority, int] = {
    ResponsePriority.P1_IMMEDIATE: 0,
    ResponsePriority.P2_URGENT: 1,
    ResponsePriority.P3_HIGH: 2,
    ResponsePriority.P4_MEDIUM: 3,
    ResponsePriority.P5_LOW: 4,
}


def priority_rank(priority: ResponsePriority) -> int:
    """Lower rank = executes first (constitution §2, "Enums" — exhaustive,
    never a bare string comparison)."""
    return _PRIORITY_RANK[priority]


class ResponseCategory(StrEnum):
    """The task's exact named set of concrete response action kinds this
    package supports recommendations for."""

    HOST_ISOLATION = "host_isolation"
    NETWORK_BLOCKING = "network_blocking"
    ACCOUNT_DISABLEMENT = "account_disablement"
    PASSWORD_RESET = "password_reset"
    IOC_BLOCKING = "ioc_blocking"
    FIREWALL_UPDATE = "firewall_update"
    EDR_ACTION = "edr_action"
    PATCH_PRIORITIZATION = "patch_prioritization"
    SERVICE_SHUTDOWN = "service_shutdown"
    BACKUP_RESTORATION = "backup_restoration"
    EVIDENCE_PRESERVATION = "evidence_preservation"


class ResponsePhase(StrEnum):
    """The task's exact named NIST SP 800-61-aligned response phases this
    package generates plans for."""

    CONTAINMENT = "containment"
    ISOLATION = "isolation"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    VALIDATION = "validation"
    POST_INCIDENT = "post_incident"


class ResponseTimeframe(StrEnum):
    """Blueprint's Response Planning ask: "Immediate actions, Short-term
    remediation, Long-term hardening" — a dimension distinct from
    `ResponsePhase` (a CONTAINMENT-phase action can be either immediate or
    short-term depending on the triggering finding's severity)."""

    IMMEDIATE = "immediate"
    SHORT_TERM = "short_term"
    LONG_TERM = "long_term"


class ResponseEvidence(BaseModel):
    """One piece of evidence a `ResponseRecommendation` cites as its basis —
    the task's named "Required evidence" field, kept as its own small model
    so a caller can inspect provenance without re-deriving it (constitution
    §1.2)."""

    model_config = ConfigDict(frozen=True)

    finding_id: str = ""
    source: str = ""
    description: str = ""


class ResponseAction(BaseModel):
    """One concrete, categorized action — the task's named `ResponseAction`
    model. Deliberately carries no priority/confidence/ordering of its own;
    those are `ResponseRecommendation`'s job (a `ResponseAction` is the
    "what," a `ResponseRecommendation` is the "what, and why, and how
    urgently")."""

    model_config = ConfigDict(frozen=True)

    category: ResponseCategory
    phase: ResponsePhase
    title: str
    description: str
    #: The concrete subject this action targets, if known from the
    #: triggering finding (a hostname, account, IP, service name) — empty
    #: when the finding carried no such identifier.
    target: str = ""


class ResponseRecommendation(BaseModel):
    """One fully-specified recommendation — the task's exact named field
    list: "Priority, Confidence, Required evidence, Supporting findings,
    MITRE references, Risk score, Expected impact, Suggested execution
    order."""

    model_config = ConfigDict(frozen=True)

    recommendation_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    action: ResponseAction
    timeframe: ResponseTimeframe
    priority: ResponsePriority
    confidence: float = Field(ge=0.0, le=1.0)
    required_evidence: tuple[ResponseEvidence, ...] = ()
    supporting_finding_ids: tuple[str, ...] = ()
    mitre_technique_ids: tuple[str, ...] = ()
    risk_score: float = Field(ge=0.0, le=100.0)
    expected_impact: str = ""
    rationale: str = ""
    #: 1-based, lower executes first — assigned by
    #: `core.incident_response.action_ordering`, never by the rule engine
    #: that first generates the recommendation (single source of truth,
    #: constitution §2 "Constants").
    execution_order: int = Field(ge=1)


class ResponseMetrics(BaseModel):
    """The task's named `ResponseMetrics` model — this plan's own
    observability payload (constitution §11's "response statistics"), never
    recomputed by a caller from `IncidentResponsePlan.recommendations`
    (single source of truth)."""

    model_config = ConfigDict(frozen=True)

    total_recommendations: int = 0
    recommendations_by_phase: dict[str, int] = Field(default_factory=dict)
    recommendations_by_priority: dict[str, int] = Field(default_factory=dict)
    recommendations_by_category: dict[str, int] = Field(default_factory=dict)
    average_confidence: float = 0.0
    highest_risk_score: float = 0.0
    finding_count_considered: int = 0
    mitre_technique_count: int = 0
    generation_duration_ms: float = 0.0


class IncidentResponsePlan(BaseModel):
    """The task's named `IncidentResponsePlan` model — this case's full,
    deterministic, reproducible response plan (blueprint §7's Incident
    Response Agent output). One canonical, execution-ordered
    `recommendations` tuple is the single source of truth; every
    phase/timeframe grouping below is a derived `@property`, never a
    separately-stored duplicate (constitution §2, "a magic number/value
    that appears in two places will eventually be updated in only one")."""

    model_config = ConfigDict(frozen=True)

    plan_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    case_id: str
    incident_severity: IncidentSeverity
    overall_risk_score: float = Field(ge=0.0, le=100.0)
    overall_confidence: float = Field(ge=0.0, le=1.0)
    recommendations: tuple[ResponseRecommendation, ...] = ()
    lessons_learned: tuple[str, ...] = ()
    metrics: ResponseMetrics = Field(default_factory=ResponseMetrics)
    plan_degraded: bool = False
    degraded_reason: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def _by_phase(self, phase: ResponsePhase) -> tuple[ResponseRecommendation, ...]:
        return tuple(r for r in self.recommendations if r.action.phase is phase)

    def _by_timeframe(self, timeframe: ResponseTimeframe) -> tuple[ResponseRecommendation, ...]:
        return tuple(r for r in self.recommendations if r.timeframe is timeframe)

    @property
    def containment_actions(self) -> tuple[ResponseRecommendation, ...]:
        return self._by_phase(ResponsePhase.CONTAINMENT)

    @property
    def isolation_actions(self) -> tuple[ResponseRecommendation, ...]:
        return self._by_phase(ResponsePhase.ISOLATION)

    @property
    def eradication_actions(self) -> tuple[ResponseRecommendation, ...]:
        return self._by_phase(ResponsePhase.ERADICATION)

    @property
    def recovery_actions(self) -> tuple[ResponseRecommendation, ...]:
        return self._by_phase(ResponsePhase.RECOVERY)

    @property
    def validation_actions(self) -> tuple[ResponseRecommendation, ...]:
        return self._by_phase(ResponsePhase.VALIDATION)

    @property
    def post_incident_actions(self) -> tuple[ResponseRecommendation, ...]:
        return self._by_phase(ResponsePhase.POST_INCIDENT)

    @property
    def immediate_actions(self) -> tuple[ResponseRecommendation, ...]:
        return self._by_timeframe(ResponseTimeframe.IMMEDIATE)

    @property
    def short_term_remediation(self) -> tuple[ResponseRecommendation, ...]:
        return self._by_timeframe(ResponseTimeframe.SHORT_TERM)

    @property
    def long_term_hardening(self) -> tuple[ResponseRecommendation, ...]:
        return self._by_timeframe(ResponseTimeframe.LONG_TERM)
