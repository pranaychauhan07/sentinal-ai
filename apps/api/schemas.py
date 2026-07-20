"""Request/response schemas for the Case/Evidence/IOC/Finding routes
(Milestone M1's first real domain API surface).

Per constitution §6, every endpoint's response is a named Pydantic model
here — never a bare dict, never the ORM row directly. Response models use
`from_attributes=True` (inherited from `core.schemas.BaseSchema`'s pattern,
restated locally to avoid a circular import back into `core/db`) so they
construct directly from SQLAlchemy rows in the router, matching constitution
§7's "translation happens in one place" rule.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from core.db.models.case import CasePriority, CaseStatus
from core.db.models.evidence import EvidenceStatus
from core.db.models.ioc import IOCStatus
from core.db.models.timeline_event import TimelineEventType
from core.findings.models import FindingPriority, FindingSeverity, FindingStatus
from core.parsers.models import EvidenceType, Severity
from core.threat_intel.models import IOCType, ThreatCategory, ThreatSeverity


class ApiSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# --- Case ---------------------------------------------------------------


class CaseCreateRequest(ApiSchema):
    title: str = Field(min_length=1, max_length=500)
    description: str = ""
    severity: Severity = Severity.INFO
    priority: CasePriority = CasePriority.MEDIUM


class CaseStatusUpdateRequest(ApiSchema):
    status: CaseStatus


class CaseDetailsUpdateRequest(ApiSchema):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    description: str | None = None


class CaseAssignmentUpdateRequest(ApiSchema):
    owner_id: str | None = None
    assignee_id: str | None = None


class CasePriorityUpdateRequest(ApiSchema):
    priority: CasePriority


class CaseLabelsUpdateRequest(ApiSchema):
    labels: dict[str, str]


class CaseTagRequest(ApiSchema):
    tag: str = Field(min_length=1, max_length=100)


class CaseNoteCreateRequest(ApiSchema):
    body: str = Field(min_length=1)


class CaseNoteUpdateRequest(ApiSchema):
    body: str = Field(min_length=1)


class CaseNoteResponse(ApiSchema):
    id: uuid.UUID
    case_id: uuid.UUID
    author_id: str
    body: str
    created_at: datetime
    updated_at: datetime


class CaseTagResponse(ApiSchema):
    id: uuid.UUID
    case_id: uuid.UUID
    tag: str
    created_at: datetime


class CaseResponse(ApiSchema):
    id: uuid.UUID
    title: str
    description: str
    status: CaseStatus
    severity: Severity
    priority: CasePriority
    risk_score: float | None
    analyst_id: str
    owner_id: str | None
    assignee_id: str | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None


# --- Evidence -------------------------------------------------------------


class EvidenceResponse(ApiSchema):
    id: uuid.UUID
    case_id: uuid.UUID
    evidence_type: EvidenceType
    original_filename: str
    sha256: str
    file_size_bytes: int
    mime_type: str
    parser_name: str | None
    parser_confidence: float | None
    status: EvidenceStatus
    uploaded_at: datetime
    parsed_at: datetime | None


class EvidenceUploadResponse(ApiSchema):
    """`POST /cases/{case_id}/evidence`'s response — the full investigation
    result (`core.services.case_service.CaseInvestigationResult`), not just
    the persisted `Evidence` row, since upload synchronously triggers the
    whole ingest -> extract -> generate -> analyze pipeline."""

    case_id: uuid.UUID
    evidence_id: uuid.UUID
    ioc_count: int
    created_finding_ids: list[uuid.UUID]
    merged_finding_ids: list[uuid.UUID]
    soc_risk_score: float | None
    soc_risk_label: str | None
    #: Populated only when this upload routed to `PhishingAgent` (an `.eml`
    #: artifact) rather than `SocAnalystAgent` — additive fields, per
    #: constitution §13's versioning rule (non-breaking, no `/api/v2` needed).
    phishing_risk_score: float | None = None
    phishing_risk_label: str | None = None
    #: Populated only when this upload routed to `VulnerabilityAssessmentAgent`
    #: (a Nessus/OpenVAS scan report) rather than `SocAnalystAgent` —
    #: additive, per constitution §13's versioning rule.
    vulnerability_finding_count: int | None = None
    highest_vulnerability_score: float | None = None
    #: Populated only when this upload routed to `ThreatHunterAgent` (an
    #: SSH-auth/syslog artifact) — additive, per constitution §13's
    #: versioning rule (docs/adr/0018-linux-security-threat-hunting-framework.md).
    linux_security_finding_count: int | None = None
    highest_linux_security_risk_score: float | None = None
    #: Populated only when this upload routed to `LinuxSecurityAgent` (a raw
    #: command/`ls -l` artifact) — additive, per constitution §13's
    #: versioning rule (docs/adr/0019-linux-security-advisor-agent.md).
    linux_advisory_count: int | None = None
    highest_linux_advisory_risk_level: str | None = None
    #: Populated only when this upload routed to `WebSecurityAgent` (an HTTP
    #: transaction transcript) — additive, per constitution §13's
    #: versioning rule (docs/adr/0020-owasp-web-security-agent.md).
    owasp_web_finding_count: int | None = None
    highest_owasp_web_risk_level: str | None = None
    #: Populated only when this upload routed to `OwaspSecurityAgent` (a
    #: source code file) — additive, per constitution §13's versioning rule
    #: (docs/adr/0021-owasp-security-agent-ast-sast.md).
    sast_finding_count: int | None = None
    highest_sast_risk_level: str | None = None
    #: Populated once at least one Finding on this case has been mapped to an
    #: ATT&CK technique — cross-cutting, so populated regardless of which
    #: specialist(s) this upload also routed to (additive, per constitution
    #: §13's versioning rule; docs/adr/0022-mitre-mapping-agent.md).
    mitre_technique_count: int | None = None
    mitre_distinct_group_count: int | None = None


# --- IOC --------------------------------------------------------------------


class IOCResponse(ApiSchema):
    id: uuid.UUID
    case_id: uuid.UUID
    evidence_id: uuid.UUID | None
    ioc_type: IOCType
    value: str
    source: str
    confidence: float
    severity: ThreatSeverity
    classification: ThreatCategory
    composite_score: float
    status: IOCStatus
    first_seen_at: datetime
    last_seen_at: datetime


# --- Finding ------------------------------------------------------------


class FindingResponse(ApiSchema):
    id: uuid.UUID
    case_id: uuid.UUID
    title: str
    description: str
    severity: FindingSeverity
    confidence: float
    status: FindingStatus
    priority: FindingPriority
    risk_score: float
    ioc_count: int
    created_at: datetime
    updated_at: datetime


# --- Timeline -----------------------------------------------------------


class TimelineEventResponse(ApiSchema):
    id: uuid.UUID
    case_id: uuid.UUID
    timestamp: datetime
    event_type: TimelineEventType
    source_finding_id: uuid.UUID | None
    narrative: str
