"""Canonical Linux security schema — the Threat Hunting Agent's Linux-log
detection surface (docs/adr/0018-linux-security-threat-hunting-framework.md).
Every normalizer, analyzer, confidence/scoring engine, and finding generator
in `core/linux_security` reads and returns only these shapes (constitution
§1.2).

Deliberately its own `LinuxSecuritySeverity`, never a reuse of
`core.parsers.models.Severity` or any sibling leaf's severity scale — matches
the identical, already-established precedent
`core.vulnerabilities.models.VulnerabilitySeverity`'s own docstring: each leaf
package owns its own severity scale, mapped explicitly at translation points.

Design note on detection candidates: rather than one bespoke Pydantic model
per `LinuxSecurityFindingCategory` (fifteen near-identical shapes differing
only in which extra fields they carry), every analyzer in this package
produces the single shared `LinuxSecurityCandidate` shape, differentiated by
`category` plus a `context` bag for category-specific extras (the command
text, the group name, the port, ...). This mirrors
`core.vulnerabilities.models.VulnerabilityRecord`'s own "one shape, many
kinds" precedent and keeps the analyzer set additive without a matching
model-file explosion (constitution §1.3, "small, focused modules" — one
well-tested shape is more focused than fifteen structurally-identical ones).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LinuxSecuritySeverity(StrEnum):
    """This package's own severity scale (see module docstring)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LinuxSecurityFindingCategory(StrEnum):
    """Closed set of detection categories this framework's analyzers
    produce (task requirement's named detection surface)."""

    BRUTE_FORCE = "brute_force"
    COMPROMISE_AFTER_BRUTE_FORCE = "compromise_after_brute_force"
    FAILED_LOGIN_SPIKE = "failed_login_spike"
    ROOT_LOGIN = "root_login"
    NEW_USER = "new_user"
    USER_DELETION = "user_deletion"
    PASSWORD_CHANGE = "password_change"
    SUDO_ABUSE = "sudo_abuse"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_CRON = "suspicious_cron"
    REVERSE_SHELL = "reverse_shell"
    SUSPICIOUS_SERVICE = "suspicious_service"
    SUSPICIOUS_PROCESS = "suspicious_process"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    UNAUTHORIZED_ACCOUNT_ACTIVITY = "unauthorized_account_activity"


class SourceReliability(StrEnum):
    """Admiralty-scale-inspired reliability of the originating evidence
    artifact — one of the Threat Scoring Engine's required dimensions (task
    requirement: "Source Reliability"). Deliberately its own enum rather than
    reusing `core.vulnerabilities.models.SourceReliability`/
    `core.threat_intel.models.SourceReliability` sideways (same
    leaf-ownership reasoning as `LinuxSecuritySeverity`)."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class LinuxLogEvent(BaseModel):
    """This package's own normalized intermediate record — one Linux
    security-relevant event, built by `core.linux_security.normalizer` from a
    `core.parsers.models.EvidenceRecord`. `process` carries whichever
    classification the owning parser already assigned to
    `EvidenceRecord.event_type`: `SshAuthParser` sets it to the classified
    auth-event kind (`auth_failure`/`auth_success`/`disconnect`/
    `session_opened`); `SyslogParser` sets it to the emitting process name
    (`sudo`/`CRON`/`useradd`/`systemd`/...). Every analyzer in this package
    reads `process` as the discriminator for which regex/logic applies."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime | None = None
    host: str | None = None
    user: str | None = None
    ip_address: str | None = None
    process: str | None = None
    raw_message: str = ""
    evidence_id: uuid.UUID | None = None
    line_number: int | None = None


class LinuxSecurityCandidate(BaseModel):
    """One analyzer's raw detection output, before confidence/scoring
    (mirrors `core.vulnerabilities.models.VulnerabilityRecord`'s
    per-item, immutable, self-contained shape). `subject` is the
    deterministic correlation key `finding_generator.py` groups on — an IP
    address for SSH-based findings, a username for privesc/persistence
    findings, matching the task's "group by source IP / by user / by asset"
    requirement."""

    model_config = ConfigDict(frozen=True)

    candidate_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    category: LinuxSecurityFindingCategory
    severity: LinuxSecuritySeverity
    subject: str
    subject_type: str = "host"
    title: str
    description: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    occurrence_count: int = 1
    evidence_id: uuid.UUID | None = None
    line_numbers: tuple[int, ...] = ()
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = ""
    context: dict[str, Any] = Field(default_factory=dict)


class LinuxSecurityScore(BaseModel):
    """The Threat Scoring Engine's output for one `LinuxSecurityCandidate` —
    every dimension the task requires (detection confidence, event
    frequency, severity, evidence quality, source reliability, IOC
    correlation, existing findings) plus the composite 0-100 score.
    Mirrors `core.vulnerabilities.models.VulnerabilityScore`'s shape."""

    model_config = ConfigDict(frozen=True)

    detection_confidence: float = Field(ge=0.0, le=1.0)
    event_frequency: float = Field(ge=0.0, le=1.0)
    severity_weight: float = Field(ge=0.0, le=1.0)
    evidence_quality: float = Field(ge=0.0, le=1.0)
    source_reliability: float = Field(ge=0.0, le=1.0)
    ioc_correlation: float = Field(ge=0.0, le=1.0)
    existing_findings: float = Field(ge=0.0, le=1.0)
    composite_score: float = Field(ge=0.0, le=100.0)


class ScoredLinuxSecurityCandidate(BaseModel):
    """One fully-processed candidate — mirrors
    `core.vulnerabilities.models.ScoredVulnerability`."""

    model_config = ConfigDict(frozen=True)

    candidate: LinuxSecurityCandidate
    score: LinuxSecurityScore
    occurrence_count: int = 1


class LinuxSecurityFinding(BaseModel):
    """A case-level aggregation of one or more `ScoredLinuxSecurityCandidate`
    entries sharing the same `(category, subject)` key. Deliberately carries
    no remediation/recommendation field and no Incident Response fields —
    both are explicitly out of scope for this framework (module docstring /
    ADR-0018), matching `core.vulnerabilities.models.VulnerabilityFinding`'s
    identical "assessment only" precedent.

    Not persisted to the shared `findings` DB table — mirrors
    `VulnerabilityFinding`'s identical, already-documented scoping decision
    (ADR-0014 point 4, reaffirmed ADR-0016/0017). The underlying per-candidate
    `LinuxSecurityFinding` DB rows *are* persisted
    (`core/db/models/linux_security_finding.py`).
    """

    model_config = ConfigDict(frozen=True)

    finding_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    category: LinuxSecurityFindingCategory
    subject: str
    subject_type: str = "host"
    title: str
    description: str = ""
    severity: LinuxSecuritySeverity
    composite_score: float = Field(ge=0.0, le=100.0)
    occurrence_count: int = 1
    line_numbers: tuple[int, ...] = ()
    evidence_ids: tuple[uuid.UUID, ...] = ()
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuthenticationTimelineEntry(BaseModel):
    """One chronological entry in this analysis run's own authentication
    timeline (see `core.linux_security.authentication_timeline`'s module
    docstring for how this differs from the blueprint §13 Threat Timeline
    UI feature)."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    event_type: str
    user: str | None = None
    ip_address: str | None = None
    host: str | None = None
    detail: str = ""


class NormalizedLinuxSecurityIntel(BaseModel):
    """The Linux Security Analysis Framework's one output contract for a
    single evidence artifact — mirrors
    `core.vulnerabilities.models.NormalizedVulnerabilityIntel`'s "per-artifact
    container" shape. Never silently drops a candidate: a candidate that
    failed validation is recorded in `rejected_candidates`, never discarded
    (constitution §1.7)."""

    model_config = ConfigDict(frozen=True)

    result_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    evidence_id: uuid.UUID | None
    source: str
    extractor_name: str
    extractor_version: str
    candidates: tuple[ScoredLinuxSecurityCandidate, ...] = ()
    findings: tuple[LinuxSecurityFinding, ...] = ()
    timeline: tuple[AuthenticationTimelineEntry, ...] = ()
    rejected_candidates: tuple[str, ...] = ()
    skipped_record_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def candidate_count(self) -> int:
        return len(self.candidates)

    @property
    def finding_count(self) -> int:
        return len(self.findings)
