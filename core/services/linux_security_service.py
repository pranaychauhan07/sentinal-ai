"""Linux Security / Threat Hunting Pipeline Manager
(docs/adr/0018-linux-security-threat-hunting-framework.md).
`LinuxSecurityPipeline` implements the ten named stages the task's own
diagram calls for (Evidence Normalization -> Authentication Analysis ->
Privilege Analysis -> Persistence Analysis -> Behavior Detection -> Scoring
-> Finding Generation -> Persistence -> Event Publication -> Case/Timeline
Notification), each independently unit-testable; `assess_linux_security()`
composes them into the one call `core/services/case_service.py` (or a test
harness) invokes — mirrors
`core/services/vulnerability_service.py`'s `VulnerabilityPipeline`/
`assess_vulnerabilities()` shape exactly.

`core/services` importing `core/linux_security` and `core/parsers` directly
(rather than only `core/graph`) is a documented, deliberate exception —
`docs/adr/0018...md` / `docs/dependency-rules.md` rule 4f: Linux security
analysis is pre-investigation, deterministic, and involves no agent/LLM
reasoning, worded identically to rule 4e's precedent for
`vulnerability_service.py`.

**Scope-gating decision:** `assess_linux_security()` only runs against
`EvidenceType.SSH_AUTH`/`EvidenceType.SYSLOG` — deliberately **not**
`EvidenceType.JSON`, even though a journald JSON export is a plausible
future Linux-security input. `JSON` evidence is used generically elsewhere
in this codebase for arbitrary structured exports (e.g. EDR alerts); forcing
Linux-security analysis onto every JSON upload would be wrong (mirrors
ADR-0017 point 9's identical scan-type gating reasoning for vulnerability
assessment). This gating decision lives in `core/services/case_service.py`
(`_LINUX_SECURITY_EVIDENCE_TYPES`), not here — this module itself is
evidence-type-agnostic and will happily analyze whatever `NormalizedEvidence`
it's given, same as `VulnerabilityPipeline`.
"""

from __future__ import annotations

import json
import uuid

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.db.linux_security_finding_repository import LinuxSecurityFindingRepository
from core.db.models.linux_security_finding import (
    LinuxSecurityFindingRow,
    LinuxSecurityFindingStatus,
)
from core.linux_security.audit import AuditAction, log_linux_security_audit_event
from core.linux_security.authentication_timeline import build_timeline
from core.linux_security.confidence_engine import (
    LinuxSecurityConfidenceEngine,
    LinuxSecurityConfidenceWeights,
)
from core.linux_security.cron_analyzer import CronAnalyzer
from core.linux_security.events import (
    LinuxSecurityEvent,
    LinuxSecurityEventPublisher,
    LinuxSecurityEventType,
)
from core.linux_security.exceptions import OversizedLinuxSecurityDatasetError
from core.linux_security.finding_generator import LinuxSecurityFindingGenerator
from core.linux_security.models import (
    AuthenticationTimelineEntry,
    LinuxLogEvent,
    LinuxSecurityCandidate,
    LinuxSecurityFinding,
    NormalizedLinuxSecurityIntel,
    ScoredLinuxSecurityCandidate,
)
from core.linux_security.normalizer import LinuxSecurityNormalizer
from core.linux_security.persistence_detector import detect_persistence_mechanisms
from core.linux_security.privilege_escalation import PrivilegeEscalationDetector
from core.linux_security.process_detector import scan_generic_process_lines
from core.linux_security.scoring import (
    LinuxSecurityScoringWeights,
    LinuxThreatScoringEngine,
    score_candidates,
)
from core.linux_security.service_analyzer import ServiceAnalyzer
from core.linux_security.ssh_auth_analyzer import SshAuthAnalyzer
from core.linux_security.sudo_analyzer import SudoActivityAnalyzer
from core.logging import get_logger, logging_context
from core.memory.interfaces import CaseMemory
from core.parsers.models import NormalizedEvidence

_logger = get_logger(__name__)

#: Composite score below which a successfully-persisted finding is still
#: flagged as a degraded detection event (distinct from a hard failure) —
#: mirrors `vulnerability_service.DEGRADED_SCORE_THRESHOLD`'s role.
DEGRADED_SCORE_THRESHOLD = 20.0

_EXTRACTOR_NAME = "linux_security_pipeline"
_EXTRACTOR_VERSION = "1.0.0"


class LinuxSecurityAssessmentResult(BaseModel):
    """What `assess_linux_security()` returns — the one typed contract
    every caller (the Threat Hunting Agent, a test) reads."""

    model_config = ConfigDict(frozen=True)

    case_id: uuid.UUID
    evidence_id: uuid.UUID | None
    candidate_count: int
    finding_count: int
    normalized_linux_security_intel: NormalizedLinuxSecurityIntel


class LinuxSecurityPipeline:
    """The ten-stage analysis pipeline, each stage a small, typed,
    independently-testable method:

    1. `normalize_evidence` — Evidence Normalization
    2. `authentication_analysis` — Authentication Analysis
    3. `privilege_analysis` — Privilege Analysis
    4. `persistence_analysis` — Persistence Analysis
    5. `behavior_detection` — Behavior Detection
    6. `score` — Threat Scoring (+ Confidence)
    7. `generate_findings` — Finding Generation
    8. `persist` — Persistence (DB)
    9. `publish_event` — Event Publication
    10. `notify_memory` — Case/Timeline Notification

    Every dependency is injected (constitution §2) — nothing here reaches
    for a module-level singleton.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        event_publisher: LinuxSecurityEventPublisher | None = None,
        case_memory: CaseMemory | None = None,
    ) -> None:
        self._settings = settings
        self._normalizer = LinuxSecurityNormalizer()
        self._ssh_auth_analyzer = SshAuthAnalyzer(
            brute_force_threshold=settings.linux_security_brute_force_threshold,
            brute_force_window_minutes=settings.linux_security_brute_force_window_minutes,
            failed_login_spike_threshold=settings.linux_security_failed_login_spike_threshold,
            failed_login_spike_min_sources=(settings.linux_security_failed_login_spike_min_sources),
        )
        self._sudo_analyzer = SudoActivityAnalyzer(
            failure_threshold=settings.linux_security_sudo_failure_threshold,
            failure_window_minutes=settings.linux_security_sudo_failure_window_minutes,
        )
        self._privilege_escalation_detector = PrivilegeEscalationDetector(
            escalation_chain_window_minutes=(
                settings.linux_security_escalation_chain_window_minutes
            ),
        )
        self._cron_analyzer = CronAnalyzer()
        self._service_analyzer = ServiceAnalyzer()
        self._confidence_engine = LinuxSecurityConfidenceEngine(
            weights=LinuxSecurityConfidenceWeights(
                pattern_match_strength=settings.linux_security_confidence_weight_pattern_match,
                occurrence_signal=settings.linux_security_confidence_weight_occurrence,
                evidence_completeness=(
                    settings.linux_security_confidence_weight_evidence_completeness
                ),
                corroboration=settings.linux_security_confidence_weight_corroboration,
            )
        )
        self._scoring_engine = LinuxThreatScoringEngine(
            weights=LinuxSecurityScoringWeights(
                detection_confidence=(settings.linux_security_scoring_weight_detection_confidence),
                event_frequency=settings.linux_security_scoring_weight_event_frequency,
                severity=settings.linux_security_scoring_weight_severity,
                evidence_quality=settings.linux_security_scoring_weight_evidence_quality,
                source_reliability=settings.linux_security_scoring_weight_source_reliability,
                ioc_correlation=settings.linux_security_scoring_weight_ioc_correlation,
                existing_findings=settings.linux_security_scoring_weight_existing_findings,
            )
        )
        self._finding_generator = LinuxSecurityFindingGenerator()
        self._event_publisher = event_publisher or LinuxSecurityEventPublisher()
        self._case_memory = case_memory
        self._max_records = settings.linux_security_max_records_per_artifact

    # -- Stage 1: Evidence Normalization ------------------------------------
    def normalize_evidence(self, evidence: NormalizedEvidence) -> tuple[list[LinuxLogEvent], int]:
        if len(evidence.records) > self._max_records:
            raise OversizedLinuxSecurityDatasetError(
                f"Evidence artifact contains {len(evidence.records)} record(s), exceeding the "
                f"{self._max_records}-record analysis limit.",
                details={"count": len(evidence.records), "max_records": self._max_records},
            )
        return self._normalizer.normalize(evidence)

    # -- Stage 2: Authentication Analysis ------------------------------------
    def authentication_analysis(self, events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
        return self._ssh_auth_analyzer.analyze(events)

    # -- Stage 3: Privilege Analysis -----------------------------------------
    def privilege_analysis(self, events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
        return [
            *self._sudo_analyzer.analyze(events),
            *self._privilege_escalation_detector.analyze(events),
        ]

    # -- Stage 4: Persistence Analysis ---------------------------------------
    def persistence_analysis(
        self, events: list[LinuxLogEvent], privilege_candidates: list[LinuxSecurityCandidate]
    ) -> list[LinuxSecurityCandidate]:
        cron_candidates = self._cron_analyzer.analyze(events)
        service_candidates = self._service_analyzer.analyze(events)
        persistence_candidates = detect_persistence_mechanisms(
            cron_candidates, service_candidates, privilege_candidates
        )
        return [*cron_candidates, *service_candidates, *persistence_candidates]

    # -- Stage 5: Behavior Detection ------------------------------------------
    def behavior_detection(self, events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
        return scan_generic_process_lines(events)

    # -- Stage 6: Threat Scoring (+ Confidence) -------------------------------
    def score(
        self, candidates: list[LinuxSecurityCandidate], *, evidence_quality: float
    ) -> list[ScoredLinuxSecurityCandidate]:
        return score_candidates(
            candidates,
            evidence_quality=evidence_quality,
            confidence_engine=self._confidence_engine,
            scoring_engine=self._scoring_engine,
        )

    # -- Stage 7: Finding Generation -------------------------------------------
    def generate_findings(
        self, scored_candidates: list[ScoredLinuxSecurityCandidate]
    ) -> list[LinuxSecurityFinding]:
        return self._finding_generator.generate(scored_candidates)

    # -- Stage 8: Persistence ---------------------------------------------------
    async def persist(
        self,
        session: AsyncSession,
        *,
        case_id: uuid.UUID,
        evidence_id: uuid.UUID | None,
        findings: list[LinuxSecurityFinding],
    ) -> list[LinuxSecurityFindingRow]:
        repository = LinuxSecurityFindingRepository(session)
        persisted: list[LinuxSecurityFindingRow] = []
        for finding in findings:
            row = LinuxSecurityFindingRow(
                case_id=case_id,
                evidence_id=evidence_id,
                category=finding.category,
                subject=finding.subject,
                subject_type=finding.subject_type,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                composite_score=finding.composite_score,
                occurrence_count=finding.occurrence_count,
                line_numbers_json=json.dumps(list(finding.line_numbers)),
                extractor_name=_EXTRACTOR_NAME,
                extractor_version=_EXTRACTOR_VERSION,
                status=LinuxSecurityFindingStatus.ACTIVE,
                metadata_json=finding.model_dump_json(),
                first_seen_at=finding.first_seen,
                last_seen_at=finding.last_seen,
            )
            await repository.add(row)
            persisted.append(row)
        return persisted

    # -- Stage 9: Event Publication ----------------------------------------------
    def publish_event(
        self, evidence_id: uuid.UUID | None, findings: list[LinuxSecurityFinding]
    ) -> None:
        for finding in findings:
            event_type = (
                LinuxSecurityEventType.DEGRADED
                if finding.composite_score < DEGRADED_SCORE_THRESHOLD
                else LinuxSecurityEventType.FINDING_GENERATED
            )
            self._event_publisher.publish(
                LinuxSecurityEvent(
                    event_type=event_type,
                    evidence_id=evidence_id,
                    source=_EXTRACTOR_NAME,
                    detail=(
                        f"category={finding.category.value} subject={finding.subject} "
                        f"score={finding.composite_score} severity={finding.severity.value}"
                    ),
                )
            )

    # -- Stage 10: Case/Timeline Notification -------------------------------------
    async def notify_memory(
        self,
        case_id: uuid.UUID,
        evidence_id: uuid.UUID | None,
        findings: list[LinuxSecurityFinding],
    ) -> None:
        """Advisory-only (ADR-0006's "memory is always advisory, never a
        hard dependency") — matches `VulnerabilityPipeline.notify_memory`'s
        identical contract. `TimelineEvent(LINUX_SECURITY_FINDING_DETECTED)`
        recording is `core/services/case_service.py`'s job (it owns every
        other `TimelineEvent` write in the investigation pipeline), not
        this pipeline's."""
        if self._case_memory is None or not findings:
            return
        critical_count = sum(1 for f in findings if f.severity.value == "critical")
        try:
            await self._case_memory.add_note(
                case_id,
                f"Linux security analysis of evidence {evidence_id} found "
                f"{len(findings)} finding(s), {critical_count} critical.",
            )
        except Exception as exc:  # noqa: BLE001 - memory is advisory, must never break analysis
            _logger.warning(
                "linux_security_memory_notify_failed", evidence_id=str(evidence_id), error=str(exc)
            )


async def assess_linux_security(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    evidence: NormalizedEvidence,
    settings: Settings,
    pipeline: LinuxSecurityPipeline | None = None,
) -> LinuxSecurityAssessmentResult:
    """Run the full ten-stage analysis pipeline for one `NormalizedEvidence`
    SSH-auth/syslog artifact. A malformed/corrupted individual log line never
    aborts the artifact — `normalize_evidence` skips it and records the count
    (constitution §1.7)."""
    pipeline = pipeline or LinuxSecurityPipeline(settings=settings)

    with logging_context(case_id=str(case_id)):
        events, skipped = pipeline.normalize_evidence(evidence)
        timeline: list[AuthenticationTimelineEntry] = build_timeline(events)

        auth_candidates = pipeline.authentication_analysis(events)
        privilege_candidates = pipeline.privilege_analysis(events)
        persistence_candidates = pipeline.persistence_analysis(events, privilege_candidates)
        behavior_candidates = pipeline.behavior_detection(events)

        all_candidates = [
            *auth_candidates,
            *privilege_candidates,
            *persistence_candidates,
            *behavior_candidates,
        ]

        scored_candidates = pipeline.score(all_candidates, evidence_quality=evidence.confidence)
        findings = pipeline.generate_findings(scored_candidates)

        persisted = await pipeline.persist(
            session, case_id=case_id, evidence_id=evidence.evidence_id, findings=findings
        )
        pipeline.publish_event(evidence.evidence_id, findings)
        await pipeline.notify_memory(case_id, evidence.evidence_id, findings)

        for row in persisted:
            log_linux_security_audit_event(
                action=AuditAction.PERSISTED,
                finding_id=row.id,
                evidence_id=evidence.evidence_id,
                case_id=case_id,
                category=row.category.value,
            )

        metadata: dict[str, object] = {"skipped_record_count": skipped}

        normalized_linux_security_intel = NormalizedLinuxSecurityIntel(
            evidence_id=evidence.evidence_id,
            source=evidence.source,
            extractor_name=_EXTRACTOR_NAME,
            extractor_version=_EXTRACTOR_VERSION,
            candidates=tuple(scored_candidates),
            findings=tuple(findings),
            timeline=tuple(timeline),
            skipped_record_count=skipped,
            metadata=metadata,
        )

        return LinuxSecurityAssessmentResult(
            case_id=case_id,
            evidence_id=evidence.evidence_id,
            candidate_count=len(scored_candidates),
            finding_count=len(findings),
            normalized_linux_security_intel=normalized_linux_security_intel,
        )


async def get_linux_security_finding(
    session: AsyncSession, finding_id: uuid.UUID
) -> LinuxSecurityFindingRow | None:
    repository = LinuxSecurityFindingRepository(session)
    return await repository.get_by_id(finding_id)


async def list_linux_security_findings_for_case(
    session: AsyncSession, case_id: uuid.UUID, *, limit: int = 50, cursor: uuid.UUID | None = None
) -> list[LinuxSecurityFindingRow]:
    repository = LinuxSecurityFindingRepository(session)
    return await repository.find_by_case(case_id, limit=limit, cursor=cursor)
