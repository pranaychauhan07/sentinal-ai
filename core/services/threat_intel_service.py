"""Threat Intelligence Manager — the IOC extraction pipeline orchestrator
(docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md).
`IOCExtractionPipeline` implements the nine named stages the task's own
diagram calls for, each independently unit-testable; `extract_threat_intelligence()`
composes them into the one call a future `core/agents/threat_hunter_agent.py`
(or a test harness) invokes — mirrors
`core/services/evidence_service.py`'s `EvidencePipeline`/`ingest_evidence()`
shape exactly.

`core/services` importing `core/threat_intel` and `core/parsers` directly
(rather than only `core/graph`) is a documented, deliberate exception —
`docs/adr/0012...md` point 2 / `docs/dependency-rules.md` rule 4b: IOC
extraction is pre-investigation, deterministic, and involves no agent/LLM
reasoning.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.db.ioc_repository import IOCRepository
from core.db.models.ioc import IOC, IOCStatus
from core.logging import get_logger, logging_context
from core.memory.interfaces import CaseMemory
from core.parsers.models import NormalizedEvidence
from core.threat_intel.attribution import EvidenceAttributionTracker
from core.threat_intel.audit import AuditAction, log_threat_intel_audit_event
from core.threat_intel.classification import (
    ThreatClassificationEngine,
    derive_severity_from_classification,
)
from core.threat_intel.dedup import deduplicate_iocs
from core.threat_intel.events import (
    ThreatIntelEvent,
    ThreatIntelEventPublisher,
    ThreatIntelEventType,
)
from core.threat_intel.exceptions import IOCValidationError
from core.threat_intel.metrics import ThreatIntelMetricsCollector
from core.threat_intel.models import (
    IOCRecord,
    NormalizedThreatIntel,
    RuleMatchResult,
    ScoredIOC,
    SourceReliability,
)
from core.threat_intel.normalizer import IOCNormalizer
from core.threat_intel.registry import ExtractorRegistry, default_extractor_registry
from core.threat_intel.rules import DetectionRuleEngine
from core.threat_intel.scoring import ConfidenceCalculator, ScoringWeights, ThreatScoringEngine
from core.threat_intel.validator import IOCValidator

_logger = get_logger(__name__)

#: Composite score below which a successfully-persisted result is still
#: flagged as a degraded extraction event (distinct from a hard failure) —
#: mirrors `evidence_service.DEGRADED_CONFIDENCE_THRESHOLD`'s role.
DEGRADED_SCORE_THRESHOLD = 20.0


class ThreatIntelExtractionResult(BaseModel):
    """What `extract_threat_intelligence()` returns — the one typed
    contract every caller (a future agent, a test) reads."""

    model_config = ConfigDict(frozen=True)

    case_id: uuid.UUID
    evidence_id: uuid.UUID | None
    ioc_count: int
    rejected_count: int
    normalized_threat_intel: NormalizedThreatIntel


class IOCExtractionPipeline:
    """The nine-stage extraction pipeline, each stage a small, typed,
    independently-testable method: discover -> validate -> normalize ->
    deduplicate -> classify -> score -> persist -> publish_event ->
    notify_memory.

    Every dependency is injected (constitution §2) — nothing here reaches
    for a module-level singleton except the documented, explicitly-cached
    `default_extractor_registry()` when the caller doesn't provide one.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        extractor_registry: ExtractorRegistry | None = None,
        event_publisher: ThreatIntelEventPublisher | None = None,
        metrics: ThreatIntelMetricsCollector | None = None,
        case_memory: CaseMemory | None = None,
        rule_engine: DetectionRuleEngine | None = None,
        scoring_weights: ScoringWeights | None = None,
    ) -> None:
        self._settings = settings
        self._extractor_registry = extractor_registry or default_extractor_registry()
        self._event_publisher = event_publisher or ThreatIntelEventPublisher()
        self._metrics = metrics or ThreatIntelMetricsCollector()
        self._case_memory = case_memory
        self._validator = IOCValidator()
        self._normalizer = IOCNormalizer()
        self._rule_engine = rule_engine or DetectionRuleEngine()
        self._scoring_engine = ThreatScoringEngine(weights=scoring_weights)
        self._confidence_calculator = ConfidenceCalculator()
        self._classification_engine = ThreatClassificationEngine(
            malicious_threshold=settings.threat_intel_malicious_score_threshold,
            suspicious_threshold=settings.threat_intel_suspicious_score_threshold,
        )
        self._attribution_tracker = EvidenceAttributionTracker()

    # -- Stage 1: Discovery (Evidence -> IOC Discovery) -----------------------
    def discover(
        self, evidence: NormalizedEvidence, *, extractor_name: str = "default"
    ) -> list[IOCRecord]:
        extractor = self._extractor_registry.get(extractor_name)
        return extractor(evidence)

    # -- Stage 2: Validation ----------------------------------------------------
    def validate(self, candidates: list[IOCRecord]) -> tuple[list[IOCRecord], list[str]]:
        """Never silently drops a candidate (constitution §1.7): a
        candidate that fails validation is recorded as a rejection reason,
        not discarded without a trace."""
        valid: list[IOCRecord] = []
        rejected: list[str] = []
        for candidate in candidates:
            try:
                self._validator.validate(candidate)
                valid.append(candidate)
            except IOCValidationError as exc:
                rejected.append(f"{candidate.ioc_type.value}:{candidate.raw_value} - {exc.message}")
        return valid, rejected

    # -- Stage 3: Normalization --------------------------------------------------
    def normalize(self, valid_candidates: list[IOCRecord]) -> list[IOCRecord]:
        return [self._normalizer.normalize(candidate) for candidate in valid_candidates]

    # -- Stage 4: Deduplication ----------------------------------------------------
    def deduplicate(self, normalized_candidates: list[IOCRecord]) -> tuple[list[IOCRecord], int]:
        """Applies the resource-exhaustion cap
        (`Settings.threat_intel_max_iocs_per_artifact`) after deduplication.
        Returns `(kept, truncated_count)`."""
        deduplicated = deduplicate_iocs(normalized_candidates)
        cap = self._settings.threat_intel_max_iocs_per_artifact
        if len(deduplicated) <= cap:
            return deduplicated, 0
        return deduplicated[:cap], len(deduplicated) - cap

    # -- Stage 5: Classification (Detection Rule Engine) ---------------------------
    def classify(self, iocs: list[IOCRecord]) -> list[RuleMatchResult]:
        return self._rule_engine.evaluate(iocs)

    # -- Stage 6: Threat Scoring (+ Confidence, + Attribution) -----------------------
    def score(
        self,
        iocs: list[IOCRecord],
        rule_matches: list[RuleMatchResult],
        *,
        evidence_quality: float,
        source_reliability: SourceReliability = SourceReliability.UNKNOWN,
    ) -> list[ScoredIOC]:
        attributions = {
            attribution.ioc_id: attribution
            for attribution in self._attribution_tracker.attribute(iocs)
        }
        scored: list[ScoredIOC] = []
        for ioc in iocs:
            own_matches = [match for match in rule_matches if match.ioc_id == ioc.ioc_id]
            score = self._scoring_engine.score(
                ioc,
                rule_matches=own_matches,
                evidence_quality=evidence_quality,
                source_reliability=source_reliability,
            )
            confidence = self._confidence_calculator.calculate(
                extraction_confidence=ioc.confidence,
                validation_passed=True,
                rule_match_count=len(own_matches),
                source_reliability=source_reliability,
            )
            classification = self._classification_engine.classify(score, own_matches)
            # `IOCRecord.severity` defaults to INFO at construction (nothing
            # observed yet) — this is the one place it is actually derived
            # from the classification/score this pipeline just computed.
            # Previously this update only touched `confidence`, so every
            # persisted IOC silently kept the INFO default regardless of how
            # malicious it classified — see
            # `core.threat_intel.classification.derive_severity_from_classification`'s
            # docstring for the downstream Finding-severity inconsistency
            # this caused.
            severity = derive_severity_from_classification(classification, score)
            ioc_with_confidence = ioc.model_copy(
                update={"confidence": confidence, "severity": severity}
            )
            scored.append(
                ScoredIOC(
                    record=ioc_with_confidence,
                    rule_matches=tuple(own_matches),
                    score=score,
                    classification=classification,
                    attribution=attributions[ioc.ioc_id],
                )
            )
        return scored

    # -- Stage 7: Persistence -----------------------------------------------------
    async def persist(
        self,
        session: AsyncSession,
        *,
        case_id: uuid.UUID,
        evidence_id: uuid.UUID | None,
        extractor_name: str,
        extractor_version: str,
        scored_iocs: list[ScoredIOC],
    ) -> list[IOC]:
        repository = IOCRepository(session)
        persisted: list[IOC] = []
        now = datetime.now(UTC)
        for scored in scored_iocs:
            row = IOC(
                case_id=case_id,
                evidence_id=evidence_id,
                ioc_type=scored.record.ioc_type,
                value=scored.record.value,
                raw_value=scored.record.raw_value,
                source=scored.record.source,
                confidence=scored.record.confidence,
                severity=scored.record.severity,
                classification=scored.classification.category,
                composite_score=scored.score.composite_score,
                rule_match_count=len(scored.rule_matches),
                occurrence_count=scored.attribution.occurrence_count,
                extractor_name=extractor_name,
                extractor_version=extractor_version,
                status=IOCStatus.ACTIVE,
                metadata_json=scored.model_dump_json(),
                first_seen_at=scored.attribution.first_seen,
                last_seen_at=now,
            )
            await repository.add(row)
            persisted.append(row)
        return persisted

    # -- Stage 8: Event publication --------------------------------------------------
    def publish_event(
        self, evidence_id: uuid.UUID | None, extractor_name: str, scored_iocs: list[ScoredIOC]
    ) -> None:
        for scored in scored_iocs:
            event_type = (
                ThreatIntelEventType.DEGRADED
                if scored.score.composite_score < DEGRADED_SCORE_THRESHOLD
                else ThreatIntelEventType.CLASSIFIED
            )
            self._event_publisher.publish(
                ThreatIntelEvent(
                    event_type=event_type,
                    evidence_id=evidence_id,
                    extractor_name=extractor_name,
                    source=scored.record.source,
                    detail=(
                        f"ioc_type={scored.record.ioc_type.value} "
                        f"score={scored.score.composite_score} "
                        f"classification={scored.classification.category.value}"
                    ),
                )
            )
            self._metrics.record_ioc(scored.record.ioc_type.value)
            for match in scored.rule_matches:
                self._metrics.record_rule_match(match.rule_id)

    # -- Stage 9: Memory notification -----------------------------------------------
    async def notify_memory(
        self, case_id: uuid.UUID, evidence_id: uuid.UUID | None, scored_iocs: list[ScoredIOC]
    ) -> None:
        """Advisory-only (ADR-0006's "memory is always advisory, never a
        hard dependency") — matches `EvidencePipeline.notify_memory`'s
        contract exactly."""
        if self._case_memory is None or not scored_iocs:
            return
        malicious_count = sum(
            1 for scored in scored_iocs if scored.classification.category.value == "malicious"
        )
        try:
            await self._case_memory.add_note(
                case_id,
                f"IOC extraction from evidence {evidence_id} found {len(scored_iocs)} "
                f"indicator(s), {malicious_count} classified malicious.",
            )
        except Exception as exc:  # noqa: BLE001 - memory is advisory, must never break extraction
            _logger.warning(
                "threat_intel_memory_notify_failed", evidence_id=str(evidence_id), error=str(exc)
            )


async def extract_threat_intelligence(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    evidence: NormalizedEvidence,
    settings: Settings,
    pipeline: IOCExtractionPipeline | None = None,
    source_reliability: SourceReliability = SourceReliability.UNKNOWN,
    extractor_name: str = "default",
) -> ThreatIntelExtractionResult:
    """Run the full nine-stage extraction pipeline for one
    `NormalizedEvidence` artifact. Validation failures never raise — an
    invalid candidate is recorded in `rejected_candidates` and extraction
    continues (constitution §1.7); this differs deliberately from
    `evidence_service.ingest_evidence()`, where an *upload* validation
    failure is a rejected artifact. Here, one bad IOC candidate must never
    abort discovery of every other valid one in the same evidence artifact.
    """
    pipeline = pipeline or IOCExtractionPipeline(settings=settings)

    with logging_context(case_id=str(case_id)):
        candidates = pipeline.discover(evidence, extractor_name=extractor_name)
        valid, rejected = pipeline.validate(candidates)
        normalized = pipeline.normalize(valid)
        deduplicated, truncated_count = pipeline.deduplicate(normalized)
        rule_matches = pipeline.classify(deduplicated)
        scored_iocs = pipeline.score(
            deduplicated,
            rule_matches,
            evidence_quality=evidence.confidence,
            source_reliability=source_reliability,
        )

        extractor = pipeline._extractor_registry.get(extractor_name)  # noqa: SLF001
        persisted = await pipeline.persist(
            session,
            case_id=case_id,
            evidence_id=evidence.evidence_id,
            extractor_name=extractor.name,
            extractor_version=extractor.version,
            scored_iocs=scored_iocs,
        )
        pipeline.publish_event(evidence.evidence_id, extractor.name, scored_iocs)
        await pipeline.notify_memory(case_id, evidence.evidence_id, scored_iocs)

        for row in persisted:
            log_threat_intel_audit_event(
                action=AuditAction.PERSISTED,
                ioc_id=row.id,
                evidence_id=evidence.evidence_id,
                case_id=case_id,
                ioc_type=row.ioc_type.value,
            )
        if rejected:
            log_threat_intel_audit_event(
                action=AuditAction.REJECTED,
                ioc_id=None,
                evidence_id=evidence.evidence_id,
                case_id=case_id,
                detail=f"{len(rejected)} candidate(s) rejected",
            )

        metadata: dict[str, object] = {"rejected_count": len(rejected)}
        if truncated_count:
            metadata["truncated_iocs"] = truncated_count

        normalized_threat_intel = NormalizedThreatIntel(
            evidence_id=evidence.evidence_id,
            source=evidence.source,
            extractor_name=extractor.name,
            extractor_version=extractor.version,
            iocs=tuple(scored_iocs),
            rejected_candidates=tuple(rejected),
            metadata=metadata,
        )

        return ThreatIntelExtractionResult(
            case_id=case_id,
            evidence_id=evidence.evidence_id,
            ioc_count=len(scored_iocs),
            rejected_count=len(rejected),
            normalized_threat_intel=normalized_threat_intel,
        )


async def get_ioc(session: AsyncSession, ioc_id: uuid.UUID) -> IOC | None:
    repository = IOCRepository(session)
    return await repository.get_by_id(ioc_id)


async def list_iocs_for_case(
    session: AsyncSession, case_id: uuid.UUID, *, limit: int = 50, cursor: uuid.UUID | None = None
) -> list[IOC]:
    repository = IOCRepository(session)
    return await repository.find_by_case(case_id, limit=limit, cursor=cursor)
