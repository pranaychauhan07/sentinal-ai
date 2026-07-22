"""Finding Generation Pipeline — the Finding & MITRE ATT&CK Intelligence
Engine's orchestrator (docs/adr/0013-finding-mitre-intelligence-engine-shape.md).
`FindingGenerationPipeline` implements the explicit stages the task's own
diagram calls for — `discover` -> `map_and_generate` -> `deduplicate` ->
`persist` -> `publish_event` -> `notify_memory` — each independently
unit-testable; `generate_findings_for_case()` composes them into the one
call a future `core/agents/mitre_mapping_agent.py`/`threat_hunter_agent.py`
(or a test harness) invokes — mirrors
`core/services/threat_intel_service.py`'s `IOCExtractionPipeline`/
`extract_threat_intelligence()` shape exactly.

`core/services` importing `core/findings`, `core/threat_intel` (models
only), `core/knowledge`, and `core/memory` directly (rather than only
`core/graph`) is a documented, deliberate exception —
docs/adr/0013 point 3 / `docs/dependency-rules.md` rule 4c: Finding
generation is pre-investigation, deterministic, and involves no agent/LLM
reasoning.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.db.finding_repository import FindingRepository
from core.db.ioc_repository import IOCRepository
from core.db.mitre_repository import MitreTechniqueRepository
from core.db.models.finding import Finding
from core.db.models.finding_mitre_mapping import FindingMitreMapping
from core.db.models.ioc import IOCStatus
from core.findings.dedup import FindingDeduplicationEngine, merge_findings
from core.findings.events import FindingEvent, FindingEventPublisher, FindingEventType
from core.findings.finding_generator import FindingGenerationEngine
from core.findings.mapping_engine import MitreMappingEngine
from core.findings.mapping_rules import MAPPING_RULES
from core.findings.metrics import FindingsMetricsCollector
from core.findings.models import DedupDecision, FindingRecord
from core.knowledge.mitre.bootstrap import load_mitre_dataset
from core.knowledge.mitre.lookup import MitreLookup
from core.logging import get_logger, logging_context
from core.memory.interfaces import CaseMemory
from core.threat_intel.models import ScoredIOC, SourceReliability

_logger = get_logger(__name__)


class FindingGenerationResult(BaseModel):
    """What `generate_findings_for_case()` returns — the one typed contract
    every caller (a future agent, a test) reads."""

    model_config = ConfigDict(frozen=True)

    case_id: uuid.UUID
    created_finding_ids: tuple[uuid.UUID, ...]
    merged_finding_ids: tuple[uuid.UUID, ...]
    candidate_count: int


class FindingGenerationPipeline:
    """The Finding Engine's explicit pipeline stages, each a small, typed,
    independently-testable method. Every dependency is injected
    (constitution §2) — the one exception is `_lookup`, built once from the
    vendored MITRE bundle via `core.knowledge.mitre.bootstrap.
    load_mitre_dataset`, since constructing it is itself an explicit,
    documented step, not a hidden global."""

    def __init__(
        self,
        *,
        settings: Settings,
        lookup: MitreLookup | None = None,
        mapping_engine: MitreMappingEngine | None = None,
        generation_engine: FindingGenerationEngine | None = None,
        dedup_engine: FindingDeduplicationEngine | None = None,
        event_publisher: FindingEventPublisher | None = None,
        metrics: FindingsMetricsCollector | None = None,
        case_memory: CaseMemory | None = None,
    ) -> None:
        self._settings = settings
        self._lookup = lookup or MitreLookup(load_mitre_dataset(settings))
        self._metrics = metrics or FindingsMetricsCollector()
        self._mapping_engine = mapping_engine or MitreMappingEngine(
            lookup=self._lookup,
            rules=MAPPING_RULES,
            min_confidence=settings.finding_mapping_min_confidence,
            metrics=self._metrics,
        )
        self._generation_engine = generation_engine or FindingGenerationEngine(
            mapping_engine=self._mapping_engine, lookup=self._lookup
        )
        self._dedup_engine = dedup_engine or FindingDeduplicationEngine(
            time_window_minutes=settings.finding_dedup_time_window_minutes
        )
        self._event_publisher = event_publisher or FindingEventPublisher()
        self._case_memory = case_memory

    # -- Stage 1: Discovery (persisted IOCs -> ScoredIOC) ------------------------
    async def discover(self, session: AsyncSession, case_id: uuid.UUID) -> list[ScoredIOC]:
        """Reconstructs the case's `ScoredIOC`s from `IOC.metadata_json`
        (the full serialized `ScoredIOC` the Threat Intelligence Layer
        already persisted) — never re-extracts or re-scores. Rows with a
        status other than `ACTIVE` (dismissed/false-positive/failed) are
        excluded; an analyst's dismissal must not resurrect a Finding."""
        repository = IOCRepository(session)
        rows = await repository.find_by_case(
            case_id, limit=self._settings.finding_max_candidates_per_case
        )
        scored: list[ScoredIOC] = []
        for row in rows:
            if row.status is not IOCStatus.ACTIVE:
                continue
            try:
                scored.append(ScoredIOC.model_validate_json(row.metadata_json or "{}"))
            except ValueError as exc:
                _logger.warning(
                    "finding_discovery_skipped_malformed_ioc", ioc_id=str(row.id), error=str(exc)
                )
        return scored

    # -- Stage 2: MITRE mapping + Finding generation ---------------------------
    def map_and_generate(
        self,
        case_id: uuid.UUID,
        iocs: list[ScoredIOC],
        *,
        source_reliability: SourceReliability = SourceReliability.UNKNOWN,
    ) -> list[FindingRecord]:
        candidates = self._generation_engine.generate(
            case_id, iocs, source_reliability=source_reliability
        )
        for candidate in candidates:
            for mapping in candidate.mitre_mappings:
                self._metrics.record_technique_match(mapping.technique_id)
        return candidates

    # -- Stage 3: Deduplication -------------------------------------------------
    def deduplicate(
        self, candidates: list[FindingRecord], existing_findings: list[FindingRecord]
    ) -> list[tuple[FindingRecord, DedupDecision, FindingRecord | None]]:
        """Returns one `(candidate, decision, matched_existing_or_None)`
        triple per candidate. Matching is evaluated against `existing_findings`
        as passed in, plus any Findings this same call already decided are
        `NEW` — so two near-duplicate candidates generated in the same run
        (e.g. two techniques sharing every supporting IOC) merge into each
        other rather than both landing as separate open Findings."""
        decisions: list[tuple[FindingRecord, DedupDecision, FindingRecord | None]] = []
        pool = list(existing_findings)
        for candidate in candidates:
            result = self._dedup_engine.evaluate(
                candidate_ioc_ids=candidate.ioc_refs,
                candidate_evidence_ids=candidate.evidence_refs,
                candidate_mappings=list(candidate.mitre_mappings),
                candidate_affected_assets=candidate.affected_assets,
                candidate_first_seen=candidate.created_at,
                candidate_last_seen=candidate.updated_at,
                existing_findings=pool,
                similarity_threshold=self._settings.finding_dedup_similarity_threshold,
            )
            if result.decision is DedupDecision.MERGE and result.matched_finding_id is not None:
                matched = next(f for f in pool if f.finding_id == result.matched_finding_id)
                merged = merge_findings(matched, candidate)
                pool = [merged if f.finding_id == matched.finding_id else f for f in pool]
                decisions.append((candidate, DedupDecision.MERGE, merged))
                self._metrics.record_duplicate_rejected()
            else:
                pool.append(candidate)
                decisions.append((candidate, DedupDecision.NEW, None))
        return decisions

    # -- Stage 4: Persistence ---------------------------------------------------
    async def persist(
        self,
        session: AsyncSession,
        decisions: list[tuple[FindingRecord, DedupDecision, FindingRecord | None]],
    ) -> tuple[list[Finding], list[Finding]]:
        finding_repo = FindingRepository(session)
        technique_repo = MitreTechniqueRepository(session)
        created: list[Finding] = []
        merged: list[Finding] = []

        for candidate, decision, merged_record in decisions:
            if decision is DedupDecision.NEW:
                row = self._to_finding_row(candidate)
                await finding_repo.add(row)
                await self._persist_mappings(technique_repo, finding_repo, row.id, candidate)
                created.append(row)
                self._metrics.record_finding_generated()
            else:
                assert merged_record is not None
                existing_row = await finding_repo.get_by_id(merged_record.finding_id)
                if existing_row is None:
                    _logger.error(
                        "finding_merge_target_missing", finding_id=str(merged_record.finding_id)
                    )
                    continue
                self._apply_merged_record(existing_row, merged_record)
                await session.flush()
                await self._persist_mappings(
                    technique_repo, finding_repo, existing_row.id, merged_record, only_new=True
                )
                merged.append(existing_row)
                self._metrics.record_finding_merged()
        return created, merged

    async def _persist_mappings(
        self,
        technique_repo: MitreTechniqueRepository,
        finding_repo: FindingRepository,
        finding_id: uuid.UUID,
        record: FindingRecord,
        *,
        only_new: bool = False,
    ) -> None:
        existing_technique_row_ids: set[uuid.UUID] = set()
        if only_new:
            existing = await finding_repo.mappings_for_finding(finding_id)
            existing_technique_row_ids = {m.mitre_technique_id for m in existing}

        for mapping in record.mitre_mappings:
            technique_row = await technique_repo.find_by_technique_id(
                mapping.technique_id, mapping.attack_spec_version
            )
            if technique_row is None:
                _logger.error(
                    "finding_mapping_technique_not_seeded",
                    technique_id=mapping.technique_id,
                    detail=(
                        "MitreTechnique reference row missing — run "
                        "scripts/mitre/import_attack_bundle.py before generating Findings."
                    ),
                )
                continue
            if technique_row.id in existing_technique_row_ids:
                continue
            await finding_repo.add_mapping(
                FindingMitreMapping(
                    finding_id=finding_id,
                    mitre_technique_id=technique_row.id,
                    confidence=mapping.confidence,
                    mapping_source=mapping.mapping_source,
                    attack_spec_version=mapping.attack_spec_version,
                )
            )

    @staticmethod
    def _to_finding_row(record: FindingRecord) -> Finding:
        """`Finding.id` is explicitly set to `record.finding_id` rather than
        left to `Entity`'s default `uuid.uuid4` factory — the persisted
        row's surrogate PK and the embedded `FindingRecord.finding_id` must
        be the same identity, since `deduplicate()`/`merge_findings()`
        reason about "this Finding" purely in terms of `FindingRecord.
        finding_id` and `persist()` looks a merge target up by that same
        value."""
        return Finding(
            id=record.finding_id,
            case_id=record.case_id,
            primary_evidence_id=record.evidence_refs[0] if record.evidence_refs else None,
            primary_ioc_id=record.ioc_refs[0] if record.ioc_refs else None,
            title=record.title,
            description=record.description,
            severity=record.severity,
            confidence=record.confidence.composite,
            status=record.status,
            priority=record.priority,
            risk_score=record.risk_score,
            ioc_count=len(record.ioc_refs),
            finding_data_json=record.model_dump_json(),
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    @staticmethod
    def _apply_merged_record(row: Finding, merged_record: FindingRecord) -> None:
        row.title = merged_record.title
        row.description = merged_record.description
        row.severity = merged_record.severity
        row.confidence = merged_record.confidence.composite
        row.status = merged_record.status
        row.priority = merged_record.priority
        row.risk_score = merged_record.risk_score
        row.ioc_count = len(merged_record.ioc_refs)
        row.finding_data_json = merged_record.model_dump_json()
        row.updated_at = datetime.now(UTC)

    # -- Stage 5: Event publication ----------------------------------------------
    def publish_event(
        self,
        case_id: uuid.UUID,
        decisions: list[tuple[FindingRecord, DedupDecision, FindingRecord | None]],
    ) -> None:
        for candidate, decision, merged_record in decisions:
            for mapping in candidate.mitre_mappings:
                self._event_publisher.publish(
                    FindingEvent(
                        event_type=FindingEventType.TECHNIQUE_MAPPED,
                        case_id=case_id,
                        finding_id=candidate.finding_id,
                        technique_id=mapping.technique_id,
                        detail=f"confidence={mapping.confidence:.2f}",
                    )
                )
            if decision is DedupDecision.NEW:
                self._event_publisher.publish(
                    FindingEvent(
                        event_type=FindingEventType.FINDING_CREATED,
                        case_id=case_id,
                        finding_id=candidate.finding_id,
                    )
                )
            else:
                assert merged_record is not None
                self._event_publisher.publish(
                    FindingEvent(
                        event_type=FindingEventType.FINDING_MERGED,
                        case_id=case_id,
                        finding_id=candidate.finding_id,
                        merged_into_finding_id=merged_record.finding_id,
                    )
                )
            self._event_publisher.publish(
                FindingEvent(
                    event_type=FindingEventType.CONFIDENCE_UPDATED,
                    case_id=case_id,
                    finding_id=(merged_record or candidate).finding_id,
                    detail=f"composite={candidate.confidence.composite:.2f}",
                )
            )

    # -- Stage 6: Memory notification -----------------------------------------------
    async def notify_memory(
        self, case_id: uuid.UUID, created: list[Finding], merged: list[Finding]
    ) -> None:
        """Advisory-only (ADR-0006's "memory is always advisory, never a
        hard dependency") — matches `threat_intel_service.notify_memory`'s
        contract exactly."""
        if self._case_memory is None or not (created or merged):
            return
        try:
            await self._case_memory.add_note(
                case_id,
                f"Finding generation produced {len(created)} new Finding(s) and "
                f"merged {len(merged)} into existing ones.",
            )
        except Exception as exc:  # noqa: BLE001 - memory is advisory, must never break generation
            _logger.warning("finding_memory_notify_failed", case_id=str(case_id), error=str(exc))


async def generate_findings_for_case(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    settings: Settings,
    pipeline: FindingGenerationPipeline | None = None,
    source_reliability: SourceReliability = SourceReliability.UNKNOWN,
) -> FindingGenerationResult:
    """Run the full Finding Generation Pipeline for one case's currently
    active IOCs."""
    pipeline = pipeline or FindingGenerationPipeline(settings=settings)

    with logging_context(case_id=str(case_id)):
        iocs = await pipeline.discover(session, case_id)
        candidates = pipeline.map_and_generate(case_id, iocs, source_reliability=source_reliability)

        finding_repo = FindingRepository(session)
        existing_rows = await finding_repo.find_open_for_case(case_id)
        existing_records = [
            FindingRecord.model_validate_json(row.finding_data_json) for row in existing_rows
        ]

        decisions = pipeline.deduplicate(candidates, existing_records)
        created_rows, merged_rows = await pipeline.persist(session, decisions)
        pipeline.publish_event(case_id, decisions)
        await pipeline.notify_memory(case_id, created_rows, merged_rows)

        return FindingGenerationResult(
            case_id=case_id,
            created_finding_ids=tuple(row.id for row in created_rows),
            merged_finding_ids=tuple(row.id for row in merged_rows),
            candidate_count=len(candidates),
        )


async def get_finding(session: AsyncSession, finding_id: uuid.UUID) -> Finding | None:
    repository = FindingRepository(session)
    return await repository.get_by_id(finding_id)


async def list_findings_for_case(
    session: AsyncSession, case_id: uuid.UUID, *, limit: int = 50, cursor: uuid.UUID | None = None
) -> list[Finding]:
    repository = FindingRepository(session)
    return await repository.find_by_case(case_id, limit=limit, cursor=cursor)


class CaseMitreMappingSummary(BaseModel):
    """One case's mapped MITRE technique, joined with its reference-table
    name/tactics and the count of Findings that mapped to it — the read
    shape blueprint §13's MITRE ATT&CK Coverage view needs
    (`apps/web/pages/5_MITRE_Map.py`), not otherwise exposed by
    `list_findings_for_case` (which returns raw `Finding` rows, each only
    carrying its mappings inside `finding_data_json`, not joined with the
    `MitreTechnique` reference table's name/tactics)."""

    model_config = ConfigDict(frozen=True)

    technique_id: str
    technique_name: str
    tactic_shortnames: tuple[str, ...]
    finding_count: int
    max_confidence: float


async def list_mitre_mappings_for_case(
    session: AsyncSession, case_id: uuid.UUID
) -> list[CaseMitreMappingSummary]:
    """Aggregates `FindingRepository.mitre_mappings_for_case`'s per-mapping
    rows into one summary per distinct technique (a technique mapped from
    several Findings collapses into one row with a Finding count) — never a
    re-derivation of the mapping itself (constitution §1.9), purely a
    read-side grouping of what `FindingGenerationPipeline` already computed
    and persisted."""
    repository = FindingRepository(session)
    rows = await repository.mitre_mappings_for_case(case_id)

    by_technique: dict[str, CaseMitreMappingSummary] = {}
    for mapping, technique, _finding in rows:
        try:
            tactic_shortnames = tuple(json.loads(technique.tactic_shortnames_json))
        except (TypeError, ValueError):
            tactic_shortnames = ()
        existing = by_technique.get(technique.technique_id)
        if existing is None:
            by_technique[technique.technique_id] = CaseMitreMappingSummary(
                technique_id=technique.technique_id,
                technique_name=technique.name,
                tactic_shortnames=tactic_shortnames,
                finding_count=1,
                max_confidence=mapping.confidence,
            )
        else:
            by_technique[technique.technique_id] = existing.model_copy(
                update={
                    "finding_count": existing.finding_count + 1,
                    "max_confidence": max(existing.max_confidence, mapping.confidence),
                }
            )
    return sorted(by_technique.values(), key=lambda s: s.technique_id)
