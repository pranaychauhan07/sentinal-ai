"""Evidence Manager — the Upload/Parsing Pipeline orchestrator (blueprint §9
steps 1-3, ADR-0011). `EvidencePipeline` implements the ten named stages the
task asked for, each independently unit-testable; `ingest_evidence()`
composes them into the one call `apps/api`/`apps/web` (once they exist) or a
test harness invokes.

`core/services` importing `core/parsers` directly (rather than only
`core/graph`) is a documented, deliberate exception —
`docs/adr/0011-evidence-ingestion-pipeline-shape.md` point 1: ingestion is
pre-investigation, deterministic, and involves no agent/LLM reasoning.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.db.evidence_repository import EvidenceRepository
from core.db.models.evidence import Evidence, EvidenceStatus
from core.logging import get_logger, logging_context
from core.memory.interfaces import CaseMemory
from core.parsers.audit import AuditAction, log_evidence_audit_event
from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.detection import detect_encoding, detect_mime_type
from core.parsers.events import ParserEvent, ParserEventPublisher, ParserEventType
from core.parsers.exceptions import ParserError
from core.parsers.factory import select_parser
from core.parsers.fingerprint import FileFingerprint, compute_sha256
from core.parsers.metrics import ParserMetricsCollector
from core.parsers.models import NormalizedEvidence
from core.parsers.registry import ParserRegistry, default_parser_registry
from core.parsers.validation import MAX_RECORDS_PER_ARTIFACT, validate_upload

_logger = get_logger(__name__)

#: Confidence below which a successfully-persisted result is still flagged
#: as a degraded ingestion event (distinct from a hard failure).
DEGRADED_CONFIDENCE_THRESHOLD = 0.5


class EvidenceIngestionResult(BaseModel):
    """What `ingest_evidence()` returns — the one typed contract every
    caller (a future API route, a test) reads."""

    model_config = ConfigDict(frozen=True)

    evidence_id: uuid.UUID
    status: EvidenceStatus
    confidence: float
    warnings: list[str]
    normalized_evidence: NormalizedEvidence


class EvidencePipeline:
    """The ten-stage ingestion pipeline, each stage a small, typed,
    independently-testable method:
    upload -> validate -> fingerprint -> extract_metadata -> select_parser ->
    parse -> normalize -> persist -> publish_event -> notify_memory.

    Every dependency is injected (constitution §2, "dependency injection") —
    nothing here reaches for a module-level singleton except the documented,
    explicitly-cached `default_parser_registry()` when the caller doesn't
    provide one.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        registry: ParserRegistry | None = None,
        event_publisher: ParserEventPublisher | None = None,
        metrics: ParserMetricsCollector | None = None,
        case_memory: CaseMemory | None = None,
        ingested_by: str = "unknown",
    ) -> None:
        self._settings = settings
        self._registry = registry or default_parser_registry()
        self._event_publisher = event_publisher or ParserEventPublisher()
        self._metrics = metrics or ParserMetricsCollector()
        self._case_memory = case_memory
        self._ingested_by = ingested_by

    @property
    def ingested_by(self) -> str:
        return self._ingested_by

    # -- Stage 1: Upload -------------------------------------------------
    def upload(self, filename: str, content: bytes) -> RawEvidenceInput:
        return RawEvidenceInput(filename=filename, content=content, ingested_by=self._ingested_by)

    # -- Stage 2: Validation ----------------------------------------------
    def validate(self, raw: RawEvidenceInput) -> str:
        """Returns the validated, lowercased extension. Raises a
        `core.parsers.exceptions.ParserError` subclass on the first
        violation (constitution §10, boundary validation)."""
        _sanitized_filename, extension = validate_upload(raw.filename, raw.content, self._settings)
        return extension

    # -- Stage 3: Fingerprinting ------------------------------------------
    def fingerprint(self, raw: RawEvidenceInput) -> FileFingerprint:
        return compute_sha256(raw.content)

    # -- Stage 4: Metadata extraction --------------------------------------
    def extract_metadata(self, raw: RawEvidenceInput) -> dict[str, str]:
        _decoded_text, encoding_result = detect_encoding(raw.content)
        return {
            "mime_type": detect_mime_type(raw.filename),
            "encoding": encoding_result.encoding,
        }

    # -- Stage 5: Parser selection ------------------------------------------
    def select_parser_for(self, raw: RawEvidenceInput, extension: str) -> BaseParser:
        decoded_text, _ = detect_encoding(raw.content)
        return select_parser(self._registry, raw, decoded_text, extension=extension)

    # -- Stage 6: Parsing ---------------------------------------------------
    def parse(self, parser: BaseParser, raw: RawEvidenceInput) -> NormalizedEvidence:
        return parser(raw)

    # -- Stage 7: Normalization ----------------------------------------------
    def normalize(self, normalized: NormalizedEvidence) -> NormalizedEvidence:
        """Framework-wide invariants applied uniformly across every
        parser's output — currently: the resource-exhaustion cap on record
        count (constitution §10's "resource exhaustion" prevention;
        per-upload size is already capped in `validate()`)."""
        if len(normalized.records) <= MAX_RECORDS_PER_ARTIFACT:
            return normalized
        truncated_count = len(normalized.records) - MAX_RECORDS_PER_ARTIFACT
        return normalized.model_copy(
            update={
                "records": normalized.records[:MAX_RECORDS_PER_ARTIFACT],
                "metadata": {
                    **normalized.metadata,
                    "truncated_records": truncated_count,
                },
            }
        )

    # -- Stage 8: Persistence -------------------------------------------------
    async def persist(
        self,
        session: AsyncSession,
        *,
        case_id: uuid.UUID,
        raw: RawEvidenceInput,
        extension: str,
        fingerprint: FileFingerprint,
        metadata: dict[str, str],
        normalized: NormalizedEvidence,
    ) -> Evidence:
        storage_ref = self._store_raw_content(raw.content, fingerprint.sha256, extension)
        repository = EvidenceRepository(session)
        evidence = Evidence(
            case_id=case_id,
            evidence_type=normalized.evidence_type,
            original_filename=raw.filename,
            storage_ref=storage_ref,
            sha256=fingerprint.sha256,
            file_size_bytes=fingerprint.size_bytes,
            mime_type=metadata["mime_type"],
            encoding=metadata["encoding"],
            uploaded_at=datetime.now(UTC),
        )
        await repository.add(evidence)
        await repository.mark_parsed(
            evidence.id,
            parser_name=normalized.parser_name,
            parser_version=normalized.parser_version,
            parser_confidence=normalized.confidence,
            parsed_json=normalized.model_dump_json(),
        )
        return evidence

    def _store_raw_content(self, content: bytes, sha256: str, extension: str) -> str:
        """Content-addressed local storage: idempotent (re-uploading the
        same bytes writes the same path), avoiding duplicate blobs on disk.
        A future object-store swap (S3/Azure Blob) replaces only this
        method — every caller only ever sees the returned `storage_ref`."""
        storage_dir = Path(self._settings.evidence_storage_dir)
        storage_dir.mkdir(parents=True, exist_ok=True)
        destination = storage_dir / f"{sha256}{extension}"
        if not destination.exists():
            destination.write_bytes(content)
        return str(destination)

    # -- Stage 9: Event publication -------------------------------------------
    def publish_event(self, evidence: Evidence, normalized: NormalizedEvidence) -> None:
        event_type = (
            ParserEventType.DEGRADED
            if normalized.confidence < DEGRADED_CONFIDENCE_THRESHOLD
            else ParserEventType.PARSED
        )
        self._event_publisher.publish(
            ParserEvent(
                event_type=event_type,
                evidence_id=evidence.id,
                parser_name=normalized.parser_name,
                source=normalized.source,
                detail=f"confidence={normalized.confidence}",
            )
        )

    # -- Stage 10: Memory notification ----------------------------------------
    async def notify_memory(
        self, case_id: uuid.UUID, evidence: Evidence, normalized: NormalizedEvidence
    ) -> None:
        """Advisory-only (constitution/ADR-0006's "memory is always
        advisory, never a hard dependency"): a failure here is logged and
        swallowed, never raised — matching every other `core/memory`
        consumer's contract."""
        if self._case_memory is None:
            return
        try:
            await self._case_memory.add_note(
                case_id,
                f"Evidence {evidence.id} ({normalized.evidence_type.value}) ingested "
                f"with {normalized.record_count} record(s), confidence={normalized.confidence}.",
            )
        except Exception as exc:  # noqa: BLE001 - memory is advisory, must never break ingestion
            _logger.warning(
                "evidence_memory_notify_failed", evidence_id=str(evidence.id), error=str(exc)
            )


async def ingest_evidence(
    session: AsyncSession,
    *,
    case_id: uuid.UUID,
    filename: str,
    content: bytes,
    settings: Settings,
    pipeline: EvidencePipeline | None = None,
) -> EvidenceIngestionResult:
    """Run the full ten-stage ingestion pipeline for one uploaded artifact.

    Upload/validation failures (`core.parsers.exceptions.ParserError`
    subclasses) are audit-logged as `REJECTED` and re-raised — typed, never
    a bare `500` (constitution §9) — for the caller (a future API route) to
    translate into a `4xx` response. A parser-internal failure never reaches
    here as an exception: `BaseParser.__call__` already degrades it into a
    low-confidence `NormalizedEvidence` (constitution §1.7).
    """
    pipeline = pipeline or EvidencePipeline(settings=settings)

    with logging_context(case_id=str(case_id)):
        raw = pipeline.upload(filename, content)
        try:
            extension = pipeline.validate(raw)
        except ParserError as exc:
            log_evidence_audit_event(
                action=AuditAction.REJECTED,
                evidence_id=None,
                case_id=case_id,
                actor=pipeline.ingested_by,
                filename=filename,
                detail=str(exc),
            )
            raise

        fingerprint = pipeline.fingerprint(raw)
        metadata = pipeline.extract_metadata(raw)
        parser = pipeline.select_parser_for(raw, extension)
        normalized = pipeline.parse(parser, raw)
        normalized = pipeline.normalize(normalized)

        evidence = await pipeline.persist(
            session,
            case_id=case_id,
            raw=raw,
            extension=extension,
            fingerprint=fingerprint,
            metadata=metadata,
            normalized=normalized,
        )
        pipeline.publish_event(evidence, normalized)
        await pipeline.notify_memory(case_id, evidence, normalized)

        log_evidence_audit_event(
            action=AuditAction.PERSISTED,
            evidence_id=evidence.id,
            case_id=case_id,
            actor=pipeline._ingested_by,  # noqa: SLF001
            filename=filename,
            sha256=fingerprint.sha256,
        )

        return EvidenceIngestionResult(
            evidence_id=evidence.id,
            status=evidence.status,
            confidence=normalized.confidence,
            warnings=list(normalized.unparsed_fragments[:5]),
            normalized_evidence=normalized,
        )


async def get_evidence(session: AsyncSession, evidence_id: uuid.UUID) -> Evidence | None:
    repository = EvidenceRepository(session)
    return await repository.get_by_id(evidence_id)


async def list_evidence_for_case(
    session: AsyncSession, case_id: uuid.UUID, *, limit: int = 50, cursor: uuid.UUID | None = None
) -> list[Evidence]:
    repository = EvidenceRepository(session)
    return await repository.find_by_case(case_id, limit=limit, cursor=cursor)
