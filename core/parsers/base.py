"""``BaseParser`` — the concrete base every format-specific parser in
`core/parsers/*.py` implements, shaped identically to
`core/tools/base.py::BaseTool` and `core/agents/base.py::BaseAgent`
(template method: the abstract base owns the mechanical parts, subclasses
implement only the domain-specific step).

Framework-only: no format-specific extraction logic lives here. This module
gives every concrete parser, for free: encoding detection, timing, structured
logging, metrics emission, and the constitution §1.7 contract ("a parser that
can't fully parse an artifact returns a partial, confidence-scored result ...
never both crashes the investigation and silently drops data").
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import ClassVar

from pydantic import BaseModel, ConfigDict

from core.logging import get_logger
from core.parsers.detection import detect_encoding
from core.parsers.exceptions import MalformedEvidenceError
from core.parsers.fingerprint import FileFingerprint, compute_sha256
from core.parsers.metrics import ParserMetricsCollector
from core.parsers.models import ChainOfCustody, EvidenceType, NormalizedEvidence

_logger = get_logger(__name__)


class RawEvidenceInput(BaseModel):
    """The uploaded artifact, exactly as received — bytes plus the metadata
    the caller (`core/services/evidence_service.py`) already knows about it.
    """

    model_config = ConfigDict(frozen=True)

    filename: str
    content: bytes
    declared_type: EvidenceType | None = None
    ingested_by: str = "unknown"


class ParserRunResult(BaseModel):
    """Timing/outcome record for one parser invocation — the parser-layer
    equivalent of `core.tools.base.ToolExecutionMetadata`, kept independent
    per the same leaf-layering reasoning (`core/parsers` must never import
    `core/tools`)."""

    model_config = ConfigDict(frozen=True)

    parser_name: str
    succeeded: bool
    started_at: datetime
    completed_at: datetime

    @property
    def duration_ms(self) -> float:
        return (self.completed_at - self.started_at).total_seconds() * 1000


class BaseParser(ABC):
    """Template-method base for every deterministic evidence parser.

    Concrete subclasses declare identity via class attributes and implement
    :meth:`sniff`, :meth:`validate_content`, and :meth:`parse_content`.
    :meth:`__call__` is the one public entry point and owns encoding
    detection, fingerprinting, timing, metrics, logging, and the
    degrade-vs-reject error boundary described below.
    """

    #: Stable, unique parser name — how it's registered in `ParserRegistry`.
    name: ClassVar[str]
    description: ClassVar[str]
    evidence_type: ClassVar[EvidenceType]
    version: ClassVar[str] = "1.0.0"
    #: Extensions this parser claims (including the leading dot), used by
    #: `core.parsers.factory` as one selection signal among several.
    supported_extensions: ClassVar[tuple[str, ...]] = ()
    #: MIME types this parser claims, matching `core.parsers.detection`'s
    #: sniffed candidates.
    supported_mime_types: ClassVar[tuple[str, ...]] = ()

    def __init__(self, *, metrics: ParserMetricsCollector | None = None) -> None:
        self._metrics = metrics
        self.last_run: ParserRunResult | None = None

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        """Confidence (0.0-1.0) that this parser is the right one for `raw`,
        used by `core.parsers.factory.select_parser` when no declared type
        or extension match is available. Default: no opinion. Subclasses
        override with a real content heuristic."""
        return 0.0

    @abstractmethod
    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        """Format-specific structural check (e.g. "has at least one XML
        element", "has a header row"). Raise
        `core.parsers.exceptions.MalformedEvidenceError` on failure — caught
        by `__call__` and converted into a zero-confidence degraded result,
        never propagated raw."""
        raise NotImplementedError

    @abstractmethod
    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        """The actual extraction. Subclasses implement only this (plus
        `validate_content`/`sniff`) — never override `__call__`."""
        raise NotImplementedError

    def __call__(self, raw: RawEvidenceInput) -> NormalizedEvidence:
        started_at = datetime.now(UTC)
        succeeded = False
        try:
            decoded_text, _encoding_result = detect_encoding(raw.content)
            try:
                self.validate_content(raw, decoded_text)
                result = self.parse_content(raw, decoded_text)
            except MalformedEvidenceError as exc:
                _logger.warning(
                    "parser_degraded",
                    parser=self.name,
                    filename=raw.filename,
                    error=str(exc),
                )
                result = self._degraded_result(raw, decoded_text, reason=str(exc))
            succeeded = True
            return result
        finally:
            completed_at = datetime.now(UTC)
            self.last_run = ParserRunResult(
                parser_name=self.name,
                succeeded=succeeded,
                started_at=started_at,
                completed_at=completed_at,
            )
            if self._metrics is not None:
                self._metrics.record_run(self.name, self.last_run)
            _logger.debug(
                "parser_executed",
                parser=self.name,
                filename=raw.filename,
                succeeded=succeeded,
                duration_ms=self.last_run.duration_ms,
            )

    def _degraded_result(
        self, raw: RawEvidenceInput, decoded_text: str, *, reason: str
    ) -> NormalizedEvidence:
        """The constitution §1.7 fallback: never crash, never drop data —
        return a zero-confidence `NormalizedEvidence` carrying the whole
        artifact as an unparsed fragment."""
        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=0.0,
            records=[],
            metadata={"degraded_reason": reason},
            unparsed_fragments=[decoded_text],
            chain_of_custody=self._chain_of_custody(raw),
        )

    def _chain_of_custody(self, raw: RawEvidenceInput) -> ChainOfCustody:
        fingerprint: FileFingerprint = compute_sha256(raw.content)
        return ChainOfCustody(
            ingested_at=datetime.now(UTC),
            ingested_by=raw.ingested_by,
            original_filename=raw.filename,
            sha256=fingerprint.sha256,
            file_size_bytes=fingerprint.size_bytes,
        )

    def raise_if_invalid(self, condition: bool, message: str) -> None:
        """Small validation-guard helper so every `validate_content`
        override doesn't hand-roll the same `if not X: raise` shape. Raises
        `MalformedEvidenceError` — the recoverable, degrade-not-reject path
        (see `__call__`), distinct from the upload-level rejections in
        `core.parsers.validation`."""
        if not condition:
            raise MalformedEvidenceError(message, details={"parser": self.name})
