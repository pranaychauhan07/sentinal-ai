"""`BaseIOCExtractor` — the Threat Intelligence Layer's template-method base,
shaped identically to `core.parsers.base.BaseParser` (docs/adr/0012 point 1:
`core/threat_intel` is a peer leaf, same tier as `core/parsers`).

Subclasses implement only `extract_candidates`; `__call__` owns timing,
structured logging, metrics recording, and the constitution §1.7 contract:
a single malformed/oversized artifact degrades to a partial result (whatever
candidates were found before the failure), never a crash and never a
silent, total data loss.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, ConfigDict

from core.logging import get_logger
from core.parsers.models import NormalizedEvidence
from core.threat_intel.exceptions import OversizedEvidenceError, ThreatIntelError
from core.threat_intel.models import IOCRecord, IOCType

if TYPE_CHECKING:
    from core.threat_intel.metrics import ThreatIntelMetricsCollector

_logger = get_logger(__name__)


class ExtractorRunResult(BaseModel):
    """One `BaseIOCExtractor.__call__` invocation's outcome — mirrors
    `core.parsers.base.ParserRunResult`'s shape exactly."""

    model_config = ConfigDict(frozen=True)

    extractor_name: str
    succeeded: bool
    candidate_count: int
    started_at: datetime
    completed_at: datetime

    @property
    def duration_ms(self) -> float:
        return (self.completed_at - self.started_at).total_seconds() * 1000.0


class BaseIOCExtractor(ABC):
    """Template method: subclasses implement only `extract_candidates`.
    `__call__` is the one public entry point every caller (the registry, the
    pipeline, a test) uses."""

    name: ClassVar[str]
    description: ClassVar[str]
    ioc_types: ClassVar[tuple[IOCType, ...]]
    version: ClassVar[str] = "1.0.0"

    def __init__(self, *, metrics: ThreatIntelMetricsCollector | None = None) -> None:
        self._metrics = metrics
        self.last_run: ExtractorRunResult | None = None

    @abstractmethod
    def extract_candidates(self, evidence: NormalizedEvidence) -> list[IOCRecord]:
        """Return every candidate IOC found in `evidence`. Candidates are
        *not yet* validated/normalized/deduplicated — that is the
        pipeline's job (`core.services.threat_intel_service.
        IOCExtractionPipeline`); this method's only responsibility is
        discovery."""
        raise NotImplementedError

    def __call__(self, evidence: NormalizedEvidence) -> list[IOCRecord]:
        started_at = datetime.now(UTC)
        succeeded = True
        candidates: list[IOCRecord] = []
        try:
            candidates = self.extract_candidates(evidence)
        except ThreatIntelError as exc:
            succeeded = False
            _logger.warning(
                "ioc_extraction_degraded",
                extractor=self.name,
                evidence_id=str(evidence.evidence_id),
                error=str(exc),
            )
        finally:
            completed_at = datetime.now(UTC)
            self.last_run = ExtractorRunResult(
                extractor_name=self.name,
                succeeded=succeeded,
                candidate_count=len(candidates),
                started_at=started_at,
                completed_at=completed_at,
            )
            if self._metrics is not None:
                self._metrics.record_run(self.name, self.last_run)
            _logger.debug(
                "ioc_extraction_executed",
                extractor=self.name,
                evidence_id=str(evidence.evidence_id),
                succeeded=succeeded,
                candidate_count=len(candidates),
                duration_ms=self.last_run.duration_ms,
            )
        return candidates

    def raise_if_oversized(self, length: int, *, max_chars: int) -> None:
        """Guard helper every concrete extractor calls before scanning
        text — the resource-exhaustion boundary (constitution §10). Takes a
        pre-computed character count rather than the text itself so callers
        never have to materialize a throwaway string just to check size."""
        if length > max_chars:
            raise OversizedEvidenceError(
                f"Evidence text of {length} characters exceeds the "
                f"{max_chars}-character extraction limit.",
                details={"length": length, "max_chars": max_chars},
            )
