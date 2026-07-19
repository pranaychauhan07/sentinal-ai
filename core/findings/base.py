"""`BaseFindingGenerator` — the Finding & MITRE ATT&CK Intelligence Engine's
template-method base, shaped identically to `core.threat_intel.base.
BaseIOCExtractor`/`core.parsers.base.BaseParser`.

Subclasses implement only `map_candidates`; `__call__` owns timing,
structured logging, metrics recording, and the constitution §1.7 contract: a
single malformed input degrades to a partial result, never a crash and
never a silent, total data loss.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, ConfigDict

from core.findings.exceptions import FindingsError
from core.findings.models import MitreMapping
from core.logging import get_logger
from core.threat_intel.models import ScoredIOC

if TYPE_CHECKING:
    from core.findings.metrics import FindingsMetricsCollector

_logger = get_logger(__name__)


class MappingRunResult(BaseModel):
    """One `BaseFindingGenerator.__call__` invocation's outcome — mirrors
    `core.threat_intel.base.ExtractorRunResult`'s shape exactly."""

    model_config = ConfigDict(frozen=True)

    engine_name: str
    succeeded: bool
    mapping_count: int
    started_at: datetime
    completed_at: datetime

    @property
    def duration_ms(self) -> float:
        return (self.completed_at - self.started_at).total_seconds() * 1000.0


class BaseFindingGenerator(ABC):
    """Template method: subclasses implement only `map_candidates`.
    `__call__` is the one public entry point every caller (the service, a
    test) uses."""

    name: ClassVar[str]
    description: ClassVar[str]
    version: ClassVar[str] = "1.0.0"

    def __init__(self, *, metrics: FindingsMetricsCollector | None = None) -> None:
        self._metrics = metrics
        self.last_run: MappingRunResult | None = None

    @abstractmethod
    def map_candidates(self, iocs: list[ScoredIOC]) -> list[MitreMapping]:
        """Return every candidate ATT&CK mapping found across `iocs`. This
        method's only responsibility is mapping discovery — confidence
        refinement across a whole Finding, aggregation, and deduplication
        are the pipeline's job (`core.services.finding_service.
        FindingGenerationPipeline`)."""
        raise NotImplementedError

    def __call__(self, iocs: list[ScoredIOC]) -> list[MitreMapping]:
        started_at = datetime.now(UTC)
        succeeded = True
        mappings: list[MitreMapping] = []
        try:
            mappings = self.map_candidates(iocs)
        except FindingsError as exc:
            succeeded = False
            _logger.warning("mitre_mapping_degraded", engine=self.name, error=str(exc))
        finally:
            completed_at = datetime.now(UTC)
            self.last_run = MappingRunResult(
                engine_name=self.name,
                succeeded=succeeded,
                mapping_count=len(mappings),
                started_at=started_at,
                completed_at=completed_at,
            )
            if self._metrics is not None:
                self._metrics.record_run(self.name, self.last_run)
            _logger.debug(
                "mitre_mapping_executed",
                engine=self.name,
                succeeded=succeeded,
                mapping_count=len(mappings),
                duration_ms=self.last_run.duration_ms,
            )
        return mappings
