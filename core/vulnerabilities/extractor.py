"""`VulnerabilityExtractionEngine` — the Vulnerability Extraction pipeline
stage (task requirement). Reads the *structured* per-finding fields
`core/parsers/{nessus,openvas}*.py` already place on
`EvidenceRecord.normalized_fields` (scan reports are structured data, not
free text — unlike log/email evidence, no regex-over-raw-text discovery is
the primary path here) and builds candidate `VulnerabilityRecord`s.
Supplements each candidate's CVE/CWE list with
`core.vulnerabilities.cve_extractor`'s regex discovery over the
description/references text, for the (real, common) case where a plugin's
free-text description names a CVE its structured field list omitted.

Discovery only — validation/normalization/dedup/scoring are later pipeline
stages (`core.services.vulnerability_service.VulnerabilityPipeline`),
mirroring `core.threat_intel.extractor.IOCExtractionEngine`'s identical
"discovery only" scope note.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, ConfigDict

from core.knowledge.cvss_calculator import (
    CvssCalculator,
    CvssScore,
    CVSSVectorParseError,
    CvssVersion,
    classify_cvss_severity,
)
from core.logging import get_logger
from core.parsers.models import EvidenceRecord, NormalizedEvidence
from core.vulnerabilities.cve_extractor import extract_cve_ids, extract_cwe_ids
from core.vulnerabilities.exceptions import OversizedVulnerabilityDatasetError, VulnerabilityError
from core.vulnerabilities.models import DetectionSource, VulnerabilityRecord
from core.vulnerabilities.severity import severity_from_cvss, severity_from_scanner_code

if TYPE_CHECKING:
    from core.vulnerabilities.metrics import VulnerabilityMetricsCollector

_logger = get_logger(__name__)

#: Resource-exhaustion guard for the whole artifact (constitution §10);
#: overridable per-instance, driven by
#: `Settings.vulnerability_max_records_per_artifact`.
DEFAULT_MAX_CANDIDATES_PER_ARTIFACT = 20_000

_cvss_calculator = CvssCalculator()


class ExtractorRunResult(BaseModel):
    """One `BaseVulnerabilityExtractor.__call__` invocation's outcome —
    mirrors `core.threat_intel.base.ExtractorRunResult`'s shape exactly."""

    model_config = ConfigDict(frozen=True)

    extractor_name: str
    succeeded: bool
    candidate_count: int
    started_at: datetime
    completed_at: datetime

    @property
    def duration_ms(self) -> float:
        return (self.completed_at - self.started_at).total_seconds() * 1000.0


class BaseVulnerabilityExtractor(ABC):
    """Template method: subclasses implement only `extract_candidates`.
    `__call__` is the one public entry point every caller uses — mirrors
    `core.threat_intel.base.BaseIOCExtractor` exactly."""

    name: ClassVar[str]
    description: ClassVar[str]
    version: ClassVar[str] = "1.0.0"

    def __init__(self, *, metrics: VulnerabilityMetricsCollector | None = None) -> None:
        self._metrics = metrics
        self.last_run: ExtractorRunResult | None = None

    @abstractmethod
    def extract_candidates(self, evidence: NormalizedEvidence) -> list[VulnerabilityRecord]:
        raise NotImplementedError

    def __call__(self, evidence: NormalizedEvidence) -> list[VulnerabilityRecord]:
        started_at = datetime.now(UTC)
        succeeded = True
        candidates: list[VulnerabilityRecord] = []
        try:
            candidates = self.extract_candidates(evidence)
        except VulnerabilityError as exc:
            succeeded = False
            _logger.warning(
                "vulnerability_extraction_degraded",
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
                "vulnerability_extraction_executed",
                extractor=self.name,
                evidence_id=str(evidence.evidence_id),
                succeeded=succeeded,
                candidate_count=len(candidates),
                duration_ms=self.last_run.duration_ms,
            )
        return candidates

    def raise_if_oversized(self, count: int, *, max_candidates: int) -> None:
        """Guard helper — the resource-exhaustion boundary (constitution
        §10). Takes a pre-computed count rather than the records
        themselves so callers never materialize anything just to check
        size."""
        if count > max_candidates:
            raise OversizedVulnerabilityDatasetError(
                f"Scan artifact contains {count} candidate vulnerabilities, exceeding the "
                f"{max_candidates}-record extraction limit.",
                details={"count": count, "max_candidates": max_candidates},
            )


def _parse_cvss(vector: object) -> CvssScore | None:
    """Returns a `core.knowledge.cvss_calculator.CvssScore` for a
    well-formed vector string, or `None` for a missing/malformed one — a
    malformed CVSS vector degrades that one score to absent rather than
    aborting extraction of the rest of the record (constitution §1.7)."""
    if not vector or not isinstance(vector, str):
        return None
    try:
        return _cvss_calculator.score(vector)
    except CVSSVectorParseError:
        return None


def _score_from_numeric(value: object, *, version: str) -> CvssScore | None:
    """Fallback for scan-report exports that give only a bare CVSS base
    score with no full vector string (common in Nessus/OpenVAS CSV exports
    — the vector is an optional column many templates omit). Constructs a
    `CvssScore` directly from the number, skipping vector parsing entirely;
    `vector` is left empty rather than fabricated. Returns `None` for a
    missing/non-numeric/out-of-range value — never raises."""
    if value in (None, ""):
        return None
    try:
        base_score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if not (0.0 <= base_score <= 10.0):
        return None
    return CvssScore(
        version=CvssVersion(version),
        vector="",
        base_score=base_score,
        severity=classify_cvss_severity(base_score),
    )


def _safe_int(value: object, *, default: int | None) -> int | None:
    """Parses `value` as an int, returning `default` for anything
    missing/non-numeric rather than raising — a malformed scanner field
    (e.g. a non-numeric port) degrades that one field, never the whole
    candidate (constitution §1.7)."""
    if value in (None, ""):
        return default
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def _resolve_cvss(
    fields: dict[str, object], *, vector_key: str, score_key: str, version: str
) -> CvssScore | None:
    """Prefers a well-formed vector string; falls back to a bare numeric
    score if no vector is present (see `_score_from_numeric`)."""
    from_vector = _parse_cvss(fields.get(vector_key))
    if from_vector is not None:
        return from_vector
    return _score_from_numeric(fields.get(score_key), version=version)


class VulnerabilityExtractionEngine(BaseVulnerabilityExtractor):
    """Reads structured per-finding fields from `EvidenceRecord.
    normalized_fields` (populated by the Nessus/OpenVAS parsers) and builds
    candidate `VulnerabilityRecord`s, supplementing CVE/CWE discovery with
    regex extraction over the free-text description."""

    name = "vulnerability_extraction_engine"
    description = "Structured-field- and description-regex-based vulnerability discovery."
    version = "1.0.0"

    _DETECTION_SOURCE_BY_EVIDENCE_TYPE: ClassVar[dict[str, DetectionSource]] = {
        "nessus_xml": DetectionSource.NESSUS,
        "nessus_csv": DetectionSource.NESSUS,
        "openvas_xml": DetectionSource.OPENVAS,
        "openvas_csv": DetectionSource.OPENVAS,
    }

    def __init__(
        self,
        *,
        metrics: VulnerabilityMetricsCollector | None = None,
        max_candidates: int = DEFAULT_MAX_CANDIDATES_PER_ARTIFACT,
    ) -> None:
        super().__init__(metrics=metrics)
        self._max_candidates = max_candidates

    def extract_candidates(self, evidence: NormalizedEvidence) -> list[VulnerabilityRecord]:
        self.raise_if_oversized(len(evidence.records), max_candidates=self._max_candidates)
        detection_source = self._DETECTION_SOURCE_BY_EVIDENCE_TYPE.get(
            evidence.evidence_type.value, DetectionSource.NESSUS
        )
        return [
            self._record_from_evidence_record(record, evidence, detection_source)
            for record in evidence.records
        ]

    def _record_from_evidence_record(
        self,
        record: EvidenceRecord,
        evidence: NormalizedEvidence,
        detection_source: DetectionSource,
    ) -> VulnerabilityRecord:
        fields = record.normalized_fields
        description = str(fields.get("description", ""))
        references = tuple(fields.get("references", ()))

        structured_cve = str(fields.get("cve_id", "")) or None
        discovered_cves = extract_cve_ids(f"{description} {' '.join(references)}")
        cve_id = structured_cve or (discovered_cves[0] if discovered_cves else None)

        structured_cwe_ids = tuple(fields.get("cwe_ids", ()))
        discovered_cwe_ids = extract_cwe_ids(description)
        cwe_ids = tuple(dict.fromkeys((*structured_cwe_ids, *discovered_cwe_ids)))

        cvss_v2 = _resolve_cvss(
            fields, vector_key="cvss_v2_vector", score_key="cvss_v2_score", version="2.0"
        )
        cvss_v3 = _resolve_cvss(
            fields, vector_key="cvss_v3_vector", score_key="cvss_v3_score", version="3.1"
        )
        cvss_v4 = _parse_cvss(fields.get("cvss_v4_vector"))

        best_cvss = cvss_v3 or cvss_v2 or cvss_v4
        severity = (
            severity_from_cvss(best_cvss)
            if best_cvss is not None
            else severity_from_scanner_code(_safe_int(fields.get("severity_code"), default=0) or 0)
        )

        port = _safe_int(fields.get("port"), default=None)

        return VulnerabilityRecord(
            cve_id=cve_id,
            cwe_ids=cwe_ids,
            plugin_id=str(fields.get("plugin_id", "")) or None,
            plugin_name=str(fields.get("plugin_name", "")),
            host=record.host,
            ip_address=record.ip_address,
            port=port,
            protocol=str(fields.get("protocol", "")) or None,
            service=str(fields.get("service", "")) or None,
            description=description,
            references=references,
            severity=severity,
            confidence=0.95,
            detection_source=detection_source,
            cvss_v2=cvss_v2,
            cvss_v3=cvss_v3,
            cvss_v4=cvss_v4,
            evidence_id=evidence.evidence_id,
            source=evidence.source,
            line_number=record.line_number,
        )
