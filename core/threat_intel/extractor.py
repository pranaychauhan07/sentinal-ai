"""`IOCExtractionEngine` — the one concrete, data-driven IOC extractor every
built-in registration in `core.threat_intel.registry` points to
(docs/adr/0012: "one data-driven engine, not twenty near-duplicate
extractors"). Dispatches every `IOCType` from `core.threat_intel.patterns.
IOC_PATTERNS`/`STRUCTURED_FIELD_SOURCES` rather than needing a bespoke class
per type. Discovery only — validation/normalization/dedup/scoring are later
pipeline stages (`core.services.threat_intel_service.IOCExtractionPipeline`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.parsers.models import EvidenceRecord, NormalizedEvidence
from core.threat_intel.base import BaseIOCExtractor
from core.threat_intel.models import IOCRecord, IOCType
from core.threat_intel.patterns import IOC_PATTERNS, STRUCTURED_FIELD_SOURCES, refang

if TYPE_CHECKING:
    from core.threat_intel.metrics import ThreatIntelMetricsCollector

#: Resource-exhaustion guard for the whole artifact (constitution §10);
#: overridable per-instance via the constructor, driven by
#: `Settings.threat_intel_max_regex_input_chars`.
DEFAULT_MAX_INPUT_CHARS = 1_000_000

#: Capture-group-bearing patterns whose "value" is `match.group(1)`, not the
#: full `match.group(0)` (e.g. `USERNAME`'s pattern also matches the
#: preceding "user=" keyword).
_GROUPED_TYPES = frozenset({IOCType.USERNAME, IOCType.PORT, IOCType.SERVICE})


class IOCExtractionEngine(BaseIOCExtractor):
    """Regex- and structured-field-driven discovery across every
    `IOCType` in `core.threat_intel.models.IOCType`."""

    name = "ioc_extraction_engine"
    description = "Data-driven, pattern- and structured-field-based IOC discovery."
    ioc_types = tuple(IOCType)
    version = "1.0.0"

    def __init__(
        self,
        *,
        metrics: ThreatIntelMetricsCollector | None = None,
        max_input_chars: int = DEFAULT_MAX_INPUT_CHARS,
    ) -> None:
        super().__init__(metrics=metrics)
        self._max_input_chars = max_input_chars

    def extract_candidates(self, evidence: NormalizedEvidence) -> list[IOCRecord]:
        total_chars = sum(len(record.raw_line) for record in evidence.records)
        self.raise_if_oversized(total_chars, max_chars=self._max_input_chars)

        candidates: list[IOCRecord] = []
        for record in evidence.records:
            candidates.extend(self._candidates_from_structured_fields(record, evidence))
            candidates.extend(self._candidates_from_pattern_scan(record, evidence))
        return candidates

    def _candidates_from_structured_fields(
        self, record: EvidenceRecord, evidence: NormalizedEvidence
    ) -> list[IOCRecord]:
        found: list[IOCRecord] = []
        for ioc_type, attribute_names in STRUCTURED_FIELD_SOURCES.items():
            for attribute_name in attribute_names:
                value = getattr(record, attribute_name, None)
                if not value:
                    continue
                found.append(
                    IOCRecord(
                        ioc_type=ioc_type,
                        value=value,
                        raw_value=value,
                        evidence_id=evidence.evidence_id,
                        source=f"structured_field:{attribute_name}",
                        line_number=record.line_number,
                        confidence=0.95,
                    )
                )
        return found

    def _candidates_from_pattern_scan(
        self, record: EvidenceRecord, evidence: NormalizedEvidence
    ) -> list[IOCRecord]:
        text = refang(record.raw_line)
        found: list[IOCRecord] = []
        for ioc_type, pattern in IOC_PATTERNS.items():
            for match in pattern.finditer(text):
                raw_value = match.group(1) if ioc_type in _GROUPED_TYPES else match.group(0)
                if not raw_value:
                    continue
                found.append(
                    IOCRecord(
                        ioc_type=ioc_type,
                        value=raw_value,
                        raw_value=raw_value,
                        evidence_id=evidence.evidence_id,
                        source="pattern_scan:raw_line",
                        line_number=record.line_number,
                        confidence=0.6,
                    )
                )
        return found
