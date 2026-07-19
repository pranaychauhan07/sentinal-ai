"""Unit tests for core/threat_intel/base.py — the BaseIOCExtractor template
method, mirroring tests/unit/test_parsers_base.py's shape."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.parsers.models import ChainOfCustody, EvidenceRecord, EvidenceType, NormalizedEvidence
from core.threat_intel.base import BaseIOCExtractor
from core.threat_intel.exceptions import OversizedEvidenceError
from core.threat_intel.models import IOCRecord, IOCType


def _make_evidence(raw_line: str = "1.2.3.4 requested /") -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=EvidenceType.PLAIN_TEXT,
        source="test.log",
        parser_name="plain_text",
        parser_version="1.0.0",
        confidence=1.0,
        records=[EvidenceRecord(raw_line=raw_line, line_number=1)],
        chain_of_custody=ChainOfCustody(
            ingested_at=datetime.now(UTC),
            ingested_by="tester",
            original_filename="test.log",
            sha256="a" * 64,
            file_size_bytes=10,
        ),
    )


class _StubExtractor(BaseIOCExtractor):
    name = "stub"
    description = "test double"
    ioc_types = (IOCType.IPV4,)

    def extract_candidates(self, evidence: NormalizedEvidence) -> list[IOCRecord]:
        return [
            IOCRecord(
                ioc_type=IOCType.IPV4,
                value="1.2.3.4",
                raw_value="1.2.3.4",
                evidence_id=evidence.evidence_id,
                source="stub",
            )
        ]


class _FailingExtractor(BaseIOCExtractor):
    name = "failing"
    description = "test double"
    ioc_types = (IOCType.IPV4,)

    def extract_candidates(self, evidence: NormalizedEvidence) -> list[IOCRecord]:
        self.raise_if_oversized(1_000_000, max_chars=10)
        return []


@pytest.mark.unit
def test_call_returns_candidates_on_success() -> None:
    extractor = _StubExtractor()
    result = extractor(_make_evidence())
    assert len(result) == 1
    assert extractor.last_run is not None
    assert extractor.last_run.succeeded is True
    assert extractor.last_run.candidate_count == 1


@pytest.mark.unit
def test_call_degrades_instead_of_raising_on_oversized_evidence() -> None:
    extractor = _FailingExtractor()
    result = extractor(_make_evidence())
    assert result == []
    assert extractor.last_run is not None
    assert extractor.last_run.succeeded is False


@pytest.mark.unit
def test_raise_if_oversized_raises_when_over_limit() -> None:
    extractor = _StubExtractor()
    with pytest.raises(OversizedEvidenceError):
        extractor.raise_if_oversized(100, max_chars=10)


@pytest.mark.unit
def test_raise_if_oversized_passes_when_under_limit() -> None:
    extractor = _StubExtractor()
    extractor.raise_if_oversized(5, max_chars=10)  # must not raise


@pytest.mark.unit
def test_metrics_collector_records_run_when_provided() -> None:
    from core.threat_intel.metrics import ThreatIntelMetricsCollector

    metrics = ThreatIntelMetricsCollector()
    extractor = _StubExtractor(metrics=metrics)
    extractor(_make_evidence())

    stats = metrics.stats_for("stub")
    assert stats.attempts == 1
    assert stats.successes == 1
