"""Unit tests for core/threat_intel/models.py."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from core.threat_intel.models import (
    IOCRecord,
    IOCType,
    NormalizedThreatIntel,
    ThreatScore,
    ThreatSeverity,
)


@pytest.mark.unit
def test_ioc_record_defaults() -> None:
    record = IOCRecord(ioc_type=IOCType.IPV4, value="1.2.3.4", raw_value="1.2.3.4", source="test")
    assert record.confidence == 1.0
    assert record.severity == ThreatSeverity.INFO
    assert isinstance(record.ioc_id, uuid.UUID)
    assert record.tags == ()


@pytest.mark.unit
def test_ioc_record_confidence_bounds_enforced() -> None:
    with pytest.raises(ValidationError):
        IOCRecord(
            ioc_type=IOCType.IPV4, value="1.2.3.4", raw_value="1.2.3.4", source="t", confidence=1.5
        )


@pytest.mark.unit
def test_ioc_record_is_frozen() -> None:
    record = IOCRecord(
        ioc_type=IOCType.DOMAIN, value="example.com", raw_value="example.com", source="t"
    )
    with pytest.raises(ValidationError):
        record.value = "other.com"  # type: ignore[misc]


@pytest.mark.unit
def test_threat_score_composite_bounds() -> None:
    with pytest.raises(ValidationError):
        ThreatScore(
            confidence=0.5,
            severity_weight=0.5,
            impact=0.5,
            likelihood=0.5,
            evidence_quality=0.5,
            source_reliability=0.5,
            rule_match_score=0.5,
            composite_score=150.0,
        )


@pytest.mark.unit
def test_normalized_threat_intel_ioc_count() -> None:
    result = NormalizedThreatIntel(
        evidence_id=uuid.uuid4(),
        source="test.log",
        extractor_name="ioc_extraction_engine",
        extractor_version="1.0.0",
    )
    assert result.ioc_count == 0
