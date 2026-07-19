"""Unit tests for core/threat_intel/attribution.py —
EvidenceAttributionTracker."""

from __future__ import annotations

import uuid

import pytest

from core.threat_intel.attribution import EvidenceAttributionTracker
from core.threat_intel.models import IOCRecord, IOCType


@pytest.mark.unit
def test_attribute_uses_line_number_when_no_dedup_context() -> None:
    tracker = EvidenceAttributionTracker()
    evidence_id = uuid.uuid4()
    ioc = IOCRecord(
        ioc_type=IOCType.IPV4,
        value="1.2.3.4",
        raw_value="1.2.3.4",
        source="test",
        evidence_id=evidence_id,
        line_number=42,
    )
    [record] = tracker.attribute([ioc])
    assert record.ioc_id == ioc.ioc_id
    assert record.evidence_id == evidence_id
    assert record.line_numbers == (42,)
    assert record.occurrence_count == 1


@pytest.mark.unit
def test_attribute_uses_deduplicated_line_numbers_context() -> None:
    tracker = EvidenceAttributionTracker()
    ioc = IOCRecord(
        ioc_type=IOCType.IPV4,
        value="1.2.3.4",
        raw_value="1.2.3.4",
        source="test",
        context={"line_numbers": [3, 7, 9]},
    )
    [record] = tracker.attribute([ioc])
    assert record.line_numbers == (3, 7, 9)
    assert record.occurrence_count == 3


@pytest.mark.unit
def test_attribute_handles_no_line_information() -> None:
    tracker = EvidenceAttributionTracker()
    ioc = IOCRecord(ioc_type=IOCType.IPV4, value="1.2.3.4", raw_value="1.2.3.4", source="test")
    [record] = tracker.attribute([ioc])
    assert record.line_numbers == ()
    assert record.occurrence_count == 1
