"""Unit tests for core/parsers/models.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from core.parsers.models import (
    ChainOfCustody,
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
    Severity,
)


@pytest.mark.unit
def test_evidence_record_defaults_to_info_severity() -> None:
    record = EvidenceRecord(raw_line="hello")
    assert record.severity == Severity.INFO
    assert record.normalized_fields == {}


@pytest.mark.unit
def test_normalized_evidence_confidence_must_be_within_bounds() -> None:
    custody = ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="a.log",
        sha256="0" * 64,
        file_size_bytes=10,
    )
    with pytest.raises(ValidationError):
        NormalizedEvidence(
            evidence_type=EvidenceType.PLAIN_TEXT,
            source="a.log",
            parser_name="plain_text",
            parser_version="1.0.0",
            confidence=1.5,
            chain_of_custody=custody,
        )


@pytest.mark.unit
def test_normalized_evidence_record_count() -> None:
    custody = ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="a.log",
        sha256="0" * 64,
        file_size_bytes=10,
    )
    evidence = NormalizedEvidence(
        evidence_type=EvidenceType.PLAIN_TEXT,
        source="a.log",
        parser_name="plain_text",
        parser_version="1.0.0",
        confidence=1.0,
        records=[EvidenceRecord(raw_line="x"), EvidenceRecord(raw_line="y")],
        chain_of_custody=custody,
    )
    assert evidence.record_count == 2


@pytest.mark.unit
def test_normalized_evidence_is_frozen() -> None:
    custody = ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="a.log",
        sha256="0" * 64,
        file_size_bytes=10,
    )
    evidence = NormalizedEvidence(
        evidence_type=EvidenceType.PLAIN_TEXT,
        source="a.log",
        parser_name="plain_text",
        parser_version="1.0.0",
        confidence=1.0,
        chain_of_custody=custody,
    )
    with pytest.raises(ValidationError):
        evidence.confidence = 0.0  # type: ignore[misc]
