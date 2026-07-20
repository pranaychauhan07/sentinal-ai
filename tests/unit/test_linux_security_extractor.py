"""Unit tests for core/linux_security/extractor.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.linux_security.exceptions import OversizedLinuxSecurityDatasetError
from core.linux_security.extractor import LinuxSecurityAnalysisEngine
from core.parsers.models import ChainOfCustody, EvidenceRecord, EvidenceType, NormalizedEvidence

pytestmark = pytest.mark.unit


def _custody() -> ChainOfCustody:
    return ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="auth.log",
        sha256="a" * 64,
        file_size_bytes=10,
    )


def _evidence(records: list[EvidenceRecord], *, confidence: float = 1.0) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=EvidenceType.SSH_AUTH,
        source="auth.log",
        parser_name="ssh_auth",
        parser_version="1.0.0",
        confidence=confidence,
        records=records,
        chain_of_custody=_custody(),
    )


def test_brute_force_and_compromise_detected_end_to_end() -> None:
    base = datetime(2026, 7, 18, 2, 14, 0, tzinfo=UTC)
    records = [
        EvidenceRecord(
            line_number=i + 1,
            timestamp=base,
            event_type="auth_failure",
            ip_address="203.0.113.44",
        )
        for i in range(6)
    ]
    records.append(
        EvidenceRecord(
            line_number=7,
            timestamp=base,
            event_type="auth_success",
            user="root",
            ip_address="203.0.113.44",
        )
    )
    engine = LinuxSecurityAnalysisEngine()
    result = engine.analyze(_evidence(records))
    categories = {c.candidate.category.value for c in result.candidates}
    assert "brute_force" in categories
    assert "compromise_after_brute_force" in categories
    assert result.finding_count > 0


def test_oversized_artifact_raises() -> None:
    records = [EvidenceRecord(line_number=i, event_type="auth_failure") for i in range(10)]
    engine = LinuxSecurityAnalysisEngine(max_records=5)
    with pytest.raises(OversizedLinuxSecurityDatasetError):
        engine.analyze(_evidence(records))


def test_malformed_record_does_not_abort_whole_artifact() -> None:
    """A record with no usable signal at all (no timestamp, no event_type,
    no raw content) is skipped; a well-formed record in the same artifact
    is still fully analyzed (constitution §1.7)."""
    records = [
        EvidenceRecord(line_number=1),  # nothing usable at all
        EvidenceRecord(
            line_number=2,
            event_type="auth_success",
            user="root",
            timestamp=datetime.now(UTC),
        ),
    ]
    engine = LinuxSecurityAnalysisEngine()
    result = engine.analyze(_evidence(records))
    assert result.skipped_record_count == 1
    assert result.finding_count >= 1


def test_empty_evidence_returns_empty_intel() -> None:
    engine = LinuxSecurityAnalysisEngine()
    result = engine.analyze(_evidence([]))
    assert result.candidates == ()
    assert result.findings == ()
