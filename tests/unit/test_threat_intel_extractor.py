"""Unit tests for core/threat_intel/extractor.py — IOCExtractionEngine."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.parsers.models import ChainOfCustody, EvidenceRecord, EvidenceType, NormalizedEvidence
from core.threat_intel.exceptions import OversizedEvidenceError
from core.threat_intel.extractor import IOCExtractionEngine
from core.threat_intel.models import IOCType


def _make_evidence(*records: EvidenceRecord, ip_address: str | None = None) -> NormalizedEvidence:
    if ip_address is not None:
        records = (*records, EvidenceRecord(raw_line="structured", ip_address=ip_address))
    return NormalizedEvidence(
        evidence_type=EvidenceType.PLAIN_TEXT,
        source="test.log",
        parser_name="plain_text",
        parser_version="1.0.0",
        confidence=1.0,
        records=list(records),
        chain_of_custody=ChainOfCustody(
            ingested_at=datetime.now(UTC),
            ingested_by="tester",
            original_filename="test.log",
            sha256="a" * 64,
            file_size_bytes=10,
        ),
    )


@pytest.mark.unit
def test_extract_candidates_finds_ipv4_in_raw_line() -> None:
    engine = IOCExtractionEngine()
    evidence = _make_evidence(EvidenceRecord(raw_line="failed login from 10.0.0.5", line_number=1))
    candidates = engine.extract_candidates(evidence)
    assert any(c.ioc_type == IOCType.IPV4 and c.value == "10.0.0.5" for c in candidates)


@pytest.mark.unit
def test_extract_candidates_finds_domain_and_sha256() -> None:
    engine = IOCExtractionEngine()
    sha = "b" * 64
    evidence = _make_evidence(
        EvidenceRecord(raw_line=f"downloaded from evil.example.com hash={sha}", line_number=2)
    )
    candidates = engine.extract_candidates(evidence)
    types_found = {c.ioc_type for c in candidates}
    assert IOCType.DOMAIN in types_found
    assert IOCType.SHA256 in types_found


@pytest.mark.unit
def test_extract_candidates_uses_structured_ip_field_with_higher_confidence() -> None:
    engine = IOCExtractionEngine()
    evidence = _make_evidence(ip_address="8.8.8.8")
    candidates = engine.extract_candidates(evidence)
    structured = [c for c in candidates if c.source.startswith("structured_field")]
    assert structured
    assert structured[0].confidence == 0.95


@pytest.mark.unit
def test_extract_candidates_raises_when_oversized() -> None:
    engine = IOCExtractionEngine(max_input_chars=10)
    evidence = _make_evidence(EvidenceRecord(raw_line="x" * 100, line_number=1))
    with pytest.raises(OversizedEvidenceError):
        engine.extract_candidates(evidence)


@pytest.mark.unit
def test_call_degrades_gracefully_when_oversized() -> None:
    engine = IOCExtractionEngine(max_input_chars=10)
    evidence = _make_evidence(EvidenceRecord(raw_line="x" * 100, line_number=1))
    result = engine(evidence)
    assert result == []
    assert engine.last_run is not None
    assert engine.last_run.succeeded is False


@pytest.mark.unit
def test_extract_candidates_finds_defanged_ip() -> None:
    engine = IOCExtractionEngine()
    evidence = _make_evidence(EvidenceRecord(raw_line="beacon to 192[.]168[.]1[.]1", line_number=1))
    candidates = engine.extract_candidates(evidence)
    assert any(c.ioc_type == IOCType.IPV4 and c.value == "192.168.1.1" for c in candidates)
