"""Unit tests for core/vulnerabilities/extractor.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.parsers.models import (
    ChainOfCustody,
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
)
from core.vulnerabilities.exceptions import OversizedVulnerabilityDatasetError
from core.vulnerabilities.extractor import VulnerabilityExtractionEngine
from core.vulnerabilities.models import DetectionSource, VulnerabilitySeverity

pytestmark = pytest.mark.unit


def _custody() -> ChainOfCustody:
    return ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="scan.nessus",
        sha256="a" * 64,
        file_size_bytes=100,
    )


def _evidence(records: list[EvidenceRecord], *, evidence_type: EvidenceType) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=evidence_type,
        source="scan.nessus",
        parser_name="nessus",
        parser_version="1.0.0",
        confidence=1.0,
        records=records,
        chain_of_custody=_custody(),
    )


def test_extracts_full_record_from_structured_fields() -> None:
    record = EvidenceRecord(
        host="web01",
        ip_address="10.0.0.5",
        event_type="vulnerability_finding",
        normalized_fields={
            "plugin_id": "156327",
            "plugin_name": "Apache Log4Shell RCE",
            "cve_id": "CVE-2021-44228",
            "cwe_ids": ("CWE-502",),
            "port": "443",
            "protocol": "tcp",
            "service": "https",
            "description": "Apache Log4j RCE.",
            "references": ("https://nvd.nist.gov/vuln/detail/CVE-2021-44228",),
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
    )
    evidence = _evidence([record], evidence_type=EvidenceType.NESSUS_XML)
    candidates = VulnerabilityExtractionEngine().extract_candidates(evidence)

    assert len(candidates) == 1
    vuln = candidates[0]
    assert vuln.cve_id == "CVE-2021-44228"
    assert vuln.plugin_id == "156327"
    assert vuln.port == 443
    assert vuln.severity == VulnerabilitySeverity.CRITICAL
    assert vuln.detection_source == DetectionSource.NESSUS
    assert vuln.cvss_v3 is not None
    assert vuln.evidence_id == evidence.evidence_id


def test_detection_source_dispatches_by_evidence_type() -> None:
    record = EvidenceRecord(
        normalized_fields={"plugin_id": "1", "plugin_name": "x", "description": "x"}
    )
    evidence = _evidence([record], evidence_type=EvidenceType.OPENVAS_CSV)
    candidates = VulnerabilityExtractionEngine().extract_candidates(evidence)
    assert candidates[0].detection_source == DetectionSource.OPENVAS


def test_falls_back_to_regex_cve_discovery_in_description() -> None:
    record = EvidenceRecord(
        normalized_fields={
            "plugin_id": "999",
            "plugin_name": "Generic finding",
            "description": "This host is vulnerable to CVE-2021-44228.",
        }
    )
    evidence = _evidence([record], evidence_type=EvidenceType.NESSUS_XML)
    candidates = VulnerabilityExtractionEngine().extract_candidates(evidence)
    assert candidates[0].cve_id == "CVE-2021-44228"


def test_malformed_cvss_vector_degrades_to_no_score_not_a_crash() -> None:
    record = EvidenceRecord(
        normalized_fields={
            "plugin_id": "1",
            "plugin_name": "x",
            "cvss_v3_vector": "not a real vector",
        }
    )
    evidence = _evidence([record], evidence_type=EvidenceType.NESSUS_XML)
    candidates = VulnerabilityExtractionEngine().extract_candidates(evidence)
    assert candidates[0].cvss_v3 is None


def test_severity_falls_back_to_scanner_code_without_cvss() -> None:
    record = EvidenceRecord(
        normalized_fields={"plugin_id": "1", "plugin_name": "x", "severity_code": 4}
    )
    evidence = _evidence([record], evidence_type=EvidenceType.NESSUS_XML)
    candidates = VulnerabilityExtractionEngine().extract_candidates(evidence)
    assert candidates[0].severity == VulnerabilitySeverity.CRITICAL


def test_numeric_cvss_fallback_used_when_no_vector_present() -> None:
    """Some Nessus/OpenVAS CSV exports omit the full vector string and give
    only a bare numeric base score — extraction must still succeed."""
    record = EvidenceRecord(
        normalized_fields={"plugin_id": "1", "plugin_name": "x", "cvss_v3_score": "9.8"}
    )
    evidence = _evidence([record], evidence_type=EvidenceType.NESSUS_CSV)
    candidates = VulnerabilityExtractionEngine().extract_candidates(evidence)
    assert candidates[0].cvss_v3 is not None
    assert candidates[0].cvss_v3.base_score == 9.8
    assert candidates[0].severity == VulnerabilitySeverity.CRITICAL


def test_out_of_range_numeric_score_is_ignored() -> None:
    record = EvidenceRecord(
        normalized_fields={"plugin_id": "1", "plugin_name": "x", "cvss_v3_score": "999"}
    )
    evidence = _evidence([record], evidence_type=EvidenceType.NESSUS_CSV)
    candidates = VulnerabilityExtractionEngine().extract_candidates(evidence)
    assert candidates[0].cvss_v3 is None


def test_oversized_dataset_raises() -> None:
    records = [
        EvidenceRecord(normalized_fields={"plugin_id": str(i), "plugin_name": "x"})
        for i in range(5)
    ]
    evidence = _evidence(records, evidence_type=EvidenceType.NESSUS_XML)
    engine = VulnerabilityExtractionEngine(max_candidates=3)
    with pytest.raises(OversizedVulnerabilityDatasetError):
        engine.extract_candidates(evidence)


def test_call_degrades_gracefully_on_oversized_input() -> None:
    """`__call__` (not `extract_candidates` directly) never raises —
    constitution §1.7."""
    records = [
        EvidenceRecord(normalized_fields={"plugin_id": str(i), "plugin_name": "x"})
        for i in range(5)
    ]
    evidence = _evidence(records, evidence_type=EvidenceType.NESSUS_XML)
    engine = VulnerabilityExtractionEngine(max_candidates=3)
    result = engine(evidence)
    assert result == []
    assert engine.last_run is not None
    assert engine.last_run.succeeded is False


def test_empty_evidence_returns_empty() -> None:
    evidence = _evidence([], evidence_type=EvidenceType.NESSUS_XML)
    assert VulnerabilityExtractionEngine().extract_candidates(evidence) == []
