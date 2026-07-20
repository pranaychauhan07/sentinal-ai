"""Unit tests for core/parsers/nessus_csv_parser.py."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.models import EvidenceType
from core.parsers.nessus_csv_parser import NessusCsvParser

pytestmark = pytest.mark.unit

_VALID_CSV = (
    "Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also\n"
    "156327,CVE-2021-44228,10.0,Critical,10.0.0.5,tcp,443,Apache Log4Shell RCE,"
    '"RCE possible","Apache Log4j is vulnerable to remote code execution.",'
    '"Upgrade Log4j","https://nvd.nist.gov/vuln/detail/CVE-2021-44228"\n'
    "10267,,,None,10.0.0.5,tcp,22,SSH Server Type and Version Information,"
    '"Info","It is possible to obtain information about the remote SSH server.",,\n'
)

_NUMERIC_ONLY_CSV = (
    "Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,"
    "Description,Solution,See Also\n"
    "999,,9.8,Critical,10.0.0.6,tcp,443,Generic Critical Finding,,A finding.,,\n"
)


def test_parses_valid_export_with_full_confidence() -> None:
    parser = NessusCsvParser()
    raw = RawEvidenceInput(filename="scan.csv", content=_VALID_CSV.encode())
    result = parser(raw)

    assert result.evidence_type == EvidenceType.NESSUS_CSV
    assert result.confidence == 1.0
    assert result.record_count == 2

    log4shell = next(r for r in result.records if r.normalized_fields["plugin_id"] == "156327")
    assert log4shell.normalized_fields["cve_id"] == "CVE-2021-44228"
    assert log4shell.normalized_fields["cvss_v2_score"] == "10.0"
    assert log4shell.ip_address == "10.0.0.5"
    assert log4shell.normalized_fields["port"] == "443"


def test_numeric_only_cvss_column_is_captured() -> None:
    parser = NessusCsvParser()
    raw = RawEvidenceInput(filename="scan.csv", content=_NUMERIC_ONLY_CSV.encode())
    result = parser(raw)
    assert result.records[0].normalized_fields["cvss_v3_score"] == "9.8"


def test_sniff_prefers_nessus_csv_over_generic_csv() -> None:
    parser = NessusCsvParser()
    assert parser.sniff(RawEvidenceInput(filename="scan.csv", content=b""), _VALID_CSV) > 0.5


def test_missing_required_columns_degrades_gracefully() -> None:
    parser = NessusCsvParser()
    raw = RawEvidenceInput(filename="not_nessus.csv", content=b"a,b,c\n1,2,3\n")
    result = parser(raw)
    assert result.confidence == 0.0


def test_empty_content_degrades_gracefully() -> None:
    parser = NessusCsvParser()
    raw = RawEvidenceInput(filename="empty.csv", content=b"   ")
    result = parser(raw)
    assert result.confidence == 0.0
