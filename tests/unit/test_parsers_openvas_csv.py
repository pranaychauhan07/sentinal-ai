"""Unit tests for core/parsers/openvas_csv_parser.py."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.models import EvidenceType
from core.parsers.openvas_csv_parser import OpenVasCsvParser

pytestmark = pytest.mark.unit

_VALID_CSV = (
    "IP,Hostname,Port,Port Protocol,CVSS,Severity,NVT Name,Summary,Specific Result,NVT OID,CVEs\n"
    '10.0.0.5,web01,443,tcp,10.0,Critical,Apache Log4Shell RCE,"RCE possible",'
    '"details",1.3.6.1.4.1.25623.1.0.156327,CVE-2021-44228\n'
    '10.0.0.5,web01,,,0.0,Log,SSH Server banner,"info",,'
    "1.3.6.1.4.1.25623.1.0.10267,NOCVE\n"
)


def test_parses_valid_export_with_full_confidence() -> None:
    parser = OpenVasCsvParser()
    raw = RawEvidenceInput(filename="scan.csv", content=_VALID_CSV.encode())
    result = parser(raw)

    assert result.evidence_type == EvidenceType.OPENVAS_CSV
    assert result.confidence == 1.0
    assert result.record_count == 2

    log4shell = next(r for r in result.records if "156327" in r.normalized_fields["plugin_id"])
    assert log4shell.ip_address == "10.0.0.5"
    assert log4shell.host == "web01"
    assert log4shell.normalized_fields["cve_id"] == "CVE-2021-44228"
    assert log4shell.normalized_fields["cvss_v3_score"] == "10.0"


def test_nocve_placeholder_is_excluded() -> None:
    parser = OpenVasCsvParser()
    raw = RawEvidenceInput(filename="scan.csv", content=_VALID_CSV.encode())
    result = parser(raw)
    ssh_finding = next(r for r in result.records if "10267" in r.normalized_fields["plugin_id"])
    assert ssh_finding.normalized_fields["cve_id"] == ""


def test_sniff_prefers_openvas_csv_over_generic_csv() -> None:
    parser = OpenVasCsvParser()
    assert parser.sniff(RawEvidenceInput(filename="scan.csv", content=b""), _VALID_CSV) > 0.5


def test_missing_required_columns_degrades_gracefully() -> None:
    parser = OpenVasCsvParser()
    raw = RawEvidenceInput(filename="not_openvas.csv", content=b"a,b,c\n1,2,3\n")
    result = parser(raw)
    assert result.confidence == 0.0


def test_empty_content_degrades_gracefully() -> None:
    parser = OpenVasCsvParser()
    raw = RawEvidenceInput(filename="empty.csv", content=b"   ")
    result = parser(raw)
    assert result.confidence == 0.0
