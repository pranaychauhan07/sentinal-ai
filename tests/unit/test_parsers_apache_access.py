"""Unit tests for core/parsers/apache_access_parser.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.parsers.apache_access_parser import ApacheAccessParser
from core.parsers.base import RawEvidenceInput
from core.parsers.models import Severity

FIXTURE = Path("data/sample_evidence/apache_access.log")


@pytest.mark.unit
def test_parses_real_fixture_with_full_confidence() -> None:
    parser = ApacheAccessParser()
    raw = RawEvidenceInput(filename="apache_access.log", content=FIXTURE.read_bytes())
    result = parser(raw)
    assert result.confidence == 1.0
    assert result.unparsed_fragments == []
    assert result.record_count == 12


@pytest.mark.unit
def test_extracts_ip_method_path_and_status() -> None:
    parser = ApacheAccessParser()
    raw = RawEvidenceInput(filename="apache_access.log", content=FIXTURE.read_bytes())
    result = parser(raw)
    first = result.records[0]
    assert first.ip_address == "203.0.113.44"
    assert first.normalized_fields["method"] == "GET"
    assert first.normalized_fields["path"] == "/wp-login.php"
    assert first.normalized_fields["status"] == 200


@pytest.mark.unit
def test_5xx_status_is_high_severity() -> None:
    parser = ApacheAccessParser()
    raw = RawEvidenceInput(filename="apache_access.log", content=FIXTURE.read_bytes())
    result = parser(raw)
    sqli_probe = next(r for r in result.records if "UNION" in r.normalized_fields["path"])
    assert sqli_probe.severity == Severity.HIGH


@pytest.mark.unit
def test_malformed_line_is_an_unparsed_fragment() -> None:
    parser = ApacheAccessParser()
    content = b"this is not a combined log format line\n"
    raw = RawEvidenceInput(filename="access.log", content=content)
    result = parser(raw)
    assert result.confidence == 0.0
    assert result.unparsed_fragments
