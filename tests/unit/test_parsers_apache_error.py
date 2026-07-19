"""Unit tests for core/parsers/apache_error_parser.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.parsers.apache_error_parser import ApacheErrorParser
from core.parsers.base import RawEvidenceInput
from core.parsers.models import Severity

FIXTURE = Path("data/sample_evidence/apache_error.log")


@pytest.mark.unit
def test_parses_real_fixture_with_full_confidence() -> None:
    parser = ApacheErrorParser()
    raw = RawEvidenceInput(filename="apache_error.log", content=FIXTURE.read_bytes())
    result = parser(raw)
    assert result.confidence == 1.0
    assert result.unparsed_fragments == []
    assert result.record_count == 5


@pytest.mark.unit
def test_extracts_client_ip_and_level() -> None:
    parser = ApacheErrorParser()
    raw = RawEvidenceInput(filename="apache_error.log", content=FIXTURE.read_bytes())
    result = parser(raw)
    first = result.records[0]
    assert first.ip_address == "203.0.113.44"
    assert first.normalized_fields["level"] == "error"
    assert first.event_type == "apache_error"


@pytest.mark.unit
def test_crit_level_maps_to_critical_severity() -> None:
    parser = ApacheErrorParser()
    raw = RawEvidenceInput(filename="apache_error.log", content=FIXTURE.read_bytes())
    result = parser(raw)
    crit = next(r for r in result.records if r.normalized_fields["level"] == "crit")
    assert crit.severity == Severity.CRITICAL


@pytest.mark.unit
def test_malformed_line_is_unparsed() -> None:
    parser = ApacheErrorParser()
    content = b"not an apache error log line at all\n"
    raw = RawEvidenceInput(filename="error.log", content=content)
    result = parser(raw)
    assert result.confidence == 0.0
    assert result.unparsed_fragments
