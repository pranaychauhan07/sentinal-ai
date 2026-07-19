"""Unit tests for core/parsers/windows_event_parser.py (EVTX abstraction)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.exceptions import MalformedEvidenceError
from core.parsers.models import Severity
from core.parsers.windows_event_parser import WindowsEventParser

FIXTURE = Path("data/sample_evidence/windows_security_events.csv")
MALFORMED_FIXTURE = Path("data/sample_evidence/malformed/truncated_windows_events.csv")


@pytest.mark.unit
def test_parses_real_fixture_with_full_confidence() -> None:
    parser = WindowsEventParser()
    raw = RawEvidenceInput(filename="windows_security_events.csv", content=FIXTURE.read_bytes())
    result = parser(raw)
    assert result.confidence == 1.0
    assert result.record_count == 12


@pytest.mark.unit
def test_known_event_id_maps_to_logon_failure() -> None:
    parser = WindowsEventParser()
    raw = RawEvidenceInput(filename="windows_security_events.csv", content=FIXTURE.read_bytes())
    result = parser(raw)
    failure = next(r for r in result.records if r.normalized_fields["event_id"] == "4625")
    assert failure.event_type == "logon_failure"
    assert failure.severity == Severity.MEDIUM
    assert failure.user == "Administrator"
    assert failure.ip_address == "203.0.113.44"


@pytest.mark.unit
def test_unknown_event_id_falls_back_to_generic_classification() -> None:
    parser = WindowsEventParser()
    content = (
        b"EventID,TimeCreated,Computer,Account,SourceIP,LogonType,Message\n"
        b"9999,2026-07-18T00:00:00Z,DC01,someone,1.2.3.4,3,Unknown event\n"
    )
    raw = RawEvidenceInput(filename="events.csv", content=content)
    result = parser(raw)
    assert result.records[0].event_type == "windows_event_9999"
    assert result.records[0].severity == Severity.INFO


@pytest.mark.unit
def test_rows_with_missing_event_id_are_unparsed() -> None:
    parser = WindowsEventParser()
    raw = RawEvidenceInput(
        filename="truncated_windows_events.csv", content=MALFORMED_FIXTURE.read_bytes()
    )
    result = parser(raw)
    assert result.record_count == 2
    assert len(result.unparsed_fragments) == 1


@pytest.mark.unit
def test_missing_required_columns_raises_malformed_evidence_error() -> None:
    parser = WindowsEventParser()
    raw = RawEvidenceInput(filename="bad.csv", content=b"Foo,Bar\n1,2\n")
    with pytest.raises(MalformedEvidenceError):
        parser.validate_content(raw, "Foo,Bar\n1,2\n")


@pytest.mark.unit
def test_sniff_recognizes_the_evtx_export_header() -> None:
    parser = WindowsEventParser()
    header = "EventID,TimeCreated,Computer,Account,SourceIP,LogonType,Message"
    raw = RawEvidenceInput(filename="x.csv", content=header.encode())
    assert parser.sniff(raw, header) > 0.5
