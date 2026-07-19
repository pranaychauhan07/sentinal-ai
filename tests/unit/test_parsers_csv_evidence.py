"""Unit tests for core/parsers/csv_evidence_parser.py."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.csv_evidence_parser import CsvEvidenceParser


@pytest.mark.unit
def test_parses_generic_csv_with_field_aliases() -> None:
    parser = CsvEvidenceParser()
    content = (
        b"hostname,username,src_ip,action,level\n"
        b"web01,alice,1.2.3.4,login,high\n"
        b"web02,bob,5.6.7.8,logout,info\n"
    )
    raw = RawEvidenceInput(filename="generic.csv", content=content)
    result = parser(raw)
    assert result.confidence == 1.0
    assert result.record_count == 2
    first = result.records[0]
    assert first.host == "web01"
    assert first.user == "alice"
    assert first.ip_address == "1.2.3.4"
    assert first.event_type == "login"


@pytest.mark.unit
def test_blank_rows_are_unparsed_fragments() -> None:
    parser = CsvEvidenceParser()
    content = b"a,b,c\n1,2,3\n,,\n"
    raw = RawEvidenceInput(filename="with_blank.csv", content=content)
    result = parser(raw)
    assert result.record_count == 1
    assert len(result.unparsed_fragments) == 1


@pytest.mark.unit
def test_missing_header_row_degrades() -> None:
    parser = CsvEvidenceParser()
    raw = RawEvidenceInput(filename="empty.csv", content=b"")
    result = parser(raw)
    assert result.confidence == 0.0


@pytest.mark.unit
def test_sniff_requires_a_comma() -> None:
    parser = CsvEvidenceParser()
    raw = RawEvidenceInput(filename="x.csv", content=b"just one column")
    assert parser.sniff(raw, "just one column") == 0.0
