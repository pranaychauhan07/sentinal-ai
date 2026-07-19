"""Unit tests for core/parsers/json_evidence_parser.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.json_evidence_parser import JsonEvidenceParser
from core.parsers.models import Severity

FIXTURE = Path("data/sample_evidence/sample_evidence.json")
MALFORMED_FIXTURE = Path("data/sample_evidence/malformed/not_json.json")


@pytest.mark.unit
def test_parses_real_fixture_list_of_objects() -> None:
    parser = JsonEvidenceParser()
    raw = RawEvidenceInput(filename="sample_evidence.json", content=FIXTURE.read_bytes())
    result = parser(raw)
    assert result.confidence == 1.0
    assert result.record_count == 2


@pytest.mark.unit
def test_field_alias_heuristics_extract_common_fields() -> None:
    parser = JsonEvidenceParser()
    raw = RawEvidenceInput(filename="sample_evidence.json", content=FIXTURE.read_bytes())
    result = parser(raw)
    first = result.records[0]
    assert first.host == "edr-agent-01"
    assert first.user == "svc_backup"
    assert first.ip_address == "198.51.100.9"
    assert first.event_type == "process_creation"
    assert first.severity == Severity.MEDIUM
    assert first.timestamp is not None


@pytest.mark.unit
def test_single_object_is_wrapped_as_one_record() -> None:
    parser = JsonEvidenceParser()
    raw = RawEvidenceInput(filename="one.json", content=b'{"host": "x", "type": "alert"}')
    result = parser(raw)
    assert result.record_count == 1
    assert result.records[0].host == "x"


@pytest.mark.unit
def test_non_dict_list_items_are_unparsed_fragments() -> None:
    parser = JsonEvidenceParser()
    raw = RawEvidenceInput(filename="mixed.json", content=b'[{"host": "x"}, "not a dict", 42]')
    result = parser(raw)
    assert result.record_count == 1
    assert len(result.unparsed_fragments) == 2


@pytest.mark.unit
def test_malformed_json_degrades_gracefully() -> None:
    parser = JsonEvidenceParser()
    raw = RawEvidenceInput(filename="not_json.json", content=MALFORMED_FIXTURE.read_bytes())
    result = parser(raw)
    assert result.confidence == 0.0


@pytest.mark.unit
def test_top_level_scalar_is_rejected_as_malformed() -> None:
    parser = JsonEvidenceParser()
    raw = RawEvidenceInput(filename="scalar.json", content=b"42")
    result = parser(raw)
    assert result.confidence == 0.0
