"""Unit tests for core/parsers/source_code_parser.py, including registry
priority/sniff behavior."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.models import EvidenceType
from core.parsers.registry import default_parser_registry
from core.parsers.source_code_parser import SourceCodeParser

pytestmark = pytest.mark.unit


def _raw(content: str, filename: str = "app.py") -> RawEvidenceInput:
    return RawEvidenceInput(filename=filename, content=content.encode())


def test_sniff_recognizes_python_content() -> None:
    parser = SourceCodeParser()
    confidence = parser.sniff(_raw("x"), "import os\ndef run():\n    pass\n")
    assert confidence > 0.1


def test_sniff_recognizes_java_content() -> None:
    parser = SourceCodeParser()
    confidence = parser.sniff(_raw("x"), "public class Main {}\n")
    assert confidence > 0.1


def test_sniff_gives_zero_for_unrelated_text() -> None:
    parser = SourceCodeParser()
    assert parser.sniff(_raw("x"), "Dear diary, today was a good day.") == 0.0


def test_parse_produces_one_record_for_the_whole_file() -> None:
    parser = SourceCodeParser()
    source = "import os\n\ndef run(cmd):\n    os.system(cmd)\n"
    result = parser(_raw(source))
    assert result.evidence_type == EvidenceType.SOURCE_CODE
    assert len(result.records) == 1
    assert result.records[0].raw_line == source
    assert result.records[0].event_type == "source_file"


def test_empty_input_degrades_not_crashes() -> None:
    parser = SourceCodeParser()
    result = parser(_raw(""))
    assert result.confidence == 0.0
    assert result.records == []


def test_registry_priority_above_plain_text() -> None:
    registry = default_parser_registry()
    source_registration = next(r for r in registry.list_registrations() if r.name == "source_code")
    plain_text_registration = next(
        r for r in registry.list_registrations() if r.name == "plain_text"
    )
    assert source_registration.priority > plain_text_registration.priority


def test_registry_has_alias() -> None:
    registry = default_parser_registry()
    assert registry.get("source") is registry.get("source_code")
