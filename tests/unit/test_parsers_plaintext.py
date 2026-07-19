"""Unit tests for core/parsers/plaintext_parser.py — the deterministic,
last-resort fallback parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.plaintext_parser import PlainTextParser

FIXTURE = Path("data/sample_evidence/plaintext_note.txt")


@pytest.mark.unit
def test_parses_real_fixture_as_one_record() -> None:
    parser = PlainTextParser()
    raw = RawEvidenceInput(filename="plaintext_note.txt", content=FIXTURE.read_bytes())
    result = parser(raw)
    assert result.record_count == 1
    assert result.confidence == 0.3  # deliberately low — never a structured-parser substitute
    assert result.records[0].raw_line == FIXTURE.read_text(encoding="utf-8")


@pytest.mark.unit
def test_sniff_confidence_is_always_low_so_structured_parsers_win_ties() -> None:
    parser = PlainTextParser()
    raw = RawEvidenceInput(filename="note.txt", content=b"anything at all")
    assert 0.0 < parser.sniff(raw, "anything at all") < 0.5


@pytest.mark.unit
def test_empty_content_degrades() -> None:
    parser = PlainTextParser()
    raw = RawEvidenceInput(filename="empty.txt", content=b"")
    result = parser(raw)
    assert result.confidence == 0.0
