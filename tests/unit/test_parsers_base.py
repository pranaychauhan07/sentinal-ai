"""Unit tests for core/parsers/base.py — the BaseParser template method."""

from __future__ import annotations

import pytest

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.exceptions import MalformedEvidenceError
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence


class _StrictParser(BaseParser):
    name = "strict"
    description = "Raises MalformedEvidenceError on any content containing 'bad'."
    evidence_type = EvidenceType.PLAIN_TEXT

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        self.raise_if_invalid("bad" not in decoded_text, "content contains 'bad'")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=1.0,
            records=[EvidenceRecord(raw_line=decoded_text)],
            chain_of_custody=self._chain_of_custody(raw),
        )


@pytest.mark.unit
def test_call_returns_parsed_result_on_success() -> None:
    parser = _StrictParser()
    raw = RawEvidenceInput(filename="good.txt", content=b"good content", ingested_by="tester")
    result = parser(raw)
    assert result.confidence == 1.0
    assert result.records[0].raw_line == "good content"
    assert parser.last_run is not None
    assert parser.last_run.succeeded is True


@pytest.mark.unit
def test_call_degrades_instead_of_raising_on_malformed_content() -> None:
    parser = _StrictParser()
    raw = RawEvidenceInput(filename="bad.txt", content=b"this is bad content", ingested_by="tester")
    result = parser(raw)
    assert result.confidence == 0.0
    assert result.unparsed_fragments == ["this is bad content"]
    assert "degraded_reason" in result.metadata


@pytest.mark.unit
def test_chain_of_custody_records_sha256_and_ingested_by() -> None:
    parser = _StrictParser()
    raw = RawEvidenceInput(filename="good.txt", content=b"good content", ingested_by="alice")
    result = parser(raw)
    assert result.chain_of_custody.ingested_by == "alice"
    assert result.chain_of_custody.original_filename == "good.txt"
    assert len(result.chain_of_custody.sha256) == 64


@pytest.mark.unit
def test_raise_if_invalid_raises_malformed_evidence_error_directly() -> None:
    parser = _StrictParser()
    with pytest.raises(MalformedEvidenceError):
        parser.validate_content(RawEvidenceInput(filename="x", content=b"bad"), "bad")


@pytest.mark.unit
def test_default_sniff_returns_zero_confidence() -> None:
    parser = _StrictParser()
    raw = RawEvidenceInput(filename="x.txt", content=b"anything")
    assert parser.sniff(raw, "anything") == 0.0
