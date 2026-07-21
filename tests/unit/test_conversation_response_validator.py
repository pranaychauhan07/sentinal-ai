"""Unit tests for core/conversation/response_validator.py."""

from __future__ import annotations

import pytest

from core.conversation.models import (
    ChatCompletion,
    EvidenceCategory,
    RetrievedItem,
    SourceReference,
)
from core.conversation.response_validator import ResponseValidator


def _item(source_id: str) -> RetrievedItem:
    return RetrievedItem(
        category=EvidenceCategory.FINDING,
        source_id=source_id,
        text="t",
        relevance_score=0.5,
        reference=SourceReference(
            category=EvidenceCategory.FINDING, source_id=source_id, summary="s"
        ),
    )


@pytest.mark.unit
def test_valid_when_no_evidence_and_no_citations() -> None:
    validator = ResponseValidator()
    result = validator.validate(
        ChatCompletion(answer_text="no evidence"), available_items=[], citation_count=0
    )
    assert result.valid is True
    assert result.grounded is True
    assert result.has_citations is False


@pytest.mark.unit
def test_valid_when_grounded_and_cited() -> None:
    validator = ResponseValidator()
    result = validator.validate(
        ChatCompletion(answer_text="answer", used_source_ids=("f1",)),
        available_items=[_item("f1")],
        citation_count=1,
    )
    assert result.valid is True
    assert result.grounded is True
    assert result.hallucinated_source_ids == ()


@pytest.mark.unit
def test_invalid_when_completion_claims_unretrieved_source_id() -> None:
    validator = ResponseValidator()
    result = validator.validate(
        ChatCompletion(answer_text="answer", used_source_ids=("f1", "ghost")),
        available_items=[_item("f1")],
        citation_count=1,
    )
    assert result.valid is False
    assert result.grounded is False
    assert result.hallucinated_source_ids == ("ghost",)
    assert any("ghost" in issue for issue in result.issues)


@pytest.mark.unit
def test_invalid_when_evidence_available_but_no_citations() -> None:
    validator = ResponseValidator()
    result = validator.validate(
        ChatCompletion(answer_text="answer", used_source_ids=()),
        available_items=[_item("f1")],
        citation_count=0,
    )
    assert result.valid is False
    assert result.has_citations is False


@pytest.mark.unit
def test_duplicate_used_source_ids_do_not_duplicate_hallucination_report() -> None:
    validator = ResponseValidator()
    result = validator.validate(
        ChatCompletion(answer_text="answer", used_source_ids=("ghost", "ghost")),
        available_items=[],
        citation_count=0,
    )
    assert result.hallucinated_source_ids == ("ghost",)
