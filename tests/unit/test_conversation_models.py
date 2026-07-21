"""Unit tests for core/conversation/models.py."""

from __future__ import annotations

import pytest

from core.conversation.models import (
    ConversationSession,
    EvidenceCategory,
    ResponseValidationResult,
    RetrievedItem,
    SourceReference,
)


@pytest.mark.unit
def test_conversation_session_touched_increments_turn_count_and_refreshes_timestamp() -> None:
    session = ConversationSession(case_id="c1")
    touched = session.touched()

    assert touched.turn_count == 1
    assert touched.session_id == session.session_id
    assert touched.last_active_at >= session.last_active_at
    # Original is untouched (frozen model).
    assert session.turn_count == 0


@pytest.mark.unit
def test_response_validation_result_valid_is_derived_from_issues() -> None:
    valid = ResponseValidationResult(grounded=True, has_citations=True)
    invalid = ResponseValidationResult(
        grounded=False, hallucinated_source_ids=("ghost",), has_citations=False, issues=("bad",)
    )
    assert valid.valid is True
    assert invalid.valid is False


@pytest.mark.unit
def test_retrieved_item_relevance_score_bounds_enforced() -> None:
    reference = SourceReference(category=EvidenceCategory.FINDING, source_id="f1", summary="s")
    with pytest.raises(ValueError):
        RetrievedItem(
            category=EvidenceCategory.FINDING,
            source_id="f1",
            text="t",
            relevance_score=1.5,
            reference=reference,
        )
