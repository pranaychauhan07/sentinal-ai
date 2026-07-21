"""Unit tests for core/conversation/retrieval.py."""

from __future__ import annotations

import pytest

from core.conversation.exceptions import OversizedConversationInputError
from core.conversation.models import ConversationRetrievalContext, EvidenceCategory
from core.conversation.retrieval import MAX_RECORDS_PER_CATEGORY, RetrievalLayer


def _context(**overrides: object) -> ConversationRetrievalContext:
    defaults: dict[str, object] = {
        "case_id": "c1",
        "findings": (
            {
                "finding_id": "f1",
                "title": "Brute force login attempts",
                "description": "Repeated failed SSH logins from 10.0.0.5",
                "severity": "high",
            },
        ),
        "iocs": ({"ioc_id": "i1", "ioc_type": "ipv4", "value": "10.0.0.5"},),
        "mitre_mappings": ({"technique_id": "T1110", "tactic_ids": ["TA0006"]},),
        "reports": ({"report_id": "r1", "title": "Case Summary", "report_type": "executive"},),
        "timeline_events": (
            {
                "event_id": "e1",
                "event_type": "finding_generated",
                "narrative": "Brute force detected",
            },
        ),
    }
    defaults.update(overrides)
    return ConversationRetrievalContext(**defaults)  # type: ignore[arg-type]


@pytest.mark.unit
def test_retrieve_scores_matching_finding_above_zero() -> None:
    layer = RetrievalLayer()
    items = layer.retrieve(
        _context(),
        question="Why was the brute force finding scored high?",
        categories=(EvidenceCategory.FINDING,),
    )
    assert len(items) == 1
    assert items[0].source_id == "f1"
    assert items[0].relevance_score > 0.0


@pytest.mark.unit
def test_retrieve_returns_nothing_for_unrelated_question() -> None:
    layer = RetrievalLayer()
    items = layer.retrieve(
        _context(), question="zzz unrelated gibberish", categories=(EvidenceCategory.FINDING,)
    )
    assert items == []


@pytest.mark.unit
def test_retrieve_skips_malformed_non_dict_entries() -> None:
    """`ConversationRetrievalContext`'s own strict Pydantic typing means
    `retrieve` can never actually receive a non-dict entry in normal
    operation (the service filters at hydration time) — `model_construct`
    deliberately bypasses that validation to exercise the belt-and-suspenders
    `isinstance` guard directly, the same technique docs/adr/0024 documents
    for `core.reporting.section_builders`'s identical defense."""
    layer = RetrievalLayer()
    context = ConversationRetrievalContext.model_construct(
        case_id="c1",
        findings=("not-a-dict",),
        iocs=(),
        mitre_mappings=(),
        reports=(),
        timeline_events=(),
        skipped_record_count=0,
    )
    items = layer.retrieve(context, question="brute force", categories=(EvidenceCategory.FINDING,))
    assert items == []


@pytest.mark.unit
def test_retrieve_across_multiple_categories() -> None:
    layer = RetrievalLayer()
    items = layer.retrieve(
        _context(),
        question="brute force T1110 technique",
        categories=(EvidenceCategory.FINDING, EvidenceCategory.MITRE_MAPPING),
    )
    categories_seen = {item.category for item in items}
    assert EvidenceCategory.FINDING in categories_seen
    assert EvidenceCategory.MITRE_MAPPING in categories_seen


@pytest.mark.unit
def test_retrieve_raises_on_oversized_category() -> None:
    layer = RetrievalLayer()
    oversized = tuple(
        {"finding_id": str(i), "title": "x"} for i in range(MAX_RECORDS_PER_CATEGORY + 1)
    )
    context = _context(findings=oversized)
    with pytest.raises(OversizedConversationInputError):
        layer.retrieve(context, question="x", categories=(EvidenceCategory.FINDING,))
