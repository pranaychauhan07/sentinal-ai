"""Unit tests for core/conversation/response_orchestrator.py."""

from __future__ import annotations

import pytest

from core.conversation.models import (
    ChatCompletion,
    EvidenceCategory,
    PromptPayload,
    RetrievedItem,
    SourceReference,
)
from core.conversation.response_orchestrator import ResponseOrchestrator


class _FakeProvider:
    def __init__(self, completion: ChatCompletion) -> None:
        self._completion = completion

    def generate(self, prompt: PromptPayload) -> ChatCompletion:
        return self._completion


def _prompt() -> PromptPayload:
    return PromptPayload(
        system_instructions="sys", context_text="ctx", history_text="hist", question="q"
    )


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
def test_orchestrate_returns_zero_confidence_when_no_items_available() -> None:
    provider = _FakeProvider(ChatCompletion(answer_text="no evidence"))
    orchestrator = ResponseOrchestrator(llm_provider=provider)
    result = orchestrator.orchestrate(_prompt(), available_items=[])
    assert result.confidence == 0.0
    assert result.citations == ()


@pytest.mark.unit
def test_orchestrate_attaches_citations_and_positive_confidence() -> None:
    provider = _FakeProvider(ChatCompletion(answer_text="answer", used_source_ids=("f1",)))
    orchestrator = ResponseOrchestrator(llm_provider=provider)
    result = orchestrator.orchestrate(_prompt(), available_items=[_item("f1")])
    assert result.confidence > 0.0
    assert len(result.citations) == 1
    assert result.answer_text == "answer"
