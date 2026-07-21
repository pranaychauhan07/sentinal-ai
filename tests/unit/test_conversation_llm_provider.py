"""Unit tests for core/conversation/llm_provider.py."""

from __future__ import annotations

import pytest

from core.conversation.llm_provider import ChatModelProvider, TemplateChatModelProvider
from core.conversation.models import PromptPayload


def _prompt(context_text: str) -> PromptPayload:
    return PromptPayload(
        system_instructions="sys",
        context_text=context_text,
        history_text="(no prior turns in this session)",
        question="q",
    )


@pytest.mark.unit
def test_template_provider_satisfies_protocol() -> None:
    assert isinstance(TemplateChatModelProvider(), ChatModelProvider)


@pytest.mark.unit
def test_generate_reports_insufficient_evidence_when_no_context() -> None:
    provider = TemplateChatModelProvider()
    completion = provider.generate(_prompt("(no matching case evidence was found)"))
    assert "don't have enough evidence" in completion.answer_text
    assert completion.used_source_ids == ()


@pytest.mark.unit
def test_generate_composes_answer_from_context_lines_and_reports_source_ids() -> None:
    provider = TemplateChatModelProvider()
    context_text = "[finding:f1] Brute force detected\n[ioc:i1] 10.0.0.5"
    completion = provider.generate(_prompt(context_text))
    assert completion.used_source_ids == ("f1", "i1")
    assert "Brute force detected" in completion.answer_text
    assert "10.0.0.5" in completion.answer_text


@pytest.mark.unit
def test_generate_is_deterministic_given_the_same_input() -> None:
    provider = TemplateChatModelProvider()
    prompt = _prompt("[finding:f1] Brute force detected")
    first = provider.generate(prompt)
    second = provider.generate(prompt)
    assert first == second
