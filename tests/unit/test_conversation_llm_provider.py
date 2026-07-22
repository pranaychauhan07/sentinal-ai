"""Unit tests for core/conversation/llm_provider.py."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from core.config import LLMProvider, Settings
from core.conversation.exceptions import ChatProviderError
from core.conversation.llm_provider import (
    ChatModelProvider,
    GeminiChatModelProvider,
    OllamaChatModelProvider,
    OpenAIChatModelProvider,
    TemplateChatModelProvider,
    build_chat_model_provider,
)
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


def _fake_response(text: str) -> Mock:
    response = Mock()
    response.content = text
    return response


@pytest.mark.unit
def test_openai_chat_model_provider_satisfies_protocol() -> None:
    provider = OpenAIChatModelProvider(api_key="sk-test", model="gpt-4o-mini", timeout=5)
    assert isinstance(provider, ChatModelProvider)


@pytest.mark.unit
def test_openai_chat_model_provider_extracts_cited_bracket_tags() -> None:
    provider = OpenAIChatModelProvider(api_key="sk-test", model="gpt-4o-mini", timeout=5)
    prompt = _prompt("[finding:f1] Brute force detected\n[ioc:i1] 10.0.0.5")
    with patch.object(
        type(provider._client),
        "invoke",
        return_value=_fake_response("Yes, per [finding:f1] this is brute force."),
    ):
        completion = provider.generate(prompt)
    assert completion.used_source_ids == ("f1",)
    assert "brute force" in completion.answer_text.lower()


@pytest.mark.unit
def test_openai_chat_model_provider_strips_bracket_tags_from_displayed_answer() -> None:
    """Regression test: a real completion previously echoed the raw
    `[category:source_id]` tag inline in the answer text shown to the
    analyst (e.g. `... per [finding:e64e9e73-...] this is brute force.`) —
    unreadable, internal-id-leaking prose. The tag must still be counted as
    a citation, but must not appear in the text a human reads."""
    provider = OpenAIChatModelProvider(api_key="sk-test", model="gpt-4o-mini", timeout=5)
    prompt = _prompt("[finding:f1] Brute force detected")
    with patch.object(
        type(provider._client),
        "invoke",
        return_value=_fake_response("Yes, per [finding:f1] this is brute force."),
    ):
        completion = provider.generate(prompt)
    assert completion.used_source_ids == ("f1",)
    assert "[finding:f1]" not in completion.answer_text
    assert "brute force" in completion.answer_text.lower()


@pytest.mark.unit
def test_openai_chat_model_provider_never_fabricates_an_unknown_citation() -> None:
    provider = OpenAIChatModelProvider(api_key="sk-test", model="gpt-4o-mini", timeout=5)
    prompt = _prompt("[finding:f1] Brute force detected")
    with patch.object(
        type(provider._client),
        "invoke",
        return_value=_fake_response("Per [finding:f999] (never offered), yes."),
    ):
        completion = provider.generate(prompt)
    assert completion.used_source_ids == ()


@pytest.mark.unit
def test_openai_chat_model_provider_wraps_sdk_failure() -> None:
    provider = OpenAIChatModelProvider(api_key="sk-test", model="gpt-4o-mini", timeout=5)
    with (
        patch.object(type(provider._client), "invoke", side_effect=RuntimeError("boom")),
        pytest.raises(ChatProviderError),
    ):
        provider.generate(_prompt("[finding:f1] x"))


@pytest.mark.unit
def test_gemini_chat_model_provider_wraps_client_call() -> None:
    provider = GeminiChatModelProvider(api_key="test-key", model="gemini-1.5-pro", timeout=5)
    with patch.object(
        type(provider._client), "invoke", return_value=_fake_response("[finding:f1] answer")
    ):
        completion = provider.generate(_prompt("[finding:f1] Brute force detected"))
    assert completion.used_source_ids == ("f1",)


@pytest.mark.unit
def test_ollama_chat_model_provider_wraps_client_call() -> None:
    provider = OllamaChatModelProvider(
        base_url="http://localhost:11434", model="llama3.1", timeout=5
    )
    with patch.object(
        type(provider._client), "invoke", return_value=_fake_response("[finding:f1] answer")
    ):
        completion = provider.generate(_prompt("[finding:f1] Brute force detected"))
    assert completion.used_source_ids == ("f1",)


@pytest.mark.unit
def test_build_chat_model_provider_falls_back_when_openai_key_missing() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.OPENAI, OPENAI_API_KEY=None)
    assert isinstance(build_chat_model_provider(settings), TemplateChatModelProvider)


@pytest.mark.unit
def test_build_chat_model_provider_falls_back_when_gemini_key_missing() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.GEMINI, GOOGLE_API_KEY=None)
    assert isinstance(build_chat_model_provider(settings), TemplateChatModelProvider)


@pytest.mark.unit
def test_build_chat_model_provider_falls_back_when_ollama_unreachable() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.OLLAMA, OLLAMA_BASE_URL="http://127.0.0.1:1")
    assert isinstance(build_chat_model_provider(settings), TemplateChatModelProvider)


@pytest.mark.unit
def test_build_chat_model_provider_selects_openai_when_configured() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.OPENAI, OPENAI_API_KEY="sk-test")
    assert isinstance(build_chat_model_provider(settings), OpenAIChatModelProvider)


@pytest.mark.unit
def test_build_chat_model_provider_selects_gemini_when_configured() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.GEMINI, GOOGLE_API_KEY="test-key")
    assert isinstance(build_chat_model_provider(settings), GeminiChatModelProvider)


@pytest.mark.unit
def test_build_chat_model_provider_selects_ollama_when_reachable() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.OLLAMA)
    with patch("core.conversation.llm_provider._is_ollama_reachable", return_value=True):
        provider = build_chat_model_provider(settings)
    assert isinstance(provider, OllamaChatModelProvider)
