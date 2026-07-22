"""`ChatModelProvider` — blueprint §5's "LLM ... pluggable via a
`ModelProvider` interface."

ADR-0027 adds the real OpenAI/Gemini/Ollama-backed implementations this
package's prior session deliberately deferred ("create provider interfaces
only... do not integrate external LLM providers yet"). `core.config.settings.
Settings.llm_provider` (the `LLMProvider` `StrEnum`) names which backend an
operator has selected; `build_chat_model_provider(settings)` is the one place
that selection turns into a concrete instance, falling back to
`TemplateChatModelProvider` when unconfigured — exactly mirroring
`core.memory.embedding_providers.build_text_embedder`'s shape.

Every concrete provider is invoked only with the fully-assembled,
already-grounded `PromptPayload` `PromptBuilder` produces — the system
instructions still say "answer only from the provided context, cite sources,
say so if insufficient" regardless of which backend answers, so the
anti-hallucination guarantee is a property of the *prompt*, not of
`TemplateChatModelProvider`'s specific non-generative implementation.
"""

from __future__ import annotations

import re
import socket
from functools import lru_cache
from typing import Protocol, runtime_checkable
from urllib.parse import urlparse

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI

from core.config import LLMProvider, Settings, get_settings
from core.conversation.exceptions import ChatProviderError
from core.conversation.models import ChatCompletion, PromptPayload
from core.logging import get_logger

_logger = get_logger(__name__)

#: How long to wait for the one-time Ollama reachability probe
#: (`_is_ollama_reachable`) before assuming "not running" — Ollama needs no
#: API key, so "configured" alone can't distinguish "will work" from "no
#: local/self-hosted server is up," and a failed *chat* call would otherwise
#: cost a much longer HTTP-client timeout on every single request
#: (constitution §7, "fail gracefully": this keeps that cost to one short,
#: cached probe instead).
_OLLAMA_PROBE_TIMEOUT_SECONDS = 1.0

#: Matches this package's own `[category:source_id]` context-line tag format
#: (`PromptBuilder.render_context`) — used to (a) discover which source ids
#: were actually offered to the model and (b) parse which of those the
#: model's free-text answer actually cited. A citation with no matching
#: bracket tag in the answer is never inferred (constitution §10, "output
#: validation").
_BRACKET_TAG = re.compile(r"\[[a-z_]+:([^\]]+)\]")


@runtime_checkable
class ChatModelProvider(Protocol):
    """Contract every concrete chat-completion backend implements. A future
    OpenAI/Gemini/Ollama-backed provider satisfies this Protocol and is
    injected wherever a `ChatModelProvider` is expected — a provider swap,
    never a pipeline rewrite (constitution §2, "Dependency injection")."""

    def generate(self, prompt: PromptPayload) -> ChatCompletion: ...


class TemplateChatModelProvider:
    """Deterministic, non-generative default provider: composes an answer
    directly from the ranked evidence context already assembled into
    `prompt.context_text`, never invoking any model or network call.

    This is not a stand-in that will be "replaced later out of necessity" —
    it is the structural guarantee behind docs/adr/0025's "never hallucinate
    unavailable data" requirement: the only content substrate this provider
    can draw on is verified, retrieved case data (constitution §1.9)."""

    def generate(self, prompt: PromptPayload) -> ChatCompletion:
        if prompt.context_text == "(no matching case evidence was found)":
            return ChatCompletion(
                answer_text=(
                    "I don't have enough evidence in this case yet to answer that "
                    "question. No matching findings, IOCs, MITRE mappings, reports, "
                    "or timeline events were found."
                ),
                used_source_ids=(),
            )

        lines = prompt.context_text.splitlines()
        used_source_ids: list[str] = []
        summary_lines: list[str] = []
        for line in lines:
            # Each context line is "[category:source_id] text" — see
            # PromptBuilder.render_context.
            if line.startswith("[") and "]" in line:
                header, _, text = line.partition("]")
                source_id = header[1:].split(":", 1)[-1]
                used_source_ids.append(source_id)
                summary_lines.append(text.strip())

        answer_text = (
            f"Based on {len(used_source_ids)} matching case evidence item(s): "
            + " | ".join(summary_lines)
        )
        return ChatCompletion(answer_text=answer_text, used_source_ids=tuple(used_source_ids))


def _available_source_ids(context_text: str) -> set[str]:
    return set(_BRACKET_TAG.findall(context_text))


def _strip_bracket_tags(answer_text: str) -> str:
    """Removes `[category:source_id]` tags from a real model's free-text
    answer once they've served their citation-verification purpose
    (`_cited_source_ids`). Without this, a real completion echoes raw
    internal ids (e.g. `[finding:e64e9e73-1c6d-4841-b5e0-d5998a59e4c5]`)
    inline in prose meant for a human analyst to read — the resolved
    citation list (`ChatCompletion.used_source_ids`) is what the UI renders
    as its "Sources" line instead, per constitution §11's "human-readable
    reasoning... never raw [internal identifiers] dumped to the screen.\""""
    return re.sub(r"\s?" + _BRACKET_TAG.pattern, "", answer_text).strip()


def _cited_source_ids(answer_text: str, available: set[str]) -> tuple[str, ...]:
    """Deterministic post-processing of a real completion's free text
    (constitution §1.9 — the LLM's job is synthesis, not self-reporting a
    structured citation list): only a bracket tag matching a source id the
    prompt actually offered counts as a citation; anything else (a
    hallucinated id, a malformed tag) is silently dropped, matching
    `CitationEngine`'s own "never trust a claimed citation" contract."""
    found: list[str] = []
    seen: set[str] = set()
    for source_id in _BRACKET_TAG.findall(answer_text):
        if source_id in available and source_id not in seen:
            found.append(source_id)
            seen.add(source_id)
    return tuple(found)


def _messages_for(prompt: PromptPayload) -> list[SystemMessage | HumanMessage]:
    system_content = (
        f"{prompt.system_instructions}\n\n"
        f"--- Case evidence context ---\n{prompt.context_text}\n\n"
        f"--- Conversation history ---\n{prompt.history_text}"
    )
    return [SystemMessage(content=system_content), HumanMessage(content=prompt.question)]


class OpenAIChatModelProvider:
    """`ChatModelProvider` backed by `langchain_openai.ChatOpenAI`."""

    def __init__(self, *, api_key: str, model: str, timeout: float) -> None:
        self._client = ChatOpenAI(
            model=model,
            openai_api_key=api_key,
            request_timeout=timeout,  # type: ignore[call-arg]
        )

    def generate(self, prompt: PromptPayload) -> ChatCompletion:
        try:
            response = self._client.invoke(_messages_for(prompt))
            answer_text = str(response.content)
        except Exception as exc:  # noqa: BLE001 - wrapped into one narrow type for the caller
            raise ChatProviderError(
                f"OpenAI chat completion failed: {exc}", details={"provider": "openai"}
            ) from exc
        available = _available_source_ids(prompt.context_text)
        used_source_ids = _cited_source_ids(answer_text, available)
        return ChatCompletion(
            answer_text=_strip_bracket_tags(answer_text), used_source_ids=used_source_ids
        )


class GeminiChatModelProvider:
    """`ChatModelProvider` backed by
    `langchain_google_genai.ChatGoogleGenerativeAI`."""

    def __init__(self, *, api_key: str, model: str, timeout: float) -> None:
        self._client = ChatGoogleGenerativeAI(google_api_key=api_key, model=model, timeout=timeout)  # type: ignore[call-arg]

    def generate(self, prompt: PromptPayload) -> ChatCompletion:
        try:
            response = self._client.invoke(_messages_for(prompt))
            answer_text = str(response.content)
        except Exception as exc:  # noqa: BLE001 - wrapped into one narrow type for the caller
            raise ChatProviderError(
                f"Gemini chat completion failed: {exc}", details={"provider": "gemini"}
            ) from exc
        available = _available_source_ids(prompt.context_text)
        used_source_ids = _cited_source_ids(answer_text, available)
        return ChatCompletion(
            answer_text=_strip_bracket_tags(answer_text), used_source_ids=used_source_ids
        )


class OllamaChatModelProvider:
    """`ChatModelProvider` backed by `langchain_ollama.ChatOllama` — no API
    key required, only a reachable `base_url`."""

    def __init__(self, *, base_url: str, model: str, timeout: float) -> None:
        self._client = ChatOllama(base_url=base_url, model=model, request_timeout=timeout)  # type: ignore[call-arg]

    def generate(self, prompt: PromptPayload) -> ChatCompletion:
        try:
            response = self._client.invoke(_messages_for(prompt))
            answer_text = str(response.content)
        except Exception as exc:  # noqa: BLE001 - wrapped into one narrow type for the caller
            raise ChatProviderError(
                f"Ollama chat completion failed: {exc}", details={"provider": "ollama"}
            ) from exc
        available = _available_source_ids(prompt.context_text)
        used_source_ids = _cited_source_ids(answer_text, available)
        return ChatCompletion(
            answer_text=_strip_bracket_tags(answer_text), used_source_ids=used_source_ids
        )


def _is_ollama_reachable(base_url: str) -> bool:
    """One short TCP-connect probe (never an HTTP round-trip — cheaper and
    just as sufficient to detect "nothing is listening") to
    `base_url`'s host/port, bounded by `_OLLAMA_PROBE_TIMEOUT_SECONDS`.

    Ollama needs no API key, so "provider selected" alone can't distinguish
    "will actually work" from "no local/self-hosted server is running" —
    without this, a misconfigured/absent Ollama would pay a much longer
    per-request HTTP-client timeout on every single chat call instead of one
    short, cached check (constitution §7, "fail gracefully").
    """
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 11434
    try:
        with socket.create_connection((host, port), timeout=_OLLAMA_PROBE_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


def build_chat_model_provider(settings: Settings) -> ChatModelProvider:
    """Selects a real `ChatModelProvider` per `settings.llm_provider`.

    Falls back to `TemplateChatModelProvider` (logged at `WARNING`, never
    raised) whenever the selected provider is missing the credentials it
    needs, or — for Ollama specifically — is not actually reachable right
    now (constitution §7, "fail gracefully").
    """
    if settings.llm_provider is LLMProvider.OPENAI:
        if not settings.openai_api_key:
            _logger.warning(
                "chat_model_provider_fallback", provider="openai", reason="missing_api_key"
            )
            return TemplateChatModelProvider()
        return OpenAIChatModelProvider(
            api_key=settings.openai_api_key,
            model=settings.openai_model,
            timeout=settings.llm_request_timeout_seconds,
        )
    if settings.llm_provider is LLMProvider.GEMINI:
        if not settings.google_api_key:
            _logger.warning(
                "chat_model_provider_fallback", provider="gemini", reason="missing_api_key"
            )
            return TemplateChatModelProvider()
        return GeminiChatModelProvider(
            api_key=settings.google_api_key,
            model=settings.gemini_model,
            timeout=settings.llm_request_timeout_seconds,
        )
    # Ollama: no API key required, but an absent/unreachable local server is
    # the common "offline dev / CI" case (constitution §7) — probed once
    # here rather than discovered on the first real chat call.
    if not _is_ollama_reachable(settings.ollama_base_url):
        _logger.warning(
            "chat_model_provider_fallback", provider="ollama", reason="server_unreachable"
        )
        return TemplateChatModelProvider()
    return OllamaChatModelProvider(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        timeout=settings.llm_request_timeout_seconds,
    )


@lru_cache
def default_chat_model_provider() -> ChatModelProvider:
    """Process-wide singleton (constitution §2), matching
    `core.memory.manager.default_long_term_memory()`'s identical shape —
    constructed lazily via `build_chat_model_provider(get_settings())` on
    first access, so the (bounded, ~1s worst-case) Ollama reachability probe
    is paid once per process, not once per chat request. Callers needing
    isolation (tests, a future multi-process deployment) construct and
    inject their own `ChatModelProvider` instead."""
    return build_chat_model_provider(get_settings())
