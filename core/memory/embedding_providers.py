"""Concrete `TextEmbedder` (`core/memory/vector_store.py`) implementations —
real semantic embeddings via already-vendored `langchain-*` clients
(ADR-0027), replacing `HashingTextEmbedder` as the production default while
keeping it as the documented, dependency-free fallback.

Every concrete provider wraps its backend SDK's call in `try/except`,
raising `core.memory.exceptions.EmbeddingProviderError` — never letting a
raw, provider-specific SDK exception leak past this module. `long_term.py`'s
existing broad advisory-degrade boundary already catches any `Exception`
here, so this narrow type exists for callers/tests that want to distinguish
"the provider failed" from any other bug, per constitution §5's "every tool
module defines its own narrow exception classes."

No provider is imported at module import time beyond its already-required
`langchain-*` package (all three are unconditional `requirements.txt`
dependencies — no optional-import guarding needed).
"""

from __future__ import annotations

import socket
from urllib.parse import urlparse

from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_ollama import OllamaEmbeddings
from langchain_openai import OpenAIEmbeddings

from core.config import LLMProvider, Settings
from core.logging import get_logger
from core.memory.exceptions import EmbeddingProviderError
from core.memory.vector_store import HashingTextEmbedder, TextEmbedder

_logger = get_logger(__name__)

#: Mirrors `core.conversation.llm_provider._OLLAMA_PROBE_TIMEOUT_SECONDS`'s
#: identical reasoning — a small, deliberately duplicated probe (not a
#: cross-leaf import: `core/memory` and `core/conversation` are separate
#: leaves per docs/dependency-rules.md and share no common module either
#: could import this from) rather than a much longer per-call embedding
#: timeout when no local Ollama server is running (constitution §7).
_OLLAMA_PROBE_TIMEOUT_SECONDS = 1.0


def _is_ollama_reachable(base_url: str) -> bool:
    parsed = urlparse(base_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 11434
    try:
        with socket.create_connection((host, port), timeout=_OLLAMA_PROBE_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


class OpenAIEmbeddingProvider:
    """`TextEmbedder` backed by `langchain_openai.OpenAIEmbeddings`."""

    def __init__(self, *, api_key: str, model: str, timeout: float) -> None:
        self._client = OpenAIEmbeddings(
            openai_api_key=api_key,  # type: ignore[call-arg]
            model=model,
            request_timeout=timeout,
        )

    def embed(self, text: str) -> list[float]:
        try:
            return [float(component) for component in self._client.embed_query(text)]
        except Exception as exc:  # noqa: BLE001 - wrapped into one narrow type for the caller
            raise EmbeddingProviderError(
                f"OpenAI embedding call failed: {exc}", details={"provider": "openai"}
            ) from exc


class GeminiEmbeddingProvider:
    """`TextEmbedder` backed by
    `langchain_google_genai.GoogleGenerativeAIEmbeddings`."""

    def __init__(self, *, api_key: str, model: str) -> None:
        self._client = GoogleGenerativeAIEmbeddings(google_api_key=api_key, model=model)  # type: ignore[call-arg]

    def embed(self, text: str) -> list[float]:
        try:
            return [float(component) for component in self._client.embed_query(text)]
        except Exception as exc:  # noqa: BLE001 - wrapped into one narrow type for the caller
            raise EmbeddingProviderError(
                f"Gemini embedding call failed: {exc}", details={"provider": "gemini"}
            ) from exc


class OllamaEmbeddingProvider:
    """`TextEmbedder` backed by `langchain_ollama.OllamaEmbeddings` — no API
    key required (local/self-hosted server), only a reachable `base_url`."""

    def __init__(self, *, base_url: str, model: str) -> None:
        self._client = OllamaEmbeddings(base_url=base_url, model=model)

    def embed(self, text: str) -> list[float]:
        try:
            return [float(component) for component in self._client.embed_query(text)]
        except Exception as exc:  # noqa: BLE001 - wrapped into one narrow type for the caller
            raise EmbeddingProviderError(
                f"Ollama embedding call failed: {exc}", details={"provider": "ollama"}
            ) from exc


def build_text_embedder(settings: Settings) -> TextEmbedder:
    """Selects a real, semantic `TextEmbedder` per `settings.llm_provider`.

    Falls back to the deterministic `HashingTextEmbedder` (logged at
    `WARNING`, never raised) whenever the selected provider is missing the
    credentials it needs — constitution §7, "fail gracefully": a
    misconfigured deployment degrades to a working, if lower-quality,
    embedder rather than failing to start.
    """
    if settings.llm_provider is LLMProvider.OPENAI:
        if not settings.openai_api_key:
            _logger.warning(
                "embedding_provider_fallback", provider="openai", reason="missing_api_key"
            )
            return HashingTextEmbedder()
        return OpenAIEmbeddingProvider(
            api_key=settings.openai_api_key,
            model=settings.openai_embedding_model,
            timeout=settings.embedding_request_timeout_seconds,
        )
    if settings.llm_provider is LLMProvider.GEMINI:
        if not settings.google_api_key:
            _logger.warning(
                "embedding_provider_fallback", provider="gemini", reason="missing_api_key"
            )
            return HashingTextEmbedder()
        return GeminiEmbeddingProvider(
            api_key=settings.google_api_key, model=settings.gemini_embedding_model
        )
    # Ollama: no API key required, but an absent/unreachable local server is
    # the common "offline dev / CI" case — probed once here (bounded, ~1s
    # worst case) rather than discovered on the first real embedding call.
    if not _is_ollama_reachable(settings.ollama_base_url):
        _logger.warning(
            "embedding_provider_fallback", provider="ollama", reason="server_unreachable"
        )
        return HashingTextEmbedder()
    return OllamaEmbeddingProvider(
        base_url=settings.ollama_base_url, model=settings.ollama_embedding_model
    )
