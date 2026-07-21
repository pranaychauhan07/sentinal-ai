"""Unit tests for core/memory/embedding_providers.py. Per constitution §11
("mock the LLM client's HTTP call, not internals"), each concrete provider's
underlying `langchain-*` client is mocked at its `embed_query` boundary —
never a real network call.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.config import LLMProvider, Settings
from core.memory.embedding_providers import (
    GeminiEmbeddingProvider,
    OllamaEmbeddingProvider,
    OpenAIEmbeddingProvider,
    build_text_embedder,
)
from core.memory.exceptions import EmbeddingProviderError
from core.memory.vector_store import HashingTextEmbedder

pytestmark = pytest.mark.unit


def test_openai_embedding_provider_wraps_client_call() -> None:
    provider = OpenAIEmbeddingProvider(api_key="sk-test", model="text-embedding-3-small", timeout=5)
    with patch.object(
        type(provider._client), "embed_query", return_value=[0.1, 0.2, 0.3]
    ) as mocked:
        result = provider.embed("some text")
    mocked.assert_called_once_with("some text")
    assert result == [0.1, 0.2, 0.3]


def test_openai_embedding_provider_wraps_sdk_failure() -> None:
    provider = OpenAIEmbeddingProvider(api_key="sk-test", model="text-embedding-3-small", timeout=5)
    with (
        patch.object(type(provider._client), "embed_query", side_effect=RuntimeError("boom")),
        pytest.raises(EmbeddingProviderError),
    ):
        provider.embed("some text")


def test_gemini_embedding_provider_wraps_client_call() -> None:
    provider = GeminiEmbeddingProvider(api_key="test-key", model="models/text-embedding-004")
    with patch.object(type(provider._client), "embed_query", return_value=[0.4, 0.5]) as mocked:
        result = provider.embed("some text")
    mocked.assert_called_once_with("some text")
    assert result == [0.4, 0.5]


def test_gemini_embedding_provider_wraps_sdk_failure() -> None:
    provider = GeminiEmbeddingProvider(api_key="test-key", model="models/text-embedding-004")
    with (
        patch.object(type(provider._client), "embed_query", side_effect=RuntimeError("boom")),
        pytest.raises(EmbeddingProviderError),
    ):
        provider.embed("some text")


def test_ollama_embedding_provider_wraps_client_call() -> None:
    provider = OllamaEmbeddingProvider(base_url="http://localhost:11434", model="nomic-embed-text")
    with patch.object(type(provider._client), "embed_query", return_value=[0.6]) as mocked:
        result = provider.embed("some text")
    mocked.assert_called_once_with("some text")
    assert result == [0.6]


def test_ollama_embedding_provider_wraps_sdk_failure() -> None:
    provider = OllamaEmbeddingProvider(base_url="http://localhost:11434", model="nomic-embed-text")
    with (
        patch.object(
            type(provider._client), "embed_query", side_effect=RuntimeError("unreachable")
        ),
        pytest.raises(EmbeddingProviderError),
    ):
        provider.embed("some text")


def test_build_text_embedder_falls_back_to_hashing_when_openai_key_missing() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.OPENAI, OPENAI_API_KEY=None)
    embedder = build_text_embedder(settings)
    assert isinstance(embedder, HashingTextEmbedder)


def test_build_text_embedder_falls_back_to_hashing_when_gemini_key_missing() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.GEMINI, GOOGLE_API_KEY=None)
    embedder = build_text_embedder(settings)
    assert isinstance(embedder, HashingTextEmbedder)


def test_build_text_embedder_selects_openai_when_configured() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.OPENAI, OPENAI_API_KEY="sk-test")
    embedder = build_text_embedder(settings)
    assert isinstance(embedder, OpenAIEmbeddingProvider)


def test_build_text_embedder_selects_gemini_when_configured() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.GEMINI, GOOGLE_API_KEY="test-key")
    embedder = build_text_embedder(settings)
    assert isinstance(embedder, GeminiEmbeddingProvider)


def test_build_text_embedder_falls_back_to_hashing_when_ollama_unreachable() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.OLLAMA, OLLAMA_BASE_URL="http://127.0.0.1:1")
    embedder = build_text_embedder(settings)
    assert isinstance(embedder, HashingTextEmbedder)


def test_build_text_embedder_selects_ollama_when_reachable() -> None:
    settings = Settings(LLM_PROVIDER=LLMProvider.OLLAMA)
    with patch("core.memory.embedding_providers._is_ollama_reachable", return_value=True):
        embedder = build_text_embedder(settings)
    assert isinstance(embedder, OllamaEmbeddingProvider)
