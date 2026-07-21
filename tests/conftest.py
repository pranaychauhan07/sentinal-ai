"""Shared pytest fixtures for the whole suite.

Ensures every test runs against isolated settings (its own temp log dir and
an in-memory/temp-file SQLite database) rather than accidentally touching a
developer's real `.env`-configured resources.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from core.config import Settings, get_settings
from core.logging import clear_context


def _clear_process_wide_singleton_caches() -> None:
    """Clears every `@lru_cache`-decorated process-wide singleton factory
    this codebase defines (constitution §2's documented exception to
    "avoid global state") — `get_settings()` plus the ADR-0027 additions
    (`default_long_term_memory`, `default_chat_model_provider`) that
    themselves call `get_settings()` internally and would otherwise cache a
    *previous* test's settings (and, for long-term memory, a previous
    test's `CHROMA_PERSIST_DIR`) for the rest of the pytest session."""
    from core.conversation.llm_provider import default_chat_model_provider
    from core.memory.manager import default_long_term_memory

    get_settings.cache_clear()
    default_long_term_memory.cache_clear()
    default_chat_model_provider.cache_clear()


@pytest.fixture
def test_settings(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """A `Settings` instance pointed at a temp DB file, temp log dir, and
    temp ChromaDB persist directory, with every process-wide settings-derived
    singleton cache cleared before and after so tests never leak
    configuration (or a stale vector store) into each other."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("APP_ENV", "testing")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("EVIDENCE_STORAGE_DIR", str(tmp_path / "evidence_uploads"))
    monkeypatch.setenv("CHROMA_PERSIST_DIR", str(tmp_path / "chroma"))

    _clear_process_wide_singleton_caches()
    settings = get_settings()
    yield settings
    _clear_process_wide_singleton_caches()


@pytest.fixture(autouse=True)
def _clear_logging_context() -> Iterator[None]:
    """Guarantee no bound logging context (request_id, case_id, ...) leaks
    from one test into the next."""
    clear_context()
    yield
    clear_context()
