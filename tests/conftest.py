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


@pytest.fixture
def test_settings(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """A `Settings` instance pointed at a temp DB file and temp log dir,
    with the process-wide `get_settings()` cache cleared before and after so
    tests never leak configuration into each other."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("APP_ENV", "testing")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("EVIDENCE_STORAGE_DIR", str(tmp_path / "evidence_uploads"))

    get_settings.cache_clear()
    settings = get_settings()
    yield settings
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _clear_logging_context() -> Iterator[None]:
    """Guarantee no bound logging context (request_id, case_id, ...) leaks
    from one test into the next."""
    clear_context()
    yield
    clear_context()
