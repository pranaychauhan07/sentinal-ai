"""Unit tests for core/config/settings.py."""

from __future__ import annotations

import pytest

from core.config import Environment, LLMProvider, Settings, get_settings


@pytest.mark.unit
def test_settings_load_from_env(test_settings: Settings) -> None:
    assert test_settings.app_env is Environment.TESTING
    assert test_settings.llm_provider is LLMProvider.OLLAMA
    assert test_settings.is_sqlite is True


@pytest.mark.unit
def test_get_settings_is_cached(test_settings: Settings) -> None:
    assert get_settings() is get_settings()


@pytest.mark.unit
def test_invalid_log_level_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_LEVEL", "NOT_A_LEVEL")
    get_settings.cache_clear()
    with pytest.raises(ValueError, match="log_level"):
        Settings()
    get_settings.cache_clear()


@pytest.mark.unit
def test_prompt_guard_extra_pattern_list_parses_csv() -> None:
    settings = Settings(PROMPT_GUARD_EXTRA_PATTERNS="foo, bar ,, baz")
    assert settings.prompt_guard_extra_pattern_list == ["foo", "bar", "baz"]


@pytest.mark.unit
def test_llm_is_configured_openai_requires_key() -> None:
    settings = Settings(LLM_PROVIDER="openai", OPENAI_API_KEY=None)
    assert settings.llm_is_configured() is False

    settings_with_key = Settings(LLM_PROVIDER="openai", OPENAI_API_KEY="sk-test")
    assert settings_with_key.llm_is_configured() is True


@pytest.mark.unit
def test_llm_is_configured_ollama_never_requires_key() -> None:
    settings = Settings(LLM_PROVIDER="ollama")
    assert settings.llm_is_configured() is True
