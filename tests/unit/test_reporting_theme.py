"""Unit tests for core/reporting/theme.py."""

from __future__ import annotations

import pytest

from core.reporting.exceptions import UnknownThemeError
from core.reporting.theme import DARK_THEME, LIGHT_THEME, ReportTheme, resolve_theme

pytestmark = pytest.mark.unit


def test_light_and_dark_theme_presets_differ_in_dark_mode_flag() -> None:
    assert LIGHT_THEME.dark_mode is False
    assert DARK_THEME.dark_mode is True


def test_resolve_theme_defaults_to_light_when_none() -> None:
    assert resolve_theme(None) is LIGHT_THEME


def test_resolve_theme_accepts_built_in_name() -> None:
    assert resolve_theme("dark") is DARK_THEME


def test_resolve_theme_passes_through_a_custom_theme_instance() -> None:
    custom = ReportTheme(name="acme-brand", organization_name="Acme Corp")
    assert resolve_theme(custom) is custom


def test_resolve_theme_rejects_unknown_name() -> None:
    with pytest.raises(UnknownThemeError):
        resolve_theme("neon")


def test_theme_is_frozen() -> None:
    with pytest.raises(Exception):  # noqa: B017, PT011 - pydantic ValidationError on frozen mutation
        LIGHT_THEME.name = "mutated"  # type: ignore[misc]
