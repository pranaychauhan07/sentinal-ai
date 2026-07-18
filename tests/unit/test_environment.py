"""Unit tests for core/config/environment.py."""

from __future__ import annotations

import pytest

from core.config import Environment


@pytest.mark.unit
def test_is_production() -> None:
    assert Environment.PRODUCTION.is_production is True
    assert Environment.DEVELOPMENT.is_production is False
    assert Environment.TESTING.is_production is False


@pytest.mark.unit
def test_is_development() -> None:
    assert Environment.DEVELOPMENT.is_development is True
    assert Environment.PRODUCTION.is_development is False


@pytest.mark.unit
def test_is_testing() -> None:
    assert Environment.TESTING.is_testing is True
    assert Environment.PRODUCTION.is_testing is False
