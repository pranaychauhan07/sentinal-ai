"""Unit tests for core/owasp_security/confidence_calculator.py."""

from __future__ import annotations

import pytest

from core.owasp_security.confidence_calculator import calculate_confidence

pytestmark = pytest.mark.unit


def test_ast_based_gets_no_discount() -> None:
    assert calculate_confidence(0.8, is_ast_based=True) == 0.8


def test_pattern_based_is_discounted() -> None:
    result = calculate_confidence(0.8, is_ast_based=False)
    assert result < 0.8
    assert result == pytest.approx(0.6, abs=0.01)


def test_result_is_clamped_to_one() -> None:
    assert calculate_confidence(1.5, is_ast_based=True) == 1.0


def test_result_is_clamped_to_zero() -> None:
    assert calculate_confidence(-1.0, is_ast_based=True) == 0.0
