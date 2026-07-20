"""Unit tests for core/owasp_web/models.py — severity ranking helpers."""

from __future__ import annotations

import pytest

from core.owasp_web.models import WebSecuritySeverity, highest_severity, severity_rank

pytestmark = pytest.mark.unit


def test_severity_rank_orders_info_lowest_critical_highest() -> None:
    assert severity_rank(WebSecuritySeverity.INFO) < severity_rank(WebSecuritySeverity.LOW)
    assert severity_rank(WebSecuritySeverity.LOW) < severity_rank(WebSecuritySeverity.MEDIUM)
    assert severity_rank(WebSecuritySeverity.MEDIUM) < severity_rank(WebSecuritySeverity.HIGH)
    assert severity_rank(WebSecuritySeverity.HIGH) < severity_rank(WebSecuritySeverity.CRITICAL)


def test_highest_severity_empty_list_is_info() -> None:
    assert highest_severity([]) == WebSecuritySeverity.INFO


def test_highest_severity_picks_max() -> None:
    assert (
        highest_severity(
            [WebSecuritySeverity.LOW, WebSecuritySeverity.CRITICAL, WebSecuritySeverity.MEDIUM]
        )
        == WebSecuritySeverity.CRITICAL
    )
