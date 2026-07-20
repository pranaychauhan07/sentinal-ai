"""Unit tests for core/owasp_security/models.py — severity ranking and the
category->OWASP/CWE mapping tables."""

from __future__ import annotations

import pytest

from core.owasp_security.models import (
    CATEGORY_CWE_MAP,
    CATEGORY_OWASP_MAP,
    SastSeverity,
    VulnerabilityCategory,
    highest_severity,
    severity_rank,
)

pytestmark = pytest.mark.unit


def test_severity_rank_orders_info_lowest_critical_highest() -> None:
    assert severity_rank(SastSeverity.INFO) < severity_rank(SastSeverity.LOW)
    assert severity_rank(SastSeverity.LOW) < severity_rank(SastSeverity.MEDIUM)
    assert severity_rank(SastSeverity.MEDIUM) < severity_rank(SastSeverity.HIGH)
    assert severity_rank(SastSeverity.HIGH) < severity_rank(SastSeverity.CRITICAL)


def test_highest_severity_empty_list_is_info() -> None:
    assert highest_severity([]) == SastSeverity.INFO


def test_highest_severity_picks_max() -> None:
    assert (
        highest_severity([SastSeverity.LOW, SastSeverity.CRITICAL, SastSeverity.MEDIUM])
        == SastSeverity.CRITICAL
    )


def test_every_vulnerability_category_has_owasp_mapping() -> None:
    for category in VulnerabilityCategory:
        assert category in CATEGORY_OWASP_MAP


def test_every_vulnerability_category_has_cwe_mapping() -> None:
    for category in VulnerabilityCategory:
        assert category in CATEGORY_CWE_MAP
        assert CATEGORY_CWE_MAP[category].startswith("CWE-")


def test_fifteen_categories_defined() -> None:
    assert len(list(VulnerabilityCategory)) == 15
