"""Unit tests for core/vulnerabilities/severity.py."""

from __future__ import annotations

import pytest

from core.knowledge.cvss_calculator import CvssCalculator
from core.vulnerabilities.models import (
    AssetCriticality,
    VulnerabilityPriority,
    VulnerabilitySeverity,
)
from core.vulnerabilities.severity import (
    assign_priority,
    severity_from_cvss,
    severity_from_scanner_code,
)

pytestmark = pytest.mark.unit


def test_severity_from_cvss_critical() -> None:
    cvss = CvssCalculator().score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert severity_from_cvss(cvss) == VulnerabilitySeverity.CRITICAL


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (0, VulnerabilitySeverity.INFO),
        (1, VulnerabilitySeverity.LOW),
        (2, VulnerabilitySeverity.MEDIUM),
        (3, VulnerabilitySeverity.HIGH),
        (4, VulnerabilitySeverity.CRITICAL),
    ],
)
def test_severity_from_scanner_code(code: int, expected: VulnerabilitySeverity) -> None:
    assert severity_from_scanner_code(code) == expected


def test_severity_from_scanner_code_clamps_out_of_range() -> None:
    assert severity_from_scanner_code(99) == VulnerabilitySeverity.CRITICAL
    assert severity_from_scanner_code(-5) == VulnerabilitySeverity.INFO


def test_high_severity_escalates_to_p1_on_critical_asset() -> None:
    assert (
        assign_priority(VulnerabilitySeverity.HIGH, AssetCriticality.HIGH)
        == VulnerabilityPriority.P1_CRITICAL
    )


def test_high_severity_stays_p2_on_medium_asset() -> None:
    assert (
        assign_priority(VulnerabilitySeverity.HIGH, AssetCriticality.MEDIUM)
        == VulnerabilityPriority.P2_HIGH
    )


def test_critical_severity_is_always_p1() -> None:
    assert (
        assign_priority(VulnerabilitySeverity.CRITICAL, AssetCriticality.LOW)
        == VulnerabilityPriority.P1_CRITICAL
    )


def test_info_severity_is_always_p4() -> None:
    assert (
        assign_priority(VulnerabilitySeverity.INFO, AssetCriticality.CRITICAL)
        == VulnerabilityPriority.P4_LOW
    )
