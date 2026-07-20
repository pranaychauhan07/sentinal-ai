"""Unit tests for core/vulnerabilities/asset_correlation.py."""

from __future__ import annotations

import pytest

from core.vulnerabilities.asset_correlation import correlate_by_asset
from core.vulnerabilities.models import DetectionSource, VulnerabilityRecord, VulnerabilitySeverity

pytestmark = pytest.mark.unit


def _record(**overrides: object) -> VulnerabilityRecord:
    defaults: dict[str, object] = {
        "plugin_name": "x",
        "detection_source": DetectionSource.NESSUS,
    }
    defaults.update(overrides)
    return VulnerabilityRecord(**defaults)  # type: ignore[arg-type]


def test_groups_by_asset_id() -> None:
    a = _record(asset_id="10.0.0.5", host="web01", severity=VulnerabilitySeverity.LOW)
    b = _record(asset_id="10.0.0.5", host="web01", severity=VulnerabilitySeverity.CRITICAL)
    c = _record(asset_id="10.0.0.6", host="web02", severity=VulnerabilitySeverity.MEDIUM)

    correlations = correlate_by_asset([a, b, c])
    assert len(correlations) == 2
    web01 = next(c for c in correlations if c.asset_id == "10.0.0.5")
    assert web01.highest_severity == VulnerabilitySeverity.CRITICAL
    assert set(web01.vuln_ids) == {a.vuln_id, b.vuln_id}


def test_records_with_no_asset_id_are_excluded() -> None:
    a = _record(asset_id=None)
    correlations = correlate_by_asset([a])
    assert correlations == []


def test_empty_input_returns_empty() -> None:
    assert correlate_by_asset([]) == []
