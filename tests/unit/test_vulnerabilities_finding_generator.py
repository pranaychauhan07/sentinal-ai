"""Unit tests for core/vulnerabilities/finding_generator.py."""

from __future__ import annotations

import pytest

from core.vulnerabilities.finding_generator import VulnerabilityFindingGenerator
from core.vulnerabilities.models import (
    DetectionSource,
    ScoredVulnerability,
    VulnerabilityPriority,
    VulnerabilityRecord,
    VulnerabilityScore,
    VulnerabilitySeverity,
)

pytestmark = pytest.mark.unit


def _score(value: float) -> VulnerabilityScore:
    return VulnerabilityScore(
        cvss_component=0.5,
        severity_weight=0.5,
        confidence=0.5,
        asset_criticality=0.5,
        source_reliability=0.5,
        evidence_quality=0.5,
        composite_score=value,
    )


def _scored(**overrides: object) -> ScoredVulnerability:
    record_defaults: dict[str, object] = {
        "cve_id": "CVE-2021-44228",
        "plugin_id": "156327",
        "plugin_name": "Log4Shell",
        "asset_id": "10.0.0.5",
        "description": "Apache Log4j RCE",
        "severity": VulnerabilitySeverity.HIGH,
        "detection_source": DetectionSource.NESSUS,
    }
    for key in ("cve_id", "plugin_id", "plugin_name", "asset_id", "description", "severity"):
        if key in overrides:
            record_defaults[key] = overrides.pop(key)
    record = VulnerabilityRecord(**record_defaults)  # type: ignore[arg-type]
    return ScoredVulnerability(
        record=record,
        score=overrides.get("score", _score(50.0)),  # type: ignore[arg-type]
        priority=overrides.get("priority", VulnerabilityPriority.P2_HIGH),  # type: ignore[arg-type]
    )


def test_groups_by_cve_across_assets() -> None:
    a = _scored(asset_id="10.0.0.5")
    b = _scored(asset_id="10.0.0.6")
    findings = VulnerabilityFindingGenerator().generate([a, b])
    assert len(findings) == 1
    assert set(findings[0].affected_asset_ids) == {"10.0.0.5", "10.0.0.6"}
    assert findings[0].cve_id == "CVE-2021-44228"


def test_different_cves_produce_separate_findings() -> None:
    a = _scored(cve_id="CVE-2021-1")
    b = _scored(cve_id="CVE-2021-2")
    findings = VulnerabilityFindingGenerator().generate([a, b])
    assert len(findings) == 2


def test_falls_back_to_plugin_id_when_no_cve() -> None:
    a = _scored(cve_id=None, plugin_id="999")
    b = _scored(cve_id=None, plugin_id="999")
    findings = VulnerabilityFindingGenerator().generate([a, b])
    assert len(findings) == 1
    assert findings[0].cve_id is None
    assert findings[0].plugin_id == "999"


def test_finding_takes_highest_severity_and_score_among_group() -> None:
    a = _scored(
        severity=VulnerabilitySeverity.LOW,
        score=_score(20.0),
        priority=VulnerabilityPriority.P4_LOW,
    )
    b = _scored(
        severity=VulnerabilitySeverity.CRITICAL,
        score=_score(95.0),
        priority=VulnerabilityPriority.P1_CRITICAL,
    )
    findings = VulnerabilityFindingGenerator().generate([a, b])
    assert findings[0].severity == VulnerabilitySeverity.CRITICAL
    assert findings[0].composite_score == 95.0
    assert findings[0].priority == VulnerabilityPriority.P1_CRITICAL


def test_empty_input_returns_empty() -> None:
    assert VulnerabilityFindingGenerator().generate([]) == []


def test_finding_has_no_remediation_field() -> None:
    """Explicit boundary check: remediation planning is out of scope for
    this framework (task requirement)."""
    finding = VulnerabilityFindingGenerator().generate([_scored()])[0]
    assert not hasattr(finding, "recommendation")
    assert not hasattr(finding, "remediation")
