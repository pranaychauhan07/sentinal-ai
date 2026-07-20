"""Unit tests for core/vulnerabilities/scoring.py."""

from __future__ import annotations

import pytest

from core.knowledge.cvss_calculator import CvssCalculator
from core.vulnerabilities.models import (
    AssetCriticality,
    DetectionSource,
    VulnerabilityRecord,
    VulnerabilitySeverity,
)
from core.vulnerabilities.scoring import (
    VulnerabilityScoringWeights,
    VulnerabilityThreatScoringEngine,
)

pytestmark = pytest.mark.unit


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError, match="must sum to 1.0"):
        VulnerabilityScoringWeights(
            cvss=0.5,
            severity=0.5,
            confidence=0.5,
            asset_criticality=0.5,
            source_reliability=0.5,
            evidence_quality=0.5,
        )


def test_critical_vulnerability_on_critical_asset_scores_high() -> None:
    record = VulnerabilityRecord(
        cve_id="CVE-2021-44228",
        plugin_name="Log4Shell",
        severity=VulnerabilitySeverity.CRITICAL,
        detection_source=DetectionSource.NESSUS,
        cvss_v3=CvssCalculator().score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    )
    score = VulnerabilityThreatScoringEngine().score(
        record, confidence=1.0, evidence_quality=1.0, asset_criticality=AssetCriticality.CRITICAL
    )
    assert score.composite_score > 85.0


def test_info_vulnerability_scores_low() -> None:
    record = VulnerabilityRecord(
        plugin_name="Informational finding",
        severity=VulnerabilitySeverity.INFO,
        detection_source=DetectionSource.NESSUS,
    )
    score = VulnerabilityThreatScoringEngine().score(
        record, confidence=0.5, evidence_quality=0.5, asset_criticality=AssetCriticality.LOW
    )
    assert score.composite_score < 40.0


def test_score_is_bounded_0_to_100() -> None:
    record = VulnerabilityRecord(
        plugin_name="x",
        severity=VulnerabilitySeverity.CRITICAL,
        detection_source=DetectionSource.NESSUS,
    )
    score = VulnerabilityThreatScoringEngine().score(
        record, confidence=1.0, evidence_quality=1.0, asset_criticality=AssetCriticality.CRITICAL
    )
    assert 0.0 <= score.composite_score <= 100.0


def test_no_cvss_present_contributes_zero_cvss_component() -> None:
    record = VulnerabilityRecord(
        plugin_name="x",
        severity=VulnerabilitySeverity.MEDIUM,
        detection_source=DetectionSource.NESSUS,
    )
    score = VulnerabilityThreatScoringEngine().score(record, confidence=0.8, evidence_quality=0.8)
    assert score.cvss_component == 0.0


def test_v3_preferred_over_v2_when_both_present() -> None:
    v2 = CvssCalculator().score("AV:N/AC:L/Au:N/C:P/I:N/A:N")
    v3 = CvssCalculator().score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    record = VulnerabilityRecord(
        plugin_name="x",
        severity=VulnerabilitySeverity.CRITICAL,
        detection_source=DetectionSource.NESSUS,
        cvss_v2=v2,
        cvss_v3=v3,
    )
    score = VulnerabilityThreatScoringEngine().score(record, confidence=1.0, evidence_quality=1.0)
    assert score.cvss_component == pytest.approx(v3.base_score / 10.0)  # type: ignore[operator]
