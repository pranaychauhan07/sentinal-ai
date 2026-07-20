"""Unit tests for core/vulnerabilities/confidence_engine.py."""

from __future__ import annotations

import pytest

from core.knowledge.cvss_calculator import CvssCalculator
from core.vulnerabilities.confidence_engine import (
    VulnerabilityConfidenceEngine,
    VulnerabilityConfidenceWeights,
)
from core.vulnerabilities.models import DetectionSource, VulnerabilityRecord

pytestmark = pytest.mark.unit


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError, match="must sum to 1.0"):
        VulnerabilityConfidenceWeights(
            source_reliability=0.5,
            cvss_presence=0.5,
            plugin_metadata_completeness=0.5,
            host_identification=0.5,
        )


def test_default_weights_are_valid() -> None:
    VulnerabilityConfidenceWeights()  # must not raise


def test_complete_record_scores_higher_than_sparse_record() -> None:
    engine = VulnerabilityConfidenceEngine()
    complete = VulnerabilityRecord(
        cve_id="CVE-2021-44228",
        plugin_id="156327",
        plugin_name="Log4Shell",
        description="Apache Log4j RCE",
        references=("https://nvd.nist.gov/vuln/detail/CVE-2021-44228",),
        host="web01",
        ip_address="10.0.0.5",
        detection_source=DetectionSource.NESSUS,
        cvss_v3=CvssCalculator().score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    )
    sparse = VulnerabilityRecord(
        plugin_name="Unknown Plugin", detection_source=DetectionSource.NESSUS
    )
    assert engine.calculate(complete) > engine.calculate(sparse)


def test_confidence_is_bounded() -> None:
    engine = VulnerabilityConfidenceEngine()
    record = VulnerabilityRecord(plugin_name="x", detection_source=DetectionSource.OPENVAS)
    value = engine.calculate(record)
    assert 0.0 <= value <= 1.0
