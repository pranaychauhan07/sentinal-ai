"""Unit tests for core/vulnerabilities/validator.py."""

from __future__ import annotations

import pytest

from core.vulnerabilities.exceptions import MalformedVulnerabilityDataError
from core.vulnerabilities.models import DetectionSource, VulnerabilityRecord
from core.vulnerabilities.validator import VulnerabilityValidator

pytestmark = pytest.mark.unit


def _record(**overrides: object) -> VulnerabilityRecord:
    defaults: dict[str, object] = {
        "plugin_id": "12345",
        "plugin_name": "Test Plugin",
        "detection_source": DetectionSource.NESSUS,
    }
    defaults.update(overrides)
    return VulnerabilityRecord(**defaults)  # type: ignore[arg-type]


def test_valid_record_passes() -> None:
    VulnerabilityValidator().validate(_record(cve_id="CVE-2021-44228"))


def test_record_with_no_identifying_field_fails() -> None:
    with pytest.raises(MalformedVulnerabilityDataError):
        VulnerabilityValidator().validate(_record(plugin_id=None, plugin_name=""))


def test_malformed_cve_id_fails() -> None:
    with pytest.raises(MalformedVulnerabilityDataError):
        VulnerabilityValidator().validate(_record(cve_id="not-a-cve"))


def test_out_of_range_port_fails() -> None:
    with pytest.raises(MalformedVulnerabilityDataError):
        VulnerabilityValidator().validate(_record(port=70000))


def test_zero_port_fails() -> None:
    with pytest.raises(MalformedVulnerabilityDataError):
        VulnerabilityValidator().validate(_record(port=0))


def test_is_valid_returns_false_without_raising() -> None:
    assert VulnerabilityValidator().is_valid(_record(plugin_id=None, plugin_name="")) is False


def test_is_valid_returns_true_for_good_record() -> None:
    assert VulnerabilityValidator().is_valid(_record()) is True
