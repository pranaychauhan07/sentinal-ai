"""Unit tests for core/vulnerabilities/normalizer.py."""

from __future__ import annotations

import pytest

from core.vulnerabilities.models import DetectionSource, VulnerabilityRecord
from core.vulnerabilities.normalizer import VulnerabilityNormalizer, derive_asset_id

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("host", "ip_address", "expected"),
    [
        ("Web01.Example.com", "10.0.0.5", "10.0.0.5"),
        ("Web01.Example.com", None, "web01.example.com"),
        (None, None, None),
    ],
)
def test_derive_asset_id(host: str | None, ip_address: str | None, expected: str | None) -> None:
    assert derive_asset_id(host=host, ip_address=ip_address) == expected


def test_normalize_canonicalizes_cve_and_host_and_derives_asset_id() -> None:
    record = VulnerabilityRecord(
        cve_id="cve-2021-44228",
        plugin_name="Log4Shell",
        host="  Web01.Example.com  ",
        ip_address=" 10.0.0.5 ",
        service="HTTPS",
        protocol="TCP",
        detection_source=DetectionSource.NESSUS,
    )
    normalized = VulnerabilityNormalizer().normalize(record)
    assert normalized.cve_id == "CVE-2021-44228"
    assert normalized.host == "web01.example.com"
    assert normalized.ip_address == "10.0.0.5"
    assert normalized.service == "https"
    assert normalized.protocol == "tcp"
    assert normalized.asset_id == "10.0.0.5"


def test_normalize_preserves_existing_asset_id() -> None:
    record = VulnerabilityRecord(
        plugin_name="x",
        host="host1",
        asset_id="custom-asset-key",
        detection_source=DetectionSource.OPENVAS,
    )
    normalized = VulnerabilityNormalizer().normalize(record)
    assert normalized.asset_id == "custom-asset-key"


def test_normalize_is_a_noop_for_already_canonical_record() -> None:
    record = VulnerabilityRecord(
        cve_id="CVE-2021-44228",
        plugin_name="x",
        detection_source=DetectionSource.NESSUS,
    )
    normalized = VulnerabilityNormalizer().normalize(record)
    assert normalized is record


def test_normalize_deduplicates_cwe_ids_case() -> None:
    record = VulnerabilityRecord(
        plugin_name="x",
        cwe_ids=("cwe-502", "CWE-502"),
        detection_source=DetectionSource.NESSUS,
    )
    normalized = VulnerabilityNormalizer().normalize(record)
    assert normalized.cwe_ids == ("CWE-502",)
