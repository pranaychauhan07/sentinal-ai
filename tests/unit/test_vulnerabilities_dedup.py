"""Unit tests for core/vulnerabilities/dedup.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.vulnerabilities.dedup import DedupStrategy, VulnerabilityDeduplicationEngine
from core.vulnerabilities.models import DetectionSource, VulnerabilityRecord

pytestmark = pytest.mark.unit


def _record(**overrides: object) -> VulnerabilityRecord:
    defaults: dict[str, object] = {
        "cve_id": "CVE-2021-44228",
        "plugin_id": "156327",
        "plugin_name": "Log4Shell",
        "asset_id": "10.0.0.5",
        "service": "https",
        "port": 443,
        "detection_source": DetectionSource.NESSUS,
        "confidence": 0.8,
    }
    defaults.update(overrides)
    return VulnerabilityRecord(**defaults)  # type: ignore[arg-type]


def test_default_strategy_merges_same_asset_and_cve() -> None:
    a = _record(confidence=0.6)
    b = _record(confidence=0.9)
    result = VulnerabilityDeduplicationEngine().deduplicate([a, b])
    assert len(result) == 1
    merged, count = result[0]
    assert count == 2
    assert merged.confidence == 0.9  # highest observed confidence kept


def test_different_asset_is_not_merged() -> None:
    a = _record(asset_id="10.0.0.5")
    b = _record(asset_id="10.0.0.6")
    result = VulnerabilityDeduplicationEngine().deduplicate([a, b])
    assert len(result) == 2


def test_earliest_first_seen_is_kept() -> None:
    earlier = datetime.now(UTC) - timedelta(days=1)
    a = _record(first_seen=datetime.now(UTC))
    b = _record(first_seen=earlier)
    merged, _count = VulnerabilityDeduplicationEngine().deduplicate([a, b])[0]
    assert merged.first_seen == earlier


def test_asset_and_plugin_strategy() -> None:
    a = _record(cve_id=None, plugin_id="999")
    b = _record(cve_id=None, plugin_id="999")
    result = VulnerabilityDeduplicationEngine(strategy=DedupStrategy.ASSET_AND_PLUGIN).deduplicate(
        [a, b]
    )
    assert len(result) == 1


def test_same_service_strategy_separates_different_services() -> None:
    a = _record(service="https")
    b = _record(service="http")
    result = VulnerabilityDeduplicationEngine(strategy=DedupStrategy.SAME_SERVICE).deduplicate(
        [a, b]
    )
    assert len(result) == 2


def test_same_port_strategy_separates_different_ports() -> None:
    a = _record(port=443)
    b = _record(port=8443)
    result = VulnerabilityDeduplicationEngine(strategy=DedupStrategy.SAME_PORT).deduplicate([a, b])
    assert len(result) == 2


def test_custom_strategy_requires_key_fn() -> None:
    with pytest.raises(ValueError, match="CUSTOM"):
        VulnerabilityDeduplicationEngine(strategy=DedupStrategy.CUSTOM)


def test_custom_strategy_uses_provided_key_fn() -> None:
    engine = VulnerabilityDeduplicationEngine(
        strategy=DedupStrategy.CUSTOM, key_fn=lambda r: (r.detection_source,)
    )
    a = _record(cve_id="CVE-2021-1")
    b = _record(cve_id="CVE-2021-2")
    result = engine.deduplicate([a, b])
    assert len(result) == 1  # merged because both share the same detection_source


def test_merge_preserves_references_and_tags_without_duplicates() -> None:
    a = _record(references=("https://a.example",), tags=("t1",))
    b = _record(references=("https://a.example", "https://b.example"), tags=("t1", "t2"))
    merged, _count = VulnerabilityDeduplicationEngine().deduplicate([a, b])[0]
    assert merged.references == ("https://a.example", "https://b.example")
    assert merged.tags == ("t1", "t2")


def test_empty_input_returns_empty() -> None:
    assert VulnerabilityDeduplicationEngine().deduplicate([]) == []
