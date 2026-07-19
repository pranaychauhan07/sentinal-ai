"""Unit tests for core/threat_intel/registry.py — ExtractorRegistry."""

from __future__ import annotations

import pytest

from core.threat_intel.base import BaseIOCExtractor
from core.threat_intel.models import IOCRecord, IOCType
from core.threat_intel.registry import (
    ExtractorNotFoundError,
    ExtractorRegistry,
    default_extractor_registry,
)


class _NoopExtractor(BaseIOCExtractor):
    name = "noop"
    description = "test double"
    ioc_types = (IOCType.IPV4,)
    version = "2.0.0"

    def extract_candidates(self, evidence: object) -> list[IOCRecord]:  # type: ignore[override]
        return []


@pytest.mark.unit
def test_register_and_get_roundtrip() -> None:
    registry = ExtractorRegistry()
    registry.register(_NoopExtractor(), aliases=("np",), priority=5)
    assert registry.get("noop") is not None
    assert registry.get("np") is not None


@pytest.mark.unit
def test_get_unknown_raises_not_found() -> None:
    registry = ExtractorRegistry()
    with pytest.raises(ExtractorNotFoundError):
        registry.get("nonexistent")


@pytest.mark.unit
def test_disabled_extractor_not_returned_by_default() -> None:
    registry = ExtractorRegistry()
    registry.register(_NoopExtractor())
    registry.disable("noop")
    with pytest.raises(ExtractorNotFoundError):
        registry.get("noop")
    assert registry.get("noop", include_disabled=True) is not None


@pytest.mark.unit
def test_enable_re_enables_extractor() -> None:
    registry = ExtractorRegistry()
    registry.register(_NoopExtractor())
    registry.disable("noop")
    registry.enable("noop")
    assert registry.get("noop") is not None


@pytest.mark.unit
def test_find_by_ioc_type_sorted_by_priority_desc() -> None:
    registry = ExtractorRegistry()
    registry.register(_NoopExtractor(), priority=1)
    matches = registry.find_by_ioc_type(IOCType.IPV4)
    assert len(matches) == 1
    assert matches[0].priority == 1


@pytest.mark.unit
def test_unregister_removes_extractor_and_aliases() -> None:
    registry = ExtractorRegistry()
    registry.register(_NoopExtractor(), aliases=("np",))
    registry.unregister("noop")
    assert not registry.has("noop")
    assert not registry.has("np")


@pytest.mark.unit
def test_load_plugins_missing_group_is_noop() -> None:
    registry = ExtractorRegistry()
    loaded = registry.load_plugins(group="cdc.threat_intel_extractors.nonexistent_group")
    assert loaded == 0


@pytest.mark.unit
def test_default_extractor_registry_has_builtin_engine() -> None:
    registry = default_extractor_registry()
    assert registry.has("default")
    assert registry.has("regex_engine")
    assert registry.has("ioc_extraction_engine")
