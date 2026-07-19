"""Unit tests for core/threat_intel/provider_registry.py — ProviderRegistry."""

from __future__ import annotations

import pytest

from core.threat_intel.models import IOCQuery, ProviderLookupResult
from core.threat_intel.provider_registry import (
    ProviderNotFoundError,
    ProviderRegistry,
    default_provider_registry,
)


class _FakeProvider:
    provider_name = "fake"

    def lookup(self, query: IOCQuery) -> ProviderLookupResult | None:
        return None

    def bulk_lookup(self, queries: list[IOCQuery]) -> list[ProviderLookupResult]:
        return []


@pytest.mark.unit
def test_register_and_get_roundtrip() -> None:
    registry = ProviderRegistry()
    registry.register(_FakeProvider())
    assert registry.get("fake") is not None


@pytest.mark.unit
def test_get_unknown_raises_not_found() -> None:
    registry = ProviderRegistry()
    with pytest.raises(ProviderNotFoundError):
        registry.get("nonexistent")


@pytest.mark.unit
def test_has_reflects_registration_state() -> None:
    registry = ProviderRegistry()
    assert registry.has("fake") is False
    registry.register(_FakeProvider())
    assert registry.has("fake") is True


@pytest.mark.unit
def test_load_plugins_missing_group_is_noop() -> None:
    registry = ProviderRegistry()
    loaded = registry.load_plugins(group="cdc.threat_intel_providers.nonexistent")
    assert loaded == 0


@pytest.mark.unit
def test_default_provider_registry_starts_empty() -> None:
    registry = default_provider_registry()
    assert registry.list_names() == ()
