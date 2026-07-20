"""Unit tests for core/vulnerabilities/registry.py."""

from __future__ import annotations

import pytest

from core.vulnerabilities.interfaces import EnrichmentResult, VulnerabilityEnrichmentProvider
from core.vulnerabilities.models import VulnerabilityRecord
from core.vulnerabilities.registry import ProviderNotFoundError, VulnerabilityProviderRegistry

pytestmark = pytest.mark.unit


class _FakeProvider:
    provider_name = "fake_provider"

    def enrich(self, record: VulnerabilityRecord) -> EnrichmentResult | None:
        return EnrichmentResult({"ok": True})


def test_register_and_get() -> None:
    registry = VulnerabilityProviderRegistry()
    registry.register(_FakeProvider())
    assert registry.has("fake_provider") is True
    assert registry.get("fake_provider").provider_name == "fake_provider"


def test_get_unknown_provider_raises() -> None:
    with pytest.raises(ProviderNotFoundError):
        VulnerabilityProviderRegistry().get("does_not_exist")


def test_disabled_provider_is_not_returned() -> None:
    registry = VulnerabilityProviderRegistry()
    registry.register(_FakeProvider(), enabled=False)
    with pytest.raises(ProviderNotFoundError):
        registry.get("fake_provider")


def test_list_names_is_empty_by_default() -> None:
    assert VulnerabilityProviderRegistry().list_names() == ()


def test_fake_provider_satisfies_protocol() -> None:
    assert isinstance(_FakeProvider(), VulnerabilityEnrichmentProvider)
