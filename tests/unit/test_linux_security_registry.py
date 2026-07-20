"""Unit tests for core/linux_security/registry.py."""

from __future__ import annotations

import pytest

from core.linux_security.interfaces import EnrichmentResult, LinuxSecurityEnrichmentProvider
from core.linux_security.models import (
    LinuxSecurityCandidate,
)
from core.linux_security.registry import LinuxSecurityProviderRegistry, ProviderNotFoundError

pytestmark = pytest.mark.unit


class _FakeProvider:
    provider_name = "fake_provider"

    def enrich(self, candidate: LinuxSecurityCandidate) -> EnrichmentResult | None:
        return EnrichmentResult({"ok": True})


def test_register_and_get() -> None:
    registry = LinuxSecurityProviderRegistry()
    registry.register(_FakeProvider())
    assert registry.has("fake_provider") is True
    assert registry.get("fake_provider").provider_name == "fake_provider"


def test_get_unknown_provider_raises() -> None:
    with pytest.raises(ProviderNotFoundError):
        LinuxSecurityProviderRegistry().get("does_not_exist")


def test_disabled_provider_is_not_returned() -> None:
    registry = LinuxSecurityProviderRegistry()
    registry.register(_FakeProvider(), enabled=False)
    with pytest.raises(ProviderNotFoundError):
        registry.get("fake_provider")


def test_list_names_is_empty_by_default() -> None:
    assert LinuxSecurityProviderRegistry().list_names() == ()


def test_fake_provider_satisfies_protocol() -> None:
    assert isinstance(_FakeProvider(), LinuxSecurityEnrichmentProvider)
