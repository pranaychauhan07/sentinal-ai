"""Unit tests for core/threat_intel/interfaces.py — Protocol conformance.

No concrete provider exists (docs/adr/0012 point 4); these tests only
verify the Protocols are structurally usable by a minimal conforming
implementation, guarding against an accidental signature change.
"""

from __future__ import annotations

import pytest

from core.threat_intel.interfaces import IOCEnrichmentProvider, ThreatIntelProvider
from core.threat_intel.models import (
    EnrichmentResult,
    IOCQuery,
    IOCRecord,
    IOCType,
    ProviderLookupResult,
)


class _FakeThreatIntelProvider:
    provider_name = "fake"

    def lookup(self, query: IOCQuery) -> ProviderLookupResult | None:
        return None

    def bulk_lookup(self, queries: list[IOCQuery]) -> list[ProviderLookupResult]:
        return []


class _FakeEnrichmentProvider:
    provider_name = "fake_enrichment"

    def enrich(self, ioc: IOCRecord) -> EnrichmentResult | None:
        return None


@pytest.mark.unit
def test_conforming_class_satisfies_threat_intel_provider_protocol() -> None:
    assert isinstance(_FakeThreatIntelProvider(), ThreatIntelProvider)


@pytest.mark.unit
def test_conforming_class_satisfies_enrichment_provider_protocol() -> None:
    assert isinstance(_FakeEnrichmentProvider(), IOCEnrichmentProvider)


@pytest.mark.unit
def test_non_conforming_class_does_not_satisfy_protocol() -> None:
    class _NotAProvider:
        pass

    assert not isinstance(_NotAProvider(), ThreatIntelProvider)


@pytest.mark.unit
def test_ioc_query_roundtrip() -> None:
    query = IOCQuery(ioc_type=IOCType.IPV4, value="1.2.3.4")
    provider = _FakeThreatIntelProvider()
    assert provider.lookup(query) is None
