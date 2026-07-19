"""Structural contracts every threat-intelligence provider / enrichment
source would satisfy — pure `typing.Protocol`, no implementation, no
network I/O (docs/adr/0012 point 4, mirroring `core.knowledge.interfaces`'s
"structural contract, zero implementation" pattern exactly). No concrete
`MISPProvider`/`VirusTotalProvider`/etc. exists in this session's code.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.threat_intel.models import EnrichmentResult, IOCQuery, IOCRecord, ProviderLookupResult


@runtime_checkable
class ThreatIntelProvider(Protocol):
    """Contract for a named external threat-intel feed (MISP, AlienVault
    OTX, VirusTotal, AbuseIPDB, GreyNoise, OpenCTI, ...). `provider_name`
    identifies which feed this instance serves — `ProviderRegistry`
    (`provider_registry.py`) uses it as the registration key."""

    provider_name: str

    def lookup(self, query: IOCQuery) -> ProviderLookupResult | None: ...

    def bulk_lookup(self, queries: list[IOCQuery]) -> list[ProviderLookupResult]: ...


@runtime_checkable
class IOCEnrichmentProvider(Protocol):
    """Contract for a generic enrichment source (reputation score, related
    IOCs, contextual tags) operating on an already-extracted `IOCRecord`,
    distinct from `ThreatIntelProvider`'s named-feed lookup shape — a future
    enrichment step in `core.services.threat_intel_service.
    IOCExtractionPipeline` would call implementations of this Protocol
    advisory-only, the same way `notify_memory` treats `CaseMemory`."""

    provider_name: str

    def enrich(self, ioc: IOCRecord) -> EnrichmentResult | None: ...
