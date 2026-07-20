"""Structural contract every vulnerability-enrichment provider would
satisfy — pure `typing.Protocol`, no implementation, no network I/O
(mirroring `core.threat_intel.interfaces`'s "structural contract, zero
implementation" pattern exactly). No concrete `NvdEnrichmentProvider`/
`VulnDbProvider`/etc. exists in this framework — this is the seam a future
CVE-lookup enrichment (e.g. NVD API) plugs into, out of scope here per this
framework's explicit "no live network calls" boundary
(`context/01_blueprint.md` §3).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.vulnerabilities.models import VulnerabilityRecord


class EnrichmentResult(dict[str, object]):
    """Opaque enrichment payload — deliberately unstructured (`dict`-based)
    since no concrete provider exists yet to define a real shape; a future
    provider implementation refines this into a typed model without
    changing the `Protocol` below."""


@runtime_checkable
class VulnerabilityEnrichmentProvider(Protocol):
    """Contract for an external CVE/vulnerability-intelligence source
    (e.g. the NVD API, a vendor advisory feed) operating on an
    already-extracted `VulnerabilityRecord`. `provider_name` identifies
    which source this instance serves — `VulnerabilityProviderRegistry`
    uses it as the registration key."""

    provider_name: str

    def enrich(self, record: VulnerabilityRecord) -> EnrichmentResult | None: ...
