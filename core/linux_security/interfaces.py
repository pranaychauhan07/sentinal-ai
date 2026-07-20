"""Structural contract a future Linux-security enrichment provider would
satisfy — pure `typing.Protocol`, no implementation, no network I/O
(mirroring `core.vulnerabilities.interfaces`'s "structural contract, zero
implementation" pattern exactly). No concrete provider exists in this
framework — this is the seam a future live threat-intel enrichment of
detected IPs (e.g. a reputation lookup for a brute-force source) plugs into,
out of scope here per this framework's "no live network calls" boundary
(`context/01_blueprint.md` §3).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.linux_security.models import LinuxSecurityCandidate


class EnrichmentResult(dict[str, object]):
    """Opaque enrichment payload — deliberately unstructured (`dict`-based)
    since no concrete provider exists yet to define a real shape."""


@runtime_checkable
class LinuxSecurityEnrichmentProvider(Protocol):
    """Contract for an external enrichment source (e.g. an IP-reputation
    feed) operating on an already-detected `LinuxSecurityCandidate`.
    `provider_name` identifies which source this instance serves —
    `LinuxSecurityProviderRegistry` uses it as the registration key."""

    provider_name: str

    def enrich(self, candidate: LinuxSecurityCandidate) -> EnrichmentResult | None: ...
