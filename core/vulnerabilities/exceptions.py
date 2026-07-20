"""Narrow exception hierarchy for `core/vulnerabilities` — context/03_engineering_
constitution.md §5 ("every tool module defines its own narrow exception
classes ... callers need to be able to catch precisely"), mirroring
`core/threat_intel/exceptions.py`'s pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ExternalServiceError, ValidationError


class VulnerabilityError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "VULNERABILITY_ERROR"


class InvalidCveIdError(VulnerabilityError):
    """A candidate CVE identifier does not match the official
    `CVE-YYYY-NNNN+` shape (MITRE CVE ID syntax)."""

    code = "INVALID_CVE_ID"


class InvalidCvssVectorError(VulnerabilityError):
    """A candidate CVSS vector string failed
    `core.knowledge.cvss_calculator`'s parser — wrapped here (rather than
    re-raising that module's `CVSSVectorParseError` directly) so callers in
    this package catch one exception family."""

    code = "INVALID_CVSS_VECTOR"


class MalformedVulnerabilityDataError(VulnerabilityError):
    """A candidate vulnerability record is missing structurally-required
    data (no plugin ID/name and no CVE — nothing to identify it by)."""

    code = "MALFORMED_VULNERABILITY_DATA"


class OversizedVulnerabilityDatasetError(VulnerabilityError):
    """The evidence artifact presented to the extraction engine exceeds the
    configured maximum candidate count — the resource-exhaustion guard for
    pathological inputs (constitution §10), mirroring
    `core.threat_intel.exceptions.OversizedEvidenceError`'s reasoning."""

    code = "OVERSIZED_VULNERABILITY_DATASET"


class ProviderUnavailableError(ExternalServiceError):
    """A `VulnerabilityEnrichmentProvider` call failed or timed out. No
    concrete provider exists yet (this framework's explicit scope cut,
    mirroring ADR-0012's identical cut for `core.threat_intel`'s provider
    seam) — this exception is defined now so a future provider
    implementation has a precise, already-reviewed type to raise."""

    code = "VULNERABILITY_PROVIDER_UNAVAILABLE"
