"""Narrow exception hierarchy for `core/linux_security` — context/03_engineering_
constitution.md §5 ("every tool module defines its own narrow exception
classes ... callers need to be able to catch precisely"), mirroring
`core/vulnerabilities/exceptions.py`'s pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ExternalServiceError, ValidationError


class LinuxSecurityError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "LINUX_SECURITY_ERROR"


class MalformedLinuxSecurityDataError(LinuxSecurityError):
    """A candidate log record is structurally unusable (no parseable
    timestamp and no identifying subject) — degrades that one record rather
    than aborting the whole artifact (constitution §1.7)."""

    code = "MALFORMED_LINUX_SECURITY_DATA"


class OversizedLinuxSecurityDatasetError(LinuxSecurityError):
    """The evidence artifact presented to the analysis engine exceeds the
    configured maximum record count — the resource-exhaustion guard for
    pathological inputs (constitution §10), mirroring
    `core.vulnerabilities.exceptions.OversizedVulnerabilityDatasetError`'s
    reasoning."""

    code = "OVERSIZED_LINUX_SECURITY_DATASET"


class ProviderUnavailableError(ExternalServiceError):
    """A `LinuxSecurityEnrichmentProvider` call failed or timed out. No
    concrete provider exists yet (this framework's explicit scope cut,
    mirroring ADR-0012/0017's identical cuts for their own provider seams) —
    this exception is defined now so a future provider implementation has a
    precise, already-reviewed type to raise."""

    code = "LINUX_SECURITY_PROVIDER_UNAVAILABLE"
