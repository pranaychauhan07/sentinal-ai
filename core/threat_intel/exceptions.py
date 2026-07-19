"""Narrow exception hierarchy for `core/threat_intel` — context/03_engineering_
constitution.md §5 ("every tool module defines its own narrow exception
classes ... callers need to be able to catch precisely"), applied to threat
intelligence, mirroring `core/parsers/exceptions.py`'s pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ExternalServiceError, ValidationError


class ThreatIntelError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "THREAT_INTEL_ERROR"


class UnknownIOCTypeError(ThreatIntelError):
    """A candidate was tagged with an `IOCType` no registered extractor,
    validator, or normalizer knows how to handle."""

    code = "UNKNOWN_IOC_TYPE"


class MalformedIOCError(ThreatIntelError):
    """A candidate IOC's raw value could not be parsed into any known
    structure — distinct from `IOCValidationError`, which is a well-formed
    candidate that fails type-specific validation."""

    code = "MALFORMED_IOC"


class IOCValidationError(ThreatIntelError):
    """A candidate IOC failed its type-specific validation rule (e.g. an
    octet out of range for `ipv4`, an invalid hex length for `sha256`)."""

    code = "IOC_VALIDATION_ERROR"


class UnsafeRegexError(ThreatIntelError):
    """A `REGEX`-type `DetectionRule` was rejected at registration time for
    exhibiting a catastrophic-backtracking-prone shape (nested/overlapping
    quantifiers) — constitution §10's "protect against catastrophic regex"
    requirement, enforced structurally, not by review."""

    code = "UNSAFE_REGEX"


class OversizedEvidenceError(ThreatIntelError):
    """The evidence artifact presented to the extraction engine exceeds
    `Settings.threat_intel_max_regex_input_chars` — the resource-exhaustion
    guard for pathological inputs, mirroring `core.parsers.validation.
    MAX_RECORDS_PER_ARTIFACT`'s reasoning."""

    code = "OVERSIZED_EVIDENCE"


class RuleValidationError(ThreatIntelError):
    """A `DetectionRule` definition is structurally invalid for its
    `rule_type` (e.g. a `THRESHOLD` rule with no `threshold_value`, a
    `COMPOSITE` rule referencing an unregistered `composite_rule_ids`
    entry)."""

    code = "RULE_VALIDATION_ERROR"


class ProviderUnavailableError(ExternalServiceError):
    """A `ThreatIntelProvider`/`IOCEnrichmentProvider` call failed or timed
    out. No concrete provider exists yet (ADR-0012 scope cut); this
    exception is defined now so a future provider implementation has a
    precise, already-reviewed type to raise."""

    code = "THREAT_INTEL_PROVIDER_UNAVAILABLE"


class ProviderRateLimitedError(ExternalServiceError):
    """A `ThreatIntelProvider` reported a rate-limit response. Distinct from
    `ProviderUnavailableError` so a future retry policy can back off
    differently for the two cases."""

    code = "THREAT_INTEL_PROVIDER_RATE_LIMITED"
