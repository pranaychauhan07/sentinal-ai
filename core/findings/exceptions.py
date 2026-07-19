"""Narrow exception hierarchy for `core/findings` — constitution §5, mirroring
`core/threat_intel/exceptions.py`'s pattern.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class FindingsError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "FINDINGS_ERROR"


class NoTechniqueMatchError(FindingsError):
    """Raised only in contexts that require a mapping to exist (most
    callers instead treat "no match" as a normal, non-error outcome —
    `MitreMappingEngine.map_ioc` returns an empty tuple, per blueprint §7's
    "returns unmapped rather than forcing a low-confidence guess")."""

    code = "NO_TECHNIQUE_MATCH"


class InvalidMappingRuleError(FindingsError):
    """A `MappingRule` definition is structurally invalid (e.g. references
    an `IOCType` with no discriminating field, or a `technique_id` absent
    from every loaded `MitreDataset`)."""

    code = "INVALID_MAPPING_RULE"


class DuplicateExplosionGuardError(FindingsError):
    """The candidate Finding set for one case exceeds
    `Settings.finding_max_candidates_per_case` — the resource-exhaustion
    guard preventing O(n^2) deduplication blow-up, mirroring
    `core.threat_intel.exceptions.OversizedEvidenceError`'s reasoning."""

    code = "DUPLICATE_EXPLOSION_GUARD"
