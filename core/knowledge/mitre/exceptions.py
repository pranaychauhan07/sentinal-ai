"""Narrow exception hierarchy for `core/knowledge/mitre` — constitution §5
("every tool module defines its own narrow exception classes"), mirroring
`core/threat_intel/exceptions.py`'s pattern.
"""

from __future__ import annotations

from core.exceptions import NotFoundError, ValidationError


class MitreKnowledgeError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "MITRE_KNOWLEDGE_ERROR"


class MalformedMitreDataError(MitreKnowledgeError):
    """A vendored STIX bundle is missing a required field (a technique with
    no `external_references`, a relationship with no `source_ref`) or is not
    valid JSON/a STIX bundle at all. Never raised for an object type the
    loader simply doesn't care about (constitution §1.7: unknown-but-benign
    input degrades gracefully; only genuinely malformed *known* objects are
    an error)."""

    code = "MALFORMED_MITRE_DATA"


class UnknownTechniqueError(NotFoundError):
    """A requested `technique_id` (or tactic/software/group/mitigation ID)
    has no matching row in the loaded `MitreDataset`."""

    code = "UNKNOWN_MITRE_OBJECT"


class UnsupportedAttackVersionError(MitreKnowledgeError):
    """The requested `attack_spec_version` has no vendored/imported bundle
    available. Distinct from `UnknownTechniqueError` — the version itself is
    unrecognized, not just one object within a known version."""

    code = "UNSUPPORTED_ATTACK_VERSION"
