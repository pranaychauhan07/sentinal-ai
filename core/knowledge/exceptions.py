"""Narrow exception for the simple, vendored-YAML `KnowledgeSource`
implementations added by ADR-0027 (`core/knowledge/owasp/`,
`core/knowledge/playbooks/`, `core/knowledge/detection/`).

`core/knowledge/mitre/exceptions.py` stays its own, separate hierarchy — its
STIX-parsing surface is complex enough to warrant one; these three simpler,
structurally-identical YAML loaders share this single narrow type rather
than each defining a near-duplicate exception class (constitution §1.3,
"small, focused modules" cuts both ways — three files differing only in
their docstring is not meaningfully more focused than one shared type).
"""

from __future__ import annotations

from core.exceptions import ValidationError


class KnowledgeDataError(ValidationError):
    """A vendored knowledge data file is missing or fails schema validation
    — a configuration/deployment error, not a runtime user input error."""

    code = "KNOWLEDGE_DATA_ERROR"
