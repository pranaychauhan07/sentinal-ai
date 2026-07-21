"""Narrow exception hierarchy for `core/incident_response` — constitution §5
("every tool module defines its own narrow exception classes"), mirroring
`core/owasp_security/exceptions.py`'s pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class IncidentResponseError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "INCIDENT_RESPONSE_ERROR"


class InvalidFindingInputError(IncidentResponseError):
    """A finding/record handed to `response_plan_engine.py` is missing a
    required field or carries a value outside its documented domain (e.g. a
    severity string this package does not recognize) — caught by the engine
    and converted into a skipped-record count, never fatal to the whole
    plan (constitution §1.7)."""

    code = "INVALID_FINDING_INPUT"


class OversizedFindingSetError(IncidentResponseError):
    """The number of findings/records presented to
    `response_plan_engine.ResponsePlanEngine` exceeds the configured
    maximum — the resource-exhaustion guard for a pathologically large case,
    mirroring `core.owasp_security.exceptions.OversizedSourceInputError`'s
    identical reasoning."""

    code = "OVERSIZED_FINDING_SET"
