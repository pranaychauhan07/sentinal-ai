"""Narrow exception hierarchy for `core/reporting` — constitution §5 ("every
tool module defines its own narrow exception classes"), mirroring
`core/incident_response/exceptions.py`'s pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class ReportGenerationError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "REPORT_GENERATION_ERROR"


class UnknownReportTypeError(ReportGenerationError):
    """A `ReportType` was requested that `section_registry.py` has no
    section mapping for — should be unreachable for any real `ReportType`
    member (the registry is exhaustive over the enum, enforced by a unit
    test), but guarded explicitly rather than raising a bare `KeyError`."""

    code = "UNKNOWN_REPORT_TYPE"


class OversizedReportInputError(ReportGenerationError):
    """The combined size of the context handed to
    `report_engine.ReportGenerationEngine` (findings + evidence + vulnerability/
    linux/owasp records) exceeds the configured maximum — the resource-
    exhaustion guard for a pathologically large case, mirroring
    `core.incident_response.exceptions.OversizedFindingSetError`'s identical
    reasoning."""

    code = "OVERSIZED_REPORT_INPUT"
