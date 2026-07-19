"""Case lifecycle transition validation (ADR-0015 point 9) — a pure,
deterministic function guarding every `Case.status` mutation, rather than
inline `if` checks scattered across `CaseRepository`/`case_service`/the API
router (constitution Principle 9: deterministic logic is a plain function,
never left to caller discipline).

The transition table below is the single source of truth for which
`CaseStatus` moves are legal; `core/db/case_repository.py::update_status`
and `core/services/case_service.py::update_case_status` both call
`validate_transition` before writing, so an illegal move can never reach the
database through either entry point.
"""

from __future__ import annotations

from core.db.models.case import CaseStatus
from core.exceptions import BusinessRuleError

#: Legal `CaseStatus` transitions, keyed by the *current* status. A status
#: is never its own target (a "transition" to the same state is not a
#: transition and is rejected the same as any other illegal move) —
#: `ARCHIVED` has no outgoing transitions at all (a true terminal state).
_ALLOWED_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset({CaseStatus.INVESTIGATING, CaseStatus.ESCALATED, CaseStatus.CLOSED}),
    CaseStatus.INVESTIGATING: frozenset(
        {
            CaseStatus.ESCALATED,
            CaseStatus.ON_HOLD,
            CaseStatus.CONTAINED,
            CaseStatus.RESOLVED,
            CaseStatus.CLOSED,
        }
    ),
    CaseStatus.ESCALATED: frozenset(
        {CaseStatus.CONTAINED, CaseStatus.ON_HOLD, CaseStatus.INVESTIGATING, CaseStatus.RESOLVED}
    ),
    CaseStatus.ON_HOLD: frozenset(
        {CaseStatus.INVESTIGATING, CaseStatus.ESCALATED, CaseStatus.CLOSED}
    ),
    CaseStatus.CONTAINED: frozenset(
        {CaseStatus.RESOLVED, CaseStatus.INVESTIGATING, CaseStatus.ESCALATED}
    ),
    CaseStatus.RESOLVED: frozenset({CaseStatus.CLOSED, CaseStatus.INVESTIGATING}),
    CaseStatus.CLOSED: frozenset({CaseStatus.ARCHIVED, CaseStatus.INVESTIGATING}),
    CaseStatus.ARCHIVED: frozenset(),
}


def allowed_next_statuses(current: CaseStatus) -> frozenset[CaseStatus]:
    """The set of statuses `current` may legally transition to."""
    return _ALLOWED_TRANSITIONS[current]


def validate_transition(current: CaseStatus, target: CaseStatus) -> None:
    """Raise :class:`core.exceptions.BusinessRuleError` if moving a case from
    ``current`` to ``target`` is not a legal lifecycle transition.

    Constitution §9: this is exactly the "attempting to close an
    already-closed case"-shaped failure `BusinessRuleError` was already
    documented for — no new exception class is introduced.
    """
    if target not in _ALLOWED_TRANSITIONS[current]:
        raise BusinessRuleError(
            f"Cannot transition case from '{current.value}' to '{target.value}'.",
            details={
                "current_status": current.value,
                "target_status": target.value,
                "allowed_transitions": sorted(s.value for s in _ALLOWED_TRANSITIONS[current]),
            },
        )
