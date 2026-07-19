"""Unit tests for core/services/case_lifecycle.py — exhaustive over every
`(current, target)` pair (constitution §11: deterministic, small-closed-set
logic gets exhaustive, not sampled, coverage).
"""

from __future__ import annotations

import pytest

from core.db.models.case import CaseStatus
from core.exceptions import BusinessRuleError
from core.services.case_lifecycle import allowed_next_statuses, validate_transition

pytestmark = pytest.mark.unit

_LEGAL_PAIRS: set[tuple[CaseStatus, CaseStatus]] = {
    (CaseStatus.OPEN, CaseStatus.INVESTIGATING),
    (CaseStatus.OPEN, CaseStatus.ESCALATED),
    (CaseStatus.OPEN, CaseStatus.CLOSED),
    (CaseStatus.INVESTIGATING, CaseStatus.ESCALATED),
    (CaseStatus.INVESTIGATING, CaseStatus.ON_HOLD),
    (CaseStatus.INVESTIGATING, CaseStatus.CONTAINED),
    (CaseStatus.INVESTIGATING, CaseStatus.RESOLVED),
    (CaseStatus.INVESTIGATING, CaseStatus.CLOSED),
    (CaseStatus.ESCALATED, CaseStatus.CONTAINED),
    (CaseStatus.ESCALATED, CaseStatus.ON_HOLD),
    (CaseStatus.ESCALATED, CaseStatus.INVESTIGATING),
    (CaseStatus.ESCALATED, CaseStatus.RESOLVED),
    (CaseStatus.ON_HOLD, CaseStatus.INVESTIGATING),
    (CaseStatus.ON_HOLD, CaseStatus.ESCALATED),
    (CaseStatus.ON_HOLD, CaseStatus.CLOSED),
    (CaseStatus.CONTAINED, CaseStatus.RESOLVED),
    (CaseStatus.CONTAINED, CaseStatus.INVESTIGATING),
    (CaseStatus.CONTAINED, CaseStatus.ESCALATED),
    (CaseStatus.RESOLVED, CaseStatus.CLOSED),
    (CaseStatus.RESOLVED, CaseStatus.INVESTIGATING),
    (CaseStatus.CLOSED, CaseStatus.ARCHIVED),
    (CaseStatus.CLOSED, CaseStatus.INVESTIGATING),
}

_ALL_PAIRS: set[tuple[CaseStatus, CaseStatus]] = {
    (current, target) for current in CaseStatus for target in CaseStatus
}


@pytest.mark.parametrize("current,target", sorted(_LEGAL_PAIRS, key=lambda p: (p[0], p[1])))
def test_legal_transition_does_not_raise(current: CaseStatus, target: CaseStatus) -> None:
    validate_transition(current, target)  # must not raise


@pytest.mark.parametrize(
    "current,target", sorted(_ALL_PAIRS - _LEGAL_PAIRS, key=lambda p: (p[0], p[1]))
)
def test_illegal_transition_raises_business_rule_error(
    current: CaseStatus, target: CaseStatus
) -> None:
    with pytest.raises(BusinessRuleError) as exc_info:
        validate_transition(current, target)
    assert exc_info.value.details["current_status"] == current.value
    assert exc_info.value.details["target_status"] == target.value


def test_same_status_transition_is_illegal() -> None:
    for status in CaseStatus:
        with pytest.raises(BusinessRuleError):
            validate_transition(status, status)


def test_archived_is_a_true_terminal_state() -> None:
    assert allowed_next_statuses(CaseStatus.ARCHIVED) == frozenset()


def test_every_status_has_an_entry_in_the_transition_table() -> None:
    for status in CaseStatus:
        # Must not raise KeyError for any defined status.
        allowed_next_statuses(status)
