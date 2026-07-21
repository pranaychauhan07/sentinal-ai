"""Unit tests for core/conversation/audit.py."""

from __future__ import annotations

import pytest

from core.conversation.audit import log_conversation_audit_event, timed_execution
from core.conversation.models import AuditEventAction


@pytest.mark.unit
def test_log_conversation_audit_event_returns_typed_event() -> None:
    event = log_conversation_audit_event(
        action=AuditEventAction.QUESTION_RECEIVED,
        case_id="c1",
        session_id="s1",
        detail="why was this high?",
        metadata={"foo": "bar"},
    )
    assert event.action is AuditEventAction.QUESTION_RECEIVED
    assert event.case_id == "c1"
    assert event.session_id == "s1"
    assert event.metadata == {"foo": "bar"}


@pytest.mark.unit
def test_timed_execution_populates_duration_ms() -> None:
    with timed_execution("test_op") as timing:
        pass
    assert timing["duration_ms"] >= 0.0
