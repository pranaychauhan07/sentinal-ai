"""Unit tests for core/conversation/session_manager.py."""

from __future__ import annotations

import uuid

import pytest

from core.conversation.session_manager import SessionManager


@pytest.mark.unit
def test_start_session_creates_a_new_session_for_the_case() -> None:
    manager = SessionManager()
    session = manager.start_session("case-1")
    assert session.case_id == "case-1"
    assert session.turn_count == 0


@pytest.mark.unit
def test_get_or_start_returns_existing_session_when_id_known() -> None:
    manager = SessionManager()
    session = manager.start_session("case-1")
    found = manager.get_or_start(session_id=session.session_id, case_id="case-1")
    assert found.session_id == session.session_id


@pytest.mark.unit
def test_get_or_start_starts_new_session_when_id_unknown() -> None:
    manager = SessionManager()
    found = manager.get_or_start(session_id=uuid.uuid4(), case_id="case-1")
    assert found.turn_count == 0


@pytest.mark.unit
def test_record_turn_increments_turn_count() -> None:
    manager = SessionManager()
    session = manager.start_session("case-1")
    touched = manager.record_turn(session.session_id)
    assert touched is not None
    assert touched.turn_count == 1
    assert manager.get_session(session.session_id) == touched


@pytest.mark.unit
def test_record_turn_returns_none_for_unknown_session() -> None:
    manager = SessionManager()
    assert manager.record_turn(uuid.uuid4()) is None


@pytest.mark.unit
def test_end_session_removes_it() -> None:
    manager = SessionManager()
    session = manager.start_session("case-1")
    manager.end_session(session.session_id)
    assert manager.get_session(session.session_id) is None
