"""Unit tests for core/memory/models.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.memory.models import (
    ConversationRole,
    ConversationTurn,
    MemoryPriority,
    MemoryQuery,
    MemoryRecord,
    MemoryScope,
)

pytestmark = pytest.mark.unit


def test_memory_record_defaults_to_normal_priority_and_never_expired() -> None:
    record = MemoryRecord(scope=MemoryScope.CASE, key="k", content="hello")
    assert record.priority == MemoryPriority.NORMAL
    assert record.priority_weight == 1
    assert record.is_expired() is False


def test_memory_record_is_expired_when_past_expiry() -> None:
    past = datetime.now(UTC) - timedelta(seconds=1)
    record = MemoryRecord(scope=MemoryScope.SESSION, key="k", content="x", expires_at=past)
    assert record.is_expired() is True


def test_memory_record_not_expired_before_expiry() -> None:
    future = datetime.now(UTC) + timedelta(hours=1)
    record = MemoryRecord(scope=MemoryScope.SESSION, key="k", content="x", expires_at=future)
    assert record.is_expired() is False


def test_memory_record_is_frozen() -> None:
    record = MemoryRecord(scope=MemoryScope.CASE, key="k", content="x")
    with pytest.raises(Exception):  # noqa: B017, PT011 - pydantic frozen-instance error
        record.content = "y"  # type: ignore[misc]


def test_memory_query_defaults() -> None:
    query = MemoryQuery()
    assert query.limit == 10
    assert query.scope is None


def test_conversation_turn_roles() -> None:
    turn = ConversationTurn(role=ConversationRole.USER, content="hi")
    assert turn.role == ConversationRole.USER
    assert turn.content == "hi"
