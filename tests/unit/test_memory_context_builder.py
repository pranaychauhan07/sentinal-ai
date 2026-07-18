"""Unit tests for core/memory/context_builder.py."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.memory.context_builder import ContextBuilder
from core.memory.models import MemoryPriority, MemoryRecord, MemoryScope

pytestmark = pytest.mark.unit


def _record(
    content: str, *, priority: MemoryPriority = MemoryPriority.NORMAL, **kwargs
) -> MemoryRecord:
    return MemoryRecord(
        scope=MemoryScope.CASE, key=content, content=content, priority=priority, **kwargs
    )


def test_filter_active_excludes_expired_records() -> None:
    builder = ContextBuilder()
    expired = _record("stale", expires_at=datetime.now(UTC) - timedelta(seconds=1))
    active = _record("fresh")
    result = builder.filter_active([expired, active])
    assert result == [active]


def test_deduplicate_removes_exact_content_repeats() -> None:
    builder = ContextBuilder()
    first = _record("same content")
    duplicate = _record("same content")
    result = builder.deduplicate([first, duplicate])
    assert len(result) == 1


def test_rank_orders_high_priority_before_normal() -> None:
    builder = ContextBuilder()
    normal = _record("normal", priority=MemoryPriority.NORMAL)
    high = _record("high", priority=MemoryPriority.HIGH)
    ranked = builder.rank([normal, high])
    assert ranked[0].content == "high"


def test_rank_orders_most_recent_first_within_same_priority() -> None:
    builder = ContextBuilder()
    older = _record("older", created_at=datetime.now(UTC) - timedelta(hours=1))
    newer = _record("newer")
    ranked = builder.rank([older, newer])
    assert ranked[0].content == "newer"


def test_truncate_to_budget_drops_records_beyond_char_limit() -> None:
    builder = ContextBuilder(max_chars=10)
    fits = _record("short")
    overflow = _record("this is way too long to fit")
    selected, truncated = builder.truncate_to_budget([fits, overflow])
    assert selected == [fits]
    assert truncated is True


def test_assemble_runs_the_full_pipeline() -> None:
    builder = ContextBuilder(max_chars=1000)
    expired = _record("expired", expires_at=datetime.now(UTC) - timedelta(seconds=1))
    duplicate_a = _record("dup")
    duplicate_b = _record("dup")
    high = _record("important", priority=MemoryPriority.HIGH)

    context = builder.assemble([expired, duplicate_a, duplicate_b, high])

    assert context.total_candidates == 4
    assert context.truncated is False
    contents = [r.content for r in context.records]
    assert contents == ["important", "dup"]
