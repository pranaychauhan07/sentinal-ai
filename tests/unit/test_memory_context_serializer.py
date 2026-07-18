"""Unit tests for core/memory/context_serializer.py."""

from __future__ import annotations

import pytest

from core.memory.context_builder import ContextBuilder
from core.memory.context_serializer import ContextSerializer
from core.memory.models import MemoryRecord, MemoryScope

pytestmark = pytest.mark.unit


def test_to_prompt_text_is_empty_for_no_records() -> None:
    serializer = ContextSerializer()
    context = ContextBuilder().assemble([])
    assert serializer.to_prompt_text(context) == ""


def test_to_prompt_text_renders_scope_and_content() -> None:
    serializer = ContextSerializer()
    record = MemoryRecord(scope=MemoryScope.CASE, key="k", content="brute force detected")
    context = ContextBuilder().assemble([record])
    text = serializer.to_prompt_text(context)
    assert text == "[case] brute force detected"


def test_to_prompt_text_preserves_ranked_order() -> None:
    serializer = ContextSerializer()
    first = MemoryRecord(scope=MemoryScope.CASE, key="a", content="first")
    second = MemoryRecord(scope=MemoryScope.CASE, key="b", content="second")
    context = ContextBuilder().assemble([first, second])
    lines = serializer.to_prompt_text(context).splitlines()
    assert len(lines) == 2


def test_to_dict_is_json_serializable_shape() -> None:
    serializer = ContextSerializer()
    record = MemoryRecord(scope=MemoryScope.CASE, key="k", content="note")
    context = ContextBuilder().assemble([record])
    payload = serializer.to_dict(context)

    assert payload["record_count"] == 1
    assert payload["truncated"] is False
    assert payload["total_candidates"] == 1
    assert payload["records"][0]["content"] == "note"
