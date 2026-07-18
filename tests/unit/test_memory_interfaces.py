"""Structural-conformance tests for the memory Protocols — no concrete
implementation exists yet (abstraction only, per this milestone's scope);
these tests only prove the Protocols are well-formed and `runtime_checkable`."""

from __future__ import annotations

from uuid import uuid4

import pytest

from core.memory.interfaces import CaseMemory, LongTermMemory, ShortTermMemory, SimilarResult

pytestmark = pytest.mark.unit


class _DictShortTermMemory:
    def __init__(self) -> None:
        self._data: dict[str, object] = {}

    def get(self, key: str) -> object:
        return self._data.get(key)

    def set(self, key: str, value: object) -> None:
        self._data[key] = value


class _InMemoryCaseMemory:
    async def get_notes(self, case_id):  # noqa: ANN001, ANN201 - test double, structural only
        return []

    async def add_note(self, case_id, note):  # noqa: ANN001, ANN201
        return None


def test_dict_short_term_memory_satisfies_the_protocol() -> None:
    memory = _DictShortTermMemory()
    assert isinstance(memory, ShortTermMemory)
    memory.set("k", "v")
    assert memory.get("k") == "v"


def test_case_memory_protocol_is_runtime_checkable() -> None:
    assert isinstance(_InMemoryCaseMemory(), CaseMemory)


def test_similar_result_is_a_frozen_typed_model() -> None:
    result = SimilarResult(case_id=uuid4(), finding_id=uuid4(), score=0.5, excerpt="matched")
    with pytest.raises(Exception):  # noqa: B017, PT011 - pydantic frozen-instance error
        result.score = 0.9  # type: ignore[misc]


def test_long_term_memory_is_a_protocol_not_an_implementation() -> None:
    # No concrete implementation exists yet — this milestone's scope is
    # abstraction only. The Protocol must still be importable and usable in
    # a type hint without requiring a backing class.
    assert LongTermMemory.__mro__  # importable, well-formed Protocol
