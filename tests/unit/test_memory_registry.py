"""Unit tests for core/memory/registry.py."""

from __future__ import annotations

import pytest

from core.exceptions import NotFoundError
from core.memory.registry import MemoryRegistry, default_memory_registry

pytestmark = pytest.mark.unit


def test_register_and_get_round_trips() -> None:
    registry: MemoryRegistry[str] = MemoryRegistry()
    registry.register("primary", "a backend")
    assert registry.get("primary") == "a backend"


def test_get_missing_backend_raises_not_found_error() -> None:
    registry: MemoryRegistry[str] = MemoryRegistry()
    with pytest.raises(NotFoundError):
        registry.get("missing")


def test_has_reflects_registration_state() -> None:
    registry: MemoryRegistry[int] = MemoryRegistry()
    assert registry.has("x") is False
    registry.register("x", 1)
    assert registry.has("x") is True


def test_list_names_is_sorted() -> None:
    registry: MemoryRegistry[int] = MemoryRegistry()
    registry.register("b", 2)
    registry.register("a", 1)
    assert registry.list_names() == ("a", "b")


def test_unregister_removes_backend() -> None:
    registry: MemoryRegistry[int] = MemoryRegistry()
    registry.register("x", 1)
    registry.unregister("x")
    assert registry.has("x") is False


def test_default_memory_registry_is_a_singleton() -> None:
    assert default_memory_registry() is default_memory_registry()
