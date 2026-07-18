from __future__ import annotations

import pytest
from pydantic import BaseModel

from core.exceptions import NotFoundError
from core.tools.base import BaseTool
from core.tools.registry import ToolRegistry, default_tool_registry

pytestmark = pytest.mark.unit


class _Args(BaseModel):
    value: int


class _NoopTool(BaseTool[_Args, _Args]):
    name = "noop"
    description = "Returns its input unchanged."

    def run(self, arguments: _Args) -> _Args:
        return arguments


def test_register_and_get_round_trips() -> None:
    registry = ToolRegistry()
    tool = _NoopTool()
    registry.register(tool)
    assert registry.get("noop") is tool
    assert registry.has("noop")


def test_get_missing_tool_raises_not_found() -> None:
    registry = ToolRegistry()
    with pytest.raises(NotFoundError):
        registry.get("nonexistent")


def test_list_names_is_sorted() -> None:
    registry = ToolRegistry()
    registry.register(_NoopTool())
    assert registry.list_names() == ("noop",)


def test_default_tool_registry_is_a_process_wide_singleton() -> None:
    assert default_tool_registry() is default_tool_registry()
