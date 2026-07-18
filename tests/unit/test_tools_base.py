from __future__ import annotations

import time

import pytest
from pydantic import BaseModel

from core.exceptions import ToolExecutionError
from core.tools.base import (
    BaseTool,
    ToolExecutionStatus,
    ToolPermissionDeniedError,
    ToolTimeoutError,
)

pytestmark = pytest.mark.unit


class _Args(BaseModel):
    value: int


class _Result(BaseModel):
    doubled: int


class _DoubleTool(BaseTool[_Args, _Result]):
    name = "double"
    description = "Doubles a value."

    def run(self, arguments: _Args) -> _Result:
        return _Result(doubled=arguments.value * 2)


class _ApprovalTool(BaseTool[_Args, _Result]):
    name = "approval_required"
    description = "Requires approval."
    requires_approval = True

    def run(self, arguments: _Args) -> _Result:
        return _Result(doubled=arguments.value)


class _FlakyTool(BaseTool[_Args, _Result]):
    name = "flaky"
    description = "Fails once, then succeeds."
    is_io_bound = True
    max_attempts = 2

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def run(self, arguments: _Args) -> _Result:
        self.calls += 1
        if self.calls == 1:
            raise ToolExecutionError("transient")
        return _Result(doubled=arguments.value * 2)


class _SlowTool(BaseTool[_Args, _Result]):
    name = "slow"
    description = "Always exceeds its timeout."
    is_io_bound = True
    timeout_seconds = 0.05

    def run(self, arguments: _Args) -> _Result:
        time.sleep(0.2)
        return _Result(doubled=arguments.value)


def test_run_computes_the_declared_result() -> None:
    tool = _DoubleTool()
    result = tool(_Args(value=3))
    assert result.doubled == 6
    assert tool.last_execution is not None
    assert tool.last_execution.status == ToolExecutionStatus.SUCCEEDED


def test_approval_required_tool_rejects_unapproved_call() -> None:
    tool = _ApprovalTool()
    with pytest.raises(ToolPermissionDeniedError):
        tool(_Args(value=1))


def test_approval_required_tool_runs_once_approved() -> None:
    tool = _ApprovalTool()
    result = tool(_Args(value=5), approved=True)
    assert result.doubled == 5


def test_deterministic_tool_never_retries_on_failure() -> None:
    class _AlwaysFailsTool(BaseTool[_Args, _Result]):
        name = "fails"
        description = "Always fails, not I/O-bound."

        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def run(self, arguments: _Args) -> _Result:
            self.calls += 1
            raise ToolExecutionError("nope")

    tool = _AlwaysFailsTool()
    with pytest.raises(ToolExecutionError):
        tool(_Args(value=1))
    assert tool.calls == 1


def test_io_bound_tool_retries_up_to_max_attempts() -> None:
    tool = _FlakyTool()
    result = tool(_Args(value=4))
    assert result.doubled == 8
    assert tool.calls == 2


def test_io_bound_tool_times_out() -> None:
    with pytest.raises(ToolTimeoutError):
        _SlowTool()(_Args(value=1))


def test_cacheable_tool_returns_cached_result_on_repeat_call() -> None:
    class _CountingTool(BaseTool[_Args, _Result]):
        name = "counting"
        description = "Counts invocations."
        cacheable = True

        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def run(self, arguments: _Args) -> _Result:
            self.calls += 1
            return _Result(doubled=arguments.value * 2)

    tool = _CountingTool()
    tool(_Args(value=2))
    tool(_Args(value=2))
    assert tool.calls == 1
