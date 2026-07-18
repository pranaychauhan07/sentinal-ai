"""``BaseTool`` — the concrete base every deterministic function-calling tool
in `core/tools/*.py` implements (context/03_engineering_constitution.md §5).

Framework-only: no concrete tool (CVSS interpreter, log pattern detector,
...) is implemented here. This module gives every future tool, for free:
argument validation, timeout enforcement, bounded retry on genuinely
transient failures (never on deterministic no-I/O tools, per constitution
§5/§4.8), structured logging, execution metadata, and an opt-in in-process
cache for expensive idempotent lookups.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, ConfigDict

from core.exceptions import ToolExecutionError
from core.logging import get_logger

InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)

_logger = get_logger(__name__)


class ToolExecutionStatus(StrEnum):
    """Outcome of one tool invocation. Deliberately separate from
    `core.agents.contracts.ExecutionStatus` — `core/tools` is a leaf layer
    that must never import `core/agents` (docs/dependency-rules.md rule 5),
    so this tiny enum is defined locally rather than shared."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    PERMISSION_DENIED = "permission_denied"


class ToolExecutionMetadata(BaseModel):
    """Timing/outcome record for one tool call — the tool-layer equivalent of
    an agent's `ExecutionMetadata`, kept independent per the layering note
    above."""

    model_config = ConfigDict(frozen=True)

    tool_name: str
    status: ToolExecutionStatus
    started_at: datetime
    completed_at: datetime
    from_cache: bool = False

    @property
    def duration_ms(self) -> float:
        return (self.completed_at - self.started_at).total_seconds() * 1000


class ToolPermissionDeniedError(ToolExecutionError):
    """Raised when a tool requiring approval is invoked without it having
    been granted — the tool-layer counterpart to
    `core.exceptions.ApprovalRequiredError`, scoped to tool calls rather than
    agent-recommended actions (constitution §4.11)."""

    code = "TOOL_PERMISSION_DENIED"
    http_status = 403


class ToolTimeoutError(ToolExecutionError):
    """A tool exceeded its configured timeout
    (context/03_engineering_constitution.md §5, "Timeouts")."""

    code = "TOOL_TIMEOUT"
    http_status = 504


class BaseTool(ABC, Generic[InputT, OutputT]):
    """Template-method base for every deterministic tool.

    Concrete subclasses implement :meth:`run` (the actual computation) and
    declare their identity via class attributes. `__call__` is the one
    public entry point (matches `core.interfaces.Tool`) and owns validation,
    timeout, permission checks, caching, retry-on-transient-I/O-failure, and
    logging so no individual tool has to reimplement any of it.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    #: True only for tools that perform genuine I/O and may legitimately
    #: fail transiently (a future threat-intel lookup). Deterministic,
    #: no-I/O tools must leave this False — constitution §5/§4.8: retrying a
    #: pure function twice hides a real bug rather than recovering from one.
    is_io_bound: ClassVar[bool] = False
    #: Tools that recommend/perform an action (not just compute a value) must
    #: set this True; callers are then required to have passed
    #: `core.security.approval_gate` before invoking (constitution §4.11).
    requires_approval: ClassVar[bool] = False
    #: Seconds before an I/O-bound tool call is aborted. Ignored for
    #: deterministic tools (constitution §5, "Timeouts").
    timeout_seconds: ClassVar[float] = 10.0
    #: Max attempts for transient I/O failures. 1 = no retry (the default,
    #: and the only legal value for a non-I/O-bound tool).
    max_attempts: ClassVar[int] = 1
    #: Whether results are cacheable (only for expensive, idempotent
    #: lookups — constitution §5, "Caching").
    cacheable: ClassVar[bool] = False

    def __init__(self) -> None:
        self._cache: dict[Any, OutputT] = {}
        self.last_execution: ToolExecutionMetadata | None = None

    def __call__(self, arguments: InputT, *, approved: bool = False) -> OutputT:
        if self.requires_approval and not approved:
            raise ToolPermissionDeniedError(
                f"Tool '{self.name}' requires approval before execution.",
                details={"tool": self.name},
            )

        cache_key = arguments.model_dump_json() if self.cacheable else None
        if cache_key is not None and cache_key in self._cache:
            _logger.debug("tool_cache_hit", tool=self.name)
            return self._cache[cache_key]

        started_at = datetime.now(UTC)
        status = ToolExecutionStatus.FAILED
        attempts_used = 0
        last_error: Exception | None = None
        result: OutputT | None = None

        attempts_allowed = self.max_attempts if self.is_io_bound else 1
        for attempt in range(1, attempts_allowed + 1):
            attempts_used = attempt
            try:
                result = self._run_with_timeout(arguments)
                status = ToolExecutionStatus.SUCCEEDED
                last_error = None
                break
            except ToolTimeoutError as exc:
                status = ToolExecutionStatus.TIMED_OUT
                last_error = exc
            except Exception as exc:  # noqa: BLE001 - converted below, never swallowed
                last_error = exc
            if attempt < attempts_allowed:
                _logger.warning(
                    "tool_retry", tool=self.name, attempt=attempt, error=str(last_error)
                )

        completed_at = datetime.now(UTC)
        self.last_execution = ToolExecutionMetadata(
            tool_name=self.name,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
        )

        if last_error is not None or result is None:
            _logger.error(
                "tool_failed",
                tool=self.name,
                attempts=attempts_used,
                error=str(last_error),
            )
            if isinstance(last_error, ToolExecutionError):
                raise last_error
            raise ToolExecutionError(
                f"Tool '{self.name}' failed after {attempts_used} attempt(s): {last_error}",
                details={"tool": self.name, "attempts": attempts_used},
            ) from last_error

        _logger.debug(
            "tool_executed",
            tool=self.name,
            duration_ms=self.last_execution.duration_ms,
        )
        if cache_key is not None:
            self._cache[cache_key] = result
        return result

    def _run_with_timeout(self, arguments: InputT) -> OutputT:
        if not self.is_io_bound:
            return self.run(arguments)

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.run, arguments)
            try:
                return future.result(timeout=self.timeout_seconds)
            except FutureTimeoutError as exc:
                raise ToolTimeoutError(
                    f"Tool '{self.name}' exceeded its {self.timeout_seconds}s timeout.",
                    details={"tool": self.name, "timeout_seconds": self.timeout_seconds},
                ) from exc

    @abstractmethod
    def run(self, arguments: InputT) -> OutputT:
        """The tool's actual, deterministic (or documented-as-non-deterministic
        per constitution §5) computation. Subclasses implement only this —
        never override `__call__`."""
        raise NotImplementedError
