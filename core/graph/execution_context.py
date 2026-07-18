"""Execution Context — binds and scopes run-level identity
(``investigation_run_id``, ``case_id``) for the duration of one full
workflow execution, distinct from `core.agents.contracts.ExecutionMetadata`
(which scopes a single agent invocation).

Built on `core.logging`'s existing contextvars helpers rather than
reinventing binding — this module only adds workflow-run framing around
them, fulfilling constitution §8's "Correlation IDs" requirement ("a stable
investigation_run_id links all log lines from one graph execution").
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from core.logging import bind_case_id, bind_investigation_run_id, clear_context, get_logger

_logger = get_logger(__name__)


class ExecutionContext(BaseModel):
    """Run-scoped identity and timing for one full workflow execution."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    case_id: UUID
    investigation_run_id: UUID
    started_at: datetime
    completed_at: datetime | None = None

    @property
    def duration_ms(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds() * 1000


@contextmanager
def execution_scope(*, case_id: UUID, investigation_run_id: UUID) -> Iterator[ExecutionContext]:
    """Bind logging context for one full workflow run and yield an
    `ExecutionContext` tracking its timing. Always clears the bound context
    on exit, even on failure — a workflow run must never leak its
    case_id/investigation_run_id into whatever runs after it (constitution
    §8's binding discipline, applied at the workflow-run grain)."""
    context = ExecutionContext(
        case_id=case_id,
        investigation_run_id=investigation_run_id,
        started_at=datetime.now(UTC),
    )
    bind_case_id(str(case_id))
    bind_investigation_run_id(str(investigation_run_id))
    _logger.info(
        "workflow_started", case_id=str(case_id), investigation_run_id=str(investigation_run_id)
    )
    try:
        yield context
    finally:
        context.completed_at = datetime.now(UTC)
        _logger.info(
            "workflow_completed",
            case_id=str(case_id),
            investigation_run_id=str(investigation_run_id),
            duration_ms=context.duration_ms,
        )
        clear_context()
