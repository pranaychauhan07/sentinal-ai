"""Retry Strategy — the workflow engine's bounded-retry policy for node
invocations, matching constitution §4.8's split: LLM-backed work may retry
transient failures with backoff; deterministic work is never retried
(retrying a pure function twice hides a real bug rather than recovering
from one). This is the *workflow-layer* retry (blueprint §4: "WORKFLOW
LAYER ... Owns control flow, retries, checkpointing") — distinct from and
in addition to `core/tools/base.py`'s own per-tool retry, and distinct from
the future per-LLM-call retry the shared LLM client wrapper will own.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field

from core.exceptions import ExternalServiceError
from core.logging import get_logger

_logger = get_logger(__name__)
_T = TypeVar("_T")


class RetryPolicy(BaseModel):
    """Immutable retry configuration. The default (`max_attempts=1`) means
    "no retry" — the correct default for deterministic work; agents backed
    by an LLM call opt into retrying by constructing a policy with
    `max_attempts=2` (constitution §4.8: "LLM calls get one automatic
    retry")."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    max_attempts: int = Field(default=1, ge=1)
    backoff_base_seconds: float = Field(default=0.5, ge=0.0)
    backoff_multiplier: float = Field(default=2.0, ge=1.0)
    retryable_exceptions: tuple[type[Exception], ...] = (ExternalServiceError,)

    def is_retryable(self, error: Exception) -> bool:
        return isinstance(error, self.retryable_exceptions)


def run_with_retry(fn: Callable[[], _T], *, policy: RetryPolicy, op_name: str) -> _T:
    """Invoke `fn` (a zero-argument callable), retrying up to
    `policy.max_attempts` times with exponential backoff, but only for
    exceptions `policy` marks retryable. Any other exception, or the final
    retryable exception once attempts are exhausted, propagates to the
    caller (`core/graph/workflow_engine.py`, which converts it via
    `core/graph/failure_recovery.py`)."""
    delay = policy.backoff_base_seconds

    for attempt in range(1, policy.max_attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - re-raised below once policy is applied
            if not policy.is_retryable(exc) or attempt == policy.max_attempts:
                raise
            _logger.warning(
                "workflow_node_retry",
                operation=op_name,
                attempt=attempt,
                max_attempts=policy.max_attempts,
                error=str(exc),
            )
            time.sleep(delay)
            delay *= policy.backoff_multiplier

    raise AssertionError("unreachable: run_with_retry loop must return or raise")
