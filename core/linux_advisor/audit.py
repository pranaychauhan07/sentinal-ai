"""Linux Security Advisor structured audit-event emission + execution
timing (constitution §8), mirroring `core.vulnerabilities.audit`'s "thin
wrapper over `core.logging`" pattern exactly.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from enum import StrEnum

from core.logging import get_logger

_logger = get_logger(__name__)


class AuditAction(StrEnum):
    ANALYZED_COMMAND = "analyzed_command"
    ANALYZED_PERMISSION = "analyzed_permission"
    RECOMMENDATION_GENERATED = "recommendation_generated"
    LINE_SKIPPED = "line_skipped"
    OVERSIZED_INPUT_REJECTED = "oversized_input_rejected"


def log_linux_advisor_audit_event(
    *,
    action: AuditAction,
    subject: str | None = None,
    severity: str | None = None,
    detail: str = "",
) -> None:
    """Emit one structured, queryable audit log line. Never raises — an
    audit-logging failure must not abort advisory analysis (constitution
    §9's degraded-not-fatal rule)."""
    _logger.info(
        "linux_advisor_audit_event",
        action=action.value,
        subject=subject,
        severity=severity,
        detail=detail,
    )


@contextmanager
def timed_execution(operation: str) -> Iterator[dict[str, float]]:
    """Context manager yielding a mutable dict that receives
    `duration_ms` once the `with` block exits — the shared timing helper
    `advisory_engine.py`/`core.services.linux_advisor_service` use instead
    of hand-rolling `time.perf_counter()` bookkeeping at each call site."""
    result: dict[str, float] = {"duration_ms": 0.0}
    started = time.perf_counter()
    try:
        yield result
    finally:
        result["duration_ms"] = (time.perf_counter() - started) * 1000
        _logger.debug("linux_advisor_timed_execution", operation=operation, **result)
