"""Report generation structured audit-event emission + execution timing
(constitution §8), mirroring `core.incident_response.audit`'s "thin wrapper
over `core.logging`" pattern exactly.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from enum import StrEnum

from core.logging import get_logger

_logger = get_logger(__name__)


class AuditAction(StrEnum):
    SECTION_GENERATED = "section_generated"
    SECTION_FAILED = "section_failed"
    REPORT_DEGRADED = "report_degraded"
    REPORT_GENERATED = "report_generated"
    OVERSIZED_REPORT_INPUT_REJECTED = "oversized_report_input_rejected"


def log_report_generation_audit_event(
    *,
    action: AuditAction,
    case_id: str | None = None,
    section_type: str | None = None,
    detail: str = "",
) -> None:
    """Emit one structured, queryable audit log line. Never raises — an
    audit-logging failure must not abort report generation (constitution
    §9's degraded-not-fatal rule)."""
    _logger.info(
        "report_generation_audit_event",
        action=action.value,
        case_id=case_id,
        section_type=section_type,
        detail=detail,
    )


@contextmanager
def timed_execution(operation: str) -> Iterator[dict[str, float]]:
    """Context manager yielding a mutable dict that receives `duration_ms`
    once the `with` block exits — the shared timing helper
    `report_engine.py` uses instead of hand-rolling `time.perf_counter()`
    bookkeeping at each call site."""
    result: dict[str, float] = {"duration_ms": 0.0}
    started = time.perf_counter()
    try:
        yield result
    finally:
        result["duration_ms"] = (time.perf_counter() - started) * 1000
        _logger.debug("report_generation_timed_execution", operation=operation, **result)
