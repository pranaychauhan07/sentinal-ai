"""Incident Response structured audit-event emission + execution timing
(constitution §8), mirroring `core.linux_advisor.audit`'s "thin wrapper over
`core.logging`" pattern exactly.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from enum import StrEnum

from core.logging import get_logger

_logger = get_logger(__name__)


class AuditAction(StrEnum):
    FINDING_CONSIDERED = "finding_considered"
    FINDING_SKIPPED = "finding_skipped"
    RECOMMENDATION_GENERATED = "recommendation_generated"
    RECOMMENDATIONS_MERGED = "recommendations_merged"
    PLAN_DEGRADED = "plan_degraded"
    PLAN_GENERATED = "plan_generated"
    OVERSIZED_FINDING_SET_REJECTED = "oversized_finding_set_rejected"


def log_incident_response_audit_event(
    *,
    action: AuditAction,
    case_id: str | None = None,
    category: str | None = None,
    detail: str = "",
) -> None:
    """Emit one structured, queryable audit log line. Never raises — an
    audit-logging failure must not abort plan generation (constitution §9's
    degraded-not-fatal rule)."""
    _logger.info(
        "incident_response_audit_event",
        action=action.value,
        case_id=case_id,
        category=category,
        detail=detail,
    )


@contextmanager
def timed_execution(operation: str) -> Iterator[dict[str, float]]:
    """Context manager yielding a mutable dict that receives `duration_ms`
    once the `with` block exits — the shared timing helper
    `response_plan_engine.py`/`core.services.incident_response_service` use
    instead of hand-rolling `time.perf_counter()` bookkeeping at each call
    site."""
    result: dict[str, float] = {"duration_ms": 0.0}
    started = time.perf_counter()
    try:
        yield result
    finally:
        result["duration_ms"] = (time.perf_counter() - started) * 1000
        _logger.debug("incident_response_timed_execution", operation=operation, **result)
