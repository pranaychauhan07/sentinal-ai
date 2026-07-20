"""OWASP Security Agent structured audit-event emission + execution timing
(constitution §8), mirroring `core.owasp_web.audit`'s "thin wrapper over
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
    FILE_ANALYZED = "file_analyzed"
    FINDING_DETECTED = "finding_detected"
    PARSE_DEGRADED = "parse_degraded"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    OVERSIZED_INPUT_REJECTED = "oversized_input_rejected"


def log_sast_audit_event(
    *,
    action: AuditAction,
    subject: str | None = None,
    severity: str | None = None,
    detail: str = "",
) -> None:
    """Emit one structured, queryable audit log line. Never raises — an
    audit-logging failure must not abort SAST analysis (constitution §9's
    degraded-not-fatal rule)."""
    _logger.info(
        "sast_audit_event",
        action=action.value,
        subject=subject,
        severity=severity,
        detail=detail,
    )


@contextmanager
def timed_execution(operation: str) -> Iterator[dict[str, float]]:
    """Context manager yielding a mutable dict that receives `duration_ms`
    once the `with` block exits."""
    result: dict[str, float] = {"duration_ms": 0.0}
    started = time.perf_counter()
    try:
        yield result
    finally:
        result["duration_ms"] = (time.perf_counter() - started) * 1000
        _logger.debug("sast_timed_execution", operation=operation, **result)
