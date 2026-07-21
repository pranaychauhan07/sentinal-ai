"""Conversation Audit Log — the task's named "Conversation Audit Log".

Structured `structlog` audit-event emission + execution timing (constitution
§8), mirroring `core.incident_response.audit`'s "thin wrapper over
`core.logging`" pattern exactly. No new DB table — blueprint §8 does not
name a conversation/chat-message table, and ADR-0010 already scoped chat
history storage to `InMemoryConversationMemory` deliberately (docs/adr/0025
Decision 4); the audit trail here is structured log output, the same
explainability mechanism constitution §8 already establishes for every
agent's `thought`.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from core.conversation.models import AuditEventAction, ConversationAuditEvent
from core.logging import get_logger

_logger = get_logger(__name__)


def log_conversation_audit_event(
    *,
    action: AuditEventAction,
    case_id: str,
    session_id: str | None = None,
    detail: str = "",
    metadata: dict[str, object] | None = None,
) -> ConversationAuditEvent:
    """Emit one structured, queryable audit log line and return the typed
    event (so callers/tests can assert on it without parsing log strings).
    Never raises — an audit-logging failure must not abort answer
    generation (constitution §9's degraded-not-fatal rule)."""
    event = ConversationAuditEvent(
        action=action,
        case_id=case_id,
        session_id=session_id,
        detail=detail,
        metadata=metadata or {},
    )
    _logger.info(
        "conversation_audit_event",
        action=event.action.value,
        case_id=event.case_id,
        session_id=event.session_id,
        detail=event.detail,
        **event.metadata,
    )
    return event


@contextmanager
def timed_execution(operation: str) -> Iterator[dict[str, float]]:
    """Context manager yielding a mutable dict that receives `duration_ms`
    once the `with` block exits — the shared timing helper
    `conversation_manager.py`/`core.services.conversation_service` use
    instead of hand-rolling `time.perf_counter()` bookkeeping at each call
    site, mirroring `core.incident_response.audit.timed_execution` exactly."""
    result: dict[str, float] = {"duration_ms": 0.0}
    started = time.perf_counter()
    try:
        yield result
    finally:
        result["duration_ms"] = (time.perf_counter() - started) * 1000
        _logger.debug("conversation_timed_execution", operation=operation, **result)
