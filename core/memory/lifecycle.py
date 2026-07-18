"""Memory lifecycle management — expiration + cleanup strategy.

Constitution §2 forbids unbounded global state; this module is the
explicit, documented mechanism that keeps in-process stores
(`InMemoryConversationMemory`, `InMemoryVectorStore`) and persisted stores
(`MemoryRepository`) from growing without bound over a long-running process.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel

from core.logging import get_logger
from core.memory.models import MemoryScope
from core.memory.repository import MemoryRepository

_logger = get_logger(__name__)

#: Default retention per scope — session data is cheap to lose and short-
#: lived by nature; case notes and long-term retrieval metadata are kept far
#: longer since they back durable, cross-session context.
DEFAULT_RETENTION: dict[MemoryScope, timedelta] = {
    MemoryScope.SESSION: timedelta(hours=12),
    MemoryScope.CONVERSATION: timedelta(days=30),
    MemoryScope.CASE: timedelta(days=365),
    MemoryScope.LONG_TERM: timedelta(days=365),
}


class CleanupReport(BaseModel):
    """What one cleanup pass actually did — the audit record a scheduled
    cleanup job logs (constitution §8: lifecycle events are logged, not
    silent)."""

    ran_at: datetime
    records_deleted: int
    scope: MemoryScope | None


class MemoryLifecycleManager:
    """Applies TTL expiration to persisted `MemoryRecord`s.

    Does not touch in-process stores directly — those are per-instance and
    scoped to a session's/process's own lifetime already; this manager's job
    is the *persisted* data that would otherwise accumulate indefinitely.
    """

    def __init__(self, repository: MemoryRepository) -> None:
        self._repository = repository

    async def cleanup_expired(self, *, scope: MemoryScope | None = None) -> CleanupReport:
        """Delete every persisted record past its `expires_at`. Intended to
        run on a schedule (a future cron/worker, not built here — this
        method is the reusable unit that schedule would call)."""
        now = datetime.now(UTC)
        deleted = await self._repository.delete_expired(scope=scope, now=now)
        _logger.info(
            "memory_cleanup_completed", scope=scope.value if scope else "all", deleted=deleted
        )
        return CleanupReport(ran_at=now, records_deleted=deleted, scope=scope)

    @staticmethod
    def default_expiry_for(scope: MemoryScope, *, now: datetime | None = None) -> datetime:
        """Compute the default `expires_at` a new record of this scope should
        carry, per `DEFAULT_RETENTION`. Callers may always override this
        explicitly (e.g. a case an analyst pins never expires) — this is
        only the default, not a hard rule enforced elsewhere."""
        base = now or datetime.now(UTC)
        return base + DEFAULT_RETENTION[scope]
