"""`MemoryManager` — the single facade a future Memory Agent (and, in the
meantime, tests/services) constructs against instead of wiring
session/case/conversation/long-term memory, the context builder, and
metrics together by hand every time.

Every dependency is injected (constitution §2, "Dependency injection") —
`MemoryManager` itself contains no reasoning, only composition, matching
`core.interfaces.Service`'s documented convention of thin orchestration.
"""

from __future__ import annotations

from uuid import UUID

from core.memory.context_builder import AssembledContext, ContextBuilder
from core.memory.context_serializer import ContextSerializer
from core.memory.conversation_memory import ConversationMemory
from core.memory.interfaces import CaseMemory, LongTermMemory, SimilarResult
from core.memory.lifecycle import CleanupReport, MemoryLifecycleManager
from core.memory.metrics import MemoryMetricsCollector
from core.memory.models import ConversationRole, ConversationTurn, MemoryRecord
from core.memory.session_memory import SessionMemory


class MemoryManager:
    """Facade over every memory concern one case investigation or chat
    session needs. Optional pieces (`long_term_memory`, `lifecycle`) may be
    omitted — matching ADR-0006's "memory is always advisory" contract at
    the facade level too: a `MemoryManager` with no long-term backend simply
    returns empty results from `find_similar_findings`, never raises.
    """

    def __init__(
        self,
        *,
        session_memory: SessionMemory | None = None,
        case_memory: CaseMemory | None = None,
        conversation_memory: ConversationMemory | None = None,
        long_term_memory: LongTermMemory | None = None,
        context_builder: ContextBuilder | None = None,
        serializer: ContextSerializer | None = None,
        lifecycle: MemoryLifecycleManager | None = None,
        metrics: MemoryMetricsCollector | None = None,
    ) -> None:
        self.session_memory = session_memory or SessionMemory()
        self._case_memory = case_memory
        self._conversation_memory = conversation_memory
        self._long_term_memory = long_term_memory
        self._lifecycle = lifecycle
        self.context_builder = context_builder or ContextBuilder()
        self.serializer = serializer or ContextSerializer()
        self.metrics = metrics or MemoryMetricsCollector()

    async def get_case_notes(self, case_id: UUID) -> list[str]:
        if self._case_memory is None:
            return []
        with self.metrics.time_retrieval():
            notes = await self._case_memory.get_notes(case_id)
        (self.metrics.record_hit() if notes else self.metrics.record_miss())
        return notes

    async def add_case_note(self, case_id: UUID, note: str) -> None:
        if self._case_memory is None:
            return
        await self._case_memory.add_note(case_id, note)
        self.metrics.record_write()

    async def get_conversation(self, case_id: UUID, *, limit: int = 50) -> list[ConversationTurn]:
        if self._conversation_memory is None:
            return []
        return await self._conversation_memory.get_turns(case_id, limit=limit)

    async def add_conversation_turn(
        self, case_id: UUID, role: ConversationRole, content: str
    ) -> ConversationTurn | None:
        if self._conversation_memory is None:
            return None
        turn = await self._conversation_memory.add_turn(case_id, role, content)
        self.metrics.record_write()
        return turn

    async def find_similar_findings(self, query: str, *, limit: int = 5) -> list[SimilarResult]:
        """Always advisory (ADR-0006): returns `[]` with no long-term
        backend configured, rather than raising."""
        if self._long_term_memory is None:
            return []
        with self.metrics.time_retrieval():
            results = await self._long_term_memory.find_similar(query, limit=limit)
        (self.metrics.record_hit() if results else self.metrics.record_miss())
        return results

    async def record_finding(self, case_id: UUID, finding_id: UUID, content: str) -> None:
        if self._long_term_memory is None:
            return
        await self._long_term_memory.record(case_id, finding_id, content)
        self.metrics.record_write()

    def build_context(self, records: list[MemoryRecord]) -> AssembledContext:
        return self.context_builder.assemble(records)

    def render_context(self, records: list[MemoryRecord]) -> str:
        return self.serializer.to_prompt_text(self.build_context(records))

    async def cleanup(self) -> CleanupReport | None:
        if self._lifecycle is None:
            return None
        report = await self._lifecycle.cleanup_expired()
        self.metrics.record_eviction(report.records_deleted)
        return report
