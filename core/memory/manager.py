"""`MemoryManager` — the single facade a future Memory Agent (and, in the
meantime, tests/services) constructs against instead of wiring
session/case/conversation/long-term memory, the context builder, and
metrics together by hand every time.

Every dependency is injected (constitution §2, "Dependency injection") —
`MemoryManager` itself contains no reasoning, only composition, matching
`core.interfaces.Service`'s documented convention of thin orchestration.
"""

from __future__ import annotations

from functools import lru_cache
from uuid import UUID

from core.config import Settings, get_settings
from core.logging import get_logger
from core.memory.context_builder import AssembledContext, ContextBuilder
from core.memory.context_serializer import ContextSerializer
from core.memory.conversation_memory import ConversationMemory
from core.memory.embedding_providers import build_text_embedder
from core.memory.interfaces import CaseMemory, LongTermMemory, SimilarResult, VectorMemory
from core.memory.lifecycle import CleanupReport, MemoryLifecycleManager
from core.memory.long_term import LongTermMemoryManager
from core.memory.metrics import MemoryMetricsCollector
from core.memory.models import ConversationRole, ConversationTurn, MemoryRecord
from core.memory.session_memory import SessionMemory
from core.memory.vector_store import NullVectorStore

_logger = get_logger(__name__)


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

    async def find_similar_in_case(
        self, query: str, *, case_id: UUID, limit: int = 5
    ) -> list[SimilarResult]:
        """Case-scoped retrieval (ADR-0027) — always advisory."""
        if self._long_term_memory is None:
            return []
        with self.metrics.time_retrieval():
            results = await self._long_term_memory.find_similar_in_case(
                query, case_id=case_id, limit=limit
            )
        (self.metrics.record_hit() if results else self.metrics.record_miss())
        return results

    async def find_similar_past_investigations(
        self,
        query: str,
        *,
        exclude_case_id: UUID,
        limit: int = 5,
        category: str | None = None,
    ) -> list[SimilarResult]:
        """ "Have we seen this before, in another case?" (ADR-0027) — the
        "similar past investigations" requirement, optionally narrowed to
        one `category` ("finding"/"ioc"/"mitre_technique"/"report"/
        "case_summary"). Always advisory."""
        if self._long_term_memory is None:
            return []
        with self.metrics.time_retrieval():
            results = await self._long_term_memory.find_similar_excluding_case(
                query, exclude_case_id=exclude_case_id, limit=limit, category=category
            )
        (self.metrics.record_hit() if results else self.metrics.record_miss())
        return results

    async def record_finding(
        self, case_id: UUID, finding_id: UUID, content: str, *, category: str = "finding"
    ) -> None:
        if self._long_term_memory is None:
            return
        await self._long_term_memory.record(case_id, finding_id, content, category=category)
        self.metrics.record_write()

    async def forget_case(self, case_id: UUID) -> None:
        """Removes a case's long-term-memory footprint (ADR-0027) — called
        when a case is deleted so stale embeddings never resurface in a
        future cross-case search."""
        if self._long_term_memory is None:
            return
        await self._long_term_memory.delete_case(case_id)

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


def build_long_term_memory(settings: Settings) -> LongTermMemoryManager:
    """Wires the real ChromaDB-backed `VectorMemory` + a real semantic
    `TextEmbedder` per `settings.llm_provider` (ADR-0027) — the single place
    "production backend" vs. "degraded (no-op / hashing) fallback" is
    decided, so every caller (`case_service.py`, `conversation_service.py`,
    tests) gets identical behavior without re-implementing this choice.

    Never raises: if the ChromaDB collection can't be opened (e.g. an
    unwritable `CHROMA_PERSIST_DIR`), this degrades to `NullVectorStore`
    rather than failing application startup — long-term memory is always
    advisory (ADR-0006).
    """
    vector_store: VectorMemory
    try:
        # Local import: keeps `chromadb` construction lazy and isolated to
        # this one call site, so a broken Chroma install never breaks
        # importing `core.memory.manager` itself.
        from core.memory.chroma_vector_store import ChromaVectorStore

        vector_store = ChromaVectorStore(persist_dir=str(settings.chroma_persist_dir))
    except Exception as exc:  # noqa: BLE001 - fallback boundary, ADR-0006
        _logger.error("chroma_vector_store_unavailable", error=str(exc))
        vector_store = NullVectorStore()
    embedder = build_text_embedder(settings)
    return LongTermMemoryManager(vector_store=vector_store, embedder=embedder)


@lru_cache
def default_long_term_memory() -> LongTermMemoryManager:
    """Process-wide singleton (constitution §2, "a documented, explicitly-
    named singleton is fine"), matching `core.agents.registry.
    default_agent_registry()`'s/`core.knowledge.registry.
    default_knowledge_registry()`'s identical shape. Constructed lazily on
    first access via `build_long_term_memory(get_settings())` — callers
    needing isolation (tests, a future multi-process deployment) construct
    and inject their own `LongTermMemoryManager` instead."""
    return build_long_term_memory(get_settings())
