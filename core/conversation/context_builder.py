"""`ConversationContextBuilder` — the task's named "Context Builder".

Ranks and budget-truncates `RetrievedItem`s into what actually gets sent to
the prompt. A distinct, smaller assembly step from `core.memory.
context_builder.ContextBuilder` (which operates on `MemoryRecord`s, a
different, memory-layer-owned shape this package deliberately does not
import — docs/adr/0025 Decision 1) — not a duplicate of it, the same
"different shape, different home" reasoning ADR-0010 already used to keep
`ConversationMemory` distinct from `CaseMemory`.
"""

from __future__ import annotations

from core.conversation.models import AssembledConversationContext, RetrievedItem

#: A conservative character-count stand-in for a token budget — the
#: identical reasoning `core.memory.context_builder.DEFAULT_MAX_CHARS`
#: documents: a real tokenizer would couple this framework-only layer to a
#: specific LLM provider (constitution §2, dependency injection).
DEFAULT_MAX_CHARS = 6_000


class ConversationContextBuilder:
    """Deterministic: rank by relevance (then category, for a stable
    tie-break) → truncate to a character budget."""

    def __init__(self, *, max_chars: int = DEFAULT_MAX_CHARS) -> None:
        self.max_chars = max_chars

    def rank(self, items: list[RetrievedItem]) -> list[RetrievedItem]:
        return sorted(items, key=lambda item: (-item.relevance_score, item.category.value))

    def truncate_to_budget(self, items: list[RetrievedItem]) -> tuple[list[RetrievedItem], bool]:
        selected: list[RetrievedItem] = []
        used = 0
        truncated = False
        for item in items:
            cost = len(item.text)
            if used + cost > self.max_chars:
                truncated = True
                continue
            selected.append(item)
            used += cost
        return selected, truncated

    def assemble(self, items: list[RetrievedItem]) -> AssembledConversationContext:
        ranked = self.rank(items)
        selected, truncated = self.truncate_to_budget(ranked)
        return AssembledConversationContext(
            items=tuple(selected),
            total_candidates=len(items),
            truncated=truncated,
        )
