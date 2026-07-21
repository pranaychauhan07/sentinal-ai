"""`ConversationContextBuilder` — the task's named "Context Builder".

Deduplicates, ranks, and budget-truncates `RetrievedItem`s into what
actually gets sent to the prompt. A distinct, smaller assembly step from
`core.memory.context_builder.ContextBuilder` (which operates on
`MemoryRecord`s, a different, memory-layer-owned shape this package
deliberately does not import — docs/adr/0025 Decision 1) — not a duplicate
of it, the same "different shape, different home" reasoning ADR-0010
already used to keep `ConversationMemory` distinct from `CaseMemory`.

ADR-0027 adds the dedup step: once retrieval can draw from more than one
source per question (case data, the Knowledge Layer, cross-case long-term
memory), two categories can legitimately surface near-identical text (e.g.
a case Finding and a cross-case "similar finding" both describing the same
brute-force pattern) — a real gap the original five-category, single-source
design never had to handle.
"""

from __future__ import annotations

import re

from core.conversation.models import AssembledConversationContext, RetrievedItem

#: A conservative character-count stand-in for a token budget — the
#: identical reasoning `core.memory.context_builder.DEFAULT_MAX_CHARS`
#: documents: a real tokenizer would couple this framework-only layer to a
#: specific LLM provider (constitution §2, dependency injection).
DEFAULT_MAX_CHARS = 6_000

_WHITESPACE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WHITESPACE.sub(" ", text).strip().lower()


class ConversationContextBuilder:
    """Deterministic: deduplicate → rank by relevance (then category, for a
    stable tie-break) → truncate to a character budget."""

    def __init__(self, *, max_chars: int = DEFAULT_MAX_CHARS) -> None:
        self.max_chars = max_chars

    def deduplicate(self, items: list[RetrievedItem]) -> tuple[list[RetrievedItem], int]:
        """Drops any item whose normalized text exactly matches an
        already-kept item's — items are processed in the caller's existing
        order (by convention, already-ranked, so the higher-relevance
        duplicate is the one kept). Returns `(deduplicated, removed_count)`.
        """
        seen: set[str] = set()
        deduplicated: list[RetrievedItem] = []
        for item in items:
            key = _normalize(item.text)
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            deduplicated.append(item)
        return deduplicated, len(items) - len(deduplicated)

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
        deduplicated, duplicates_removed = self.deduplicate(ranked)
        selected, truncated = self.truncate_to_budget(deduplicated)
        return AssembledConversationContext(
            items=tuple(selected),
            total_candidates=len(items),
            truncated=truncated,
            duplicates_removed=duplicates_removed,
        )
