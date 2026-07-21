"""`CitationEngine` — the task's named "Citation Engine".

Attaches a `SourceReference` to every retrieved item a `ChatCompletion`
actually drew on. An answer with zero available evidence carries zero
citations and is marked `degraded` by the caller (`ConversationManager`) —
never a fabricated citation (constitution §1.7, "fail gracefully, not
silently").
"""

from __future__ import annotations

from core.conversation.models import ChatCompletion, RetrievedItem, SourceReference


class CitationEngine:
    """Stateless: a pure function mapping a completion's claimed source ids
    back to the actual `RetrievedItem`s that were available."""

    def cite(
        self, completion: ChatCompletion, *, available_items: list[RetrievedItem]
    ) -> tuple[SourceReference, ...]:
        by_id = {item.source_id: item.reference for item in available_items}
        citations: list[SourceReference] = []
        seen: set[str] = set()
        for source_id in completion.used_source_ids:
            if source_id in seen:
                continue
            reference = by_id.get(source_id)
            if reference is None:
                # A provider naming a source id we never actually retrieved
                # is exactly the "output validation" failure mode
                # constitution §10 requires guarding against — never trust
                # a claimed citation that doesn't correspond to a real,
                # retrieved item.
                continue
            citations.append(reference)
            seen.add(source_id)
        return tuple(citations)
