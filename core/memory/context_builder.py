"""`ContextBuilder` — assembles raw `MemoryRecord`s into the bounded,
de-duplicated, ranked set an agent or the future AI Analyst Chat actually
sends to an LLM.

This is the "token-efficient context creation" piece: rather than every
future agent re-implementing its own filtering/dedup/truncation logic
against memory, it happens once, here, deterministically (constitution
Principle 9 — ranking/filtering is plain Python, never left to LLM
judgment).
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel

from core.memory.models import MemoryRecord

#: A conservative stand-in for a token budget. Character count is used
#: instead of a real tokenizer because pulling in a model-specific tokenizer
#: here would couple this framework-only layer to a specific LLM provider
#: (constitution §2, dependency injection: the provider is a config choice,
#: not a hardcoded import) — callers with a real tokenizer available may
#: pass a tighter `max_chars` computed from it.
DEFAULT_MAX_CHARS = 8_000


class AssembledContext(BaseModel):
    """The result of one `ContextBuilder.assemble()` call."""

    records: tuple[MemoryRecord, ...]
    total_candidates: int
    truncated: bool


class ContextBuilder:
    """Deterministic context assembly: filter expired → deduplicate →
    rank by priority then recency → truncate to a character budget.

    Each step is a separate method so a caller needing only one piece
    (e.g. just dedup) can call it directly instead of the full pipeline —
    matching constitution Principle 3 (small, focused responsibilities).
    """

    def __init__(self, *, max_chars: int = DEFAULT_MAX_CHARS) -> None:
        self.max_chars = max_chars

    def filter_active(
        self, records: list[MemoryRecord], *, now: datetime | None = None
    ) -> list[MemoryRecord]:
        moment = now or datetime.now(UTC)
        return [record for record in records if not record.is_expired(now=moment)]

    def deduplicate(self, records: list[MemoryRecord]) -> list[MemoryRecord]:
        """Removes exact-content duplicates, keeping the first (most
        relevant, per the caller's prior ordering) occurrence."""
        seen: set[str] = set()
        deduped: list[MemoryRecord] = []
        for record in records:
            fingerprint = f"{record.scope.value}:{record.content.strip()}"
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            deduped.append(record)
        return deduped

    def rank(self, records: list[MemoryRecord]) -> list[MemoryRecord]:
        """Priority first (HIGH before NORMAL before LOW), then most recent
        first within the same priority — a stable, explicit, two-key sort
        rather than an opaque single relevance score."""
        return sorted(records, key=lambda r: (-r.priority_weight, -r.created_at.timestamp()))

    def truncate_to_budget(self, records: list[MemoryRecord]) -> tuple[list[MemoryRecord], bool]:
        selected: list[MemoryRecord] = []
        used = 0
        truncated = False
        for record in records:
            cost = len(record.content)
            if used + cost > self.max_chars:
                truncated = True
                continue
            selected.append(record)
            used += cost
        return selected, truncated

    def assemble(
        self, records: list[MemoryRecord], *, now: datetime | None = None
    ) -> AssembledContext:
        """Run the full pipeline: filter → dedup → rank → truncate."""
        active = self.filter_active(records, now=now)
        deduped = self.deduplicate(active)
        ranked = self.rank(deduped)
        selected, truncated = self.truncate_to_budget(ranked)
        return AssembledContext(
            records=tuple(selected),
            total_candidates=len(records),
            truncated=truncated,
        )
