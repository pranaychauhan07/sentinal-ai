"""Conversation Compression / Context Window Management (ADR-0029).

Deterministic token budgeting and extractive summarization for long chat
sessions — a distinct axis from `context_builder.py`'s retrieved-evidence
ranking (constitution §1.3, "a file does one thing"): this module manages
*prior conversation turns*, not retrieved case data.

Never an LLM call (constitution §1.9 extended to conversation-history
reduction: mechanical, checkable, and must not itself risk hallucinating a
turn that was never said) — `summarize_turns` only ever reproduces text that
was actually in the source turns.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from core.conversation.models import ConversationHistoryTurn

#: Rough chars-per-token heuristic for English text — good enough for a
#: budgeting decision that only needs to avoid gross prompt overflow, not
#: exact token accounting (no tokenizer dependency is worth adding for this).
CHARS_PER_TOKEN_ESTIMATE = 4

#: How much of a turn's content survives into the extractive summary line.
SUMMARY_EXCERPT_CHARS = 160


def estimate_tokens(text: str) -> int:
    """A deterministic, conservative token-count estimate. Never exact —
    documented as a heuristic, matching constitution §5's requirement that a
    non-exact estimate be explicit about it rather than presented as if it
    were precise."""
    if not text:
        return 0
    return max(1, len(text) // CHARS_PER_TOKEN_ESTIMATE)


class CompressionResult(BaseModel):
    """`summarize_turns`'s output — the summary text plus the bookkeeping
    `core/services/conversation_service.py` needs to persist a
    `ConversationSummaryRow` and to know which raw turns it may now omit
    from the prompt."""

    model_config = ConfigDict(frozen=True)

    summary_text: str
    covers_through_sequence_index: int
    summarized_message_count: int = Field(ge=0)


def summarize_turns(
    turns: list[tuple[int, ConversationHistoryTurn]],
) -> CompressionResult:
    """Reduce older turns to a bulleted excerpt list — extractive, never
    generative: every line is a truncated, attributed quote of a real turn,
    so the summary itself can never introduce a fact the conversation didn't
    contain.

    `turns` is `(sequence_index, turn)` pairs, oldest first — the caller
    (`core/services/conversation_service.py`) decides the cut point (how
    many *recent* turns to keep raw, per
    `Settings.conversation_summary_keep_recent_turns`) and only passes the
    turns to be summarized here.
    """
    if not turns:
        return CompressionResult(
            summary_text="", covers_through_sequence_index=-1, summarized_message_count=0
        )
    lines = []
    for _, turn in turns:
        excerpt = turn.content.strip().replace("\n", " ")
        if len(excerpt) > SUMMARY_EXCERPT_CHARS:
            excerpt = excerpt[:SUMMARY_EXCERPT_CHARS].rstrip() + "…"
        lines.append(f"- {turn.role}: {excerpt}")
    summary_text = (
        f"Earlier in this conversation ({len(turns)} messages, summarized):\n" + "\n".join(lines)
    )
    return CompressionResult(
        summary_text=summary_text,
        covers_through_sequence_index=turns[-1][0],
        summarized_message_count=len(turns),
    )


def build_bounded_history(
    *,
    summary_text: str | None,
    recent_turns: list[ConversationHistoryTurn],
    max_tokens: int,
) -> list[ConversationHistoryTurn]:
    """Context-window management: assemble the history actually handed to
    `PromptBuilder`, dropping the *oldest* recent turns first if the summary
    plus recent turns would still exceed `max_tokens` — the summary itself
    is never dropped (it is the compact representative of everything older,
    dropping it would lose that context entirely for a marginal token
    saving)."""
    budget = max_tokens
    history: list[ConversationHistoryTurn] = []
    if summary_text:
        summary_turn = ConversationHistoryTurn(role="system", content=summary_text)
        budget -= estimate_tokens(summary_text)
        history.append(summary_turn)

    kept: list[ConversationHistoryTurn] = []
    for turn in reversed(recent_turns):
        cost = estimate_tokens(turn.content)
        if cost > budget and kept:
            break
        kept.append(turn)
        budget -= cost
    kept.reverse()
    history.extend(kept)
    return history
