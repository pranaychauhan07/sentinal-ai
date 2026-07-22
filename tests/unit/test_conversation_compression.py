"""Unit tests for core/conversation/compression.py (ADR-0029)."""

from __future__ import annotations

import pytest

from core.conversation.compression import (
    build_bounded_history,
    estimate_tokens,
    summarize_turns,
)
from core.conversation.models import ConversationHistoryTurn

pytestmark = pytest.mark.unit


def test_estimate_tokens_empty_string_is_zero() -> None:
    assert estimate_tokens("") == 0


def test_estimate_tokens_scales_with_length() -> None:
    short = estimate_tokens("hello")
    long = estimate_tokens("hello " * 100)
    assert long > short


def test_estimate_tokens_never_zero_for_nonempty_text() -> None:
    assert estimate_tokens("a") >= 1


def test_summarize_turns_of_empty_list_returns_empty_result() -> None:
    result = summarize_turns([])
    assert result.summary_text == ""
    assert result.covers_through_sequence_index == -1
    assert result.summarized_message_count == 0


def test_summarize_turns_produces_one_bullet_per_turn() -> None:
    turns = [
        (0, ConversationHistoryTurn(role="user", content="Was T1110 mapped?")),
        (1, ConversationHistoryTurn(role="assistant", content="Yes, brute force.")),
    ]
    result = summarize_turns(turns)
    assert "user: Was T1110 mapped?" in result.summary_text
    assert "assistant: Yes, brute force." in result.summary_text
    assert result.covers_through_sequence_index == 1
    assert result.summarized_message_count == 2


def test_summarize_turns_truncates_long_content_with_ellipsis() -> None:
    long_content = "x" * 500
    turns = [(0, ConversationHistoryTurn(role="user", content=long_content))]
    result = summarize_turns(turns)
    assert "…" in result.summary_text
    assert len(result.summary_text) < len(long_content)


def test_summarize_turns_never_fabricates_text_not_in_source() -> None:
    turns = [(0, ConversationHistoryTurn(role="user", content="unique-marker-abc123"))]
    result = summarize_turns(turns)
    assert "unique-marker-abc123" in result.summary_text


def test_build_bounded_history_with_no_summary_and_ample_budget_keeps_all_turns() -> None:
    turns = [ConversationHistoryTurn(role="user", content="hi")]
    history = build_bounded_history(summary_text=None, recent_turns=turns, max_tokens=1_000)
    assert history == turns


def test_build_bounded_history_includes_summary_as_a_system_turn() -> None:
    history = build_bounded_history(
        summary_text="Earlier summary text", recent_turns=[], max_tokens=1_000
    )
    assert len(history) == 1
    assert history[0].role == "system"
    assert history[0].content == "Earlier summary text"


def test_build_bounded_history_never_drops_the_summary_under_a_tight_budget() -> None:
    long_summary = "s" * 400
    turns = [ConversationHistoryTurn(role="user", content="x" * 400)]
    history = build_bounded_history(summary_text=long_summary, recent_turns=turns, max_tokens=10)
    assert history[0].content == long_summary


def test_build_bounded_history_drops_oldest_recent_turns_first_under_a_tight_budget() -> None:
    turns = [
        ConversationHistoryTurn(role="user", content="oldest " * 50),
        ConversationHistoryTurn(role="assistant", content="middle " * 50),
        ConversationHistoryTurn(role="user", content="newest"),
    ]
    history = build_bounded_history(summary_text=None, recent_turns=turns, max_tokens=20)
    contents = [t.content for t in history]
    assert "newest" in contents
    assert "oldest " * 50 not in contents
