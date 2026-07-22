"""Unit tests for core/conversation/export.py (ADR-0029)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from core.conversation.export import (
    ExportedMessage,
    export_conversation,
    render_json,
    render_markdown,
)

pytestmark = pytest.mark.unit


def _message(**overrides: object) -> ExportedMessage:
    defaults: dict[str, object] = {
        "sequence_index": 0,
        "role": "user",
        "content": "hello",
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "citations": (),
        "confidence": None,
        "degraded": False,
    }
    defaults.update(overrides)
    return ExportedMessage.model_validate(defaults)


def test_render_json_round_trips_message_content() -> None:
    messages = [_message(content="Was T1110 mapped?"), _message(sequence_index=1, role="assistant")]
    exported = render_json(case_id="case-1", session_id="session-1", messages=messages)
    payload = json.loads(exported.content)
    assert payload["case_id"] == "case-1"
    assert payload["message_count"] == 2
    assert payload["messages"][0]["content"] == "Was T1110 mapped?"
    assert exported.media_type == "application/json"
    assert exported.filename == "conversation-session-1.json"


def test_render_markdown_includes_role_and_content() -> None:
    messages = [_message(content="Why High severity?")]
    exported = render_markdown(case_id="case-1", session_id="session-1", messages=messages)
    text = exported.content.decode("utf-8")
    assert "USER" in text
    assert "Why High severity?" in text
    assert exported.media_type == "text/markdown"


def test_render_markdown_escapes_markdown_control_characters() -> None:
    messages = [_message(content="drop table *findings* [now]")]
    exported = render_markdown(case_id="case-1", session_id="session-1", messages=messages)
    text = exported.content.decode("utf-8")
    assert "\\*findings\\*" in text
    assert "\\[now\\]" in text


def test_render_markdown_includes_citations_and_confidence() -> None:
    messages = [
        _message(
            role="assistant",
            content="Because of T1110.",
            citations=({"category": "finding", "source_id": "abc123"},),
            confidence=0.82,
        )
    ]
    exported = render_markdown(case_id="case-1", session_id="session-1", messages=messages)
    text = exported.content.decode("utf-8")
    assert "finding:abc123" in text
    assert "0.82" in text


def test_render_markdown_flags_degraded_answers() -> None:
    messages = [_message(role="assistant", degraded=True)]
    exported = render_markdown(case_id="case-1", session_id="session-1", messages=messages)
    text = exported.content.decode("utf-8")
    assert "degraded" in text.lower()


def test_export_conversation_dispatches_json() -> None:
    exported = export_conversation(
        format="json", case_id="c", session_id="s", messages=[_message()]
    )
    assert exported.media_type == "application/json"


def test_export_conversation_dispatches_markdown() -> None:
    exported = export_conversation(
        format="markdown", case_id="c", session_id="s", messages=[_message()]
    )
    assert exported.media_type == "text/markdown"


def test_export_conversation_rejects_unsupported_format() -> None:
    with pytest.raises(ValueError, match="Unsupported"):
        export_conversation(format="pdf", case_id="c", session_id="s", messages=[_message()])
