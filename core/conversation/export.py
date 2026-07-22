"""Conversation Export (ADR-0029) — the "Conversation Export" requirement.

Deliberately not a reuse of `core/reporting`'s Export Framework
(ADR-0026): that framework's theme/asset/chart machinery exists for a
generated investigation report; a chat transcript is a flat, chronological
list of role-tagged turns with no charts, themes, or branding concerns.
Two pure functions take already-fetched transcript data and return bytes —
mirroring `core/services/report_export_service.py`'s "render on request,
persist nothing new" decision (no `ConversationExport` table exists; see
docs/adr/0029-conversation-persistence-compression-export.md Decision 5).
"""

from __future__ import annotations

import json
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ExportedMessage(BaseModel):
    """One transcript entry — plain data handed in by the service layer
    (already read from `ConversationMessageRow`), never a DB row itself
    (this package stays `core/memory`/`core/db`-free)."""

    model_config = ConfigDict(frozen=True)

    sequence_index: int
    role: str
    content: str
    created_at: datetime
    citations: tuple[dict[str, object], ...] = ()
    confidence: float | None = None
    degraded: bool = False


class ExportedConversation(BaseModel):
    """The bytes + media type + filename an API route hands back — never a
    bare `bytes` return crossing a public function boundary, mirroring
    `core.reporting.export_manager.ExportedReport`'s shape."""

    model_config = ConfigDict(frozen=True)

    content: bytes
    media_type: str
    filename: str


SUPPORTED_EXPORT_FORMATS: tuple[str, ...] = ("json", "markdown")


def render_json(
    *, case_id: str, session_id: str, messages: list[ExportedMessage]
) -> ExportedConversation:
    payload = {
        "case_id": case_id,
        "session_id": session_id,
        "message_count": len(messages),
        "messages": [m.model_dump(mode="json") for m in messages],
    }
    content = json.dumps(payload, indent=2).encode("utf-8")
    return ExportedConversation(
        content=content,
        media_type="application/json",
        filename=f"conversation-{session_id}.json",
    )


def render_markdown(
    *, case_id: str, session_id: str, messages: list[ExportedMessage]
) -> ExportedConversation:
    lines = [
        f"# Conversation Transcript — Case {case_id}",
        f"Session: `{session_id}`  \nMessages: {len(messages)}",
        "",
    ]
    for message in messages:
        role_label = message.role.upper()
        lines.append(f"### {role_label} — {message.created_at.isoformat()}")
        lines.append("")
        lines.append(_escape_markdown(message.content))
        if message.citations:
            citation_labels = ", ".join(
                f"`{c.get('category', '')}:{c.get('source_id', '')}`" for c in message.citations
            )
            lines.append("")
            lines.append(f"*Citations: {citation_labels}*")
        if message.confidence is not None:
            lines.append(f"*Confidence: {message.confidence:.2f}*")
        if message.degraded:
            lines.append("*This answer was flagged as degraded/low-confidence.*")
        lines.append("")
    content = "\n".join(lines).encode("utf-8")
    return ExportedConversation(
        content=content,
        media_type="text/markdown",
        filename=f"conversation-{session_id}.md",
    )


def _escape_markdown(text: str) -> str:
    """Prevents chat content (which may contain attacker-influenced text,
    e.g. a prompt-injection attempt embedded in a phishing-derived finding
    the analyst asked about) from corrupting the exported document's
    Markdown structure — mirrors
    `core.reporting.markdown_renderer._escape_markdown`'s identical
    reasoning."""
    for char in ("\\", "`", "*", "_", "{", "}", "[", "]", "#", "|"):
        text = text.replace(char, "\\" + char)
    return text


def export_conversation(
    *, format: str, case_id: str, session_id: str, messages: list[ExportedMessage]
) -> ExportedConversation:
    """Format dispatch — the one place a new export format would be added,
    mirroring `core.reporting.export_manager.ExportManager.export`'s shape."""
    if format == "json":
        return render_json(case_id=case_id, session_id=session_id, messages=messages)
    if format == "markdown":
        return render_markdown(case_id=case_id, session_id=session_id, messages=messages)
    raise ValueError(
        f"Unsupported conversation export format: {format!r}. "
        f"Supported formats: {SUPPORTED_EXPORT_FORMATS}."
    )
