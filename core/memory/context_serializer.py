"""`ContextSerializer` — turns an `AssembledContext` (`context_builder.py`)
into the concrete shapes downstream consumers need: prompt-ready text for an
LLM call, or a structured dict for logging/inspection/the future
Investigation Trail UI.

Kept separate from `ContextBuilder` per constitution Principle 3 (a module
does one thing): assembly decides *what* belongs in context; serialization
decides *how it's rendered*, and a new rendering (e.g. a future
provider-specific chat-message-list format) is a new method here, not a
change to the assembly logic.
"""

from __future__ import annotations

from typing import Any

from core.memory.context_builder import AssembledContext


class ContextSerializer:
    """Stateless formatting of an `AssembledContext`."""

    def to_prompt_text(self, context: AssembledContext) -> str:
        """Plain-text block suitable for interpolation into an LLM prompt.

        Each record is rendered as `[scope] content` on its own line, sorted
        exactly as `ContextBuilder.rank` ordered them (most important/recent
        first) — callers must not silently re-sort this output.
        """
        if not context.records:
            return ""
        lines = [f"[{record.scope.value}] {record.content}" for record in context.records]
        return "\n".join(lines)

    def to_dict(self, context: AssembledContext) -> dict[str, Any]:
        """Structured representation for logging or UI rendering — every
        field is JSON-serializable (Pydantic `.model_dump(mode="json")`)."""
        return {
            "records": [record.model_dump(mode="json") for record in context.records],
            "total_candidates": context.total_candidates,
            "truncated": context.truncated,
            "record_count": len(context.records),
        }
