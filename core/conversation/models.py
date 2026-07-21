"""Typed contracts for `core/conversation` — every function in this package
reads and writes these shapes, never a bare dict crossing a public function
boundary (constitution §2, §4.3).

Every field here is either already-computed elsewhere (case data reduced to
plain dicts by `core/services/conversation_service.py`, mirroring
`core.reporting.inputs.ReportGenerationContext`'s identical role) or is this
package's own small, deterministic derivation (relevance scores, citations,
confidence) — never an LLM-derived value (constitution §1.9).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class EvidenceCategory(StrEnum):
    """Which case-data category a `RetrievedItem` came from — the single
    axis `ToolSelectionEngine` routes on and `RetrievalLayer` groups by."""

    FINDING = "finding"
    IOC = "ioc"
    MITRE_MAPPING = "mitre_mapping"
    REPORT = "report"
    TIMELINE_EVENT = "timeline_event"


class ConversationRetrievalContext(BaseModel):
    """Normalized, already-computed case data handed to
    `RetrievalLayer.retrieve` — mirrors `core.reporting.inputs.
    ReportGenerationContext`'s role exactly: this package performs no
    severity/risk/confidence/MITRE derivation of its own, only retrieval,
    ranking, and citation."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    findings: tuple[dict[str, object], ...] = ()
    iocs: tuple[dict[str, object], ...] = ()
    mitre_mappings: tuple[dict[str, object], ...] = ()
    reports: tuple[dict[str, object], ...] = ()
    timeline_events: tuple[dict[str, object], ...] = ()
    #: Count of malformed/skipped source records the service already
    #: dropped before building this context — feeds this package's
    #: confidence rollup, mirroring `core.incident_response.
    #: confidence_calculator`'s identical discount-by-skipped-fraction shape.
    skipped_record_count: int = Field(default=0, ge=0)


class SourceReference(BaseModel):
    """One concrete, checkable pointer back to a persisted case record —
    the unit `CitationEngine` attaches to an answer. Never fabricated: a
    `SourceReference` only ever exists because a `RetrievedItem` with this
    exact `(category, source_id)` was actually retrieved."""

    model_config = ConfigDict(frozen=True)

    category: EvidenceCategory
    source_id: str
    summary: str


class RetrievedItem(BaseModel):
    """One case-data record, scored for relevance to the current question —
    `RetrievalLayer`'s output unit."""

    model_config = ConfigDict(frozen=True)

    category: EvidenceCategory
    source_id: str
    text: str
    relevance_score: float = Field(ge=0.0, le=1.0)
    reference: SourceReference


class ToolSelection(BaseModel):
    """`ToolSelectionEngine`'s output — which categories apply to the
    current question, and why (the ReAct-style `thought`, constitution
    §4.3)."""

    model_config = ConfigDict(frozen=True)

    categories: tuple[EvidenceCategory, ...]
    thought: str


class AssembledConversationContext(BaseModel):
    """`ConversationContextBuilder.assemble`'s output — the ranked,
    budget-truncated subset of `RetrievedItem`s actually sent to the prompt."""

    model_config = ConfigDict(frozen=True)

    items: tuple[RetrievedItem, ...]
    total_candidates: int
    truncated: bool


class ConversationHistoryTurn(BaseModel):
    """One prior chat turn, passed in as plain data (the service reads the
    real history from `core.memory.conversation_memory.ConversationMemory`;
    this package never imports that module itself — see
    docs/adr/0025-ai-investigation-assistant-conversational-interface.md
    Decision 1)."""

    model_config = ConfigDict(frozen=True)

    role: str
    content: str


class PromptPayload(BaseModel):
    """`PromptBuilder`'s output — the fully-assembled, LLM-ready payload.
    `question` has already passed through `core.security.prompt_guard`
    before this object is constructed (the service's job, not this
    package's — Decision 6)."""

    model_config = ConfigDict(frozen=True)

    system_instructions: str
    context_text: str
    history_text: str
    question: str
    prompt_injection_flagged: bool = False


class ChatCompletion(BaseModel):
    """One `ChatModelProvider.generate` result — the raw answer text before
    citation attachment."""

    model_config = ConfigDict(frozen=True)

    answer_text: str
    #: Which `RetrievedItem.source_id`s the provider actually drew on to
    #: compose `answer_text` — `TemplateChatModelProvider` reports every
    #: item it templated in; a future real LLM provider would report
    #: whichever items its structured tool-calling response named
    #: (constitution §10, "Output validation" — never trusted freeform).
    used_source_ids: tuple[str, ...] = ()


class ConversationAnswer(BaseModel):
    """`ConversationManager.answer`'s final output — what
    `core/services/conversation_service.py` returns to its caller."""

    model_config = ConfigDict(frozen=True)

    answer_text: str
    citations: tuple[SourceReference, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0)
    degraded: bool
    selected_categories: tuple[EvidenceCategory, ...] = ()
    prompt_injection_flagged: bool = False


class ConversationSession(BaseModel):
    """One tracked chat session — `SessionManager`'s unit. Metadata only
    (no turn content — that lives in `ConversationMemory`)."""

    model_config = ConfigDict(frozen=True)

    session_id: UUID = Field(default_factory=uuid4)
    case_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_active_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    turn_count: int = Field(default=0, ge=0)

    def touched(self) -> ConversationSession:
        """Returns a new session with `last_active_at` refreshed and
        `turn_count` incremented — sessions are frozen, so "touching" one
        never mutates it in place (constitution §2, avoids shared mutable
        state across concurrent readers)."""
        return self.model_copy(
            update={"last_active_at": datetime.now(UTC), "turn_count": self.turn_count + 1}
        )


class AuditEventAction(StrEnum):
    """Closed set of audit-log actions this package emits — constitution
    §2's "Enums" rule, mirroring `core.incident_response.audit.AuditAction`."""

    SESSION_STARTED = "session_started"
    QUESTION_RECEIVED = "question_received"
    PROMPT_INJECTION_FLAGGED = "prompt_injection_flagged"
    CATEGORIES_SELECTED = "categories_selected"
    CONTEXT_ASSEMBLED = "context_assembled"
    ANSWER_GENERATED = "answer_generated"
    ANSWER_DEGRADED = "answer_degraded"


class ConversationAuditEvent(BaseModel):
    """One structured audit-log entry — the typed shape
    `audit.log_conversation_audit_event` emits, kept here so tests can
    assert on it without parsing log strings."""

    model_config = ConfigDict(frozen=True)

    action: AuditEventAction
    case_id: str
    session_id: str | None = None
    detail: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
