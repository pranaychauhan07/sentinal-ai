# ADR-0029: Conversation Persistence, Compression, Export

**Status:** Accepted
**Date:** 2026-07-22

## Purpose

A follow-up task asked for the AI Investigation Copilot / Case Chat System
again. A pre-implementation check (per this project's "never redesign
completed modules" rule and constitution §14.9) confirmed the ten-component
pipeline named in that task (Conversation Manager, Session Manager, Retrieval
Pipeline, Tool Calling Layer, Response Grounding/Citation, Response
Validation, Confidence Scoring, Conversation Audit Logging, Memory Agent,
Knowledge Retrieval) was already fully built across ADR-0025, its addendum,
ADR-0027, and ADR-0028 — presented to the user as a conflict via
`AskUserQuestion` rather than silently rebuilt. The user chose to close only
the genuine, previously-documented gaps: DB-persisted conversation history
(ADR-0010 and `core/conversation/README.md` both explicitly deferred this —
"a persisted implementation is a drop-in swap behind the same Protocol
later"), conversation summarization/compression/token budgeting for long
conversations, conversation export, and progressive answer delivery
("streaming," scoped per the resolution below). Search/replay/analytics were
added as read paths over the same new persisted data, since building storage
without a way to read it back would be an incomplete slice.

## Decision

1. **Persistence lands inside `core/memory`, not `core/db`.** `core/memory`
   already owns exactly this seam for `MemoryRecord`
   (`core/memory/db_models.py` + `core/memory/repository.py`, both importing
   `core.db.session.Entity` / `core.db.base_repository.BaseRepository`
   directly) — a leaf package with its own narrow persistence, the same way
   `core/db` owns the domain schema. `ConversationSessionRow`/
   `ConversationMessageRow`/`ConversationSummaryRow` (new
   `core/memory/conversation_db_models.py`) and their repositories (new
   `core/memory/conversation_repository.py`) follow this exact,
   already-established pattern. This requires **no new
   `docs/dependency-rules.md` edge**: `core/memory` → `core/db` is already an
   exercised permission (`repository.py` uses it today), and
   `core/services/conversation_service.py` already has rule 4j's grant to
   import `core.memory.conversation_memory` directly.
2. **`DbConversationMemory` implements the existing `ConversationMemory`
   Protocol** (`core/memory/conversation_memory.py`), added alongside
   `InMemoryConversationMemory` rather than replacing it — exactly the
   `ChromaVectorStore`-next-to-`InMemoryVectorStore`/`NullVectorStore` shape
   ADR-0027 already established for `VectorMemory`. The Protocol itself
   gains one additive, defaulted keyword (`session_id: UUID | None = None`)
   on all three methods so a message can be correctly scoped to *one* chat
   session rather than the whole case's undifferentiated turn history — a
   real, if narrow, correctness gap `InMemoryConversationMemory` always had
   (multiple concurrent sessions on one case shared one turn list). Existing
   callers that never pass `session_id` see identical behavior to today
   (case-wide history) on both backends.
3. **A `Settings.conversation_persistence_backend` switch** (`"database"`
   default, `"memory"` opt-out) selects which `ConversationMemory` and which
   `SessionManager`-equivalent `core/services/conversation_service.py`
   constructs by default — a config value, not a code fork, matching
   `Settings.llm_provider`'s existing shape. `SessionManager` itself is left
   untouched; `DbConversationMemory` independently persists
   `ConversationSessionRow` (created on first turn, touched on every
   subsequent one) so session metadata survives a process restart even
   though `SessionManager`'s own in-process cache does not — this is a
   deliberately narrow inconsistency: `SessionManager` remains a hot-path
   convenience cache, `ConversationSessionRow` is the durable record a
   replay/export/analytics read always goes to.
4. **Compression is a new, separate `core/conversation/compression.py`
   module**, not folded into `context_builder.py` (constitution §1.3,
   "small, focused modules": `ConversationContextBuilder` ranks/dedups/
   truncates *retrieved case evidence*; this module manages *prior
   conversation turns*, a different axis entirely). It is deterministic: a
   character-count-based token estimate (`estimate_tokens`, chars/4 — the
   same order-of-magnitude heuristic OpenAI's own docs use for English text,
   good enough for a budgeting decision that only needs to avoid gross
   overflow, not exact accounting) and an extractive summarizer
   (`summarize_turns`) that keeps the most recent N turns verbatim and
   reduces older ones to a bulleted excerpt list — never an LLM call
   (constitution §1.9 extended: conversation history reduction is
   mechanical, not "judgment," so it gets a deterministic function like
   every other reduction step in this pipeline, not a second, harder-to-test
   LLM round-trip per question). `core/services/conversation_service.py`
   calls it when a session's persisted turn count exceeds
   `Settings.conversation_compression_trigger_turns`, persisting the result
   as a `ConversationSummaryRow` (upserted, one per session — the same "1
   row per parent, replaced not appended" cardinality `Report`/
   `IncidentResponsePlanRow` already established) and feeding
   `summary_text + recent raw turns` to `PromptBuilder` instead of the full
   raw history.
5. **Export is a new `core/conversation/export.py` module**, deliberately
   *not* a reuse of `core/reporting`'s Export Framework (ADR-0026): that
   framework's theme/asset/chart machinery exists for a generated
   *investigation report*; a chat transcript is a flat, chronological list
   of role-tagged turns with no charts, themes, or branding concerns. Two
   pure functions (`render_json`, `render_markdown`) take an already-fetched
   list of persisted messages and return bytes — mirroring
   `report_export_service.py`'s "render on request, persist nothing new"
   decision (ADR-0026 Decision 4): there is no `ConversationExport` table:
   the "Conversation Export" capability is an on-demand rendering of
   `ConversationMessageRow` data that already exists, precisely the same
   reasoning that already justified `Report.file_path` staying `NULL`.
6. **"Streaming" is progressive delivery of the already-validated answer,
   not raw LLM token streaming.** The retrieval-before-reasoning ordering
   this system requires, and the Response Validator's job of catching a
   hallucinated citation *before* any text reaches the analyst
   (`core/conversation/response_validator.py`, already shipped), are
   structurally incompatible with streaming an LLM's raw token output to the
   client as it's generated — by the time validation could reject the
   answer, an ungrounded partial answer would already be visible. The new
   `POST /cases/{case_id}/conversation/stream` endpoint therefore runs the
   full, unchanged `ask_question` pipeline synchronously server-side
   (grounding, citation, validation all complete first) and then streams the
   validated `answer_text` back to the client in word-chunks over
   `text/event-stream`, followed by one final event carrying citations/
   confidence/degraded metadata. This is honestly documented as
   "progressive delivery of a pre-validated answer," not "real-time LLM
   streaming" — the latter would require reopening the Response Validator's
   already-shipped, tested design, which is out of this task's scope and not
   something a "close the gaps" task should silently reinterpret.

## Alternatives Considered

- **Persist conversation state inside `core/db` proper** (a fourth, new
  `core/db/models/conversation.py` + `core/db/conversation_repository.py`).
  Rejected: `core/memory` already owns this exact "leaf package with its own
  narrow persistence" role for `MemoryRecord`; adding a second, competing
  home for conversation-adjacent persistence inside `core/db` would be a
  second pattern doing the same job the existing one already does,
  violating constitution §14.9.
- **Fold compression into `context_builder.py`.** Rejected — different
  axis (retrieved evidence vs. prior turns), would violate constitution
  §1.3's "a file does one thing."
- **Real LLM token streaming.** Considered and rejected for this task (see
  Decision 6) — would require redesigning the already-shipped, tested
  Response Validator's placement in the pipeline, which is explicitly out of
  a "close the gaps" task's scope; named as future work below.
- **A persisted `ConversationExport` table.** Rejected — mirrors ADR-0026's
  identical, already-accepted "render on request, persist nothing" decision;
  a redundant persisted copy of already-persisted message data is pure
  duplication with no read benefit this design doesn't already provide.

## Consequences

- Conversation history now survives a process restart and is queryable
  (replay, search, analytics, export) — the actual product gap this session
  closes.
- `InMemoryConversationMemory` remains fully supported (tests, an
  explicit `conversation_persistence_backend=memory` opt-out, offline/dev
  use) — nothing is deleted.
- A long-running chat session's prompt no longer grows unbounded: token
  budgeting + summarization keep `PromptBuilder`'s input bounded even after
  hundreds of turns.
- **Not built, named as future work:** real LLM-token-level streaming (would
  require reopening the Response Validator's pipeline placement, a larger
  architectural question deserving its own ADR if ever pursued); the
  `apps/web` chat UI (still no `apps/web` code exists at all — unrelated to
  this session's scope); a persisted `ConversationExport` artifact table
  (see Alternatives).
