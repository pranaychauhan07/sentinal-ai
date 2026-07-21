# ADR-0025: AI Investigation Assistant (Conversational Interface)

**Status:** Accepted
**Date:** 2026-07-21

## Purpose

Blueprint §13 names the **AI Analyst Chat**: *"Free-form Q&A scoped to the
current case ('explain finding #4', 'why was this scored High?') — grounded
in that case's actual findings via retrieval, not a generic chatbot."*
`docs/roadmap.md` places it in **M6**, alongside ChromaDB long-term memory
and the Threat Timeline UI. This session builds the backend orchestration
layer for that feature — the "AI Investigation Assistant" — per an explicit
task brief naming ten required components: Conversation Manager, Session
Manager, Conversation Memory, Context Builder, Prompt Builder, Retrieval
Layer, Tool Selection Engine, Response Orchestrator, Citation Engine, and
Conversation Audit Log.

**A pre-implementation check found most of the generic memory
infrastructure already exists.** ADR-0010 (Memory & Knowledge Layer Shape)
already built, specifically anticipating this feature: `core.memory.
conversation_memory.ConversationMemory`/`InMemoryConversationMemory` (chat
turn storage, case-scoped), `core.memory.context_builder.ContextBuilder`
(generic filter → dedup → rank → truncate assembly over `MemoryRecord`), and
`core.memory.manager.MemoryManager` (the facade both already expose
`get_conversation`/`add_conversation_turn`/`build_context`/`render_context`
methods for). Per constitution §14.9 ("never duplicate functionality"), this
session reuses these directly rather than rebuilding a second conversation
store or a second generic context-ranking algorithm. What does not yet exist
— and is this session's actual scope — is the case-data **retrieval** that
turns persisted Findings/IOCs/MITRE mappings/Reports/Timeline into
citable content, the **prompt construction** that turns that content plus a
question into an LLM-ready payload, the **tool selection** that decides
which case-data categories a given question needs, the **response
orchestration** behind a pluggable (not-yet-implemented) LLM provider, and
the **citation** discipline that ties every claim in an answer back to a
concrete source record.

## Decision

### 1. `core/conversation/` is a new leaf package — but a different kind of leaf than `core/reporting`/`core/incident_response`

Every existing leaf in `docs/dependency-rules.md` rule 5's list (`core/tools`,
`core/parsers`, `core/threat_intel`, `core/findings`, `core/vulnerabilities`,
`core/linux_security`, `core/linux_advisor`, `core/owasp_web`,
`core/owasp_security`, `core/incident_response`, `core/reporting`) is
explicitly forbidden from importing `core/memory`. This assistant's very
purpose is to sit on top of `ConversationMemory`/`ContextBuilder`, so
`core/conversation` **cannot** be a member of that list without duplicating
memory-layer logic ADR-0010 already built. Resolution, following the same
"give the shared concept its home, don't force a cycle" rule (constitution
§3, "Circular dependency prevention"): `core/conversation` stays a pure,
`core/memory`-free leaf exactly like the others (it only ever receives
already-fetched case data and already-fetched conversation history as plain
Pydantic/`dict` input — it never itself calls `ConversationMemory` or
`MemoryManager`). The one new module that *does* need `core/memory` — and
`core/db` for retrieval, and `core/security` for prompt-injection screening
— is `core/services/conversation_service.py`, via a new, narrowly-scoped
dependency-rules exception (**rule 4j**, worded identically to 4a-4i's
established shape). This is the same "on-demand service, not a graph node"
shape ADR-0024 offered as its recommended (if not chosen) alternative — and
the obviously correct one here, since the AI Analyst Chat is explicitly a
user-triggered, on-demand action (blueprint §13), never part of the
automatic per-upload investigation pipeline. No `AskUserQuestion` was needed
this session: unlike ADR-0022's/ADR-0024's genuine two-way forks, this
shape has only one reasonable answer given blueprint §13's own wording
("Free-form Q&A" a user types on demand, not a per-upload agent) and the
already-established rule-4-family precedent for exactly this kind of
"deterministic-ish orchestration reaching into `core/db`/`core/memory`"
service.

### 2. Component-to-file mapping (the task's ten named requirements)

| Requirement | Home | Notes |
|---|---|---|
| Conversation Memory | `core.memory.conversation_memory` (existing) | Reused as-is, not rebuilt. |
| Session Manager | `core/conversation/session_manager.py` | New — tracks active chat sessions (id, case_id, timestamps, turn count) as a process-local registry, mirroring `InMemoryConversationMemory`'s identical "single-analyst, single-process" scope (ADR-0010). Distinct from turn *content* storage (that's `ConversationMemory`'s job). |
| Retrieval Layer | `core/conversation/retrieval.py` | New — turns an already-hydrated `ConversationRetrievalContext` (Findings/IOCs/MITRE mappings/Reports/Timeline, as plain dicts) into scored, citable `RetrievedItem`s. Never queries the DB itself (that's the service's job, mirroring `core.reporting.section_builders`'s identical "operates on an already-hydrated context" shape). |
| Tool Selection Engine | `core/conversation/tool_selection.py` | New — deterministic keyword routing from question text to which retrieval categories apply (constitution §1.9: a fixed, checkable answer, never an LLM's job). |
| Context Builder | `core/conversation/context_builder.py` | New — ranks/truncates `RetrievedItem`s to a character budget. A distinct, smaller assembly step from `core.memory.context_builder.ContextBuilder` (which operates on `MemoryRecord`s, a different, memory-layer-owned shape) — not a duplicate per ADR-0010's own precedent for keeping `ConversationMemory` distinct from `CaseMemory`. |
| Prompt Builder | `core/conversation/prompt_builder.py` | New — assembles system instructions + ranked context + conversation history + the (already prompt-guard-screened) question into a `PromptPayload`. |
| Response Orchestrator | `core/conversation/response_orchestrator.py` + `llm_provider.py` | New — `ChatModelProvider` Protocol (the blueprint §5 "pluggable `ModelProvider` interface," first defined this session) plus one concrete, deterministic `TemplateChatModelProvider` (never a network call — see Decision 3). |
| Citation Engine | `core/conversation/citation_engine.py` | New — attaches a `SourceReference` to every retrieved item actually surfaced in the answer; an answer with zero available evidence carries zero citations and is marked `degraded`, never a fabricated citation. |
| Conversation Manager | `core/conversation/conversation_manager.py` | New — the pipeline orchestrator: tool selection → retrieval → context build → prompt build → response orchestration → citation → `ConversationAnswer`. |
| Conversation Audit Log | `core/conversation/audit.py` | New — structured `structlog` audit events (question asked, categories selected, sources cited, confidence, degraded flag), mirroring every other leaf's `audit.py` shape (`core/incident_response/audit.py`, `core/reporting/audit.py`). No new DB table — see Decision 4. |

`core/conversation/metrics.py` (timing/hit-miss counters) and
`core/conversation/models.py`/`exceptions.py` round out the package,
mirroring every prior leaf's shape.

### 3. LLM provider: interface only, per explicit task instruction

`core/conversation/llm_provider.py` defines `ChatModelProvider` (a
`Protocol`: `generate(prompt: PromptPayload) -> ChatCompletion`) — the
concrete realization of blueprint §5's "LLM ... pluggable via a
`ModelProvider` interface" for this feature, selectable via
`core.config.settings.Settings.llm_provider` (the `LLMProvider` `StrEnum`
already scaffolded there). No OpenAI/Gemini/Ollama client is implemented
this session (explicit task instruction). The default, always-available
implementation is `TemplateChatModelProvider` — **not a stub that raises**,
but a genuinely deterministic, non-generative provider that composes an
answer directly from the ranked retrieved evidence (constitution §1.9: never
LLM freeform reasoning where a fixed, checkable answer will do). This keeps
the whole pipeline runnable and testable today without any external
dependency or network call, and structurally guarantees "never hallucinate
unavailable data": the only content substrate available to compose is
verified, retrieved case data.

### 4. No new persisted tables

Blueprint §8's DB design does not name a conversation/chat-message table
(unlike `IncidentResponsePlan`/`Report`, which ADR-0023/0024 confirmed
blueprint literally names). ADR-0010 already made this call explicitly for
turn storage ("a persisted implementation is a drop-in swap behind the same
Protocol later" — deliberately deferred). This session does not revisit that
scope: conversation turns stay in `InMemoryConversationMemory`; the
Conversation Audit Log is structured log output (constitution §8), not a new
table. This keeps the feature's scope honest to what blueprint actually
requires today and avoids inventing schema blueprint doesn't name.

### 5. Retrieval sources and the "never hallucinate" guarantee

`core/services/conversation_service.py` hydrates a `ConversationRetrievalContext`
from: `FindingRepository.find_by_case` (findings + their `mitre_mappings`,
reading `finding_data_json` directly — the identical "read the JSON blob,
never import `core.findings.models`" pattern `case_service.py`'s
`_hydrate_mitre_mapping_records` established), `IOCRepository.find_by_case`,
`ReportRepository.find_by_case`, and `TimelineEventRepository.find_by_case`.
If a case has none of these yet, the Conversation Manager returns a
`degraded=True`, zero-citation "insufficient evidence" answer — never a
guess — exactly matching every prior agent's documented "unmapped"/
"insufficient-evidence" failure mode (constitution §4.7).

### 6. Prompt-injection guarding happens at the service boundary, not inside `core/conversation`

A chat message is exactly the kind of untrusted, analyst/attacker-adjacent
text constitution §10 requires `core/security/prompt_guard.py` screen
before any LLM interpolation. Since `core/conversation` is a `core/memory`-
free, and therefore also intentionally minimal-dependency, leaf (Decision
1), it does not import `core/security` either — the guard runs in
`core/services/conversation_service.py` (which already needs the rule-4j
exception for `core/memory`/`core/db`) before the raw question ever reaches
`PromptBuilder`. A flagged question is still answered (never silently
dropped) but the flag and matched categories are recorded in the audit log
and returned to the caller, mirroring `PhishingAgent`'s established
"screen, don't silently discard" precedent.

### 7. API surface: one new on-demand action-trigger endpoint

`POST /api/v1/cases/{case_id}/conversation` (constitution §6's one
sanctioned "action modeled as a resource-creation POST" pattern, identical
in kind to `POST /cases/{case_id}/evidence`). No streaming (explicit task
instruction — a single request/response), no new auth (existing
`get_current_user` placeholder, unchanged).

## Alternatives Considered

- **A `ConversationAgent` graph node**, wired like `MitreMappingAgent`/
  `ReportGeneratorAgent`. Rejected: those agents all regenerate
  automatically on every evidence upload; a chat question is inherently a
  one-off, user-initiated request with a natural-language argument (the
  question itself) that doesn't fit the `CaseInvestigationState`-in/out node
  contract without inventing an awkward "the question is somehow already in
  state" fiction. The on-demand service shape ADR-0024 already offered (and
  the user could have chosen) as an alternative is the correct shape here.
- **Add `core/conversation` to rule 5's `core/knowledge`-permitted leaf list
  and give it `core/memory` too.** Rejected: rule 5 explicitly enumerates
  which leaves may import `core/knowledge` and explicitly states none of
  them import `core/memory`; extending that blanket grant to a new package
  whose entire purpose is memory access would blur, not clarify, the
  boundary rule 8 exists to protect (leaves stay leaves; only services reach
  down into multiple leaf-adjacent layers at once).
  Keeping `core/conversation` memory-free and pushing memory access to the
  service (rule 4j) preserves the existing shape exactly.
- **Persist conversation turns to Postgres now.** Rejected per Decision 4 —
  not blueprint-named, and ADR-0010 already made this exact call
  deliberately.
- **Integrate a real OpenAI/Gemini/Ollama client this session.** Explicitly
  out of scope per the task brief ("create provider interfaces only").

## Consequences

**Easier:** An analyst can ask grounded, cited, case-scoped questions today,
answered entirely from already-persisted, already-verified case data, with
zero risk of fabricated facts (the default provider is non-generative by
construction) and a clear extension seam (`ChatModelProvider`) for a real
LLM later — a provider swap, not a pipeline rewrite, the same
swappability property every other pluggable seam in this codebase
(`VectorMemory`, `ModelProvider` per blueprint §5) is built for.

**Harder / foreclosed:** Answers are template-composed, not fluently
synthesized prose, until a real `ChatModelProvider` is implemented (a future
session, gated on the task's own explicit "do not integrate yet"
instruction) — a reviewer must not mistake "the interface is implemented"
for "a production-quality conversational experience exists," the identical
caution ADR-0010 already stated for its in-memory vector store. No
streaming, no persisted chat history across process restarts (single-
process, single-analyst scope, unchanged from ADR-0010), no frontend chat
UI (explicit task instruction; blueprint §13's `apps/web/pages/
6_AI_Analyst_Chat.py` stays a future M6 UI milestone item, unimplemented).

**Never touched:** `core/graph/workflow_engine.py`, `core/graph/routing.py`,
`core/agents/*`, `core/memory/*` (used, not modified), and every prior
specialist agent/framework — extended by one new, independent, on-demand
service, never redesigned into.
