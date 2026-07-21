# core/conversation — AI Investigation Assistant Pipeline

**Purpose:** The deterministic orchestration engine behind blueprint §13's
AI Analyst Chat — free-form, case-scoped Q&A "grounded in that case's actual
findings via retrieval, not a generic chatbot." See
`docs/adr/0025-ai-investigation-assistant-conversational-interface.md` for
the full architecture reasoning, including why this package deliberately
stays `core/memory`/`core/db`/`core/security`-free (unlike a typical leaf,
it composes with those layers only through the service boundary).

**Responsibility (built this session):**

- `models.py` — every typed contract this package's functions read and
  write: `ConversationRetrievalContext` (the normalized input, mirroring
  `core.reporting.inputs.ReportGenerationContext`), `RetrievedItem`/
  `SourceReference`, `ToolSelection`, `AssembledConversationContext`,
  `PromptPayload`, `ChatCompletion`, `ConversationAnswer`,
  `ConversationSession`, `ConversationAuditEvent`. `EvidenceCategory` gained
  `KNOWLEDGE`/`SIMILAR_CASE` (ADR-0027).
- `exceptions.py` — narrow exception hierarchy; gained `ChatProviderError`
  (ADR-0027).
- `retrieval.py` — `RetrievalLayer`, the "Retrieval Layer" requirement:
  deterministic keyword-relevance scoring of already-hydrated case data
  (Findings/IOCs/MITRE mappings/Reports/Timeline events), plus (ADR-0027)
  Knowledge Layer search results and cross-case long-term-memory matches,
  against a question.
- `tool_selection.py` — `ToolSelectionEngine`, the "Tool Selection Engine"
  requirement: deterministic keyword routing from a question to which
  retrieval categories apply, including the two ADR-0027 additions.
- `context_builder.py` — `ConversationContextBuilder`, the "Context Builder"
  requirement: deduplicate (ADR-0027 — drops near-identical text once more
  than one retrieval source can plausibly surface the same content) → rank
  by relevance → truncate to a character budget.
- `prompt_builder.py` — `PromptBuilder`, the "Prompt Builder" requirement:
  assembles system instructions + ranked context + history + question; the
  system instructions now explicitly ask the model to reproduce each
  context line's bracket tag when citing it (ADR-0027, so a real LLM's
  citations are independently verifiable).
- `llm_provider.py` — `ChatModelProvider` (blueprint §5's "pluggable
  `ModelProvider` interface") + `TemplateChatModelProvider` (deterministic
  default/fallback) + (ADR-0027) real `OpenAIChatModelProvider`/
  `GeminiChatModelProvider`/`OllamaChatModelProvider` and
  `build_chat_model_provider`/`default_chat_model_provider` selecting among
  them per `Settings.llm_provider`, with graceful fallback to the template
  provider when unconfigured or (Ollama) unreachable.
- `citation_engine.py` — `CitationEngine`, the "Citation Engine"
  requirement: attaches a verified `SourceReference` to every claim, never a
  fabricated one.
- `response_orchestrator.py` — `ResponseOrchestrator`, the "Response
  Orchestrator" requirement: calls the injected `ChatModelProvider`, attaches
  citations, computes the deterministic confidence score, and (ADR-0027)
  catches a `ChatProviderError` to fall back to the template provider for
  that one request rather than crashing the pipeline.
- `session_manager.py` — `SessionManager`, the "Session Manager"
  requirement: process-local chat-session metadata tracking, mirroring
  `core.memory.conversation_memory.InMemoryConversationMemory`'s identical
  single-process scope (ADR-0010).
- `conversation_manager.py` — `ConversationManager`, the "Conversation
  Manager" requirement and this package's pipeline orchestrator: tool
  selection -> retrieval -> context assembly -> prompt build ->
  `ResponseOrchestrator` -> `ConversationAnswer`.
- `audit.py` — `log_conversation_audit_event`/`timed_execution`, the
  "Conversation Audit Log" requirement: structured `structlog` events, no
  new DB table (blueprint §8 does not name one; ADR-0010 already scoped
  chat history to in-memory storage deliberately).
- `metrics.py` — `ConversationMetricsCollector`, observability; gained
  LLM-call and retrieval-quality (dedup/truncation) counters (ADR-0027).

**Never bypasses the deterministic investigation pipeline:** this package
only ever reads already-persisted, already-computed case data (Findings,
IOCs, MITRE mappings, Reports, Timeline events, plus ADR-0027's Knowledge
Layer/cross-case results); it triggers no new analysis, agent run, or
scoring — it is a read-only orchestration layer over what the Case
Investigation pipeline already produced.

**Deliberately NOT built:** persisted conversation history/audit rows
(ADR-0010's existing, deliberate scope); streaming responses; the
`apps/web` chat UI page (`6_AI_Analyst_Chat.py` stays a future milestone
item); authentication (uses the existing `get_current_user` placeholder,
unchanged); a graph-integrated Memory Agent surfacing "similar past cases"
automatically at investigation start (ADR-0027 — this package's
`SIMILAR_CASE` category is chat-triggered, on-demand, not automatic).

**Why it exists:** Turns every already-built specialist agent's output into
something an analyst can actually converse with, grounded and cited, per
blueprint §2's differentiation goal (a real platform, not disconnected
demo modules) and §13's explicit AI Analyst Chat requirement.

**Future expansion:** persisted conversation history (swap
`InMemoryConversationMemory` for a DB-backed implementation behind the same
Protocol), streaming responses, the `apps/web` chat UI, and a
graph-integrated Memory Agent (blueprint §7).
