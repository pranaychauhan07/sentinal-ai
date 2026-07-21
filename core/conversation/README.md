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
  `ConversationSession`, `ConversationAuditEvent`.
- `exceptions.py` — narrow exception hierarchy.
- `retrieval.py` — `RetrievalLayer`, the "Retrieval Layer" requirement:
  deterministic keyword-relevance scoring of already-hydrated case data
  (Findings/IOCs/MITRE mappings/Reports/Timeline events) against a question.
- `tool_selection.py` — `ToolSelectionEngine`, the "Tool Selection Engine"
  requirement: deterministic keyword routing from a question to which
  retrieval categories apply.
- `context_builder.py` — `ConversationContextBuilder`, the "Context Builder"
  requirement: rank by relevance, truncate to a character budget.
- `prompt_builder.py` — `PromptBuilder`, the "Prompt Builder" requirement:
  assembles system instructions + ranked context + history + question.
- `llm_provider.py` — `ChatModelProvider` (blueprint §5's "pluggable
  `ModelProvider` interface," first defined here) + `TemplateChatModelProvider`,
  a deterministic, non-generative default implementation. No external LLM
  client is integrated this session (explicit task scope).
- `citation_engine.py` — `CitationEngine`, the "Citation Engine"
  requirement: attaches a verified `SourceReference` to every claim, never a
  fabricated one.
- `response_orchestrator.py` — `ResponseOrchestrator`, the "Response
  Orchestrator" requirement: calls the injected `ChatModelProvider`, attaches
  citations, and computes the deterministic confidence score.
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
- `metrics.py` — `ConversationMetricsCollector`, observability, mirroring
  every other leaf package's established shape.

**Never bypasses the deterministic investigation pipeline:** this package
only ever reads already-persisted, already-computed case data (Findings,
IOCs, MITRE mappings, Reports, Timeline events); it triggers no new
analysis, agent run, or scoring — it is a read-only orchestration layer over
what the Case Investigation pipeline already produced.

**Deliberately NOT built this session:** a real OpenAI/Gemini/Ollama
`ChatModelProvider` implementation (explicit task instruction — interface
only); persisted conversation history/audit rows (ADR-0010's existing,
deliberate scope); streaming responses; the `apps/web` chat UI page
(`6_AI_Analyst_Chat.py` stays a future M6 UI milestone item); authentication
(uses the existing `get_current_user` placeholder, unchanged).

**Why it exists:** Turns every already-built specialist agent's output into
something an analyst can actually converse with, grounded and cited, per
blueprint §2's differentiation goal (a real platform, not disconnected
demo modules) and §13's explicit AI Analyst Chat requirement.

**Future expansion:** A real `ChatModelProvider` (OpenAI/Gemini/Ollama),
persisted conversation history (swap `InMemoryConversationMemory` for a
DB-backed implementation behind the same Protocol), semantic (embedding-based)
retrieval in place of keyword overlap, streaming responses, and the
`apps/web` chat UI.
