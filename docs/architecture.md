# Architecture

This document summarizes the system architecture for day-to-day engineering
reference. The authoritative design rationale — why each layer/technology was
chosen — lives in **[`context/01_blueprint.md`](../context/01_blueprint.md)**
§4–§9; this file is the working index into it, kept in sync as `core/` is
built out.

**Implementation status (see `docs/roadmap.md`):** Configuration
(`core/config`), Logging (`core/logging`), the shared contracts
(`core/exceptions.py`, `core/schemas.py`, `core/interfaces.py`), the
Database Layer's connection/session/repository foundation (`core/db`), and
the full API Layer (`apps/api`) are implemented and tested. The **Multi-Agent
Framework** — `core/graph` (`state.py`, `workflow_engine.py`, `router.py`,
`investigation_graph.py`, `events.py`, `retry.py`, `failure_recovery.py`,
`metrics.py`, `execution_context.py`), `core/agents` (`base.py`,
`registry.py`, `confidence.py`, `contracts.py`, `coordinator.py`,
`planning_agent.py`), `core/tools` (`base.py`, `registry.py`), and
`core/memory/interfaces.py` — is implemented and tested (see ADR-0009),
built ahead of the milestone schedule as pure infrastructure: zero domain
reasoning, zero concrete specialist agent. `core/parsers`, `core/knowledge`,
`core/security`, `core/reporting`, and `apps/web` are still folder-level
scaffolding (a `README.md` each) — Milestone M1 onward.

## Layered architecture

```
Frontend (apps/web)          Streamlit multi-page app
        │
API (apps/api)                FastAPI service boundary (same core/services)
        │
Workflow (core/graph)         LangGraph StateGraph — the Case Investigation Graph
        │
Agents (core/agents)          Coordinator + 12 specialist/support agents
        │
Tools (core/tools)            Deterministic functions agents call — never LLM math
        │
Parsers (core/parsers)        Format-specific extractors → typed NormalizedEvidence
        │
Knowledge (core/knowledge)    MITRE ATT&CK, OWASP Top-10, CVSS calculator (read-only)
        │
Memory (core/memory)          short_term (case scratchpad) + long_term (ChromaDB)
        │
Security (core/security)      prompt_guard, pii_redaction, approval_gate
        │
Database (core/db)            PostgreSQL via SQLAlchemy — system of record
        │
Reporting (core/reporting)    Jinja2 → ReportLab PDF, Plotly charts
        │
Conversation (core/conversation)  AI Analyst Chat pipeline (retrieval →
                                   context → prompt → response → citation),
                                   on-demand via core/services/
                                   conversation_service.py — not a graph node
```

Full ASCII box diagram: blueprint §4. Mermaid source for the rendered version:
`docs/diagrams/architecture.mmd` (render with `scripts/generate_diagrams.sh`).

## The one rule that keeps this architecture real

`core/` never imports `streamlit` or `fastapi`. Both `apps/web` and `apps/api`
call the same `core/services/*` functions. See `docs/dependency-rules.md` for
the enforced layer-communication matrix and how it's checked in CI.

## Multi-agent framework internals

`docs/diagrams/multi-agent-framework.mmd` diagrams agent communication,
execution flow, state flow, and workflow lifecycle for the framework
described above. Design rationale: `docs/adr/0009-multi-agent-framework-shape.md`.

## Data flow (evidence → report)

See `docs/threat-pipeline.md` for the full 12-step walkthrough (blueprint §9),
from evidence upload through Memory Agent write-back.

## Central data model

`Case → Evidence → Finding → TimelineEvent`, with `MitreTechnique` as a
reference table and `Report` recording generated PDF metadata. Full schema:
blueprint §8, implemented in `core/db/models.py`.

## Where to go next

- New agent? Read `docs/agent-design.md`, then `core/agents/README.md`.
- New evidence format? `core/parsers/README.md`.
- Changing a cross-cutting decision (DB, memory, LLM provider)? Check
  `docs/adr/` first — it may already be decided, or needs a new ADR.
