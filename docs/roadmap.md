# Roadmap

Milestones as defined in **[`context/01_blueprint.md`](../context/01_blueprint.md)**
§15. Each milestone ends with a genuinely runnable, demoable app. Check boxes
here are updated as milestones complete — this file is the single place
progress is tracked against the plan.

## Versioning / release strategy

Pre-1.0: one tagged release per completed milestone (`v0.1-foundation`,
`v0.2-single-agent`, `v0.3-mitre-phishing`, `v0.4-multi-agent-mvp`,
`v0.5-all-modules`, `v0.6-incident-reporting`, `v0.7-memory-timeline`,
`v1.0`). Post-1.0: Semantic Versioning per `CHANGELOG.md`.

## Milestones

- [x] **M0 — Foundation.** Repo structure, Docker Compose (Postgres +
      ChromaDB), pydantic-settings config, Streamlit page shells, CI
      pipeline, engineering docs, ADRs, sample data, GitHub governance —
      **plus** (ahead of the original M0 scope, completed as its own
      engineering-foundation pass): structured logging
      (`core/logging`), the shared exception/schema/interface contracts
      (`core/exceptions.py`, `core/schemas.py`, `core/interfaces.py`), the
      async database foundation (`core/db`: engine/session management,
      `Entity` base with surrogate UUID keys, generic `BaseRepository`,
      Alembic scaffolding), and the full FastAPI application
      (`apps/api`: app factory, middleware, standardized exception
      handling, `/health` `/ready` `/version`). 72 tests, 98% coverage,
      mypy/ruff/dependency-rules clean. No domain models (`Case`/`Evidence`/
      `Finding`) or agents exist yet — those are M1.
      *Demo: `docker compose up`, then `make run-api` serves a real,
      tested `/health`, `/ready`, `/version` API with OpenAPI docs at `/docs`.*

- [ ] **M1 — First real module, single agent, no orchestration.** Domain
      models (`Case`, `Evidence`, `Finding`, `MitreTechnique`,
      `TimelineEvent`, `Report` — blueprint §8) + first Alembic migration,
      syslog/firewall log parser + SOC Analyst Agent as a standalone
      single-node LangGraph + risk scoring (`core/tools/scoring.py`) +
      persistence via `core/db/base_repository.py`.
      *Demo: upload a firewall log → get a real, saved, severity-classified finding.*

- [ ] **M2 — MITRE mapping + Phishing module.** MITRE knowledge layer + MITRE
      Agent; Phishing Investigation Agent + email parser + prompt-injection
      guard (first attacker-controlled-text agent).
      *Demo: two independent working modules, each producing a mapped/scored finding.*

- [ ] **M3 — Multi-agent orchestration.** Coordinator + Planning Agent + full
      LangGraph StateGraph wiring; automatic evidence-type routing.
      **Built ahead of schedule** (`docs/adr/0009-multi-agent-framework-shape.md`):
      the full reusable framework — `BaseAgent`/`BaseTool`, `AgentRegistry`/
      `ToolRegistry`, `CoordinatorAgent`/`PlanningAgent`, `WorkflowEngine`
      (real compiled LangGraph `StateGraph` with retry/failure-recovery/
      events/metrics), `routing.py`, memory interfaces — is implemented and
      tested (86 tests) with zero domain logic and no concrete specialist
      agent. Still not checked off: the milestone's own demo criterion
      (upload mixed *real* evidence, e.g. a log + an email, and watch the
      Coordinator fan out to *real* SOC Analyst/Phishing agents) needs M1's
      and M2's concrete agents/parsers first, which don't exist yet.
      *Demo: upload mixed evidence (log + email) to one Case; Coordinator fans out automatically.*

- [ ] **M4 — Remaining specialist modules.** Vulnerability Assessment Agent
      (+ Nmap/Nessus/OpenVAS parsers + CVSS calculator), OWASP Security Agent
      (AST-based), Linux Security Agent, Threat Hunting Agent.
      *Demo: all 9 required modules functioning through the same Coordinator.*

- [ ] **M5 — Incident Response synthesis + Reporting.** Incident Response
      Agent (case-wide synthesis), Report Generator Agent with Jinja2/
      ReportLab templates per module + executive report, Plotly charts.
      *Demo: full case → "Generate Executive Report" → real branded PDF with charts.*

- [ ] **M6 — Memory + Threat Timeline + UX polish.** ChromaDB long-term
      memory, Threat Timeline cross-evidence view, MITRE ATT&CK heatmap,
      case-scoped AI Analyst Chat.
      **Built ahead of schedule** (`docs/adr/0010-memory-knowledge-layer-shape.md`):
      the full reusable Memory & Knowledge Layer — `MemoryManager`/
      `MemoryRegistry`, concrete `SessionMemory`/`SQLiteCaseMemory`/
      `InMemoryConversationMemory`/`LongTermMemoryManager` implementations of
      every memory Protocol, SQLite persistence (`core/memory/db_models.py`,
      `repository.py`), a real (non-Chroma) `InMemoryVectorStore` +
      deterministic `HashingTextEmbedder`, TTL lifecycle/cleanup
      (`lifecycle.py`), context assembly/serialization
      (`context_builder.py`/`context_serializer.py`), memory-layer metrics,
      and the parallel Knowledge Layer abstraction (`core/knowledge`:
      `KnowledgeSource`/`KnowledgeRetriever` Protocols, `KnowledgeSourceRegistry`,
      a deterministic `KeywordKnowledgeRetriever`) — is implemented and tested
      (70 new tests) with zero cybersecurity data populated and no concrete
      specialist agent depending on it yet. Still not checked off: the
      milestone's own demo criterion (a real ChromaDB backend, populated
      MITRE/OWASP knowledge, and the Threat Timeline/AI Analyst Chat UI)
      needs M1/M2's concrete agents and real knowledge data first.
      *Demo: full Investigation Workspace as described in `docs/user-guide.md`.*

- [ ] **M7 — Hardening, tests, docs, GitHub polish.** Full test coverage pass
      (unit + integration + golden), mypy/ruff clean, docs/diagrams/
      screenshots finalized, tagged `v1.0` release.
      *Demo: portfolio-ready state.*

## Future expansion (post-v1.0, not scheduled)

See blueprint §17: Sigma rule engine, real-time evidence ingestion, multi-
tenant/RBAC, React frontend via `apps/api`, STIX/TAXII feed integration,
approved-and-gated autonomous remediation, fine-tuned small models for
high-volume summarization tasks.
