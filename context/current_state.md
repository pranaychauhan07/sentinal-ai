# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

**Milestone M1 is now complete**, alongside the M0 engineering foundation, the M3 Multi-Agent Framework, the M6 Memory & Knowledge Layer, the M1 Evidence Ingestion & Parser Framework, the M4 Threat Intelligence & IOC Extraction Framework, and the M2 Finding & MITRE ATT&CK Intelligence Engine (all built ahead of schedule in prior sessions). This session closed M1's remaining piece: the `Case`/`TimelineEvent`/`Report` domain models (completing blueprint §8's full schema), the FK-tightening migration ADR-0011/0012/0013 each owed, `core/tools/scoring.py`, the first concrete specialist agent (`core/agents/soc_analyst_agent.py`), `core/services/case_service.py` (the first real cross-subsystem orchestrator), and the first real `/api/v1` routes. Full design rationale: `docs/adr/0014-case-model-and-first-api-routes-shape.md`.

A separate request earlier in this session, to design a standalone "Investigation & Correlation Engine" (a new `Investigation` entity with its own lifecycle/graph/attack-chain builder, sitting between `Finding` and `Case`), was declined as an architectural conflict — no such entity exists in the blueprint, `Case` is blueprint's stated central object, and the request duplicated work already assigned to the Coordinator agent, `TimelineEvent`, and the future Incident Response Agent. `Case` not existing yet was blueprint's own stated blocker for that kind of work. See ADR-0014's Purpose section for the full conflict analysis; no Investigation entity/engine was built.

### M0 foundation + Multi-Agent Framework + Memory & Knowledge Layer + Evidence/Threat-Intel/Finding Frameworks (unchanged from prior sessions)

- **Configuration, logging, shared contracts, DB foundation, FastAPI app, governance, `core/agents`/`core/tools`/`core/graph` framework, `core/memory`/`core/knowledge` framework, `core/parsers` framework (9 parsers), `core/threat_intel` framework (20 IOC types), `core/findings`/`core/knowledge/mitre` (Finding & MITRE Engine)** — unchanged, see prior sessions' detail in git history / `docs/adr/0001-0013`.

### Milestone M1 completion (new this session)

- **`core/db/models/{case,timeline_event,report}.py`** — `Case` (`CaseStatus`: open/investigating/closed; `severity` reuses `core.parsers.models.Severity`), `TimelineEvent` (`TimelineEventType`: case_opened/evidence_ingested/ioc_extracted/finding_generated/agent_analysis/case_status_changed/manual_note; real FK to `cases.id`, nullable FK to `findings.id`), `Report` (`ReportType`: module/executive; schema-only, no consumer this session — Report Generator Agent is M5). Blueprint §8's full domain schema (`Case`/`Evidence`/`Finding`/`MitreTechnique`(×5 tables)/`TimelineEvent`/`Report`) is now complete. Plus `core/db/{case_repository,timeline_event_repository,report_repository}.py`.
- **FK-tightening migration (`7ae8f470d5e7`)** — `Evidence.case_id`, `IOC.case_id`, `Finding.case_id` are now real foreign keys against `cases.id`, applied via `op.batch_alter_table` (required for SQLite; a no-op wrapper on dialects supporting `ALTER ... ADD CONSTRAINT` directly). The three ORM models were updated in lockstep so `Base.metadata` never drifts from what's actually applied. Verified end-to-end against a throwaway SQLite DB: full chain from empty DB to head, FKs confirmed via `PRAGMA foreign_key_list`, clean downgrade.
- **`core/tools/scoring.py`** — `RiskScoringTool` (`BaseTool` subclass) + `ScoringWeights` (configurable, injectable, matching `FindingConfidenceWeights`'s pattern — no hardcoded scoring math). Scores a raw evidence artifact's aggregate severity distribution + source concentration into a 0-100 risk score/label. Distinct from, and never duplicating, `core/findings/severity.py`'s already-implemented IOC/Finding-level `calculate_risk_score`.
- **`core/agents/soc_analyst_agent.py`** — `SocAnalystAgent`, the first concrete specialist agent (capability `log_analysis`). Reads `NormalizedEvidence` items off `CaseInvestigationState.evidence`, calls `RiskScoringTool` via `self.use_tool()` (never computes the score itself), and flags suspected brute-force patterns (repeated failure-shaped events concentrated on few sources — deterministic, not a real Sigma/YARA engine). Produces `SocFinding[]`, appended to `CaseInvestigationState.findings` (the in-memory ReAct trail) — **not** the persisted `findings` DB table, which remains the Finding & MITRE Engine's exclusive output (ADR-0014 point 4 explains why reconciling the two is deferred). Wired into `core/graph/investigation_graph.py` via `_ensure_soc_analyst_registered`, mirroring `_ensure_framework_agents_registered`'s existing idempotency pattern — zero changes to `WorkflowEngine`/`routing.py`, confirming `docs/agent-design.md`'s stated extensibility contract for the first time against a real agent.
- **`core/services/case_service.py`** — `create_case`/`get_case`/`list_cases`/`update_case_status`/`list_timeline_for_case`, plus `investigate_new_evidence()`: the first real cross-subsystem orchestrator, composing `evidence_service.ingest_evidence` → `threat_intel_service.extract_threat_intelligence` → `finding_service.generate_findings_for_case` → a `core/graph` run of `SocAnalystAgent`, recording a `TimelineEvent` at each stage (blueprint §9's full data flow, for real, for the first time). A case auto-transitions `OPEN` → `INVESTIGATING` on its first evidence upload, never on later ones. **New documented dependency-rules exception, rule 4d**: `case_service.py` imports `core.agents.{registry, soc_analyst_agent}`, `core.memory.{case_memory, repository}`, and `core.parsers.models` (types only) directly, to construct a session-scoped `SQLiteCaseMemory` and a *fresh* (never the process-wide cached `default_agent_registry()`) `AgentRegistry` before delegating to `core/graph` — reusing the cached singleton would permanently bake in whichever caller's `case_memory` happened to register `SocAnalystAgent` first.
- **`apps/api/schemas.py` + first real `/api/v1` routes** — `routers/cases.py` (`POST`/`GET`/`PATCH /cases`, `GET /cases/{id}/timeline`), `routers/evidence.py` (`POST /cases/{id}/evidence` — the one sanctioned action-trigger endpoint this session, synchronously running the full investigation pipeline via `case_service.investigate_new_evidence`), `routers/iocs.py` and `routers/findings.py` (read-only lists). All wired into `apps/api/routers/v1.py`. **New runtime dependency: `python-multipart`** (FastAPI's `UploadFile` requires it; justified in `requirements.txt`).
- **Testing** — 33 new tests (662 total, up from 629): `test_db_case_repository.py`, `test_db_timeline_event_repository.py`, `test_tools_scoring.py`, `test_agents_soc_analyst.py` (agent-level, including a non-`NormalizedEvidence`-item degradation case), `test_case_service_pipeline.py` (integration — the real vendored MITRE bundle + `data/sample_evidence/ssh_auth.log`, asserting the full pipeline end-to-end), `test_api_case_routes.py` (integration — `TestClient` against the real FastAPI app, covering create/list/get/patch, 404 envelope, pagination, and the full upload → IOC → Finding → SOC-risk → timeline flow). One pre-existing test updated (`test_default_graph_has_only_the_coordinator_as_a_node` → `test_default_graph_has_coordinator_and_soc_analyst_as_nodes`, the one legitimate contract change from wiring in a real specialist agent — confirmed via full-suite diff that nothing else broke). mypy (strict on `core/`), `ruff check`/`format`, and `scripts/check_dependency_rules.py` all pass; the new `core/services` rule-4d boundary was manually `grep`-verified against ADR-0014's documented scope.
- **No new Settings fields** — `ScoringWeights` follows the existing `FindingConfidenceWeights` pattern (a configurable, injectable Pydantic model with sensible defaults), not settings-file-driven.

**Explicitly NOT built, by this session's stated scope:** any Investigation/Case-correlation entity beyond `Case` itself (see conflict note above); any specialist agent other than SOC Analyst (Phishing, Vulnerability, OWASP, Linux Security, Threat Hunting, Incident Response, MITRE Mapping); any LLM reasoning; `core/security/*` (prompt-injection guard); report generation (`Report` is schema-only); `apps/web` code; a `/api/v1/reports` route.

---

## Repository Status

```
apps/
  api/            FastAPI app + schemas.py (NEW) +
                   routers/{system,cases(NEW),evidence(NEW),
                   iocs(NEW),findings(NEW),v1}.py             [implemented]
  web/             Streamlit frontend                          [README only]
core/
  config/         settings.py (unchanged this session)         [implemented]
  logging/        (unchanged)                                   [implemented]
  exceptions.py, schemas.py, interfaces.py                      [implemented]
  agents/         base/registry/coordinator/planning (unchanged)
                   + soc_analyst_agent.py (NEW)                 [implemented — 1 concrete specialist agent]
  tools/          base/registry (unchanged) + scoring.py (NEW)  [implemented — 1 concrete tool]
  memory/         (unchanged — framework only)                  [implemented — framework only]
  knowledge/      abstraction + mitre/ (unchanged)               [implemented]
  graph/          state/routing/workflow_engine (unchanged) +
                   investigation_graph.py (MODIFIED: wires
                   SocAnalystAgent as a node)                    [implemented]
  db/             base_repository.py, session.py (unchanged) +
                   models/ (evidence.py, ioc.py, finding.py
                   MODIFIED: case_id now a real FK; case.py,
                   timeline_event.py, report.py NEW) +
                   case_repository.py, timeline_event_repository.py,
                   report_repository.py (NEW) +
                   migrations/versions/ (+2 NEW: create tables,
                   FK-tightening)                                [implemented — 7 real domain tables + 5 reference tables]
  parsers/        (unchanged — 9 parsers + framework)             [implemented]
  threat_intel/   (unchanged — 20 modules)                       [implemented]
  findings/       (unchanged — 13 modules)                       [implemented]
  security/       (empty — README only)                          [not started]
  reporting/      (empty — README only)                          [not started]
  services/       evidence_service.py, threat_intel_service.py,
                   finding_service.py (unchanged) +
                   case_service.py (NEW); report_service.py       [implemented — evidence + threat intel + findings + case orchestration]
data/
  sample_evidence/ (unchanged — 9 fixtures + malformed/)         [unchanged]
  mitre/          (unchanged)                                    [unchanged]
scripts/
  mitre/          import_attack_bundle.py (unchanged)             [implemented]
tests/
  unit/           106 test modules (+5 this session)
  integration/    7 test modules (+2 this session)
  golden/         (empty — no report generation exists yet)
docs/             15 markdown docs + docs/adr/ (15 ADR files incl. template) +
                   docs/diagrams/ (unchanged this session)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
scripts/          run_migrations.sh, seed_sample_data.py, check_dependency_rules.py, mitre/
.github/          (unchanged)
```

662 tests passing as of this session (629 prior → 662 now: 33 new). Modified this session: `core/db/models/{__init__,evidence,ioc,finding}.py` (FK tightening), `core/graph/investigation_graph.py` (SocAnalystAgent wiring), `apps/api/{main,routers/v1}.py`, `docs/dependency-rules.md` (rule 4d), `docs/roadmap.md` (M1 checked off), `pyproject.toml` (ruff B008 allowlist for FastAPI `Query`/`Path`/`File`/`Body`), `requirements.txt` (`python-multipart`), `tests/integration/test_investigation_graph.py` (one test updated), plus the five folder `README.md`s touched by new modules (`core/db`, `core/agents`, `core/tools`, `core/services`, `apps/api`), `CHANGELOG.md`, and this file — all currently uncommitted (see "Current Git Status" below).

**Naming note carried forward:** `context/02_repository.md` still does not exist. The actual files remain `context/01_blueprint.md` and `context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extending (not reversing) ADR-0009 through ADR-0013 per ADR-0014's explicit scoping. Eight deliberate decisions, all documented in `docs/adr/0014-case-model-and-first-api-routes-shape.md`:

1. **`Case` gets its own module**, matching the `Evidence`/`IOC`/`Finding` precedent exactly; `TimelineEvent`/`Report` complete blueprint §8's schema for the first time.
2. **`Report` is schema-only** — no service/route/repository-method-beyond-CRUD reads or writes it yet (Report Generator Agent is M5).
3. **The FK-tightening migration every prior ADR owed is applied now**, via `op.batch_alter_table` for SQLite compatibility, with the ORM models updated in lockstep.
4. **`SocAnalystAgent`'s output stays in `CaseInvestigationState.findings`, not the persisted `findings` table** — reconciling agent-produced findings with the Finding & MITRE Engine's schema (via a `source_agent` column blueprint §8 implies but doesn't exist yet) is explicit future work, not decided by default.
5. **`RiskScoringTool` and `core/findings/severity.py`'s scoring never overlap** — different inputs, different pipeline stages.
6. **New rule 4d**: `core/services/case_service.py` imports `core.agents`/`core.memory`/`core.parsers.models` directly, narrowly scoped to constructing a session-scoped `CaseMemory` + fresh `AgentRegistry` before delegating to `core/graph`.
7. **Evidence upload synchronously runs the full pipeline** (ingest → extract → generate → analyze) rather than exposing per-stage trigger endpoints — matches blueprint §9 and M1's own roadmap demo criterion without inventing an unneeded task queue.
8. **New runtime dependency `python-multipart`**, justified (FastAPI file uploads).

Plus all architectural notes carried forward unchanged from prior sessions (ADR-0001 through 0013 — see git history). No approved architectural decision has been reversed. `docs/roadmap.md`'s M1 checkbox is now checked. M2/M3/M4's checkboxes remain unchecked pending their own concrete specialist agents (Phishing, Vulnerability, OWASP, Linux Security, Threat Hunting) and a real Coordinator fan-out demo.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior sessions' "Key Decisions" sections in git history.)*

**New this session:**

- **An "Investigation & Correlation Engine" request was declined as an architectural conflict**, not built. No `Investigation` entity exists in the blueprint; `Case` is blueprint's stated central object and didn't exist yet, which was itself blueprint's own stated blocker for that kind of cross-evidence-correlation work. The request also duplicated the Coordinator agent's, `TimelineEvent`'s, and the future Incident Response Agent's already-assigned responsibilities. M1 (this session's actual work) was substituted instead, per explicit user direction.
- **`SocAnalystAgent` is deliberately kept separate from the persisted `Finding` table.** Blueprint §8 implies one shared table via `source_agent`, but that column doesn't exist on the current schema; conflating agent-level findings with the Finding & MITRE Engine's deterministic, IOC-driven output without a schema change was not a decision to make silently.
- **`default_agent_registry()`'s `@lru_cache` singleton nature is a real correctness hazard for any agent needing session-scoped state** (like `case_memory`) — discovered while wiring `SocAnalystAgent` in. Resolved by having `core/services/case_service.py` construct a *fresh* `AgentRegistry` per investigation run (rule 4d) rather than polluting the shared singleton; `build_investigation_graph()`'s own auto-registration only ever uses `case_memory=None` against the cached singleton, which is the correct, contract-compliant default for any caller not supplying a session.
- **Evidence-upload triggers the full pipeline synchronously, not via separate per-stage endpoints** — matches blueprint §9's data flow and avoids inventing a task queue this milestone doesn't need.

---

## Public Interfaces

*(M0/M3/M6/M2-findings interfaces — unchanged from prior sessions except as noted below.)*

**New this session:**

`core.db.models.{Case, CaseStatus, TimelineEvent, TimelineEventType, Report, ReportType}`, `core.db.case_repository.CaseRepository`, `core.db.timeline_event_repository.TimelineEventRepository`, `core.db.report_repository.ReportRepository`.

`core.tools.scoring.{RiskScoringTool, RiskScoringInput, RiskScoringOutput, ScoringWeights, classify_risk_score}`.

`core.agents.soc_analyst_agent.{SocAnalystAgent, SocFinding, SocAnalysisResult, default_soc_analyst_tool_registry}`. `core.graph.investigation_graph.build_investigation_graph` gained a `case_memory: CaseMemory | None` parameter.

`core.services.case_service.{CaseInvestigationResult, create_case, get_case, list_cases, update_case_status, list_timeline_for_case, investigate_new_evidence}`.

`apps.api.schemas.{CaseCreateRequest, CaseStatusUpdateRequest, CaseResponse, EvidenceResponse, EvidenceUploadResponse, IOCResponse, FindingResponse, TimelineEventResponse}`. New routes: `POST/GET/PATCH /api/v1/cases`, `GET /api/v1/cases/{id}/timeline`, `POST/GET /api/v1/cases/{id}/evidence`, `GET /api/v1/cases/{id}/iocs`, `GET /api/v1/cases/{id}/findings`.

No concrete specialist agent other than `SocAnalystAgent`, no LLM reasoning, no `/api/v1/reports` route, no `core.security.*` implementation exist as public interfaces yet.

---

## Remaining Work

1. **M2 — remaining piece.** Phishing Investigation Agent + `email_parser.py` + `core/security/prompt_guard.py`; a concrete `core/agents/mitre_mapping_agent.py` (or extended `threat_hunter_agent.py`) reasoning over `finding_service.generate_findings_for_case()`'s typed output.
2. **M3 — remaining piece.** A real Coordinator fan-out demo needs a *second* concrete specialist agent (e.g. Phishing) registered alongside `SocAnalystAgent` — the framework already supports it with zero changes, per this session's proof.
3. **M4 — remaining piece.** Vulnerability Assessment Agent (+ Nmap/Nessus/OpenVAS parsers + CVSS calculator), OWASP Security Agent, Linux Security Agent, `core/agents/threat_hunter_agent.py`.
4. **M5 — Incident Response synthesis + Reporting.** Incident Response Agent, Report Generator Agent (finally gives `Report` real behavior), Jinja2/ReportLab templates, Plotly charts, `/api/v1/reports` route.
5. **M6 — remaining piece.** Swap `InMemoryVectorStore` for real ChromaDB, populate remaining knowledge data (OWASP, playbooks), Threat Timeline/MITRE heatmap/AI Analyst Chat UI (the backend data — `TimelineEvent`, now real — already supports the Threat Timeline view).
6. **M7 — Hardening, tests, docs, GitHub polish.**

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md` doesn't exist; `apps/web` has no code; harmless Starlette deprecation warnings in test output; no CI has ever actually run on GitHub; `scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import rule, not the full sibling-layer matrix — manually verified via `grep` for each new session's boundaries; `InMemoryVectorStore` is O(n) brute-force; `HashingTextEmbedder` is not semantic; numpy not installed; `windows_event_parser.py` handles only CSV/XML export, not binary `.evtx`.)*

- **`SocAnalystAgent`'s `SocFinding[]` output is not persisted** — it lives only on `CaseInvestigationState.findings` for the duration of one graph run, visible via the API only indirectly (`soc_risk_score`/`soc_risk_label` on `EvidenceUploadResponse`). A future milestone/ADR needs to decide how (or whether) to persist it, per ADR-0014 point 4.
- **`Report` has no consumer** — the table exists, nothing reads or writes it. Deliberate, per ADR-0014 point 2.
- **`make migrate`/`make seed` were not re-verified this session** — the new migrations were verified directly via `alembic upgrade head`/`downgrade -1` against a throwaway DB, not through the Makefile wrapper.
- **No case-level authorization/ownership check** — any request can read/write any case (`AuthenticatedUser` is still the fixed placeholder from `apps/api/dependencies.py`; real auth is blueprint §17 future work).
- **`POST /cases/{id}/evidence` has no per-request size/rate limiting beyond the existing `EVIDENCE_MAX_UPLOAD_BYTES` validation** — acceptable for single-analyst mode (blueprint §3), flagged for when auth/multi-tenant work begins.

---

## Dependencies

Runtime (`requirements.txt`): **one new dependency this session** — `python-multipart>=0.0.12` (FastAPI's `UploadFile` requires it for `POST /cases/{id}/evidence`; justified inline in `requirements.txt`).

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`), with prior commits through `f151536` (a small docs wording tidy-up) — `2886f4e` (Finding & MITRE Engine) is the most recent substantive feature commit; all prior-session work is committed.

This session's Milestone M1 completion work added/modified (all currently uncommitted):
- New: `docs/adr/0014-case-model-and-first-api-routes-shape.md`, `core/db/models/{case,timeline_event,report}.py`, `core/db/{case_repository,timeline_event_repository,report_repository}.py`, `core/db/migrations/versions/{6735a0d18bb9,7ae8f470d5e7}_*.py`, `core/tools/scoring.py`, `core/agents/soc_analyst_agent.py`, `core/services/case_service.py`, `apps/api/schemas.py`, `apps/api/routers/{cases,evidence,iocs,findings}.py`, 6 new test files.
- Modified: `core/db/models/{__init__,evidence,ioc,finding}.py`, `core/graph/investigation_graph.py`, `apps/api/{main,routers/v1}.py`, `docs/dependency-rules.md`, `docs/roadmap.md`, `pyproject.toml`, `requirements.txt`, `tests/integration/test_investigation_graph.py`, `core/db/README.md`, `core/agents/README.md`, `core/tools/README.md`, `core/services/README.md`, `apps/api/README.md`, `CHANGELOG.md`, `context/current_state.md` (this file).

Full suite (662 tests), `ruff check`/`format`, `mypy core --strict`, and `scripts/check_dependency_rules.py` all pass. The new `core/services` rule-4d boundary and every new import edge were manually `grep`-verified against ADR-0014's documented scope. Commit only when the user explicitly asks.

---

## Next Recommended Prompt

> Implement Milestone M2's remaining piece exactly as scoped in `docs/roadmap.md` and this file's "Remaining Work" section: `core/parsers/email_parser.py` (`.eml`/`.txt` phishing email parsing, producing `NormalizedEvidence` per the existing parser contract), `core/security/prompt_guard.py` (prompt-injection/jailbreak pattern detection — the first attacker-controlled-text guard, structurally required per constitution §4.11/§9/§10 before any email body reaches an LLM prompt), and `core/agents/phishing_agent.py` (a concrete `BaseAgent` subclass declaring a distinct capability, e.g. `email_triage`, so it can register alongside `SocAnalystAgent` in `core/graph/investigation_graph.py` with zero framework changes — proving the Coordinator's real fan-out for the first time, which closes M3's own demo criterion too). Wire it into `core/services/case_service.py`'s `investigate_new_evidence()` (or a parallel entry point) so a phishing email upload triggers the same TimelineEvent-recording pattern. Add a `POST /api/v1/cases/{id}/evidence` content-type/classification path that routes `.eml` uploads correctly (the parser factory already does extension/content sniffing — confirm it dispatches to the new parser without router changes). Preserve every existing file and architectural decision described in this document — including the Case/TimelineEvent/Report schema, the SOC Analyst Agent, and the Finding & MITRE Engine — only extend them.
