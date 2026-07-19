# ADR-0014: Case Model, SOC Analyst Agent, and First API Routes Shape

**Status:** Accepted
**Date:** 2026-07-20

## Purpose

This session completes Milestone M1's remaining piece exactly as scoped in
`context/current_state.md`'s prior "Next Recommended Prompt": the `Case`
domain model (blueprint §1/§8's central object, deliberately deferred by
ADR-0011/0012/0013), the FK-tightening follow-up migration those three ADRs
each explicitly owed, `core/tools/scoring.py`, `core/agents/
soc_analyst_agent.py` as the first concrete specialist agent, and the first
real `/api/v1` routes wiring evidence ingestion, IOC extraction, Finding
generation, and SOC analysis together end-to-end.

A prior session in this same conversation was asked to design a separate
"Investigation & Correlation Engine" (a new `Investigation` entity sitting
between `Finding` and `Case`, with its own lifecycle/graph/attack-chain
builder). That request was declined and this M1 work substituted instead: it
introduced entities and responsibilities (`Asset`/`Host`/`Process` nodes, a
generic investigation graph, an `Investigation` status lifecycle competing
with `Case.status`) with no home in `context/01_blueprint.md`'s schema, and
duplicated work already assigned to the Coordinator agent, the
`TimelineEvent` table, and the Incident Response Agent. `Case` not existing
yet was also blueprint's own stated blocker (§18 rec #1) for that kind of
work. This ADR's decisions are scoped strictly to closing that M1 gap.

## Decisions

1. **`Case` gets its own module, `core/db/models/case.py`, matching the
   `Evidence`/`IOC`/`Finding` precedent exactly** — surrogate UUID PK,
   `CaseStatus` (`open`/`investigating`/`closed`, blueprint §8), and
   `severity` typed as `core.parsers.models.Severity` (reused, not
   re-declared — constitution §14.9). `TimelineEvent` and `Report` get their
   own sibling modules the same way, completing blueprint §8's full schema
   list for the first time.

2. **`Report` is schema-only this session.** The table/columns exist
   (`report_type`, `file_path`, `generated_at`) so `Case`'s owned-entity set
   matches the blueprint exactly, but no service, repository method beyond
   generic CRUD, or API route reads/writes it — the Report Generator Agent
   (Milestone M5) is what gives it real behavior. Building more than that now
   would be exactly the placeholder logic constitution §8 forbids.

3. **The FK-tightening migration ADR-0011/0012/0013 each explicitly owed is
   applied now, in one migration, via `op.batch_alter_table`** (required for
   SQLite, a no-op wrapper on dialects that support `ALTER ... ADD
   CONSTRAINT` directly). `Evidence.case_id`, `IOC.case_id`, and
   `Finding.case_id` become real foreign keys against `cases.id`; the ORM
   models are updated to match so `Base.metadata` never drifts from what the
   migration actually applied. Verified end-to-end against a throwaway
   SQLite DB: full chain from empty DB to head, FK constraints confirmed via
   `PRAGMA foreign_key_list`, and a clean downgrade.

4. **`SocAnalystAgent`'s `SocFinding[]` output is appended to
   `CaseInvestigationState.findings` (the in-memory ReAct trail) and to its
   own `AgentExecutionResult.output` — it is *not* written to the persisted
   `findings` DB table.** Blueprint §8's schema implies every specialist
   agent's findings share one `Finding` table via a `source_agent` column,
   but that column doesn't exist on the current schema or
   `core.findings.models.FindingRecord`, and the persisted `findings` table
   is ADR-0013's exclusive, deterministic, IOC-driven output — conflating
   the two without a schema change was not decided by default. Reconciling
   them into one shared representation is left to a future milestone/ADR.

5. **`core/tools/scoring.py`'s `RiskScoringTool` is distinct from, and never
   duplicates, `core/findings/severity.py`'s `calculate_risk_score`.** The
   former scores a raw evidence artifact's aggregate signal (severity
   counts, source concentration) before any IOC/Finding exists — blueprint
   §7's "Tools used: log_tools.py, scoring.py" for the SOC Analyst Agent.
   The latter scores an already MITRE-mapped `FindingRecord`. Both are
   real, both are needed, and they operate on different inputs at different
   pipeline stages.

6. **New rule 4d** (`docs/dependency-rules.md`): `core/services/
   case_service.py` imports `core.agents.{registry, soc_analyst_agent}`,
   `core.memory.{case_memory, repository}`, and `core.parsers.models`
   (types only) directly — the fourth documented, narrowly-scoped exception
   to "services only call `core/graph`," worded identically to 4a/4b/4c.
   The reason is specific: constructing a session-scoped `SQLiteCaseMemory`
   and a *fresh* `AgentRegistry` (never the process-wide cached
   `default_agent_registry()`) before delegating to
   `core/graph/investigation_graph.py`. Reusing the cached singleton would
   permanently bake in whichever caller's `case_memory` (or lack of one)
   happened to register `SocAnalystAgent` first — a real correctness
   hazard given `default_agent_registry()` is `@lru_cache`d for the process
   lifetime, not a style preference. `build_investigation_graph()` itself
   gained a `case_memory: CaseMemory | None` parameter and a
   `_ensure_soc_analyst_registered` helper mirroring
   `_ensure_framework_agents_registered`'s existing idempotency pattern
   exactly — any caller not supplying a session (tests, or a future
   caller) still gets a working agent with `case_memory=None`, per
   `docs/agent-design.md`'s existing contract.

7. **Evidence upload (`POST /cases/{case_id}/evidence`) synchronously runs
   the full pipeline** — ingest → extract IOCs → generate Findings → run
   SOC analysis — recording a `TimelineEvent` at each stage, rather than
   exposing separate trigger endpoints per stage. This matches blueprint
   §9's data flow and M1's own roadmap demo criterion ("upload a firewall
   log → get a real, saved, severity-classified finding") without inventing
   a task queue this milestone doesn't need. `core/services/case_service.py`
   composing `evidence_service`/`threat_intel_service`/`finding_service`
   directly is normal service composition (no dependency-rules exception
   needed) — those three's own 4a/4b/4c exceptions are about reaching
   *below* `core/graph`, not about services calling each other.

8. **A new runtime dependency, `python-multipart`, is required** —
   FastAPI's `UploadFile` form-data handling needs it; there was no prior
   file-upload endpoint. Added to `requirements.txt` with a comment
   justifying it, per constitution §10.

## Consequences

- `docs/roadmap.md`'s M1 checkbox is now closed — its stated demo criterion
  ("upload a firewall log → get a real, AI-generated severity-classified
  finding, saved and visible on refresh") is genuinely met end-to-end,
  verified by `tests/integration/test_api_case_routes.py` and
  `tests/integration/test_case_service_pipeline.py` against the real
  vendored MITRE bundle and a real sample evidence fixture.
- `docs/agent-design.md`'s "How an agent joins the graph" contract was
  exercised for real for the first time — `SocAnalystAgent` required zero
  changes to `WorkflowEngine`/`routing.py`, confirming the framework's
  stated extensibility property.
- `tests/integration/test_investigation_graph.py::
  test_default_graph_has_only_the_coordinator_as_a_node` was renamed/updated
  to expect both `coordinator` and `soc_analyst` nodes — the only existing
  test whose contract legitimately changed by wiring in a real specialist
  agent; every other pre-existing test was unaffected (confirmed via a full
  suite run before and after).
- `MitreTechnique`-as-blueprint-flat-table, `TimelineEvent`/`Report`-as-UI-
  backed-features, any other specialist agent, prompt-injection guarding,
  and report generation remain explicitly out of scope — unchanged from
  ADR-0011/0012/0013's identical scope cuts.
