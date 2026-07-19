# ADR-0011: Evidence Ingestion & Parser Framework Shape

**Status:** Accepted
**Date:** 2026-07-19

## Purpose

The next milestone this project's own `context/current_state.md` scoped was a
minimal M1: one syslog parser plus the SOC Analyst Agent. The task actually
requested this session is broader and differently shaped: a reusable,
agent-independent Evidence Ingestion & Parser Framework covering nine
evidence formats, explicitly excluding investigation/agent/MITRE logic. This
mirrors ADR-0009's "framework first" precedent (the Multi-Agent Framework)
and ADR-0010's (the Memory & Knowledge Layer): build the reusable
infrastructure before the concrete domain logic that will eventually sit on
top of it. This ADR records the four points where that infrastructure
genuinely extends the approved architecture, and the plugin/pipeline
refinements requested during planning.

## Decisions

1. **`core/services/evidence_service.py` may import `core/parsers` (and
   `core/memory`) directly** — the one documented exception to
   `docs/dependency-rules.md`'s "services only call `core/graph`, `core/db`,
   `core/reporting`." Blueprint §9 steps 1-3 (upload, classify, parse) are
   deterministic and pre-investigation; blueprint's own Parser/Evidence
   Agent only exists to add an *LLM fallback* on top of this deterministic
   layer, out of scope here. Routing pure ingestion through `core/graph` for
   no reason would be scope creep in the other direction. `core/agents/
   parser_agent.py` (the LLM-fallback wrapper) remains unbuilt; this decision
   doesn't affect it. `core/memory` access is not actually a new edge —
   `core/services/README.md` already documented services coordinating with
   Memory ("creating a case also checks Memory for similar past cases");
   `evidence_service.py`'s advisory `notify_memory` pipeline stage is simply
   the first thing to exercise it.

2. **`Evidence.case_id` is a plain UUID column, not a foreign key.** `Case`
   doesn't exist yet. This applies the exact precedent
   `core/memory/db_models.py::MemoryRecordRow` set (ADR-0010) to the first
   real domain table — not a new decision, an extension of an already-accepted
   one. A follow-up additive migration adds the FK constraint once Milestone
   M1 builds `Case` (constitution §7, "Future scalability").

3. **`core.parsers.models.EvidenceType` is more granular than blueprint §8's
   illustrative `evidence_type` enum** (`email/log/nmap/nessus/openvas/
   source_code/incident_note`). Parser selection needs to distinguish
   `ssh_auth`/`apache_access`/`apache_error`/`syslog`/`windows_event`/`json`/
   `csv`/`nmap_xml`/`plain_text`. Nothing has been built against the coarser
   enum, so this is additive refinement, not a breaking change.

4. **Windows Event Log support is a CSV/XML export abstraction, not binary
   EVTX parsing** — explicitly permitted by scope ("EVTX abstraction if full
   parsing is deferred"). `windows_event_parser.py` accepts the
   `EventID,TimeCreated,Computer,Account,SourceIP,LogonType,Message` export
   shape (matching `data/sample_evidence/windows_security_events.csv`).
   Binary `.evtx` parsing (e.g. via `python-evtx`) is a documented future
   extension.

## Refinements (requested during planning, before implementation)

- **Ten explicit pipeline stages**, each a small typed method on
  `EvidencePipeline` (`core/services/evidence_service.py`): upload →
  validate → fingerprint → extract_metadata → select_parser → parse →
  normalize → persist → publish_event → notify_memory. "Future Agent
  Notification" folds into `publish_event`: a future `ParserAgent`/
  Coordinator subscribes to the same `ParserEventPublisher`
  (`core/parsers/events.py`) rather than needing its own pipeline stage.
- **`ParserRegistry` (`core/parsers/registry.py`) is plugin-capable.** Every
  registration carries `aliases`, `version`, `priority` (tie-break
  ordering when more than one parser's `sniff()` plausibly matches),
  `enabled` (soft-disable without unregistering), and `source`
  (`"builtin"`/`"plugin"`). `default_parser_registry()` auto-registers the
  nine builtin parsers, then calls `load_plugins()`, which discovers
  external parsers via `importlib.metadata.entry_points(group="cdc.parsers")`
  — a real, working extension seam even though no third-party plugin package
  exists yet. A missing entry-point group is a documented no-op; one failing
  plugin is logged and skipped, never aborting discovery of the rest
  (constitution §9, "fail gracefully").
- **`core/db/models/` is a package, not a single `models.py`.**
  `models/__init__.py` re-exports everything (`from core.db.models import
  Evidence` keeps working); `models/evidence.py` holds `Evidence` +
  `EvidenceStatus`. Every future domain table (`Case`, `Finding`,
  `MitreTechnique`, `TimelineEvent`, `Report`) gets its own sibling module —
  no refactor needed when Milestone M1 adds them. `core/db/migrations/env.py`
  imports the `core.db.models` package (not a specific module) so Alembic
  autogeneration keeps discovering every table via `Base.metadata`.

## Scope Cuts (explicit, not silent)

- No FastAPI route this session — `Case` doesn't exist, so a case-scoped
  upload endpoint would be fake plumbing wired to an orphan UUID. Wiring
  `evidence_service.ingest_evidence()` to `apps/api` is natural M1 follow-up.
- No `email_parser`/`nessus_parser`/`openvas_parser`/`source_code_parser`/
  `incident_parser` — not in this task's nine-parser scope; still
  blueprint-scoped future work, untouched.
- No MITRE mapping, threat intelligence, or investigation logic, per explicit
  instruction.
- One new runtime dependency: **`defusedxml`**, used only by
  `nmap_parser.py`. Stdlib `xml.etree.ElementTree` is vulnerable to
  entity-expansion ("billion laughs") and XXE attacks; a scan report is
  exactly the kind of artifact an attacker could plant for an analyst to
  later upload, and the task explicitly requires preventing "unsafe
  parsing." No `chardet`/`python-magic` dependency was added — stdlib
  BOM-sniffing plus a fixed `utf-8`/`utf-8-sig`/`latin-1` fallback ladder
  and extension/content heuristics are sufficient for this framework's nine
  known formats (see `core/parsers/detection.py`).

## Alternatives Considered

- **Wait for Milestone M1's `Case` model before building any `Evidence`
  persistence** — rejected for the same reason ADR-0010 rejected waiting for
  domain models before building memory persistence: it would force the
  eventual concrete ingestion work to retrofit persistence ad hoc instead of
  inheriting an already-tested repository.
- **Route all ingestion through `core/graph` to avoid a `core/services` →
  `core/parsers` edge** — rejected as architecture-for-its-own-sake; nothing
  in the ingestion pipeline branches on investigation state or needs
  checkpointing, and forcing a graph node here would blur the boundary
  between "deterministic pre-investigation processing" and "agentic
  reasoning" the constitution's tool/LLM boundary (§9/§4.5) is built to keep
  sharp.
- **Two separate registries** ("Evidence Registry" + "Parser Registry," as
  the task's wording suggested) — rejected; one `ParserRegistry` indexed by
  name, alias, evidence type, and extension serves both purposes without
  duplicate lookup logic (constitution §1.3).

## Consequences

- A future `core/agents/parser_agent.py` (LLM-fallback wrapper) can be added
  without changing anything in `core/parsers` or `core/services/
  evidence_service.py` — it would simply call `ingest_evidence()` first and
  only invoke an LLM if `select_parser` raises `UnsupportedFormatError`.
- `Evidence.case_id`'s FK constraint is a known, tracked gap until Milestone
  M1 — a reviewer should not mistake the plain UUID column for an oversight.
- The `cdc.parsers` entry-point group is a public extension contract from
  this point forward; renaming it would be a breaking change to any future
  plugin package.
