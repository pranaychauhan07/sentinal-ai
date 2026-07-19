# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

**Still no concrete specialist agent or investigation logic exists.** What is now complete, beyond the M0 engineering foundation, the M3 Multi-Agent Framework, and the M6 Memory & Knowledge Layer, is the **Evidence Ingestion & Parser Framework**: a reusable, agent-independent pipeline that turns nine raw evidence formats into the canonical `NormalizedEvidence` contract, plus the first real domain table (`Evidence`) and its persistence. Built ahead of the milestone schedule (normally part of M1) at explicit user direction — framework-first, mirroring the precedent set by the Multi-Agent Framework (ADR-0009) and Memory & Knowledge Layer (ADR-0010) sessions. Full design rationale, including four deliberate architecture extensions and three planning-stage refinements: `docs/adr/0011-evidence-ingestion-pipeline-shape.md`.

### M0 foundation + Multi-Agent Framework + Memory & Knowledge Layer (unchanged from prior sessions)

- **Configuration, logging, shared contracts, DB foundation, FastAPI app, governance, `core/agents`/`core/tools`/`core/graph` framework, `core/memory`/`core/knowledge` framework** — unchanged, see prior sessions' detail in git history / `docs/adr/0001-0010`. 245 tests as of the prior session.

### Evidence Ingestion & Parser Framework (new this session)

- **`core/parsers/models.py`** — the canonical evidence contract: `EvidenceType` (nine formats, a refinement of blueprint §8's illustrative enum — additive, nothing was built against the coarser set), `Severity`, `ChainOfCustody`, `EvidenceRecord` (one parsed event), `NormalizedEvidence` (the per-artifact container every parser returns — `records: list[EvidenceRecord]` + confidence + metadata + `unparsed_fragments` + chain of custody).
- **`core/parsers/base.py`** — `BaseParser`, a template-method base shaped identically to `BaseTool`/`BaseAgent`: `__call__` owns encoding detection, fingerprinting, timing, metrics, structured logging, and the constitution §1.7 contract (never crash, never silently drop data — a malformed artifact degrades to a zero-confidence result with the whole artifact preserved in `unparsed_fragments`). Subclasses implement only `sniff()`/`validate_content()`/`parse_content()`.
- **`core/parsers/registry.py`** — `ParserRegistry`, redesigned during planning to be **plugin-capable**: every registration carries aliases, a version, a priority (tie-break ordering), an enable/disable flag, and a source (`"builtin"`/`"plugin"`). `default_parser_registry()` auto-registers all nine builtin parsers, then calls `load_plugins()`, which discovers external parsers via `importlib.metadata.entry_points(group="cdc.parsers")` — a real, working extension seam even though no third-party plugin package exists yet.
- **`core/parsers/factory.py`** — `select_parser()`: deterministic precedence (declared type → extension → content-sniff ranking), raising `UnsupportedFormatError` if nothing matches — never a silent guess.
- **`core/parsers/detection.py`** — stdlib-only MIME-type guessing (`mimetypes`) and content-based evidence-type sniffing, plus BOM-sniffing + `utf-8`/`utf-8-sig`/`latin-1` fallback-ladder encoding detection. No `chardet`/`python-magic` dependency added.
- **`core/parsers/validation.py`** — the upload security boundary: `validate_filename` (path-traversal/null-byte/absolute-path rejection), `validate_extension` (allowlist, new `Settings.evidence_allowed_extensions`), `validate_size` (new `Settings.evidence_max_upload_bytes`), plus `MAX_RECORDS_PER_ARTIFACT` (the resource-exhaustion cap `EvidencePipeline.normalize()` enforces).
- **`core/parsers/fingerprint.py`** — SHA-256 (`hashlib`, not the salted builtin `hash()`).
- **`core/parsers/metrics.py`**, **`events.py`**, **`audit.py`** — self-contained parser-run metrics and an in-process `ParserEventPublisher` (both deliberately independent of `core.graph.events.EventBus`, mirroring `core/memory/metrics.py`'s leaf-layering reasoning), plus structured chain-of-custody audit logging via `core.logging`.
- **`core/parsers/syslog_common.py`**, **`field_heuristics.py`** — shared, non-parser helper modules factored out so the RFC3164 header regex (used by `ssh_auth_parser.py` and `syslog_parser.py`) and the generic field-name-alias heuristics (used by `json_evidence_parser.py` and `csv_evidence_parser.py`) each live in exactly one place.
- **Nine concrete parsers**, each a `BaseParser` subclass, registered in `registry.py`:
  - `ssh_auth_parser.py` — `sshd` auth/session/disconnect lines.
  - `apache_access_parser.py` — NCSA Combined Log Format.
  - `apache_error_parser.py` — Apache error log (modern `[module:level]` and classic `[level]` forms).
  - `syslog_parser.py` — generic RFC3164-ish fallback for any non-`sshd` syslog line.
  - `windows_event_parser.py` — a **CSV/XML EVTX abstraction** (accepts the `EventID,TimeCreated,Computer,Account,SourceIP,LogonType,Message` export shape); binary `.evtx` parsing is an explicitly documented, out-of-scope future extension.
  - `json_evidence_parser.py` — a single JSON object or list of objects, field-alias heuristics.
  - `csv_evidence_parser.py` — any header-having CSV, same field-alias heuristics.
  - `nmap_parser.py` — Nmap XML via **`defusedxml`** (XXE/entity-expansion-safe — verified against a hand-crafted XXE-attempt fixture: the entity is never resolved, the parser degrades gracefully instead of leaking or crashing).
  - `plaintext_parser.py` — deterministic, deliberately low-confidence last-resort fallback (no LLM reasoning — that's the still-unbuilt `core/agents/parser_agent.py`'s job).
- **`core/db/models/`** (new package, first domain persistence) — `evidence.py` defines `Evidence(Entity)` + `EvidenceStatus`; `__init__.py` re-exports for `from core.db.models import Evidence`. `case_id` is a **plain UUID column, not a foreign key** — `Case` doesn't exist yet; this extends the exact precedent `core/memory/db_models.py::MemoryRecordRow` set (ADR-0010) to the first real domain table. Indexed on `case_id`, `evidence_type`, `sha256`, `status`. `core/db/migrations/env.py` now imports `core.db.models` for Alembic autogeneration; the first real migration, `20df7c637d48_create_evidence_table.py`, is generated, hand-reviewed, and verified (applied to a throwaway SQLite DB, table + all four indexes confirmed present).
- **`core/db/evidence_repository.py`** — `EvidenceRepository(BaseRepository[Evidence])` + `find_by_case`, `find_by_sha256` (duplicate-upload detection), `mark_parsed`, `mark_failed`.
- **`core/services/evidence_service.py`** — the Evidence Manager: `EvidencePipeline`, with the ten stages requested during planning as explicit, independently-testable methods — `upload` → `validate` → `fingerprint` → `extract_metadata` → `select_parser_for` → `parse` → `normalize` → `persist` → `publish_event` → `notify_memory` — composed by one `ingest_evidence()` orchestrator, plus `get_evidence()`/`list_evidence_for_case()`. `notify_memory` is advisory-only (a broken `CaseMemory` never breaks ingestion, verified by test). Content-addressed local file storage (`Settings.evidence_storage_dir`) is idempotent — re-uploading identical bytes doesn't duplicate the blob.
- **New `Settings` fields**: `evidence_max_upload_bytes`, `evidence_allowed_extensions`, `evidence_storage_dir` (all documented in `.env.example`).
- **New sample fixtures**: `data/sample_evidence/apache_error.log`, `sample_evidence.json`, `plaintext_note.txt`, and a `data/sample_evidence/malformed/` folder (truncated Windows-event CSV, an XXE-attempt Nmap XML, malformed JSON, an empty file, non-UTF8 byte content) — used by the adversarial-input tests constitution §11 requires.
- **New mermaid diagrams**: `docs/diagrams/evidence-ingestion-pipeline.mmd` (the ten-stage sequence), `parser-lifecycle.mmd` (one parser's selection → decode → validate → parse/degrade state machine).
- **Testing** — 107 new tests (352 total, up from 245): one dedicated `tests/unit/test_*.py` file per framework module and per concrete parser, `test_db_evidence_repository.py` (real SQLite, mirroring `test_base_repository.py`'s pattern), `test_evidence_service.py` (full pipeline, including the XXE-blocking assertion, the memory-advisory-failure assertion, and the record-count-cap assertion). mypy (strict on `core/`), `ruff check`/`format`, and `scripts/check_dependency_rules.py` all pass; the one new `core/services → core/parsers`/`core/memory` edge was verified by manual `grep` to be exactly as scoped in the ADR.
- **New dependency**: `defusedxml` (runtime — XXE protection for `nmap_parser.py`, the framework's only XML-handling parser) + `types-defusedxml` (dev — mypy stubs).

**Explicitly NOT built, by this session's stated scope:** `Case`/`Finding`/`MitreTechnique`/`TimelineEvent`/`Report` domain models, any concrete specialist agent (SOC Analyst, Phishing, Vulnerability, OWASP, Linux Security, Incident Response, MITRE Mapping), `core/agents/parser_agent.py` (the blueprint's LLM-fallback wrapper around this parser framework), any `/api/v1` evidence route (a case-scoped upload endpoint would be fake plumbing without a real `Case`), `email_parser.py`/`nessus_parser.py`/`openvas_parser.py`/`source_code_parser.py`/`incident_parser.py` (blueprint-scoped, not in this session's nine-parser list), `core/security/*`, `core/reporting/*`, any `apps/web` code, MITRE mapping, threat intelligence, or any investigation logic.

---

## Repository Status

```
apps/
  api/            FastAPI app (unchanged)                          [implemented]
  web/             Streamlit frontend                               [README only]
core/
  config/         settings.py + 3 new evidence_* fields             [implemented]
  logging/        (unchanged)                                       [implemented]
  exceptions.py, schemas.py, interfaces.py                          [implemented]
  agents/         (unchanged — framework only)                      [implemented — framework only]
  tools/          (unchanged — framework only)                      [implemented — framework only]
  memory/         (unchanged — framework only)                      [implemented — framework only]
  knowledge/      (unchanged — abstraction + one retriever)          [implemented — abstraction only]
  graph/          (unchanged — framework only)                       [implemented — framework only]
  db/             base_repository.py, session.py (unchanged) +
                   models/ (NEW: __init__.py, evidence.py),
                   evidence_repository.py (NEW),
                   migrations/versions/20df7c637d48_create_evidence_table.py [implemented — first domain table]
  parsers/        models.py, exceptions.py, base.py, detection.py,
                   validation.py, fingerprint.py, registry.py,
                   factory.py, metrics.py, events.py, audit.py,
                   syslog_common.py, field_heuristics.py,
                   ssh_auth_parser.py, apache_access_parser.py,
                   apache_error_parser.py, syslog_parser.py,
                   windows_event_parser.py, json_evidence_parser.py,
                   csv_evidence_parser.py, nmap_parser.py,
                   plaintext_parser.py                               [implemented — 9 parsers + framework]
  security/       (empty — README only)                              [not started]
  reporting/      (empty — README only)                              [not started]
  services/       evidence_service.py (NEW); case_service.py,
                   report_service.py                                 [implemented — evidence only]
data/
  sample_evidence/ +apache_error.log, sample_evidence.json,
                    plaintext_note.txt, malformed/ (5 fixtures)      [new fixtures added]
tests/
  unit/           63 test modules (352 tests total, +107 this session)
  integration/    4 test modules (17 tests, unchanged)
  golden/         (empty — no report generation exists yet)
docs/             15 markdown docs + docs/adr/ (12 ADR files incl. template) +
                   docs/diagrams/ (+2 new .mmd files)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
scripts/          (unchanged)
.github/          (unchanged)
```

221 files committed as of `0ee65d5` (the M0 + Multi-Agent Framework + Memory & Knowledge Layer commit); this session added roughly 45 new files (21 `core/` modules, 20 test files, 5 new sample fixtures, 2 new diagrams, 1 new ADR) plus edits to ~9 existing files (settings.py, .env.example, requirements.txt, requirements-dev.txt, pyproject.toml, dependency-rules.md, three READMEs, roadmap.md, CHANGELOG.md, migrations/env.py + README.md), all currently uncommitted (see "Current Git Status" below).

**Naming note carried forward:** `context/02_repository.md` and `context/03_constitution.md` still do not exist. The actual files remain `context/01_blueprint.md` and `context/03_engineering_constitution.md`. This session's prompt again referenced both non-existent filenames — flagged and worked around identically to prior sessions' notes.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extending (not reversing) ADR-0009/0010 per ADR-0011's explicit scoping. Four deliberate architecture extensions, all documented in `docs/adr/0011-evidence-ingestion-pipeline-shape.md`:

1. **`core/services/evidence_service.py` may import `core/parsers` and `core/memory` directly** — the one documented exception to "services only call `core/graph`/`core/db`/`core/reporting`" (`docs/dependency-rules.md` rule 4a). Evidence ingestion is deterministic and pre-investigation; blueprint's own Parser/Evidence Agent only exists to add an LLM fallback on top of this layer, out of scope here. Verified by manual `grep` (no `core.graph`/`core.agents` import anywhere in `core/parsers` or `evidence_service.py`).
2. **`Evidence.case_id` is a plain UUID column, not a foreign key** — extends ADR-0010's `MemoryRecordRow` precedent to the first real domain table; a follow-up additive migration adds the FK once Milestone M1 builds `Case`.
3. **`core.parsers.models.EvidenceType`** is more granular than blueprint §8's illustrative enum — additive refinement, nothing was built against the coarser set.
4. **Windows Event Log support is a CSV/XML export abstraction, not binary EVTX parsing** — explicitly permitted by scope; binary parsing is a documented future extension.

Plus the three carried-forward architectural notes from prior sessions (unchanged): `core/logging/` fills a blueprint §4 gap with no assigned folder in §6; three root-level `core/` modules (`exceptions.py`, `schemas.py`, `interfaces.py`) are shared leaves with no assigned home; `core/graph/state.py` is a shared leaf contract `core/agents` may import, distinct from the rest of `core/graph`; `core/memory`/`core/knowledge` own their own persistence the same way `core/db` owns the domain schema.

No approved architectural decision has been reversed. `docs/roadmap.md`'s M1 checkbox remains unchecked — the Evidence Ingestion & Parser Framework is implemented, but M1's own demo criterion (a real `Case`, a concrete SOC Analyst Agent, an actual "upload a firewall log → get a saved, severity-classified finding" flow) needs domain models and a concrete agent first.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: UUID surrogate PKs via `Entity`; `Tool`/`Agent` Protocol variance; `Service` is not a Protocol; ruff format only; FastAPI `Annotated[Type, Depends(...)]` style; cursor pagination by UUID `id`; the Coordinator delegates planning and never executes agents itself; two-tier error handling in `BaseAgent`/`workflow_engine.py`; reducer-based `CaseInvestigationState`; `core/graph/routing.py` not `router.py`; `core/memory`/`core/knowledge` own their own SQLite persistence rather than waiting for domain models; ChromaDB stays exactly where ADR-0005 put it; `HashingTextEmbedder` uses `hashlib`, not builtin `hash()`; `core/memory/metrics.py` doesn't subscribe to `EventBus`; `MemoryRegistry` is generic; numpy currently uninstalled.)*

**New this session:**

- **`core/parsers` and `core/db/evidence_repository.py` reuse existing patterns rather than inventing new ones.** `BaseParser` is `BaseTool`/`BaseAgent`'s template-method shape applied to a third layer; `ParserRegistry` is `ToolRegistry`'s pattern, extended with plugin metadata; `core/parsers/metrics.py`/`events.py` are `core/memory/metrics.py`'s "self-contained, no `EventBus`" pattern applied again. Considered and rejected: inventing parser-specific abstractions from scratch — rejected because the existing patterns already solve the same problems (identity, validation, lifecycle, leaf-layer independence) and a fourth divergent shape would cost future readers more than it'd save.
- **One `ParserRegistry`, not two ("Evidence Registry" + "Parser Registry").** The task's wording suggested two separate registries; implemented as one, indexed by name, alias, evidence type, and extension, to avoid duplicate lookup logic (constitution §1.3). Documented explicitly in ADR-0011's "Alternatives Considered."
- **`ParserRegistry` is plugin-capable via `importlib.metadata` entry points (`cdc.parsers` group), requested during planning before implementation began.** A missing/empty group is a no-op; one failing plugin is logged and skipped, never aborting discovery of the rest — the same "fail gracefully" contract every other framework piece follows.
- **`core/db/models/` is a package, not a single `models.py`, requested during planning.** `models/evidence.py` today; every future domain table gets its own sibling module. `core/db/migrations/env.py` imports the package (not a specific module) so autogeneration keeps discovering new tables without an `env.py` edit.
- **`NormalizedEvidence` is a container of `EvidenceRecord`s, not a single flat record.** The task's canonical per-event schema (timestamp/host/user/ip/event_type/severity) and blueprint's per-artifact Parser output were reconciled by splitting them into two levels — documented in ADR-0011 since it's a non-obvious modeling call.
- **`defusedxml`, not stdlib `xml.etree.ElementTree`, for the one XML-handling parser.** Justified specifically by the task's "prevent unsafe parsing" requirement and verified against a hand-crafted XXE-attempt fixture (the entity is never resolved; the parser degrades instead of crashing or leaking).
- **No `chardet`/`python-magic` dependency for encoding/MIME detection.** stdlib BOM-sniffing + a fixed `utf-8`/`utf-8-sig`/`latin-1` fallback ladder, plus extension/content heuristics, are sufficient for this framework's nine known formats — avoids an unjustified new dependency (constitution §10).
- **No FastAPI route this session.** `Case` doesn't exist, so a case-scoped upload endpoint would be wired to an orphan UUID — explicitly flagged as a scope cut, not a silent gap, and queued as natural M1 follow-up.

---

## Public Interfaces

*(M0/M3/M6 interfaces — `core.config`, `core.logging`, `core.exceptions`, `core.schemas`, `core.interfaces`, `core.db.{Base, BaseRepository, Database, Entity}`, `core.agents.*`, `core.tools.*`, `core.graph.*`, `core.memory.*`, `core.knowledge.*`, `apps.api.*` — unchanged from prior sessions except as noted below.)*

**Parser contracts:** `core.parsers.models.{EvidenceType, Severity, ChainOfCustody, EvidenceRecord, NormalizedEvidence}`, `core.parsers.base.{BaseParser, RawEvidenceInput, ParserRunResult}`, `core.parsers.exceptions.{ParserError, UnsupportedFormatError, ParserValidationError, FileTooLargeError, EmptyFileError, PathTraversalError, EncodingDetectionError, MalformedEvidenceError}`.

**Parser framework:** `core.parsers.registry.{ParserRegistry, ParserRegistration, default_parser_registry, PLUGIN_ENTRY_POINT_GROUP}`, `core.parsers.factory.select_parser`, `core.parsers.detection.{detect_encoding, detect_mime_type, sniff_evidence_type}`, `core.parsers.validation.{validate_filename, validate_extension, validate_size, validate_upload, MAX_RECORDS_PER_ARTIFACT}`, `core.parsers.fingerprint.{compute_sha256, FileFingerprint}`, `core.parsers.metrics.{ParserMetricsCollector, ParserStats, ParserMetricsSnapshot}`, `core.parsers.events.{ParserEvent, ParserEventType, ParserEventPublisher}`, `core.parsers.audit.{AuditAction, log_evidence_audit_event}`.

**Concrete parsers:** `core.parsers.{ssh_auth_parser.SshAuthParser, apache_access_parser.ApacheAccessParser, apache_error_parser.ApacheErrorParser, syslog_parser.SyslogParser, windows_event_parser.WindowsEventParser, json_evidence_parser.JsonEvidenceParser, csv_evidence_parser.CsvEvidenceParser, nmap_parser.NmapXmlParser, plaintext_parser.PlainTextParser}`.

**Domain persistence:** `core.db.models.{Evidence, EvidenceStatus}`, `core.db.evidence_repository.EvidenceRepository`.

**Evidence service:** `core.services.evidence_service.{EvidencePipeline, ingest_evidence, get_evidence, list_evidence_for_case, EvidenceIngestionResult, DEGRADED_CONFIDENCE_THRESHOLD}`.

No `Case`/`Finding`/`MitreTechnique`/`TimelineEvent`/`Report` models/schemas, concrete specialist agents, concrete tools, `core/agents/parser_agent.py`, populated knowledge data, or `/api/v1` evidence routes exist as public interfaces yet.

---

## Remaining Work

Unchanged in substance from the prior session's plan (see `docs/roadmap.md`), except M1's parser/persistence piece is now done ahead of schedule:

1. **M1 — remaining piece.** `Case`/`Finding`/`MitreTechnique`/`TimelineEvent`/`Report` domain models (`core/db/models/case.py`, etc.) + their Alembic migration (including the follow-up migration turning `Evidence.case_id` into a real FK); `core/tools/scoring.py`; `core/agents/soc_analyst_agent.py` (registered via `AgentRegistry`, added to `investigation_graph.py`, constructed with a real `SQLiteCaseMemory`); first real `/api/v1` route + wiring `core.services.evidence_service.ingest_evidence()` and `core.services.case_service` together.
2. **M2 — MITRE mapping + Phishing module.** MITRE knowledge layer + MITRE Agent (the first concrete `KnowledgeSource`); Phishing Investigation Agent + `email_parser.py` (a `BaseParser` subclass, following this session's exact pattern) + `core/security/prompt_guard.py`.
3. **M3 — remaining piece:** wire real agents through the now-implemented framework (unchanged from prior sessions' note).
4. **M4 — Remaining specialist modules**, including `nessus_parser.py`/`openvas_parser.py`/`source_code_parser.py` (following this session's `BaseParser` pattern) and `core/agents/parser_agent.py` (the LLM-fallback wrapper this session's framework was designed to slot under without any change).
5. **M5 — Incident Response synthesis + Reporting.**
6. **M6 — remaining piece:** swap `InMemoryVectorStore` for real ChromaDB, populate knowledge data, Threat Timeline/MITRE heatmap/AI Analyst Chat UI.
7. **M7 — Hardening, tests, docs, GitHub polish.**

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md`/`03_constitution.md` don't exist; `make migrate`/`make seed` are no-ops; `apps/web` has no code; harmless Starlette deprecation warnings in test output; no performance/load testing; no CI has ever actually run on GitHub; `scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import rule, not the full sibling-layer matrix — this session's `core/services → core/parsers`/`core/memory` edge was verified manually via `grep`, same as prior sessions' `core/memory`/`core/knowledge` layering; `InMemoryVectorStore` is O(n) brute-force; `HashingTextEmbedder` is not semantic; numpy not installed.)*

- **`windows_event_parser.py` handles only the CSV/XML export abstraction, not binary `.evtx` files.** Explicitly scoped this way per the task's own allowance; a real `.evtx` parser (e.g. via `python-evtx`) is a documented future extension, not a bug.
- **Traditional syslog lines have no year** (`syslog_common.py::parse_syslog_line`); the current UTC year is assumed unless a `reference_year` is explicitly passed. A line timestamped near a year boundary could be misattributed by one year — a known, documented limitation of the format itself, not fixable without external context.
- **`Evidence.case_id` has no referential integrity yet** (plain UUID, no FK) — a caller could persist evidence against a `case_id` that doesn't correspond to any real case, since `Case` doesn't exist. Tracked, not a bug; resolved when Milestone M1 adds `Case` and its follow-up FK migration.
- **No `/api/v1` evidence route exists** — `ingest_evidence()` is only callable from `core/services` directly (as this session's tests do), not yet from `apps/api` or `apps/web`.

---

## Dependencies

Runtime (`requirements.txt`): **new this session** — `defusedxml>=0.7` (XXE-safe XML parsing, used only by `core/parsers/nmap_parser.py`). No other new runtime dependency; parsing otherwise uses only the stdlib (`csv`, `json`, `mimetypes`, `hashlib`, `re`).

Dev (`requirements-dev.txt`): **new this session** — `types-defusedxml` (mypy stubs).

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`), with one prior commit: `0ee65d5 feat(memory): implement Memory & Knowledge Layer ahead of schedule` (which itself followed `eae4fb8`, the M0 + Multi-Agent Framework commit). This session's Evidence Ingestion & Parser Framework work is **uncommitted**:

- Modified: `CHANGELOG.md`, `context/current_state.md`, `docs/roadmap.md`, `docs/dependency-rules.md`, `docs/diagrams/README.md`, `core/parsers/README.md`, `core/db/README.md`, `core/db/__init__.py`, `core/parsers/__init__.py`, `core/services/README.md`, `core/config/settings.py`, `core/db/migrations/env.py`, `core/db/migrations/README.md`, `.env.example`, `.gitignore`, `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `tests/conftest.py`.
- Untracked (new): `docs/adr/0011-evidence-ingestion-pipeline-shape.md`, `docs/diagrams/{evidence-ingestion-pipeline,parser-lifecycle}.mmd`, all 21 new `core/parsers/*.py` modules, `core/db/models/{__init__,evidence}.py`, `core/db/evidence_repository.py`, `core/db/migrations/versions/20df7c637d48_create_evidence_table.py`, `core/services/evidence_service.py`, `data/evidence_uploads/` (storage dir, `.gitkeep` + `README.md` only), 5 new `data/sample_evidence/` fixtures (+ `malformed/` subfolder), and 20 new `tests/unit/test_{parsers,db_evidence,evidence_service}_*.py` files.

The working tree is in a complete, self-consistent, fully-tested state (352 tests passing — mypy/ruff/dependency-rules clean, migration verified against a real SQLite DB) but has not yet been committed; commit only when the user explicitly asks.

---

## Next Recommended Prompt

> Implement the remaining piece of Milestone M1 exactly as scoped in `docs/roadmap.md` and this file's "Remaining Work" section: add `core/db/models/case.py` (and `finding.py`, `mitre_technique.py`, `timeline_event.py`, `report.py`) defining `Case`, `Finding`, `MitreTechnique`, `TimelineEvent`, and `Report` (each inheriting `core.db.Entity`, per `context/01_blueprint.md` §8 and `context/03_engineering_constitution.md` §7), generate the Alembic migration against them (including a follow-up migration that turns `Evidence.case_id` into a real foreign key against the new `Case` table — additive, per constitution §7), implement `core/tools/scoring.py` as a concrete `BaseTool` subclass, and implement `core/agents/soc_analyst_agent.py` as a concrete `BaseAgent` subclass — constructed with a real `core.memory.case_memory.SQLiteCaseMemory` rather than `None` — registered into `AgentRegistry` and wired into `core/graph/investigation_graph.py` following `docs/agent-design.md`'s "Adding a new agent" section. Wire `core.services.evidence_service.ingest_evidence()` and the new `core.services.case_service` together, and add the first real `/api/v1` route (`apps/api/routers/cases.py` and/or `evidence.py`) so a case can actually be created and have evidence uploaded to it end-to-end. Do not build the OWASP/Vulnerability/Phishing/etc. agents yet, and do not populate any MITRE/OWASP knowledge data yet — those are later milestones. Preserve every existing file and architectural decision described in this document, including the Multi-Agent Framework, the Memory & Knowledge Layer, and the Evidence Ingestion & Parser Framework built in prior sessions; only extend them.
