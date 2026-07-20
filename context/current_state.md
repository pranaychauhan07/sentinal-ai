# Current Project State

**Project:** Cyber Defense Copilot — an AI-native, case-centric SOC analyst workbench (capstone Project 9: a multi-agent cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator).

**Project root:** `C:\Users\prana\ai security`

**This file is the single source of truth for "what actually exists right now."** It is regenerated (overwritten, not appended) at the end of each implementation session. Read this file before reading anything else when resuming work.

---

## Completed Features

This session implemented the **Vulnerability Assessment Agent Framework**
end-to-end — an explicit ADR: **ADR-0017, Vulnerability Assessment
Framework** (`docs/adr/0017-vulnerability-assessment-framework.md`). This
closes Milestone M4's Vulnerability Assessment Agent piece and adds the
**third** concrete specialist agent (after `SocAnalystAgent` M1,
`PhishingAgent` M2), proving the same three-step extension pattern
(parser/tool in its owning leaf package, an agent declaring a distinct
capability, two lines in `investigation_graph.py`) a third time.

### M0/M1/M2/M3 frameworks (unchanged from prior sessions)

Configuration, logging, shared contracts, DB foundation, FastAPI app,
governance, `core/agents`/`core/tools`/`core/graph` framework,
`core/memory`/`core/knowledge` framework (minus the new `cvss_calculator.py`,
below), `core/threat_intel` framework (20 IOC types), `core/findings`/
`core/knowledge/mitre` (Finding & MITRE Engine), `Case`/`Evidence`/`Finding`/
`TimelineEvent`/`Report` domain models, `SocAnalystAgent`, `PhishingAgent`,
`core/security/prompt_guard.py`, the Case lifecycle/ownership/tags/notes/
events/metrics extension (ADR-0015), and
`core/services/case_service.py`'s `investigate_new_evidence()` orchestrator
— all unchanged except where explicitly noted below.

### Vulnerability Assessment Framework (new this session, ADR-0017)

- **`core/knowledge/cvss_calculator.py`** (new, the blueprint's named
  location) — `CvssCalculator` (unified parse/score facade). Implements the
  official, published NVD/FIRST base-score formulas for CVSS v2.0 and
  v3.0/3.1, each independently hand-verified against FIRST's own worked
  reference examples during implementation. **CVSS v4.0 support is
  deliberately scope-cut to vector parsing/format validation only** — v4.0's
  base score is defined by a ~90,000-row MacroVector lookup table (FIRST's
  spec), not a closed-form formula; a wrong reimplementation would be worse
  than the documented gap. Its own `CvssSeverity` scale (never a reuse of a
  sibling leaf's).
- **`core/vulnerabilities/`** (new leaf package, peer to `core/threat_intel`/
  `core/findings`, mirroring their file-for-file shape) — `models.py`
  (`VulnerabilityRecord` with three independent optional CVSS slots since a
  single scan-report row commonly carries both a v2 and v3 score
  simultaneously; `VulnerabilityScore`, `ScoredVulnerability`,
  `AssetCorrelation`, `VulnerabilityFinding` — deliberately no remediation
  field; `NormalizedVulnerabilityIntel`; own `VulnerabilitySeverity`/
  `VulnerabilityPriority`/`AssetCriticality`/`DetectionSource`/
  `SourceReliability` enums), `exceptions.py`, `cve_extractor.py` (CVE/CWE
  regex discovery + MITRE ID syntax validation), `validator.py`,
  `normalizer.py` (deterministic `asset_id` derivation), `dedup.py`
  (`VulnerabilityDeduplicationEngine`, configurable dedup key: asset+CVE /
  asset+plugin / same service / same port / custom), `asset_correlation.py`,
  `confidence_engine.py` (`VulnerabilityConfidenceEngine`, four configurable,
  sum-to-1.0-validated dimensions), `severity.py` (CVSS-to-severity mapping,
  scanner-code fallback, priority assignment folding in asset criticality),
  `scoring.py` (`VulnerabilityThreatScoringEngine`, six configurable,
  sum-to-1.0-validated dimensions: CVSS/severity/confidence/asset
  criticality/source reliability/evidence quality), `finding_generator.py`
  (groups scored vulnerabilities by CVE, or plugin absent a CVE, across
  assets into `VulnerabilityFinding`s), `extractor.py`
  (`VulnerabilityExtractionEngine`, reads structured per-finding fields from
  `EvidenceRecord.normalized_fields`, numeric-CVSS fallback for
  vector-less exports, oversized-dataset guard), `metrics.py`/`events.py`/
  `audit.py` (observability, mirroring `core.threat_intel`'s identical
  three-module split), `registry.py`/`interfaces.py`
  (`VulnerabilityProviderRegistry`, an unimplemented
  `VulnerabilityEnrichmentProvider` seam — no concrete provider, an honest
  scope cut mirroring `core.threat_intel`'s identical gap).
- **Four new parsers** (`core/parsers/`) — `nessus_parser.py` (`.nessus` XML
  via `defusedxml`, XXE-safe), `openvas_parser.py` (OpenVAS/GVM XML, same
  safety), `nessus_csv_parser.py`/`openvas_csv_parser.py` (their CSV export
  counterparts, sharing new `csv_common.py`'s case-tolerant column lookup
  helper). Four new additive `EvidenceType` values
  (`NESSUS_XML`/`NESSUS_CSV`/`OPENVAS_XML`/`OPENVAS_CSV`). All four place
  structured CVE/CWE/CVSS/port/service fields directly into
  `EvidenceRecord.normalized_fields` — the existing
  `VulnerabilityExtractionEngine` reads these without any new
  extraction/scoring code. Registered in `default_parser_registry()`.
- **`core/db/models/vulnerability.py`** (`Vulnerability`, new) + **`core/db/
  vulnerability_repository.py`** (new) — mirrors `IOC`'s shape exactly, both
  `case_id`/`evidence_id` real foreign keys from the start (unlike `IOC`'s
  original two-step tightening — `Case`/`Evidence` both already existed by
  the time this table was introduced). Two new migrations (create
  `vulnerabilities` table; additively extend `timeline_event_type_enum` with
  `VULNERABILITY_ASSESSED`), both verified end-to-end (upgrade → downgrade →
  re-upgrade against a throwaway SQLite DB, schema inspected directly).
- **`core/services/vulnerability_service.py`** (new) — `VulnerabilityPipeline`,
  the ten-stage assessment pipeline (extract → validate → normalize →
  deduplicate → correlate → score → generate_findings → persist →
  publish_event → notify_memory), mirroring
  `threat_intel_service.IOCExtractionPipeline`'s shape exactly. Gets the
  documented dependency-rules exception 4e (mirrors 4b).
- **`core/tools/vuln_tools.py`** (`VulnerabilityAssessmentTool`, new) —
  aggregates already-computed finding data (severity, priority, composite
  score) into a case-level summary; never recomputes CVSS/severity/threat
  score itself.
- **`core/agents/vulnerability_agent.py`** (`VulnerabilityAssessmentAgent`,
  new) — the third concrete specialist agent, capability
  `vulnerability_assessment`. Deliberately thin: reads
  `CaseInvestigationState.vulnerability_records` (new state field, plain
  `dict[str, object]` entries — `core/agents` has no dependency-rules.md
  import edge onto `core/vulnerabilities`, identical reasoning to
  `PhishingAgent`'s IOC-attribution pattern) and calls
  `VulnerabilityAssessmentTool` to produce a `VulnerabilityAssessment`.
- **`core/graph/investigation_graph.py`** (modified) — `VulnerabilityAssessmentAgent`
  registered/wired with the same two-line pattern the other two specialists
  established.
- **`core/services/case_service.py`** (modified) — `_EVIDENCE_TYPE_CAPABILITY`
  gained the four new `EvidenceType`s → `vulnerability_assessment`;
  `_run_specialist_agents` registers the third agent and accepts/hydrates
  `vulnerability_records`; `investigate_new_evidence()` conditionally calls
  `assess_vulnerabilities()` (only for actual scan-report evidence types —
  running it against a log/email would only ever produce rejected
  candidates) and reduces its already-generated `VulnerabilityFinding`s to
  plain dicts before hydrating state. `CaseInvestigationResult` gained
  `vulnerability_finding_count`/`highest_vulnerability_score`; new
  `_extract_vulnerability_assessment` mirrors `_extract_soc_risk`.
- **`apps/api/schemas.py`/`routers/evidence.py`** (modified) —
  `EvidenceUploadResponse` gained the same two fields (both
  `None`-defaulted, purely additive). No router changes needed for
  `.nessus`/OpenVAS dispatch — the existing parser factory's extension/
  content-sniff selection already routes them.
- **Testing** — 168 new tests (989 total, up from 821): CVSS calculator
  unit tests against hand-verified FIRST reference vectors (v2, v3.0/3.1
  unchanged- and changed-scope, v4.0 validation-only), unit tests for every
  `core/vulnerabilities` module (cve_extractor, validator, normalizer,
  dedup, asset_correlation, confidence_engine, severity, scoring,
  finding_generator, extractor, metrics, events, registry), unit tests for
  all four new parsers (including a crafted XXE payload test per XML
  format, numeric-CVSS-fallback cases, malformed/empty-content degradation),
  the DB repository, the tool, the agent, an integration test proving a real
  Nessus scan fixture (two hosts sharing one CVE plus one host-specific
  finding) correctly deduplicates/correlates/aggregates end to end through
  persistence, a malformed-report regression test (one bad candidate never
  aborts the rest), and API `TestClient`/`case_service` integration tests
  proving a `.nessus` upload routes to `VulnerabilityAssessmentAgent` (not
  `SocAnalystAgent`) with zero router changes. mypy (`--strict` on `core/`),
  `ruff check`/`format`, `scripts/check_dependency_rules.py`, and the full
  pytest suite all pass.

**Explicitly NOT built, by ADR-0017's stated scope:** remediation/patch
planning (no `VulnerabilityFinding` field for it at all); Incident Response
synthesis; LLM reasoning of any kind; a concrete
`VulnerabilityEnrichmentProvider` (e.g. a live NVD API lookup); CVSS v4.0
base-score computation (vector validation only); OWASP Security Agent,
Linux Security Agent, Threat Hunting Agent (M4's remaining pieces); any
redesign of `SocAnalystAgent`, `PhishingAgent`, `Case`, or any other
already-completed module.

---

## Repository Status

```
apps/
  api/            schemas.py (MODIFIED: +2 vulnerability response fields) +
                   routers/{system,cases,evidence(MODIFIED: passes through
                   vulnerability fields),iocs,findings,v1}.py             [implemented]
  web/             Streamlit frontend                                     [README only]
core/
  config/         settings.py (MODIFIED: +VULNERABILITY_MAX_RECORDS_
                   PER_ARTIFACT)                                          [implemented]
  logging/        (unchanged)                                             [implemented]
  agents/         soc_analyst_agent.py, phishing_agent.py (unchanged) +
                   vulnerability_agent.py (NEW — third concrete
                   specialist agent)                                      [implemented — 3 concrete specialist agents]
  tools/          scoring.py, phishing_tools.py (unchanged) +
                   vuln_tools.py (NEW — VulnerabilityAssessmentTool)       [implemented — 3 concrete tools]
  memory/         (unchanged)                                             [implemented — framework only]
  knowledge/      mitre/ (unchanged) + cvss_calculator.py (NEW)            [implemented]
  graph/          investigation_graph.py (MODIFIED: +VulnerabilityAssessmentAgent
                   wiring) + state.py (MODIFIED: +vulnerability_records
                   field) + routing.py/workflow_engine.py/events.py/
                   retry.py/failure_recovery.py/metrics.py (unchanged)     [implemented]
  db/             models/vulnerability.py (NEW — Vulnerability,
                   VulnerabilityStatus) + models/__init__.py (MODIFIED) +
                   vulnerability_repository.py (NEW) + migrations/versions/
                   (+2 NEW: create vulnerabilities table, extend
                   timeline_event_type_enum) + all M1/ADR-0015 models
                   (unchanged)                                            [implemented — 10 real domain tables + 5 reference tables]
  parsers/        models.py (MODIFIED: +4 EvidenceType values) +
                   detection.py (unchanged this session) + registry.py
                   (MODIFIED: +4 parser registrations) + csv_common.py
                   (NEW — shared CSV lookup helper) +
                   nessus_parser.py, nessus_csv_parser.py,
                   openvas_parser.py, openvas_csv_parser.py (NEW) +
                   the ten M1/M2 parsers (unchanged)                       [implemented — 14 concrete parsers]
  vulnerabilities/  (NEW leaf package — models, exceptions, cve_extractor,
                   validator, normalizer, dedup, asset_correlation,
                   confidence_engine, severity, scoring, finding_generator,
                   extractor, metrics, events, audit, registry,
                   interfaces)                                            [implemented]
  threat_intel/   (unchanged)                                             [implemented]
  findings/       (unchanged)                                             [implemented]
  security/       prompt_guard.py (unchanged); pii_redaction.py,
                   approval_gate.py still not started                     [implemented — 1 of 3 modules]
  reporting/      (empty — README only)                                   [not started]
  services/       case_service.py (MODIFIED: +vulnerability capability
                   routing, +_run_specialist_agents third agent,
                   +_extract_vulnerability_assessment) +
                   vulnerability_service.py (NEW — VulnerabilityPipeline,
                   assess_vulnerabilities) + evidence_service.py,
                   threat_intel_service.py, finding_service.py (unchanged);
                   report_service.py                                      [implemented]
data/             sample_evidence/nessus_scan.nessus (NEW fixture — two
                   hosts sharing one CVE plus one host-specific finding)
scripts/          (unchanged)
tests/
  unit/           136 test modules (+21 this session: test_knowledge_cvss_
                   calculator.py, test_vulnerabilities_{cve_extractor,
                   validator,normalizer,dedup,asset_correlation,
                   confidence_engine,severity,scoring,finding_generator,
                   extractor,metrics,events,registry}.py,
                   test_parsers_{nessus,nessus_csv,openvas,openvas_csv}.py,
                   test_db_vulnerability_repository.py,
                   test_tools_vuln_tools.py, test_agents_vulnerability.py;
                   +1 existing test renamed/extended:
                   test_parsers_registry.py)
  integration/    8 test modules (+1 NEW:
                   test_vulnerability_pipeline_integration.py; +2 extended:
                   test_case_service_pipeline.py, test_api_case_routes.py,
                   test_investigation_graph.py [node-set assertion extended])
  golden/         (empty — no report generation exists yet)
docs/             18 markdown docs (roadmap.md addendum) +
                   docs/adr/ (18 ADR files incl. template, +0017) +
                   docs/dependency-rules.md (MODIFIED: rule 4e added,
                   rules 4d/5 extended) + docs/diagrams/ (unchanged)
context/
  01_blueprint.md, 03_engineering_constitution.md, current_state.md (this file)
```

989 tests passing as of this session (821 prior → 989 now: 168 new).
Modified this session: `core/parsers/{models,registry}.py`,
`core/config/settings.py`, `.env.example`, `core/db/models/__init__.py`,
`core/db/models/timeline_event.py`, `core/graph/{state,investigation_graph}.py`,
`core/services/case_service.py`, `apps/api/{schemas,routers/evidence}.py`,
`docs/roadmap.md`, `docs/dependency-rules.md`, `core/{knowledge,agents,tools,
parsers,db,services}/README.md`, `tests/integration/{test_case_service_pipeline,
test_api_case_routes,test_investigation_graph}.py`, `CHANGELOG.md`, and this
file — all currently uncommitted (see "Current Git Status" below).

**Naming note carried forward:** `context/02_repository.md` still does not
exist. The actual files remain `context/01_blueprint.md` and
`context/03_engineering_constitution.md`.

---

## Architecture Status

Fully aligned with `context/01_blueprint.md`, extending (not reversing)
ADR-0001 through ADR-0016 per ADR-0017's explicit scoping. Ten deliberate
decisions, all documented in
`docs/adr/0017-vulnerability-assessment-framework.md`:

1. **`core/vulnerabilities/` mirrors `core/threat_intel`'s file-for-file
   shape** — a third sibling leaf package, same tier, same deterministic-
   first design.
2. **`VulnerabilitySeverity` is its own enum** — never a reuse of
   `core.parsers.models.Severity` or `core.threat_intel.models.
   ThreatSeverity`, matching the already-established "each leaf owns its
   own severity scale" precedent.
3. **`core/knowledge/cvss_calculator.py`** implements full CVSS v2/v3.x
   scoring; CVSS v4.0 is vector-validation-only (no public closed-form
   formula exists).
4. **`VulnerabilityRecord` has three independent, optional CVSS slots**
   (v2/v3/v4) — a single scan row commonly reports two simultaneously.
5. **Scan-report parsers extract structured fields, never regex over free
   text as the primary path** — unlike log/email parsers.
6. **A numeric-only CVSS fallback** handles export variants that omit the
   full vector string.
7. **`vuln_tools.py`/`vulnerability_agent.py` never recompute CVSS,
   severity, or a threat score** — `core/agents` has no import edge onto
   `core/vulnerabilities`, so state stays plain-dict-typed.
8. **`VulnerabilityFinding` is not persisted to `findings`** — matches
   `SocFinding`/`PhishingVerdict`'s identical precedent; the underlying
   `Vulnerability` rows *are* persisted.
9. **`assess_vulnerabilities()` only runs against actual scan-report
   evidence types** — unlike IOC extraction's genuine generality.
10. **`case_service.py`'s capability-routing table gains a fourth mapping
    and a third registered agent** — closing a real demo criterion, not
    just an addition.

`docs/roadmap.md` records this as a dated addendum under M4's still-open
entry (OWASP/Linux/Threat Hunting agents remain outstanding, so M4 itself
stays unchecked). No approved architectural decision (ADR-0001 through
0016) was reversed.

---

## Key Decisions

*(Carried forward from prior sessions — still true, unchanged: see prior
sessions' "Key Decisions" sections in git history.)*

**New this session:**

- **CVSS v4.0 base-score computation was deliberately not implemented** —
  FIRST's v4.0 specification defines the base score via a ~90,000-row
  MacroVector lookup table, not a closed-form formula; a wrong
  reimplementation would silently misclassify severity, which is worse than
  the documented "vector validated, score deferred to the scanner's own
  reported value" gap. Vector parsing/format validation is fully
  implemented.
- **`core/vulnerabilities` was built as its own leaf package rather than
  extending `core/threat_intel` or `core/findings`** — vulnerabilities are
  not IOCs (no indicator-of-compromise semantics) and are not MITRE-mapped
  findings; forcing them into either existing engine would have violated
  each package's own documented scope boundary (ADR-0012/0013).
- **`assess_vulnerabilities()` is gated to actual scan-report `EvidenceType`s
  only**, discovered while designing the case_service wiring — unlike IOC
  extraction (generic regex discovery, meaningfully applicable to any
  evidence type), vulnerability extraction is structured-field-based;
  running it against a log or email would only ever produce candidates that
  immediately fail validation, pure wasted work with no informational value.
- **`VulnerabilityRecord` needed three independent CVSS slots, not one** —
  discovered while designing the Nessus parser: real Nessus exports report
  both `cvss_base_score` (v2) and `cvss3_base_score` (v3) unconditionally on
  the same finding. A single "the" CVSS field would have silently discarded
  one of them.

---

## Public Interfaces

*(M0–M4/ADR-0015/0016 interfaces — unchanged from prior sessions except as
noted below.)*

**New/changed this session:**

`core.knowledge.cvss_calculator.{CvssCalculator, CvssScore, CvssSeverity,
CvssVersion, CVSSVectorParseError, parse_cvss_v2_vector,
parse_cvss_v3_vector, validate_cvss_v4_vector, calculate_cvss_v2_base_score,
calculate_cvss_v3_base_score, classify_cvss_severity}` (new).

`core.vulnerabilities.*` (new package) — `models.{VulnerabilityRecord,
VulnerabilityScore, ScoredVulnerability, AssetCorrelation,
VulnerabilityFinding, NormalizedVulnerabilityIntel, VulnerabilitySeverity,
VulnerabilityPriority, AssetCriticality, DetectionSource,
SourceReliability}`, `cve_extractor.{extract_cve_ids, extract_cwe_ids,
is_valid_cve_id, normalize_cve_id}`, `validator.VulnerabilityValidator`,
`normalizer.{VulnerabilityNormalizer, derive_asset_id}`,
`dedup.{VulnerabilityDeduplicationEngine, DedupStrategy}`,
`asset_correlation.correlate_by_asset`,
`confidence_engine.{VulnerabilityConfidenceEngine,
VulnerabilityConfidenceWeights}`, `severity.{severity_from_cvss,
severity_from_scanner_code, assign_priority}`,
`scoring.{VulnerabilityThreatScoringEngine, VulnerabilityScoringWeights}`,
`finding_generator.VulnerabilityFindingGenerator`,
`extractor.{VulnerabilityExtractionEngine, BaseVulnerabilityExtractor}`,
`metrics.VulnerabilityMetricsCollector`,
`events.{VulnerabilityEvent, VulnerabilityEventPublisher,
VulnerabilityEventType}`, `registry.{VulnerabilityProviderRegistry,
default_vulnerability_provider_registry}`,
`interfaces.VulnerabilityEnrichmentProvider`.

`core.parsers.models.EvidenceType` gained `NESSUS_XML`, `NESSUS_CSV`,
`OPENVAS_XML`, `OPENVAS_CSV`. `core.parsers.{nessus_parser.NessusXmlParser,
nessus_csv_parser.NessusCsvParser, openvas_parser.OpenVasXmlParser,
openvas_csv_parser.OpenVasCsvParser, csv_common.lookup_column}` (new).

`core.db.models.vulnerability.{Vulnerability, VulnerabilityStatus}` (new).
`core.db.vulnerability_repository.VulnerabilityRepository` (new).
`core.db.models.timeline_event.TimelineEventType.VULNERABILITY_ASSESSED`
(new).

`core.services.vulnerability_service.{VulnerabilityPipeline,
assess_vulnerabilities, VulnerabilityAssessmentResult, get_vulnerability,
list_vulnerabilities_for_case}` (new).

`core.tools.vuln_tools.{VulnerabilityAssessmentTool,
VulnerabilityAssessmentInput, VulnerabilityAssessmentOutput,
VulnerabilityFindingSummaryInput}` (new).

`core.agents.vulnerability_agent.{VulnerabilityAssessmentAgent,
default_vulnerability_agent_tool_registry, VulnerabilityAssessment,
VulnerabilityAgentResult}` (new).

`core.graph.state.CaseInvestigationState.vulnerability_records` (new field).
`core.graph.investigation_graph.build_investigation_graph` now also
registers/wires `VulnerabilityAssessmentAgent` (node name
`vulnerability_agent`).

`core.services.case_service`: `_EVIDENCE_TYPE_CAPABILITY` gained four
entries; `_run_specialist_agents` gained `vulnerability_records` parameter
and registers a third agent; new `_extract_vulnerability_assessment`.
`CaseInvestigationResult` gained `vulnerability_finding_count`/
`highest_vulnerability_score`.

`apps.api.schemas.EvidenceUploadResponse` gained
`vulnerability_finding_count`/`highest_vulnerability_score` (both optional,
default `None`).

No OWASP/Linux Security/Threat Hunting/Incident Response/MITRE Mapping
Agent, LLM reasoning, `/api/v1/reports` route, or
`core.security.{pii_redaction,approval_gate}` implementation exist as
public interfaces yet.

---

## Remaining Work

1. **M2 — still open.** A concrete `core/agents/mitre_mapping_agent.py`
   wrapping `core.knowledge.mitre`'s lookup engine.
2. **M3 — closed** (prior session).
3. **M4 — remaining pieces.** OWASP Security Agent (AST-based, not regex),
   Linux Security Agent, `core/agents/threat_hunter_agent.py` (extends
   `core.threat_intel` to cross-log IOC hunting).
4. **M5 — Incident Response synthesis + Reporting.** Incident Response
   Agent (the correct home for cross-agent recommendation/escalation/
   remediation synthesis — still not built, by design), Report Generator
   Agent, Jinja2/ReportLab templates, Plotly charts, `/api/v1/reports`
   route.
5. **M6 — remaining piece.** Swap `InMemoryVectorStore` for real ChromaDB,
   populate remaining knowledge data (OWASP, playbooks), Threat Timeline/
   MITRE heatmap/AI Analyst Chat UI.
6. **M7 — Hardening, tests, docs, GitHub polish.**
7. **Deferred, not scheduled:** `core/security/pii_redaction.py`/
   `approval_gate.py`; a structured read endpoint for `Case.labels`; a
   concrete `VulnerabilityEnrichmentProvider` (e.g. a live NVD API lookup);
   CVSS v4.0 base-score computation; reconciling `SocFinding`/
   `PhishingVerdict`/`VulnerabilityFinding` (all in-memory only) with the
   persisted `Finding` table into one shared representation; an
   asset-criticality inventory (currently always `AssetCriticality.MEDIUM`
   by default everywhere).

---

## Known Issues

*(Carried forward, still true: `context/02_repository.md` doesn't exist;
`apps/web` has no code; harmless Starlette deprecation warnings in test
output; no CI has ever actually run on GitHub;
`scripts/check_dependency_rules.py` only checks the streamlit/fastapi-import
rule, not the full sibling-layer matrix; `InMemoryVectorStore` is O(n)
brute-force; `HashingTextEmbedder` is not semantic; numpy not installed;
`windows_event_parser.py` handles only CSV/XML export, not binary `.evtx`;
`SocAnalystAgent`'s/`PhishingAgent`'s finding output is still not persisted
to the `findings` table; `Report` still has no consumer; on PostgreSQL,
downgrading the `CaseStatus`/`timeline_event_type` enum-extension migrations
is a no-op; `Case.labels` has no read endpoint; no case-level authorization/
ownership check; the duplicate-case guard is intentionally narrow.)*

- **`VulnerabilityFinding` is also not persisted to `findings`**, the
  identical gap `SocFinding`/`PhishingVerdict` already had — now three
  specialist agents' outputs live only in `CaseInvestigationState`/in-process
  `AgentExecutionResult`, not the DB (the underlying per-record
  `Vulnerability` rows *are* persisted, unlike IOC-less findings). Deferred,
  not decided by default.
- **CVSS v4.0 support is vector parsing/validation only** — no base-score
  computation. Documented in `core/knowledge/cvss_calculator.py`'s module
  docstring and `core/vulnerabilities/README.md`, not silently overstated.
- **Multi-CVE scan findings are folded to their first CVE** as the record's
  primary identifier (a `<ReportItem>`/`<result>` citing more than one CVE)
  — every cited CVE still appears in the description/references text, so
  the regex fallback can discover the rest in a future pass, but today only
  one becomes the record's `cve_id`.
- **No asset-criticality inventory exists** — `AssetCriticality.MEDIUM` is
  the default used everywhere in scoring/priority assignment until a
  case-specific asset inventory feature is built.
- **`_EVIDENCE_TYPE_CAPABILITY`/`_VULNERABILITY_SCAN_EVIDENCE_TYPES` in
  `case_service.py` are simple dicts/frozensets**, not a general routing
  engine — a future specialist agent needing multi-capability or
  content-based (not just `EvidenceType`-based) routing will need a small
  design decision, not automatically fall out of the current shape.

---

## Dependencies

Runtime (`requirements.txt`): **no new dependencies this session** — the
new parsers reuse the already-vendored `defusedxml` (via the existing
`nmap_parser.py` precedent) and stdlib `csv`; CVSS math is pure Python.

Dev (`requirements-dev.txt`): unchanged.

---

## Current Git Status

A git repository exists (`main` branch: `main`; working branch: `master`).
All prior-session work (through the Phishing Agent / ADR-0016 commit) is
committed.

This session's Vulnerability Assessment Framework work added/modified
(63 files touched, all currently uncommitted):
- New: `docs/adr/0017-vulnerability-assessment-framework.md`,
  `core/knowledge/cvss_calculator.py`, the full `core/vulnerabilities/`
  package (17 files), `core/parsers/{nessus_parser,nessus_csv_parser,
  openvas_parser,openvas_csv_parser,csv_common}.py`,
  `core/db/models/vulnerability.py`, `core/db/vulnerability_repository.py`,
  two new Alembic migrations, `core/services/vulnerability_service.py`,
  `core/tools/vuln_tools.py`, `core/agents/vulnerability_agent.py`,
  `data/sample_evidence/nessus_scan.nessus`, 21 new test files (unit) + 1
  new integration test file.
- Modified: `core/parsers/{models,registry}.py`, `core/config/settings.py`,
  `.env.example`, `core/db/models/{__init__,timeline_event}.py`,
  `core/graph/{state,investigation_graph}.py`,
  `core/services/case_service.py`, `apps/api/{schemas,routers/evidence}.py`,
  `docs/roadmap.md`, `docs/dependency-rules.md`,
  `core/{knowledge,agents,tools,parsers,db,services}/README.md`,
  `tests/unit/test_parsers_registry.py`,
  `tests/integration/{test_case_service_pipeline,test_api_case_routes,
  test_investigation_graph}.py`, `CHANGELOG.md`, `context/current_state.md`
  (this file).

Full suite (989 tests), `ruff check`/`format`, `mypy core --strict`, and
`scripts/check_dependency_rules.py` all pass. Commit only when the user
explicitly asks.

---

## Next Recommended Prompt

> Implement M4's remaining pieces: the OWASP Security Agent (AST-based
> static analysis via Python's `ast` module — constitution's own quality
> bar, "never just regex" — mapping SQLi/XSS/broken-auth patterns to OWASP
> Top-10 2021, per blueprint §7) and the Linux Security Agent (command/
> permission-string explainer and hardening advisor). Alternatively, close
> out M2 first with a concrete `core/agents/mitre_mapping_agent.py`
> wrapping `core.knowledge.mitre`'s existing `MitreLookup` (returning
> "unmapped" rather than a low-confidence guess when nothing matches),
> which is the one piece keeping M2's `docs/roadmap.md` checkbox open. Do
> **not** build the Incident Response Agent yet — that agent's job is
> case-wide cross-agent synthesis (recommendations, escalation,
> remediation) and depends on having more specialist agents' findings to
> actually synthesize; building it early was explicitly declined in a
> prior session as scope belonging to M5. Follow the exact three-step
> extension pattern `SocAnalystAgent`/`PhishingAgent`/
> `VulnerabilityAssessmentAgent` all three now demonstrate: a
> parser/tool in its owning leaf package, an agent in `core/agents/`
> declaring a distinct capability, and two lines in
> `core/graph/investigation_graph.py`. Preserve every existing file and
> architectural decision described in this document — including all three
> specialist agents, the Case lifecycle subsystem, the Finding & MITRE
> Engine, and the Vulnerability Assessment Framework — only extend them.
