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

- [x] **M1 — First real module, single agent, no orchestration.** Domain
      models (`Case`, `Finding`, `MitreTechnique`, `TimelineEvent`, `Report` —
      blueprint §8) + their Alembic migration, SOC Analyst Agent as a
      standalone single-node LangGraph + risk scoring
      (`core/tools/scoring.py`), constructed with a real
      `core.memory.case_memory.SQLiteCaseMemory`.
      Built ahead of schedule (`docs/adr/0011-evidence-ingestion-pipeline-shape.md`):
      the reusable Evidence Ingestion & Parser Framework — plugin-capable
      `ParserRegistry` (aliases, priority, versioning, enable/disable,
      `importlib.metadata` plugin discovery), deterministic
      `select_parser` factory, upload validation (size/extension/path-
      traversal), stdlib-only MIME/encoding detection, SHA-256
      fingerprinting, self-contained parser metrics/events, audit logging,
      and nine concrete parsers (`ssh_auth`, `apache_access`,
      `apache_error`, `syslog`, `windows_event` [CSV/XML EVTX abstraction],
      `json_evidence`, `csv_evidence`, `nmap_xml` [via `defusedxml`, XXE-safe],
      `plain_text`) producing the canonical `NormalizedEvidence` contract —
      plus the first real domain table, `Evidence`, its repository, and the
      ten-stage `EvidencePipeline` (`core/services/evidence_service.py`).
      **This session** (`docs/adr/0014-case-model-and-first-api-routes-shape.md`)
      closed the milestone: `core/db/models/{case,timeline_event,report}.py`
      + repositories, the FK-tightening migration turning `Evidence.case_id`/
      `IOC.case_id`/`Finding.case_id` into real foreign keys against
      `cases.id`, `core/tools/scoring.py` (`RiskScoringTool`),
      `core/agents/soc_analyst_agent.py` (the first concrete specialist
      agent, wired into `core/graph/investigation_graph.py` with zero
      framework changes), `core/services/case_service.py` (the
      `investigate_new_evidence()` orchestrator composing evidence
      ingestion → IOC extraction → Finding generation → SOC analysis, one
      `TimelineEvent` per stage), and the first real `/api/v1` routes
      (`cases`, `evidence`, `iocs`, `findings`). 33 new tests (662 total),
      mypy/ruff/dependency-rules clean.
      *Demo: `POST /api/v1/cases`, then `POST /api/v1/cases/{id}/evidence`
      with `data/sample_evidence/ssh_auth.log` → a real, saved,
      severity-classified SOC finding plus extracted IOCs and MITRE-mapped
      Findings, all visible via `GET /api/v1/cases/{id}/...` on refresh.*

      **2026-07-20 addendum** (`docs/adr/0015-case-management-extension.md`):
      hardened/extended the Case subsystem M1 shipped — not a new milestone,
      this milestone's own scope closed already. `CaseStatus` extended
      additively (five new escalation-capable states), `CasePriority`,
      case-level `risk_score` rollup, `owner_id`/`assignee_id`, `labels`,
      a new `CaseNote` entity (distinct from `TimelineEvent.MANUAL_NOTE`),
      a new `case_tags` join table, validated lifecycle transitions
      (`core/services/case_lifecycle.py`), `CaseEvent` domain-event
      publication (`core/services/case_events.py`), and case-level metrics
      (`core/services/case_metrics.py`). Ten new `/api/v1/cases/{id}/...`
      routes for assignment/priority/labels/tags/notes.

- [x] **M2 — MITRE mapping + Phishing module.** MITRE knowledge layer + MITRE
      Agent; Phishing Investigation Agent + email parser + prompt-injection
      guard (first attacker-controlled-text agent).
      **Built ahead of schedule** (`docs/adr/0013-finding-mitre-intelligence-engine-shape.md`):
      the MITRE knowledge layer's concrete data — `core/knowledge/mitre/`
      (`MitreAttackSource`, a real `KnowledgeSource`; a STIX 2.1 bundle
      loader reading only local, vendored files, never the network;
      `MitreLookup` fast lookups) — plus the full, reusable Finding & MITRE
      ATT&CK Intelligence Engine (`core/findings/`): a rule-based, data-driven
      `MitreMappingEngine` (twenty mapping rules covering every vendored
      technique, one-IOC-to-many-techniques and many-IOCs-to-one-technique
      via co-occurrence boosting), `EvidenceAggregator` (timeline
      reconstruction, chain-of-custody preservation), a configurable
      `ConfidenceEngine` (seven required dimensions, sum-to-1.0 validated),
      deterministic severity/priority/risk-score assignment, and a
      six-dimension, bucket-first `FindingDeduplicationEngine` — plus the
      third and fourth real domain tables/schemas: five MITRE reference
      tables (`mitre_tactics`/`techniques`/`software`/`groups`/`mitigations`,
      seeded only by `scripts/mitre/import_attack_bundle.py`) and
      `findings`/`finding_mitre_mappings` (a real many-to-many join table),
      and the ten-stage `FindingGenerationPipeline`
      (`core/services/finding_service.py`). No LLM reasoning, no
      investigation logic, no cross-case correlation — explicitly out of
      scope per the ADR. A curated (not complete) real-ATT&CK-data subset is
      vendored (`data/mitre/raw/`, documented honestly in
      `data/mitre/README.md`); a MITRE Agent still doesn't exist.
      *Demo: two independent working modules, each producing a mapped/scored finding.*

      **2026-07-20 addendum** (`docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`):
      closed the milestone's remaining named piece — `core/parsers/email_parser.py`
      (stdlib `email` package, no new dependency; `EvidenceType.EMAIL` added
      additively), `core/security/prompt_guard.py` (the first concrete
      `core/security` implementation: deterministic instruction-override/
      role-override/exfiltration/obfuscation pattern detection, no LLM call),
      and `core/agents/phishing_agent.py` (`PhishingAgent`, capability
      `email_triage`, + `core/tools/phishing_tools.py`'s
      `PhishingScoringTool`) — the second concrete specialist agent, wired
      into `core/graph/investigation_graph.py` with the same two-line
      pattern `SocAnalystAgent` established. `core/services/case_service.py`'s
      per-upload capability routing was generalized from a SOC-only hardcode
      to an `EvidenceType`-driven table, so an `.eml` upload now
      automatically fans out to `PhishingAgent` instead — this also closes
      **M3's own demo criterion** (see M3 below). Still not done at the time:
      a concrete MITRE Mapping Agent (`core/knowledge/mitre`'s lookup engine
      had no agent wrapper yet) — M2 stayed unchecked until that existed.

      **2026-07-21 addendum** (`docs/adr/0022-mitre-mapping-agent.md`): closes
      the milestone's last piece. A pre-implementation review found the
      requested "MITRE Mapping framework" almost entirely already existed
      (`core/findings/`'s mapping/confidence/dedup/metrics/audit engines,
      already wired into `finding_service.py`/`case_service.py`) — the
      conflict was surfaced to the user, who chose a thin extension:
      `core/tools/mitre_tools.py` (`MitreMappingResolutionTool`, blueprint's
      exact named file — resolves already-mapped technique IDs to tactics,
      sub-technique parents, associated threat groups, associated software,
      and mitigations via `MitreLookup`'s previously-unused
      `groups_using_technique`/`software_using_technique` methods) and
      `core/agents/mitre_mapping_agent.py` (`MitreMappingAgent`, the eighth
      concrete specialist agent, capability `mitre_technique_mapping`) — no
      second mapping engine, confidence calculator, or persistence layer
      built. Cross-cutting, not evidence-type-gated: its capability is
      appended to every evidence type's required-capability list in
      `case_service._required_capabilities_for`, since Finding generation
      (and therefore MITRE mapping) already runs unconditionally on every
      upload. **M2 is now fully closed.**

- [x] **M3 — Multi-agent orchestration.** Coordinator + Planning Agent + full
      LangGraph StateGraph wiring; automatic evidence-type routing.
      **Built ahead of schedule** (`docs/adr/0009-multi-agent-framework-shape.md`):
      the full reusable framework — `BaseAgent`/`BaseTool`, `AgentRegistry`/
      `ToolRegistry`, `CoordinatorAgent`/`PlanningAgent`, `WorkflowEngine`
      (real compiled LangGraph `StateGraph` with retry/failure-recovery/
      events/metrics), `routing.py`, memory interfaces — implemented and
      tested (86 tests) with zero domain logic, before any concrete
      specialist agent existed.
      **2026-07-20** (`docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`):
      closed the milestone's own demo criterion — `core/services/
      case_service.py`'s per-upload capability routing now selects
      `email_triage` for `.eml` evidence and `log_analysis` for every
      log-shaped format, so a log upload and an email upload to the same
      Case each automatically fan out to the correct real specialist
      (`SocAnalystAgent`/`PhishingAgent`), not test doubles.
      *Demo: upload mixed evidence (log + email) to one Case; Coordinator fans out automatically.*

- [x] **M4 — Remaining specialist modules.** Vulnerability Assessment Agent
      (+ Nmap/Nessus/OpenVAS parsers + CVSS calculator), OWASP Security Agent
      (AST-based), Linux Security Agent, Threat Hunting Agent. **Closed
      2026-07-21** — all four blueprint-named pieces are now built (see the
      dated addendums below); the OWASP Security Agent's AST-based scope was
      the milestone's last open item, closed by
      `docs/adr/0021-owasp-security-agent-ast-sast.md`.
      **Built ahead of schedule** (`docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md`):
      the reusable Threat Intelligence & IOC Extraction Framework —
      data-driven `IOCExtractionEngine` covering twenty `IOCType`s
      (IPv4/IPv6, domain, hostname, URL, email, SHA1/SHA256/MD5, file name,
      username, process name, registry key, port, service, mutex, scheduled
      task, command line, user agent, certificate fingerprint), a
      plugin-capable `ExtractorRegistry`, `IOCValidator`/`IOCNormalizer`,
      within-run deduplication, a `DetectionRuleEngine` (pattern/regex/
      threshold/composite rules, Sigma-adjacent metadata, regex-safety
      validation against catastrophic backtracking), a configurable
      `ThreatScoringEngine`/`ConfidenceCalculator`, a
      `ThreatClassificationEngine`, an `EvidenceAttributionTracker`, and
      unimplemented `ThreatIntelProvider`/`IOCEnrichmentProvider` interfaces
      (MISP/AlienVault OTX/VirusTotal/AbuseIPDB/GreyNoise/OpenCTI, no
      concrete provider) — plus the second real domain table, `IOC`
      (`core/db/models/ioc.py`, a real FK to `evidence.id`; `case_id` was a
      plain UUID at the time, tightened into a real FK to `cases.id` once
      M1 closed — `docs/adr/0014-case-model-and-first-api-routes-shape.md`
      point 3), its repository, and the nine-stage `IOCExtractionPipeline`
      (`core/services/threat_intel_service.py`). No MITRE mapping, incident
      correlation, or LLM reasoning — explicitly out of scope per the ADR.

      **2026-07-20** (`docs/adr/0017-vulnerability-assessment-framework.md`):
      closed the Vulnerability Assessment Agent piece — a third sibling leaf
      package, `core/vulnerabilities/` (models, exceptions, CVE/CWE
      extraction, validator, normalizer, configurable dedup, asset
      correlation, a four-dimension confidence engine, severity/priority
      assignment, a six-dimension threat scoring engine, finding generation,
      metrics/events/audit, and an unimplemented
      `VulnerabilityEnrichmentProvider` seam — mirrors `core/threat_intel`'s
      shape exactly), `core/knowledge/cvss_calculator.py` (official CVSS
      v2.0/v3.0/3.1 base-score formulas, hand-verified against FIRST's
      published examples; CVSS v4.0 is vector-validation-only — no public
      closed-form formula exists), four new parsers
      (`nessus_parser.py`/`nessus_csv_parser.py`/`openvas_parser.py`/
      `openvas_csv_parser.py`, four new additive `EvidenceType`s), the third
      real domain table (`Vulnerability`, mirroring `IOC`'s shape, both FKs
      real from the start), the ten-stage `VulnerabilityPipeline`
      (`core/services/vulnerability_service.py`), `core/tools/vuln_tools.py`
      (`VulnerabilityAssessmentTool`), and `core/agents/vulnerability_agent.py`
      (`VulnerabilityAssessmentAgent`, capability `vulnerability_assessment`)
      — the third concrete specialist agent, wired into
      `core/graph/investigation_graph.py` with the same two-line pattern
      `SocAnalystAgent`/`PhishingAgent` established.
      `core/services/case_service.py`'s per-upload capability routing table
      gained the four new `EvidenceType`s, so a `.nessus`/OpenVAS upload now
      automatically fans out to `VulnerabilityAssessmentAgent` instead of
      `SocAnalystAgent`. No remediation planning, Incident Response, or LLM
      reasoning — explicitly out of scope per the ADR and this task's own
      instruction.

      **2026-07-20** (`docs/adr/0018-linux-security-threat-hunting-framework.md`):
      closed the Threat Hunting Agent piece — a fourth sibling leaf package,
      `core/linux_security/` (models incl. a single shared
      `LinuxSecurityCandidate` shape across fifteen detection categories,
      exceptions, normalizer with a documented journald best-effort
      supplement, `ssh_auth_analyzer.py` — brute force/failed-login spike/
      root login/compromise-after-brute-force, `sudo_analyzer.py` —
      sensitive-file access/shell-escape/repeated auth failures,
      `privilege_escalation.py` — new user/deletion/password change/group
      escalation/su-to-root plus a combined new-user-then-escalation
      pattern, `cron_analyzer.py`/`service_analyzer.py` — suspicious cron
      jobs and service starts, `process_detector.py` — the single shared
      reverse-shell regex set every other analyzer delegates to,
      `persistence_detector.py` — cross-category aggregation into
      persistence findings, `authentication_timeline.py` — this run's own
      auth reconstruction, a confidence engine and a seven-dimension threat
      scoring engine (both configurable, sum-to-1.0-validated), finding
      generation, metrics/events/audit, and an unimplemented
      `LinuxSecurityEnrichmentProvider` seam — mirrors
      `core/vulnerabilities`'s shape exactly), the fourth real domain table
      (`LinuxSecurityFindingRow`, mirroring `Vulnerability`'s shape, both FKs
      real from the start), the ten-stage `LinuxSecurityPipeline`
      (`core/services/linux_security_service.py`, gated to
      `SSH_AUTH`/`SYSLOG` evidence only — deliberately not `JSON`),
      `core/tools/linux_security_tools.py` (`LinuxSecurityAssessmentTool`),
      and `core/agents/threat_hunter_agent.py` (`ThreatHunterAgent`,
      capability `cross_log_threat_hunting`) — the fourth concrete
      specialist agent, wired into `core/graph/investigation_graph.py` with
      the same two-line pattern the other three established.
      `core/services/case_service.py`'s per-upload capability routing table
      changed shape (`dict[EvidenceType, str]` -> `dict[EvidenceType,
      tuple[str, ...]]`): `SSH_AUTH`/`SYSLOG` now route to *both*
      `SocAnalystAgent` and `ThreatHunterAgent`, proving a single evidence
      type can require more than one specialist capability without any
      Planning Agent/routing framework change. No Incident Response,
      remediation, or LLM reasoning — explicitly out of scope per the ADR
      and this task's own instruction. Still not checked off: the
      milestone's own demo criterion (all 9 modules through the Coordinator)
      needs the concrete OWASP Security Agent and the blueprint §7-scoped
      Linux command/permission-string advisor Agent first, which don't
      exist yet (the user explicitly declined to build the latter this
      session in favor of the Threat Hunting Agent).
      *Demo: all 9 required modules functioning through the same Coordinator.*

      **2026-07-20** (`docs/adr/0019-linux-security-advisor-agent.md`):
      closed the blueprint §7-scoped Linux Security Agent piece (the
      narrow command/permission advisor, explicitly distinct from
      ADR-0018's Threat Hunting Agent) — a fifth sibling leaf package,
      `core/linux_advisor/` (models with its own `LinuxAdvisorSeverity`
      scale, exceptions, a generic data-driven `RuleEngine`/`Rule` seam
      supporting regex/literal-substring/callable-signature matchers,
      `command_rules.py`'s default dangerous-command rule set — `rm -rf`,
      `chmod 777`/`666`, `curl|wget` piped to a shell, unrestricted sudo,
      insecure `chown`/`chgrp` of sensitive files, world-writable directory
      creation — `permission_parser.py`'s pure octal/rwx/`ls -l`/symbolic-
      mode/umask conversions, `command_analyzer.py`/`permission_analyzer.py`,
      `hardening_advisor.py` (finding-triggered + baseline recommendations
      across eight named categories), `risk_assessment.py` (a configurable,
      sum-to-1.0-validated five-dimension scoring engine), `advisory_engine.py`
      (the orchestrator, with an oversized-input guard and log-injection
      sanitization), and metrics/audit modules — deliberately **no** DB
      persistence and **no** enrichment-provider seam, unlike
      `core/vulnerabilities`/`core/linux_security`, matching blueprint's
      original "advisor" framing), a new additive `EvidenceType.LINUX_COMMAND_INPUT`
      + `core/parsers/linux_command_parser.py` (`LinuxCommandInputParser`),
      the five-stage `core/services/linux_advisor_service.py`
      (`assess_linux_command_input`, synchronous — no DB session, since this
      framework never persists), `core/tools/linux_tools.py`
      (`LinuxSecurityAdvisoryTool`), and `core/agents/linux_security_agent.py`
      (`LinuxSecurityAgent`, capability `linux_security_advisory`, output
      type `LinuxSecurityAdvice`) — the fifth concrete specialist agent,
      wired into `core/graph/investigation_graph.py` with the same two-line
      pattern the other four established. `core/services/case_service.py`'s
      per-upload capability routing table gained the new `EvidenceType`, so
      a raw command/`ls -l` upload now automatically fans out to
      `LinuxSecurityAgent`. No log analysis, threat hunting, SOC analysis,
      IOC extraction, timeline generation, finding correlation, Incident
      Response, remediation, or LLM reasoning — explicitly out of scope per
      the ADR and this task's own instruction. Still not checked off: the
      milestone's own demo criterion (all 9 modules through the Coordinator)
      needs the concrete OWASP Security Agent first, which does not exist
      yet.

      **2026-07-21** (`docs/adr/0020-owasp-web-security-agent.md`): added a
      new, out-of-blueprint **Web Security Agent** — a deterministic
      analyzer of HTTP traffic artifacts (requests/responses, security
      headers, cookies, JWT metadata, web server logs, API responses) mapped
      to the OWASP Top 10 (2021) taxonomy. Deliberately **not** blueprint
      §7's OWASP Security Agent (the AST-based source-code/API static
      reviewer still named below), which remains completely unbuilt and
      unmodified — this is a sixth sibling leaf package, `core/owasp_web/`
      (its own `WebSecuritySeverity` scale, a first-class `OwaspCategory`
      enum used directly on `rule_engine.Rule`, a generic data-driven
      `RuleEngine`/`Rule` seam identical in shape to `core/linux_advisor`'s
      but never imported from it, `header_rules.py`'s missing-header specs +
      value-quality rules, `cookie_rules.py`'s pure structural checks,
      `misconfig_rules.py`'s default pattern rules, `header_analyzer.py`/
      `cookie_analyzer.py`/`jwt_analyzer.py`/`misconfiguration_detector.py`,
      `category_mapper.py`, `finding_generator.py` normalizing every
      analyzer's finding into the unified `OwaspFinding` shape,
      `risk_assessment.py` (a configurable, sum-to-1.0-validated
      five-dimension scoring engine), `advisory_engine.py` (the orchestrator,
      with an oversized-input guard and log-injection sanitization), and
      metrics/audit modules — deliberately **no** DB persistence and **no**
      enrichment-provider seam, matching ADR-0019's "advisor" framing), a new
      additive `EvidenceType.HTTP_TRANSACTION` +
      `core/parsers/http_transaction_parser.py` (`HttpTransactionParser`),
      the synchronous `core/services/web_security_service.py`
      (`assess_http_transaction` — no DB session, since this framework never
      persists), `core/tools/web_security_tools.py`
      (`WebSecurityAdvisoryTool`), and `core/agents/web_security_agent.py`
      (`WebSecurityAgent`, capability `owasp_web_security_assessment`) — the
      sixth concrete specialist agent, wired into
      `core/graph/investigation_graph.py` with the same two-line pattern the
      other five established. `core/services/case_service.py`'s per-upload
      capability routing table gained the new `EvidenceType`, so an HTTP
      transaction upload now automatically fans out to `WebSecurityAgent`.
      No penetration testing, active scanning, incident response, threat
      hunting, MITRE mapping, automated exploitation, or LLM reasoning —
      explicitly out of scope per the ADR and this task's own instruction.
      **This does not close M4** — blueprint §7's AST-based OWASP Security
      Agent (source code/API static review) remains the milestone's only
      unbuilt, outstanding piece.

      **2026-07-21** (`docs/adr/0021-owasp-security-agent-ast-sast.md`):
      closed blueprint §7's **OWASP Security Agent** — the milestone's last
      remaining piece, source code / API static review, AST-based (not just
      regex). A seventh sibling leaf package, `core/owasp_security/`
      (its own `SastSeverity` scale, a first-class `OwaspCategory` enum, a
      fifteen-category `VulnerabilityCategory` enum mapped to both
      `OwaspCategory` and a representative CWE id, a generic `RuleEngine`/
      `Rule` seam extended with a fourth `ast_predicate` matcher kind
      alongside `regex`/`literal_substring`/`callable_signature`,
      `language_detector.py` (extension-first, content-heuristic fallback),
      `python_ast_rules.py` (fifteen genuine AST-predicate rules over the
      stdlib `ast` module — zero new dependencies), `pattern_rules.py`
      (regex-based rules for JavaScript/TypeScript/Java, since this project
      has no AST library for those languages — an explicit, documented
      scope boundary, not a hidden shortcut), `python_ast_analyzer.py`/
      `pattern_analyzer.py`, `vulnerability_detection_engine.py`
      (dispatches by language), `secure_coding_advisor.py` (baseline +
      finding-triggered recommendations), `evidence_mapper.py`,
      `confidence_calculator.py` (discounts pattern-based findings relative
      to AST-based ones), `finding_generator.py`, `risk_assessment.py` (the
      same five-dimension scoring shape), `analysis_engine.py` (the
      orchestrator: oversized-input guard, graceful degradation on an
      unsupported language or a genuine Python syntax error, log-injection
      sanitization), and metrics/audit modules — deliberately **no** DB
      persistence and **no** enrichment-provider seam, matching ADR-0019/
      0020's "advisor" framing), a new additive `EvidenceType.SOURCE_CODE` +
      `core/parsers/source_code_parser.py` (`SourceCodeParser` — one
      `EvidenceRecord` per file, carrying the full source text, a
      deliberate deviation from the per-line-record convention since AST
      parsing needs the whole file as one syntactic unit), the synchronous
      `core/services/owasp_security_service.py` (`assess_source_code` — no
      DB session, since this framework never persists),
      `core/tools/owasp_tools.py` (blueprint's exact named file,
      `OwaspSecurityAssessmentTool`), and
      `core/agents/owasp_security_agent.py` (`OwaspSecurityAgent`,
      capability `owasp_source_code_review`) — the seventh concrete
      specialist agent, wired into `core/graph/investigation_graph.py` with
      the same two-line pattern the other six established.
      `core/services/case_service.py`'s per-upload capability routing table
      gained the new `EvidenceType`, so a source-code upload now
      automatically fans out to `OwaspSecurityAgent`; the evidence-upload
      extension allowlist gained `.py`/`.js`/`.jsx`/`.mjs`/`.cjs`/`.ts`/
      `.tsx`/`.java`. **Not** `core/owasp_web/` (ADR-0020's HTTP-traffic
      analyzer) — the two packages never import each other. No penetration
      testing, active scanning, incident response, threat hunting, MITRE
      mapping, automated exploitation, or LLM reasoning — explicitly out of
      scope per the ADR and this task's own instruction. **M4 is now fully
      closed** — every blueprint-named specialist agent for this milestone
      exists.

- [ ] **M5 — Incident Response synthesis + Reporting.** Incident Response
      Agent (case-wide synthesis), Report Generator Agent with Jinja2/
      ReportLab templates per module + executive report, Plotly charts.
      *Demo: full case → "Generate Executive Report" → real branded PDF with charts.*
      **Partially closed** (`docs/adr/0023-incident-response-agent.md`): the
      Incident Response Agent half is done — `core/incident_response/`
      (deterministic NIST SP 800-61-aligned response-playbook synthesis:
      severity classification, MITRE-tactic/keyword/severity-fallback rule
      matching, prioritization, execution ordering, confidence rollups),
      `core/tools/ir_tools.py` (blueprint's named tool file), the ninth
      concrete specialist agent (`IncidentResponseAgent`, cross-cutting like
      `MitreMappingAgent`), and real DB persistence
      (`incident_response_plans` table, blueprint §8's literal
      `Case -> 1 IncidentResponsePlan (nullable)`). The Report Generator
      Agent half remains open.

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
