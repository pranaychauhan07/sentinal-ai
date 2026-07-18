# Cyber Defense Copilot — Engineering Blueprint
## (Capstone Project 9, built to enterprise-grade standard)

**Context.** This is a greenfield project (the working directory is empty — no existing code, no git repo). The capstone PDF specifies Project 9 as a multi-module cybersecurity assistant combining log analysis, threat hunting, phishing detection, vulnerability assessment, OWASP review, Linux security, and incident response behind a ReAct multi-agent orchestrator. The brief asks for this to be treated as the primary functional specification, built to the quality bar of a real engineering team, taught alongside as I learn cybersecurity concepts, and structured so it can be built incrementally without ever redesigning down to something smaller. This document is that blueprint — it is deliberately implementation-code-free and will drive the actual build in phases afterward.

Everything below extends the PDF's Project 9 scope (9 modules + ReAct + function calling + multi-agent + GitHub integration). Nothing here replaces a required module; additions are architectural scaffolding (API layer, proper DB, case management, evidence graph) that the PDF's own "Cyber Defense Copilot" section implies but doesn't spell out at engineering depth.

---

## 1. Executive Vision

Cyber Defense Copilot (CDC) is an AI-native SOC analyst workbench: a single platform where a human analyst uploads raw security artifacts (logs, emails, scan reports, incident notes) and a team of specialized AI agents — coordinated the way a real SOC shift is coordinated — investigates, correlates, scores, and reports, with every step justified in plain language.

The differentiator versus a "wrap an LLM in Streamlit" project: **cases, not one-shot uploads**. Real SOC work accumulates evidence over hours/days into one investigation. CDC is built around a `Case` as the central object from day one, so multiple log files, a phishing email, and an Nmap scan can all belong to the same investigation and get correlated — this is what turns 9 disconnected demo modules into one coherent product and is the single highest-leverage architectural decision in this project.

## 2. Product Objectives

1. Faithfully implement all capabilities the PDF assigns to Project 9 (modules listed in section 12 below) with no scope reduction.
2. Demonstrate professional agentic AI engineering: LangGraph state machine, not a chained series of `if` statements pretending to be agents.
3. Produce a portfolio artifact that reads as production software to a hiring engineer — typed contracts, tested tools, real persistence, honest docs.
4. Teach cybersecurity fundamentals in-line as they're encountered (MITRE, OWASP, CVSS, IOC, SIEM, etc.) without ever blocking momentum on "go read X first."
5. Keep the system runnable entirely offline-capable (Ollama option) so it's a credible demo without live API keys, while defaulting to hosted LLMs (OpenAI/Gemini) for the best analysis quality.

## 3. Project Scope

**In scope (from the PDF, non-negotiable):**
- SOC log analysis (firewall/IDS/server logs) with MITRE ATT&CK mapping
- Threat hunting (IOC extraction across firewall/IDS/server logs)
- Phishing email detection & investigation (.txt/.eml)
- Vulnerability scanner report analysis (Nmap/Nessus/OpenVAS) with CVSS
- OWASP Top-10 source code / API security review
- Linux command & permission security advisor
- Incident response copilot (NIST SP 800-61 lifecycle)
- Executive PDF report generation for every module
- Multi-agent orchestration with shared memory, ReAct reasoning, function calling
- Streamlit (or richer) dashboard, chat interface, GitHub-ready repo

**Out of scope (explicitly, to prevent scope creep):**
- Live network scanning / active exploitation (this is a *report analyzer*, not a scanner — we consume Nmap/Nessus output, we never invoke nmap against real hosts from the app)
- Real SIEM/EDR integrations (we accept exported log files; no live agent-based collection)
- Autonomous remediation actions (the system recommends; a human executes — this is a hard safety boundary, see §10 Security Layer)
- Multi-tenant SaaS auth/billing (single-analyst / single-org use is the target for this capstone)

## 4. System Architecture

Layered, hexagonal-ish architecture. Each layer talks only to the layer(s) adjacent to it through typed interfaces — this is what lets you swap Streamlit for React later, or OpenAI for Ollama, without touching agent logic.

```
┌─────────────────────────────────────────────────────────────────┐
│  FRONTEND LAYER        Streamlit multi-page app (Phase 1-4)      │
│                        → optional React/FastAPI split (Phase 5+) │
├─────────────────────────────────────────────────────────────────┤
│  API LAYER             FastAPI service boundary (even when       │
│                        Streamlit calls it in-process at first)   │
├─────────────────────────────────────────────────────────────────┤
│  WORKFLOW LAYER        LangGraph StateGraph: the Case Investiga- │
│                        tion graph. Owns control flow, retries,    │
│                        checkpointing.                             │
├─────────────────────────────────────────────────────────────────┤
│  AGENT LAYER           Coordinator + 9 specialist agents (§7)     │
├─────────────────────────────────────────────────────────────────┤
│  TOOL LAYER            Deterministic Python functions agents call │
│                        (parsers, scorers, mappers) — NOT LLM calls│
├─────────────────────────────────────────────────────────────────┤
│  PARSER LAYER          Format-specific extractors (EML, Nmap XML, │
│                        Nessus, syslog, CSV, etc.) → normalized     │
│                        Pydantic models                            │
├─────────────────────────────────────────────────────────────────┤
│  KNOWLEDGE LAYER       Static reference data: MITRE ATT&CK STIX   │
│                        bundle, OWASP Top-10 taxonomy, CVSS         │
│                        vector calculator, IOC/TTP pattern rules    │
├─────────────────────────────────────────────────────────────────┤
│  MEMORY LAYER          Short-term (per-case scratchpad, LangGraph │
│                        state) + long-term (cross-case vector      │
│                        search over past findings via ChromaDB)    │
├─────────────────────────────────────────────────────────────────┤
│  SECURITY LAYER        Input validation, prompt-injection &       │
│                        jailbreak guardrails on any user-supplied  │
│                        text that reaches the LLM, secrets mgmt,   │
│                        human-approval gate before any "action"    │
├─────────────────────────────────────────────────────────────────┤
│  DATABASE LAYER        PostgreSQL (cases, evidence, findings,     │
│                        timeline, users) + ChromaDB (embeddings)   │
├─────────────────────────────────────────────────────────────────┤
│  CONFIGURATION LAYER   pydantic-settings: .env, model selection,  │
│                        per-agent prompt/temperature config        │
├─────────────────────────────────────────────────────────────────┤
│  REPORTING LAYER       Jinja2 → ReportLab PDF pipeline, Plotly    │
│                        chart generation, executive vs. technical  │
│                        report templates                           │
├─────────────────────────────────────────────────────────────────┤
│  LOGGING LAYER         Structured JSON logs (structlog) for every │
│                        agent decision — this doubles as the       │
│                        "explainability" audit trail a real SOC    │
│                        tool needs                                 │
├─────────────────────────────────────────────────────────────────┤
│  TESTING LAYER         pytest: parser fixtures, tool unit tests,  │
│                        agent contract tests, golden-file report   │
│                        snapshots                                  │
├─────────────────────────────────────────────────────────────────┤
│  DEPLOYMENT LAYER      Docker Compose (app + Postgres + Chroma),  │
│                        GitHub Actions CI (lint/test/build)        │
└─────────────────────────────────────────────────────────────────┘
```

**Why FastAPI even in Phase 1 (Streamlit-only)?** Streamlit calls the same `services/` Python functions that a future FastAPI app would expose as endpoints. The rule: **Streamlit pages never contain business logic**, they only render state and call `services.case_service.run_investigation(case_id)`. This single discipline is what makes "swap the frontend later" actually possible instead of aspirational.

**Why Postgres over SQLite from the start?** SQLite is fine for a toy; the PDF's own Project 9 diagram already reaches for "SQLite/FAISS" but a multi-case, multi-evidence-type system has real relational structure (cases → evidence → findings → timeline events, many-to-many). Postgres via SQLAlchemy costs nothing extra to set up with Docker Compose and avoids a rewrite when this becomes a real portfolio piece. (If a grader environment truly can't run Docker, SQLite is a drop-in fallback behind the same SQLAlchemy layer — this is exactly why the DB layer is abstracted.)

## 5. Technology Stack

| Concern | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | PDF requirement; modern typing (`TypedDict`, `Self`) |
| Agent framework | **LangGraph** | PDF names it explicitly for Project 9; gives real state-machine control vs. LangChain's linear chains |
| LLM | OpenAI GPT-4o / GPT-4o-mini (default), Google Gemini, Ollama (offline) — pluggable via `ModelProvider` interface | Cost/quality tiering; offline demo path |
| Frontend | Streamlit (Phase 1–4) | PDF requirement; fastest path to a working demo |
| API | FastAPI | Industry-standard, typed, async, trivial OpenAPI docs for the "GitHub quality" bar |
| Database | PostgreSQL + SQLAlchemy 2.0 (async) | Relational integrity across cases/evidence/findings |
| Vector store | ChromaDB | PDF-named option; embeds past findings for the Memory Agent |
| Validation | Pydantic v2 | Every parser output and agent I/O is a typed model, not a dict — this is the #1 thing that separates "capstone demo" from "production code" |
| PDF generation | ReportLab + Jinja2 | PDF requirement; Jinja2 templating keeps report layout out of Python string concatenation |
| Charts | Plotly | PDF requirement; interactive in Streamlit, static-exportable for PDF reports |
| Parsing libs | `email`/`eml_parser`, `python-libnmap` or `xmltodict`, `beautifulsoup4`, `tldextract`, `pandas` | Per-format, matches PDF's per-project library lists |
| Testing | pytest, pytest-asyncio, hypothesis (for parser fuzzing) | Confidence in parsers that face adversarial input (phishing emails, malformed XML) |
| Observability | structlog, OpenTelemetry (stub, Phase 5+) | Auditable agent reasoning trail |
| Containerization | Docker Compose | One-command local run: `docker compose up` |
| CI | GitHub Actions | lint (ruff), type-check (mypy), test (pytest) on every push |

## 6. Folder Structure

```
cyber-defense-copilot/
├── apps/
│   ├── web/                        # Streamlit frontend (Phase 1-4)
│   │   ├── Home.py
│   │   ├── pages/
│   │   │   ├── 1_Case_Dashboard.py
│   │   │   ├── 2_New_Investigation.py
│   │   │   ├── 3_Evidence_Explorer.py
│   │   │   ├── 4_Threat_Timeline.py
│   │   │   ├── 5_MITRE_Map.py
│   │   │   ├── 6_AI_Analyst_Chat.py
│   │   │   ├── 7_Executive_Reports.py
│   │   │   └── 8_Settings.py
│   │   └── components/             # Reusable Streamlit widgets (charts, case cards)
│   └── api/                        # FastAPI service (Phase 5+; same services/ underneath)
│       ├── main.py
│       └── routers/
├── core/                            # The actual product — framework-agnostic
│   ├── agents/
│   │   ├── coordinator.py
│   │   ├── planning_agent.py
│   │   ├── parser_agent.py
│   │   ├── soc_analyst_agent.py
│   │   ├── threat_hunter_agent.py
│   │   ├── phishing_agent.py
│   │   ├── vulnerability_agent.py
│   │   ├── owasp_agent.py
│   │   ├── linux_security_agent.py
│   │   ├── incident_response_agent.py
│   │   ├── mitre_agent.py
│   │   ├── report_agent.py
│   │   └── memory_agent.py
│   ├── graph/
│   │   ├── state.py                # CaseInvestigationState (TypedDict/Pydantic)
│   │   ├── investigation_graph.py  # LangGraph StateGraph wiring
│   │   └── routing.py              # Conditional edges / dynamic tool routing
│   ├── tools/
│   │   ├── log_tools.py            # summarize, detect_bruteforce, etc.
│   │   ├── phishing_tools.py       # sender/url/content/attachment analyzers
│   │   ├── vuln_tools.py           # CVSS interpreter, risk prioritizer
│   │   ├── owasp_tools.py          # SQLi/XSS/auth static checks
│   │   ├── linux_tools.py          # command explainer, permission analyzer
│   │   ├── ir_tools.py             # containment/eradication/recovery generators
│   │   ├── mitre_tools.py          # technique lookup/mapping
│   │   └── scoring.py              # shared risk-scoring math (single source of truth)
│   ├── parsers/
│   │   ├── email_parser.py
│   │   ├── syslog_parser.py
│   │   ├── nmap_parser.py
│   │   ├── nessus_parser.py
│   │   ├── openvas_parser.py
│   │   ├── source_code_parser.py
│   │   └── incident_parser.py
│   ├── knowledge/
│   │   ├── mitre_attack.json       # local STIX-derived technique dataset
│   │   ├── owasp_top10.yaml
│   │   └── cvss_calculator.py
│   ├── memory/
│   │   ├── short_term.py           # per-case scratchpad (graph state)
│   │   └── long_term.py            # ChromaDB retrieval over past cases
│   ├── security/
│   │   ├── prompt_guard.py         # injection/jailbreak detection on ingested text
│   │   ├── pii_redaction.py
│   │   └── approval_gate.py        # human-in-the-loop for high-risk actions
│   ├── db/
│   │   ├── models.py                # SQLAlchemy ORM: Case, Evidence, Finding, TimelineEvent
│   │   ├── session.py
│   │   └── migrations/              # Alembic
│   ├── reporting/
│   │   ├── templates/               # Jinja2 report templates per module
│   │   ├── charts.py                # Plotly figure builders
│   │   └── pdf_builder.py
│   ├── config/
│   │   └── settings.py              # pydantic-settings; model provider selection
│   └── services/                    # Thin orchestration layer both Streamlit & FastAPI call
│       ├── case_service.py
│       ├── evidence_service.py
│       └── report_service.py
├── data/
│   ├── sample_evidence/              # phishing emails, sample logs, nmap/nessus reports
│   └── reports_out/
├── tests/
│   ├── unit/                         # per parser, per tool
│   ├── integration/                  # full graph runs against sample_evidence
│   └── golden/                       # expected report snapshots
├── docs/
│   ├── architecture.md
│   ├── agents.md
│   └── diagrams/                     # exported architecture diagrams (mermaid source + png)
├── .github/
│   ├── workflows/ci.yml
│   └── ISSUE_TEMPLATE/
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── requirements.txt
├── README.md
├── CONTRIBUTING.md
├── ROADMAP.md
└── LICENSE
```

**Why `core/` is framework-agnostic:** every agent, tool, and parser imports nothing from Streamlit or FastAPI. This is what lets `tests/` exercise the entire investigation pipeline headlessly, and it's the difference between "a Streamlit app" and "a platform with a Streamlit frontend."

## 7. Agent Architecture

All agents are LangGraph nodes. Each has a strict Pydantic input/output contract — no agent passes free-text where a typed model will do. "ReAct reasoning" is implemented as an explicit `Thought` field on every agent's output (logged, shown in the UI's "Investigation Trail" panel), not just prompted-for narration.

### Coordinator Agent
- **Purpose:** Entry point for every case. Decides which specialist agents the current evidence set requires.
- **Responsibilities:** Classify uploaded evidence type(s); build an execution plan; sequence agent calls; merge results into case state; decide when investigation is "complete" vs needs another pass.
- **Input:** `Case` (raw evidence list, case metadata)
- **Output:** `InvestigationPlan` (ordered list of agent invocations + rationale)
- **Tools used:** none directly — it calls the Planning Agent for complex multi-evidence cases
- **Interacts with:** every other agent (fan-out), Memory Agent (checks for related past cases first)
- **Failure handling:** if evidence type is unrecognized, routes to a `ManualTriageRequired` state surfaced to the analyst instead of guessing

### Planning Agent
- **Purpose:** For cases with 2+ evidence types (e.g., a phishing email *and* firewall logs from the same incident), decides investigation order and what correlations to attempt.
- **Responsibilities:** Dependency-aware sequencing (e.g., run Parser before any analyst agent); flag opportunities for cross-evidence correlation (same IP in both a firewall log and a phishing sender domain).
- **Input:** `InvestigationRequest`
- **Output:** `ExecutionGraph` (DAG of agent calls the Coordinator executes)
- **Failure handling:** falls back to sequential default order if planning confidence is low (confidence score below threshold)

### Parser/Evidence Agent
- **Purpose:** Wraps the deterministic parser layer with an LLM fallback for messy/unstructured input (e.g., a pasted terminal transcript that doesn't match a known log format).
- **Responsibilities:** Route file to correct deterministic parser by extension/content sniffing; if no parser matches, use LLM-assisted structured extraction as a documented fallback (lower confidence, flagged in output).
- **Input:** raw file/text + declared or sniffed type
- **Output:** `NormalizedEvidence` (Pydantic model per evidence type)
- **Tools used:** all of `core/parsers/`
- **Failure handling:** never silently drops unparseable fields — returns partial results with an explicit `unparsed_fragments` list

### SOC Analyst Agent
- **Purpose:** The generalist log analyst — summarizes events, flags anomalies, classifies severity.
- **Responsibilities:** log summarization, failed-login/brute-force pattern detection, severity classification (Low/Medium/High/Critical)
- **Input:** `NormalizedEvidence` (log type)
- **Output:** `SocFinding[]`
- **Tools used:** `log_tools.py`, `scoring.py`
- **Interacts with:** hands findings to MITRE Agent for technique mapping
- **Failure handling:** if log volume exceeds context window, chunks and summarizes hierarchically (map-reduce), never truncates silently

### Threat Hunting Agent
- **Purpose:** Proactive IOC hunting across firewall/IDS/server logs — the PDF's Project 3.
- **Responsibilities:** extract IOCs (IPs, hashes, domains), check against local blocklist/allowlist knowledge, identify multi-stage patterns (recon → exploitation → persistence)
- **Input:** `NormalizedEvidence[]` (multiple log sources)
- **Output:** `ThreatHuntingReport` (IOC list + narrative)
- **Tools used:** `log_tools.py`, `mitre_tools.py`
- **Failure handling:** distinguishes "no threats found" (explicit clean bill) from "insufficient log coverage to conclude" — a real SOC tool must never conflate the two

### Phishing Investigation Agent
- **Purpose:** PDF's Project 1 — full email triage.
- **Responsibilities:** sender/domain analysis, URL risk scoring, content social-engineering detection, attachment risk, aggregate risk score
- **Input:** `NormalizedEvidence` (parsed .eml/.txt)
- **Output:** `PhishingVerdict` (score 0–100, indicators, recommended actions)
- **Tools used:** `phishing_tools.py`, `scoring.py`
- **Security note:** this agent is the highest-risk surface for prompt injection (attacker-controlled email body reaches the LLM) — see §10, `prompt_guard.py` runs on every email body before it's included in any prompt

### Vulnerability Assessment Agent
- **Purpose:** PDF's Project 4 — Nmap/Nessus/OpenVAS report interpretation.
- **Responsibilities:** explain each vulnerability in plain language, interpret/assign CVSS, prioritize by exploitability + exposure, recommend fixes
- **Input:** `NormalizedEvidence` (parsed scan report)
- **Output:** `VulnerabilityAssessment` (per-finding CVSS + priority + remediation)
- **Tools used:** `vuln_tools.py`, `knowledge/cvss_calculator.py`

### OWASP Security Agent
- **Purpose:** PDF's Project 7 — source code / API static review.
- **Responsibilities:** detect SQLi/XSS/broken-auth patterns, map to OWASP Top-10 (2021), severity + secure-coding recommendation
- **Input:** `NormalizedEvidence` (parsed source/API spec)
- **Output:** `OwaspFindings[]`
- **Tools used:** `owasp_tools.py` (AST-based static analysis, not just regex, for the SQLi/XSS detectors — this is a concrete quality bar: `ast` module for Python input, not string-matching)

### Linux Security Agent
- **Purpose:** PDF's Project 6 — command/permission advisor.
- **Responsibilities:** explain command, analyze permission strings, recommend hardening
- **Input:** raw command string or `ls -l` style output
- **Output:** `LinuxSecurityAdvice`
- **Tools used:** `linux_tools.py`

### Incident Response Agent
- **Purpose:** PDF's Project 8 — NIST SP 800-61 lifecycle guidance.
- **Responsibilities:** classify incident, generate containment/eradication/recovery plans, lessons-learned
- **Input:** aggregated case findings (from any/all of the above agents) — this agent is deliberately the "downstream" consumer that ties a whole case together
- **Output:** `IncidentResponsePlan`
- **Tools used:** `ir_tools.py`
- **Interacts with:** pulls from every other agent's output already in case state — never re-parses evidence itself

### MITRE Mapping Agent
- **Purpose:** Cross-cutting technique mapper used by SOC/Threat Hunting/Incident agents.
- **Responsibilities:** map a described behavior ("repeated failed SSH logins from one IP") to MITRE technique ID (T1110), with tactic/phase
- **Input:** natural-language behavior description or structured finding
- **Output:** `MitreMapping[]` (technique ID, name, tactic, confidence)
- **Tools used:** `mitre_tools.py` against `knowledge/mitre_attack.json`
- **Failure handling:** returns "unmapped" rather than forcing a low-confidence guess into the report

### Report Generator Agent
- **Purpose:** Assembles all case findings into module-specific and case-level executive PDF reports.
- **Responsibilities:** template selection, chart generation, narrative synthesis, PDF build
- **Input:** full `CaseState`
- **Output:** PDF file + in-app report preview
- **Tools used:** `reporting/` package (deterministic — the PDF is templated, not LLM-freeform, so reports are reproducible)

### Memory Agent
- **Purpose:** Cross-case learning — "have we seen this IP/pattern before?"
- **Responsibilities:** embed new findings into ChromaDB, retrieve similar past cases at investigation start, surface to Coordinator
- **Input:** case findings (write path), new case evidence (read path)
- **Output:** `SimilarCaseReferences[]`
- **Tools used:** ChromaDB client wrapper in `memory/long_term.py`
- **Failure handling:** memory retrieval is always advisory/optional — a Chroma outage degrades to "no historical context" rather than blocking the investigation

## 8. Database Design

Core relational schema (PostgreSQL via SQLAlchemy):

```
Case
 ├─ id, title, status (open/investigating/closed), severity, created_at, analyst_id
 ├─ 1..* Evidence
 ├─ 1..* Finding
 ├─ 1..* TimelineEvent
 └─ 1 IncidentResponsePlan (nullable)

Evidence
 ├─ id, case_id (FK), evidence_type (enum: email/log/nmap/nessus/source_code/incident_note),
 │  raw_file_ref, parsed_json, parser_confidence, uploaded_at

Finding
 ├─ id, case_id (FK), evidence_id (FK, nullable for cross-evidence findings),
 │  source_agent, finding_type, severity, risk_score, mitre_technique_id (FK, nullable),
 │  description, recommendation, created_at

MitreTechnique (reference/knowledge table, seeded from mitre_attack.json)
 ├─ technique_id (PK, e.g. "T1110"), name, tactic, description

TimelineEvent
 ├─ id, case_id (FK), timestamp, event_type, source_finding_id (FK), narrative

Report
 ├─ id, case_id (FK), report_type (module/executive), file_path, generated_at

User  (single-analyst mode now; schema supports multi-user later)
 ├─ id, name, role
```

ChromaDB (vector store) holds one collection: `case_findings_embeddings`, each entry `{finding_id, case_id, embedding, metadata}` — used only for retrieval, Postgres remains the system of record.

## 9. Data Flow

Concrete, evidence-agnostic walkthrough (generalizes the PDF's per-module ReAct diagrams into the one real pipeline):

```
1. Analyst opens/creates a Case, uploads evidence (email / log / scan report / note)
        ↓
2. Evidence Classification — sniff file type + extension, tag evidence_type
        ↓
3. Parser Agent — routes to deterministic parser → NormalizedEvidence (Pydantic)
   (LLM-assisted fallback only if no deterministic parser matches; flagged low-confidence)
        ↓
4. Memory Agent (read) — check ChromaDB for similar past findings; attach as context
        ↓
5. Coordinator + Planning Agent — build ExecutionGraph: which specialist agent(s)
   this evidence needs (e.g. email → Phishing Agent; syslog → SOC + Threat Hunting)
        ↓
6. Specialist Agent(s) run (ReAct loop: Thought → Tool Call → Observation → ...)
   → produce typed Finding objects, persisted to Postgres immediately (not batched)
        ↓
7. MITRE Agent — maps qualifying findings to ATT&CK techniques
        ↓
8. Cross-evidence correlation (Coordinator) — if case has multiple evidence items,
   check for shared indicators (same IP, domain, hash) across findings
        ↓
9. Incident Response Agent — if severity crosses threshold or analyst requests it,
   synthesizes containment/eradication/recovery/lessons-learned from ALL case findings
        ↓
10. Report Agent — renders module-level + case-level executive PDF (Jinja2 → ReportLab),
    generates Plotly charts (severity pie, MITRE tactic bar, timeline)
        ↓
11. Memory Agent (write) — embeds this case's findings into ChromaDB for future retrieval
        ↓
12. Dashboard updates — Case status, risk score, timeline, all live in Streamlit
```

Every arrow above is a LangGraph edge with explicit state passed as the typed `CaseInvestigationState`. No agent mutates global variables; state transitions are the only way data moves, which is what makes checkpointing/replay/audit possible.

## 10. Security Concepts (Teaching, applied to this project)

- **MITRE ATT&CK** — A public, structured knowledge base of real-world adversary tactics and techniques (e.g., T1110 = Brute Force), maintained by MITRE. It exists so analysts have a *common vocabulary* instead of everyone describing the same attack differently. We use it as the taxonomy every SOC/Threat Hunting finding gets mapped into — this is what turns "we saw weird login activity" into "this matches T1110 Brute Force under the Credential Access tactic," which is exactly how real SOC tickets are written.
- **OWASP Top-10** — A community-ranked list of the 10 most critical web app security risks (SQL Injection, Broken Access Control, etc.), refreshed periodically by the OWASP Foundation. Exists to focus limited security review time on what actually gets exploited most. Used directly by the OWASP Security Agent to classify source-code findings.
- **NIST SP 800-61** — The U.S. government's Incident Response lifecycle standard (Preparation → Detection/Analysis → Containment/Eradication/Recovery → Post-Incident Activity). Exists so incident response isn't ad-hoc; the Incident Response Agent's output sections map 1:1 to this lifecycle.
- **SIEM (Security Information and Event Management)** — A system that aggregates logs from many sources into one place for correlation and alerting (e.g., Splunk, Sentinel). We don't build a SIEM; we consume *exported* SIEM-style data (CSV/log dumps) as evidence — CDC is the analysis layer that would sit downstream of a real SIEM.
- **IOC (Indicator of Compromise)** — A forensic artifact (an IP, file hash, domain) that suggests a system has been breached. The Threat Hunting Agent's primary output is a list of IOCs — this is literally what a "threat hunter" job title means: proactively searching for these before an alert fires.
- **CVSS (Common Vulnerability Scoring System)** — A standardized 0–10 severity score for vulnerabilities, computed from exploitability + impact metrics. Exists so "critical" means the same thing across every vendor's scanner. The Vulnerability Agent both *interprets* scanner-provided CVSS and can *estimate* one when a scan tool didn't provide it.
- **YARA / Sigma** (referenced, not core to Project 9's scope) — YARA is a pattern-matching language for identifying malware by byte/string signatures; Sigma is the log-analysis equivalent (vendor-neutral detection rules translatable to any SIEM's query language). Worth knowing because Sigma rules are the "right" long-term way to encode the SOC Analyst Agent's detection logic instead of hardcoded Python — flagged as a Phase 6+ enhancement (§16).
- **EDR (Endpoint Detection and Response)** — Software agents on endpoints that monitor process/file/network activity in real time (CrowdStrike, Defender for Endpoint). We treat EDR *alert exports* as one more evidence type the Parser Agent can ingest, not something CDC runs itself.
- **IDS/IPS (Intrusion Detection/Prevention System)** — IDS watches traffic and alerts; IPS watches traffic and actively blocks. Their logs are one of the three canonical inputs to the Threat Hunting Agent.
- **Firewall** — Network traffic gatekeeper based on rules (allow/deny by IP/port/protocol). Firewall logs are the most common evidence type across SOC Analyst and Threat Hunting agents.
- **Detection Engineering** — The discipline of writing and tuning the actual detection logic (rules/queries) that catches attacker behavior, as opposed to responding after a human notices something. Our `log_tools.py` detection functions (brute-force pattern, port-scan pattern) are, in miniature, detection engineering artifacts — and the reason they're deterministic Python functions rather than LLM prompts is that detection logic needs to be testable and reproducible, exactly like Sigma rules are.
- **Risk Scoring** — Converting qualitative findings into a comparable number (e.g., 0–100) so an analyst can triage by severity across dissimilar evidence types. `scoring.py` is intentionally the *one* place this math lives — every module (phishing, vuln, log) calls the same weighted-scoring function rather than inventing its own scale, so a "72" always means the same relative severity everywhere in the app.
- **Prompt Injection / Jailbreak defense** (from the PDF's Project 5, applied here as a cross-cutting concern rather than a standalone product) — Because phishing emails and source code are *attacker- or third-party-authored text* that gets included in LLM prompts, `security/prompt_guard.py` screens all such text for injection patterns ("ignore previous instructions", etc.) before it's interpolated into any agent prompt, and any agent output that recommends an *action* (not just an assessment) passes through the `approval_gate.py` human-in-the-loop check before it can be marked "executed" in the UI. This is a real vulnerability class (an attacker crafts a phishing email designed to manipulate the *analyzing* AI, not just the human victim) and is exactly why this isn't cosmetic.

## 11. AI Concepts (Teaching, applied to this project)

- **Agentic AI** — Software where an LLM doesn't just answer once, but plans, calls tools, observes results, and decides next steps autonomously within bounds. Every specialist agent here is agentic: it decides *which* tool to call based on what it's seen so far, not a fixed script.
- **LangGraph** — A framework for building agents as an explicit state machine (nodes = agents/tools, edges = control flow, shared typed state) instead of a linear chain. Chosen because our workflow genuinely branches (a case with only a phishing email skips the Vulnerability Agent entirely) and needs checkpointing (resume an investigation after a crash) — LangChain's basic chains can't express that cleanly.
- **ReAct (Reason + Act)** — A prompting pattern where the model alternates explicit "Thought" (reasoning) and "Action" (tool call) steps, rather than jumping straight to an answer. We surface each agent's Thought log directly in the UI's Investigation Trail — this is both good engineering (debuggable) and good product (an analyst trusts a tool that shows its work).
- **Function/Tool Calling** — The mechanism by which an LLM emits a structured request ("call `check_cvss_score(vector_string)`") that the app executes and feeds back as an observation, rather than the LLM trying to compute CVSS math itself (which it would get wrong). Every deterministic calculation (CVSS, risk scores, MITRE lookups) is a tool call, never left to the LLM's arithmetic.
- **Shared Memory** — State visible across multiple agents in one workflow (short-term: the current case's evidence and findings-so-far) versus across workflows over time (long-term: "has this IOC appeared in a past case?" via vector search). This is what makes the Cyber Defense Copilot smarter the longer it's used, per the PDF's explicit Project 9 requirement.
- **Planning** — An explicit step where an agent decides *what order* to do things in before doing them, rather than reacting evidence-item-by-evidence-item. Necessary once a case has multiple, interdependent evidence types.
- **Confidence Scoring** — Every parser and every agent finding carries a numeric/qualitative confidence value, so downstream consumers (and the human analyst) know when to trust an inference versus double-check it (e.g., the LLM-fallback parser always reports lower confidence than a deterministic parser).
- **Error Recovery** — LangGraph's checkpointing lets a failed node (e.g., an LLM API timeout) retry or route to a degraded-but-safe fallback path rather than crashing the whole investigation.
- **Human-readable reasoning** — Design constraint that every agent's *output*, not just its internal Thought, is written for a human SOC analyst to read and act on — never raw JSON dumped to the screen as the primary UI.

## 12. Core Modules (mapped 1:1 to the PDF's 9 Project-9 modules)

1. **Threat Detection** → SOC Analyst Agent + Threat Hunting Agent
2. **Phishing Detection** → Phishing Investigation Agent
3. **Log Analyzer** → SOC Analyst Agent (shared parser layer)
4. **Vulnerability Analyzer** → Vulnerability Assessment Agent
5. **Nmap Report Reader** → `nmap_parser.py` + Vulnerability Assessment Agent
6. **Incident Response Assistant** → Incident Response Agent
7. **Security Report Generator** → Report Generator Agent
8. **OWASP Security Review** → OWASP Security Agent (this is Project 7's capability folded into the Copilot, exactly as the PDF's Project 9 module list requires)
9. **Linux Security Guidance** → Linux Security Agent

Plus the cross-cutting pieces the PDF explicitly names for Project 9: ReAct Agent (built into every specialist agent's execution pattern, not a separate agent), Function Calling (the Tool Layer), Multi-Agent Workflow (the LangGraph graph itself), GitHub Integration (§13).

## 13. User Experience

Streamlit multi-page app, dark-theme-first (SOC tools are dark-themed for a reason: analysts stare at these for hours; light mode offered as a toggle, not default).

- **Landing Dashboard** — Open case count, total findings this week, severity breakdown donut, recent activity feed. This is the "walk up and understand system health in 5 seconds" screen.
- **Case Management** — List/create/filter cases by status/severity/date; each case is a first-class object you can revisit.
- **Investigation Workspace** (per case) — Tabs: Evidence | Findings | Timeline | MITRE Map | IR Plan | Reports. This is where 90% of analyst time is spent.
- **AI Analyst Chat** — Free-form Q&A scoped to the current case ("explain finding #4", "why was this scored High?") — grounded in that case's actual findings via retrieval, not a generic chatbot.
- **Evidence Explorer** — Raw + parsed view of every uploaded artifact, side by side, so an analyst can verify the parser didn't miss something.
- **Threat Timeline** — Chronological reconstruction of events across all evidence in a case (a login failure at 09:12, a suspicious outbound connection at 09:14, a phishing email received at 08:58 — laid out on one axis). This is the single most "wow" UI element and directly demonstrates the cross-evidence correlation architecture is real, not decorative.
- **MITRE Visualization** — ATT&CK matrix heatmap highlighting which tactics/techniques this case touched.
- **Executive Reports** — One-click PDF per module or full-case executive summary, previewable in-app before download.
- **Settings** — Model provider selection (OpenAI/Gemini/Ollama), API key entry (never logged), per-agent verbosity.

## 14. GitHub Repository Design

- **README.md** — Problem statement, architecture diagram (mermaid, rendered inline), quickstart (`docker compose up`), screenshots/GIF of the Investigation Workspace and Threat Timeline, tech stack table, module coverage checklist mapped visibly to "Project 9 requirements."
- **Architecture diagrams** — Mermaid source in `docs/diagrams/`, rendered PNGs embedded in README — the layered diagram from §4 and the data-flow diagram from §9 are the two that matter most.
- **CONTRIBUTING.md** — Setup, test-running, coding standards (ruff + mypy), PR expectations.
- **ROADMAP.md** — Phased milestones from §15 below, kept visibly in sync with actual progress (checked-off items) — this alone signals engineering maturity to a reviewer.
- **Issue Templates** — Bug report / feature request templates in `.github/ISSUE_TEMPLATE/`.
- **CI (GitHub Actions)** — lint + type-check + pytest on every push/PR; badge in README.
- **License** — MIT (portfolio-friendly).
- **Release strategy** — Tagged releases per completed milestone (`v0.1-parsers`, `v0.2-single-agent`, `v1.0-multi-agent-mvp`...), each with release notes summarizing what became demoable.
- **Commit strategy** — Conventional Commits (`feat:`, `fix:`, `docs:`), one logical change per commit, no "wip" squash-mush — a reviewer scanning `git log` should be able to reconstruct the build order from §15 below.

## 15. Development Milestones

Each milestone ends with a genuinely runnable, demoable app — never a half-wired skeleton. The full architecture (§4) is scaffolded early (even empty layers exist as stubs) so later milestones *fill in* rather than *bolt on*.

**M0 — Foundation (scaffolding, no AI yet)**
Repo structure, Docker Compose (Postgres + app), SQLAlchemy models + Alembic migration, pydantic-settings config, Streamlit shell with the page list (empty pages), CI pipeline green on lint+test of an empty test suite. *Demo:* `docker compose up` shows a running empty dashboard.

**M1 — First real module, single agent, no orchestration**
Build the Log/Evidence parser layer for one format (syslog/firewall log) + the SOC Analyst Agent as a standalone LangGraph single-node graph (no Coordinator yet) + risk scoring + Case/Evidence/Finding persisted to Postgres. *Demo:* upload a firewall log, get a real AI-generated severity-classified finding, saved and visible on refresh.

**M2 — MITRE mapping + second module (Phishing)**
Add MITRE knowledge layer + MITRE Agent; add Phishing Investigation Agent + email parser + prompt-injection guard (since this is the first attacker-controlled-text agent). *Demo:* two independent working modules, each producing a mapped/scored finding.

**M3 — Multi-agent orchestration (the architectural centerpiece)**
Build the Coordinator + Planning Agent + full LangGraph StateGraph wiring all agents built so far; evidence classification routes automatically to the right specialist. *Demo:* upload mixed evidence (a log + an email) to one Case and watch the Coordinator fan out to both agents automatically.

**M4 — Remaining specialist modules**
Vulnerability Assessment Agent (+ Nmap/Nessus/OpenVAS parsers + CVSS calculator), OWASP Security Agent (+ AST-based source scanners), Linux Security Agent, Threat Hunting Agent (extends SOC parsers to cross-log IOC hunting). *Demo:* all 9 PDF-required modules functioning through the same Coordinator.

**M5 — Incident Response synthesis + Reporting**
Incident Response Agent (consumes case-wide findings), Report Generator Agent with Jinja2/ReportLab templates per module + case-level executive report, Plotly charts wired into both UI and PDF. *Demo:* a full case → click "Generate Executive Report" → real branded PDF with charts.

**M6 — Memory + Threat Timeline + polish UX**
ChromaDB long-term memory (write on case close, read on new case), Threat Timeline cross-evidence view, MITRE ATT&CK matrix heatmap visualization, AI Analyst Chat scoped to case context. *Demo:* the "wow" milestone — full Investigation Workspace as described in §13.

**M7 — Hardening, tests, docs, GitHub polish**
Test coverage pass (unit + integration + golden-file report snapshots), mypy/ruff clean, README + diagrams + CONTRIBUTING + ROADMAP finalized, tagged `v1.0` release. *Demo:* the portfolio-ready state.

## 16. Risks

| Risk | Mitigation |
|---|---|
| LLM cost/latency during heavy testing | Default to GPT-4o-mini for dev, cache prompts, offer Ollama offline path for iteration |
| Parser brittleness against malformed/adversarial input (esp. phishing .eml) | pytest + hypothesis fuzz tests per parser from M1 onward; never let a parser exception crash the graph — degrade to partial-parse |
| Scope creep back toward "10 disconnected demos" | Case-centric architecture (§1) is the structural guardrail; Coordinator + shared DB make disconnection structurally hard to regress into |
| Prompt injection via attacker-authored evidence (phishing bodies, malicious source code comments) | `prompt_guard.py` as a cross-cutting gate (§10), never optional, tested with adversarial fixtures |
| Over-trusting LLM arithmetic (CVSS/risk scores) | All scoring math is deterministic Python (`scoring.py`, `cvss_calculator.py`), LLM only explains/contextualizes, never computes |
| Report generation becoming unmaintainable string-templating | Jinja2 templates + ReportLab from day one, golden-file snapshot tests catch regressions |
| Solo-developer time constraints stretching milestones | Milestones (§15) are each independently demoable — if time runs out, whatever milestone was last completed is still a coherent, working product, never a half-built mess |

## 17. Future Expansion

- **Sigma rule engine** replacing/augmenting hardcoded detection logic in `log_tools.py` — makes detection logic portable to real SIEMs.
- **Real-time evidence ingestion** (tail a log file / webhook from a real SIEM) instead of file upload only.
- **Multi-tenant / RBAC** — the `User` table and Case ownership already anticipate this.
- **React frontend** consuming the FastAPI layer directly, once Streamlit's UI ceiling is reached (the layered architecture in §4 makes this a frontend swap, not a rewrite).
- **STIX/TAXII threat intel feed integration** to enrich IOC checks beyond the local knowledge layer.
- **Autonomous-but-approved remediation actions** (e.g., actually calling a firewall API to block an IP) strictly behind the human-approval gate already scaffolded in `security/approval_gate.py`.
- **Fine-tuned/small local model** for the high-volume deterministic-adjacent tasks (log summarization) to cut cost at scale, keeping GPT-4o-class models for genuinely hard reasoning (IR synthesis, cross-evidence correlation).

## 18. Final Engineering Recommendations

1. **Build the Case/Evidence/Finding data model in M0, before any agent exists.** This is the one decision that, if deferred, forces a rewrite later — every subsequent milestone depends on it.
2. **Never let an agent perform arithmetic it should call a tool for.** CVSS, risk scores, and severity thresholds are pure functions with unit tests, always.
3. **Treat prompt-injection defense as infrastructure, not a feature.** It belongs in the Security Layer from M2 onward (first attacker-text-consuming agent), not bolted on at the end.
4. **Keep `core/` importable with zero Streamlit/FastAPI imports.** This single discipline is what makes the test suite, the future API split, and the "is this real software or a notebook" impression all work.
5. **Ship each milestone as a tagged, demoable release.** A reviewer (or you, three months from now) should be able to `git checkout v0.3` and see a working, if smaller, product — never a broken intermediate state.
6. **Resist adding a 10th module.** The PDF's 9 modules plus faithful multi-agent orchestration is already an ambitious, complete scope; the differentiation from other students' submissions is depth and correctness of the case-centric architecture, not extra breadth.
