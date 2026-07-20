# core/parsers — Evidence Ingestion & Parser Framework

**Purpose:** The Parser Layer (`context/01_blueprint.md` §4) plus its
supporting framework: registry, factory/selection, validation, detection,
fingerprinting, metrics, events, audit logging. Converts raw uploaded
artifacts into the one canonical contract, `core.parsers.models.
NormalizedEvidence` (see `docs/adr/0011-evidence-ingestion-pipeline-shape.md`).

**Implemented parsers (seventeen, per the current milestone's scope):**
`ssh_auth_parser.py`, `apache_access_parser.py`, `apache_error_parser.py`,
`syslog_parser.py` (generic RFC3164-ish fallback), `windows_event_parser.py`
(a CSV/XML **EVTX abstraction** — binary `.evtx` parsing is a documented
future extension, not implemented here), `json_evidence_parser.py`,
`csv_evidence_parser.py`, `nmap_parser.py` (via `defusedxml`, XXE-safe),
`plaintext_parser.py` (deterministic last-resort fallback), `email_parser.py`
(Milestone M2, `docs/adr/0016-phishing-agent-email-parser-prompt-guard.md` —
stdlib `email` package only, no new dependency; extracts header/body
structure for `core.agents.phishing_agent.PhishingAgent` to triage, never
extracting IOCs or rendering a verdict itself — the existing
`IOCExtractionEngine` already regex-scans its `raw_line` output),
`nessus_parser.py`/`openvas_parser.py` (Milestone M4,
`docs/adr/0017-vulnerability-assessment-framework.md` — `.nessus`/OpenVAS
XML via `defusedxml`, XXE-safe), `nessus_csv_parser.py`/
`openvas_csv_parser.py` (their CSV export counterparts, sharing
`csv_common.py`'s case-tolerant column lookup helper). All four scan-report
parsers place structured per-finding fields (CVE, CWE, CVSS vector/score,
port/protocol/service) directly into `EvidenceRecord.normalized_fields` for
`core.vulnerabilities.extractor.VulnerabilityExtractionEngine` to read
without re-parsing — never extracting IOCs, computing CVSS, or rendering a
verdict themselves. Every parser subclasses `base.py::BaseParser` and
reports a confidence score plus an explicit `unparsed_fragments` list rather
than silently dropping data (constitution §1.7).

`linux_command_parser.py` (Milestone M4,
`docs/adr/0019-linux-security-advisor-agent.md` — `LinuxCommandInputParser`,
one `EvidenceRecord` per non-blank line, no deep classification; a real
above-`plaintext_parser.py` `sniff()` confidence when it recognizes an
`ls -l` permission-string prefix, a shebang, or a security-relevant command
name; backs `core.agents.linux_security_agent.LinuxSecurityAgent`).

`http_transaction_parser.py` (Milestone M4,
`docs/adr/0020-owasp-web-security-agent.md` — `HttpTransactionParser`, one
`EvidenceRecord` per non-blank line of an HTTP request/response transcript,
no deep classification; a real above-`plaintext_parser.py` `sniff()`
confidence when it recognizes an HTTP request/status line, a `Set-Cookie`
header, or a security-relevant header name; backs
`core.agents.web_security_agent.WebSecurityAgent`).

`source_code_parser.py` (Milestone M4,
`docs/adr/0021-owasp-security-agent-ast-sast.md` — `SourceCodeParser`.
Deliberately different from every other parser's per-line-record
convention: **one** `EvidenceRecord` per uploaded file, carrying the full
decoded source text (AST parsing needs a file's whole text as one syntactic
unit, not a stream of independent lines). `sniff()` recognizes Python/
JavaScript/TypeScript/Java content shapes; claims `.py`/`.pyw`/`.js`/`.jsx`/
`.mjs`/`.cjs`/`.ts`/`.tsx`/`.java` extensions; backs
`core.agents.owasp_security_agent.OwaspSecurityAgent`).

**Framework modules:** `registry.py` (plugin-capable `ParserRegistry` —
aliases, priority, versioning, enable/disable, `importlib.metadata`
entry-point plugin discovery), `factory.py` (deterministic parser
selection), `detection.py` (stdlib-only MIME/encoding/content-type
sniffing), `validation.py` (upload-boundary validation: size caps, extension
allowlist, path-traversal guard), `fingerprint.py` (SHA-256),
`metrics.py`/`events.py` (self-contained, leaf-layer observability — never
import `core/graph`), `audit.py` (chain-of-custody structured logging),
`csv_common.py` (shared case-tolerant CSV column lookup for the two CSV
scan-report parsers).

**Why it exists:** Deterministic parsing is faster, cheaper, and more
reliable than asking an LLM to extract structure every time. A future
LLM-assisted fallback (`core/agents/parser_agent.py`, unbuilt) would only
kick in when nothing in this framework matches — not implemented this
milestone (no agent/investigation logic, per explicit scope).

**Not yet built** (blueprint-scoped, future milestones):
`incident_parser.py`.

**Future expansion:** New evidence formats get a new `BaseParser` subclass
registered in `registry.py`, or — without touching this codebase at all — an
out-of-tree package registering itself under the `cdc.parsers`
`importlib.metadata` entry-point group.
