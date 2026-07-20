# ADR-0020: OWASP Web Security Agent

**Status:** Accepted
**Date:** 2026-07-21

## Purpose

Build a new, narrowly-scoped **Web Security Agent** performing deterministic
analysis of HTTP traffic artifacts — requests/responses, security headers,
cookies, JWT metadata, web server logs, API responses, and already-existing
findings/evidence — mapped to the OWASP Top 10 (2021) taxonomy. Capabilities:
a Security Header Analyzer (CSP, HSTS, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy), a Cookie
Analyzer (Secure/HttpOnly/SameSite/Expiration/Domain/Path), a JWT Analyzer
(algorithm/expiration/issuer/audience/header anomalies, no cryptographic
verification), a Misconfiguration Detector (directory listing, missing
headers, weak TLS configuration metadata, debug endpoints, default-credential
indicators, excessive information disclosure), an OWASP Category Mapper, a
Finding Generator, a data-driven Rule Engine, metrics, and audit logging.

This is **not** penetration testing, active vulnerability scanning, incident
response, threat hunting, MITRE ATT&CK mapping, automated exploitation, or
LLM reasoning of any kind — all explicitly out of scope by the task's own
brief.

## Why a separate package/agent from blueprint §7's OWASP Security Agent

`context/01_blueprint.md` §7 defines a **different** "OWASP Security Agent":
*"PDF's Project 7 — source code / API static review... detect SQLi/XSS/
broken-auth patterns... map to OWASP Top-10 (2021)... Input:
`NormalizedEvidence` (parsed source/API spec)... Tools used: `owasp_tools.py`
(AST-based static analysis, not just regex, for the SQLi/XSS detectors)."*
`context/current_state.md`'s own "Next Recommended Prompt" reaffirms this
exact scope (AST-based source-code review) as M4's one remaining item.

This task's input shape is fundamentally different: HTTP requests/responses,
headers, cookies, JWTs, server logs — **no source code, no AST**. Building
this as blueprint's `owasp_agent.py`/`owasp_tools.py` would silently redefine
an already-approved agent's documented input/technique without an amendment
process (constitution §14, "if a task seems to require crossing a forbidden
dependency or bypassing a tool/agent boundary, stop and raise it as an
architecture question"). Following the exact precedent ADR-0019 already set
(`core/linux_advisor/` as a deliberately distinct sibling of
`core/linux_security/`, never conflated despite both being "Linux security"),
this task is built as a **new, separate package and agent**:

- Package: **`core/owasp_web/`** — never `core/owasp/` or anything blueprint
  might later claim for the AST-based source-code reviewer.
- Agent: **`core/agents/web_security_agent.py`** (`WebSecurityAgent`,
  capability `owasp_web_security_assessment`) — never `owasp_agent.py`.
- Tool: **`core/tools/web_security_tools.py`** — never `owasp_tools.py`.

Blueprint §7's OWASP Security Agent (AST-based source-code review) remains
completely unbuilt and unmodified. `docs/roadmap.md`'s M4 checkbox stays
unchecked — this agent does not close M4; it is an additive, out-of-blueprint
capability, exactly as ADR-0019 was for the Linux Security Advisor.

## Decisions

1. **New `EvidenceType.HTTP_TRANSACTION`** (`core/parsers/models.py`) — purely
   additive, matching the precedent ADR-0017/ADR-0019 already set for adding
   evidence types.

2. **New parser `core/parsers/http_transaction_parser.py`
   (`HttpTransactionParser`)** — deliberately dumb/generic like every other
   parser in this package: one `EvidenceRecord` per non-blank line of an
   uploaded HTTP transcript (request line, status line, header lines,
   `Set-Cookie` lines, `Authorization:` lines, response/log body lines), no
   deep classification. Whether a line is a header, a cookie, a JWT-bearing
   line, or a misconfiguration-relevant body/log line is decided by
   `core/owasp_web/advisory_engine.py`, not the parser — the same "parsers
   extract structure only where unambiguous" precedent ADR-0018/ADR-0019
   already established.

3. **`core/owasp_web/` has no DB persistence and no
   `registry.py`/`interfaces.py` enrichment-provider seam** — a single
   request in, a single `WebSecurityAdvice` out, matching ADR-0019's
   precedent for a stateless advisor with no case-evidence lifecycle to
   track. `core/services/web_security_service.py` accordingly takes no DB
   session parameter and is synchronous.

4. **`WebSecuritySeverity` is its own enum**, never a reuse of
   `core.parsers.models.Severity` or any sibling leaf's — matching the
   "each leaf owns its own severity scale" precedent (ADR-0017 point 2 /
   ADR-0018 point 2 / ADR-0019 point 4).

5. **`OwaspCategory` is a first-class, strongly-typed enum** (the ten 2021
   Top-10 categories) used directly on every finding model and on
   `rule_engine.Rule.category` — stronger typing than ADR-0019's plain
   `str` category, since OWASP-category mapping is this agent's defining
   responsibility rather than an incidental grouping label.

6. **A generic, data-driven `RuleEngine`/`Rule` seam
   (`core/owasp_web/rule_engine.py`)**, functionally identical to
   `core/linux_advisor/rule_engine.py` (same `regex`/`literal_substring`/
   `callable_signature` matcher kinds, same metadata/version/priority/
   enable-disable shape) but never imported across packages — each leaf
   owns its own copy per the established "leaves don't share code sideways"
   precedent. Adding a new header-value or misconfiguration detection later
   means adding a `Rule` object to `header_rules.py`/`misconfig_rules.py`;
   this engine's code never changes. Header **presence** checks (a header is
   entirely missing) and cookie **attribute** checks (`Secure`/`HttpOnly`/
   `SameSite`/expiration/domain/path) are absence/structural checks a
   regex-over-one-line engine cannot express — these are deterministic pure
   functions (`cookie_rules.py`) or structured presence tables
   (`header_rules.py`'s `MISSING_HEADER_SPECS`), mirroring
   `permission_parser.py`'s "pure function, not rule engine" precedent for
   structural (rather than pattern) checks.

7. **`jwt_analyzer.py` performs no cryptographic signature verification**
   (task brief's explicit instruction) — it base64-decodes the header/
   payload JSON only, checking algorithm (`none`/missing flagged as
   critical), expiration, issuer, audience, and header anomalies (unexpected
   `jku`/`jwk`/`kid` fields). A malformed JWT (bad base64/JSON) raises
   `MalformedJwtError`, caught and skipped by `advisory_engine.py`, never
   fatal to the whole artifact.

8. **`category_mapper.py`** is a small, pure, deterministic lookup
   (`OwaspCategoryMapper`) from `OwaspCategory` to its official 2021 name/
   description — used by the Finding Generator and available to future
   reporting consumers, never computed by an LLM.

9. **`finding_generator.py`** (`FindingGenerator`) is the single place that
   converts every analyzer's narrow finding type (`HeaderFinding`,
   `CookieFinding`, `JwtFinding`, `MisconfigurationFinding`) into the task's
   unified, strongly-typed `OwaspFinding` shape (OWASP category, severity,
   confidence, evidence reference, explanation, recommended remediation) —
   Single Responsibility Principle applied at the module level (constitution
   §1.4): analyzers detect, `FindingGenerator` normalizes into the one
   reportable shape.

10. **Config-driven, no-hardcoded-values scoring** — `risk_assessment.py`'s
    `RiskAssessmentEngine` combines five configurable dimensions (highest
    individual severity, highest individual confidence, distinct finding
    count, whether any critical-category rule matched, corroboration across
    header+cookie+JWT+misconfiguration analysis) into the overall risk
    verdict, weights read from `core.config.settings.Settings`
    (`owasp_web_risk_weight_*`), validated to sum to 1.0 at construction time
    — identical shape to `core.linux_advisor.risk_assessment`.

11. **`advisory_engine.py` defends against the same three failure classes
    ADR-0019 established**: a configurable oversized-input guard (max
    lines/characters, read from `Settings`, never hardcoded), a malformed
    individual line (an unparseable header, a broken JWT — skipped, counted,
    never fatal), and log-injection-shaped content (control characters and
    embedded newlines stripped before any analyzed text appears in a log
    line or in the advice text itself). This package performs pure text
    analysis and never executes, `eval`s, sends a live HTTP request, or
    shells out to any analyzed content — no active scanning of any kind.

12. **`core/agents/web_security_agent.py` (`WebSecurityAgent`, capability
    `owasp_web_security_assessment`) never recomputes a header's, cookie's,
    or JWT's risk itself** — `core/agents` has no dependency-rules.md import
    edge onto `core/owasp_web`, so `CaseInvestigationState.owasp_web_records`
    stays plain-dict-typed, exactly like `linux_advisory_records`.

13. **`core/services/case_service.py`'s capability-routing table gained one
    new `EvidenceType` entry** (`HTTP_TRANSACTION` ->
    `owasp_web_security_assessment`) — the same additive-table pattern every
    prior specialist agent used.

14. **No penetration testing, active scanning, incident response, threat
    hunting, MITRE mapping, automated exploitation, or LLM reasoning
    anywhere in this package**, matching the task brief's explicit exclusion
    list.

## Alternatives Considered

- **Redefining blueprint §7's OWASP Security Agent to mean this** — rejected:
  the blueprint's own text names AST-based source-code static analysis as
  the required technique and parsed source/API spec as the input; silently
  substituting HTTP-traffic analysis would be an unreviewed architecture
  change, not an extension (constitution §14 point 10). This ADR builds an
  additional, separately-named agent instead, leaving M4's blueprint-defined
  item exactly as open as it was before this session.
- **Reusing `core/linux_advisor/rule_engine.py` directly** — rejected: leaf
  packages do not import each other sideways (docs/dependency-rules.md rule
  10 / rule 5's leaf-isolation principle); each leaf owns its own copy of
  this small, generic engine, matching the "no shared utils across sibling
  leaves" precedent already established.
- **A single monolithic per-category `WebSecurityAdvice`-shaped model with
  no `RuleEngine` seam** — rejected per the same "future rule expansion must
  not require architecture changes" requirement ADR-0019 already applied.
- **Persisting `WebSecurityAdvice` to a DB table** — rejected: this task
  frames the agent as a single request/response advisor with no
  case-evidence lifecycle to track, identical to ADR-0019's reasoning for
  `core/linux_advisor`.

## Consequences

- A sixth concrete specialist agent now exists, proving the same three-step
  extension pattern (parser/tool in its owning leaf package, an agent
  declaring a distinct capability, two lines in `investigation_graph.py`) a
  sixth time.
- `docs/roadmap.md`'s M4 entry gains this addendum but **stays unchecked** —
  blueprint §7's AST-based OWASP Security Agent remains M4's only
  outstanding, unbuilt piece; this ADR does not close it.
- `context/current_state.md`'s "Next Recommended Prompt" continues to point
  at the AST-based OWASP Security Agent and/or the still-open M2 MITRE
  Mapping Agent gap, explicitly declining Incident Response as premature
  (M5 scope).
