# ADR-0021: OWASP Security Agent (AST-Based SAST)

**Status:** Accepted
**Date:** 2026-07-21

## Purpose

Build blueprint §7's **OWASP Security Agent** — the last remaining M4
specialist agent. Blueprint's exact scope: *"Purpose: source code / API
static review. Responsibilities: detect SQLi/XSS/broken-auth patterns, map
to OWASP Top-10 (2021), severity + secure-coding recommendation. Input:
`NormalizedEvidence` (parsed source/API spec). Tools used: `owasp_tools.py`
(AST-based static analysis, not just regex, for the SQLi/XSS detectors)."*

This agent performs deterministic, AST-based Static Application Security
Testing (SAST) over source code. It never analyzes HTTP traffic, never
duplicates `docs/adr/0020-owasp-web-security-agent.md`'s Web Security
Agent, and never performs LLM reasoning, penetration testing, or automated
remediation.

## Zero overlap with ADR-0020 (`core/owasp_web`)

| | `core/owasp_web` (ADR-0020) | `core/owasp_security` (this ADR) |
|---|---|---|
| Input | HTTP request/response transcripts, headers, cookies, JWTs | Source code files (`.py`/`.js`/`.ts`/`.java`) |
| `EvidenceType` | `HTTP_TRANSACTION` | `SOURCE_CODE` |
| Technique | Line classification + regex/structural checks | AST parsing (Python) / pattern matching (JS/TS/Java) |
| Agent | `web_security_agent.py` (`WebSecurityAgent`) | `owasp_security_agent.py` (`OwaspSecurityAgent`) |
| Tool | `web_security_tools.py` | `owasp_tools.py` (blueprint's exact named file) |
| Capability | `owasp_web_security_assessment` | `owasp_source_code_review` |
| State field | `owasp_web_records` | `owasp_security_records` |

Never imported by or importing each other, matching the same "deliberately
distinct sibling leaf packages" precedent ADR-0019/0020 already established.

## Why Python gets AST and JavaScript/TypeScript/Java get pattern matching

Blueprint's quality bar is explicit: *"AST-based static analysis, not just
regex."* This project's runtime is Python, so the stdlib `ast` module gives
genuine AST parsing for Python source **at zero new-dependency cost** — the
correct, honest way to satisfy that bar for the language this codebase
already depends on.

No JavaScript/TypeScript/Java AST library exists in `requirements.txt`
(confirmed by inspection before writing any code), and adding one (e.g.
`esprima`, `tree-sitter`, `javalang`) is a new-dependency decision this task
does not by itself justify (constitution §10, "a new third-party dependency
is justified in its introducing PR's description"). Rather than silently
degrade to "AST for everything, badly" or skip these languages entirely,
this ADR makes the scope boundary explicit and structural:

- **Python**: `python_ast_analyzer.py` builds a real `ast.AST` via
  `ast.parse()` and walks it with named AST-predicate rules
  (`python_ast_rules.py`) covering all fifteen task-named vulnerability
  categories.
- **JavaScript/TypeScript/Java**: `pattern_analyzer.py` runs the same
  generic `rule_engine.RuleEngine` in its text/regex mode
  (`pattern_rules.py`) — the task brief's own instruction, *"Use pattern
  matching only where AST cannot reasonably express the rule,"* applied at
  the language level: these languages have no AST facility in this project,
  so pattern matching is the honest fallback, not a hidden shortcut.
- **`confidence_calculator.py`** discounts pattern-based findings relative
  to AST-based ones (a real, structural signal that AST findings are more
  reliable), so downstream consumers can distinguish "the system is sure"
  from "the system pattern-matched."
- **Future extension**: `LanguageAnalyzer` is an implicit protocol
  (`analyze(source: str) -> list[SourceFinding]`); adding a real AST-based
  analyzer for JavaScript/TypeScript/Java later is a new class plus a
  routing entry in `vulnerability_detection_engine.py`, requiring its own
  ADR for the new dependency — never a redesign of this framework.

## Decisions

1. **New `EvidenceType.SOURCE_CODE`** (`core/parsers/models.py`) — purely
   additive, matching ADR-0017/0019/0020's precedent.

2. **New parser `core/parsers/source_code_parser.py`
   (`SourceCodeParser`)** — one `EvidenceRecord` per uploaded file, carrying
   the full decoded source text in `normalized_fields["source_text"]` (AST
   parsing needs the whole file, not per-line records — a deliberate
   deviation from the per-line-record convention `linux_command_parser.py`/
   `http_transaction_parser.py` established, justified by source code being
   a single syntactic unit rather than a stream of independent lines).
   `sniff()`/extension matching claims `.py`/`.js`/`.jsx`/`.mjs`/`.ts`/
   `.tsx`/`.java`; `evidence_allowed_extensions` gains these extensions
   (source files are realistically uploaded with real extensions, unlike
   the `.txt`-fallback precedent ADR-0019/0020 used).

3. **`core/owasp_security/` has no DB persistence and no
   `registry.py`/`interfaces.py` enrichment-provider seam**, matching
   ADR-0019/0020's "advisor" framing exactly — a single file in, a single
   `SastAdvice` out. `core/services/owasp_security_service.py` accordingly
   takes no DB session parameter.

4. **`SastSeverity`/`OwaspCategory` are this package's own enums** — never
   a reuse of `core.owasp_web.models.OwaspCategory` or any other sibling
   leaf's, matching the "each leaf owns its own copy" precedent
   (docs/dependency-rules.md rule 10; leaves never share code sideways).

5. **A fifteen-category `VulnerabilityCategory` enum** (SQL Injection, XSS,
   Command Injection, Path Traversal, SSRF, Hardcoded Secrets, Weak
   Cryptography, Insecure Randomness, Unsafe Deserialization, Broken
   Authentication, Missing Input Validation, Dangerous File Operations,
   Open Redirect, Sensitive Information Exposure, Insecure Configuration) —
   the task's named detection surface, each mapped to an `OwaspCategory`
   and a CWE id via static lookup tables (`models.py`).

6. **One generic `Rule`/`RuleEngine` (`rule_engine.py`) supports both text
   and AST matching** via a four-kind tagged union
   (`regex`/`literal_substring`/`callable_signature`/`ast_predicate`) — a
   composable, versioned, prioritized, enable/disable-capable rule seam
   satisfying every property the task's "Rule Engine" section names.
   `ast_predicate` rules are registered by name
   (`register_ast_predicate`) exactly like `callable_signature` rules
   already are, so `Rule` stays a plain, serializable Pydantic model with
   no embedded closures. Adding a detection later means adding a `Rule`
   object to `python_ast_rules.py`/`pattern_rules.py`; the engine itself
   never changes.

7. **`python_ast_rules.py`'s AST predicates are heuristic, not full taint
   tracking** — e.g. SQL injection detection flags a `.execute(...)` call
   whose argument is a dynamically-built string (an f-string/`%`-format/
   string-concatenation `BinOp`) rather than a `Constant`; it cannot prove
   the dynamic content is truly attacker-controlled. Every rule's docstring
   states its detection basis and known false-positive shape explicitly.

8. **`secure_coding_advisor.py`** mirrors `hardening_advisor.py`'s
   established shape: one baseline recommendation per vulnerability
   category (always surfaced) plus finding-triggered recommendations
   (naming the specific file/line that triggered them), distinguished by
   `is_baseline`.

9. **`evidence_mapper.py`** is the task's named "Evidence Mapping"
   capability — a small, pure function producing a human-readable
   `"{filename}:{line_number}"`-style evidence reference for every finding,
   used by `finding_generator.py`.

10. **`confidence_calculator.py`** is the task's named "Confidence
    Calculator" capability — combines a rule's declared confidence with a
    language-support multiplier (`1.0` for AST-based Python findings,
    `0.75` for pattern-based JS/TS/Java findings), a real, documented signal
    of relative reliability rather than a single flat number everywhere.

11. **Config-driven, no-hardcoded-values scoring** — `risk_assessment.py`'s
    `RiskAssessmentEngine` combines five configurable dimensions (identical
    shape to ADR-0019/0020's), weights read from `Settings`
    (`owasp_security_risk_weight_*`), validated to sum to 1.0.

12. **`analysis_engine.py` (`SourceCodeAnalysisEngine`) defends against
    four failure classes without ever aborting the whole artifact**: an
    oversized-input guard (max lines/chars, from `Settings`), an
    unsupported/undetected language (`UnsupportedLanguageError`, caught and
    surfaced as a degraded, zero-finding `SastAdvice` rather than a crash),
    a Python syntax error (`ast.parse()` raising `SyntaxError` — caught,
    converted to `AstParseError`, degrades to a zero-finding result with an
    explicit "could not parse" explanation rather than guessing), and
    log-injection-shaped content (control characters/embedded newlines
    stripped from any snippet before it reaches a log line or advice text).
    This package never executes, `eval`s, or runs any analyzed source code.

13. **`core/agents/owasp_security_agent.py` (`OwaspSecurityAgent`,
    capability `owasp_source_code_review`) never recomputes a finding's
    severity, confidence, or the overall risk score itself** — `core/agents`
    has no dependency-rules.md import edge onto `core/owasp_security`, so
    `CaseInvestigationState.owasp_security_records` stays plain-dict-typed
    (a new, distinct field name from every other `*_records` field).

14. **`core/services/case_service.py`'s capability-routing table gained one
    new `EvidenceType` entry** (`SOURCE_CODE` -> `owasp_source_code_review`)
    — the same additive-table pattern every prior specialist agent used.

15. **No penetration testing, active scanning, incident response, threat
    hunting, MITRE mapping, automated exploitation, or LLM reasoning
    anywhere in this package.** This package never runs, imports, or
    `eval`s the source code it analyzes.

## Alternatives Considered

- **Adding a third-party JS/TS/Java AST library this session** — rejected:
  not justified by this task alone (constitution §10); the seam is built so
  it can be added later behind its own ADR without touching the Python
  engine or this framework's shape.
- **Regex-only detection for every language, including Python** — rejected:
  blueprint's own quality bar explicitly requires AST-based analysis "not
  just regex" wherever practical, and Python's `ast` module makes "wherever
  practical" include Python at zero cost.
- **Reusing `core.owasp_web.rule_engine.RuleEngine`** — rejected: leaf
  packages never share code sideways (docs/dependency-rules.md rule 10);
  this package owns its own copy, extended with the `ast_predicate` matcher
  kind `core.owasp_web` has no need for.
- **Persisting `SastAdvice` to a DB table** — rejected: matches ADR-0019/
  0020's "single request in, single advice out" framing; no case-evidence
  lifecycle to track.
- **One `EvidenceRecord` per source line (matching `linux_command_parser.py`/
  `http_transaction_parser.py`'s per-line convention)** — rejected: AST
  parsing requires the whole file as one syntactic unit; splitting it into
  per-line records would force `core/owasp_security` to reassemble the
  original file from records, an unnecessary round-trip. One record per
  file, carrying full source text, is the correct shape here.

## Consequences

- A seventh concrete specialist agent now exists, proving the same
  three-step extension pattern a seventh time.
- **This closes M4 entirely** — `docs/roadmap.md`'s M4 checkbox is checked
  off in this session's addendum: Vulnerability Assessment, Threat Hunting,
  the Linux Security Advisor, the out-of-blueprint Web Security Agent
  (ADR-0020), and now the blueprint-defined AST-based OWASP Security Agent
  are all built.
- JavaScript/TypeScript/Java detection quality is intentionally
  lower-confidence (pattern-based) than Python's (AST-based) — surfaced
  structurally via `confidence_calculator.py`, not hidden.
- `context/current_state.md`'s "Next Recommended Prompt" moves on to M2's
  still-open MITRE Mapping Agent and/or M5's Incident Response Agent, since
  M4 is now fully closed.
