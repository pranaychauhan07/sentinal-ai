# core/owasp_security

Blueprint §7's **OWASP Security Agent** — deterministic, AST-based (Python) /
pattern-based (JavaScript, TypeScript, Java) Static Application Security
Testing (SAST) over source code, mapping findings to the OWASP Top 10
(2021) taxonomy and CWE ids. See
`docs/adr/0021-owasp-security-agent-ast-sast.md`.

**This is not** `core/owasp_web/` (ADR-0020's Web Security Agent — HTTP
traffic/header/cookie/JWT analysis, no source code, no AST). The two are
deliberately named differently and never import each other. If you are
looking for HTTP-traffic analysis, that lives in `core/owasp_web/`, not here.

## Scope

- Detect SQL Injection, XSS, Command Injection, Path Traversal, SSRF,
  Hardcoded Secrets, Weak Cryptography, Insecure Randomness, Unsafe
  Deserialization, Broken Authentication, Missing Input Validation,
  Dangerous File Operations, Open Redirect, Sensitive Information Exposure,
  and Insecure Configuration.
- **Python**: genuine AST-based analysis via the stdlib `ast` module.
- **JavaScript/TypeScript/Java**: pattern-based (regex) analysis — this
  project has no AST library for these languages; see the ADR for why this
  is an explicit, documented scope boundary rather than a hidden shortcut.
- Map every finding to an OWASP Top 10 (2021) category and a representative
  CWE id.
- Generate secure-coding recommendations (baseline + finding-triggered).

## Explicitly out of scope

Penetration testing, active vulnerability scanning, incident response,
threat hunting, MITRE ATT&CK mapping, automated exploitation/remediation,
and LLM reasoning of any kind. This package never executes, `eval`s, or
runs any analyzed source code — it is pure static text/AST analysis.

## Module map

| Module | Responsibility |
|---|---|
| `models.py` | `SourceLanguage`, `SastSeverity`, `OwaspCategory`, `VulnerabilityCategory` (+ OWASP/CWE mapping tables), `SourceFinding`, `SastFinding`, `SastAdvice`, `SecureCodingRecommendation`. |
| `exceptions.py` | Narrow exception hierarchy for malformed/unsupported input. |
| `language_detector.py` | `LanguageDetector` — extension-first, content-heuristic-fallback detection. |
| `rule_engine.py` | Generic, data-driven `RuleEngine`/`Rule` — supports `regex`/`literal_substring`/`callable_signature`/`ast_predicate` matchers. |
| `python_ast_rules.py` | Registered AST predicates + `DEFAULT_PYTHON_AST_RULES` — one rule per task-named category, genuine AST analysis. |
| `pattern_rules.py` | `DEFAULT_PATTERN_RULES` — regex-based rules for JavaScript/TypeScript/Java. |
| `python_ast_analyzer.py` | `PythonAstAnalyzer` + `build_ast` (the "AST Builder") — one Python file -> `list[SourceFinding]`. |
| `pattern_analyzer.py` | `PatternSourceAnalyzer` — one JS/TS/Java file -> `list[SourceFinding]`. |
| `vulnerability_detection_engine.py` | `VulnerabilityDetectionEngine` — dispatches to the AST or pattern analyzer by language. |
| `secure_coding_advisor.py` | `SecureCodingAdvisor` — baseline + finding-triggered recommendations. |
| `evidence_mapper.py` | `map_evidence_reference` — human-readable evidence reference per finding. |
| `confidence_calculator.py` | `calculate_confidence` — AST vs. pattern-based confidence discounting. |
| `finding_generator.py` | `FindingGenerator` — normalizes findings into the unified `SastFinding` shape. |
| `risk_assessment.py` | `RiskAssessmentEngine` — configurable, weighted overall risk/confidence. |
| `analysis_engine.py` | `SourceCodeAnalysisEngine` — the orchestrator; oversized-input guard, graceful degradation, log-injection sanitization. |
| `metrics.py` | `SastMetricsCollector`. |
| `audit.py` | Structured audit-event emission + timing. |

## No DB persistence, no enrichment-provider seam

Unlike `core/vulnerabilities`/`core/linux_security`, this framework never
persists findings and has no `registry.py`/`interfaces.py`
enrichment-provider seam — a single file in, a single `SastAdvice` out,
matching `docs/adr/0019`/`docs/adr/0020`'s "advisor" framing.

## Dependency rules

A leaf package (`docs/dependency-rules.md`). May import `core/config`/
`core/logging`. Must never import `core/agents`, `core/graph`, `core/memory`,
or any sibling leaf package (including `core/owasp_web`).
