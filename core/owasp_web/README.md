# core/owasp_web

The **OWASP Web Security Agent** framework — a deterministic analyzer of
HTTP traffic artifacts (requests/responses, security headers, cookies, JWT
metadata, web server logs, API responses) mapped to the OWASP Top 10 (2021)
taxonomy. See `docs/adr/0020-owasp-web-security-agent.md`.

**This is not** blueprint §7's OWASP Security Agent (AST-based source-code/
API static review — SQLi/XSS/broken-auth pattern detection over parsed
source code, still unbuilt). The two are deliberately named differently and
never import each other. If you are looking for source-code static
analysis, that agent does not exist yet — see M4's still-open item.

## Scope

- Map detected issues to the OWASP Top 10 (2021) taxonomy.
- Analyze security headers (CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy) for absence
  and value-quality issues.
- Analyze cookies (Secure, HttpOnly, SameSite, expiration, Domain, Path).
- Analyze JWT metadata (algorithm, expiration, issuer, audience, header
  anomalies) — no cryptographic signature verification.
- Detect misconfigurations (directory listing, missing headers, weak TLS
  configuration metadata, debug endpoints, default-credential indicators,
  excessive information disclosure).

## Explicitly out of scope

Penetration testing, active vulnerability scanning, incident response,
threat hunting, MITRE ATT&CK mapping, automated exploitation, and LLM
reasoning of any kind. This package never sends a live HTTP request,
executes, or `eval`s any analyzed content — it is pure static text analysis
over untrusted input.

## Module map

| Module | Responsibility |
|---|---|
| `models.py` | `OwaspCategory`, `WebSecuritySeverity`, `ParsedHeader`/`ParsedCookie`/`ParsedJwt`, per-analyzer finding types, `OwaspFinding`, `WebSecurityAdvice`, `RuleMatch`. |
| `exceptions.py` | Narrow exception hierarchy for malformed input. |
| `rule_engine.py` | Generic, data-driven `RuleEngine`/`Rule` — the extensibility seam; add a `Rule`, never touch this file. |
| `header_rules.py` | Missing-header presence specs + default header value-quality `Rule` set. |
| `cookie_rules.py` | Pure structural cookie-attribute checks. |
| `misconfig_rules.py` | Default misconfiguration-detection `Rule` set. |
| `header_analyzer.py` | `HeaderAnalyzer` — missing/misconfigured security headers. |
| `cookie_analyzer.py` | `CookieAnalyzer` + `parse_set_cookie_line` — one `Set-Cookie` line -> `CookieFinding`. |
| `jwt_analyzer.py` | `JwtAnalyzer` + `parse_jwt` — one JWT -> `JwtFinding`, no signature verification. |
| `misconfiguration_detector.py` | `MisconfigurationDetector` — one generic line -> `MisconfigurationFinding`. |
| `category_mapper.py` | `OwaspCategoryMapper` — OWASP Top 10 category name/description lookup. |
| `finding_generator.py` | `FindingGenerator` — normalizes every analyzer's finding into the unified `OwaspFinding` shape. |
| `risk_assessment.py` | `RiskAssessmentEngine` — configurable, weighted overall risk/confidence. |
| `advisory_engine.py` | `WebSecurityAdvisoryEngine` — the orchestrator; oversized-input guard, log-injection sanitization. |
| `metrics.py` | `WebSecurityMetricsCollector`. |
| `audit.py` | Structured audit-event emission + timing. |

## No DB persistence, no enrichment-provider seam

Unlike `core/vulnerabilities`/`core/linux_security`, this framework never
persists findings and has no `registry.py`/`interfaces.py`
enrichment-provider seam — a single request in, a single
`WebSecurityAdvice` out, matching `docs/adr/0019`'s "advisor" framing.

## Dependency rules

A leaf package (`docs/dependency-rules.md`). May import `core/config`/
`core/logging`. Must never import `core/agents`, `core/graph`, `core/memory`,
or any sibling leaf package (including `core/linux_advisor`).
