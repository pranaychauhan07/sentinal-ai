# core/linux_advisor

Blueprint §7's **Linux Security Agent** framework — a narrow, deterministic
command/permission/hardening advisor. See
`docs/adr/0019-linux-security-advisor-agent.md`.

**This is not** `core/linux_security/` (ADR-0018's Linux Security *Threat
Hunting* framework — SSH-auth/syslog-based detection of brute force, sudo
abuse, persistence, cron abuse, etc.). The two packages are deliberately
named differently and never import each other. If you are looking for log
analysis, IOC extraction, or cross-event correlation, that lives in
`core/linux_security/`, not here.

## Scope

- Explain a raw Linux command in plain language.
- Analyze `ls -l`-style permission strings and octal/symbolic chmod modes.
- Recommend hardening actions across eight categories (SSH configuration,
  sudo configuration, file permissions, ownership, services, least
  privilege, filesystem security, account security).

## Explicitly out of scope

Log parsing, threat hunting, SOC analysis, IOC extraction, timeline
generation, finding correlation, incident response, automated remediation,
and LLM reasoning of any kind. This package never executes, `eval`s, or
shells out to any analyzed content — it is pure static text analysis over
untrusted input.

## Module map

| Module | Responsibility |
|---|---|
| `models.py` | `LinuxAdvisorSeverity`, `LinuxCommand`, `PermissionAnalysis`, `CommandRisk`, `PermissionRisk`, `HardeningRecommendation`, `LinuxSecurityAdvice`, `RuleMatch`. |
| `exceptions.py` | Narrow exception hierarchy for malformed input. |
| `rule_engine.py` | Generic, data-driven `RuleEngine`/`Rule` — the extensibility seam; add a `Rule`, never touch this file. |
| `command_rules.py` | Default dangerous-command `Rule` data set. |
| `permission_parser.py` | Pure octal/rwx/`ls -l`/symbolic-mode/umask conversion functions. |
| `command_analyzer.py` | `CommandAnalyzer` — one command line -> `CommandRisk`. |
| `permission_analyzer.py` | `PermissionAnalyzer` — one `PermissionAnalysis` -> `PermissionRisk`. |
| `hardening_advisor.py` | `HardeningAdvisor` — finding-triggered + baseline recommendations. |
| `risk_assessment.py` | `RiskAssessmentEngine` — configurable, weighted overall risk/confidence. |
| `advisory_engine.py` | `LinuxSecurityAdvisoryEngine` — the orchestrator; oversized-input guard, log-injection sanitization. |
| `metrics.py` | `LinuxAdvisorMetricsCollector`. |
| `audit.py` | Structured audit-event emission + timing. |

## No DB persistence, no enrichment-provider seam

Unlike `core/vulnerabilities`/`core/linux_security`, this framework never
persists findings and has no `registry.py`/`interfaces.py`
enrichment-provider seam — a single request in, a single
`LinuxSecurityAdvice` out, matching blueprint's original "advisor" framing.

## Dependency rules

A leaf package (`docs/dependency-rules.md`). May import `core/config`/
`core/logging`. Must never import `core/agents`, `core/graph`, `core/memory`,
or `core/linux_security`.
