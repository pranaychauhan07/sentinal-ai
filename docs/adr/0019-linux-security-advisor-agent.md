# ADR-0019: Linux Security Advisor Agent

**Status:** Accepted
**Date:** 2026-07-20

## Purpose

Build blueprint §7's **Linux Security Agent** — the narrow, deterministic
command/permission/hardening advisor explicitly declined in
`docs/adr/0018-linux-security-threat-hunting-framework.md` in favor of the
Threat Hunting Agent. Blueprint §7's exact scope: *"Purpose: command/
permission advisor. Responsibilities: explain command, analyze permission
strings, recommend hardening. Input: raw command string or `ls -l` style
output. Output: `LinuxSecurityAdvice`. Tools used: `linux_tools.py`."*

This is **not** log analysis, threat hunting, SOC analysis, IOC extraction,
timeline generation, finding correlation, Incident Response, automated
remediation, or LLM reasoning of any kind — those all belong to
`core/linux_security/` (ADR-0018) or later milestones, and are explicitly out
of scope here.

## Why a separate package from `core/linux_security/`

`core/linux_security/` (ADR-0018) is a complete, already-shipped framework
for Linux **log**-based detection (SSH brute force, sudo abuse, privilege
escalation, persistence, cron/service abuse) over `SSH_AUTH`/`SYSLOG`
evidence. This task's scope — explaining a raw command string, analyzing an
`ls -l` permission listing, recommending hardening — is a fundamentally
different input shape (freeform command/permission text, not structured log
events) and a fundamentally different responsibility (advisory guidance, not
detection). Reusing the name `core/linux_security/` or anything confusingly
similar for this work would conflate two independently-scoped frameworks
with different inputs, different severity scales, and different agents. The
new package is named **`core/linux_advisor/`** — deliberately distinct,
never imported by or importing `core/linux_security/`.

## Decisions

1. **New `EvidenceType.LINUX_COMMAND_INPUT`** (`core/parsers/models.py`) —
   purely additive, matching the precedent ADR-0017 set adding
   `NESSUS_XML`/`NESSUS_CSV`/`OPENVAS_XML`/`OPENVAS_CSV`.

2. **New parser `core/parsers/linux_command_parser.py`
   (`LinuxCommandInputParser`)** — deliberately dumb/generic like every
   other parser in this package: one `EvidenceRecord` per non-blank line
   (`event_type="linux_input_line"`), no deep classification. Whether a line
   is an `ls -l` entry, a shell command, or a `chmod` call is decided by
   `core/linux_advisor/advisory_engine.py`, not the parser — the established
   "parsers extract structure only where unambiguous" precedent, applied
   identically to sudo/cron message parsing in `core/linux_security/`.
   `sniff()` returns 0.4 (above `PlainTextParser`'s 0.1) when it recognizes
   an `ls -l` permission-string prefix, a shebang, or a security-relevant
   command name; registered at priority 3 in `core/parsers/registry.py` —
   heuristic, not a fully structured format.

3. **`core/linux_advisor/` has no DB persistence and no
   `registry.py`/`interfaces.py` enrichment-provider seam**, unlike
   `core/vulnerabilities`/`core/linux_security`. This task never asks for
   persisted findings, cross-case correlation, or external enrichment — a
   single request in, a single `LinuxSecurityAdvice` out, matching
   blueprint's original "advisor" framing exactly. `core/services/
   linux_advisor_service.py` accordingly takes no DB session parameter.

4. **`LinuxAdvisorSeverity` is its own enum**, never a reuse of
   `core.parsers.models.Severity`, `core.vulnerabilities.models.
   VulnerabilitySeverity`, or `core.linux_security.models.
   LinuxSecuritySeverity` — matching the already-established "each leaf
   owns its own severity scale" precedent (ADR-0017 point 2 / ADR-0018
   point 2).

5. **A generic, data-driven `RuleEngine`/`Rule` seam
   (`core/linux_advisor/rule_engine.py`)** is the extensibility point the
   task brief calls out: "future rule expansion must not require
   architecture changes." A `Rule` is a plain Pydantic model with a tagged-
   union `matcher` supporting `regex`, `literal_substring`, and
   `callable_signature` (a named predicate registered via
   `register_callable`, for cross-field checks regex can't express cleanly
   — e.g. a `mkdir` immediately followed by `chmod 777` in the same
   sequence). Adding a detection later means adding a `Rule` object to
   `core/linux_advisor/command_rules.py` (or a caller's own module); this
   engine's code never changes.

6. **`permission_parser.py` is pure, exhaustively bidirectional
   conversion functions** — octal <-> rwx triplets both directions, `ls -l`
   permission-string parsing (including file-type and setuid/setgid/sticky
   special-bit characters), symbolic `chmod` mode application against a base
   permission, and `umask` interpretation. Every malformed-input path
   (invalid octal digit, wrong-length permission string, unrecognized
   symbolic operator) raises a narrow, named exception
   (`core/linux_advisor/exceptions.py`) rather than guessing.

7. **Config-driven, no-hardcoded-values scoring** — `risk_assessment.py`'s
   `RiskAssessmentEngine` combines five configurable dimensions (highest
   individual severity, highest individual confidence, distinct finding
   count, whether any critical-category rule matched, corroboration across
   command+permission analysis) into the overall risk verdict. Weights are
   read from `core.config.settings.Settings`
   (`linux_advisor_risk_weight_*`), validated to sum to 1.0 at construction
   time — mirroring `core.linux_security.scoring.
   LinuxThreatScoringEngine`'s established shape.

8. **`hardening_advisor.py` distinguishes finding-triggered from baseline
   recommendations** (`HardeningRecommendation.is_baseline`) across the
   task's eight named categories (SSH configuration, sudo configuration,
   file permissions, ownership, services, least privilege, filesystem
   security, account security) — baseline recommendations always surface
   regardless of findings; finding-triggered ones name the specific
   command/path that triggered them.

9. **`advisory_engine.py` defends against three failure classes without
   ever aborting the whole artifact**: a configurable oversized-input guard
   (max lines / max characters, read from `Settings`, never hardcoded), a
   malformed individual line (an unparseable `ls -l` entry, broken shell
   quoting — skipped, counted, never fatal), and command-injection/
   log-injection-shaped content (control characters and embedded newlines
   are stripped before any analyzed text appears in a log line or in the
   advice text itself). This package performs pure text analysis and never
   executes, `eval`s, or shells out to any analyzed content, full stop.

10. **`core/agents/linux_security_agent.py` (`LinuxSecurityAgent`,
    capability `linux_security_advisory`) never recomputes a command's risk,
    a permission's risk, or the overall risk score itself** — `core/agents`
    has no dependency-rules.md import edge onto `core/linux_advisor`, so
    `CaseInvestigationState.linux_advisory_records` stays plain-dict-typed
    (a **new**, distinct field name from `linux_security_records`, which
    `ThreatHunterAgent` already uses — the two frameworks' outputs must
    never collide on the same state field).

11. **`core/services/case_service.py`'s capability-routing table gained one
    new `EvidenceType` entry** (`LINUX_COMMAND_INPUT` ->
    `linux_security_advisory`) — the same additive-table pattern every prior
    specialist agent used, no Planning Agent/routing-framework change
    needed.

12. **No Incident Response, no remediation execution, no LLM reasoning
    anywhere in this package.**

## Alternatives Considered

- **Overloading `EvidenceType.PLAIN_TEXT`** for this agent's input —
  rejected: `PLAIN_TEXT` is a shared, deliberately low-confidence catch-all
  already used for unrelated evidence (analyst notes, pasted transcripts)
  with existing default capability routing in `case_service.py`; reusing it
  here would silently change existing routing behavior for every other
  `PLAIN_TEXT` consumer.
- **Extending `core/linux_security/` with a command/permission mode** —
  rejected: that package's models, severity scale, and pipeline shape are
  built around log-event analysis over time; bolting a stateless,
  single-request advisor mode onto it would violate constitution §1.3
  ("small, focused modules... if a module's responsibility needs 'and' to
  describe it, it needs to be split").
- **A single monolithic per-category `LinuxSecurityAdvice`-shaped model
  with no `RuleEngine` seam** — rejected per the task brief's explicit
  requirement that future rule expansion never require architecture
  changes; a hardcoded `if/elif` chain of dangerous-pattern checks would
  violate that requirement on the first new rule.
- **Persisting `LinuxSecurityAdvice` to a DB table** (mirroring
  `Vulnerability`/`LinuxSecurityFindingRow`) — rejected: the task brief
  frames this agent as a single request/response advisor with no
  case-evidence lifecycle to track, unlike the two prior frameworks which
  explicitly needed cross-artifact aggregation and finding history.

## Consequences

- A fifth concrete specialist agent now exists, proving the same
  three-step extension pattern (parser/tool in its owning leaf package, an
  agent declaring a distinct capability, two lines in
  `investigation_graph.py`) a fifth time, this time with the lightest-weight
  leaf package shape yet (no DB, no enrichment seam).
- `docs/roadmap.md`'s M4 entry gains this addendum but stays unchecked — the
  OWASP Security Agent (AST-based static analysis) remains M4's only
  outstanding piece.
- `context/current_state.md`'s "Next Recommended Prompt" points at the
  OWASP Security Agent and/or the still-open M2 MITRE Mapping Agent gap,
  explicitly declining Incident Response as premature (M5 scope).
