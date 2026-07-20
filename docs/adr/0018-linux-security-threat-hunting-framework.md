# ADR-0018: Linux Security Threat Hunting Framework

**Status:** Accepted
**Date:** 2026-07-20

## Purpose

The user asked for a broad "Linux Security Analysis Agent Framework" (SSH
brute force, sudo abuse, privilege escalation, persistence, cron, services,
suspicious processes, auth timeline, finding generation, confidence scoring,
metrics — everything except Incident Response/remediation). Blueprint §7's
"Linux Security Agent" is scoped narrowly (a command/permission-string
explainer) — that is **not** this task, and remains unbuilt, separate, and
still open. With the user's explicit approval, this work is scoped instead
as the **Threat Hunting Agent** (blueprint §7: "proactive IOC hunting...
identify multi-stage patterns (recon -> exploitation -> persistence)"),
which `docs/roadmap.md`/`context/current_state.md` already name as M4's next
piece: `core/agents/threat_hunter_agent.py` extending cross-log hunting over
SSH-auth/syslog evidence. This ADR implements it as a fourth sibling leaf
package (`core/linux_security/`) to `core/threat_intel`, `core/findings`, and
`core/vulnerabilities` — the same shape, same tier, same "deterministic
first" design those three already established, extended rather than
redesigned.

## Decisions

1. **`core/linux_security/` mirrors `core/vulnerabilities`'s file-for-file
   shape**: `models.py`, `exceptions.py`, `normalizer.py`,
   `ssh_auth_analyzer.py`, `sudo_analyzer.py`, `privilege_escalation.py`,
   `persistence_detector.py`, `cron_analyzer.py`, `service_analyzer.py`,
   `process_detector.py`, `authentication_timeline.py`,
   `confidence_engine.py`, `scoring.py`, `finding_generator.py`,
   `extractor.py`, `metrics.py`, `events.py`, `audit.py`,
   `registry.py`/`interfaces.py`. Every module is a pure function or
   stateless engine — no LLM call exists anywhere in this package
   (constitution §1.9).

2. **`LinuxSecuritySeverity` is its own enum**, never a reuse of
   `core.parsers.models.Severity` or a sibling leaf's severity scale —
   matching the identical, already-established precedent
   `core.vulnerabilities.models.VulnerabilitySeverity`'s own docstring: each
   leaf package owns its own severity scale, mapped explicitly at
   translation points where needed.

3. **One shared `LinuxSecurityCandidate` shape, not fifteen bespoke
   per-category models.** The task named fifteen detection categories
   (brute force, compromise-after-brute-force, failed-login spike, root
   login, new user, user deletion, password change, sudo abuse, privilege
   escalation, suspicious cron, reverse shell, suspicious service, suspicious
   process, persistence mechanism, unauthorized account activity). Rather
   than one near-identical Pydantic model per category, every analyzer
   produces the same `LinuxSecurityCandidate` shape, differentiated by
   `category` plus a `context` dict for category-specific extras (the
   command text, the group name, the port, ...). This mirrors
   `core.vulnerabilities.models.VulnerabilityRecord`'s own "one shape, many
   kinds" precedent and keeps the fifteen-category detection surface
   additive without a matching model-file explosion.

4. **`SshAuthParser`/`SyslogParser` already emit everything this package's
   analyzers need — no new parsers, no new `EvidenceType` values.**
   `SshAuthParser` classifies `auth_failure`/`auth_success`/`disconnect`/
   `session_opened` events with `user`/`ip_address`/`timestamp` already
   populated. `SyslogParser` emits generic records with
   `event_type=<process name>` (`sudo`/`CRON`/`useradd`/`userdel`/`passwd`/
   `usermod`/`systemd`) and `normalized_fields={"pid":..., "message": <full
   free-text message>}`. `core.linux_security.normalizer.LinuxSecurityNormalizer`
   maps `EvidenceRecord.event_type` onto `LinuxLogEvent.process` uniformly —
   for SSH-auth records this is already the classified event kind; for
   syslog records it's the emitting process name — and every analyzer in
   this package regexes `normalized_fields["message"]`/`raw_message` itself,
   the same documented supplement-not-primary-path role
   `core.vulnerabilities.cve_extractor`'s regex discovery plays over
   scan-report free text.

5. **`JsonEvidenceParser`'s generic field-heuristics do not yet map
   journald's `_`-prefixed field names** (`_COMM`, `_SYSTEMD_UNIT`,
   `SYSLOG_IDENTIFIER`, `MESSAGE`, `_PID`) — an honest, documented gap
   (same spirit as ADR-0017's CVSS v4.0 gap), not a blocker.
   `core.linux_security.normalizer`'s `_read_journald_fields` opportunistically
   reads those specific keys from `EvidenceRecord.normalized_fields` as a
   best-effort supplement when the standard `event_type`/`message` fields
   come back empty. Because `assess_linux_security()` (point 9 below) only
   ever runs against `SSH_AUTH`/`SYSLOG` evidence — not `JSON` — this
   supplement is currently dormant; it is documented, not force-fixed,
   pending a future evidence-routing decision about journald JSON exports.

6. **A single `EvidenceType` can now require more than one specialist
   capability.** `SYSLOG` already routed to `SocAnalystAgent`'s
   `log_analysis` capability by default (the pre-existing fallback in
   `core/services/case_service.py`'s evidence-to-capability table); this
   ADR adds `ThreatHunterAgent`'s `cross_log_threat_hunting` capability
   alongside it for both `SSH_AUTH` and `SYSLOG`, rather than replacing the
   existing routing. `_EVIDENCE_TYPE_CAPABILITIES` changed from
   `dict[EvidenceType, str]` to `dict[EvidenceType, tuple[str, ...]]`; the
   Planning Agent (`core/agents/planning_agent.py`) already fans out to
   every matched capability in `state.metadata["required_capabilities"]`
   independently — this needed no framework change, only a data-shape
   widening in `case_service.py`.

7. **`core/tools/linux_security_tools.py`'s `LinuxSecurityAssessmentTool`
   and `core/agents/threat_hunter_agent.py` never recompute a detection,
   confidence, or risk score.** They only aggregate what
   `core.services.linux_security_service.LinuxSecurityPipeline` already
   computed (constitution §1.9). Per `docs/dependency-rules.md` rule 4,
   `core/agents` has no import edge onto `core/linux_security` — the same
   reasoning `core/agents/vulnerability_agent.py`'s docstring documents for
   `core/vulnerabilities` — so `CaseInvestigationState.linux_security_records`
   stays a plain `dict[str, object]` list, and `linux_security_tools.py`'s
   input model is dict-shaped, not a typed `LinuxSecurityFinding` import.

8. **`LinuxSecurityFinding` is not persisted to the shared `findings`
   table.** Mirrors `VulnerabilityFinding`'s identical, already-documented
   scoping decision (ADR-0014 point 4, reaffirmed ADR-0016/0017). The
   underlying per-candidate `LinuxSecurityFindingRow` rows *are* persisted
   (`core/db/models/linux_security_finding.py`, mirroring `Vulnerability`'s
   shape) — findings are a case-level, in-memory aggregation computed fresh
   from persisted rows, not their own separate table.

9. **`assess_linux_security()` only runs against `EvidenceType.SSH_AUTH`/
   `EvidenceType.SYSLOG` — deliberately NOT `EvidenceType.JSON`.** `JSON`
   evidence is used generically elsewhere in this codebase for arbitrary
   structured exports (e.g. EDR alerts); forcing Linux-security analysis
   onto every JSON upload would be wrong. Mirrors ADR-0017 point 9's
   identical scan-type gating reasoning for vulnerability assessment
   (running against non-matching evidence would only ever produce empty
   results, wasted work for a guaranteed-empty outcome).

10. **`case_service._run_specialist_agents` gains a fourth registered agent
    and the `_EVIDENCE_TYPE_CAPABILITIES` table gains multi-capability
    entries for `SSH_AUTH`/`SYSLOG`**, closing this framework's own
    real-world demo criterion: uploading an `auth.log` now automatically
    routes to *both* `SocAnalystAgent` and `ThreatHunterAgent`, the same
    fan-out pattern `VulnerabilityAssessmentAgent` (ADR-0017) already
    proved for a fourth agent, now proved for concurrent-capability routing
    on one evidence type.

11. **No Incident Response, no remediation, no LLM reasoning anywhere in
    this framework.** Deterministic-first per constitution §1.9, matching
    the task's explicit exclusion. `authentication_timeline.py`'s per-run
    auth reconstruction is explicitly documented as *not* the blueprint §13
    cross-evidence Threat Timeline UI feature (that remains Milestone M6,
    unbuilt) — its own module docstring says so, to prevent a future session
    from conflating the two.

12. **`service_analyzer.py`'s heuristic is honestly weaker than the other
    analyzers'**, and says so in its own docstring: standard syslog output
    rarely carries a service's full unit-file content (`ExecStart=` almost
    never reaches syslog verbatim), so this analyzer can only reason from a
    "Started"/"Starting" message plus a referenced path — scored at a
    correspondingly low confidence (0.4) rather than presented as
    authoritative.

## Alternatives Considered

- **Build the blueprint §7-scoped Linux Security Agent (command/permission-
  string advisor) instead** — rejected per explicit user direction this
  session; that piece remains unbuilt and separate, and the next
  recommended session should build it.
- **Fifteen separate Pydantic models, one per detection category** —
  rejected: near-identical shapes differing only in a couple of
  category-specific fields; the shared `LinuxSecurityCandidate` + `context`
  bag pattern (point 3) keeps this maintainable and matches
  `VulnerabilityRecord`'s established precedent.
- **Route journald JSON exports through this package by adding `JSON` to the
  gating set** — rejected: `JSON` evidence is deliberately generic
  elsewhere in this codebase; forcing every JSON upload through Linux
  security analysis would be a real regression for non-Linux-security JSON
  evidence types (e.g. EDR alert exports). The journald field-mapping gap
  stays documented, not force-fixed.
- **Silently drop `SocAnalystAgent` from `SYSLOG` routing in favor of
  `ThreatHunterAgent`** — rejected: `SocAnalystAgent`'s generalist log
  analysis and `ThreatHunterAgent`'s Linux-security-specific detection are
  complementary, not competing; both now run for `SYSLOG` evidence.

## Consequences

Makes easier: a future OWASP Security Agent or the still-open blueprint §7
Linux command/permission advisor Agent follows the identical extension
pattern this and the three prior specialist agents (`SocAnalystAgent`,
`PhishingAgent`, `VulnerabilityAssessmentAgent`) now demonstrate four times
over — including, for the first time, the multi-capability-per-evidence-type
routing shape a future evidence type needing two specialists can reuse
directly. Makes harder: `_EVIDENCE_TYPE_CAPABILITIES` in `case_service.py`
now needs to track *sets* of capabilities per evidence type, not a single
string — an accepted, documented tradeoff, and a data-shape change every
future evidence-routing decision must respect. Forecloses: this ADR does not
implement Incident Response synthesis, remediation/hardening
recommendations, the blueprint §7 Linux command/permission-string advisor
Agent, or any LLM reasoning — explicitly out of scope per the task's own
instruction and this codebase's established deterministic-first precedent.

Honest limitations carried into `core/linux_security/README.md`: the
journald `_`-field supplement is dormant pending a future evidence-routing
decision (point 5); `service_analyzer.py`'s heuristic is a best-effort,
low-confidence signal, not authoritative (point 12); no live IP-reputation
or threat-intel enrichment exists for detected brute-force sources
(`core.linux_security.registry`'s unimplemented provider seam, mirroring
ADR-0012/0017's identical gaps); the blueprint §7 Linux Security Agent
(command/permission-string advisor) remains a separate, still-unbuilt M4
piece.
