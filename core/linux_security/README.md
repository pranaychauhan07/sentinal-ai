# core/linux_security — Linux Security Analysis Framework

**Purpose:** Deterministic, cross-log Linux security detection over
`SSH_AUTH`/`SYSLOG` evidence (ingested via `core/parsers/{ssh_auth,syslog}
_parser.py`) — a peer leaf package to `core/threat_intel`, `core/findings`,
and `core/vulnerabilities`, same tier, same shape
(docs/adr/0018-linux-security-threat-hunting-framework.md).

**Scope note:** this is the concrete Linux-log detection surface built for
the **Threat Hunting Agent** (`core/agents/threat_hunter_agent.py`), per
blueprint §7's "identify multi-stage patterns (recon -> exploitation ->
persistence)" — *not* the blueprint §7 Linux Security Agent (a narrowly
scoped command/permission-string explainer), which remains unbuilt and is a
separate, still-open piece of M4.

**Responsibility:** Deterministic first, zero LLM calls anywhere in this
package (constitution §1.9). `core/services/linux_security_service.py`
orchestrates these modules into a ten-stage pipeline (Evidence Normalization
-> Authentication Analysis -> Privilege Analysis -> Persistence Analysis ->
Behavior Detection -> Scoring -> Finding Generation -> Persistence -> Event
Publication -> Case/Timeline Notification), reconciled onto the same
ten-stage code shape `core.services.vulnerability_service.VulnerabilityPipeline`
established. `core.agents.threat_hunter_agent.ThreatHunterAgent` only
*summarizes* what this pipeline already computed via
`core.tools.linux_security_tools.LinuxSecurityAssessmentTool` — it never
recomputes a detection, confidence, or risk score itself.

**Implemented:**
- `models.py` — `LinuxLogEvent` (this package's own normalized intermediate
  record), `LinuxSecuritySeverity`/`LinuxSecurityFindingCategory`/
  `SourceReliability` enums (never reusing a sibling leaf's severity scale),
  a single shared `LinuxSecurityCandidate` shape for every detection category
  (see the module's own docstring for why one shape, not fifteen),
  `LinuxSecurityScore`/`ScoredLinuxSecurityCandidate`/`LinuxSecurityFinding`,
  `AuthenticationTimelineEntry`, `NormalizedLinuxSecurityIntel`.
- `exceptions.py` — narrow exception hierarchy.
- `normalizer.py` — `EvidenceRecord` -> `LinuxLogEvent`, with a documented
  best-effort journald `_`-field supplement (see its own docstring for why
  this supplement is currently dormant) and a log-injection guard
  (`sanitize_text`, strips control characters from every free-text field).
- `ssh_auth_analyzer.py` — brute force (sliding-window threshold per source
  IP), failed-login spike (global rate across many distinct sources),
  root login, and compromise-after-brute-force (a later successful login
  from a source that already crossed the brute-force threshold).
- `sudo_analyzer.py` — sensitive-file access, shell-escape-to-root, and
  repeated sudo authentication failures.
- `privilege_escalation.py` — new user / user deletion / password change /
  group-membership escalation / su-to-root, plus a combined
  "new user immediately escalated" multi-step pattern.
- `cron_analyzer.py` / `service_analyzer.py` — suspicious cron jobs and
  service starts. `service_analyzer.py`'s heuristic is honestly weaker
  (documented in its own docstring): syslog rarely carries a service's full
  unit-file content.
- `process_detector.py` — the single shared reverse-shell/suspicious-command
  regex set (`REVERSE_SHELL_PATTERNS`), called by every other analyzer that
  needs it plus its own generic, category-agnostic scan.
- `persistence_detector.py` — cross-category aggregation (suspicious
  cron/service + the new-user-then-escalation pattern) into
  `persistence_mechanism` findings.
- `authentication_timeline.py` — this analysis run's own auth timeline.
  **Not** the blueprint §13 cross-evidence Threat Timeline UI feature (that
  stays M6, unbuilt) — see the module's own docstring.
- `confidence_engine.py` / `scoring.py` — `LinuxSecurityConfidenceEngine`
  and `LinuxThreatScoringEngine`, configurable, sum-to-1.0-validated
  dimensions, weights read from `core/config/settings.py`.
- `finding_generator.py` — groups scored candidates by `(category, subject)`
  into `LinuxSecurityFinding`s. **No remediation/Incident Response field.**
- `extractor.py` — `LinuxSecurityAnalysisEngine`, the orchestrating pipeline
  with an oversized-evidence guard.
- `metrics.py`/`events.py`/`audit.py` — observability, mirroring
  `core.vulnerabilities`'s identical three-module split.
- `registry.py`/`interfaces.py` — `LinuxSecurityProviderRegistry`, a
  plugin-capable seam for a future `LinuxSecurityEnrichmentProvider` (e.g. an
  IP-reputation lookup for a detected brute-force source). **No concrete
  provider exists.**

**Not persisted to the shared `findings` DB table.** `LinuxSecurityFinding`
mirrors `VulnerabilityFinding`'s identical, already-documented scoping
decision. Per-candidate `LinuxSecurityFinding` DB rows *are* persisted
(`core/db/models/linux_security_finding.py`).

**Gating decision:** `assess_linux_security()` only runs against
`EvidenceType.SSH_AUTH`/`SYSLOG` — deliberately **not** `EvidenceType.JSON`,
even though a journald JSON export is a plausible future Linux-security
input. `JSON` evidence is used generically elsewhere for arbitrary
structured exports (e.g. EDR alerts); forcing Linux-security analysis onto
every JSON upload would be wrong (mirrors ADR-0017 point 9's identical
scan-type gating reasoning for vulnerability assessment).

**`SYSLOG` now routes to two specialist agents** (`SocAnalystAgent` and
`ThreatHunterAgent`) — a `core/services/case_service.py` evidence type can
map to more than one capability now; see ADR-0018 point 6.

**Not yet built, by explicit scope:** any concrete
`LinuxSecurityEnrichmentProvider`; remediation/Incident Response synthesis;
LLM-assisted detection triage; the blueprint §7 Linux command/permission-
string advisor Agent (a separate, still-open M4 piece).
