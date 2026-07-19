# ADR-0016: Phishing Investigation Agent, Email Parser, Prompt Guard

**Status:** Accepted
**Date:** 2026-07-20

## Purpose

`docs/roadmap.md` M2 named three still-open items: an email parser, the
Phishing Investigation Agent, and `core/security/prompt_guard.py` (the first
guard against attacker-controlled text, required structurally before that
text reaches an agent). A prior request in this session asked for a
ground-up "complete SOC Analyst Agent" rebuild; that request was flagged as
a conflict — `SocAnalystAgent` already exists (M1-closed) at blueprint §7's
narrower scope (log summarization/severity classification), and the
requested case-wide recommendation/escalation-engine scope belongs to the
Incident Response Agent (M5), not the SOC Analyst Agent. This ADR instead
implements the actually-queued M2 item, an **addition** alongside the
existing `SocAnalystAgent`, never a redesign of it.

## Decisions

1. **`EvidenceType.EMAIL` is an additive enum value**, matching
   ADR-0011 point 3's precedent (`core/parsers/models.py`'s `EvidenceType`
   is already "more granular than blueprint §8's illustrative enum...
   additive"). `EmailParser` is registered in `default_parser_registry()`
   exactly like every other builtin parser — no factory/dispatch changes
   needed, since `core.parsers.factory.select_parser` already resolves by
   extension/content-sniff.

2. **`EmailParser` uses only the stdlib `email` package**
   (`email.message_from_string` + `policy.default`), not `eml_parser` or
   any third-party library — constitution §10's "a new dependency is
   justified in its introducing PR's description" bar isn't met when the
   stdlib already parses RFC 5322/MIME correctly for this framework's
   phishing-triage use case (blueprint's tech-stack table lists `email` as
   an accepted option, not `eml_parser` exclusively).

3. **`EmailParser` never extracts IOCs or renders a security verdict.**
   It only decodes the message into header/body `EvidenceRecord`s whose
   `raw_line` carries the sender/reply-to/subject/body text as plain text.
   `core.threat_intel.extractor.IOCExtractionEngine` already regex-scans
   every record's `raw_line` for `EMAIL`/`URL`/`DOMAIN` IOCs (both types
   were already in the 20-type `IOCType` enum, unused until now) — this is
   what lets email evidence flow through the *existing* IOC extraction and
   scoring pipeline with zero new extraction code, honoring "never
   reimplement IOC extraction/threat scoring."

4. **`core/security/prompt_guard.py` is deterministic pattern/keyword
   matching, not an ML classifier or an LLM call.** A guard that could
   itself be manipulated by the text it screens (or that adds another LLM
   round-trip in the hot path) would defeat its own purpose; constitution
   §1.9 reserves LLM reasoning for judgment/synthesis, not a checkable
   yes/no gate. It has zero outbound `core/` dependency other than
   `core/config` (dependency-rules.md rule 8) — `Settings.
   prompt_guard_extra_pattern_list` (already scaffolded, unused until now)
   is its only configuration surface.

5. **`PhishingAgent` never re-extracts IOCs or recomputes threat scores.**
   `core.tools.phishing_tools.PhishingScoringTool` combines net-new
   phishing-specific heuristics (sender/reply-to domain mismatch, urgency/
   social-engineering phrase density, high-risk attachment extensions —
   none of which have an existing home) with the case's *already-scored*
   attributed URL/domain/email IOC composite scores, on its own independent
   0-100 scale (distinct from, never duplicating,
   `core.tools.scoring.RiskScoringTool`'s raw-log risk scale).

6. **`CaseInvestigationState.extracted_indicators` entries stay plain
   `dict[str, object]`, not typed `core.threat_intel.models.ScoredIOC`
   instances.** `docs/dependency-rules.md` rule 4 does not grant
   `core/agents` an import edge onto `core/threat_intel` — only
   `core/services/threat_intel_service.py` and
   `core/services/finding_service.py` get that documented exception
   (rules 4b/4c). `core/graph/state.py` itself already documents
   `extracted_indicators` as staying generic "until a future milestone's
   Threat Hunting Agent narrows it" — introducing a typed `ScoredIOC`
   dependency into `core/agents` now would be exactly the kind of
   layer-boundary violation constitution §14.10 requires stopping for.
   `core/services/case_service.py::_hydrate_attributed_iocs` instead reads
   the case's persisted `IOC` ORM rows (a normal, always-sanctioned
   `core/services` -> `core/db` edge, not a new exception) and reduces each
   to `{"evidence_id", "ioc_type", "composite_score"}` before hydrating
   state — `PhishingAgent` only ever reads plain dicts.

7. **Per-artifact capability routing replaces the SOC-only hardcode.**
   `case_service._run_soc_analysis` (which only ever registered
   `SocAnalystAgent` and hardcoded `required_capabilities=["log_analysis"]`)
   is generalized to `_run_specialist_agents`, registering both concrete
   specialist agents and computing `required_capabilities` from the newly-
   ingested artifact's `EvidenceType` (`EMAIL` -> `email_triage`, everything
   else -> `log_analysis`, preserving every existing log-shaped format's
   prior behavior unchanged). This is a real behavior change to an
   already-shipped internal function (not just an addition) — covered by a
   regression test proving the pre-existing SOC-only path is unchanged for
   non-email evidence, plus new tests proving an `.eml` upload routes to
   `PhishingAgent` instead. This also closes M3's own still-open demo
   criterion: "upload mixed evidence (log + email) to one Case and watch
   the Coordinator fan out to both agents automatically."

8. **`PhishingVerdict` is not persisted to the `findings` table**, matching
   ADR-0014 point 4's identical scoping decision for `SocFinding`. It is
   appended to `CaseInvestigationState.findings` (the in-memory ReAct
   trail) and `AgentExecutionResult.output` only. Reconciling specialist-
   agent findings with the Finding & MITRE Engine's persisted `Finding` rows
   into one shared representation is left to a future milestone.

9. **`EvidenceUploadResponse` gains `phishing_risk_score`/
   `phishing_risk_label`, purely additively** (both `None`-defaulted). No
   existing field changes meaning; this is not a `/api/v2` cutover
   (constitution §13).

## Alternatives Considered

- **Reuse `RiskScoringTool` for phishing scoring** — rejected: that tool's
  weights/scale are calibrated for log severity-distribution aggregation,
  a different measurement than phishing risk; blueprint §7 explicitly names
  a distinct `phishing_tools.py`.
- **Have `PhishingAgent` call `IOCRepository` directly** — rejected:
  `docs/dependency-rules.md` rule 4 forbids `core/agents` importing
  `core/db`; the case's attributed IOCs must be hydrated onto
  `CaseInvestigationState` by `core/services` before the graph runs.
- **Narrow `extracted_indicators` to `ScoredIOC` now** — rejected (see
  Decision 6): no sanctioned import edge exists yet, and `core/graph/
  state.py` already defers this narrowing to the Threat Hunting Agent
  milestone.
- **LLM-based social-engineering/urgency detection** — rejected: no LLM
  client wrapper exists anywhere in this codebase yet, and constitution
  §1.9 reserves LLM reasoning for judgment/synthesis, not a checkable
  keyword/phrase signal a plain function already handles deterministically
  and testably.

## Consequences

Makes easier: any future evidence format gets the same three-step extension
pattern (`core/parsers/*.py` + registry line, `core/agents/*.py` + two graph
lines, capability-routing table entry) `SocAnalystAgent`/`PhishingAgent` both
now demonstrate twice over. Makes harder: `case_service._run_specialist_agents`
now needs updating (one dict entry) for every new evidence-type-to-capability
mapping — an accepted, documented tradeoff, not hidden. Forecloses: this ADR
does not implement LLM reasoning, MITRE mapping for phishing findings, or
IR-agent-level cross-case correlation — explicitly out of scope, per the
prompt's own instruction and blueprint §7's Incident Response Agent boundary.

Honest limitation carried into `core/security/README.md`: `prompt_guard.py`
is a heuristic, signature-based defense layer, not a guarantee — a novel
injection phrasing may not match any pattern. It raises the cost of a naive
attack and gives the analyst a visible signal; it does not claim
exhaustiveness.
