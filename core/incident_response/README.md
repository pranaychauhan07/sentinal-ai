# core/incident_response

Blueprint §7's **Incident Response Agent** — deterministic, NIST SP
800-61-aligned response-plan synthesis from a case's already-computed
findings. See `docs/adr/0023-incident-response-agent.md`.

This package never parses evidence, never re-derives a severity/risk score/
MITRE mapping, and never calls an LLM (task requirement: "No LLM
reasoning"). It only synthesizes an already-assessed case's findings into a
prioritized, ordered, confidence-scored response plan.

## Scope

- Classify a case's overall `IncidentSeverity` from its findings.
- Match each finding to one or more `ResponseCategory` actions via a
  deterministic MITRE-tactic -> keyword -> severity-fallback rule engine
  (`playbook_rules.py`).
- Prioritize, deduplicate, and order every generated recommendation into a
  single execution-ordered list (`risk_prioritizer.py`, `action_ordering.py`).
- Calculate plan-level confidence/risk rollups (`confidence_calculator.py`).
- Generate deterministic, template-driven lessons-learned entries.

## Explicitly out of scope

Evidence parsing, IOC extraction, MITRE technique mapping, vulnerability/
OWASP/Linux/threat-hunting analysis (all consumed as already-computed
input), report generation, and any LLM reasoning. This package never
executes a recommended action itself — it only produces the recommendation
(constitution §4.11's human-approval-gate boundary applies to whatever
future system actually executes an action, not to this package).

## Module map

| Module | Responsibility |
|---|---|
| `models.py` | `IncidentSeverity`, `ResponsePriority`, `ResponseCategory`, `ResponsePhase`, `ResponseTimeframe`, `ResponseEvidence`, `ResponseAction`, `ResponseRecommendation`, `ResponseMetrics`, `IncidentResponsePlan`. |
| `exceptions.py` | Narrow exception hierarchy for malformed/oversized input. |
| `inputs.py` | `IncidentInputFinding` — the normalized engine-input contract every upstream subsystem's already-computed signal is reduced to. |
| `severity_classifier.py` | `IncidentSeverityClassifier` — case-level severity rollup. |
| `playbook_rules.py` | The rule engine: MITRE tactic / keyword / severity-fallback -> `ResponseCategory`, plus the static per-category template table. |
| `risk_prioritizer.py` | `RiskPrioritizer` — one finding+category -> a fully-specified `ResponseRecommendation`. |
| `action_ordering.py` | `order_recommendations` — dedup, sort, and assign `execution_order`. |
| `confidence_calculator.py` | Plan-level confidence/risk-score rollups. |
| `response_plan_engine.py` | `ResponsePlanEngine` — the pipeline orchestrator; builds the full `IncidentResponsePlan`. |
| `metrics.py` | `IncidentResponseMetricsCollector`. |
| `audit.py` | Structured audit-event emission + timing. |

## No DB persistence in this package

Unlike `SastAdvice`/`WebSecurityAdvice`/`LinuxSecurityAdvice`,
`IncidentResponsePlan` **is** persisted — but the persistence itself lives
in `core/db/models/incident_response_plan.py` /
`core/db/incident_response_plan_repository.py` and is written by
`core/services/case_service.py`, never by this package directly (rule 7:
"`core/db` is the only layer allowed to import SQLAlchemy models directly
for writes").

## Dependency rules

A leaf package (`docs/dependency-rules.md`). May import `core/config`/
`core/logging`. Must never import `core/agents`, `core/graph`, `core/memory`,
or any sibling leaf package. `core/tools/ir_tools.py` is granted a
documented exception (rule 5b) to import this package directly, mirroring
`core/tools/mitre_tools.py`'s identical exception for `core/knowledge` —
see ADR-0023 for why.
