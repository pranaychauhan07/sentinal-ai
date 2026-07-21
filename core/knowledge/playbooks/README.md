# core/knowledge/playbooks — Security Playbook Knowledge Source

**Purpose:** Fulfills `core/knowledge`'s `KnowledgeSourceType.SECURITY_PLAYBOOK`
slot (ADR-0010's deferred promise, closed by ADR-0027). Combines two
vendored, offline data files into one source: `data/knowledge/
security_best_practices.yaml` (general hardening/defense-in-depth
guidance) and `data/knowledge/incident_response_guidance.yaml` (NIST SP
800-61 incident-response-lifecycle guidance).

**Responsibility:** Read-only reference content plus the pure functions that
parse and look it up. Never mutated at runtime.

**Implemented:**
- `models.py` — `BestPracticeEntry`, `IncidentResponsePhaseGuidance`.
- `loader.py` — `load_best_practices(path)`, `load_incident_response_guidance(path)`.
- `source.py` — `SecurityPlaybookSource`, a concrete `KnowledgeSource`.

**Not this package's job:** `core/incident_response`'s deterministic,
case-specific `ResponsePlanEngine` (generates an actual `IncidentResponsePlan`
for a case). This package answers "what does the containment phase of NIST
SP 800-61 generally involve," not "what should this specific case's
response plan be."
