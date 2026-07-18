# Threat Pipeline (Evidence → Executive Report)

This is the concrete, evidence-agnostic data flow every case follows,
reproduced from **[`context/01_blueprint.md`](../context/01_blueprint.md)** §9
as the implementation reference for `core/graph/investigation_graph.py`.

```
1.  Analyst opens/creates a Case, uploads evidence (email / log / scan report / note)
2.  Evidence Classification — sniff file type + extension, tag evidence_type
3.  Parser Agent — routes to deterministic parser → NormalizedEvidence (Pydantic)
    (LLM-assisted fallback only if no deterministic parser matches; flagged low-confidence)
4.  Memory Agent (read) — check ChromaDB for similar past findings; attach as context
5.  Coordinator + Planning Agent — build ExecutionGraph: which specialist agent(s)
    this evidence needs (e.g. email → Phishing Agent; syslog → SOC + Threat Hunting)
6.  Specialist Agent(s) run (ReAct loop: Thought → Tool Call → Observation → ...)
    → produce typed Finding objects, persisted to Postgres immediately (not batched)
7.  MITRE Agent — maps qualifying findings to ATT&CK techniques
8.  Cross-evidence correlation (Coordinator) — shared IOCs across findings (same IP,
    domain, hash) surfaced when a case has multiple evidence items
9.  Incident Response Agent — if severity crosses threshold or analyst requests it,
    synthesizes containment/eradication/recovery/lessons-learned from ALL case findings
10. Report Agent — renders module-level + case-level executive PDF, generates
    Plotly charts (severity pie, MITRE tactic bar, timeline)
11. Memory Agent (write) — embeds this case's findings into ChromaDB for future retrieval
12. Dashboard updates — Case status, risk score, timeline, all live in Streamlit
```

## Why this is one pipeline, not nine

Steps 2–8 are identical regardless of evidence type; only *which specialist
agent* runs at step 6 differs. This is the mechanism that makes the system a
coherent investigation platform instead of nine disconnected single-purpose
scripts (see blueprint §1).

## Implementation notes

- Every arrow above is a LangGraph edge over the single typed
  `CaseInvestigationState` — no agent mutates state outside the object the
  graph passes it.
- Step 6 (specialist agent execution) can fan out to multiple agents in
  parallel when a case has multiple evidence types; the Planning Agent
  (step 5) decides the fan-out shape.
- Step 9 is conditional — a low-severity case (e.g. a single "safe" phishing
  verdict) does not require full incident-response synthesis.
- Step 11 is best-effort: a ChromaDB outage must not block case closure (see
  `docs/adr/0006-memory-strategy.md`).
