# `data/knowledge/`

Vendored, hand-curated reference content for `core/knowledge`'s
`OWASP_TOP10`/`SECURITY_PLAYBOOK`/`DETECTION_RULE` sources (ADR-0027) —
read only at process startup (`core.knowledge.bootstrap.
register_default_knowledge_sources`), **never fetched over the network**,
mirroring `data/mitre/README.md`'s identical offline-vendoring convention.

- `owasp_top10.yaml` — OWASP Top 10:2021 categories, descriptions, and
  remediation guidance, summarized from the publicly published taxonomy
  (https://owasp.org/Top10/).
- `security_best_practices.yaml` — general hardening/defense-in-depth
  principles (least privilege, MFA, patch management, logging, backups,
  encryption, hardened configuration, security awareness, vendor risk).
- `incident_response_guidance.yaml` — NIST SP 800-61 Rev. 2's
  incident-response lifecycle (Preparation, Detection & Analysis,
  Containment, Eradication, Recovery, Post-Incident Activity).
- `detection_engineering_guidance.yaml` — general detection-engineering
  principles (testable/versioned rules, behavior- over signature-based
  detection, MITRE ATT&CK-mapped coverage, false-positive tuning,
  vendor-neutral rule formats, "no evidence" vs. "no coverage,"
  documenting rationale).

**This is general, read-only reference/teaching content — never case-specific
data.** It answers "what does good practice look like," never "what did this
case's evidence show." The system's actual case-specific analysis (MITRE
mapping, OWASP static analysis, incident response plan generation) lives in
`core/findings`, `core/owasp_security`/`core/owasp_web`, and
`core/incident_response` respectively, and is structurally independent of
this data.
