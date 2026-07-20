# core/vulnerabilities — Vulnerability Assessment Framework

**Purpose:** Transforms structured vulnerability scan results (Nessus/OpenVAS
XML/CSV, ingested via `core/parsers/{nessus,openvas}*.py`) into normalized,
scored `VulnerabilityFinding`s — a peer leaf package to `core/threat_intel`
(IOC extraction) and `core/findings` (Finding & MITRE Engine), same tier,
same shape (docs/adr/0017-vulnerability-assessment-framework.md).

**Responsibility:** Deterministic first, AI-assisted second (task
requirement) — every module here is a pure function or a stateless engine;
no LLM call exists anywhere in this package. `core/services/
vulnerability_service.py` orchestrates these modules into the ten-stage
pipeline (extract -> validate -> normalize -> deduplicate -> correlate ->
score -> generate findings -> persist -> publish -> notify); the
`core.agents.vulnerability_agent.VulnerabilityAssessmentAgent` only
*summarizes* what this pipeline already computed — it never recomputes CVSS,
severity, or a threat score itself.

**Implemented:**
- `models.py` — `VulnerabilityRecord`, `VulnerabilityScore`,
  `ScoredVulnerability`, `AssetCorrelation`, `VulnerabilityFinding`,
  `NormalizedVulnerabilityIntel`, plus this package's own
  `VulnerabilitySeverity`/`VulnerabilityPriority`/`AssetCriticality`/
  `DetectionSource`/`SourceReliability` enums (never reusing a sibling
  leaf's severity scale directly — see the module's own docstring).
- `exceptions.py` — narrow exception hierarchy.
- `cve_extractor.py` — CVE/CWE regex discovery + MITRE ID syntax validation.
- `validator.py` — structural validation (has an identifying key, CVE
  syntax, port range).
- `normalizer.py` — canonicalization (CVE/host/IP/service case) and
  deterministic `asset_id` derivation.
- `dedup.py` — `VulnerabilityDeduplicationEngine`, configurable dedup key
  (asset+CVE / asset+plugin / same service / same port / custom).
- `asset_correlation.py` — deterministic grouping by asset.
- `confidence_engine.py` — `VulnerabilityConfidenceEngine`, four
  configurable, sum-to-1.0-validated dimensions.
- `severity.py` — CVSS-to-severity mapping, scanner-code fallback, priority
  assignment (severity + asset criticality).
- `scoring.py` — `VulnerabilityThreatScoringEngine`, six configurable,
  sum-to-1.0-validated dimensions (CVSS/severity/confidence/asset
  criticality/source reliability/evidence quality).
- `finding_generator.py` — groups scored vulnerabilities by CVE (or plugin)
  across assets into `VulnerabilityFinding`s. **No remediation/
  recommendation field** — remediation planning is explicitly out of scope
  (task requirement).
- `extractor.py` — `VulnerabilityExtractionEngine`, reads the *structured*
  per-finding fields the Nessus/OpenVAS parsers place on
  `EvidenceRecord.normalized_fields`, supplemented by `cve_extractor`'s
  regex discovery over free-text descriptions.
- `metrics.py`/`events.py`/`audit.py` — observability: per-extractor
  attempt/success/degraded counters, an in-process lifecycle-event
  publisher, and structured audit logging — mirroring
  `core.threat_intel`'s identical three-module split.
- `registry.py`/`interfaces.py` — `VulnerabilityProviderRegistry`, a
  plugin-capable seam for a future `VulnerabilityEnrichmentProvider` (e.g.
  an NVD API lookup). **No concrete provider exists** — an explicit scope
  cut mirroring `core.threat_intel`'s identical, honestly-documented gap.

**CVSS math** lives in `core/knowledge/cvss_calculator.py` (the blueprint's
named location, `context/01_blueprint.md` §6), not here — this package only
*consumes* it. CVSS v2 and v3.0/3.1 base scores are computed via the
official published formulas; **CVSS v4.0 support is vector parsing/
validation only** (no closed-form base-score formula exists for v4.0 — see
that module's docstring).

**Not persisted to the shared `findings` DB table.** `VulnerabilityFinding`
mirrors `core.agents.soc_analyst_agent.SocFinding`'s and
`core.agents.phishing_agent.PhishingVerdict`'s identical, already-documented
scoping decision (ADR-0014 point 4, reaffirmed ADR-0016): reconciling every
specialist agent's in-memory finding type into one shared, persisted
representation is deferred to a future milestone. `Vulnerability` rows
(the per-record scored data) *are* persisted (`core/db/models/vulnerability.py`).

**Why it exists:** Deterministic scan-report interpretation is faster,
cheaper, and more reliable than asking an LLM to re-derive a CVSS score or
re-discover a CVE ID every time (constitution §1.9) — this is the Tool/
processing layer the future Vulnerability Assessment Agent leans on, exactly
as `core/threat_intel` is for the (still unbuilt) Threat Hunting Agent.

**Not yet built, by explicit scope:** any concrete
`VulnerabilityEnrichmentProvider`; remediation/patch-planning logic;
Incident Response synthesis; LLM-assisted vulnerability triage.
