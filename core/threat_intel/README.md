# core/threat_intel — Threat Intelligence & IOC Extraction Framework

**Purpose:** Transforms `core.parsers.models.NormalizedEvidence` into
structured, scored, classified threat intelligence — deterministic
first, LLM-assisted reasoning strictly out of scope for this package
(`docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md`).
Reusable by any future investigation workflow (constitution §1.9,
task requirement).

**Implemented components (task-scoped, twelve):** `IOCExtractionEngine`
(`extractor.py`, one data-driven engine covering all twenty `IOCType`s via
`patterns.py`), `ExtractorRegistry`/`ProviderRegistry` (`registry.py`,
`provider_registry.py` — plugin-capable, `importlib.metadata` entry points),
the `IOCRecord`/`NormalizedThreatIntel`/etc. models (`models.py`),
`IOCValidator` (`validator.py`), `IOCNormalizer` (`normalizer.py`),
`deduplicate_iocs` (`dedup.py`), `ThreatIntelProvider`/`IOCEnrichmentProvider`
Protocols (`interfaces.py`, unimplemented), `DetectionRuleEngine`
(`rules.py` + `rule_validation.py`), `ThreatScoringEngine`/
`ConfidenceCalculator` (`scoring.py`), `ThreatClassificationEngine`
(`classification.py`), `EvidenceAttributionTracker` (`attribution.py`).

**IOC types supported (twenty):** IPv4, IPv6, domain, hostname, URL, email,
SHA1, SHA256, MD5, file name, username, process name, registry key, port,
service, mutex, scheduled task, command line, user agent, certificate
fingerprint — see `models.IOCType`.

**Framework modules:** `metrics.py`/`events.py` (self-contained,
leaf-layer observability — never import `core/graph`), `audit.py`
(evidentiary/attribution structured logging), `exceptions.py` (narrow
hierarchy over `core.exceptions.ValidationError`/`ExternalServiceError`).

**Why it exists:** IOC extraction is exactly the kind of deterministic,
checkable computation constitution §1.9 requires to be a plain function —
never LLM freeform reasoning. A future `core/agents/threat_hunter_agent.py`
(blueprint §7) calls `core.services.threat_intel_service.
extract_threat_intelligence()` and reasons over its typed output, the same
way a future `parser_agent.py` would call `ingest_evidence()`.

**Not yet built** (explicit scope cuts, `docs/adr/0012...md`): MITRE ATT&CK
mapping, cross-case/incident correlation, any concrete
`ThreatIntelProvider`/`IOCEnrichmentProvider` (MISP, AlienVault OTX,
VirusTotal, AbuseIPDB, GreyNoise, OpenCTI), any LLM reasoning, any
`/api/v1` route.

**Future expansion:** New IOC types extend `patterns.py`/`validator.py`/
`normalizer.py`'s per-type tables. A genuinely novel extraction strategy
(e.g. an ML-based extractor) registers a new `BaseIOCExtractor` subclass in
`registry.py`, or — without touching this codebase at all — an out-of-tree
package registering itself under the `cdc.threat_intel_extractors` or
`cdc.threat_intel_providers` `importlib.metadata` entry-point groups. A
future Sigma-rule importer maps onto `models.DetectionRule`'s
already-Sigma-adjacent field names without a redesign.
