# core/findings — Finding & MITRE ATT&CK Intelligence Engine

**Purpose:** Deterministic, LLM-free mapping of scored IOCs
(`core.threat_intel.models.ScoredIOC`) to MITRE ATT&CK techniques, and
generation of typed, confidence-scored `Finding`s from that mapping —
`docs/adr/0013-finding-mitre-intelligence-engine-shape.md`. This is a new
leaf package, peer to `core/threat_intel`/`core/parsers`/`core/tools`.

**Responsibility:** IOC-to-technique mapping, evidence aggregation, Finding
confidence/severity/priority assignment, and within-case deduplication. No
LLM reasoning, no investigation logic, no cross-case correlation — those are
later milestones (the Investigation Engine, the Incident Response Agent).

**Implemented:**
- `models.py` — `FindingSeverity`, `FindingStatus`, `FindingPriority`,
  `MappingConfidenceFactors`, `MitreMapping`, `TimelineEntry`,
  `EvidenceBundle`, `FindingConfidence`, `DuplicateMatchResult`,
  `FindingRecord`.
- `exceptions.py` — `FindingsError`, `NoTechniqueMatchError`,
  `InvalidMappingRuleError`, `DuplicateExplosionGuardError`.
- `base.py` — `BaseFindingGenerator`, the template-method base every
  mapping engine implements (mirrors `core.threat_intel.base.
  BaseIOCExtractor`).
- `mapping_rules.py` — `MAPPING_RULES`, the data-driven IOC-type ->
  technique-ID table (one-IOC-to-many-techniques and many-IOCs-to-one-
  technique via co-occurrence boosting), covering every technique in the
  vendored MITRE dataset.
- `mapping_engine.py` — `MitreMappingEngine`, the one concrete,
  rule-dispatching mapper.
- `evidence_aggregation.py` — `EvidenceAggregator`: cross-reference
  tracking, timeline reconstruction, chain-of-custody preservation.
- `confidence_engine.py` — `ConfidenceEngine`/`FindingConfidenceWeights`
  (all seven required dimensions, sum-to-1.0 validated).
- `severity.py` — pure functions: `assign_severity`, `assign_priority`,
  `calculate_risk_score`.
- `dedup.py` — `FindingDeduplicationEngine` (bucket-first, six required
  dimensions) + `merge_findings`.
- `finding_generator.py` — `FindingGenerationEngine`, composing the above
  into candidate `FindingRecord`s (one per mapped technique).
- `metrics.py`, `events.py`, `audit.py` — self-contained, leaf-layer
  observability (never import `core.graph.events.EventBus`), mirroring
  `core/threat_intel`'s identical pattern. `events.py` defines the six
  required lifecycle events: `FindingCreated`, `FindingUpdated`,
  `FindingMerged`, `TechniqueMapped`, `ConfidenceUpdated`, `FindingClosed`.

**Explicitly not built here:** persistence (`core/db/models/finding.py` +
`core/db/finding_repository.py`), orchestration/event-publication/memory-
notification (`core/services/finding_service.py`) — those live one layer up,
per the exact `core/threat_intel` / `threat_intel_service.py` split.

**Dependencies (docs/dependency-rules.md rule 5, extended):** may import
`core.knowledge` (specifically `core.knowledge.mitre`) and, as the one
documented sideways leaf-model exception, `core.threat_intel.models`
(`ScoredIOC`/`IOCRecord`/`IOCType`/`ThreatSeverity`/`SourceReliability` —
its input contract only, never `core.threat_intel.scoring`/`classification`/
etc.). Never imports `core.agents`, `core.graph`, `core.memory`, or
`core.db`.
