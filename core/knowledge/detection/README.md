# core/knowledge/detection — Detection Engineering Knowledge Source

**Purpose:** Fulfills `core/knowledge`'s `KnowledgeSourceType.DETECTION_RULE`
slot (ADR-0010's deferred promise, closed by ADR-0027). Parses the vendored,
offline `data/knowledge/detection_engineering_guidance.yaml` file into typed
`DetectionPrinciple` records and exposes them as a `core.knowledge.
interfaces.KnowledgeSource`.

**Responsibility:** Read-only reference content plus the pure functions that
parse and look it up. Never mutated at runtime.

**Implemented:**
- `models.py` — `DetectionPrinciple`.
- `loader.py` — `load_detection_principles(path)`.
- `source.py` — `DetectionRuleSource`, a concrete `KnowledgeSource`.

**Not this package's job:** `core/findings/mapping_rules.py` (this
project's actual, deterministic IOC-to-MITRE-technique mapping engine).
This package answers "what makes a good detection rule in general," never
whether this case's evidence maps to a specific technique.
