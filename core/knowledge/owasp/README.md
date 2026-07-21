# core/knowledge/owasp — OWASP Top 10 Knowledge Source

**Purpose:** Fulfills `core/knowledge`'s `KnowledgeSourceType.OWASP_TOP10`
slot (ADR-0010's deferred promise, closed by ADR-0027). Parses the vendored,
offline `data/knowledge/owasp_top10.yaml` file into typed `OwaspCategory`
records and exposes them as a `core.knowledge.interfaces.KnowledgeSource`.

**Responsibility:** Read-only reference content plus the pure functions that
parse and look it up. Never mutated at runtime.

**Implemented:**
- `models.py` — `OwaspCategory`.
- `loader.py` — `load_owasp_categories(path)`.
- `source.py` — `OwaspTop10Source`, a concrete `KnowledgeSource`.

**Not this package's job:** static-analysis OWASP detection
(`core/owasp_security`, `core/owasp_web` — separate leaf packages with
their own CWE/OWASP mapping tables). This package answers "what does OWASP
say about broken access control," not "does this case's evidence show
broken access control."
