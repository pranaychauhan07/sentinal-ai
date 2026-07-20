# core/knowledge — Static Reference Data

**Purpose:** The Knowledge Layer (`context/01_blueprint.md` §4): the taxonomies
the system reasons against. `mitre_attack.json` (local MITRE ATT&CK technique
dataset), `owasp_top10.yaml` (OWASP Top-10 2021 taxonomy), `cvss_calculator.py`
(CVSS vector → score) — `mitre_attack.json`/`owasp_top10.yaml` don't exist yet;
`cvss_calculator.py` does (see below).

**Responsibility:** Read-only reference data plus the pure functions that
interpret it. Never mutated at runtime — updates come from re-seeding, not
from agent writes.

**Implemented (abstraction only, no data):**
- `models.py` — `KnowledgeSourceType` (MITRE/OWASP/threat-intel/playbook/
  detection-rule/investigation-template), `KnowledgeDocument`,
  `KnowledgeQuery`, `KnowledgeSearchResult`.
- `interfaces.py` — `KnowledgeSource` Protocol (one taxonomy/dataset),
  `KnowledgeRetriever` Protocol (a retrieval strategy across sources — the
  seam a future RAG/embedding pipeline plugs into).
- `registry.py` — `KnowledgeSourceRegistry`/`default_knowledge_registry()`,
  empty until a concrete source registers itself.
- `retrieval.py` — `KeywordKnowledgeRetriever`, a deterministic keyword-match
  `KnowledgeRetriever` (constitution Principle 9) — genuinely functional
  against whatever sources are registered, but explicitly not semantic/RAG
  retrieval; that's a documented future swap behind the same Protocol.

**Implemented (new this session, docs/adr/0013-finding-mitre-intelligence-
engine-shape.md):**
- `mitre/` — `MitreAttackSource` (a concrete `KnowledgeSource`) plus typed
  MITRE ATT&CK reference models (`MitreTechnique`, `MitreTactic`,
  `MitreSoftware`, `MitreGroup`, `MitreMitigation`), a STIX 2.1 bundle
  loader, and `MitreLookup` fast in-memory lookups — see
  `core/knowledge/mitre/README.md`. Data is vendored offline
  (`data/mitre/raw/`), never fetched over the network.

**Implemented (docs/adr/0017-vulnerability-assessment-framework.md):**
- `cvss_calculator.py` — `CvssCalculator` (unified parse/score facade),
  official published NVD/FIRST base-score formulas for CVSS v2.0 and
  v3.0/3.1 (hand-verified against FIRST's own worked examples), plus
  `CvssSeverity` (this module's own severity scale — never a reuse of a
  sibling leaf's, per constitution §3). **CVSS v4.0 support is vector
  parsing/format validation only** — no closed-form base-score formula
  exists for v4.0 (FIRST's spec uses a ~90,000-row MacroVector lookup
  table); a wrong reimplementation would be worse than the documented gap.
  Consumed by `core/vulnerabilities/` (never duplicated there).

**Not yet built, by explicit scope:** `OwaspTop10Source`, a threat-intel/
playbook/detection-rule/investigation-template source, and any populated
dataset for those domains. This is cybersecurity-domain content, deliberately
deferred past this session.

**Why it exists:** Gives every agent a shared, versioned vocabulary (see
`docs/mitre.md`, `docs/owasp.md`) instead of each agent inventing its own
categorization.

**Future expansion:** STIX/TAXII feed ingestion would extend this layer with
live threat-intel data, still read-only from the agents' perspective;
embedding-based `KnowledgeRetriever` for real RAG once a concrete source
exists to embed.
