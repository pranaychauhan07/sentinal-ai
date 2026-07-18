# core/knowledge — Static Reference Data

**Purpose:** The Knowledge Layer (`context/01_blueprint.md` §4): the taxonomies
the system reasons against. `mitre_attack.json` (local MITRE ATT&CK technique
dataset), `owasp_top10.yaml` (OWASP Top-10 2021 taxonomy), `cvss_calculator.py`
(CVSS v3.1 vector → score).

**Responsibility:** Read-only reference data plus the pure functions that
interpret it. Never mutated at runtime — updates come from re-seeding, not
from agent writes.

**Why it exists:** Gives every agent a shared, versioned vocabulary (see
`docs/mitre.md`, `docs/owasp.md`) instead of each agent inventing its own
categorization.

**Future expansion:** STIX/TAXII feed ingestion would extend this layer with
live threat-intel data, still read-only from the agents' perspective.
