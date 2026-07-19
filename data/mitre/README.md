# `data/mitre/`

Vendored MITRE ATT&CK data — read only at process startup / by the seed
script (`scripts/mitre/import_attack_bundle.py`), **never fetched over the
network at runtime** (`docs/adr/0013-finding-mitre-intelligence-engine-shape.md`
point 4). This is what makes the Finding & MITRE ATT&CK Intelligence Engine
work completely offline.

## `raw/attack-enterprise-15.1.json`

A genuine STIX 2.1 bundle (`type: "bundle"`, `spec_version: "2.1"`), but a
**curated, hand-authored subset** of the official MITRE ATT&CK Enterprise
matrix, not a byte-identical mirror of MITRE's published download. It
covers:

- All 14 Enterprise ATT&CK tactics (`x-mitre-tactic` objects, real `TA00xx`
  IDs).
- 20 real, well-known Enterprise techniques (`attack-pattern` objects, real
  `Txxxx` IDs) spanning most tactics, chosen for mapping-engine test
  coverage rather than completeness.
- 5 real software entries (`tool`/`malware` objects, real `Sxxxx` IDs).
- 5 real threat groups (`intrusion-set` objects, real `Gxxxx` IDs).
- 6 real mitigations (`course-of-action` objects, real `Mxxxx` IDs).
- ~39 real `uses`/`mitigates` `relationship` objects connecting the above.

Every ID, name, and relationship above corresponds to MITRE's published
ATT&CK taxonomy. The STIX object `id` UUIDs (the `attack-pattern--<uuid>`
etc. values) are **session-generated for this repository**, not the
UUIDs MITRE's own bundle assigns — only the `external_references[].external_id`
(the `Txxxx`/`TAxxxx`/`Sxxxx`/`Gxxxx`/`Mxxxx` values) are the real, stable
MITRE identifiers this codebase actually keys on.

**Why a subset, not the full corpus:** the official bundle is a large
multi-megabyte file covering hundreds of techniques; hand-authoring it
faithfully is impractical, and downloading it at build time would violate
the "no network fetch" requirement. This subset is sized for genuine
mapping-engine test coverage across every tactic, not a placeholder.

## Importing a future (or the complete official) ATT&CK release

`scripts/mitre/import_attack_bundle.py` is the supported, versioned import
path for **any** STIX 2.1 bundle in this same shape — including the real,
complete official bundle, once vendored:

```
python -m scripts.mitre.import_attack_bundle \
    --bundle data/mitre/raw/attack-enterprise-16.0.json \
    --version 16.0
```

This is deliberately the *only* way new ATT&CK data enters the system.
`core/knowledge/mitre/loader.py` parses any conforming bundle without a code
change — adding a release is "vendor a new file under `raw/`, run the
script with its version," never an application-code change
(`docs/adr/0013` point 4). Existing rows for prior versions are never
mutated in place; each import is additive, keyed by `attack_spec_version`.
