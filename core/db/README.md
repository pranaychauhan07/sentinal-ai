# core/db — Persistence (SQLAlchemy ORM)

**Purpose:** The Database Layer (`context/01_blueprint.md` §4). `models/` is a
package, one module per table (`models/evidence.py`, `models/ioc.py`,
`models/finding.py`, `models/finding_mitre_mapping.py`,
`models/mitre_tactic.py`, `models/mitre_technique.py`,
`models/mitre_software.py`, `models/mitre_group.py`,
`models/mitre_mitigation.py` today; future `models/case.py`,
`models/timeline_event.py`, `models/report.py` as Milestone M1 adds them),
re-exported from `models/__init__.py` exactly as blueprint §8 specifies.
`session.py` provides the async SQLAlchemy session factory. `migrations/`
holds Alembic migrations.

**`Evidence.case_id`, `IOC.case_id`, and `Finding.case_id` are plain UUID
columns, not yet foreign keys** — `Case` doesn't exist yet. See
`docs/adr/0011-evidence-ingestion-pipeline-shape.md` (extending the identical
precedent `core/memory/db_models.py::MemoryRecordRow` set in ADR-0010),
`docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md` point 3,
and `docs/adr/0013-finding-mitre-intelligence-engine-shape.md` point 6
(`IOC.evidence_id`/`Finding.primary_evidence_id`/`Finding.primary_ioc_id`, by
contrast, **are** real foreign keys, since `evidence`/`iocs` already exist).
A follow-up additive migration adds all three `case_id` FK constraints once
Milestone M1 builds `Case`.

**The five `mitre_*` tables are reference tables, seeded only by
`scripts/mitre/import_attack_bundle.py`, never written by application
logic.** Each has a surrogate UUID PK plus a unique indexed business column
(`technique_id`, `tactic_id`, etc.) and an `attack_spec_version` column — a
new ATT&CK release is additive new rows, never an in-place mutation of an
existing one (constitution §7). `finding_mitre_mappings` is the real
many-to-many join table between `Finding` and `MitreTechnique`.

**Responsibility:** System-of-record persistence only. ChromaDB (in
`core/memory/long_term.py`) is retrieval-only and never authoritative.

**Why it exists:** A multi-case, multi-evidence-type system has real relational
structure; see `docs/adr/0004-relational-database.md` for why PostgreSQL (with
SQLite as a drop-in fallback) was chosen over a flat-file or pure-vector store.

**Future expansion:** Multi-user/RBAC tables are additive to this schema, not a
rewrite of it.
