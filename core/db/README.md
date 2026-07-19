# core/db — Persistence (SQLAlchemy ORM)

**Purpose:** The Database Layer (`context/01_blueprint.md` §4). `models/` is a
package, one module per table (`models/evidence.py` today; future
`models/case.py`, `models/finding.py`, `models/mitre_technique.py`,
`models/timeline_event.py`, `models/report.py` as Milestone M1 adds them),
re-exported from `models/__init__.py` exactly as blueprint §8 specifies.
`session.py` provides the async SQLAlchemy session factory. `migrations/`
holds Alembic migrations.

**`Evidence.case_id` is a plain UUID column, not yet a foreign key** — `Case`
doesn't exist yet. See `docs/adr/0011-evidence-ingestion-pipeline-shape.md`
(extending the identical precedent `core/memory/db_models.py::MemoryRecordRow`
set in ADR-0010). A follow-up additive migration adds the FK constraint once
Milestone M1 builds `Case`.

**Responsibility:** System-of-record persistence only. ChromaDB (in
`core/memory/long_term.py`) is retrieval-only and never authoritative.

**Why it exists:** A multi-case, multi-evidence-type system has real relational
structure; see `docs/adr/0004-relational-database.md` for why PostgreSQL (with
SQLite as a drop-in fallback) was chosen over a flat-file or pure-vector store.

**Future expansion:** Multi-user/RBAC tables are additive to this schema, not a
rewrite of it.
