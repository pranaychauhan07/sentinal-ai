# core/db — Persistence (SQLAlchemy ORM)

**Purpose:** The Database Layer (`context/01_blueprint.md` §4). `models.py`
defines the relational schema (`Case`, `Evidence`, `Finding`, `MitreTechnique`,
`TimelineEvent`, `Report`, `User`) exactly as specified in the blueprint §8.
`session.py` provides the async SQLAlchemy session factory. `migrations/`
holds Alembic migrations.

**Responsibility:** System-of-record persistence only. ChromaDB (in
`core/memory/long_term.py`) is retrieval-only and never authoritative.

**Why it exists:** A multi-case, multi-evidence-type system has real relational
structure; see `docs/adr/0004-relational-database.md` for why PostgreSQL (with
SQLite as a drop-in fallback) was chosen over a flat-file or pure-vector store.

**Future expansion:** Multi-user/RBAC tables are additive to this schema, not a
rewrite of it.
