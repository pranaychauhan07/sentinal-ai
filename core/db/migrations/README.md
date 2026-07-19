# migrations — Alembic Schema Migrations

Every schema change (new table, new column, new index) is captured as a
migration here, never applied by hand against a running database. `env.py` is
already wired to the project's async engine and `core.config.get_settings()`
(no second, hand-maintained `sqlalchemy.url`) — see `alembic.ini` and
`docs/adr/0004-relational-database.md`.

`20df7c637d48_create_evidence_table.py` is the first real migration —
`evidence`, with its four indexes (`case_id`, `evidence_type`, `sha256`,
`status`), scoped exactly per `docs/adr/0011-evidence-ingestion-pipeline-shape.md`.
Milestone M1's own migration adds `Case`/`Finding`/`MitreTechnique`/
`TimelineEvent`/`Report` (blueprint §8) plus the follow-up additive migration
that turns `evidence.case_id` into a real foreign key once `Case` exists.
Every table inherits the surrogate UUID `id` primary key from
`core.db.Entity` (`core/db/session.py`).
