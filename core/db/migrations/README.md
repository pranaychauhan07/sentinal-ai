# migrations — Alembic Schema Migrations

Every schema change (new table, new column, new index) is captured as a
migration here, never applied by hand against a running database. `env.py` is
already wired to the project's async engine and `core.config.get_settings()`
(no second, hand-maintained `sqlalchemy.url`) — see `alembic.ini` and
`docs/adr/0004-relational-database.md`. The first migration
(`0001_initial_schema`) creates the tables described in `core/db/README.md` /
blueprint §8, each inheriting the surrogate UUID `id` primary key from
`core.db.Entity` (`core/db/session.py`), and is expected in Milestone M1.
