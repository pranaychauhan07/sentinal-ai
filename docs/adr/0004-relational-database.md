# ADR-0004: PostgreSQL as System of Record (SQLite as Fallback)

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

A multi-case, multi-evidence-type investigation platform has real relational
structure (`Case` 1–to–many `Evidence`/`Finding`/`TimelineEvent`, `Finding`
many-to-one `MitreTechnique`). We needed to decide the persistence technology
before writing `core/db/models.py`, since it shapes the entire Database
Layer.

## Decision

PostgreSQL via SQLAlchemy 2.0 (async) is the system of record, run via Docker
Compose in every normal dev/deploy path. SQLite (via `aiosqlite`) is an
explicitly supported fallback behind the *same* SQLAlchemy layer, for
environments where Docker/Postgres genuinely cannot run (e.g. a constrained
grading environment) — selected purely via the `DATABASE_URL` env var, no
code changes required. See `context/01_blueprint.md` §4, `.env.example`.

## Alternatives Considered

- **SQLite only, always** — simplest to set up, and the capstone's own
  Project 9 diagram gestures at "SQLite/FAISS." Rejected as the *primary*
  choice because it doesn't reflect the real relational complexity
  (concurrent writes across multiple agents updating findings on the same
  case) and would force a migration later if the project grows past a
  single-analyst demo.
- **A document store (MongoDB) matching each `Finding`'s variable shape** —
  findings do vary by module, but the *relationships* (case → evidence →
  finding → timeline, finding → MITRE technique) are exactly what relational
  foreign keys model well; a document store would push that relational
  integrity into application code instead of the database.
- **Storing everything in ChromaDB alongside embeddings** — conflates the
  system of record with the advisory retrieval layer; a Chroma outage should
  degrade the Memory Agent, not the entire application (see
  `docs/adr/0006-memory-strategy.md`) — this requires them to be separate
  stores.

## Consequences

- **Positive:** real relational integrity (foreign keys, cascade rules) for
  a genuinely relational domain; Alembic migrations give a reviewable schema
  history; the SQLite fallback means the project never becomes undemoable
  just because Docker isn't available.
- **Negative:** two DB dialects to keep compatible (Postgres-specific SQL
  features must be avoided or guarded) — mitigated by staying within
  SQLAlchemy Core's portable feature set and testing the SQLite path in CI
  alongside the Postgres path.
