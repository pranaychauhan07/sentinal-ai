# ADR-0002: FastAPI Service Boundary (Built Early, Alongside Streamlit)

**Status:** Accepted
**Date:** 2026-07-18

## Purpose

The PDF requires a Streamlit dashboard. Streamlit alone is enough to ship the
capstone, but a Streamlit-only codebase invites business logic to leak
directly into page files, which would make any future frontend change (or a
second consumer, like a CLI or a real integration) require a rewrite rather
than a swap.

## Decision

Scaffold `apps/api` (FastAPI) from Milestone M0 onward, even though nothing
calls it over the network yet. Both `apps/web` and `apps/api` are required to
call the same `core/services/*` functions — never duplicate logic between
them. See `core/services/README.md` and `docs/dependency-rules.md` rule 2–3.

## Alternatives Considered

- **Streamlit only, add FastAPI later "if needed"** — cheaper up front, but
  in practice the discipline of "no business logic in pages" erodes without
  a second consumer proving the services layer is real; retrofitting an API
  after business logic has leaked into Streamlit pages is a rewrite, not an
  addition.
- **Django or Flask instead of FastAPI** — FastAPI's native Pydantic
  integration matches the typed-contract discipline used everywhere else in
  `core/` (agents, tools, parsers all use Pydantic models); Django's ORM-
  centric design would compete with SQLAlchemy rather than complement it.

## Consequences

- **Positive:** the "Streamlit pages never contain business logic" rule has
  a concrete, testable proof point (the API router calling the identical
  service function); OpenAPI docs are free; a future React frontend is a
  swap, not a rewrite.
- **Negative:** slightly more scaffolding maintained from day one for a
  consumer that doesn't exist yet — mitigated by keeping `apps/api` genuinely
  thin (routers only, no logic) so its maintenance cost stays near zero
  until it's actually used.
