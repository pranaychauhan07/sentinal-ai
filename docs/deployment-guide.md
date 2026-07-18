# Deployment Guide

## Current supported deployment: Docker Compose (single host)

```bash
docker compose up -d                      # postgres + chromadb + web
docker compose --profile api up -d api    # optionally also run the FastAPI service
```

This is the target deployment shape for the capstone submission and for a
personal/small-team demo: one host, three containers (`postgres`, `chromadb`,
`web`), with `api` available behind an opt-in Compose profile since nothing
consumes it yet.

## Environment configuration

All runtime configuration is env-var driven through `core/config/settings.py`
— see `.env.example` for the full list. In a deployed environment, set these
via your platform's secret manager rather than a committed `.env` file.

## Data persistence

- **PostgreSQL** (`postgres_data` volume) — system of record; back this up.
- **ChromaDB** (`chroma_data` volume) — advisory long-term memory; losing it
  degrades the Memory Agent gracefully (no historical context) rather than
  breaking the app, so it's lower backup priority than Postgres.
- **`data/reports_out/`** — generated PDFs; treat as regenerable cache unless
  you need long-term report archival, in which case mount it to persistent
  storage.

## Database migrations in production

Never run `alembic upgrade head` against a live database without a backup.
`scripts/run_migrations.sh` is the wrapper used in both dev and deploy —
review the generated migration diff before applying in any shared
environment.

## Scaling considerations (future)

The layered architecture (`docs/architecture.md`) means `apps/web` and
`apps/api` can be split into independently scaled services once there's a
reason to (e.g. the API layer gets a second, non-Streamlit consumer). Until
then, a single container serving Streamlit is sufficient and simpler — see
`docs/adr/0002-fastapi-service-boundary.md` for why the API layer exists
early anyway.

## Observability

Structured JSON logs (`logs/`, `structlog`) are the primary observability
surface today. An OpenTelemetry stub is planned for Phase 5+ per
`context/01_blueprint.md` §5 — not yet wired in.

## Out of scope for this deployment guide

Multi-tenant/SaaS deployment, Kubernetes manifests, and CDN/edge concerns are
explicitly out of scope per blueprint §3 ("Out of scope") and
`docs/roadmap.md` ("Future Expansion") — do not add infrastructure for these
without a corresponding ADR.
