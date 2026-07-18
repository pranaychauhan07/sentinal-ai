# scripts — Developer & Operations Utilities

**Purpose:** Small, standalone scripts that support development but are not
part of the shipped application: `seed_sample_data.py` (loads
`data/sample_evidence` into a fresh dev database as demo cases),
`run_migrations.sh` (Alembic upgrade wrapper), `generate_diagrams.sh` (Mermaid
CLI batch render for `docs/diagrams/`), `check_dependency_rules.py` (static
check that `core/` contains no Streamlit/FastAPI imports, enforced in CI).

**Why it exists:** Keeps one-off operational tasks out of `core/` and out of
ad-hoc shell history, and makes onboarding ("how do I get sample data?")
a documented, runnable script rather than tribal knowledge.

**Future expansion:** A CLI entrypoint (`cdc-cli`) could eventually wrap these
scripts as subcommands, reusing `core/services` exactly like the Streamlit and
FastAPI frontends do.
