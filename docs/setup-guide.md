# Setup Guide

## Prerequisites

- Python 3.11+
- Docker + Docker Compose (for Postgres and ChromaDB)
- An API key for OpenAI or Google Gemini, **or** a local [Ollama](https://ollama.com)
  install if you want to run fully offline

## 1. Clone and configure environment

```bash
git clone <repo-url>
cd cyber-defense-copilot
cp .env.example .env
```

Edit `.env`:

- **Hosted LLM (recommended for best analysis quality):** set
  `LLM_PROVIDER=openai` and `OPENAI_API_KEY=...` (or `LLM_PROVIDER=gemini` with
  `GOOGLE_API_KEY=...`).
- **Fully offline demo:** set `LLM_PROVIDER=ollama`, run `ollama pull llama3.1`,
  leave `OLLAMA_BASE_URL` at its default.

Never commit `.env` — it's gitignored by design (`.gitignore`).

## 2. Start backing services

```bash
docker compose up -d postgres chromadb
```

This starts PostgreSQL (system of record) and ChromaDB (long-term memory).
The application itself can be run either inside Docker (`make docker-up`, full
stack) or directly on your machine against these two containers (recommended
for active development — faster reload).

## 3. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pre-commit install
```

## 4. Initialize the database

```bash
make migrate    # runs scripts/run_migrations.sh (Alembic upgrade head)
make seed       # loads data/sample_evidence as demo cases (scripts/seed_sample_data.py)
```

As of the current foundation stage (Milestone M0, see `docs/roadmap.md`), no
domain models exist yet — `make migrate` has nothing to apply and `make seed`
is an intentional documented no-op (it explains what it's waiting on rather
than failing silently). Both become meaningful once Milestone M1 adds
`core/db/models.py` and the first Alembic migration.

## 5. Run the app

```bash
make run-api    # FastAPI   → http://localhost:8000/docs
```

`GET /health`, `/ready`, and `/version` are live today and fully tested.
`make run-web` (Streamlit) will work once `apps/web/Home.py` and its pages
are implemented (Milestone M1+) — right now `apps/web` only contains
per-folder purpose documentation.

## 6. Run tests

```bash
pytest tests/unit              # fast, no external services required
pytest tests/integration        # exercises the full FastAPI app + a real (temp) database
```

Everything currently in the repository (config, logging, exceptions,
schemas, interfaces, the database session/repository foundation, and the
entire `apps/api` layer) is covered — see `tests/unit/` and
`tests/integration/` for the concrete test modules.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `LLM_PROVIDER` calls fail immediately | Missing/invalid API key in `.env`, or Ollama not running locally |
| `sqlalchemy.exc.OperationalError` on startup | Postgres container not up yet — `docker compose ps` to check health |
| ChromaDB connection refused | `chromadb` container not started, or `CHROMA_HOST`/port mismatch |
| Pre-commit hook fails on `check_dependency_rules.py` | You imported `streamlit`/`fastapi` inside `core/` — see `docs/dependency-rules.md` |

Full developer workflow (branching, testing philosophy, code review
expectations) is in `docs/developer-guide.md`.
