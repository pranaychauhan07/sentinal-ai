# core/config — Application Settings

**Purpose:** The Configuration Layer (`context/01_blueprint.md` §4).
`settings.py` uses pydantic-settings to load `.env` values: LLM provider
selection (OpenAI/Gemini/Ollama), database URL, ChromaDB path, per-agent
temperature/verbosity overrides.

**Responsibility:** The *only* place `os.environ` is read anywhere in the
codebase — every other module receives config via dependency injection from
here (see `docs/engineering-standards.md`).

**Why it exists:** Centralizing config loading is what makes `.env.example`
complete and prevents "which env var does this file need" archaeology.

**Future expansion:** Per-organization config profiles when multi-tenant
support is added.
