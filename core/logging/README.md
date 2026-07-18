# core/logging — Logging Layer

**Purpose:** Implements the Logging Layer named in `context/01_blueprint.md`
§4 (it was described architecturally there but not assigned a folder in
§6 — this fills that gap without redesigning anything).

**Responsibility:** `config.py` configures `structlog` + stdlib logging
(JSON in production, console in development/testing, always also a rotating
file handler under `settings.log_dir`) and exposes `get_logger()` /
`log_execution_time()`. `context.py` provides the request/case/agent/
correlation-ID context-variable bindings every log line automatically
inherits — see `context/03_engineering_constitution.md` §8.

**Why it exists:** The Investigation Trail UI feature and the project's
"explainability audit trail" promise (blueprint §1, §11) both depend on every
agent's reasoning being captured in a structured, filterable log — this is
where that capture is implemented.

**Future expansion:** An OpenTelemetry exporter (blueprint §5, Phase 5+)
would be added as an additional structlog processor here, not a new layer.
