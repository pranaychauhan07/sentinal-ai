# routers — FastAPI Route Modules

One router module per resource (`cases.py`, `evidence.py`, `reports.py`,
`agents.py`). Each router only validates input, calls a `core/services` function,
and serializes the typed result — mirrors the Streamlit pages' discipline.
