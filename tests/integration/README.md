# integration — Full Graph Runs

Exercises `core/graph/investigation_graph.py` end-to-end against sample
evidence, asserting on persisted `Finding` rows and MITRE mappings. Uses a
disposable test database (SQLite in-memory or a Dockerized Postgres via
`docker-compose.yml`'s test profile). LLM calls may be mocked or, in a
nightly CI job, run against a real cheap model to catch prompt drift.
