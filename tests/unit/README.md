# unit — Pure Function Tests

One test module per `core/parsers/*` and `core/tools/*` file. No database, no
LLM calls (mocked), no filesystem beyond fixture files in `data/sample_evidence`.
Fast — this tier is expected to run in seconds and gate every commit.
