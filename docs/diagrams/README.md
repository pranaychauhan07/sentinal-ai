# diagrams — Mermaid Sources + Rendered Images

Mermaid `.mmd` source files for the layered architecture diagram (blueprint
§4) and the data-flow diagram (§9), plus their rendered `.png` exports embedded
in the root `README.md`. Regenerate PNGs with the Mermaid CLI
(`mmdc -i diagram.mmd -o diagram.png`) whenever the `.mmd` source changes.

- `multi-agent-framework.mmd` — agent communication/execution/state flow
  (`docs/adr/0009-multi-agent-framework-shape.md`).
- `evidence-ingestion-pipeline.mmd` — the Evidence Ingestion & Parser
  Framework's ten-stage pipeline, upload through memory notification
  (`docs/adr/0011-evidence-ingestion-pipeline-shape.md`).
- `parser-lifecycle.mmd` — one `BaseParser` subclass's lifecycle: selection,
  decoding, validation, and the degrade-not-crash contract every parser
  follows (constitution §1.7).
