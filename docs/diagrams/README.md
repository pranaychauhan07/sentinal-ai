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
- `threat-intel-pipeline.mmd` — the Threat Intelligence & IOC Extraction
  Framework's nine-stage pipeline, discovery through memory notification
  (`docs/adr/0012-threat-intelligence-ioc-extraction-framework-shape.md`).
- `ioc-lifecycle.mmd` — one candidate `IOCRecord`'s lifecycle: discovery,
  validation, normalization, deduplication, rule evaluation, scoring,
  classification, attribution, and persistence, including the
  never-silently-drop-a-rejection contract (constitution §1.7).
- `finding-mitre-mapping-pipeline.mmd` — the Finding & MITRE ATT&CK
  Intelligence Engine's Finding Generation Pipeline: MITRE mapping, evidence
  aggregation, confidence/severity/priority assignment, deduplication,
  persistence, and event publication
  (`docs/adr/0013-finding-mitre-intelligence-engine-shape.md`).
- `finding-lifecycle.mmd` — one candidate `FindingRecord`'s lifecycle:
  mapping, aggregation, scoring, deduplication, and the open/merged/closed
  state machine, including the never-a-forced-low-confidence-guess and
  never-drop-evidence-on-merge contracts (constitution §1.7).
