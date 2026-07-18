# core/memory — Shared Memory (Short-Term + Long-Term)

**Purpose:** The Memory Layer (`context/01_blueprint.md` §4). `short_term.py`
is the per-case scratchpad (effectively the LangGraph state itself, exposed
here for agent convenience). `long_term.py` wraps ChromaDB for cross-case
retrieval — "has this IOC/pattern appeared before?"

**Responsibility:** Long-term memory is always advisory: a Chroma outage
degrades to "no historical context," never blocks an investigation (see
`docs/adr/0006-memory-strategy.md`).

**Implemented:** `interfaces.py` (`ShortTermMemory`/`CaseMemory`/
`LongTermMemory`/`VectorMemory` `Protocol`s) — abstraction only, per the
Multi-Agent Framework milestone's explicit scope
(`docs/adr/0009-multi-agent-framework-shape.md`). `short_term.py` and
`long_term.py` (the concrete implementations these Protocols describe) do
not exist yet — Milestone M6.

**Why it exists:** This is what makes the Copilot smarter the longer it's used,
per the PDF's explicit Project 9 requirement — and what lets the Memory Agent
do its job.

**Future expansion:** Multi-tenant memory partitioning if/when multi-org support
is added.
