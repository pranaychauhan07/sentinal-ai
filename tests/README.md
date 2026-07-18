# tests — Testing Layer

**Purpose:** pytest suite covering three tiers: `unit/` (one test module per
parser/tool — pure functions, no I/O), `integration/` (full LangGraph
investigation runs against `data/sample_evidence` fixtures), `golden/`
(snapshot tests comparing generated PDF/report content against committed
expected output, catching silent report-template regressions).

**Responsibility:** Every parser and every tool in `core/tools` ships with unit
tests before it's wired into an agent (see `docs/engineering-standards.md` —
Definition of Done). Adversarial fixtures (malformed XML, prompt-injection
attempts in a phishing body) are required for any parser/agent touching
untrusted input.

**Why it exists:** `core/` being framework-agnostic (no Streamlit/FastAPI
imports) is what makes this whole suite runnable headlessly in CI.
