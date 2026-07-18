# core — The Product (Framework-Agnostic)

**Purpose:** Every piece of actual Cyber Defense Copilot logic: agents, tools,
parsers, knowledge, memory, security, persistence, reporting. Nothing in `core/`
imports Streamlit or FastAPI — this is the single discipline that keeps the
system testable headlessly and keeps the frontend swappable (see
`docs/dependency-rules.md`).

**Responsibility:** All business logic, all typed contracts (Pydantic models),
all agent/tool implementations.

**Why it exists:** Separates "the product" from "how it's currently presented,"
which is the difference between a Streamlit app and a platform with a Streamlit
frontend.

**Future expansion:** Every new module (a 10th evidence type, a new agent) is
added here first, then wired into `apps/*` — never the other way around.
