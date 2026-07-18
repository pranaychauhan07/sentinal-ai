# Cyber Defense Copilot

> An AI-native, case-centric SOC analyst workbench. Multiple specialized AI
> agents — coordinated the way a real SOC shift is coordinated — investigate
> logs, phishing emails, vulnerability scans, source code, and Linux
> configurations, then produce executive-ready incident response reports.

[![CI](https://img.shields.io/badge/CI-pending--first--build-lightgrey)](.github/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![Status: Foundation](https://img.shields.io/badge/status-foundation--stage-orange)](docs/roadmap.md)

## Why this project exists

Real SOC investigations don't happen one upload at a time — they accumulate
evidence (a log, an email, a scan report) into a single case over hours or
days. Cyber Defense Copilot is built around a **`Case`** as its central object
from day one, so a firewall log, a phishing email, and an Nmap scan can all
belong to one investigation and get correlated by a coordinated team of AI
agents, instead of living as nine disconnected demo tools.

Full rationale, architecture, and design reasoning: **[`context/01_blueprint.md`](context/01_blueprint.md)**.

## What it does

| Module (per capstone spec) | Owning Agent |
|---|---|
| Threat Detection | SOC Analyst Agent + Threat Hunting Agent |
| Phishing Detection | Phishing Investigation Agent |
| Log Analyzer | SOC Analyst Agent |
| Vulnerability Analyzer | Vulnerability Assessment Agent |
| Nmap Report Reader | Vulnerability Assessment Agent (`core/parsers/nmap_parser.py`) |
| Incident Response Assistant | Incident Response Agent |
| Security Report Generator | Report Generator Agent |
| OWASP Security Review | OWASP Security Agent |
| Linux Security Guidance | Linux Security Agent |

Cross-cutting: ReAct reasoning (every agent), function/tool calling
(`core/tools/`), multi-agent orchestration (`core/graph/`, LangGraph), shared
short/long-term memory (`core/memory/`).

## Architecture at a glance

```
User → Streamlit/FastAPI → Coordinator Agent → Specialist Agents (ReAct)
     → MITRE Mapping → Incident Response Synthesis → Executive PDF Report
     → Long-Term Memory (ChromaDB) → next case starts smarter
```

Full layered architecture diagram, data flow, and agent-by-agent design:
see [`docs/architecture.md`](docs/architecture.md) and
[`docs/agent-design.md`](docs/agent-design.md).

## Repository layout

```
apps/       Frontend (Streamlit) + API boundary (FastAPI) — presentation only
core/       The product: agents, tools, parsers, knowledge, memory, security,
            db, reporting, config, services — framework-agnostic
data/       Sample evidence fixtures + generated report output
tests/      unit / integration / golden (report-snapshot) test tiers
docs/       Architecture, ADRs, agent design, setup/dev/deploy/user guides
scripts/    Dev & ops utilities (seed data, migrations, dependency check)
examples/   Fully worked example investigations
context/    Source-of-truth engineering blueprint this repo implements
```

Every folder contains its own `README.md` explaining purpose, responsibility,
and future expansion — start there when navigating.

## Quickstart

```bash
git clone <repo-url> && cd cyber-defense-copilot
cp .env.example .env                 # add an LLM API key, or set LLM_PROVIDER=ollama
docker compose up -d postgres chromadb
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
make run-api                         # → http://localhost:8000/docs (health/ready/version live today)
```

`make run-web` (Streamlit) and `make migrate`/`make seed` become meaningful
once domain models and agents land in Milestone M1 — right now `apps/web`
and `core/db` migrations are scaffolding only. Full walkthrough (including
the Ollama offline path): [`docs/setup-guide.md`](docs/setup-guide.md).

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — layered system design
- [`docs/agent-design.md`](docs/agent-design.md) — every agent's contract
- [`docs/adr/`](docs/adr/) — Architecture Decision Records
- [`docs/threat-pipeline.md`](docs/threat-pipeline.md) — evidence → report data flow
- [`docs/mitre.md`](docs/mitre.md) / [`docs/owasp.md`](docs/owasp.md) — knowledge-base concepts
- [`docs/setup-guide.md`](docs/setup-guide.md) · [`docs/developer-guide.md`](docs/developer-guide.md) · [`docs/deployment-guide.md`](docs/deployment-guide.md) · [`docs/user-guide.md`](docs/user-guide.md)
- [`docs/engineering-standards.md`](docs/engineering-standards.md) · [`docs/dependency-rules.md`](docs/dependency-rules.md)
- [`docs/roadmap.md`](docs/roadmap.md) — milestone plan (M0 → M7)

## Project status

**Foundation stage (M0) — complete.** Repository scaffolding, engineering
standards, ADRs, sample data, CI/governance, and the full backend engineering
foundation (configuration, structured logging, shared exception/schema/
interface contracts, async database layer, and a fully working FastAPI
application with `/health`, `/ready`, `/version`) are in place and tested.

**Multi-Agent Framework — implemented ahead of schedule** (normally M3;
see `docs/adr/0009-multi-agent-framework-shape.md`). The reusable
agent/tool/workflow infrastructure — `BaseAgent`, `BaseTool`,
`AgentRegistry`/`ToolRegistry`, `CoordinatorAgent`/`PlanningAgent`, a real
compiled LangGraph `StateGraph` (`WorkflowEngine`) with retry, failure
recovery, event publication, and metrics — is implemented and tested, with
zero cybersecurity domain logic and no concrete specialist agent yet.

158 tests total, mypy/ruff/dependency-rules all clean. No domain models
(`Case`/`Evidence`/`Finding`) or any concrete specialist agent (SOC Analyst,
Phishing, ...) exist yet — that's Milestone M1, next. Screenshots/GIFs and
rendered architecture diagrams will be added to `assets/` and
`docs/diagrams/` as the Investigation Workspace becomes demoable
(Milestone M6). See `docs/roadmap.md` for the full milestone plan.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, branch/commit conventions,
and the PR checklist. Governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
Security issues: see [`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE)
