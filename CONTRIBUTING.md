# Contributing

Thanks for looking at Cyber Defense Copilot. This document covers setup,
workflow, and expectations for contributions. Detailed engineering rules live
in `docs/engineering-standards.md` and `docs/dependency-rules.md` — read those
before your first PR touching `core/`.

## Setup

See `docs/setup-guide.md` for the full walkthrough. Quick version:

```bash
cp .env.example .env          # fill in an LLM API key or set LLM_PROVIDER=ollama
docker compose up -d postgres chromadb
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
pre-commit install
pytest tests/unit
```

## Branch Strategy

- `main` is always releasable — every commit on `main` passes CI.
- Work happens on short-lived feature branches: `feat/<short-name>`,
  `fix/<short-name>`, `docs/<short-name>`, `chore/<short-name>`.
- No direct commits to `main`; every change lands via pull request.
- Rebase (not merge) your branch on `main` before opening a PR to keep history
  linear and bisectable.

## Commit Messages

[Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`.

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`.
Scope is usually a top-level folder (`agents`, `parsers`, `db`, `web`, `api`).

```
feat(parsers): add Nessus XML parser with confidence scoring
fix(scoring): clamp risk score to 0-100 range
docs(adr): add ADR-0009 for report template versioning
```

One logical change per commit — no "wip" or "misc fixes" squash-mush. A
reviewer should be able to reconstruct intent from `git log` alone.

## Pull Requests

Use the PR template (auto-populated). A PR must:

1. Reference the milestone or issue it advances (see `docs/roadmap.md`).
2. Include tests for any new `core/parsers` or `core/tools` function
   (Definition of Done — `docs/engineering-standards.md`).
3. Pass CI: `ruff` (lint), `mypy` (types), `pytest` (unit + integration).
4. Respect the dependency rules in `docs/dependency-rules.md` — CI includes an
   automated check (`scripts/check_dependency_rules.py`) that `core/` imports
   nothing from `apps/`.
5. Update `CHANGELOG.md` under `[Unreleased]`.

## Code Review Checklist

Reviewers (and self-reviewers before requesting review) check:

- [ ] Does this belong in `core/` (framework-agnostic) or `apps/` (thin
      presentation)? Business logic in `apps/` is a blocking finding.
- [ ] Is every new agent/tool I/O a typed Pydantic model, not a dict?
- [ ] Is any deterministic calculation (score, CVSS, MITRE lookup) a tool
      function, not inline in an agent's prompt/reasoning?
- [ ] Does any code path handling phishing-email or source-code content pass
      through `core/security/prompt_guard.py` first?
- [ ] Are new dependencies added to `pyproject.toml`/`requirements.txt` with a
      one-line justification in the PR description?
- [ ] Do new parsers/tools have unit tests, and do adversarial-input paths
      have a fuzz/malformed-input test?

## Definition of Done

A task/issue is done when: the code is merged to `main`, tests pass in CI,
documentation (`docs/`) reflects the change, `docs/roadmap.md` checkbox is
updated if it closes a milestone item, and no TODOs/placeholder logic remain
in the changed files.

## Code of Conduct

Participation in this project is governed by `CODE_OF_CONDUCT.md`.
