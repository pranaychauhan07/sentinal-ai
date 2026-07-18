## Summary

<!-- What does this change do, and why? Link the milestone/issue it advances (docs/roadmap.md). -->

## Type of change

- [ ] New agent / evidence parser
- [ ] New tool (deterministic function)
- [ ] Bug fix
- [ ] Documentation / ADR
- [ ] Infrastructure / CI / deployment
- [ ] Other

## Checklist (see CONTRIBUTING.md for full detail)

- [ ] I ran `make lint`, `make typecheck`, `make test` locally and they pass
- [ ] New `core/parsers`/`core/tools` code has unit tests (including at least
      one adversarial/malformed-input case if it touches untrusted input)
- [ ] No business logic was added to `apps/web` or `apps/api` — it calls
      `core/services` only (see `docs/dependency-rules.md`)
- [ ] Any new deterministic calculation lives in `core/tools/`, not inline in
      an agent's prompt or reasoning (`docs/adr/0008-agent-tool-boundary.md`)
- [ ] Any code path handling phishing-email or source-code content passes
      through `core/security/prompt_guard.py`
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] `docs/roadmap.md` checkbox updated if this closes a milestone item
- [ ] New architecturally-significant decisions have a corresponding ADR in
      `docs/adr/`

## How was this tested?

<!-- Describe manual verification and/or point to the automated tests added. -->
