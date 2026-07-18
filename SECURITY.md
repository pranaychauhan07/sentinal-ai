# Security Policy

Cyber Defense Copilot is a security-adjacent project. We take its own security
seriously, in addition to being a tool that teaches security concepts.

## Supported Versions

Until the first `v1.0` tag, only the `main` branch receives security fixes.
After `v1.0`, the latest minor release line will be supported per the
versioning strategy in `docs/roadmap.md`.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.
Instead, use GitHub's private vulnerability reporting
(Security tab → "Report a vulnerability") or contact the maintainers directly.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal evidence file or prompt that triggers it)
- Whether it involves prompt injection / jailbreak evasion, a parser crash on
  malformed input, a dependency CVE, or a data-handling issue

We aim to acknowledge reports within 5 business days.

## Project-Specific Threat Classes

Because this project ingests untrusted, potentially adversarial content
(phishing emails, uploaded source code, log files) and feeds portions of it to
an LLM, the following classes of report are explicitly in scope and high
priority:

- **Prompt injection / jailbreak bypass** of `core/security/prompt_guard.py`
- **Parser crashes or resource exhaustion** on malformed/oversized evidence
  (`core/parsers/*`)
- **Secrets leakage** via logs (`logs/`), reports (`data/reports_out/`), or
  error messages
- **Approval-gate bypass** — any path where an agent's recommended action
  could be marked "executed" without passing `core/security/approval_gate.py`

## Out of Scope

- Vulnerabilities in sample/demo data under `data/sample_evidence/`
  (intentionally includes a vulnerable code snippet for the OWASP module —
  see `data/sample_evidence/vulnerable_app/README.md`)
- Denial-of-service via LLM provider rate limits (a provider-side concern)
