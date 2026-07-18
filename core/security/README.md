# core/security — Guardrails and Human-in-the-Loop

**Purpose:** The Security Layer (`context/01_blueprint.md` §4). `prompt_guard.py`
screens any attacker-or-third-party-authored text (phishing email bodies,
uploaded source code) for prompt-injection/jailbreak patterns before it reaches
an LLM prompt. `pii_redaction.py` strips obvious PII before logging/embedding.
`approval_gate.py` is the human-in-the-loop checkpoint every *action*-
recommending agent output must pass before it can be marked "executed."

**Responsibility:** Cross-cutting defense — not a standalone feature, wired into
every agent that consumes untrusted text (from Milestone M2 onward, per
`docs/roadmap.md`).

**Why it exists:** Phishing emails and source code are adversarial input by
definition; an attacker can craft content designed to manipulate the analyzing
AI, not just the human victim. See `docs/threat-pipeline.md`.

**Future expansion:** Real remediation actions (e.g. calling a firewall API)
are gated here first, always.
