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

**Implemented (Milestone M2, `docs/adr/0016-phishing-agent-email-parser-prompt-guard.md`):**
`prompt_guard.py` (`scan_text`, `PromptGuardResult`, `PromptInjectionCategory`)
— deterministic, pattern-based detection of instruction-override/role-
override/exfiltration/obfuscation injection shapes, never an ML classifier or
an LLM call itself (a guard that could be manipulated by the text it screens
would defeat its own purpose). Has no outbound dependency on any other
`core/` subpackage except `core/config` (for operator-supplied
`PROMPT_GUARD_EXTRA_PATTERNS` overrides), per dependency-rules.md rule 8.
Called by `core.agents.phishing_agent.PhishingAgent` on every email
subject/body before that text is used for anything else — the first agent in
the codebase consuming attacker-controlled text. `pii_redaction.py` and
`approval_gate.py` are not yet built.

**Honest limitation:** this is a heuristic, signature-based defense layer,
not a guarantee — a sufficiently novel injection phrasing may not match any
pattern below. It raises the cost of a naive attack and gives the analyst a
visible signal; it does not claim to be exhaustive.

**Why it exists:** Phishing emails and source code are adversarial input by
definition; an attacker can craft content designed to manipulate the analyzing
AI, not just the human victim. See `docs/threat-pipeline.md`.

**Future expansion:** Real remediation actions (e.g. calling a firewall API)
are gated here first, always.
