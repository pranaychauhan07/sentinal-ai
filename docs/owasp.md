# OWASP Top-10 in Cyber Defense Copilot

## What it is

The OWASP Top-10 is a community-ranked list of the ten most critical web
application security risks (SQL Injection, Broken Access Control, Security
Misconfiguration, etc.), published and periodically refreshed by the OWASP
Foundation based on real-world vulnerability data.

## Why it exists

There are thousands of possible code-level security flaws; the Top-10 exists
to focus limited review time and training budget on what actually gets
exploited most in practice. It's the de-facto standard vocabulary for
"which class of bug is this" in application security, analogous to what
MITRE ATT&CK is for attacker behavior (see `docs/mitre.md`).

## Where this project uses it

The **OWASP Security Agent** (`core/agents/owasp_agent.py`) statically
analyzes uploaded source code / API specifications
(`core/parsers/source_code_parser.py`) using AST-based detectors in
`core/tools/owasp_tools.py` — not regex string-matching, since regex misses
context (e.g. a string that merely *contains* "SELECT" is not necessarily a
SQL query). Each finding is classified against the local
`core/knowledge/owasp_top10.yaml` taxonomy with a severity and a secure-coding
recommendation.

## Practical example

```python
query = "SELECT * FROM users WHERE id=" + user_input
```

The AST detector recognizes string concatenation feeding directly into a
query construction call, flags it against **OWASP A03:2021 – Injection**,
assigns severity based on whether the input is externally reachable, and
recommends parameterized queries as the fix — mirroring blueprint §7's
worked example for this agent.

## Relationship to CVSS

OWASP Top-10 classifies *what kind* of flaw this is; CVSS (see the
Vulnerability Assessment Agent, blueprint §7) scores *how severe* a specific
instance is. A single OWASP-classified finding from source code review may
also receive an estimated CVSS score if the Vulnerability Agent is asked to
assess exploitability/impact for it.
