"""OWASP Security Agent framework — blueprint §7's source-code/API static
reviewer: deterministic, AST-based (Python) / pattern-based (JavaScript,
TypeScript, Java) Static Application Security Testing (SAST), mapping
findings to the OWASP Top 10 (2021) taxonomy and CWE ids. See
`docs/adr/0021-owasp-security-agent-ast-sast.md` and
`core/owasp_security/README.md`.

**Not** `core/owasp_web/` (ADR-0020's Web Security Agent — HTTP traffic/
header/cookie/JWT analysis, no source code, no AST). This package never
analyzes HTTP requests/responses and never imports `core.owasp_web`. It
also never executes, `eval`s, or runs any analyzed source code, and never
performs penetration testing, active scanning, incident response, threat
hunting, MITRE mapping, or LLM reasoning of any kind.
"""

from __future__ import annotations
