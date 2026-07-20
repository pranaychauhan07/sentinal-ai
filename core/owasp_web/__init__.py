"""OWASP Web Security Agent framework — a deterministic analyzer of HTTP
traffic artifacts (requests/responses, security headers, cookies, JWT
metadata, web server logs, API responses) mapped to the OWASP Top 10 (2021)
taxonomy. See `docs/adr/0020-owasp-web-security-agent.md` and
`core/owasp_web/README.md`.

**Not** blueprint §7's OWASP Security Agent (AST-based source-code/API
static review — SQLi/XSS/broken-auth pattern detection over parsed source
code, still unbuilt). This package never parses source code, never builds an
AST, and never performs active scanning, penetration testing, incident
response, threat hunting, MITRE mapping, or LLM reasoning of any kind.
"""

from __future__ import annotations
