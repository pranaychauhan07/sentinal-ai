# vulnerable_app — OWASP Demo Fixture

**Intentionally vulnerable** sample Flask application used exclusively as
static-analysis input for the OWASP Security Agent (`core/agents/owasp_agent.py`)
and its AST-based detectors (`core/tools/owasp_tools.py`). This code is never
executed by the test suite or the application — it is parsed as text/AST only.

Contains deliberate instances of, mapped to OWASP Top-10 (2021):

| File | Vulnerability | OWASP Category |
|---|---|---|
| `app.py` | String-concatenated SQL query | A03:2021 – Injection |
| `app.py` | Unescaped user input rendered as HTML | A03:2021 – Injection (XSS) |
| `app.py` | Hardcoded credentials / weak session secret | A07:2021 – Identification and Authentication Failures |
| `app.py` | Debug mode enabled in what reads as a production entrypoint | A05:2021 – Security Misconfiguration |

See `docs/owasp.md` for how these map to agent findings. **Do not deploy or
run this file outside of static-analysis fixtures.**
