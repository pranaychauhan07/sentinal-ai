# templates — Jinja2 Report Templates

One template per module (`soc_report.html.j2`, `phishing_report.html.j2`,
`vulnerability_report.html.j2`, `owasp_report.html.j2`,
`incident_response_report.html.j2`) plus `executive_summary.html.j2` for the
case-level rollup. Templates consume the typed Pydantic finding models
directly — no ad-hoc dict access.
