# sample_evidence — Realistic Demo/Test Fixtures

Small, hand-crafted (never real/sensitive) sample artifacts covering every
evidence type the Parser Layer supports: SSH auth logs, Apache access logs,
Windows security events, an Nmap XML scan, a phishing `.eml`, a Linux audit
log, and a deliberately vulnerable Flask snippet for the OWASP Security Agent.
Used by `tests/unit`, `tests/integration`, and the Streamlit "load sample case"
convenience button.
