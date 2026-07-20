"""Linux Security Advisor Framework — blueprint §7's Linux Security Agent
(command/permission advisor). See `docs/adr/0019-linux-security-advisor-agent.md`
and `core/linux_advisor/README.md`.

**Not** `core/linux_security/` (ADR-0018's Linux Security *Threat Hunting*
Framework — SSH-auth/syslog-based detection). This package performs pure,
in-memory static text analysis of raw command strings and `ls -l`-style
permission listings; it never parses logs, correlates events across time, or
persists findings.
"""

from __future__ import annotations
