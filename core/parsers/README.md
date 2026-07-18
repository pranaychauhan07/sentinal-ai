# core/parsers — Format-Specific Evidence Extractors

**Purpose:** The Parser Layer (`context/01_blueprint.md` §4). Converts raw
uploaded artifacts (.eml, syslog/firewall text, Nmap XML, Nessus/OpenVAS
reports, source code, incident notes) into normalized, typed
`NormalizedEvidence` Pydantic models.

**Responsibility:** One parser per format (`email_parser.py`, `syslog_parser.py`,
`nmap_parser.py`, `nessus_parser.py`, `openvas_parser.py`,
`source_code_parser.py`, `incident_parser.py`). Every parser reports a
confidence score and an explicit `unparsed_fragments` list rather than silently
dropping data.

**Why it exists:** Deterministic parsing is faster, cheaper, and more reliable
than asking an LLM to extract structure every time; the Parser Agent
(`core/agents/parser_agent.py`) only falls back to LLM extraction when no
parser matches.

**Future expansion:** New evidence formats (EDR alert exports, Sigma rule
matches) get a new parser module here first.
