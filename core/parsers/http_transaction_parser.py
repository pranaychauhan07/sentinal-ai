"""``HttpTransactionParser`` — evidence intake for the Web Security Agent
(`docs/adr/0020-owasp-web-security-agent.md`).

Deliberately dumb/generic, matching every other parser in this package:
produces exactly one `EvidenceRecord` per non-blank input line
(`event_type="http_transaction_line"`, `raw_line=<the line>`). It does **not**
classify a line as a header vs. a `Set-Cookie` line vs. a JWT-bearing line vs.
a generic log/body line — that deeper semantic classification is
`core.owasp_web.advisory_engine.WebSecurityAdvisoryEngine`'s job, the same
"parsers extract structure only where unambiguous" precedent already applied
identically in `linux_command_parser.py` for the Linux Security Advisor
Framework (`docs/adr/0019`) — a *different* package this parser must never be
confused with.

`sniff()` gives this parser a real, above-`PlainTextParser` (0.1) confidence
when it recognizes one of four shapes: an HTTP request line, an HTTP status
line, a `Set-Cookie` header, or an `Authorization:`/security-header line —
registered in `core.parsers.registry` at priority 3 (heuristic, not a fully
structured format like Nessus XML).
"""

from __future__ import annotations

import re

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence, Severity

#: An HTTP request line, e.g. `GET /path HTTP/1.1`.
_REQUEST_LINE_PREFIX = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/\d(?:\.\d)?",
    re.IGNORECASE,
)

#: An HTTP status line, e.g. `HTTP/1.1 200 OK`.
_STATUS_LINE_PREFIX = re.compile(r"^HTTP/\d(?:\.\d)?\s+\d{3}\b", re.IGNORECASE)

#: A `Set-Cookie` header line.
_SET_COOKIE_PREFIX = re.compile(r"^set-cookie\s*:", re.IGNORECASE)

#: Security-relevant header names this parser recognizes as a signal that a
#: line is worth the advisor's attention — not an exhaustive allowlist of
#: every header the advisor can analyze; `advisory_engine.py` handles any
#: `Name: Value` line. This is only a `sniff()` confidence signal.
_SECURITY_RELEVANT_HEADER_PREFIX = re.compile(
    r"^(?:authorization|content-security-policy|strict-transport-security|"
    r"x-frame-options|x-content-type-options|referrer-policy|"
    r"permissions-policy|server|x-powered-by)\s*:",
    re.IGNORECASE,
)

#: Confidence returned when a line matches one of the four recognized
#: shapes — above `PlainTextParser`'s 0.1, low enough that a fully structured
#: parser always wins a tie-break.
_SNIFF_CONFIDENCE_MATCH = 0.4
_SNIFF_CONFIDENCE_NONE = 0.0


def _looks_like_http_transaction(line: str) -> bool:
    return bool(
        _REQUEST_LINE_PREFIX.match(line)
        or _STATUS_LINE_PREFIX.match(line)
        or _SET_COOKIE_PREFIX.match(line)
        or _SECURITY_RELEVANT_HEADER_PREFIX.match(line)
    )


class HttpTransactionParser(BaseParser):
    name = "http_transaction"
    description = (
        "Parser for raw HTTP request/response transcripts (request/status "
        "lines, headers, Set-Cookie lines, Authorization headers) — one "
        "EvidenceRecord per non-blank line, no deep classification (that is "
        "the Web Security Agent's job)."
    )
    evidence_type = EvidenceType.HTTP_TRANSACTION
    #: `.txt` is intentionally also claimed here (shared with
    #: `PlainTextParser`/`LinuxCommandInputParser`) so that a `.txt` upload
    #: containing recognizable HTTP-transaction content is routed here via
    #: `sniff()` rather than always falling to the plain-text fallback — see
    #: `core.parsers.factory._best_sniff_match`.
    supported_extensions = (".http", ".har", ".txt")
    supported_mime_types = ("message/http",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        for line in decoded_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if _looks_like_http_transaction(stripped):
                return _SNIFF_CONFIDENCE_MATCH
        return _SNIFF_CONFIDENCE_NONE

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        self.raise_if_invalid(bool(decoded_text.strip()), "HTTP transaction input is empty.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        records: list[EvidenceRecord] = []
        for line_number, raw_line in enumerate(decoded_text.splitlines(), start=1):
            if not raw_line.strip():
                continue
            records.append(
                EvidenceRecord(
                    line_number=line_number,
                    event_type="http_transaction_line",
                    severity=Severity.INFO,
                    raw_line=raw_line,
                    normalized_fields={},
                )
            )
        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=0.6 if records else 0.1,
            records=records,
            metadata={"line_count": len(records)},
            unparsed_fragments=[],
            chain_of_custody=self._chain_of_custody(raw),
        )
