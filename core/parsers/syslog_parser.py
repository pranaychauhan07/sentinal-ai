"""Generic Linux syslog parser — the blueprint §6-named `syslog_parser.py`
module, implemented generically (any RFC3164-ish process, not just `sshd`).
`SshAuthParser` is preferred (higher registry priority) whenever a line
looks specifically like an `sshd` line; this parser is the catch-all for
everything else emitted through syslog (cron, systemd, kernel, etc.).
"""

from __future__ import annotations

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import (
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
    Severity,
)
from core.parsers.syslog_common import parse_syslog_line

_SEVERITY_HINTS: tuple[tuple[str, Severity], ...] = (
    ("emerg", Severity.CRITICAL),
    ("alert", Severity.CRITICAL),
    ("crit", Severity.CRITICAL),
    ("error", Severity.HIGH),
    ("fail", Severity.HIGH),
    ("warn", Severity.MEDIUM),
)


def _infer_severity(message: str) -> Severity:
    lowered = message.lower()
    for hint, severity in _SEVERITY_HINTS:
        if hint in lowered:
            return severity
    return Severity.INFO


class SyslogParser(BaseParser):
    name = "syslog"
    description = "Parses generic RFC3164-style Linux syslog lines."
    evidence_type = EvidenceType.SYSLOG
    supported_extensions = (".log", ".txt")
    supported_mime_types = ("text/plain",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        sample = [line for line in decoded_text.splitlines()[:20] if line.strip()]
        if not sample:
            return 0.0
        matches = sum(1 for line in sample if parse_syslog_line(line) is not None)
        return matches / len(sample)

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        self.raise_if_invalid(bool(decoded_text.strip()), "Syslog content is empty.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for line_number, raw_line in enumerate(decoded_text.splitlines(), start=1):
            if not raw_line.strip():
                continue
            header = parse_syslog_line(raw_line)
            if header is None:
                unparsed.append(raw_line)
                continue
            records.append(
                EvidenceRecord(
                    line_number=line_number,
                    timestamp=header.timestamp,
                    host=header.host,
                    event_type=header.process,
                    severity=_infer_severity(header.message),
                    raw_line=raw_line,
                    normalized_fields={"pid": header.pid, "message": header.message},
                )
            )

        confidence = 1.0 if records and not unparsed else (0.6 if records else 0.0)
        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=confidence,
            records=records,
            metadata={"total_lines": len(decoded_text.splitlines())},
            unparsed_fragments=unparsed,
            chain_of_custody=self._chain_of_custody(raw),
        )
