"""SSH authentication log parser — `sshd` syslog lines (Failed/Accepted
password, Accepted publickey, PAM session open/close, disconnects). One of
the task's nine "INITIAL PARSERS."
"""

from __future__ import annotations

import re

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import (
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
    Severity,
)
from core.parsers.syslog_common import SyslogHeader, parse_syslog_line

_FAILED_RE = re.compile(
    r"^Failed (password|publickey|none) for (invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED_RE = re.compile(
    r"^Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_DISCONNECT_RE = re.compile(r"^Received disconnect from (?P<ip>\S+) port (?P<port>\d+)")
_SESSION_OPENED_RE = re.compile(r"session opened for user (?P<user>\S+)")

_SSHD_HINT_RE = re.compile(r"sshd(\[\d+\])?:")


class SshAuthParser(BaseParser):
    name = "ssh_auth"
    description = "Parses SSH daemon (sshd) authentication log lines."
    evidence_type = EvidenceType.SSH_AUTH
    supported_extensions = (".log", ".txt")
    supported_mime_types = ("text/plain",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        sample = decoded_text.splitlines()[:20]
        hits = sum(1 for line in sample if _SSHD_HINT_RE.search(line))
        return min(1.0, hits / max(1, len(sample)) * 2) if hits else 0.0

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        self.raise_if_invalid(bool(decoded_text.strip()), "SSH auth log is empty.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for line_number, raw_line in enumerate(decoded_text.splitlines(), start=1):
            if not raw_line.strip():
                continue
            header = parse_syslog_line(raw_line)
            if header is None or "sshd" not in header.process:
                unparsed.append(raw_line)
                continue

            record = self._classify(header.message, line_number, raw_line, header)
            records.append(record)

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

    def _classify(
        self, message: str, line_number: int, raw_line: str, header: SyslogHeader
    ) -> EvidenceRecord:
        host = header.host
        timestamp = header.timestamp

        failed = _FAILED_RE.match(message)
        if failed:
            return EvidenceRecord(
                line_number=line_number,
                timestamp=timestamp,
                host=host,
                user=failed["user"],
                ip_address=failed["ip"],
                event_type="auth_failure",
                severity=Severity.MEDIUM,
                raw_line=raw_line,
                normalized_fields={"port": failed["port"]},
            )

        accepted = _ACCEPTED_RE.match(message)
        if accepted:
            return EvidenceRecord(
                line_number=line_number,
                timestamp=timestamp,
                host=host,
                user=accepted["user"],
                ip_address=accepted["ip"],
                event_type="auth_success",
                severity=Severity.INFO,
                raw_line=raw_line,
                normalized_fields={"port": accepted["port"]},
            )

        disconnect = _DISCONNECT_RE.match(message)
        if disconnect:
            return EvidenceRecord(
                line_number=line_number,
                timestamp=timestamp,
                host=host,
                ip_address=disconnect["ip"],
                event_type="disconnect",
                severity=Severity.INFO,
                raw_line=raw_line,
                normalized_fields={"port": disconnect["port"]},
            )

        session_opened = _SESSION_OPENED_RE.search(message)
        if session_opened:
            return EvidenceRecord(
                line_number=line_number,
                timestamp=timestamp,
                host=host,
                user=session_opened["user"],
                event_type="session_opened",
                severity=Severity.INFO,
                raw_line=raw_line,
            )

        return EvidenceRecord(
            line_number=line_number,
            timestamp=timestamp,
            host=host,
            event_type="sshd_other",
            severity=Severity.INFO,
            raw_line=raw_line,
        )
