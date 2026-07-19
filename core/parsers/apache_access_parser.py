"""Apache/NCSA Combined Log Format access-log parser."""

from __future__ import annotations

import re
from datetime import datetime

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import (
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
    Severity,
)

_COMBINED_RE = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
    r'( "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _severity_for_status(status: int) -> Severity:
    if status >= 500:
        return Severity.HIGH
    if status in (401, 403):
        return Severity.MEDIUM
    if status == 404:
        return Severity.LOW
    return Severity.INFO


class ApacheAccessParser(BaseParser):
    name = "apache_access"
    description = "Parses Apache/NCSA Combined Log Format access log lines."
    evidence_type = EvidenceType.APACHE_ACCESS
    supported_extensions = (".log", ".txt")
    supported_mime_types = ("text/plain",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        sample = [line for line in decoded_text.splitlines()[:20] if line.strip()]
        if not sample:
            return 0.0
        matches = sum(1 for line in sample if _COMBINED_RE.match(line))
        return matches / len(sample)

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        self.raise_if_invalid(bool(decoded_text.strip()), "Apache access log is empty.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for line_number, raw_line in enumerate(decoded_text.splitlines(), start=1):
            if not raw_line.strip():
                continue
            match = _COMBINED_RE.match(raw_line)
            if match is None:
                unparsed.append(raw_line)
                continue

            status = int(match["status"])
            try:
                timestamp = datetime.strptime(match["timestamp"], _TIMESTAMP_FORMAT)
            except ValueError:
                timestamp = None

            records.append(
                EvidenceRecord(
                    line_number=line_number,
                    timestamp=timestamp,
                    ip_address=match["ip"],
                    user=match["user"] if match["user"] != "-" else None,
                    event_type=f"http_{match['method'].lower()}",
                    severity=_severity_for_status(status),
                    raw_line=raw_line,
                    normalized_fields={
                        "method": match["method"],
                        "path": match["path"],
                        "protocol": match["protocol"],
                        "status": status,
                        "size": match["size"],
                        "referer": match["referer"],
                        "user_agent": match["user_agent"],
                    },
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
