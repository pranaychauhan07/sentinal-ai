"""Apache HTTP Server error-log parser — supports both the modern
(`[module:level]`) and classic (`[level]`) log formats."""

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

_ERROR_LINE_RE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\] "
    r"\[(?:(?P<module>[\w.]+):)?(?P<level>\w+)\]"
    r"(?: \[pid (?P<pid>\d+)(?::tid \d+)?\])?"
    r"(?: \[client (?P<client>[^\]]+)\])? "
    r"(?P<message>.*)$"
)

_TIMESTAMP_FORMATS = ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y")

_LEVEL_SEVERITY: dict[str, Severity] = {
    "emerg": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warn": Severity.MEDIUM,
    "notice": Severity.INFO,
    "info": Severity.INFO,
    "debug": Severity.INFO,
}


def _parse_timestamp(raw_timestamp: str) -> datetime | None:
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw_timestamp, fmt)
        except ValueError:
            continue
    return None


class ApacheErrorParser(BaseParser):
    name = "apache_error"
    description = "Parses Apache HTTP Server error log lines."
    evidence_type = EvidenceType.APACHE_ERROR
    supported_extensions = (".log", ".txt")
    supported_mime_types = ("text/plain",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        sample = [line for line in decoded_text.splitlines()[:20] if line.strip()]
        if not sample:
            return 0.0
        matches = sum(1 for line in sample if _ERROR_LINE_RE.match(line))
        return matches / len(sample)

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        self.raise_if_invalid(bool(decoded_text.strip()), "Apache error log is empty.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for line_number, raw_line in enumerate(decoded_text.splitlines(), start=1):
            if not raw_line.strip():
                continue
            match = _ERROR_LINE_RE.match(raw_line)
            if match is None:
                unparsed.append(raw_line)
                continue

            level = match["level"].lower()
            client = match["client"]
            ip_address = client.rsplit(":", maxsplit=1)[0] if client else None

            records.append(
                EvidenceRecord(
                    line_number=line_number,
                    timestamp=_parse_timestamp(match["timestamp"]),
                    ip_address=ip_address,
                    event_type=f"apache_{level}",
                    severity=_LEVEL_SEVERITY.get(level, Severity.INFO),
                    raw_line=raw_line,
                    normalized_fields={
                        "module": match["module"],
                        "level": level,
                        "pid": match["pid"],
                        "message": match["message"],
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
