"""Windows Event Log parser — an **EVTX abstraction**, not binary EVTX
parsing (explicitly permitted by scope: "EVTX abstraction if full parsing is
deferred"). Accepts a CSV export of Windows Security events (e.g. produced
by `Get-WinEvent | Export-Csv` or an EVTX-to-CSV conversion step) with the
header `EventID,TimeCreated,Computer,Account,SourceIP,LogonType,Message` —
exactly the shape of `data/sample_evidence/windows_security_events.csv`.

Binary `.evtx` parsing (via a library such as `python-evtx`) is a documented
future extension, not implemented here — see `core/parsers/README.md`.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import (
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
    Severity,
)

REQUIRED_HEADER_FIELDS = {"eventid", "timecreated"}

#: Well-known Windows Security event IDs this parser recognizes, mapped to
#: an `(event_type, severity)` pair. Anything else falls back to a generic,
#: low-severity `windows_event_<id>` classification rather than guessing.
_KNOWN_EVENT_IDS: dict[str, tuple[str, Severity]] = {
    "4624": ("logon_success", Severity.INFO),
    "4625": ("logon_failure", Severity.MEDIUM),
    "4672": ("special_privileges_assigned", Severity.MEDIUM),
    "4688": ("process_created", Severity.INFO),
    "4720": ("user_account_created", Severity.HIGH),
    "4732": ("group_member_added", Severity.HIGH),
    "4738": ("user_account_changed", Severity.MEDIUM),
}


class WindowsEventParser(BaseParser):
    name = "windows_event"
    description = (
        "Parses a CSV export of Windows Event Log entries (EVTX abstraction; "
        "binary .evtx parsing is deferred)."
    )
    evidence_type = EvidenceType.WINDOWS_EVENT
    supported_extensions = (".csv", ".evtx")
    supported_mime_types = ("text/csv",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        first_line = next((line for line in decoded_text.splitlines() if line.strip()), "")
        header_fields = {f.strip().lower() for f in first_line.split(",")}
        return 0.9 if header_fields >= REQUIRED_HEADER_FIELDS else 0.0

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        reader = csv.reader(io.StringIO(decoded_text))
        header = next(reader, None)
        self.raise_if_invalid(header is not None, "Windows event CSV has no header row.")
        header_fields = {f.strip().lower() for f in (header or [])}
        self.raise_if_invalid(
            header_fields >= REQUIRED_HEADER_FIELDS,
            f"Windows event CSV is missing required columns {REQUIRED_HEADER_FIELDS}.",
        )

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        reader = csv.DictReader(io.StringIO(decoded_text))
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for line_number, row in enumerate(reader, start=2):  # header is line 1
            event_id = (row.get("EventID") or "").strip()
            if not event_id:
                unparsed.append(",".join(row.values()))
                continue

            timestamp = self._parse_timestamp(row.get("TimeCreated"))
            event_type, severity = _KNOWN_EVENT_IDS.get(
                event_id, (f"windows_event_{event_id}", Severity.INFO)
            )

            records.append(
                EvidenceRecord(
                    line_number=line_number,
                    timestamp=timestamp,
                    host=row.get("Computer"),
                    user=row.get("Account"),
                    ip_address=row.get("SourceIP") or None,
                    event_type=event_type,
                    severity=severity,
                    raw_line=",".join(row.values()),
                    normalized_fields={
                        "event_id": event_id,
                        "logon_type": row.get("LogonType"),
                        "message": row.get("Message"),
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
            metadata={"total_rows": len(records) + len(unparsed)},
            unparsed_fragments=unparsed,
            chain_of_custody=self._chain_of_custody(raw),
        )

    @staticmethod
    def _parse_timestamp(raw_timestamp: str | None) -> datetime | None:
        if not raw_timestamp:
            return None
        try:
            return datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
        except ValueError:
            return None
