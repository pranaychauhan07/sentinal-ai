"""Generic CSV evidence parser — any header-having CSV export whose columns
aren't one of this framework's more specific formats
(`windows_event_parser.py` claims the specific Windows-event CSV shape at
higher registry priority). Uses the same field-name-alias heuristics as
`json_evidence_parser.py` via `core.parsers.field_heuristics`.
"""

from __future__ import annotations

import csv
import io

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.field_heuristics import (
    EVENT_TYPE_KEYS,
    HOST_KEYS,
    IP_KEYS,
    SEVERITY_KEYS,
    TIMESTAMP_KEYS,
    USER_KEYS,
    first_present,
    parse_generic_severity,
    parse_generic_timestamp,
    stringify,
)
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence


class CsvEvidenceParser(BaseParser):
    name = "csv_evidence"
    description = "Parses a generic header-having CSV evidence export."
    evidence_type = EvidenceType.CSV
    supported_extensions = (".csv",)
    supported_mime_types = ("text/csv",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        first_line = next((line for line in decoded_text.splitlines() if line.strip()), "")
        if "," not in first_line:
            return 0.0
        return 0.4

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        reader = csv.reader(io.StringIO(decoded_text))
        header = next(reader, None)
        self.raise_if_invalid(header is not None and len(header) > 0, "CSV has no header row.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        reader = csv.DictReader(io.StringIO(decoded_text))
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for line_number, row in enumerate(reader, start=2):  # header is line 1
            if not any(row.values()):
                unparsed.append(",".join(str(v) for v in row.values()))
                continue

            row_str_values = {k: v for k, v in row.items() if k is not None}
            records.append(
                EvidenceRecord(
                    line_number=line_number,
                    timestamp=parse_generic_timestamp(
                        first_present(row_str_values, TIMESTAMP_KEYS)
                    ),
                    host=stringify(first_present(row_str_values, HOST_KEYS)),
                    user=stringify(first_present(row_str_values, USER_KEYS)),
                    ip_address=stringify(first_present(row_str_values, IP_KEYS)),
                    event_type=stringify(first_present(row_str_values, EVENT_TYPE_KEYS)),
                    severity=parse_generic_severity(first_present(row_str_values, SEVERITY_KEYS)),
                    raw_line=",".join(str(v) for v in row.values()),
                    normalized_fields=dict(row_str_values),
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
            metadata={"row_count": len(records) + len(unparsed)},
            unparsed_fragments=unparsed,
            chain_of_custody=self._chain_of_custody(raw),
        )
