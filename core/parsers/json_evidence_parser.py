"""Generic JSON evidence parser — a single JSON object or a list of JSON
objects (e.g. an EDR alert export, a structured application log dump).
Normalizes common field-name variants via `core.parsers.field_heuristics`
(shared with `csv_evidence_parser.py`) rather than an LLM; anything that
doesn't match a known alias is preserved verbatim in `normalized_fields`,
never dropped.
"""

from __future__ import annotations

import json
from typing import Any

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


class JsonEvidenceParser(BaseParser):
    name = "json_evidence"
    description = "Parses a single JSON object or a list of JSON objects."
    evidence_type = EvidenceType.JSON
    supported_extensions = (".json",)
    supported_mime_types = ("application/json",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        stripped = decoded_text.strip()
        if not stripped or stripped[0] not in "{[":
            return 0.0
        try:
            json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return 0.0
        return 0.9

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        stripped = decoded_text.strip()
        self.raise_if_invalid(bool(stripped), "JSON evidence is empty.")
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, ValueError) as exc:
            self.raise_if_invalid(False, f"Content is not valid JSON: {exc}")
            return
        self.raise_if_invalid(
            isinstance(parsed, dict | list), "Top-level JSON must be an object or array."
        )

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        parsed = json.loads(decoded_text.strip())
        items: list[Any] = parsed if isinstance(parsed, list) else [parsed]

        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for line_number, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                unparsed.append(json.dumps(item))
                continue

            records.append(
                EvidenceRecord(
                    line_number=line_number,
                    timestamp=parse_generic_timestamp(first_present(item, TIMESTAMP_KEYS)),
                    host=stringify(first_present(item, HOST_KEYS)),
                    user=stringify(first_present(item, USER_KEYS)),
                    ip_address=stringify(first_present(item, IP_KEYS)),
                    event_type=stringify(first_present(item, EVENT_TYPE_KEYS)),
                    severity=parse_generic_severity(first_present(item, SEVERITY_KEYS)),
                    raw_line=json.dumps(item),
                    normalized_fields=item,
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
            metadata={"item_count": len(items)},
            unparsed_fragments=unparsed,
            chain_of_custody=self._chain_of_custody(raw),
        )
