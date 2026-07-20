"""OpenVAS/GVM CSV scan-report export parser. GVM's default CSV export
(`IP,Hostname,Port,Port Protocol,CVSS,Severity,NVT Name,Summary,
Specific Result,NVT OID,CVEs,Task ID,Task Name,Timestamp,Result ID`).

Uses stdlib `csv.DictReader` only — no new dependency. Mirrors
`core/parsers/nessus_csv_parser.py`'s "structured extraction only, skip
remediation text" contract exactly.
"""

from __future__ import annotations

import csv
import io

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.csv_common import lookup_column
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence, Severity

#: GVM's own textual severity rating -> the 0-4 scanner severity code
#: `core.vulnerabilities.severity.severity_from_scanner_code` already knows
#: how to map.
_SEVERITY_TO_CODE: dict[str, int] = {
    "log": 0,
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_REQUIRED_HEADERS = ("IP", "NVT Name")


class OpenVasCsvParser(BaseParser):
    name = "openvas_csv"
    description = "Parses OpenVAS/GVM CSV scan-report exports."
    evidence_type = EvidenceType.OPENVAS_CSV
    supported_extensions = (".csv",)
    supported_mime_types = ("text/csv",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        first_line = decoded_text.splitlines()[0] if decoded_text.splitlines() else ""
        header_fields = {f.strip().strip('"').lower() for f in first_line.split(",")}
        if {"ip", "nvt name", "nvt oid"} <= header_fields:
            return 0.9
        if "nvt oid" in header_fields:
            return 0.6
        return 0.0

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        reader = csv.DictReader(io.StringIO(decoded_text))
        header = reader.fieldnames or []
        normalized_header = {h.strip().lower() for h in header}
        self.raise_if_invalid(
            all(required.lower() in normalized_header for required in _REQUIRED_HEADERS),
            f"CSV is missing required OpenVAS export column(s): {_REQUIRED_HEADERS}.",
        )

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        reader = csv.DictReader(io.StringIO(decoded_text))
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for line_number, row in enumerate(reader, start=2):  # header is line 1
            record = self._parse_row(row, line_number)
            if record is None:
                unparsed.append(str(row))
            else:
                records.append(record)

        confidence = 1.0 if records and not unparsed else (0.6 if records else 0.0)
        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=confidence,
            records=records,
            metadata={"finding_count": len(records)},
            unparsed_fragments=unparsed,
            chain_of_custody=self._chain_of_custody(raw),
        )

    def _parse_row(self, row: dict[str, str], line_number: int) -> EvidenceRecord | None:
        plugin_id = lookup_column(row, "NVT OID")
        plugin_name = lookup_column(row, "NVT Name")
        if not plugin_id and not plugin_name:
            return None

        ip_address = lookup_column(row, "IP")
        hostname = lookup_column(row, "Hostname")
        cve_raw = lookup_column(row, "CVEs")
        cve_id = "" if cve_raw.upper() == "NOCVE" else cve_raw.split(",")[0].strip()
        severity_text = lookup_column(row, "Severity").lower()
        severity_code = _SEVERITY_TO_CODE.get(severity_text, 0)
        description = lookup_column(row, "Summary", "Specific Result")

        return EvidenceRecord(
            line_number=line_number,
            host=hostname or ip_address or None,
            ip_address=ip_address or None,
            event_type="vulnerability_finding",
            severity=Severity.INFO,
            raw_line=description,
            normalized_fields={
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "cve_id": cve_id,
                "cwe_ids": (),
                "port": lookup_column(row, "Port"),
                "protocol": lookup_column(row, "Port Protocol"),
                "service": "",
                "description": description,
                "references": (),
                "cvss_v3_score": lookup_column(row, "CVSS"),
                "severity_code": severity_code,
            },
        )
