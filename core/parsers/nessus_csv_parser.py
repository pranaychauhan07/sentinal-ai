"""Nessus CSV scan-report export parser. Tenable's default CSV export
(`Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,
Solution,See Also,Plugin Output`, with some export templates instead giving
separate `CVSS v2.0 Base Score`/`CVSS v3.0 Base Score` columns and no full
vector string at all — a real, common export variant this parser handles
via `core.vulnerabilities.extractor`'s numeric-score fallback path).

Uses stdlib `csv.DictReader` only — no new dependency. Deliberately
skips the `Solution` column entirely: remediation planning is out of
scope for this framework (task requirement), so this parser never even
extracts that text.
"""

from __future__ import annotations

import csv
import io

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.csv_common import lookup_column
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence, Severity

#: Nessus's own textual risk rating -> the 0-4 scanner severity code this
#: framework's `core.vulnerabilities.severity.severity_from_scanner_code`
#: already knows how to map.
_RISK_TO_SEVERITY_CODE: dict[str, int] = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

#: Required header columns — anything without these is not a Nessus CSV
#: export this parser recognizes.
_REQUIRED_HEADERS = ("Plugin ID", "Host")


class NessusCsvParser(BaseParser):
    name = "nessus_csv"
    description = "Parses Tenable Nessus CSV scan-report exports."
    evidence_type = EvidenceType.NESSUS_CSV
    supported_extensions = (".csv",)
    supported_mime_types = ("text/csv",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        first_line = decoded_text.splitlines()[0] if decoded_text.splitlines() else ""
        header_fields = {f.strip().strip('"').lower() for f in first_line.split(",")}
        if {"plugin id", "cve", "risk"} <= header_fields:
            return 0.9
        if "plugin id" in header_fields:
            return 0.6
        return 0.0

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        reader = csv.DictReader(io.StringIO(decoded_text))
        header = reader.fieldnames or []
        normalized_header = {h.strip().lower() for h in header}
        self.raise_if_invalid(
            all(required.lower() in normalized_header for required in _REQUIRED_HEADERS),
            f"CSV is missing required Nessus export column(s): {_REQUIRED_HEADERS}.",
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
        plugin_id = lookup_column(row, "Plugin ID")
        plugin_name = lookup_column(row, "Name")
        if not plugin_id and not plugin_name:
            return None

        host = lookup_column(row, "Host")
        cve_raw = lookup_column(row, "CVE")
        cve_id = cve_raw.split(",")[0].strip() if cve_raw else ""
        risk = lookup_column(row, "Risk").lower()
        severity_code = _RISK_TO_SEVERITY_CODE.get(risk, 0)
        see_also = lookup_column(row, "See Also")
        references = tuple(ref.strip() for ref in see_also.splitlines() if ref.strip())
        description = lookup_column(row, "Description", "Synopsis")

        return EvidenceRecord(
            line_number=line_number,
            host=host or None,
            ip_address=host or None,
            event_type="vulnerability_finding",
            severity=Severity.INFO,
            raw_line=description,
            normalized_fields={
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "cve_id": cve_id,
                "cwe_ids": (),
                "port": lookup_column(row, "Port"),
                "protocol": lookup_column(row, "Protocol"),
                "service": "",
                "description": description,
                "references": references,
                "cvss_v2_score": lookup_column(row, "CVSS", "CVSS v2.0 Base Score"),
                "cvss_v3_score": lookup_column(row, "CVSS v3.0 Base Score", "CVSS v3 Base Score"),
                "severity_code": severity_code,
            },
        )
