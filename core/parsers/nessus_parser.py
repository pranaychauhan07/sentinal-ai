"""Nessus `.nessus` XML scan report parser — blueprint §6's named
`nessus_parser.py`. Uses `defusedxml.ElementTree` (not stdlib
`xml.etree.ElementTree`), same XXE/entity-expansion safety reasoning as
`core/parsers/nmap_parser.py` — a scan report is exactly the kind of
artifact an attacker could plant for an analyst to later upload.

Produces one `EvidenceRecord` per `<ReportItem>`, with the plugin's
structured fields (CVE, CWE, CVSS vectors, port/protocol/service,
description, references) placed directly into `normalized_fields` —
`core.vulnerabilities.extractor.VulnerabilityExtractionEngine` reads these
without any regex re-parsing (constitution §1.9: scan reports are
structured data, not free text). This parser performs no vulnerability
scoring, severity judgment, or CVE/CVSS interpretation of its own — only
structural extraction (constitution §1.4).

A `<ReportItem>` citing more than one `<cve>` is folded to its first CVE as
the record's primary identifier; every cited CVE still appears in the raw
description/references text, so
`core.vulnerabilities.cve_extractor`'s regex fallback discovers the rest —
a documented simplification, not silent data loss.
"""

from __future__ import annotations

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence, Severity


class NessusXmlParser(BaseParser):
    name = "nessus_xml"
    description = "Parses Nessus .nessus XML scan reports (defusedxml, XXE-safe)."
    evidence_type = EvidenceType.NESSUS_XML
    supported_extensions = (".nessus",)
    supported_mime_types = ("application/xml", "text/xml")

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        stripped = decoded_text.lstrip()
        if "<NessusClientData_v2" in stripped[:2000]:
            return 0.95
        if stripped.startswith("<?xml"):
            return 0.2
        return 0.0

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        try:
            root = SafeElementTree.fromstring(decoded_text)
        except (DefusedXmlException, Exception) as exc:  # noqa: BLE001 - malformed XML, one outcome
            self.raise_if_invalid(False, f"Nessus XML is not well-formed: {exc}")
            return
        self.raise_if_invalid(
            root.tag == "NessusClientData_v2", "Root element is not <NessusClientData_v2>."
        )

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        root = SafeElementTree.fromstring(decoded_text)
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for report_host in root.findall(".//ReportHost"):
            host_name = report_host.get("name")
            host_ip = self._host_property(report_host, "host-ip") or host_name

            for report_item in report_host.findall("ReportItem"):
                record = self._parse_report_item(report_item, host=host_name, ip_address=host_ip)
                if record is None:
                    unparsed.append(SafeElementTree.tostring(report_item, encoding="unicode"))
                else:
                    records.append(record)

        confidence = 1.0 if records else 0.0
        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=confidence,
            records=records,
            metadata={
                "host_count": len(root.findall(".//ReportHost")),
                "finding_count": len(records),
            },
            unparsed_fragments=unparsed,
            chain_of_custody=self._chain_of_custody(raw),
        )

    def _host_property(self, report_host: object, tag_name: str) -> str | None:
        for tag in report_host.findall(".//tag"):  # type: ignore[attr-defined]
            if tag.get("name") == tag_name:
                return str(tag.text) if tag.text is not None else None
        return None

    def _parse_report_item(
        self, report_item: object, *, host: str | None, ip_address: str | None
    ) -> EvidenceRecord | None:
        plugin_id = report_item.get("pluginID")  # type: ignore[attr-defined]
        plugin_name = report_item.get("pluginName", "")  # type: ignore[attr-defined]
        if not plugin_id and not plugin_name:
            return None

        port_raw = report_item.get("port")  # type: ignore[attr-defined]
        protocol = report_item.get("protocol")  # type: ignore[attr-defined]
        service = report_item.get("svc_name")  # type: ignore[attr-defined]
        severity_code = report_item.get("severity", "0")  # type: ignore[attr-defined]

        description = self._child_text(report_item, "description")
        cve_elements = report_item.findall("cve")  # type: ignore[attr-defined]
        cve_ids = tuple(el.text.strip() for el in cve_elements if el.text)
        cwe_elements = report_item.findall("cwe")  # type: ignore[attr-defined]
        cwe_ids = tuple(f"CWE-{el.text.strip()}" for el in cwe_elements if el.text)
        references = tuple(
            el.text.strip()
            for el in (*report_item.findall("see_also"), *report_item.findall("xref"))  # type: ignore[attr-defined]
            if el.text
        )
        cvss_v2_vector = self._child_text(report_item, "cvss_vector")
        cvss_v3_vector = self._child_text(report_item, "cvss3_vector")
        cvss_v4_vector = self._child_text(report_item, "cvss4_vector")

        return EvidenceRecord(
            host=host,
            ip_address=ip_address,
            event_type="vulnerability_finding",
            severity=Severity.INFO,
            raw_line=description,
            normalized_fields={
                "plugin_id": plugin_id or "",
                "plugin_name": plugin_name,
                "cve_id": cve_ids[0] if cve_ids else "",
                "cwe_ids": cwe_ids,
                "port": port_raw or "",
                "protocol": protocol or "",
                "service": service or "",
                "description": description,
                "references": references,
                "cvss_v2_vector": cvss_v2_vector or "",
                "cvss_v3_vector": cvss_v3_vector or "",
                "cvss_v4_vector": cvss_v4_vector or "",
                "severity_code": severity_code,
            },
        )

    def _child_text(self, element: object, tag_name: str) -> str:
        child = element.find(tag_name)  # type: ignore[attr-defined]
        return child.text.strip() if child is not None and child.text else ""
