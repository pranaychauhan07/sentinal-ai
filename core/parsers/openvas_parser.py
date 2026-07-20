"""OpenVAS/GVM XML scan report parser — blueprint §6's named
`openvas_parser.py`. Uses `defusedxml.ElementTree`, same XXE/entity-
expansion safety reasoning as `core/parsers/nmap_parser.py` and
`core/parsers/nessus_parser.py`.

Expects a GVM/OpenVAS report export's `<report><results><result>...`
structure: one `EvidenceRecord` per `<result>`, with the NVT's structured
fields (CVE, CVSS vector/base score, CWE, references) placed directly into
`normalized_fields` — mirrors `nessus_parser.py`'s identical "structured
extraction only, no scoring/judgment" contract (constitution §1.4).
"""

from __future__ import annotations

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence, Severity

#: OpenVAS's own textual threat rating -> the 0-4 scanner severity code
#: `core.vulnerabilities.severity.severity_from_scanner_code` already knows
#: how to map. "Log" and "Debug" are OpenVAS-specific informational-only
#: ratings below "None" in practice; both map to 0.
_THREAT_TO_SEVERITY_CODE: dict[str, int] = {
    "log": 0,
    "debug": 0,
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class OpenVasXmlParser(BaseParser):
    name = "openvas_xml"
    description = "Parses OpenVAS/GVM XML scan reports (defusedxml, XXE-safe)."
    evidence_type = EvidenceType.OPENVAS_XML
    supported_extensions = (".xml",)
    supported_mime_types = ("application/xml", "text/xml")

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        stripped = decoded_text.lstrip()
        if "<report" in stripped[:200] and "<results" in stripped[:2000]:
            return 0.85
        if stripped.startswith("<?xml"):
            return 0.1
        return 0.0

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        try:
            root = SafeElementTree.fromstring(decoded_text)
        except (DefusedXmlException, Exception) as exc:  # noqa: BLE001 - any malformed XML is the same outcome
            self.raise_if_invalid(False, f"OpenVAS XML is not well-formed: {exc}")
            return
        self.raise_if_invalid(root.tag == "report", "Root element is not <report>.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        root = SafeElementTree.fromstring(decoded_text)
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        for result in root.findall(".//results/result"):
            record = self._parse_result(result)
            if record is None:
                unparsed.append(SafeElementTree.tostring(result, encoding="unicode"))
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
            metadata={"finding_count": len(records)},
            unparsed_fragments=unparsed,
            chain_of_custody=self._chain_of_custody(raw),
        )

    def _parse_result(self, result: object) -> EvidenceRecord | None:
        nvt = result.find("nvt")  # type: ignore[attr-defined]
        plugin_id = nvt.get("oid") if nvt is not None else None
        plugin_name = self._child_text(nvt, "name") if nvt is not None else ""
        if not plugin_id and not plugin_name:
            return None

        host = self._child_text(result, "host") or None
        port_field = self._child_text(result, "port")
        port, protocol = self._split_port(port_field)

        description = self._child_text(result, "description")
        threat = self._child_text(result, "threat").lower()
        severity_code = _THREAT_TO_SEVERITY_CODE.get(threat, 0)

        cve_text = self._child_text(nvt, "cve") if nvt is not None else ""
        cve_id = cve_text if cve_text and cve_text.upper() != "NOCVE" else ""
        cwe_text = self._child_text(nvt, "cwe") if nvt is not None else ""
        cwe_ids = (cwe_text,) if cwe_text else ()

        cvss_base_score = self._child_text(nvt, "cvss_base") if nvt is not None else ""
        cvss_base_vector = self._child_text(nvt, "cvss_base_vector") if nvt is not None else ""

        references: tuple[str, ...] = ()
        if nvt is not None:
            refs_el = nvt.find("refs")
            if refs_el is not None:
                references = tuple(
                    ref.get("id", "") for ref in refs_el.findall("ref") if ref.get("id")
                )

        return EvidenceRecord(
            host=host,
            ip_address=host,
            event_type="vulnerability_finding",
            severity=Severity.INFO,
            raw_line=description,
            normalized_fields={
                "plugin_id": plugin_id or "",
                "plugin_name": plugin_name,
                "cve_id": cve_id,
                "cwe_ids": cwe_ids,
                "port": port,
                "protocol": protocol,
                "service": "",
                "description": description,
                "references": references,
                "cvss_v3_vector": cvss_base_vector,
                "cvss_v3_score": cvss_base_score,
                "severity_code": severity_code,
            },
        )

    def _split_port(self, port_field: str) -> tuple[str, str]:
        """OpenVAS reports `<port>` as `"443/tcp"` (or `"general/tcp"` for
        host-level, non-port-specific findings)."""
        if "/" not in port_field:
            return "", ""
        port, _, protocol = port_field.partition("/")
        return (port if port.isdigit() else ""), protocol

    def _child_text(self, element: object, tag_name: str) -> str:
        if element is None:
            return ""
        child = element.find(tag_name)  # type: ignore[attr-defined]
        return child.text.strip() if child is not None and child.text else ""
