"""Nmap XML report parser — the blueprint §6-named `nmap_parser.py` module.

Uses `defusedxml.ElementTree` rather than the stdlib `xml.etree.ElementTree`:
stdlib XML parsing is vulnerable to entity-expansion ("billion laughs") and
external-entity (XXE) attacks, and a scan report is exactly the kind of
artifact an attacker could plant on a compromised host for an analyst to
later upload — this is the one parser in the framework handling XML, and the
task explicitly requires preventing "unsafe parsing" (see
`docs/adr/0011-evidence-ingestion-pipeline-shape.md`).
"""

from __future__ import annotations

from datetime import UTC, datetime

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import (
    EvidenceRecord,
    EvidenceType,
    NormalizedEvidence,
    Severity,
)

#: Ports commonly associated with legacy/high-risk services — used only to
#: flag severity on the parser's own output, never to render a security
#: verdict (that's the future Vulnerability Assessment Agent's job, out of
#: scope here per constitution §9's tool/LLM boundary — this is a
#: deterministic, documented heuristic, not "investigation logic").
_NOTABLE_PORTS: dict[str, Severity] = {
    "21": Severity.MEDIUM,  # FTP — frequently unencrypted/anonymous
    "23": Severity.HIGH,  # Telnet — unencrypted remote shell
    "3389": Severity.MEDIUM,  # RDP — common brute-force/ransomware target
}


class NmapXmlParser(BaseParser):
    name = "nmap_xml"
    description = "Parses Nmap XML scan reports (defusedxml, XXE-safe)."
    evidence_type = EvidenceType.NMAP_XML
    supported_extensions = (".xml",)
    supported_mime_types = ("application/xml", "text/xml")

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        stripped = decoded_text.lstrip()
        if "<nmaprun" in stripped[:2000]:
            return 0.95
        if stripped.startswith("<?xml"):
            return 0.3
        return 0.0

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        try:
            root = SafeElementTree.fromstring(decoded_text)
        except (DefusedXmlException, Exception) as exc:  # noqa: BLE001 - any malformed XML is the same outcome
            self.raise_if_invalid(False, f"Nmap XML is not well-formed: {exc}")
            return
        self.raise_if_invalid(root.tag == "nmaprun", "Root element is not <nmaprun>.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        root = SafeElementTree.fromstring(decoded_text)
        records: list[EvidenceRecord] = []
        unparsed: list[str] = []

        scanner = root.get("args", "")
        for host_el in root.findall("host"):
            record = self._parse_host(host_el)
            if record is None:
                unparsed.append(SafeElementTree.tostring(host_el, encoding="unicode"))
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
            metadata={"scanner_args": scanner, "host_count": len(records)},
            unparsed_fragments=unparsed,
            chain_of_custody=self._chain_of_custody(raw),
        )

    def _parse_host(self, host_el: object) -> EvidenceRecord | None:
        address_el = host_el.find("address")  # type: ignore[attr-defined]
        if address_el is None:
            return None
        ip_address = address_el.get("addr")

        starttime = host_el.get("starttime")  # type: ignore[attr-defined]
        timestamp = (
            datetime.fromtimestamp(int(starttime), tz=UTC)
            if starttime and starttime.isdigit()
            else None
        )

        open_ports: list[dict[str, str | None]] = []
        max_severity = Severity.INFO
        for port_el in host_el.findall("ports/port"):  # type: ignore[attr-defined]
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            port_id = port_el.get("portid", "")
            open_ports.append(
                {
                    "port": port_id,
                    "protocol": port_el.get("protocol"),
                    "service": service_el.get("name") if service_el is not None else None,
                    "product": service_el.get("product") if service_el is not None else None,
                    "version": service_el.get("version") if service_el is not None else None,
                }
            )
            port_severity = _NOTABLE_PORTS.get(port_id, Severity.INFO)
            if _severity_rank(port_severity) > _severity_rank(max_severity):
                max_severity = port_severity

        os_match_el = host_el.find("os/osmatch")  # type: ignore[attr-defined]
        os_name = os_match_el.get("name") if os_match_el is not None else None

        return EvidenceRecord(
            timestamp=timestamp,
            host=ip_address,
            ip_address=ip_address,
            event_type="nmap_host_scanned",
            severity=max_severity,
            raw_line=f"host {ip_address}: {len(open_ports)} open port(s)",
            normalized_fields={"open_ports": open_ports, "os_match": os_name},
        )


_SEVERITY_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def _severity_rank(severity: Severity) -> int:
    return _SEVERITY_ORDER.index(severity)
