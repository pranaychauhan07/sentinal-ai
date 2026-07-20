"""Unit tests for core/parsers/openvas_parser.py."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.models import EvidenceType
from core.parsers.openvas_parser import OpenVasXmlParser

pytestmark = pytest.mark.unit

_VALID_OPENVAS = """<?xml version="1.0"?>
<report>
  <results>
    <result id="r1">
      <host>10.0.0.5</host>
      <port>443/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.156327">
        <name>Apache Log4Shell RCE</name>
        <cve>CVE-2021-44228</cve>
        <cwe>CWE-502</cwe>
        <cvss_base>10.0</cvss_base>
        <cvss_base_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</cvss_base_vector>
        <refs>
          <ref type="url" id="https://nvd.nist.gov/vuln/detail/CVE-2021-44228"/>
        </refs>
      </nvt>
      <description>Apache Log4j is vulnerable to remote code execution.</description>
      <threat>Critical</threat>
      <severity>10.0</severity>
    </result>
    <result id="r2">
      <host>10.0.0.5</host>
      <port>general/tcp</port>
      <nvt oid="1.3.6.1.4.1.25623.1.0.10267">
        <name>SSH Server type and version</name>
        <cve>NOCVE</cve>
      </nvt>
      <description>SSH server info.</description>
      <threat>Log</threat>
      <severity>0.0</severity>
    </result>
  </results>
</report>
"""

_MALICIOUS_XXE = """<?xml version="1.0" ?>
<!DOCTYPE report [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<report><results><result id="&xxe;"></result></results></report>
"""


def test_parses_valid_report_with_full_confidence() -> None:
    parser = OpenVasXmlParser()
    raw = RawEvidenceInput(filename="scan.xml", content=_VALID_OPENVAS.encode())
    result = parser(raw)

    assert result.evidence_type == EvidenceType.OPENVAS_XML
    assert result.confidence == 1.0
    assert result.record_count == 2

    log4shell = next(r for r in result.records if "156327" in r.normalized_fields["plugin_id"])
    assert log4shell.ip_address == "10.0.0.5"
    assert log4shell.normalized_fields["cve_id"] == "CVE-2021-44228"
    assert log4shell.normalized_fields["cwe_ids"] == ("CWE-502",)
    assert log4shell.normalized_fields["port"] == "443"
    assert log4shell.normalized_fields["protocol"] == "tcp"
    assert (
        log4shell.normalized_fields["cvss_v3_vector"]
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )


def test_nocve_placeholder_is_excluded() -> None:
    parser = OpenVasXmlParser()
    raw = RawEvidenceInput(filename="scan.xml", content=_VALID_OPENVAS.encode())
    result = parser(raw)
    ssh_finding = next(r for r in result.records if "10267" in r.normalized_fields["plugin_id"])
    assert ssh_finding.normalized_fields["cve_id"] == ""


def test_general_port_has_no_numeric_port() -> None:
    parser = OpenVasXmlParser()
    raw = RawEvidenceInput(filename="scan.xml", content=_VALID_OPENVAS.encode())
    result = parser(raw)
    ssh_finding = next(r for r in result.records if "10267" in r.normalized_fields["plugin_id"])
    assert ssh_finding.normalized_fields["port"] == ""
    assert ssh_finding.normalized_fields["protocol"] == "tcp"


def test_sniff_prefers_openvas_over_generic_xml() -> None:
    parser = OpenVasXmlParser()
    raw = RawEvidenceInput(filename="scan.xml", content=_VALID_OPENVAS.encode())
    assert parser.sniff(raw, _VALID_OPENVAS) > 0.5


def test_wrong_root_element_degrades_gracefully() -> None:
    parser = OpenVasXmlParser()
    raw = RawEvidenceInput(filename="wrong.xml", content=b"<nmaprun></nmaprun>")
    result = parser(raw)
    assert result.confidence == 0.0


def test_malformed_xml_degrades_gracefully() -> None:
    parser = OpenVasXmlParser()
    raw = RawEvidenceInput(filename="broken.xml", content=b"<report><unclosed>")
    result = parser(raw)
    assert result.confidence == 0.0


def test_xxe_payload_does_not_leak_file_contents() -> None:
    parser = OpenVasXmlParser()
    raw = RawEvidenceInput(filename="evil.xml", content=_MALICIOUS_XXE.encode())
    result = parser(raw)
    for record in result.records:
        assert "/etc/passwd" not in str(record.normalized_fields)


def test_empty_content_degrades_gracefully() -> None:
    parser = OpenVasXmlParser()
    raw = RawEvidenceInput(filename="empty.xml", content=b"   ")
    result = parser(raw)
    assert result.confidence == 0.0
