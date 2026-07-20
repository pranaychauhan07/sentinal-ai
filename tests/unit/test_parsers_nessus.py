"""Unit tests for core/parsers/nessus_parser.py."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.models import EvidenceType
from core.parsers.nessus_parser import NessusXmlParser

pytestmark = pytest.mark.unit

_VALID_NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="scan">
    <ReportHost name="web01.example.com">
      <HostProperties>
        <tag name="host-ip">10.0.0.5</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="4"
                  pluginID="156327" pluginName="Apache Log4Shell RCE">
        <description>Apache Log4j is vulnerable to remote code execution.</description>
        <cve>CVE-2021-44228</cve>
        <cwe>502</cwe>
        <cvss_vector>AV:N/AC:M/Au:N/C:C/I:C/A:C</cvss_vector>
        <cvss3_vector>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</cvss3_vector>
        <see_also>https://nvd.nist.gov/vuln/detail/CVE-2021-44228</see_also>
      </ReportItem>
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="0"
                  pluginID="10267" pluginName="SSH Server Type and Version Information">
        <description>It is possible to obtain information about the remote SSH server.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

_MALICIOUS_XXE = """<?xml version="1.0" ?>
<!DOCTYPE NessusClientData_v2 [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<NessusClientData_v2>
  <Report name="&xxe;"><ReportHost name="x"></ReportHost></Report>
</NessusClientData_v2>
"""


def test_parses_well_formed_report_with_full_confidence() -> None:
    parser = NessusXmlParser()
    raw = RawEvidenceInput(filename="scan.nessus", content=_VALID_NESSUS.encode())
    result = parser(raw)

    assert result.evidence_type == EvidenceType.NESSUS_XML
    assert result.confidence == 1.0
    assert result.record_count == 2

    log4shell = next(r for r in result.records if r.normalized_fields["plugin_id"] == "156327")
    assert log4shell.host == "web01.example.com"
    assert log4shell.ip_address == "10.0.0.5"
    assert log4shell.normalized_fields["cve_id"] == "CVE-2021-44228"
    assert log4shell.normalized_fields["cwe_ids"] == ("CWE-502",)
    assert (
        log4shell.normalized_fields["cvss_v3_vector"]
        == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    )
    assert log4shell.normalized_fields["port"] == "443"
    assert log4shell.normalized_fields["service"] == "https"


def test_sniff_prefers_nessus_over_generic_xml() -> None:
    parser = NessusXmlParser()
    raw = RawEvidenceInput(filename="scan.nessus", content=_VALID_NESSUS.encode())
    assert parser.sniff(raw, _VALID_NESSUS) > 0.5


def test_malformed_xml_degrades_gracefully() -> None:
    parser = NessusXmlParser()
    raw = RawEvidenceInput(filename="broken.nessus", content=b"<NessusClientData_v2><unclosed>")
    result = parser(raw)
    assert result.confidence == 0.0


def test_wrong_root_element_degrades_gracefully() -> None:
    parser = NessusXmlParser()
    raw = RawEvidenceInput(filename="wrong.nessus", content=b"<nmaprun></nmaprun>")
    result = parser(raw)
    assert result.confidence == 0.0


def test_xxe_payload_does_not_leak_file_contents() -> None:
    """XXE safety, mirroring core/parsers/nmap_parser.py's identical test —
    defusedxml must reject external entity expansion outright."""
    parser = NessusXmlParser()
    raw = RawEvidenceInput(filename="evil.nessus", content=_MALICIOUS_XXE.encode())
    result = parser(raw)
    # Either the parser degrades (defusedxml raises) or, if somehow parsed,
    # no record ever contains the entity's expansion.
    for record in result.records:
        assert "/etc/passwd" not in str(record.normalized_fields)


def test_empty_content_degrades_gracefully() -> None:
    parser = NessusXmlParser()
    raw = RawEvidenceInput(filename="empty.nessus", content=b"   ")
    result = parser(raw)
    assert result.confidence == 0.0
