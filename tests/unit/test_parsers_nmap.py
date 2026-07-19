"""Unit tests for core/parsers/nmap_parser.py — defusedxml-based, XXE-safe."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.models import Severity
from core.parsers.nmap_parser import NmapXmlParser

FIXTURE = Path("data/sample_evidence/nmap_scan.xml")
XXE_FIXTURE = Path("data/sample_evidence/malformed/xxe_attempt.xml")


@pytest.mark.unit
def test_parses_real_fixture_with_full_confidence() -> None:
    parser = NmapXmlParser()
    raw = RawEvidenceInput(filename="nmap_scan.xml", content=FIXTURE.read_bytes())
    result = parser(raw)
    assert result.confidence == 1.0
    assert result.record_count == 1


@pytest.mark.unit
def test_extracts_open_ports_and_os_match() -> None:
    parser = NmapXmlParser()
    raw = RawEvidenceInput(filename="nmap_scan.xml", content=FIXTURE.read_bytes())
    result = parser(raw)
    host_record = result.records[0]
    assert host_record.ip_address == "198.51.100.23"
    open_ports = host_record.normalized_fields["open_ports"]
    assert {p["port"] for p in open_ports} == {"22", "80", "443", "3306", "21"}
    assert "Linux" in host_record.normalized_fields["os_match"]


@pytest.mark.unit
def test_ftp_port_flags_medium_severity() -> None:
    parser = NmapXmlParser()
    raw = RawEvidenceInput(filename="nmap_scan.xml", content=FIXTURE.read_bytes())
    result = parser(raw)
    assert result.records[0].severity == Severity.MEDIUM  # port 21 (FTP) is open


@pytest.mark.unit
def test_xxe_attempt_is_blocked_and_degrades_gracefully() -> None:
    """The core security guarantee of this parser: defusedxml rejects the
    external entity before it can be resolved, and BaseParser converts that
    into a zero-confidence degraded result rather than a crash. The raw
    upload (which legitimately contains the literal `file:///etc/passwd`
    DTD declaration as untouched evidence, per constitution §1.7's "never
    drop data") is preserved in `unparsed_fragments` — what must never
    happen is the entity actually being *resolved* into real file content,
    which `EntitiesForbidden` in the degraded reason proves didn't occur.
    """
    parser = NmapXmlParser()
    raw = RawEvidenceInput(filename="xxe_attempt.xml", content=XXE_FIXTURE.read_bytes())
    result = parser(raw)
    assert result.confidence == 0.0
    assert result.records == []
    assert "EntitiesForbidden" in result.metadata["degraded_reason"]


@pytest.mark.unit
def test_non_nmap_root_element_degrades() -> None:
    parser = NmapXmlParser()
    raw = RawEvidenceInput(filename="other.xml", content=b"<?xml version='1.0'?><root/>")
    result = parser(raw)
    assert result.confidence == 0.0


@pytest.mark.unit
def test_malformed_xml_degrades_instead_of_raising() -> None:
    parser = NmapXmlParser()
    raw = RawEvidenceInput(filename="broken.xml", content=b"<nmaprun><unclosed>")
    result = parser(raw)
    assert result.confidence == 0.0
