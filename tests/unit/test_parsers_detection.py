"""Unit tests for core/parsers/detection.py."""

from __future__ import annotations

import pytest

from core.parsers.detection import (
    detect_encoding,
    detect_mime_type,
    sniff_evidence_type,
)
from core.parsers.models import EvidenceType


@pytest.mark.unit
def test_detect_encoding_utf8() -> None:
    text, result = detect_encoding(b"hello world")
    assert text == "hello world"
    assert result.encoding == "utf-8"
    assert result.confidence == 1.0


@pytest.mark.unit
def test_detect_encoding_utf8_bom() -> None:
    text, result = detect_encoding(b"\xef\xbb\xbfhello")
    assert text == "hello"
    assert result.encoding == "utf-8-sig"


@pytest.mark.unit
def test_detect_encoding_falls_back_to_latin1() -> None:
    # 0xe9 0xe8 are not valid UTF-8 continuation bytes here.
    text, result = detect_encoding(b"caf\xe9 na\xe8ve")
    assert result.encoding == "latin-1"
    assert result.confidence < 1.0
    assert "caf" in text


@pytest.mark.unit
def test_detect_encoding_never_raises_for_nonempty_bytes() -> None:
    # latin-1 accepts every byte value, so this should not raise even for
    # arbitrary binary content.
    text, _ = detect_encoding(bytes(range(256)))
    assert len(text) == 256


@pytest.mark.unit
def test_detect_mime_type_known_and_unknown_extensions() -> None:
    assert detect_mime_type("evidence.json") == "application/json"
    assert detect_mime_type("evidence.log") == "application/octet-stream"


@pytest.mark.unit
def test_sniff_evidence_type_nmap_xml() -> None:
    candidates = sniff_evidence_type(
        "scan.xml", '<?xml version="1.0"?>\n<nmaprun scanner="nmap"></nmaprun>'
    )
    assert candidates[0][0] == EvidenceType.NMAP_XML


@pytest.mark.unit
def test_sniff_evidence_type_json() -> None:
    candidates = sniff_evidence_type("evidence.json", '{"a": 1}')
    assert candidates[0][0] == EvidenceType.JSON


@pytest.mark.unit
def test_sniff_evidence_type_ssh_auth() -> None:
    line = "Jul 18 02:14:01 web-prod-01 sshd[10321]: Failed password for root from 1.2.3.4 port 1"
    candidates = sniff_evidence_type("auth.log", line)
    assert candidates[0][0] == EvidenceType.SSH_AUTH


@pytest.mark.unit
def test_sniff_evidence_type_apache_access() -> None:
    line = '1.2.3.4 - - [18/Jul/2026:02:13:40 +0000] "GET / HTTP/1.1" 200 100 "-" "curl"'
    candidates = sniff_evidence_type("access.log", line)
    assert candidates[0][0] == EvidenceType.APACHE_ACCESS


@pytest.mark.unit
def test_sniff_evidence_type_falls_back_to_plain_text() -> None:
    candidates = sniff_evidence_type("note.txt", "just some free-form analyst notes")
    assert candidates == [(EvidenceType.PLAIN_TEXT, 0.2)]


@pytest.mark.unit
def test_sniff_evidence_type_empty_content_has_no_candidates() -> None:
    assert sniff_evidence_type("empty.txt", "   ") == []
