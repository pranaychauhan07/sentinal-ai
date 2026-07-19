"""Unit tests for core/parsers/email_parser.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.email_parser import EmailParser
from core.parsers.models import EvidenceType

PHISHING_FIXTURE = Path("data/sample_evidence/phishing_sample_01.eml")
LEGITIMATE_FIXTURE = Path("data/sample_evidence/legitimate_sample_01.eml")


@pytest.mark.unit
def test_parses_phishing_fixture_with_full_confidence() -> None:
    parser = EmailParser()
    raw = RawEvidenceInput(filename="phishing_sample_01.eml", content=PHISHING_FIXTURE.read_bytes())
    result = parser(raw)

    assert result.evidence_type == EvidenceType.EMAIL
    assert result.confidence == 1.0
    assert result.unparsed_fragments == []
    assert result.record_count == 2

    header = next(r for r in result.records if r.event_type == "email_header")
    assert header.normalized_fields["from_address"] == "support@amaz0n-security-verify.xyz"
    assert header.normalized_fields["subject"].startswith("URGENT")

    body = next(r for r in result.records if r.event_type == "email_body")
    assert "amaz0n-login-security.xyz" in body.raw_line


@pytest.mark.unit
def test_parses_legitimate_fixture() -> None:
    parser = EmailParser()
    raw = RawEvidenceInput(
        filename="legitimate_sample_01.eml", content=LEGITIMATE_FIXTURE.read_bytes()
    )
    result = parser(raw)

    header = next(r for r in result.records if r.event_type == "email_header")
    assert header.normalized_fields["from_address"] == "notifications@github.com"
    assert result.metadata["reply_to_address"] == ""


@pytest.mark.unit
def test_header_record_text_carries_sender_for_ioc_extraction() -> None:
    """The header record's `raw_line` must contain the sender address as
    plain text, since `IOCExtractionEngine` regex-scans `raw_line` — this
    parser deliberately does not extract IOCs itself (module docstring)."""
    parser = EmailParser()
    raw = RawEvidenceInput(filename="phishing_sample_01.eml", content=PHISHING_FIXTURE.read_bytes())
    result = parser(raw)
    header = next(r for r in result.records if r.event_type == "email_header")
    assert "support@amaz0n-security-verify.xyz" in header.raw_line


@pytest.mark.unit
def test_sniff_prefers_email_over_plain_text() -> None:
    parser = EmailParser()
    text = "From: a@b.com\nSubject: hi\nDate: Mon, 1 Jan 2024 00:00:00 +0000\n\nBody text."
    raw = RawEvidenceInput(filename="note.eml", content=text.encode())
    assert parser.sniff(raw, text) > 0.5


@pytest.mark.unit
def test_missing_required_headers_degrades_gracefully() -> None:
    parser = EmailParser()
    content = b"This is just plain text with no email headers at all.\nSecond line.\n"
    raw = RawEvidenceInput(filename="not_an_email.eml", content=content)
    result = parser(raw)
    assert result.confidence == 0.0
    assert result.unparsed_fragments == [
        "This is just plain text with no email headers at all.\nSecond line.\n"
    ]


@pytest.mark.unit
def test_empty_content_degrades_gracefully() -> None:
    parser = EmailParser()
    raw = RawEvidenceInput(filename="empty.eml", content=b"   ")
    result = parser(raw)
    assert result.confidence == 0.0


@pytest.mark.unit
def test_attachments_are_captured_in_metadata() -> None:
    parser = EmailParser()
    message = (
        "From: attacker@evil.example\n"
        "To: victim@example.com\n"
        "Subject: Invoice attached\n"
        "Date: Mon, 1 Jan 2024 00:00:00 +0000\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="BOUNDARY"\n'
        "\n"
        "--BOUNDARY\n"
        "Content-Type: text/plain\n"
        "\n"
        "Please see attached invoice.\n"
        "--BOUNDARY\n"
        "Content-Type: application/octet-stream\n"
        'Content-Disposition: attachment; filename="invoice.exe"\n'
        "Content-Transfer-Encoding: base64\n"
        "\n"
        "AAAA\n"
        "--BOUNDARY--\n"
    )
    raw = RawEvidenceInput(filename="with_attachment.eml", content=message.encode())
    result = parser(raw)
    assert result.metadata["attachments"] == [
        {"filename": "invoice.exe", "content_type": "application/octet-stream"}
    ]
