"""Unit tests for core/parsers/http_transaction_parser.py, including
registry priority/sniff behavior."""

from __future__ import annotations

import pytest

from core.parsers.base import RawEvidenceInput
from core.parsers.http_transaction_parser import HttpTransactionParser
from core.parsers.models import EvidenceType
from core.parsers.registry import default_parser_registry

pytestmark = pytest.mark.unit


def _raw(content: str) -> RawEvidenceInput:
    return RawEvidenceInput(filename="transaction.txt", content=content.encode())


def test_sniff_recognizes_request_line() -> None:
    parser = HttpTransactionParser()
    confidence = parser.sniff(_raw("x"), "GET /path HTTP/1.1")
    assert confidence > 0.1


def test_sniff_recognizes_status_line() -> None:
    parser = HttpTransactionParser()
    confidence = parser.sniff(_raw("x"), "HTTP/1.1 200 OK")
    assert confidence > 0.1


def test_sniff_recognizes_set_cookie_header() -> None:
    parser = HttpTransactionParser()
    confidence = parser.sniff(_raw("x"), "Set-Cookie: session=abc; Secure")
    assert confidence > 0.1


def test_sniff_recognizes_security_relevant_header() -> None:
    parser = HttpTransactionParser()
    confidence = parser.sniff(_raw("x"), "Content-Security-Policy: default-src 'self'")
    assert confidence > 0.1


def test_sniff_gives_zero_for_unrelated_text() -> None:
    parser = HttpTransactionParser()
    assert parser.sniff(_raw("x"), "Dear diary, today was a good day.") == 0.0


def test_parse_produces_one_record_per_nonblank_line() -> None:
    parser = HttpTransactionParser()
    raw = _raw("GET / HTTP/1.1\n\nHTTP/1.1 200 OK\n")
    result = parser(raw)
    assert result.evidence_type == EvidenceType.HTTP_TRANSACTION
    assert len(result.records) == 2
    assert result.records[0].raw_line == "GET / HTTP/1.1"
    assert result.records[0].event_type == "http_transaction_line"


def test_empty_input_degrades_not_crashes() -> None:
    parser = HttpTransactionParser()
    result = parser(_raw(""))
    assert result.confidence == 0.0
    assert result.records == []


def test_registry_priority_above_plain_text() -> None:
    registry = default_parser_registry()
    http_registration = next(
        r for r in registry.list_registrations() if r.name == "http_transaction"
    )
    plain_text_registration = next(
        r for r in registry.list_registrations() if r.name == "plain_text"
    )
    assert http_registration.priority > plain_text_registration.priority


def test_registry_has_alias() -> None:
    registry = default_parser_registry()
    assert registry.get("http") is registry.get("http_transaction")
