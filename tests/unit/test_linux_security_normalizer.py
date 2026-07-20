"""Unit tests for core/linux_security/normalizer.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.linux_security.normalizer import LinuxSecurityNormalizer, sanitize_text
from core.parsers.models import ChainOfCustody, EvidenceRecord, EvidenceType, NormalizedEvidence

pytestmark = pytest.mark.unit


def _custody() -> ChainOfCustody:
    return ChainOfCustody(
        ingested_at=datetime.now(UTC),
        ingested_by="tester",
        original_filename="auth.log",
        sha256="a" * 64,
        file_size_bytes=10,
    )


def _evidence(records: list[EvidenceRecord]) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_type=EvidenceType.SSH_AUTH,
        source="auth.log",
        parser_name="ssh_auth",
        parser_version="1.0.0",
        confidence=1.0,
        records=records,
        chain_of_custody=_custody(),
    )


def test_normalizes_basic_record() -> None:
    record = EvidenceRecord(
        line_number=1,
        timestamp=datetime.now(UTC),
        host="web01",
        user="root",
        ip_address="203.0.113.44",
        event_type="auth_failure",
        raw_line="raw",
    )
    events, skipped = LinuxSecurityNormalizer().normalize(_evidence([record]))
    assert skipped == 0
    assert len(events) == 1
    assert events[0].process == "auth_failure"
    assert events[0].user == "root"


def test_syslog_message_field_becomes_raw_message() -> None:
    record = EvidenceRecord(
        line_number=1,
        timestamp=datetime.now(UTC),
        event_type="sudo",
        normalized_fields={"message": "deploy : COMMAND=/bin/ls"},
    )
    events, _skipped = LinuxSecurityNormalizer().normalize(_evidence([record]))
    assert events[0].raw_message == "deploy : COMMAND=/bin/ls"


def test_record_with_no_timestamp_and_no_signal_is_skipped() -> None:
    record = EvidenceRecord(line_number=1)
    events, skipped = LinuxSecurityNormalizer().normalize(_evidence([record]))
    assert events == []
    assert skipped == 1


def test_record_with_no_timestamp_but_process_is_kept() -> None:
    record = EvidenceRecord(line_number=1, event_type="CRON", raw_line="(root) CMD (ls)")
    events, skipped = LinuxSecurityNormalizer().normalize(_evidence([record]))
    assert len(events) == 1
    assert skipped == 0


def test_journald_field_supplement_used_when_no_structured_signal() -> None:
    record = EvidenceRecord(
        line_number=1,
        normalized_fields={"SYSLOG_IDENTIFIER": "sudo", "MESSAGE": "some sudo message"},
    )
    events, skipped = LinuxSecurityNormalizer().normalize(_evidence([record]))
    assert skipped == 0
    assert events[0].process == "sudo"
    assert events[0].raw_message == "some sudo message"


def test_malformed_record_is_skipped_not_crashed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A record that raises during normalization degrades to a skip rather
    than aborting the whole artifact (constitution §1.7)."""
    normalizer = LinuxSecurityNormalizer()

    class _BoomRecord:
        line_number = 1
        normalized_fields: dict[str, object] = {}
        timestamp = None
        event_type = None
        raw_line = ""

        @property
        def host(self) -> str:
            raise ValueError("corrupted field")

        user = None
        ip_address = None

    evidence = _evidence([])
    # Bypass Pydantic typing to simulate a genuinely corrupted record object.
    object.__setattr__(evidence, "records", [_BoomRecord()])
    events, skipped = normalizer.normalize(evidence)
    assert events == []
    assert skipped == 1


def test_sanitize_text_strips_control_characters() -> None:
    """Log-injection guard: embedded newlines/control chars must never
    reach a downstream log line or finding field verbatim."""
    dirty = "alice\n\rFake: injected line\x07"
    cleaned = sanitize_text(dirty)
    assert "\n" not in cleaned
    assert "\r" not in cleaned
    assert "\x07" not in cleaned


def test_sanitize_text_truncates_long_input() -> None:
    assert len(sanitize_text("a" * 10_000, max_length=100)) == 100


def test_sanitize_text_handles_none_and_empty() -> None:
    assert sanitize_text(None) == ""
    assert sanitize_text("") == ""
