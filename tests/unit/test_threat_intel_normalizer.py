"""Unit tests for core/threat_intel/normalizer.py — IOCNormalizer."""

from __future__ import annotations

import pytest

from core.threat_intel.models import IOCRecord, IOCType
from core.threat_intel.normalizer import IOCNormalizer


def _ioc(ioc_type: IOCType, value: str) -> IOCRecord:
    return IOCRecord(ioc_type=ioc_type, value=value, raw_value=value, source="test")


@pytest.mark.unit
def test_normalize_ipv4_round_trips_canonical_form() -> None:
    normalizer = IOCNormalizer()
    result = normalizer.normalize(_ioc(IOCType.IPV4, "10.1.1.1"))
    assert result.value == "10.1.1.1"


@pytest.mark.unit
def test_normalize_domain_lowercases_and_strips_trailing_dot() -> None:
    normalizer = IOCNormalizer()
    result = normalizer.normalize(_ioc(IOCType.DOMAIN, "EVIL.Example.COM."))
    assert result.value == "evil.example.com"


@pytest.mark.unit
def test_normalize_hash_lowercases() -> None:
    normalizer = IOCNormalizer()
    result = normalizer.normalize(_ioc(IOCType.SHA256, "A" * 64))
    assert result.value == "a" * 64


@pytest.mark.unit
def test_normalize_email_lowercases() -> None:
    normalizer = IOCNormalizer()
    result = normalizer.normalize(_ioc(IOCType.EMAIL, "User@Example.COM"))
    assert result.value == "user@example.com"


@pytest.mark.unit
def test_normalize_command_line_collapses_whitespace() -> None:
    normalizer = IOCNormalizer()
    result = normalizer.normalize(_ioc(IOCType.COMMAND_LINE, "cmd.exe   /c    whoami"))
    assert result.value == "cmd.exe /c whoami"


@pytest.mark.unit
def test_normalize_preserves_raw_value() -> None:
    normalizer = IOCNormalizer()
    result = normalizer.normalize(_ioc(IOCType.DOMAIN, "EVIL.COM"))
    assert result.raw_value == "EVIL.COM"


@pytest.mark.unit
def test_normalize_returns_same_instance_when_already_canonical() -> None:
    normalizer = IOCNormalizer()
    ioc = _ioc(IOCType.DOMAIN, "already.canonical.com")
    result = normalizer.normalize(ioc)
    assert result is ioc
