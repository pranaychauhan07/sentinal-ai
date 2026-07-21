"""Unit tests for core/threat_intel/patterns.py."""

from __future__ import annotations

import time

import pytest

from core.threat_intel.models import IOCType
from core.threat_intel.patterns import IOC_PATTERNS, refang


@pytest.mark.unit
def test_ipv4_pattern_matches_valid_address() -> None:
    match = IOC_PATTERNS[IOCType.IPV4].search("connection from 192.168.1.1 accepted")
    assert match is not None
    assert match.group(0) == "192.168.1.1"


@pytest.mark.unit
def test_domain_pattern_matches() -> None:
    match = IOC_PATTERNS[IOCType.DOMAIN].search("beaconing to evil.example.com over https")
    assert match is not None
    assert match.group(0) == "evil.example.com"


@pytest.mark.unit
def test_sha256_pattern_requires_exact_length() -> None:
    valid = "a" * 64
    assert IOC_PATTERNS[IOCType.SHA256].search(f"hash={valid}") is not None
    assert IOC_PATTERNS[IOCType.SHA256].search(f"hash={'a' * 63}") is None


@pytest.mark.unit
def test_refang_reverses_common_defanging_conventions() -> None:
    assert refang("hxxp://evil[.]example[.]com") == "http://evil.example.com"
    assert refang("user(at)example(dot)com") == "user@example.com"


@pytest.mark.unit
def test_refang_is_idempotent_on_already_live_text() -> None:
    text = "http://example.com/path"
    assert refang(text) == text


@pytest.mark.unit
@pytest.mark.parametrize("ioc_type", list(IOC_PATTERNS))
def test_every_pattern_compiles_and_matches_bounded_text_quickly(ioc_type: IOCType) -> None:
    """Regression guard for catastrophic backtracking: every pattern must
    finish scanning a worst-case-shaped 5,000-character string well under a
    second."""
    pattern = IOC_PATTERNS[ioc_type]
    adversarial_text = ("a" * 200 + " ") * 25  # 5,000+ chars, no matches
    started = time.monotonic()
    pattern.findall(adversarial_text)
    elapsed = time.monotonic() - started
    assert elapsed < 1.0


# --- FILE_NAME false-positive regression tests -----------------------------
# A real investigation found the previous FILE_NAME pattern
# (`\b[\w,\s-]{1,100}\.[A-Za-z0-9]{1,10}\b`) matching IP-address octet
# fragments and whole log-line phrases as "file names," which then fed
# spurious MITRE mappings (T1027/T1036/T1204) downstream. These tests pin
# both the false-positive fix and genuine file-name detection so neither
# regresses.


@pytest.mark.unit
@pytest.mark.parametrize(
    "text",
    [
        "Failed password for root from 203.0.113.44 port 51422 ssh2",
        "connection from 203.0.113.44 to 198.51.100.9",
        "host 198.51.100.23 responded",
        "203.0.113.44",
    ],
)
def test_file_name_pattern_does_not_match_ip_fragments_or_log_prose(text: str) -> None:
    assert IOC_PATTERNS[IOCType.FILE_NAME].search(text) is None


@pytest.mark.unit
@pytest.mark.parametrize(
    "text,expected",
    [
        ("dropped payload.exe to disk", "payload.exe"),
        ("uploaded invoice.docx as an attachment", "invoice.docx"),
        ("wrote backup-2026.tar.gz to /tmp", "backup-2026.tar"),
        ("execution of malware.dll detected", "malware.dll"),
    ],
)
def test_file_name_pattern_matches_genuine_file_names(text: str, expected: str) -> None:
    match = IOC_PATTERNS[IOCType.FILE_NAME].search(text)
    assert match is not None
    assert match.group(0).lower() == expected.lower()


@pytest.mark.unit
def test_file_name_pattern_rejects_purely_numeric_extension() -> None:
    # A bare "word.42"-shaped token (no letters in the "extension") must
    # never match — this is exactly the shape of an IP octet's tail.
    assert IOC_PATTERNS[IOCType.FILE_NAME].search("value is 113.44 exactly") is None
