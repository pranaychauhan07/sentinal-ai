"""Unit tests for core/vulnerabilities/cve_extractor.py."""

from __future__ import annotations

import pytest

from core.vulnerabilities.cve_extractor import (
    extract_cve_ids,
    extract_cwe_ids,
    is_valid_cve_id,
    normalize_cve_id,
)
from core.vulnerabilities.exceptions import InvalidCveIdError

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("CVE-2021-44228", True),
        ("cve-2021-44228", True),
        ("CVE-2021-123456789", True),
        ("CVE-1998-0001", False),  # before MITRE's earliest assignment year
        ("CVE-2021", False),
        ("not-a-cve", False),
        ("", False),
    ],
)
def test_is_valid_cve_id(candidate: str, expected: bool) -> None:
    assert is_valid_cve_id(candidate) is expected


def test_normalize_cve_id_uppercases() -> None:
    assert normalize_cve_id("cve-2021-44228") == "CVE-2021-44228"


def test_normalize_cve_id_rejects_malformed() -> None:
    with pytest.raises(InvalidCveIdError):
        normalize_cve_id("not-a-cve")


def test_extract_cve_ids_finds_multiple_distinct() -> None:
    text = "Affected by CVE-2021-44228 and CVE-2021-45046. Also see cve-2021-44228 again."
    assert extract_cve_ids(text) == ("CVE-2021-44228", "CVE-2021-45046")


def test_extract_cve_ids_empty_for_no_match() -> None:
    assert extract_cve_ids("no identifiers here") == ()


def test_extract_cwe_ids_finds_multiple_distinct() -> None:
    text = "Related to CWE-502 and CWE-20. Also CWE-502 again."
    assert extract_cwe_ids(text) == ("CWE-502", "CWE-20")
