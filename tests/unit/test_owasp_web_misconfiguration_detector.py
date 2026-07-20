"""Unit tests for core/owasp_web/misconfiguration_detector.py."""

from __future__ import annotations

import pytest

from core.owasp_web.misconfiguration_detector import MisconfigurationDetector
from core.owasp_web.models import OwaspCategory

pytestmark = pytest.mark.unit


def test_benign_line_has_no_finding() -> None:
    assert MisconfigurationDetector().analyze("Welcome to our homepage.") is None


def test_directory_listing_flagged() -> None:
    finding = MisconfigurationDetector().analyze("Index of /backups")
    assert finding is not None
    assert "directory_listing_enabled" in finding.matched_rule_ids
    assert finding.category == OwaspCategory.A05_SECURITY_MISCONFIGURATION


def test_debug_endpoint_flagged() -> None:
    finding = MisconfigurationDetector().analyze("Reachable diagnostic path: /debug console")
    assert finding is not None
    assert "debug_endpoint_exposed" in finding.matched_rule_ids


def test_default_credentials_indicator_flagged() -> None:
    finding = MisconfigurationDetector().analyze("Login with admin/admin to continue")
    assert finding is not None
    assert "default_credentials_indicator" in finding.matched_rule_ids


def test_stack_trace_disclosure_flagged() -> None:
    finding = MisconfigurationDetector().analyze("Traceback (most recent call last):")
    assert finding is not None
    assert "stack_trace_disclosure" in finding.matched_rule_ids


def test_weak_tls_metadata_flagged() -> None:
    finding = MisconfigurationDetector().analyze("Server supports SSLv3 and RC4 ciphers")
    assert finding is not None
    assert "weak_tls_protocol_metadata" in finding.matched_rule_ids


def test_excessive_information_disclosure_flagged() -> None:
    finding = MisconfigurationDetector().analyze("Error writing to /var/www/uploads/tmp")
    assert finding is not None
    assert "excessive_information_disclosure" in finding.matched_rule_ids
