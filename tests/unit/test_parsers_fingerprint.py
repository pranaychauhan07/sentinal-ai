"""Unit tests for core/parsers/fingerprint.py."""

from __future__ import annotations

import hashlib

import pytest

from core.parsers.fingerprint import compute_sha256


@pytest.mark.unit
def test_compute_sha256_matches_hashlib() -> None:
    content = b"evidence bytes"
    fingerprint = compute_sha256(content)
    assert fingerprint.sha256 == hashlib.sha256(content).hexdigest()
    assert fingerprint.size_bytes == len(content)


@pytest.mark.unit
def test_compute_sha256_is_deterministic() -> None:
    content = b"same content"
    assert compute_sha256(content).sha256 == compute_sha256(content).sha256


@pytest.mark.unit
def test_compute_sha256_differs_for_different_content() -> None:
    assert compute_sha256(b"a").sha256 != compute_sha256(b"b").sha256
