"""Unit tests for core/parsers/validation.py — the upload security boundary."""

from __future__ import annotations

import pytest

from core.parsers.exceptions import (
    EmptyFileError,
    FileTooLargeError,
    PathTraversalError,
    UnsupportedFormatError,
)
from core.parsers.validation import (
    validate_extension,
    validate_filename,
    validate_size,
    validate_upload,
)


@pytest.mark.unit
def test_validate_filename_rejects_traversal() -> None:
    with pytest.raises(PathTraversalError):
        validate_filename("../../etc/passwd")


@pytest.mark.unit
def test_validate_filename_rejects_null_byte() -> None:
    with pytest.raises(PathTraversalError):
        validate_filename("evil\x00.log")


@pytest.mark.unit
def test_validate_filename_rejects_absolute_path() -> None:
    with pytest.raises(PathTraversalError):
        validate_filename("/etc/passwd")
    with pytest.raises(PathTraversalError):
        validate_filename("C:\\Windows\\System32\\evil.log")


@pytest.mark.unit
def test_validate_filename_rejects_empty() -> None:
    with pytest.raises(PathTraversalError):
        validate_filename("   ")


@pytest.mark.unit
def test_validate_filename_strips_directory_components() -> None:
    assert validate_filename("some/dir/evidence.log") == "evidence.log"


@pytest.mark.unit
def test_validate_extension_rejects_unsupported(test_settings) -> None:
    with pytest.raises(UnsupportedFormatError):
        validate_extension("payload.exe", test_settings)


@pytest.mark.unit
def test_validate_extension_accepts_allowed(test_settings) -> None:
    assert validate_extension("access.log", test_settings) == ".log"


@pytest.mark.unit
def test_validate_size_rejects_empty(test_settings) -> None:
    with pytest.raises(EmptyFileError):
        validate_size(b"", test_settings)


@pytest.mark.unit
def test_validate_size_rejects_oversized(test_settings) -> None:
    test_settings.evidence_max_upload_bytes = 10
    with pytest.raises(FileTooLargeError):
        validate_size(b"x" * 11, test_settings)


@pytest.mark.unit
def test_validate_upload_happy_path(test_settings) -> None:
    filename, extension = validate_upload("auth.log", b"some content", test_settings)
    assert filename == "auth.log"
    assert extension == ".log"
