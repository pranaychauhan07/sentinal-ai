"""Narrow exception hierarchy for `core/parsers` — context/03_engineering_
constitution.md §5 ("every tool module defines its own narrow exception
classes ... callers need to be able to catch precisely"), applied to parsers.

Every exception here is a subclass of `core.exceptions.AppError` so it still
maps cleanly onto the shared API error envelope (constitution §6) if ever
raised across `apps/api`, while remaining specific enough for
`core/services/evidence_service.py` to catch precisely.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class ParserError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "PARSER_ERROR"


class UnsupportedFormatError(ParserError):
    """No registered parser matches the uploaded artifact (by declared type,
    extension, or content sniff). A rejected upload, not a partial parse."""

    code = "UNSUPPORTED_FORMAT"


class ParserValidationError(ParserError):
    """The artifact failed a validation rule before any parser attempted it
    (constitution §10, "input validation ... at the boundary")."""

    code = "PARSER_VALIDATION_ERROR"


class FileTooLargeError(ParserValidationError):
    """Upload exceeds the configured maximum size — the "prevent oversized
    uploads" / resource-exhaustion guard."""

    code = "FILE_TOO_LARGE"


class EmptyFileError(ParserValidationError):
    """Upload has zero bytes of content."""

    code = "EMPTY_FILE"


class PathTraversalError(ParserValidationError):
    """The declared filename attempts to escape its intended storage
    location (`..`, an absolute path, embedded null bytes)."""

    code = "PATH_TRAVERSAL_ATTEMPT"


class EncodingDetectionError(ParserError):
    """The artifact's byte content could not be decoded under any of the
    encodings this framework attempts (constitution §1.7 — this is raised,
    never silently mis-decoded, since misinterpreted bytes are worse than an
    explicit failure)."""

    code = "ENCODING_DETECTION_FAILED"


class MalformedEvidenceError(ParserError):
    """A parser's format-specific structural check failed (e.g. XML that
    doesn't parse at all, a CSV with no header row) — distinct from a
    partial/degraded parse, which returns a low-confidence
    `NormalizedEvidence` rather than raising."""

    code = "MALFORMED_EVIDENCE"
