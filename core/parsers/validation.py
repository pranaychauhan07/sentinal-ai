"""Upload validation — the security boundary every artifact crosses before
any parser touches it (constitution §10, "input validation ... at the
boundary"; task requirement: "Prevent unsupported formats, oversized
uploads, malformed files, path traversal, unsafe parsing, resource
exhaustion").

Deliberately has zero dependency on any specific parser — it validates the
*upload*, not the format-specific content (that's each parser's
`validate_content`).
"""

from __future__ import annotations

import re

from core.config import Settings
from core.parsers.exceptions import (
    EmptyFileError,
    FileTooLargeError,
    PathTraversalError,
    UnsupportedFormatError,
)

#: Maximum number of records a single parser invocation will emit — the
#: resource-exhaustion guard for pathological inputs (e.g. a multi-gigabyte
#: log file within the size cap but with millions of one-byte "lines").
MAX_RECORDS_PER_ARTIFACT = 200_000

_PATH_TRAVERSAL_RE = re.compile(r"\.\.[/\\]|\x00")


def validate_filename(filename: str) -> str:
    """Reject a filename that attempts path traversal or embeds a null
    byte, and reject an absolute path — the caller must always treat the
    returned value as a bare filename, never a path to join verbatim onto a
    storage location without its own `os.path` safety check.
    """
    if not filename or filename.strip() == "":
        raise PathTraversalError("Filename must not be empty.")
    if _PATH_TRAVERSAL_RE.search(filename):
        raise PathTraversalError(
            "Filename contains a path traversal sequence or null byte.",
            details={"filename": filename},
        )
    if filename.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", filename):
        raise PathTraversalError(
            "Filename must not be an absolute path.", details={"filename": filename}
        )
    # Only the basename is ever trusted downstream.
    return filename.replace("\\", "/").rsplit("/", maxsplit=1)[-1]


def validate_extension(filename: str, settings: Settings) -> str:
    """Reject an extension outside `settings.evidence_allowed_extension_list`.
    Returns the lowercased extension (including the leading dot) on success.
    """
    suffix = "." + filename.rsplit(".", maxsplit=1)[-1].lower() if "." in filename else ""
    allowed = settings.evidence_allowed_extension_list
    if suffix not in allowed:
        raise UnsupportedFormatError(
            f"Extension '{suffix}' is not in the allowed list.",
            details={"filename": filename, "allowed": allowed},
        )
    return suffix


def validate_size(content: bytes, settings: Settings) -> None:
    """Reject empty uploads and uploads exceeding
    `settings.evidence_max_upload_bytes` (the oversized-upload /
    resource-exhaustion guard)."""
    if len(content) == 0:
        raise EmptyFileError("Uploaded file is empty.")
    if len(content) > settings.evidence_max_upload_bytes:
        raise FileTooLargeError(
            f"Upload of {len(content)} bytes exceeds the "
            f"{settings.evidence_max_upload_bytes}-byte limit.",
            details={
                "size_bytes": len(content),
                "max_bytes": settings.evidence_max_upload_bytes,
            },
        )


def validate_upload(filename: str, content: bytes, settings: Settings) -> tuple[str, str]:
    """Run the full upload-validation gate. Returns
    `(sanitized_filename, extension)` on success; raises a specific
    `core.parsers.exceptions.ParserError` subclass on the first failure."""
    sanitized = validate_filename(filename)
    extension = validate_extension(sanitized, settings)
    validate_size(content, settings)
    return sanitized, extension
