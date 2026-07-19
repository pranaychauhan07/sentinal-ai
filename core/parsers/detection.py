"""File/MIME/encoding detection — deliberately stdlib-only.

No `python-magic`/`chardet`/`charset-normalizer` dependency is introduced
(constitution §10, "a new third-party dependency is justified in its
introducing PR's description"): extension + a handful of documented content
heuristics are sufficient to disambiguate this framework's nine known
evidence formats, and BOM-sniffing plus a fixed utf-8/utf-8-sig/latin-1
fallback ladder covers the encodings real log exports use in practice.
"""

from __future__ import annotations

import json
import mimetypes
import re
from dataclasses import dataclass

from core.parsers.exceptions import EncodingDetectionError
from core.parsers.models import EvidenceType

_APACHE_COMBINED_RE = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[A-Z]+ \S+ \S+" \d{3} \S+')
_APACHE_ERROR_RE = re.compile(r"^\[[^\]]+\] \[[a-z:]+\] (\[pid \d+\] )?")
_SYSLOG_RE = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ \S+")
_SSH_AUTH_HINT_RE = re.compile(r"sshd\[\d+\]:")

#: Ordered fallback ladder for decoding bytes with no/ambiguous BOM.
_TEXT_ENCODING_LADDER: tuple[str, ...] = ("utf-8", "utf-8-sig", "latin-1")


@dataclass(frozen=True)
class EncodingDetectionResult:
    """Which encoding decoded the content, and how confident the guess is."""

    encoding: str
    confidence: float


def detect_encoding(content: bytes) -> tuple[str, EncodingDetectionResult]:
    """Decode `content` to text, returning the text and the detection
    result. Raises `EncodingDetectionError` only if every entry in the
    fallback ladder fails — `latin-1` is a total fallback (it never raises
    `UnicodeDecodeError`, since every byte value is a valid latin-1 code
    point), so this only happens for genuinely empty/degenerate input.
    """
    if content.startswith(b"\xef\xbb\xbf"):
        return content.decode("utf-8-sig"), EncodingDetectionResult("utf-8-sig", 1.0)
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        return content.decode("utf-16"), EncodingDetectionResult("utf-16", 1.0)

    for encoding in _TEXT_ENCODING_LADDER:
        try:
            text = content.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            continue
        confidence = 1.0 if encoding == "utf-8" else 0.6
        return text, EncodingDetectionResult(encoding, confidence)

    raise EncodingDetectionError(
        "Could not decode content under any supported encoding.",
        details={"attempted": list(_TEXT_ENCODING_LADDER)},
    )


def detect_mime_type(filename: str) -> str:
    """Extension-based MIME guess via stdlib `mimetypes`, falling back to
    `application/octet-stream` for extensions it doesn't know (e.g. `.log`,
    `.evtx`)."""
    guessed, _encoding = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"


def _first_nonblank_lines(text: str, count: int = 5) -> list[str]:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[:count]


def sniff_evidence_type(filename: str, decoded_text: str) -> list[tuple[EvidenceType, float]]:
    """Rank plausible `EvidenceType` candidates from filename + content
    heuristics. Used by `core.parsers.factory.select_parser` only when no
    declared type or extension match resolves the choice on its own.
    """
    candidates: list[tuple[EvidenceType, float]] = []
    stripped = decoded_text.lstrip()
    sample_lines = _first_nonblank_lines(decoded_text)
    first_line = sample_lines[0] if sample_lines else ""

    if stripped.startswith("<?xml") or stripped.startswith("<nmaprun"):
        candidates.append((EvidenceType.NMAP_XML, 0.9 if "<nmaprun" in stripped[:2000] else 0.4))

    if stripped.startswith("{") or stripped.startswith("["):
        try:
            json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            pass
        else:
            candidates.append((EvidenceType.JSON, 0.9))

    if first_line and "," in first_line and not first_line.startswith("#"):
        header_fields = [f.strip().lower() for f in first_line.split(",")]
        if {"eventid", "timecreated"} & set(header_fields):
            candidates.append((EvidenceType.WINDOWS_EVENT, 0.9))
        elif len(header_fields) >= 2:
            candidates.append((EvidenceType.CSV, 0.5))

    if any(_SSH_AUTH_HINT_RE.search(line) for line in sample_lines):
        candidates.append((EvidenceType.SSH_AUTH, 0.9))
    elif any(_SYSLOG_RE.match(line) for line in sample_lines):
        candidates.append((EvidenceType.SYSLOG, 0.7))

    if any(_APACHE_COMBINED_RE.match(line) for line in sample_lines):
        candidates.append((EvidenceType.APACHE_ACCESS, 0.9))
    elif any(_APACHE_ERROR_RE.match(line) for line in sample_lines):
        candidates.append((EvidenceType.APACHE_ERROR, 0.85))

    if not candidates and decoded_text.strip():
        candidates.append((EvidenceType.PLAIN_TEXT, 0.2))

    candidates.sort(key=lambda pair: pair[1], reverse=True)
    return candidates
