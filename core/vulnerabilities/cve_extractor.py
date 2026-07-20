"""CVE/CWE extraction — pure regex discovery over free-text description
fields (task requirement: "CVE Extraction"). Scan-report parsers
(`core/parsers/{nessus,openvas}*.py`) already place a plugin's *structured*
CVE/CWE reference list into `EvidenceRecord.normalized_fields` when the
report provides one; this module is the fallback discovery path for
free-text descriptions/references that don't, and the single place both
paths' candidates are validated for correct MITRE ID shape (constitution
§1.9: deterministic, no LLM judgment in identifier discovery).
"""

from __future__ import annotations

import re

from core.vulnerabilities.exceptions import InvalidCveIdError

#: Official MITRE CVE ID syntax: `CVE-` + a 4-digit year + a hyphen +
#: 4-or-more digits (the sequence number has grown beyond 4 digits for
#: high-volume years, per MITRE's own 2014 syntax change).
_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-(\d+)\b", re.IGNORECASE)

#: Earliest year MITRE ever assigned a CVE ID under — anything before this
#: is a malformed/fabricated identifier, not a real CVE.
_MINIMUM_CVE_YEAR = 1999


def is_valid_cve_id(candidate: str) -> bool:
    """Structural validation only (constitution §1.9) — does not check
    whether the ID is actually registered with MITIRE/NVD (this framework
    makes no network calls, per blueprint §3's "no live" scope boundary)."""
    match = _CVE_RE.fullmatch(candidate.strip())
    if match is None:
        return False
    return int(match.group(1)) >= _MINIMUM_CVE_YEAR


def normalize_cve_id(candidate: str) -> str:
    """Canonical uppercase `CVE-YYYY-NNNN` form. Raises `InvalidCveIdError`
    if `candidate` isn't a well-formed CVE ID."""
    stripped = candidate.strip().upper()
    if not is_valid_cve_id(stripped):
        raise InvalidCveIdError(
            f"'{candidate}' is not a well-formed CVE identifier.", details={"candidate": candidate}
        )
    return stripped


def extract_cve_ids(text: str) -> tuple[str, ...]:
    """Every well-formed, distinct CVE ID found in `text`, in first-seen
    order. Malformed near-matches (a year before 1999) are silently excluded
    — they are not CVE IDs, not a validation failure of a real candidate."""
    seen: dict[str, None] = {}
    for match in _CVE_RE.finditer(text):
        candidate = match.group(0).upper()
        if int(match.group(1)) >= _MINIMUM_CVE_YEAR:
            seen.setdefault(candidate, None)
    return tuple(seen.keys())


def extract_cwe_ids(text: str) -> tuple[str, ...]:
    """Every distinct `CWE-<digits>` identifier found in `text`, in
    first-seen order, canonical uppercase form."""
    seen: dict[str, None] = {}
    for match in _CWE_RE.finditer(text):
        seen.setdefault(match.group(0).upper(), None)
    return tuple(seen.keys())
