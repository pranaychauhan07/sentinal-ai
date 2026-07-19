"""Parser selection — blueprint §9 step 3 ("routes to deterministic
parser"). Deterministic precedence, never a guess dressed up as one:

1. `declared_type` (caller already knows the format) → exact evidence-type match.
2. File extension → `ParserRegistry.find_by_extension`.
3. Content sniff → `core.parsers.detection.sniff_evidence_type`, matched back
   to a registered parser for that type.

Raises `UnsupportedFormatError` if none of the three resolves — a rejected
upload, never a silent guess (constitution §1.7).
"""

from __future__ import annotations

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.detection import sniff_evidence_type
from core.parsers.exceptions import UnsupportedFormatError
from core.parsers.models import EvidenceType
from core.parsers.registry import ParserRegistration, ParserRegistry


def select_parser(
    registry: ParserRegistry,
    raw: RawEvidenceInput,
    decoded_text: str,
    *,
    extension: str,
) -> BaseParser:
    """Resolve the single best-matching enabled parser for `raw`."""
    if raw.declared_type is not None and raw.declared_type != EvidenceType.UNKNOWN:
        by_type = registry.find_by_evidence_type(raw.declared_type)
        if by_type:
            return by_type[0].parser

    by_extension = registry.find_by_extension(extension)
    if by_extension:
        return _best_sniff_match(by_extension, raw, decoded_text)

    sniffed = sniff_evidence_type(raw.filename, decoded_text)
    for evidence_type, _confidence in sniffed:
        by_type = registry.find_by_evidence_type(evidence_type)
        if by_type:
            return by_type[0].parser

    raise UnsupportedFormatError(
        "No registered parser matches this evidence.",
        details={"filename": raw.filename, "extension": extension},
    )


def _best_sniff_match(
    candidates: list[ParserRegistration], raw: RawEvidenceInput, decoded_text: str
) -> BaseParser:
    """When more than one enabled parser claims the same extension (e.g.
    `.log` claimed by both `SshAuthParser` and `SyslogParser`), break the tie
    with each candidate's own `sniff()` confidence, falling back to registry
    priority order if every candidate is equally (un)confident."""
    if len(candidates) == 1:
        return candidates[0].parser

    scored = [
        (registration, registration.parser.sniff(raw, decoded_text)) for registration in candidates
    ]
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored[0][0].parser
