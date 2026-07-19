"""Plain-text evidence parser — the last-resort, deterministic fallback for
unstructured evidence (analyst notes, pasted terminal transcripts) that
doesn't match any of the framework's structured formats.

Deliberately low-confidence and low-priority in the registry (see
`core.parsers.registry._register_builtin_parsers`): it never outranks a
structured parser, and `core.parsers.factory.select_parser` only reaches it
when nothing else claims the extension/content, or when the caller
explicitly declares `EvidenceType.PLAIN_TEXT`. This is *not* the blueprint's
LLM-assisted fallback (`core/agents/parser_agent.py`, unbuilt) — it performs
no reasoning at all, only a single whole-artifact record.
"""

from __future__ import annotations

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence, Severity


class PlainTextParser(BaseParser):
    name = "plain_text"
    description = "Fallback parser for unstructured plain-text evidence."
    evidence_type = EvidenceType.PLAIN_TEXT
    supported_extensions = (".txt",)
    supported_mime_types = ("text/plain",)

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        # Deliberately weak: any non-empty text "matches" plain text, but at
        # low confidence so a structured parser's sniff() always wins the
        # tie-break in core.parsers.factory._best_sniff_match.
        return 0.1 if decoded_text.strip() else 0.0

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        self.raise_if_invalid(bool(decoded_text.strip()), "Plain-text evidence is empty.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        lines = decoded_text.splitlines()
        record = EvidenceRecord(
            line_number=1,
            event_type="unstructured_note",
            severity=Severity.INFO,
            raw_line=decoded_text,
            normalized_fields={"line_count": len(lines), "char_count": len(decoded_text)},
        )
        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=0.3,
            records=[record],
            metadata={"line_count": len(lines)},
            unparsed_fragments=[],
            chain_of_custody=self._chain_of_custody(raw),
        )
