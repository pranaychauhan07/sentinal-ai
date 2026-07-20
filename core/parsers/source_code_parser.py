"""``SourceCodeParser`` — evidence intake for the OWASP Security Agent
(blueprint §7's source-code/API static reviewer;
`docs/adr/0021-owasp-security-agent-ast-sast.md`).

Deliberately different from every other parser's per-line-record
convention (`linux_command_parser.py`/`http_transaction_parser.py`): AST
parsing needs a source file's *whole* text as one syntactic unit, so this
parser produces exactly **one** `EvidenceRecord` per uploaded file
(`event_type="source_file"`, `raw_line=<the full decoded source text>`).
Language detection is deliberately **not** done here — that's
`core.owasp_security.language_detector.LanguageDetector`'s job, run by
`core.services.owasp_security_service.py` — matching the established
"parsers extract structure only where unambiguous" precedent.

`sniff()` gives this parser a real, above-`PlainTextParser` (0.1) confidence
when the content looks like Python/JavaScript/TypeScript/Java source
(reusing a small subset of `LanguageDetector`'s own content heuristics),
registered in `core.parsers.registry` at priority 3.
"""

from __future__ import annotations

import re

from core.parsers.base import BaseParser, RawEvidenceInput
from core.parsers.models import EvidenceRecord, EvidenceType, NormalizedEvidence, Severity

_SOURCE_EXTENSIONS = (".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java")

#: A small subset of source-code content shapes, used only as a `sniff()`
#: confidence signal — not the language detector itself.
_SOURCE_CONTENT_HEURISTICS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*(?:import\s+\w+|from\s+\w+(?:\.\w+)*\s+import\s)", re.MULTILINE),
    re.compile(r"^\s*def\s+\w+\s*\([^)]*\)\s*:", re.MULTILINE),
    re.compile(
        r"^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?class\s+\w+", re.MULTILINE
    ),
    re.compile(r"^\s*package\s+[\w.]+;", re.MULTILINE),
    re.compile(r"\b(?:function\s+\w*\s*\(|const\s+\w+\s*=|require\(|=>\s*\{)"),
    re.compile(r"^\s*interface\s+\w+\s*\{", re.MULTILINE),
)

_SNIFF_CONFIDENCE_MATCH = 0.4
_SNIFF_CONFIDENCE_NONE = 0.0


def _looks_like_source_code(text: str) -> bool:
    return any(pattern.search(text) for pattern in _SOURCE_CONTENT_HEURISTICS)


class SourceCodeParser(BaseParser):
    name = "source_code"
    description = (
        "Parser for source code files (Python/JavaScript/TypeScript/Java) — "
        "one EvidenceRecord per uploaded file, carrying the full decoded "
        "source text; language detection and vulnerability analysis are the "
        "OWASP Security Agent's own job."
    )
    evidence_type = EvidenceType.SOURCE_CODE
    supported_extensions = _SOURCE_EXTENSIONS
    supported_mime_types = ("text/x-python", "application/javascript", "text/x-java-source")

    def sniff(self, raw: RawEvidenceInput, decoded_text: str) -> float:
        if _looks_like_source_code(decoded_text):
            return _SNIFF_CONFIDENCE_MATCH
        return _SNIFF_CONFIDENCE_NONE

    def validate_content(self, raw: RawEvidenceInput, decoded_text: str) -> None:
        self.raise_if_invalid(bool(decoded_text.strip()), "Source code input is empty.")

    def parse_content(self, raw: RawEvidenceInput, decoded_text: str) -> NormalizedEvidence:
        record = EvidenceRecord(
            line_number=1,
            event_type="source_file",
            severity=Severity.INFO,
            raw_line=decoded_text,
            normalized_fields={
                "filename": raw.filename,
                "line_count": len(decoded_text.splitlines()),
            },
        )
        return NormalizedEvidence(
            evidence_type=self.evidence_type,
            source=raw.filename,
            parser_name=self.name,
            parser_version=self.version,
            confidence=0.6,
            records=[record],
            metadata={"line_count": len(decoded_text.splitlines())},
            unparsed_fragments=[],
            chain_of_custody=self._chain_of_custody(raw),
        )
