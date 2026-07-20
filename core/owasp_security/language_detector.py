"""``LanguageDetector`` — the task's named "Language Detection" capability.

Detects a source file's language from its filename extension first (cheap,
reliable when present), falling back to a small set of content heuristics
when the extension is missing/ambiguous. `SourceLanguage.UNKNOWN` is a real,
reachable outcome — never silently guessed as Python (constitution §1.7).
"""

from __future__ import annotations

import re

from core.owasp_security.models import SourceLanguage

_EXTENSION_MAP: dict[str, SourceLanguage] = {
    ".py": SourceLanguage.PYTHON,
    ".pyw": SourceLanguage.PYTHON,
    ".js": SourceLanguage.JAVASCRIPT,
    ".jsx": SourceLanguage.JAVASCRIPT,
    ".mjs": SourceLanguage.JAVASCRIPT,
    ".cjs": SourceLanguage.JAVASCRIPT,
    ".ts": SourceLanguage.TYPESCRIPT,
    ".tsx": SourceLanguage.TYPESCRIPT,
    ".java": SourceLanguage.JAVA,
}

#: Content heuristics, checked in order, only when the extension is
#: missing/unrecognized. Each is a `(pattern, language)` pair; the first
#: match wins.
_CONTENT_HEURISTICS: tuple[tuple[re.Pattern[str], SourceLanguage], ...] = (
    (re.compile(r"^#!.*\bpython[0-9.]*\b", re.MULTILINE), SourceLanguage.PYTHON),
    (
        re.compile(r"^\s*(?:import\s+\w+|from\s+\w+(?:\.\w+)*\s+import\s)", re.MULTILINE),
        SourceLanguage.PYTHON,
    ),
    (re.compile(r"^\s*def\s+\w+\s*\([^)]*\)\s*:", re.MULTILINE), SourceLanguage.PYTHON),
    (
        re.compile(r"^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?class\s+\w+"),
        SourceLanguage.JAVA,
    ),
    (re.compile(r"^\s*package\s+[\w.]+;", re.MULTILINE), SourceLanguage.JAVA),
    (re.compile(r":\s*(?:string|number|boolean|any|void)\b"), SourceLanguage.TYPESCRIPT),
    (re.compile(r"^\s*interface\s+\w+\s*\{", re.MULTILINE), SourceLanguage.TYPESCRIPT),
    (
        re.compile(r"\b(?:function\s+\w*\s*\(|const\s+\w+\s*=|require\(|=>\s*\{)"),
        SourceLanguage.JAVASCRIPT,
    ),
)


class LanguageDetector:
    def detect(self, *, filename: str, source_text: str) -> SourceLanguage:
        extension = self._extension_of(filename)
        if extension in _EXTENSION_MAP:
            return _EXTENSION_MAP[extension]
        for pattern, language in _CONTENT_HEURISTICS:
            if pattern.search(source_text):
                return language
        return SourceLanguage.UNKNOWN

    @staticmethod
    def _extension_of(filename: str) -> str:
        lowered = filename.lower()
        dot_index = lowered.rfind(".")
        if dot_index == -1:
            return ""
        return lowered[dot_index:]
