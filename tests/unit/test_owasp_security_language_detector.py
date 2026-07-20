"""Unit tests for core/owasp_security/language_detector.py."""

from __future__ import annotations

import pytest

from core.owasp_security.language_detector import LanguageDetector
from core.owasp_security.models import SourceLanguage

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("app.py", SourceLanguage.PYTHON),
        ("app.pyw", SourceLanguage.PYTHON),
        ("app.js", SourceLanguage.JAVASCRIPT),
        ("app.jsx", SourceLanguage.JAVASCRIPT),
        ("app.mjs", SourceLanguage.JAVASCRIPT),
        ("app.ts", SourceLanguage.TYPESCRIPT),
        ("app.tsx", SourceLanguage.TYPESCRIPT),
        ("App.java", SourceLanguage.JAVA),
    ],
)
def test_detects_by_extension(filename: str, expected: SourceLanguage) -> None:
    assert LanguageDetector().detect(filename=filename, source_text="") == expected


def test_falls_back_to_content_heuristic_for_python() -> None:
    detector = LanguageDetector()
    result = detector.detect(filename="script", source_text="import os\ndef run():\n    pass\n")
    assert result == SourceLanguage.PYTHON


def test_falls_back_to_content_heuristic_for_java() -> None:
    detector = LanguageDetector()
    result = detector.detect(
        filename="unnamed", source_text="package com.example;\npublic class Main {}\n"
    )
    assert result == SourceLanguage.JAVA


def test_falls_back_to_content_heuristic_for_javascript() -> None:
    detector = LanguageDetector()
    result = detector.detect(filename="unnamed", source_text="const x = require('fs');\n")
    assert result == SourceLanguage.JAVASCRIPT


def test_unknown_for_unrecognized_content() -> None:
    detector = LanguageDetector()
    assert (
        detector.detect(filename="unnamed", source_text="just some plain text")
        == SourceLanguage.UNKNOWN
    )


def test_extension_wins_over_content_heuristic() -> None:
    detector = LanguageDetector()
    # Java-shaped content, but a .py extension: extension takes priority.
    result = detector.detect(
        filename="weird.py", source_text="package com.example;\npublic class Main {}\n"
    )
    assert result == SourceLanguage.PYTHON
