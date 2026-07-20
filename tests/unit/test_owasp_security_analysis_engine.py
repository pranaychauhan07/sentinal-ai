"""Unit tests for core/owasp_security/analysis_engine.py — the
orchestrator, including adversarial/malformed-input, oversized-input, and
regression cases."""

from __future__ import annotations

import pytest

from core.owasp_security.analysis_engine import SourceCodeAnalysisEngine, sanitize_text
from core.owasp_security.exceptions import OversizedSourceInputError
from core.owasp_security.models import SastSeverity, SourceLanguage

pytestmark = pytest.mark.unit


def _engine(**overrides: int) -> SourceCodeAnalysisEngine:
    defaults = {"max_lines": 5000, "max_total_chars": 500_000}
    defaults.update(overrides)
    return SourceCodeAnalysisEngine(**defaults)  # type: ignore[arg-type]


def test_clean_python_file_is_info() -> None:
    advice = _engine().analyze("def add(a, b):\n    return a + b\n", filename="clean.py")
    assert advice.overall_risk_level == SastSeverity.INFO
    assert advice.sast_findings == ()
    assert advice.language == SourceLanguage.PYTHON
    assert advice.parse_degraded is False


def test_vulnerable_multiline_python_file_produces_findings() -> None:
    """Regression test: a real multi-line Python file must parse correctly
    end-to-end — this previously broke because the orchestrator ran a
    single-line-oriented `sanitize_text` over the *entire* source before
    AST parsing, collapsing every newline and making the whole file
    syntactically invalid (a bug caught by manual smoke-testing during
    development, see docs/adr/0021)."""
    source = "import os\n\ndef run(cmd):\n    os.system(cmd)\n    return True\n"
    advice = _engine().analyze(source, filename="app.py")
    assert advice.parse_degraded is False
    assert advice.total_line_count == 5
    assert len(advice.sast_findings) == 1
    assert advice.overall_risk_level in (SastSeverity.HIGH, SastSeverity.CRITICAL)


def test_unknown_language_degrades_gracefully() -> None:
    advice = _engine().analyze("just some plain text\nwith no code shape\n", filename="notes.txt")
    assert advice.parse_degraded is True
    assert advice.sast_findings == ()
    assert advice.overall_risk_level == SastSeverity.INFO
    assert "could not be determined" in advice.overall_explanation


def test_malformed_python_degrades_gracefully_not_a_crash() -> None:
    advice = _engine().analyze("def f(:\n    pass\n", filename="broken.py")
    assert advice.parse_degraded is True
    assert advice.sast_findings == ()
    assert "could not be parsed" in advice.overall_explanation


def test_oversized_line_count_rejected() -> None:
    engine = _engine(max_lines=2)
    with pytest.raises(OversizedSourceInputError):
        engine.analyze("a\nb\nc\n", filename="big.py")


def test_oversized_char_count_rejected() -> None:
    engine = _engine(max_lines=5000, max_total_chars=10)
    with pytest.raises(OversizedSourceInputError):
        engine.analyze("x" * 50, filename="big.py")


def test_javascript_file_uses_pattern_analysis() -> None:
    advice = _engine().analyze("eval(x);\n", filename="app.js")
    assert advice.language == SourceLanguage.JAVASCRIPT
    assert advice.sast_findings
    assert advice.parse_degraded is False


def test_control_characters_sanitized_in_snippet_helper() -> None:
    assert sanitize_text("hello\x00\x1fworld\r\nnext") == "helloworld next"
