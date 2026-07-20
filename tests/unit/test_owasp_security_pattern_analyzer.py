"""Unit tests for core/owasp_security/pattern_analyzer.py — pattern-based
detection for JavaScript, TypeScript, and Java (no AST library available
for these languages, docs/adr/0021)."""

from __future__ import annotations

import pytest

from core.owasp_security.models import VulnerabilityCategory
from core.owasp_security.pattern_analyzer import PatternSourceAnalyzer

pytestmark = pytest.mark.unit

_analyzer = PatternSourceAnalyzer()


def _categories(source: str, language: str) -> set[VulnerabilityCategory]:
    findings = _analyzer.analyze(source, file_path="test", language=language)
    return {f.category for f in findings}


def test_js_command_injection_detected() -> None:
    source = "child_process.exec(cmd);\n"
    assert VulnerabilityCategory.COMMAND_INJECTION in _categories(source, "javascript")


def test_js_xss_innerhtml_detected() -> None:
    source = "el.innerHTML = userInput;\n"
    assert VulnerabilityCategory.XSS in _categories(source, "javascript")


def test_js_eval_detected_as_unsafe_deserialization() -> None:
    source = "eval(userInput);\n"
    assert VulnerabilityCategory.UNSAFE_DESERIALIZATION in _categories(source, "javascript")


def test_js_insecure_randomness_detected() -> None:
    source = "const token = Math.random();\n"
    assert VulnerabilityCategory.INSECURE_RANDOMNESS in _categories(source, "javascript")


def test_js_hardcoded_secret_detected() -> None:
    source = 'const apiKey = "sk-abcdef123456";\n'
    assert VulnerabilityCategory.HARDCODED_SECRETS in _categories(source, "javascript")


def test_js_insecure_tls_config_detected() -> None:
    source = "const opts = { rejectUnauthorized: false };\n"
    assert VulnerabilityCategory.INSECURE_CONFIGURATION in _categories(source, "javascript")


def test_ts_findings_share_js_rules() -> None:
    source = "el.innerHTML = userInput;\n"
    assert VulnerabilityCategory.XSS in _categories(source, "typescript")


def test_java_command_injection_detected() -> None:
    source = "Runtime.getRuntime().exec(cmd);\n"
    assert VulnerabilityCategory.COMMAND_INJECTION in _categories(source, "java")


def test_java_weak_cryptography_detected() -> None:
    source = 'MessageDigest.getInstance("MD5");\n'
    assert VulnerabilityCategory.WEAK_CRYPTOGRAPHY in _categories(source, "java")


def test_java_insecure_randomness_detected() -> None:
    source = "Random r = new Random();\n"
    assert VulnerabilityCategory.INSECURE_RANDOMNESS in _categories(source, "java")


def test_java_rule_not_applied_to_javascript() -> None:
    # A Java-only rule (Runtime.getRuntime().exec) must not match under the
    # javascript language filter, even if the literal text were present.
    source = "Runtime.getRuntime().exec(cmd);\n"
    assert VulnerabilityCategory.COMMAND_INJECTION not in _categories(source, "javascript")


def test_clean_javascript_produces_no_findings() -> None:
    source = "function add(a, b) {\n  return a + b;\n}\n"
    assert _analyzer.analyze(source, file_path="clean.js", language="javascript") == []


def test_findings_are_not_ast_based() -> None:
    source = "eval(x);\n"
    findings = _analyzer.analyze(source, file_path="test.js", language="javascript")
    assert findings
    assert all(not f.is_ast_based for f in findings)
    assert all(f.line_number == 1 for f in findings)


def test_line_numbers_are_real_for_multiline_source() -> None:
    source = "function ok() {}\n\neval(x);\n"
    findings = _analyzer.analyze(source, file_path="test.js", language="javascript")
    assert any(f.line_number == 3 for f in findings)
