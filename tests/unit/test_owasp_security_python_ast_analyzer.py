"""Unit tests for core/owasp_security/python_ast_analyzer.py — genuine
AST-based detection covering all fifteen task-named vulnerability
categories for Python, plus malformed-source handling."""

from __future__ import annotations

import pytest

from core.owasp_security.exceptions import AstParseError
from core.owasp_security.models import VulnerabilityCategory
from core.owasp_security.python_ast_analyzer import PythonAstAnalyzer, build_ast

pytestmark = pytest.mark.unit

_analyzer = PythonAstAnalyzer()


def _categories(source: str) -> set[VulnerabilityCategory]:
    findings = _analyzer.analyze(source, file_path="test.py")
    return {f.category for f in findings}


def test_sql_injection_detected() -> None:
    source = "def f(user_id):\n    cursor.execute('SELECT * FROM t WHERE id=' + user_id)\n"
    assert VulnerabilityCategory.SQL_INJECTION in _categories(source)


def test_sql_injection_not_flagged_for_constant_query() -> None:
    source = "def f():\n    cursor.execute('SELECT * FROM t')\n"
    assert VulnerabilityCategory.SQL_INJECTION not in _categories(source)


def test_xss_mark_safe_detected() -> None:
    source = "def f(x):\n    return mark_safe(x)\n"
    assert VulnerabilityCategory.XSS in _categories(source)


def test_command_injection_os_system_detected() -> None:
    source = "import os\ndef f(cmd):\n    os.system(cmd)\n"
    assert VulnerabilityCategory.COMMAND_INJECTION in _categories(source)


def test_command_injection_subprocess_shell_true_detected() -> None:
    source = "import subprocess\ndef f(cmd):\n    subprocess.call(cmd, shell=True)\n"
    assert VulnerabilityCategory.COMMAND_INJECTION in _categories(source)


def test_command_injection_not_flagged_without_shell() -> None:
    source = "import subprocess\ndef f(cmd):\n    subprocess.call([cmd])\n"
    assert VulnerabilityCategory.COMMAND_INJECTION not in _categories(source)


def test_path_traversal_detected() -> None:
    source = "def f(name):\n    return open('/tmp/' + name)\n"
    assert VulnerabilityCategory.PATH_TRAVERSAL in _categories(source)


def test_path_traversal_not_flagged_for_constant_path() -> None:
    source = "def f():\n    return open('/tmp/fixed.txt')\n"
    assert VulnerabilityCategory.PATH_TRAVERSAL not in _categories(source)


def test_ssrf_detected() -> None:
    source = "import requests\ndef f(host):\n    return requests.get('http://' + host)\n"
    assert VulnerabilityCategory.SSRF in _categories(source)


def test_hardcoded_secrets_detected() -> None:
    source = 'API_TOKEN = "abcdef123456"\n'
    assert VulnerabilityCategory.HARDCODED_SECRETS in _categories(source)


def test_hardcoded_secrets_not_flagged_for_short_value() -> None:
    source = 'API_TOKEN = "x"\n'
    assert VulnerabilityCategory.HARDCODED_SECRETS not in _categories(source)


def test_weak_cryptography_md5_detected() -> None:
    source = "import hashlib\ndef f(x):\n    return hashlib.md5(x)\n"
    assert VulnerabilityCategory.WEAK_CRYPTOGRAPHY in _categories(source)


def test_insecure_randomness_detected() -> None:
    source = "import random\ndef f():\n    return random.randint(1, 10)\n"
    assert VulnerabilityCategory.INSECURE_RANDOMNESS in _categories(source)


def test_unsafe_deserialization_pickle_detected() -> None:
    source = "import pickle\ndef f(data):\n    return pickle.loads(data)\n"
    assert VulnerabilityCategory.UNSAFE_DESERIALIZATION in _categories(source)


def test_unsafe_deserialization_eval_detected() -> None:
    source = "def f(x):\n    return eval(x)\n"
    assert VulnerabilityCategory.UNSAFE_DESERIALIZATION in _categories(source)


def test_unsafe_deserialization_yaml_safe_load_not_flagged() -> None:
    source = "import yaml\ndef f(x):\n    return yaml.load(x, Loader=yaml.SafeLoader)\n"
    assert VulnerabilityCategory.UNSAFE_DESERIALIZATION not in _categories(source)


def test_unsafe_deserialization_yaml_unsafe_load_flagged() -> None:
    source = "import yaml\ndef f(x):\n    return yaml.load(x)\n"
    assert VulnerabilityCategory.UNSAFE_DESERIALIZATION in _categories(source)


def test_broken_authentication_detected() -> None:
    source = "def f(password, submitted):\n    if password == submitted:\n        return True\n"
    assert VulnerabilityCategory.BROKEN_AUTHENTICATION in _categories(source)


def test_missing_input_validation_detected() -> None:
    source = "def f():\n    os.system(input())\n"
    assert VulnerabilityCategory.MISSING_INPUT_VALIDATION in _categories(source)


def test_dangerous_file_operations_remove_detected() -> None:
    source = "import os\ndef f(path):\n    os.remove(path)\n"
    assert VulnerabilityCategory.DANGEROUS_FILE_OPERATIONS in _categories(source)


def test_dangerous_file_operations_chmod_777_detected() -> None:
    source = "import os\ndef f(path):\n    os.chmod(path, 0o777)\n"
    assert VulnerabilityCategory.DANGEROUS_FILE_OPERATIONS in _categories(source)


def test_open_redirect_detected() -> None:
    source = "def f(target):\n    return redirect(target)\n"
    assert VulnerabilityCategory.OPEN_REDIRECT in _categories(source)


def test_open_redirect_not_flagged_for_constant_target() -> None:
    source = "def f():\n    return redirect('/home')\n"
    assert VulnerabilityCategory.OPEN_REDIRECT not in _categories(source)


def test_sensitive_information_exposure_detected() -> None:
    source = 'PASSWORD = "hunter2xyz"\ndef f():\n    print(PASSWORD)\n'
    assert VulnerabilityCategory.SENSITIVE_INFORMATION_EXPOSURE in _categories(source)


def test_insecure_configuration_debug_true_detected() -> None:
    source = "DEBUG = True\n"
    assert VulnerabilityCategory.INSECURE_CONFIGURATION in _categories(source)


def test_insecure_configuration_verify_false_detected() -> None:
    source = "import requests\ndef f(url):\n    return requests.get(url, verify=False)\n"
    assert VulnerabilityCategory.INSECURE_CONFIGURATION in _categories(source)


def test_clean_file_produces_no_findings() -> None:
    source = "def add(a, b):\n    return a + b\n"
    assert _analyzer.analyze(source, file_path="clean.py") == []


def test_all_findings_are_ast_based() -> None:
    source = "import os\ndef f(cmd):\n    os.system(cmd)\n"
    findings = _analyzer.analyze(source, file_path="test.py")
    assert findings
    assert all(f.is_ast_based for f in findings)
    assert all(f.line_number is not None for f in findings)


def test_malformed_source_raises_ast_parse_error() -> None:
    with pytest.raises(AstParseError):
        build_ast("def f(:\n    pass\n", filename="broken.py")


def test_analyzer_propagates_ast_parse_error_for_malformed_source() -> None:
    with pytest.raises(AstParseError):
        _analyzer.analyze("def f(:\n    pass\n", file_path="broken.py")
