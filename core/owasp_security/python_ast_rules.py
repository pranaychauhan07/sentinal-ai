"""Default AST-predicate rule set for Python — `python_ast_analyzer.py`'s
detection logic, registered via `rule_engine.register_ast_predicate` and
declared as `Rule`s in `DEFAULT_PYTHON_AST_RULES`.

Every predicate is a heuristic, not full taint tracking (docs/adr/0021
point 7): each flags an AST shape strongly correlated with the named
vulnerability category (e.g. a `.execute(...)` call whose argument is
dynamically built rather than a constant) without proving the dynamic
content is actually attacker-controlled. Each predicate's docstring states
its detection basis and known false-positive shape explicitly.
"""

from __future__ import annotations

import ast
import re

from core.owasp_security.models import MatcherKind, SastSeverity, VulnerabilityCategory
from core.owasp_security.rule_engine import Matcher, Rule, register_ast_predicate

#: Cookie/token/secret-like identifier fragments used by several predicates
#: below to raise/lower confidence or gate a check to security-relevant
#: variable names.
_SECRET_NAME_PATTERN = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)


def _dotted_name(node: ast.expr) -> str | None:
    """Reconstructs a dotted call target name (`os.system`, `hashlib.md5`)
    from a `Call.func` node, or `None` if it isn't a simple attribute/name
    chain (e.g. a subscript or a call result)."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    else:
        return None
    return ".".join(reversed(parts))


def _line_snippet(source_lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()
    return ""


def _is_dynamic_string(node: ast.expr) -> bool:
    """True if `node` is a string built at runtime (f-string, `%`-format,
    `+`-concatenation, `.format(...)` call) rather than a plain constant —
    the SQL-injection/path-traversal/SSRF/command-injection shared
    heuristic: a sink fed a dynamically-built string is worth flagging,
    even though this cannot prove the dynamic part is attacker-controlled."""
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod | ast.Add):
        return True
    if isinstance(node, ast.Call):
        target = _dotted_name(node.func)
        if target and target.endswith(".format"):
            return True
    return not isinstance(node, ast.Constant)


def _iter_calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


# --- 1. SQL Injection -------------------------------------------------------

_SQL_EXECUTE_METHODS = frozenset({"execute", "executemany", "raw", "executescript"})


def _detect_sql_injection(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags `<cursor/connection>.execute*(...)` calls whose first argument
    is a dynamically-built string rather than a constant/parameterized
    placeholder. False positives: a dynamically-built but fully
    trusted/constant-sourced query string."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in _SQL_EXECUTE_METHODS:
            continue
        if not call.args:
            continue
        if _is_dynamic_string(call.args[0]):
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
    return matches


register_ast_predicate("py_sql_injection", _detect_sql_injection)


# --- 2. Cross-Site Scripting -------------------------------------------------

_XSS_SINK_NAMES = frozenset({"mark_safe", "render_template_string"})


def _detect_xss(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags Django `mark_safe(...)` (disables auto-escaping) and Flask
    `render_template_string(...)` (renders a template built from a string,
    often user-influenced) calls. False positives: `mark_safe` applied to
    genuinely static, developer-authored HTML."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        name = _dotted_name(call.func)
        if name is None:
            continue
        if name.split(".")[-1] in _XSS_SINK_NAMES:
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
    return matches


register_ast_predicate("py_xss", _detect_xss)


# --- 3. Command Injection ----------------------------------------------------

_SHELL_CALL_NAMES = frozenset({"system", "popen"})
_SUBPROCESS_NAMES = frozenset({"call", "run", "Popen", "check_call", "check_output"})


def _detect_command_injection(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags `os.system`/`os.popen` (always shell-interpreted) and any
    `subprocess.*` call passed `shell=True`. False positives: none for
    `os.system`/`os.popen` (always shell-based); `subprocess` calls with
    `shell=True` but a hardcoded, non-dynamic command are still flagged
    (shell=True is itself the risk surface regardless of the command)."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        name = _dotted_name(call.func)
        if name is None:
            continue
        short = name.split(".")[-1]
        if short in _SHELL_CALL_NAMES and name.startswith(("os.", "os")):
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
            continue
        if short in _SUBPROCESS_NAMES:
            for kw in call.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
                    break
    return matches


register_ast_predicate("py_command_injection", _detect_command_injection)


# --- 4. Path Traversal -------------------------------------------------------

_FILE_OPEN_NAMES = frozenset({"open"})


def _detect_path_traversal(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags `open(...)` calls whose path argument is dynamically built
    (string concatenation/f-string) rather than constant. False positives:
    a dynamically-built path that is actually validated/sanitized upstream
    (this predicate does no data-flow analysis)."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        if not isinstance(call.func, ast.Name) or call.func.id not in _FILE_OPEN_NAMES:
            continue
        if not call.args:
            continue
        if _is_dynamic_string(call.args[0]):
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
    return matches


register_ast_predicate("py_path_traversal", _detect_path_traversal)


# --- 5. SSRF ------------------------------------------------------------------

_HTTP_CALL_NAMES = frozenset({"get", "post", "put", "delete", "patch", "urlopen", "request"})


def _detect_ssrf(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags `requests.<verb>(...)`/`urllib.request.urlopen(...)` calls
    whose URL argument is dynamically built rather than constant. False
    positives: a dynamic URL restricted to a known-safe allowlist upstream
    (not visible to this predicate)."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        name = _dotted_name(call.func)
        if name is None:
            continue
        short = name.split(".")[-1]
        if short not in _HTTP_CALL_NAMES:
            continue
        if "requests" not in name and "urlopen" not in name and "urllib" not in name:
            continue
        if not call.args:
            continue
        if _is_dynamic_string(call.args[0]):
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
    return matches


register_ast_predicate("py_ssrf", _detect_ssrf)


# --- 6. Hardcoded Secrets -----------------------------------------------------


def _detect_hardcoded_secrets(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags `Assign` statements where the target name looks secret-like
    (password/token/api_key/...) and the assigned value is a non-trivial
    string literal. False positives: a variable named like a secret that
    actually holds a placeholder/example value."""
    matches: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            continue
        if len(node.value.value) < 6:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and _SECRET_NAME_PATTERN.search(target.id):
                matches.append((node.lineno, _line_snippet(source_lines, node.lineno)))
                break
    return matches


register_ast_predicate("py_hardcoded_secrets", _detect_hardcoded_secrets)


# --- 7. Weak Cryptography ----------------------------------------------------

_WEAK_HASH_NAMES = frozenset({"md5", "sha1"})


def _detect_weak_cryptography(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags `hashlib.md5(...)`/`hashlib.sha1(...)` calls. False positives:
    MD5/SHA1 used for a non-security checksum (e.g. cache-busting), not
    password/signature hashing — this predicate cannot distinguish intent."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        name = _dotted_name(call.func)
        if name is None:
            continue
        if name.split(".")[-1] in _WEAK_HASH_NAMES and "hashlib" in name:
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
    return matches


register_ast_predicate("py_weak_cryptography", _detect_weak_cryptography)


# --- 8. Insecure Randomness ---------------------------------------------------

_RANDOM_MODULE_CALLS = frozenset({"random", "randint", "choice", "randrange", "uniform"})


def _detect_insecure_randomness(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags `random.<fn>(...)` calls — the stdlib `random` module is not
    cryptographically secure. False positives: `random` used for a
    non-security purpose (e.g. shuffling a game deck) — this predicate
    flags every call regardless of context; `secrets`/`os.urandom` is
    always the safer recommendation when security matters."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        name = _dotted_name(call.func)
        if name is None:
            continue
        parts = name.split(".")
        if len(parts) >= 2 and parts[0] == "random" and parts[-1] in _RANDOM_MODULE_CALLS:
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
    return matches


register_ast_predicate("py_insecure_randomness", _detect_insecure_randomness)


# --- 9. Unsafe Deserialization -------------------------------------------------

_UNSAFE_DESERIALIZATION_CALLS = frozenset({"loads", "load"})


def _detect_unsafe_deserialization(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags `pickle.load(s)(...)` (arbitrary code execution on untrusted
    input), bare `eval(...)`/`exec(...)`, and `yaml.load(...)` without an
    explicit `Loader=yaml.SafeLoader`/`CSafeLoader` keyword. False
    positives: `pickle`/`yaml.load` used only on fully trusted, internally
    generated data."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        name = _dotted_name(call.func)
        if name is None:
            continue
        if isinstance(call.func, ast.Name) and name in ("eval", "exec"):
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
            continue
        parts = name.split(".")
        if parts[0] == "pickle" and parts[-1] in _UNSAFE_DESERIALIZATION_CALLS:
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
            continue
        if parts[-1] == "load" and "yaml" in name:
            has_safe_loader = any(
                kw.arg == "Loader"
                and isinstance(kw.value, ast.Attribute)
                and "Safe" in kw.value.attr
                for kw in call.keywords
            )
            if not has_safe_loader:
                matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
    return matches


register_ast_predicate("py_unsafe_deserialization", _detect_unsafe_deserialization)


# --- 10. Broken Authentication -------------------------------------------------


def _detect_broken_authentication(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags a direct `==`/`!=` comparison where one side is a name/attribute
    that looks like a password/token and the other is anything (a classic
    timing-attack-prone credential check that should use a constant-time
    comparison, e.g. `hmac.compare_digest`). False positives: a comparison
    against a non-secret field that happens to be named similarly."""
    matches: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, ast.Eq | ast.NotEq) for op in node.ops):
            continue
        operands = [node.left, *node.comparators]
        for operand in operands:
            candidate_name = None
            if isinstance(operand, ast.Name):
                candidate_name = operand.id
            elif isinstance(operand, ast.Attribute):
                candidate_name = operand.attr
            if candidate_name and _SECRET_NAME_PATTERN.search(candidate_name):
                matches.append((node.lineno, _line_snippet(source_lines, node.lineno)))
                break
    return matches


register_ast_predicate("py_broken_authentication", _detect_broken_authentication)


# --- 11. Missing Input Validation ----------------------------------------------

_VALIDATION_SINK_NAMES = frozenset({"system", "popen", "execute", "eval", "exec", "open"})


def _detect_missing_input_validation(
    tree: ast.AST, source_lines: list[str]
) -> list[tuple[int, str]]:
    """Flags the builtin `input(...)` call result used directly (same
    expression statement, or assigned and used on the very next statement)
    as an argument to a known sink call, with no intervening validation
    call. Deliberately narrow and heuristic-only (documented, not
    exhaustive) — this predicate does no real data-flow analysis."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        target = _dotted_name(call.func) or (
            call.func.id if isinstance(call.func, ast.Name) else None
        )
        if target is None:
            continue
        if target.split(".")[-1] not in _VALIDATION_SINK_NAMES:
            continue
        for arg in call.args:
            if (
                isinstance(arg, ast.Call)
                and isinstance(arg.func, ast.Name)
                and arg.func.id == "input"
            ):
                matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
                break
    return matches


register_ast_predicate("py_missing_input_validation", _detect_missing_input_validation)


# --- 12. Dangerous File Operations ---------------------------------------------

_DANGEROUS_FILE_OP_NAMES = frozenset({"remove", "rmdir", "rmtree", "unlink"})


def _detect_dangerous_file_operations(
    tree: ast.AST, source_lines: list[str]
) -> list[tuple[int, str]]:
    """Flags `os.remove`/`os.rmdir`/`os.unlink`/`shutil.rmtree` calls and
    `os.chmod(..., 0o777)`-style overly permissive mode changes. False
    positives: a deletion of a path that is always a fixed, trusted,
    application-internal temp file."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        name = _dotted_name(call.func)
        if name is None:
            continue
        short = name.split(".")[-1]
        if short in _DANGEROUS_FILE_OP_NAMES:
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
            continue
        if short == "chmod" and len(call.args) >= 2:
            mode_arg = call.args[1]
            if isinstance(mode_arg, ast.Constant) and mode_arg.value in (0o777, 0o666):
                matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
    return matches


register_ast_predicate("py_dangerous_file_operations", _detect_dangerous_file_operations)


# --- 13. Open Redirect ---------------------------------------------------------


def _detect_open_redirect(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags Flask/Django `redirect(...)` calls whose target argument is
    dynamically built rather than a constant literal. False positives: a
    dynamic redirect target validated against an allowlist upstream (not
    visible to this predicate)."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        name = _dotted_name(call.func)
        if name is None:
            continue
        if name.split(".")[-1] != "redirect":
            continue
        if not call.args:
            continue
        if _is_dynamic_string(call.args[0]):
            matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
    return matches


register_ast_predicate("py_open_redirect", _detect_open_redirect)


# --- 14. Sensitive Information Exposure ----------------------------------------

_LOGGING_SINK_MODULES = frozenset(
    {"print", "debug", "info", "warning", "error", "critical", "exception"}
)


def _detect_sensitive_information_exposure(
    tree: ast.AST, source_lines: list[str]
) -> list[tuple[int, str]]:
    """Flags `print(...)`/`logging.*(...)` calls with an argument that is a
    bare name/attribute whose identifier looks secret-like. False
    positives: a variable named similarly to a secret that holds a
    non-sensitive value (e.g. `token_count`)."""
    matches: list[tuple[int, str]] = []
    for call in _iter_calls(tree):
        name = _dotted_name(call.func)
        if name is None:
            continue
        if name.split(".")[-1] not in _LOGGING_SINK_MODULES:
            continue
        for arg in call.args:
            candidate_name = None
            if isinstance(arg, ast.Name):
                candidate_name = arg.id
            elif isinstance(arg, ast.Attribute):
                candidate_name = arg.attr
            if candidate_name and _SECRET_NAME_PATTERN.search(candidate_name):
                matches.append((call.lineno, _line_snippet(source_lines, call.lineno)))
                break
    return matches


register_ast_predicate("py_sensitive_information_exposure", _detect_sensitive_information_exposure)


# --- 15. Insecure Configuration -------------------------------------------------


def _detect_insecure_configuration(tree: ast.AST, source_lines: list[str]) -> list[tuple[int, str]]:
    """Flags `DEBUG = True` module-level assignment and any call passed
    `verify=False` (disables TLS certificate verification, e.g.
    `requests.get(url, verify=False)`). False positives: `DEBUG = True`
    intentionally set in a test-only module (this predicate has no
    file-path-based exemption)."""
    matches: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == "DEBUG"
                    and isinstance(node.value, ast.Constant)
                    and node.value.value is True
                ):
                    matches.append((node.lineno, _line_snippet(source_lines, node.lineno)))
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if (
                    kw.arg == "verify"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                ):
                    matches.append((node.lineno, _line_snippet(source_lines, node.lineno)))
    return matches


register_ast_predicate("py_insecure_configuration", _detect_insecure_configuration)


def _ast_rule(
    rule_id: str,
    *,
    name: str,
    category: VulnerabilityCategory,
    severity: SastSeverity,
    confidence: float,
    predicate_name: str,
    explanation: str,
    recommendation: str,
    priority: int,
) -> Rule:
    return Rule(
        id=rule_id,
        name=name,
        category=category,
        severity=severity,
        confidence=confidence,
        matcher=Matcher(kind=MatcherKind.AST_PREDICATE, ast_predicate_name=predicate_name),
        explanation=explanation,
        recommendation=recommendation,
        languages=("python",),
        priority=priority,
    )


#: One `Rule` per registered predicate above — the task's fifteen named
#: detection categories, each expressed as a genuine AST-based check for
#: Python (docs/adr/0021).
DEFAULT_PYTHON_AST_RULES: tuple[Rule, ...] = (
    _ast_rule(
        "py_sql_injection",
        name="Dynamically-built SQL query",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=SastSeverity.HIGH,
        confidence=0.75,
        predicate_name="py_sql_injection",
        explanation=(
            "A database `.execute()`-family call is passed a dynamically-built "
            "string (f-string/%-format/concatenation) instead of a parameterized "
            "query, risking SQL injection."
        ),
        recommendation=(
            "Use parameterized queries (placeholders + a separate params argument) instead of "
            "string building."
        ),
        priority=90,
    ),
    _ast_rule(
        "py_xss",
        name="Unescaped/unsafe HTML rendering",
        category=VulnerabilityCategory.XSS,
        severity=SastSeverity.HIGH,
        confidence=0.7,
        predicate_name="py_xss",
        explanation=(
            "`mark_safe()`/`render_template_string()` was called, which can "
            "render unescaped HTML and enable stored/reflected XSS."
        ),
        recommendation=(
            "Avoid mark_safe on dynamic content; use a templating engine's default auto-escaping."
        ),
        priority=85,
    ),
    _ast_rule(
        "py_command_injection",
        name="Shell command execution",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SastSeverity.CRITICAL,
        confidence=0.85,
        predicate_name="py_command_injection",
        explanation=(
            "`os.system`/`os.popen`, or a `subprocess` call with `shell=True`, "
            "invokes a shell — if any part of the command is attacker-influenced, "
            "this enables arbitrary command execution."
        ),
        recommendation=(
            "Use subprocess with shell=False and an argument list; never build shell strings."
        ),
        priority=95,
    ),
    _ast_rule(
        "py_path_traversal",
        name="Dynamically-built file path",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        severity=SastSeverity.MEDIUM,
        confidence=0.6,
        predicate_name="py_path_traversal",
        explanation=(
            "`open()` is passed a dynamically-built path — if attacker-"
            "influenced, this enables path traversal (`../../etc/passwd`)."
        ),
        recommendation="Validate/normalize paths against an allowed base directory before opening.",
        priority=70,
    ),
    _ast_rule(
        "py_ssrf",
        name="Dynamically-built outbound request URL",
        category=VulnerabilityCategory.SSRF,
        severity=SastSeverity.HIGH,
        confidence=0.6,
        predicate_name="py_ssrf",
        explanation=(
            "An outbound HTTP request is made to a dynamically-built URL — if "
            "attacker-influenced, this enables server-side request forgery."
        ),
        recommendation=(
            "Validate outbound URLs against an allowlist of trusted hosts before requesting."
        ),
        priority=80,
    ),
    _ast_rule(
        "py_hardcoded_secrets",
        name="Hardcoded secret-like literal",
        category=VulnerabilityCategory.HARDCODED_SECRETS,
        severity=SastSeverity.HIGH,
        confidence=0.65,
        predicate_name="py_hardcoded_secrets",
        explanation="A variable named like a secret is assigned a hardcoded string literal.",
        recommendation=(
            "Load secrets from environment variables/a secrets manager, never hardcode them."
        ),
        priority=85,
    ),
    _ast_rule(
        "py_weak_cryptography",
        name="Weak hash algorithm",
        category=VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
        severity=SastSeverity.MEDIUM,
        confidence=0.8,
        predicate_name="py_weak_cryptography",
        explanation="MD5/SHA1 are cryptographically broken for security-sensitive hashing.",
        recommendation=(
            "Use SHA-256 or stronger (or a dedicated password-hashing KDF like bcrypt/argon2)."
        ),
        priority=65,
    ),
    _ast_rule(
        "py_insecure_randomness",
        name="Non-cryptographic randomness",
        category=VulnerabilityCategory.INSECURE_RANDOMNESS,
        severity=SastSeverity.MEDIUM,
        confidence=0.5,
        predicate_name="py_insecure_randomness",
        explanation="The `random` module is not cryptographically secure.",
        recommendation=(
            "Use the `secrets` module (or os.urandom) for any security-relevant randomness."
        ),
        priority=50,
    ),
    _ast_rule(
        "py_unsafe_deserialization",
        name="Unsafe deserialization",
        category=VulnerabilityCategory.UNSAFE_DESERIALIZATION,
        severity=SastSeverity.CRITICAL,
        confidence=0.85,
        predicate_name="py_unsafe_deserialization",
        explanation=(
            "`pickle`/unsafe `yaml.load`/`eval`/`exec` on untrusted input enables "
            "arbitrary code execution."
        ),
        recommendation=(
            "Use `json`, or `yaml.safe_load`, and never `eval`/`exec`/`pickle.load` "
            "on untrusted data."
        ),
        priority=95,
    ),
    _ast_rule(
        "py_broken_authentication",
        name="Non-constant-time credential comparison",
        category=VulnerabilityCategory.BROKEN_AUTHENTICATION,
        severity=SastSeverity.MEDIUM,
        confidence=0.45,
        predicate_name="py_broken_authentication",
        explanation=(
            "A password/token is compared with `==`, which is vulnerable to timing attacks."
        ),
        recommendation="Use `hmac.compare_digest()` for constant-time secret comparison.",
        priority=55,
    ),
    _ast_rule(
        "py_missing_input_validation",
        name="Unvalidated input passed to a sensitive sink",
        category=VulnerabilityCategory.MISSING_INPUT_VALIDATION,
        severity=SastSeverity.MEDIUM,
        confidence=0.4,
        predicate_name="py_missing_input_validation",
        explanation=(
            "The result of `input()` is passed directly into a sensitive call with "
            "no visible validation."
        ),
        recommendation=(
            "Validate/sanitize user input before passing it to a file/process/eval sink."
        ),
        priority=45,
    ),
    _ast_rule(
        "py_dangerous_file_operations",
        name="Dangerous file operation",
        category=VulnerabilityCategory.DANGEROUS_FILE_OPERATIONS,
        severity=SastSeverity.MEDIUM,
        confidence=0.55,
        predicate_name="py_dangerous_file_operations",
        explanation="A file/directory deletion or overly permissive chmod was found.",
        recommendation=(
            "Confirm the target path is validated/trusted; avoid world-writable "
            "permissions (0o777/0o666)."
        ),
        priority=60,
    ),
    _ast_rule(
        "py_open_redirect",
        name="Dynamically-built redirect target",
        category=VulnerabilityCategory.OPEN_REDIRECT,
        severity=SastSeverity.MEDIUM,
        confidence=0.55,
        predicate_name="py_open_redirect",
        explanation=(
            "`redirect()` is passed a dynamically-built target — if attacker-"
            "influenced, this enables open redirect."
        ),
        recommendation=(
            "Validate redirect targets against an allowlist of relative paths/trusted hosts."
        ),
        priority=60,
    ),
    _ast_rule(
        "py_sensitive_information_exposure",
        name="Secret-like value logged/printed",
        category=VulnerabilityCategory.SENSITIVE_INFORMATION_EXPOSURE,
        severity=SastSeverity.MEDIUM,
        confidence=0.5,
        predicate_name="py_sensitive_information_exposure",
        explanation="A secret-like variable is passed directly to print()/a logging call.",
        recommendation="Never log secrets; mask/redact sensitive fields before logging.",
        priority=55,
    ),
    _ast_rule(
        "py_insecure_configuration",
        name="Insecure configuration",
        category=VulnerabilityCategory.INSECURE_CONFIGURATION,
        severity=SastSeverity.MEDIUM,
        confidence=0.7,
        predicate_name="py_insecure_configuration",
        explanation=(
            "`DEBUG = True` or `verify=False` (disabled TLS certificate verification) was found."
        ),
        recommendation="Disable DEBUG in production; never disable TLS certificate verification.",
        priority=65,
    ),
)
