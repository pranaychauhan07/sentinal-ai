"""Default pattern-based (regex) `Rule` set for JavaScript, TypeScript, and
Java — `pattern_analyzer.py`'s detection logic. This project has no AST
library for these languages (docs/adr/0021's explicit scope decision), so
pattern matching stands in as the honest, documented fallback: *"Use
pattern matching only where AST cannot reasonably express the rule"*
applied at the language level. `confidence_calculator.py` discounts these
findings relative to Python's AST-based ones.
"""

from __future__ import annotations

from core.owasp_security.models import MatcherKind, SastSeverity, VulnerabilityCategory
from core.owasp_security.rule_engine import Matcher, Rule


def _pattern_rule(
    rule_id: str,
    *,
    name: str,
    category: VulnerabilityCategory,
    severity: SastSeverity,
    confidence: float,
    pattern: str,
    languages: tuple[str, ...],
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
        matcher=Matcher(kind=MatcherKind.REGEX, pattern=pattern),
        explanation=explanation,
        recommendation=recommendation,
        languages=languages,
        priority=priority,
    )


_JS_TS = ("javascript", "typescript")

DEFAULT_PATTERN_RULES: tuple[Rule, ...] = (
    # --- SQL Injection (JS/TS/Java) -----------------------------------------
    _pattern_rule(
        "pat_sql_injection_js",
        name="String-built SQL query (JS/TS)",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=SastSeverity.HIGH,
        confidence=0.55,
        pattern=r"\.(?:query|execute)\s*\(\s*[`'\"].*\$\{",
        languages=_JS_TS,
        explanation=(
            "A query call is passed a template literal with interpolation instead of a "
            "parameterized query."
        ),
        recommendation=(
            "Use parameterized/prepared queries instead of building SQL via string interpolation."
        ),
        priority=80,
    ),
    _pattern_rule(
        "pat_sql_injection_java",
        name="String-built SQL query (Java)",
        category=VulnerabilityCategory.SQL_INJECTION,
        severity=SastSeverity.HIGH,
        confidence=0.55,
        pattern=r"(?:createStatement|executeQuery|executeUpdate)\s*\([^)]*\+",
        languages=("java",),
        explanation=(
            "A JDBC Statement is executed with a string built via concatenation instead of "
            "PreparedStatement."
        ),
        recommendation=(
            "Use PreparedStatement with bound parameters instead of string concatenation."
        ),
        priority=80,
    ),
    # --- XSS ------------------------------------------------------------------
    _pattern_rule(
        "pat_xss_innerhtml",
        name="Unsafe innerHTML assignment",
        category=VulnerabilityCategory.XSS,
        severity=SastSeverity.HIGH,
        confidence=0.5,
        pattern=r"\.innerHTML\s*=",
        languages=_JS_TS,
        explanation=(
            "Assigning to innerHTML with unsanitized content can execute injected script (XSS)."
        ),
        recommendation="Use textContent, or sanitize HTML before assigning to innerHTML.",
        priority=75,
    ),
    _pattern_rule(
        "pat_xss_document_write",
        name="document.write with dynamic content",
        category=VulnerabilityCategory.XSS,
        severity=SastSeverity.MEDIUM,
        confidence=0.45,
        pattern=r"document\.write\s*\(",
        languages=_JS_TS,
        explanation="document.write() with dynamic content can enable XSS and blocks rendering.",
        recommendation="Avoid document.write; render via the DOM API with proper escaping.",
        priority=55,
    ),
    # --- Command Injection ------------------------------------------------------
    _pattern_rule(
        "pat_command_injection_js",
        name="Shell command execution (JS/TS)",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SastSeverity.CRITICAL,
        confidence=0.7,
        pattern=r"child_process\.(?:exec|execSync)\s*\(",
        languages=_JS_TS,
        explanation=(
            "child_process.exec() runs a command through a shell — attacker-influenced input "
            "enables injection."
        ),
        recommendation=(
            "Use execFile/spawn with an argument array instead of a shell-interpreted command "
            "string."
        ),
        priority=95,
    ),
    _pattern_rule(
        "pat_command_injection_java",
        name="Shell command execution (Java)",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SastSeverity.CRITICAL,
        confidence=0.65,
        pattern=r"Runtime\.getRuntime\(\)\.exec\s*\(",
        languages=("java",),
        explanation=(
            "Runtime.exec() with a dynamically-built command string enables command injection."
        ),
        recommendation=(
            "Use ProcessBuilder with an explicit argument list, never a single shell-interpreted "
            "string."
        ),
        priority=90,
    ),
    # --- Path Traversal -----------------------------------------------------
    _pattern_rule(
        "pat_path_traversal",
        name="Path traversal sequence",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        severity=SastSeverity.MEDIUM,
        confidence=0.4,
        pattern=r"\.\./",
        languages=(*_JS_TS, "java"),
        explanation="A literal '../' path-traversal sequence was found in source.",
        recommendation="Validate/normalize file paths against an allowed base directory.",
        priority=50,
    ),
    _pattern_rule(
        "pat_path_traversal_java_file",
        name="Dynamically-built java.io.File path",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        severity=SastSeverity.MEDIUM,
        confidence=0.4,
        pattern=r"new\s+File\s*\([^)]*\+",
        languages=("java",),
        explanation="new File(...) built via string concatenation may enable path traversal.",
        recommendation=(
            "Validate/canonicalize file paths against an allowed base directory before use."
        ),
        priority=50,
    ),
    # --- SSRF -----------------------------------------------------------------
    _pattern_rule(
        "pat_ssrf_fetch",
        name="Dynamically-built fetch/axios URL",
        category=VulnerabilityCategory.SSRF,
        severity=SastSeverity.HIGH,
        confidence=0.45,
        pattern=r"(?:fetch|axios\.(?:get|post))\s*\(\s*[`'\"]?[^`'\"]*\$\{",
        languages=_JS_TS,
        explanation="An outbound HTTP request URL is built via template-literal interpolation.",
        recommendation=(
            "Validate outbound URLs against an allowlist of trusted hosts before requesting."
        ),
        priority=70,
    ),
    # --- Hardcoded Secrets ----------------------------------------------------
    _pattern_rule(
        "pat_hardcoded_secrets",
        name="Hardcoded secret-like literal",
        category=VulnerabilityCategory.HARDCODED_SECRETS,
        severity=SastSeverity.HIGH,
        confidence=0.55,
        pattern=r"(?i)(?:password|secret|token|api[_-]?key)\s*[:=]\s*[\"'][^\"']{6,}[\"']",
        languages=(*_JS_TS, "java"),
        explanation="A secret-like identifier is assigned a hardcoded string literal.",
        recommendation=(
            "Load secrets from environment variables/a secrets manager, never hardcode them."
        ),
        priority=80,
    ),
    # --- Weak Cryptography ------------------------------------------------------
    _pattern_rule(
        "pat_weak_cryptography_js",
        name="Weak hash algorithm (JS/TS)",
        category=VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
        severity=SastSeverity.MEDIUM,
        confidence=0.6,
        pattern=r"createHash\s*\(\s*[\"'](?:md5|sha1)[\"']\s*\)",
        languages=_JS_TS,
        explanation="MD5/SHA1 are cryptographically broken for security-sensitive hashing.",
        recommendation=(
            "Use SHA-256 or stronger (or a dedicated password-hashing KDF like bcrypt/argon2)."
        ),
        priority=60,
    ),
    _pattern_rule(
        "pat_weak_cryptography_java",
        name="Weak hash algorithm (Java)",
        category=VulnerabilityCategory.WEAK_CRYPTOGRAPHY,
        severity=SastSeverity.MEDIUM,
        confidence=0.6,
        pattern=r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"\s*\)",
        languages=("java",),
        explanation="MD5/SHA1 are cryptographically broken for security-sensitive hashing.",
        recommendation=(
            "Use SHA-256 or stronger (or a dedicated password-hashing KDF like bcrypt/argon2)."
        ),
        priority=60,
    ),
    # --- Insecure Randomness -----------------------------------------------------
    _pattern_rule(
        "pat_insecure_randomness_js",
        name="Non-cryptographic randomness (JS/TS)",
        category=VulnerabilityCategory.INSECURE_RANDOMNESS,
        severity=SastSeverity.MEDIUM,
        confidence=0.4,
        pattern=r"Math\.random\s*\(\s*\)",
        languages=_JS_TS,
        explanation="Math.random() is not cryptographically secure.",
        recommendation=(
            "Use crypto.getRandomValues() (browser) or the Node.js crypto module for "
            "security-relevant randomness."
        ),
        priority=45,
    ),
    _pattern_rule(
        "pat_insecure_randomness_java",
        name="Non-cryptographic randomness (Java)",
        category=VulnerabilityCategory.INSECURE_RANDOMNESS,
        severity=SastSeverity.MEDIUM,
        confidence=0.4,
        pattern=r"new\s+Random\s*\(",
        languages=("java",),
        explanation="java.util.Random is not cryptographically secure.",
        recommendation="Use java.security.SecureRandom for security-relevant randomness.",
        priority=45,
    ),
    # --- Unsafe Deserialization --------------------------------------------------
    _pattern_rule(
        "pat_unsafe_deserialization_js",
        name="Dynamic code evaluation",
        category=VulnerabilityCategory.UNSAFE_DESERIALIZATION,
        severity=SastSeverity.CRITICAL,
        confidence=0.6,
        pattern=r"\beval\s*\(",
        languages=_JS_TS,
        explanation=(
            "eval() executes a string as code — on untrusted input this enables arbitrary code "
            "execution."
        ),
        recommendation="Never eval untrusted input; use JSON.parse for data, not eval.",
        priority=95,
    ),
    _pattern_rule(
        "pat_unsafe_deserialization_java",
        name="Unsafe Java deserialization",
        category=VulnerabilityCategory.UNSAFE_DESERIALIZATION,
        severity=SastSeverity.CRITICAL,
        confidence=0.6,
        pattern=r"ObjectInputStream\s*\([^)]*\)\s*\.\s*readObject\s*\(",
        languages=("java",),
        explanation=(
            "Deserializing untrusted data via ObjectInputStream.readObject() can "
            "enable remote code execution."
        ),
        recommendation=(
            "Avoid native Java serialization for untrusted data; use a safe data format (e.g. "
            "JSON)."
        ),
        priority=90,
    ),
    # --- Broken Authentication ----------------------------------------------------
    _pattern_rule(
        "pat_broken_authentication",
        name="Non-constant-time credential comparison",
        category=VulnerabilityCategory.BROKEN_AUTHENTICATION,
        severity=SastSeverity.MEDIUM,
        confidence=0.35,
        pattern=r"(?i)(?:password|token|secret)\s*===?\s*",
        languages=(*_JS_TS, "java"),
        explanation=(
            "A password/token is compared with ==/=== , which is vulnerable to timing attacks."
        ),
        recommendation="Use a constant-time comparison function for secret/credential comparisons.",
        priority=40,
    ),
    # --- Missing Input Validation --------------------------------------------------
    _pattern_rule(
        "pat_missing_input_validation",
        name="Unvalidated request parameter passed to a sink",
        category=VulnerabilityCategory.MISSING_INPUT_VALIDATION,
        severity=SastSeverity.MEDIUM,
        confidence=0.3,
        pattern=r"(?:req\.(?:query|body|params)|request\.getParameter)\s*[.(\[][^)]*\)\s*(?:;|\))?\s*$",
        languages=(*_JS_TS, "java"),
        explanation="A raw request parameter appears used without a visible validation step.",
        recommendation=(
            "Validate/sanitize all request parameters before use in a sensitive operation."
        ),
        priority=30,
    ),
    # --- Dangerous File Operations --------------------------------------------------
    _pattern_rule(
        "pat_dangerous_file_operations_js",
        name="Dangerous file operation (JS/TS)",
        category=VulnerabilityCategory.DANGEROUS_FILE_OPERATIONS,
        severity=SastSeverity.MEDIUM,
        confidence=0.5,
        pattern=r"fs\.(?:unlink|unlinkSync|rmdir|rmdirSync|rm|rmSync)\s*\(",
        languages=_JS_TS,
        explanation="A file/directory deletion call was found.",
        recommendation="Confirm the target path is validated/trusted before deletion.",
        priority=55,
    ),
    _pattern_rule(
        "pat_dangerous_file_operations_java",
        name="Dangerous file operation (Java)",
        category=VulnerabilityCategory.DANGEROUS_FILE_OPERATIONS,
        severity=SastSeverity.MEDIUM,
        confidence=0.5,
        pattern=r"\.(?:delete|deleteOnExit)\s*\(\s*\)",
        languages=("java",),
        explanation="A File deletion call was found.",
        recommendation="Confirm the target path is validated/trusted before deletion.",
        priority=55,
    ),
    # --- Open Redirect -------------------------------------------------------------
    _pattern_rule(
        "pat_open_redirect_js",
        name="Dynamically-built redirect target (JS/TS)",
        category=VulnerabilityCategory.OPEN_REDIRECT,
        severity=SastSeverity.MEDIUM,
        confidence=0.4,
        pattern=r"res\.redirect\s*\(\s*req\.",
        languages=_JS_TS,
        explanation="res.redirect() is passed a value derived directly from the request.",
        recommendation=(
            "Validate redirect targets against an allowlist of relative paths/trusted hosts."
        ),
        priority=50,
    ),
    _pattern_rule(
        "pat_open_redirect_java",
        name="Dynamically-built redirect target (Java)",
        category=VulnerabilityCategory.OPEN_REDIRECT,
        severity=SastSeverity.MEDIUM,
        confidence=0.4,
        pattern=r"sendRedirect\s*\(\s*request\.",
        languages=("java",),
        explanation="sendRedirect() is passed a value derived directly from the request.",
        recommendation=(
            "Validate redirect targets against an allowlist of relative paths/trusted hosts."
        ),
        priority=50,
    ),
    # --- Sensitive Information Exposure --------------------------------------------
    _pattern_rule(
        "pat_sensitive_information_exposure",
        name="Secret-like value logged/printed",
        category=VulnerabilityCategory.SENSITIVE_INFORMATION_EXPOSURE,
        severity=SastSeverity.MEDIUM,
        confidence=0.35,
        pattern=r"(?i)console\.log\s*\([^)]*(?:password|secret|token|api[_-]?key)",
        languages=_JS_TS,
        explanation="A secret-like value appears passed directly to console.log().",
        recommendation="Never log secrets; mask/redact sensitive fields before logging.",
        priority=45,
    ),
    # --- Insecure Configuration -----------------------------------------------------
    _pattern_rule(
        "pat_insecure_configuration_js",
        name="Disabled TLS certificate verification (JS/TS)",
        category=VulnerabilityCategory.INSECURE_CONFIGURATION,
        severity=SastSeverity.HIGH,
        confidence=0.6,
        pattern=r"rejectUnauthorized\s*:\s*false",
        languages=_JS_TS,
        explanation=(
            "TLS certificate verification is explicitly disabled (rejectUnauthorized: false)."
        ),
        recommendation="Never disable TLS certificate verification in production code.",
        priority=75,
    ),
    _pattern_rule(
        "pat_insecure_configuration_java",
        name="Disabled TLS certificate verification (Java)",
        category=VulnerabilityCategory.INSECURE_CONFIGURATION,
        severity=SastSeverity.HIGH,
        confidence=0.5,
        pattern=r"TrustManager\s*\[\s*\]\s*\{\s*new\s+X509TrustManager",
        languages=("java",),
        explanation="A custom TrustManager appears to bypass certificate validation.",
        recommendation=(
            "Never implement a TrustManager that accepts all certificates in production code."
        ),
        priority=70,
    ),
)
