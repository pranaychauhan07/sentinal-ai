"""``OwaspCategoryMapper`` — the task brief's "OWASP Category Mapper"
capability: a small, pure, deterministic lookup from `OwaspCategory` to its
official OWASP Top 10 (2021) name and one-line description. Never computed
by an LLM — this is reference data, exactly like
`core.knowledge.mitre`'s technique lookup.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from core.owasp_web.models import OwaspCategory


class OwaspCategoryInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: OwaspCategory
    name: str
    description: str


_CATEGORY_INFO: dict[OwaspCategory, OwaspCategoryInfo] = {
    OwaspCategory.A01_BROKEN_ACCESS_CONTROL: OwaspCategoryInfo(
        category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
        name="A01:2021 - Broken Access Control",
        description=(
            "Restrictions on what authenticated users are allowed to do are not properly enforced."
        ),
    ),
    OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES: OwaspCategoryInfo(
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        name="A02:2021 - Cryptographic Failures",
        description=(
            "Sensitive data is exposed due to weak, missing, or misconfigured "
            "cryptography/transport security."
        ),
    ),
    OwaspCategory.A03_INJECTION: OwaspCategoryInfo(
        category=OwaspCategory.A03_INJECTION,
        name="A03:2021 - Injection",
        description=(
            "Untrusted input is interpreted as part of a command or query (SQLi, XSS, and similar)."
        ),
    ),
    OwaspCategory.A04_INSECURE_DESIGN: OwaspCategoryInfo(
        category=OwaspCategory.A04_INSECURE_DESIGN,
        name="A04:2021 - Insecure Design",
        description="A missing or ineffective control design, not an implementation bug.",
    ),
    OwaspCategory.A05_SECURITY_MISCONFIGURATION: OwaspCategoryInfo(
        category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
        name="A05:2021 - Security Misconfiguration",
        description=(
            "Missing hardening, default configurations, verbose errors, or "
            "unnecessary features enabled."
        ),
    ),
    OwaspCategory.A06_VULNERABLE_COMPONENTS: OwaspCategoryInfo(
        category=OwaspCategory.A06_VULNERABLE_COMPONENTS,
        name="A06:2021 - Vulnerable and Outdated Components",
        description=(
            "Use of components with known vulnerabilities or that are no longer supported."
        ),
    ),
    OwaspCategory.A07_AUTHENTICATION_FAILURES: OwaspCategoryInfo(
        category=OwaspCategory.A07_AUTHENTICATION_FAILURES,
        name="A07:2021 - Identification and Authentication Failures",
        description=(
            "Weaknesses in confirming a user's identity, authentication, or session management."
        ),
    ),
    OwaspCategory.A08_SOFTWARE_DATA_INTEGRITY_FAILURES: OwaspCategoryInfo(
        category=OwaspCategory.A08_SOFTWARE_DATA_INTEGRITY_FAILURES,
        name="A08:2021 - Software and Data Integrity Failures",
        description=(
            "Code and infrastructure that does not protect against integrity "
            "violations (e.g. insecure deserialization, unsigned updates)."
        ),
    ),
    OwaspCategory.A09_LOGGING_MONITORING_FAILURES: OwaspCategoryInfo(
        category=OwaspCategory.A09_LOGGING_MONITORING_FAILURES,
        name="A09:2021 - Security Logging and Monitoring Failures",
        description=(
            "Insufficient logging/monitoring/alerting to detect and respond to breaches in time."
        ),
    ),
    OwaspCategory.A10_SSRF: OwaspCategoryInfo(
        category=OwaspCategory.A10_SSRF,
        name="A10:2021 - Server-Side Request Forgery",
        description=(
            "A server fetches a remote resource without validating the user-supplied URL/target."
        ),
    ),
}


class OwaspCategoryMapper:
    def describe(self, category: OwaspCategory) -> OwaspCategoryInfo:
        return _CATEGORY_INFO[category]

    def all_categories(self) -> tuple[OwaspCategoryInfo, ...]:
        return tuple(_CATEGORY_INFO.values())
