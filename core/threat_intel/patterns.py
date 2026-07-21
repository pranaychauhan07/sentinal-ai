"""Deterministic IOC discovery patterns — the data table
`core.threat_intel.extractor.IOCExtractionEngine` dispatches from
(docs/adr/0012, "one data-driven engine, not twenty near-duplicate
extractors").

Every pattern below is deliberately **bounded**: fixed/explicit `{m,n}`
quantifiers, no nested or overlapping quantifiers (no `(a+)+`-shaped
groups), so none of them are susceptible to catastrophic backtracking
(constitution §10, "protect against catastrophic regex"). `sniff_candidates`
also always operates against `refang()`'d, length-capped text — see
`core.threat_intel.rule_validation.validate_regex_safety` for the same
guarantee applied to *user-supplied* `DetectionRule.regex` values.
"""

from __future__ import annotations

import re

from core.threat_intel.models import IOCType

#: Compiled once at import time — never re-compiled per call (constitution
#: §5, "caching ... explicit and scoped").
IOC_PATTERNS: dict[IOCType, re.Pattern[str]] = {
    IOCType.IPV4: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    IOCType.IPV6: re.compile(
        r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b"
    ),
    IOCType.DOMAIN: re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,10}[A-Za-z]{2,24}\b"
    ),
    # IOCType.HOSTNAME deliberately has no free-text pattern: a single
    # alphanumeric-or-hyphen token matches essentially any English word,
    # making unbounded pattern-scan extraction pure noise. Hostnames are
    # extracted only from a parser's structured `host` field
    # (STRUCTURED_FIELD_SOURCES below), never guessed from raw text.
    IOCType.URL: re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s<>\"']{1,2000}"),
    IOCType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b"),
    IOCType.SHA1: re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    IOCType.SHA256: re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    IOCType.MD5: re.compile(r"\b[A-Fa-f0-9]{32}\b"),
    #: Deliberately an *extension allowlist*, not "any text, then a dot,
    #: then alphanumerics" — that broader shape (this pattern's previous
    #: form) matched IP-address octets ("203.0", "113.44") and arbitrary
    #: log-line fragments ("Failed password for root from 203.0") as
    #: false-positive "file names," which in turn fed spurious MITRE
    #: mappings (T1027/T1036/T1204) downstream. A real file name (a) never
    #: contains a space/comma (`[\w-]`, not `[\w,\s-]`) and (b) ends in an
    #: extension that is actually a plausible extension, never a bare
    #: numeric suffix like an IP octet's trailing digits.
    IOCType.FILE_NAME: re.compile(
        r"\b[\w-]{1,80}\.(?:exe|dll|sys|drv|bat|cmd|com|scr|msi|ps1|psm1|vbs|vbe|js|jse|"
        r"wsf|hta|jar|apk|ipa|sh|bash|py|pyc|pyo|php|asp|aspx|jsp|jspx|"
        r"zip|rar|7z|tar|gz|bz2|xz|iso|"
        r"doc|docx|docm|xls|xlsx|xlsm|ppt|pptx|pptm|pdf|rtf|"
        r"txt|log|tmp|temp|dat|bin|dmp|cfg|conf|ini|"
        r"lnk|reg|dll32|dll64)\b",
        re.IGNORECASE,
    ),
    IOCType.USERNAME: re.compile(
        r"\b(?:user|username|for user|account)[:=]?\s+([A-Za-z0-9_.\\-]{1,64})\b", re.IGNORECASE
    ),
    IOCType.PROCESS_NAME: re.compile(r"\b[A-Za-z0-9_-]{1,64}\.exe\b", re.IGNORECASE),
    IOCType.REGISTRY_KEY: re.compile(
        r"\b(?:HKEY_[A-Z_]{2,30}|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s]{1,260}"
    ),
    IOCType.PORT: re.compile(r"\bport[:=]?\s*(\d{1,5})\b", re.IGNORECASE),
    IOCType.SERVICE: re.compile(r"\bservice[:=]\s*([A-Za-z0-9_.\-]{1,64})\b", re.IGNORECASE),
    IOCType.MUTEX: re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_.\-{}]{1,128}"),
    IOCType.SCHEDULED_TASK: re.compile(r"\\Microsoft\\Windows\\[^\s]{1,200}|\\Task\\[^\s]{1,200}"),
    IOCType.COMMAND_LINE: re.compile(
        r"\b(?:cmd\.exe|powershell\.exe|/bin/(?:ba)?sh|/bin/dash)\b.{0,500}", re.IGNORECASE
    ),
    IOCType.USER_AGENT: re.compile(
        r"(?:Mozilla|curl|python-requests|Wget|Go-http-client)[^\r\n\"]{0,300}"
    ),
    IOCType.CERTIFICATE_FINGERPRINT: re.compile(r"\b(?:[A-Fa-f0-9]{2}:){15,31}[A-Fa-f0-9]{2}\b"),
}

#: `EvidenceRecord` attribute names checked *before* regex scanning for the
#: IOC types a parser may already have extracted into a structured field —
#: higher confidence than a regex match against `raw_line` (used by
#: `core.threat_intel.extractor.IOCExtractionEngine`).
STRUCTURED_FIELD_SOURCES: dict[IOCType, tuple[str, ...]] = {
    IOCType.IPV4: ("ip_address",),
    IOCType.HOSTNAME: ("host",),
    IOCType.USERNAME: ("user",),
}

#: Common IOC-defanging substitutions analysts/threat feeds use so a shared
#: artifact isn't accidentally "live" (e.g. a clickable URL). Order matters:
#: longer/more-specific substrings first.
_DEFANG_SUBSTITUTIONS: tuple[tuple[str, str], ...] = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("[.]", "."),
    ("(.)", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[://]", "://"),
)


def refang(text: str) -> str:
    """Reverse common IOC-defanging conventions before pattern matching.
    Deterministic, order-preserving substitution — never regex-based itself,
    so it carries no backtracking risk regardless of input size."""
    result = text
    for defanged, live in _DEFANG_SUBSTITUTIONS:
        result = result.replace(defanged, live)
    return result
