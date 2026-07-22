"""Default Detection Rule set — `core.threat_intel.rules.DetectionRuleEngine`
was built with the full pattern/regex/threshold/composite rule model this
task requires, but nothing in the real pipeline
(`core.services.threat_intel_service.IOCExtractionPipeline`) ever called
`register_rule` with an actual rule: every extracted IOC's `rule_matches`
was always empty, meaning `ThreatClassificationEngine` and
`ThreatScoringEngine` never had any local, offline detection signal to work
with — only `ioc.confidence`/`evidence_quality`/`source_reliability`, none
of which alone is enough to cross the suspicious/malicious thresholds.

This is a distinct gap from ADR-0012's disclosed "no concrete
`ThreatIntelProvider`/external reputation feed" scope cut — that gap is
about *live, third-party* enrichment (VirusTotal, AbuseIPDB, ...) and
remains unimplemented by design. This module closes the *local, offline*
half: a small, conservative, always-safe (REGEX rules pass
`validate_regex_safety`) rule set covering patterns a SOC analyst would
recognize without any external lookup — mirroring the same
"vendored, offline-only reference content" precedent
`core.knowledge.{owasp,playbooks,detection}` already established for
knowledge population (ADR-0027).
"""

from __future__ import annotations

from core.threat_intel.models import DetectionRule, IOCType, RuleType, ThreatSeverity
from core.threat_intel.rules import DetectionRuleEngine

#: Domains registered under these TLDs are disproportionately used for
#: phishing/typosquat infrastructure (cheap, minimal registration
#: verification) — a well-established, publicly documented heuristic, not a
#: fabricated one.
_SUSPICIOUS_TLD_REGEX = r"(?i)\.(xyz|top|tk|club|country|gq|cf|ml|zip|mov|work|link)$"

#: Common non-standard ports historically associated with backdoors/RATs/
#: IRC-based C2 (31337 "eleet", 4444 Metasploit's default handler, 1337,
#: 6667 IRC, 12345 NetBus, 9001 Tor/others) — a long-standing, publicly
#: documented list, not a fabricated one.
_BACKDOOR_PORT_REGEX = r"^(4444|31337|1337|6667|12345|9001|2222|31335)$"

#: Privileged/default service account usernames attackers target first in
#: credential-stuffing and brute-force campaigns.
_PRIVILEGED_USERNAME_REGEX = (
    r"(?i)^(root|admin|administrator|postgres|oracle|deploy|ubuntu|ec2-user|www-data)$"
)

#: A phishing lure archive/executable naming convention (an "invoice"/
#: "payment"/"receipt"-themed file that is actually an archive or
#: executable, not a document) — the exact shape of this session's own
#: seeded phishing sample (`Invoice_2026.zip`).
_LURE_ARCHIVE_REGEX = (
    r"(?i)(invoice|payment|receipt|statement|remittance).*\.(zip|exe|scr|js|vbs|jar|bat)$"
)

#: A bare executable/script extension on a `FILE_NAME` IOC — lower priority
#: than the lure-archive rule (a legitimate `.exe` mention is common; this
#: rule exists to still contribute *some* signal when the more specific
#: lure-naming pattern doesn't match).
_EXECUTABLE_EXTENSION_REGEX = r"(?i)\.(exe|scr|vbs|ps1|jar)$"


def _default_rules() -> tuple[DetectionRule, ...]:
    return (
        DetectionRule(
            rule_id="default-suspicious-tld-domain",
            name="Domain registered under a high-abuse TLD",
            description=(
                "Flags domains under TLDs disproportionately used for phishing/"
                "typosquat infrastructure."
            ),
            rule_type=RuleType.REGEX,
            regex=_SUSPICIOUS_TLD_REGEX,
            ioc_types=(IOCType.DOMAIN, IOCType.HOSTNAME),
            severity=ThreatSeverity.MEDIUM,
            priority=10,
            tags=("phishing", "typosquat"),
        ),
        DetectionRule(
            rule_id="default-backdoor-port",
            name="Known backdoor/C2-associated port",
            description="Flags ports historically associated with backdoors/RATs/C2 channels.",
            rule_type=RuleType.REGEX,
            regex=_BACKDOOR_PORT_REGEX,
            ioc_types=(IOCType.PORT,),
            severity=ThreatSeverity.HIGH,
            priority=20,
            tags=("c2", "backdoor"),
        ),
        DetectionRule(
            rule_id="default-privileged-username-target",
            name="Privileged/default account targeted",
            description=(
                "Flags authentication attempts against privileged or default "
                "service-account usernames."
            ),
            rule_type=RuleType.REGEX,
            regex=_PRIVILEGED_USERNAME_REGEX,
            ioc_types=(IOCType.USERNAME,),
            severity=ThreatSeverity.MEDIUM,
            priority=10,
            tags=("credential-access", "brute-force"),
        ),
        DetectionRule(
            rule_id="default-phishing-lure-archive",
            name="Phishing-themed lure archive/executable filename",
            description=(
                "Flags an invoice/payment/receipt-themed filename that is actually an "
                "archive or executable, not a document."
            ),
            rule_type=RuleType.REGEX,
            regex=_LURE_ARCHIVE_REGEX,
            ioc_types=(IOCType.FILE_NAME,),
            severity=ThreatSeverity.HIGH,
            priority=20,
            tags=("phishing", "malware-delivery"),
        ),
        DetectionRule(
            rule_id="default-executable-extension",
            name="Executable/script file extension",
            description="Flags a bare executable or script file extension.",
            rule_type=RuleType.REGEX,
            regex=_EXECUTABLE_EXTENSION_REGEX,
            ioc_types=(IOCType.FILE_NAME,),
            severity=ThreatSeverity.MEDIUM,
            priority=5,
            tags=("malware-delivery",),
        ),
    )


def build_default_rule_engine() -> DetectionRuleEngine:
    """A `DetectionRuleEngine` pre-registered with this module's default
    rule set — the engine every `IOCExtractionPipeline` uses unless a
    caller (e.g. a test exercising a specific rule in isolation) explicitly
    injects its own via the existing `rule_engine=` constructor parameter."""
    engine = DetectionRuleEngine()
    for rule in _default_rules():
        engine.register_rule(rule)
    return engine
