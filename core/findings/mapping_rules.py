"""Data-driven IOC-type -> ATT&CK-technique mapping rules — one table, not
twenty near-duplicate per-technique classes, matching the exact precedent
`core/threat_intel/patterns.py` set for IOC extraction (constitution §1.9,
"never duplicated across files").

Each `MappingRule` fires when a `ScoredIOC` of one of its `ioc_types` is
present; `co_occurrence_ioc_types` supports the "many-IOCs-to-one-technique"
requirement (e.g. an IP address *and* an open port together are stronger
evidence of network service discovery than either alone), and one IOC type
deliberately appears in several rules to satisfy "one-IOC-to-many-
techniques" (e.g. a `USERNAME` IOC is weak evidence for both Brute Force and
Valid Accounts). `match_tags`, when non-empty, gates the rule entirely — it
must not fire without at least one matching tag, keeping precision-limited
IOC types (`FILE_NAME`, `PROCESS_NAME`) from mapping to a high-severity
technique on IOC type alone.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from core.threat_intel.models import IOCType


class MappingRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    technique_id: str
    ioc_types: tuple[IOCType, ...]
    base_confidence: float = Field(ge=0.0, le=1.0)
    match_tags: tuple[str, ...] = ()
    co_occurrence_ioc_types: tuple[IOCType, ...] = ()
    co_occurrence_boost: float = Field(default=0.0, ge=0.0, le=1.0)
    description: str = ""


#: Every rule this engine evaluates. Real technique IDs correspond to
#: `data/mitre/raw/attack-enterprise-15.1.json`'s vendored technique set —
#: a rule referencing a technique_id absent from the loaded `MitreDataset`
#: is rejected at registration time by `MitreMappingEngine.__init__`
#: (`core.findings.exceptions.InvalidMappingRuleError`), never discovered
#: mid-evaluation.
MAPPING_RULES: tuple[MappingRule, ...] = (
    MappingRule(
        rule_id="R-T1110-brute-force",
        technique_id="T1110",
        ioc_types=(IOCType.USERNAME,),
        base_confidence=0.4,
        co_occurrence_ioc_types=(IOCType.IPV4, IOCType.IPV6),
        co_occurrence_boost=0.2,
        description="Repeated username IOCs, especially with a source IP, suggest brute force.",
    ),
    MappingRule(
        rule_id="R-T1078-valid-accounts",
        technique_id="T1078",
        ioc_types=(IOCType.USERNAME,),
        base_confidence=0.3,
        description="A username IOC alone is weak evidence of valid-account abuse.",
    ),
    MappingRule(
        rule_id="R-T1059-command-scripting",
        technique_id="T1059",
        ioc_types=(IOCType.COMMAND_LINE,),
        base_confidence=0.6,
        description="A captured command line is direct evidence of interpreter execution.",
    ),
    MappingRule(
        rule_id="R-T1566-phishing",
        technique_id="T1566",
        ioc_types=(IOCType.EMAIL,),
        base_confidence=0.4,
        co_occurrence_ioc_types=(IOCType.URL,),
        co_occurrence_boost=0.25,
        description="A sender email IOC with an accompanying URL is stronger phishing evidence.",
    ),
    MappingRule(
        rule_id="R-T1021-remote-services",
        technique_id="T1021",
        ioc_types=(IOCType.PORT,),
        base_confidence=0.35,
        co_occurrence_ioc_types=(IOCType.IPV4, IOCType.IPV6),
        co_occurrence_boost=0.2,
        description="A remote-service port with a destination IP suggests lateral movement.",
    ),
    MappingRule(
        rule_id="R-T1027-obfuscated-files",
        technique_id="T1027",
        ioc_types=(IOCType.FILE_NAME,),
        base_confidence=0.4,
        description="A suspicious file name is weak, precision-limited obfuscation evidence.",
    ),
    MappingRule(
        rule_id="R-T1053-scheduled-task",
        technique_id="T1053",
        ioc_types=(IOCType.SCHEDULED_TASK,),
        base_confidence=0.7,
        description="A scheduled-task IOC is direct, high-precision evidence.",
    ),
    MappingRule(
        rule_id="R-T1055-process-injection",
        technique_id="T1055",
        ioc_types=(IOCType.PROCESS_NAME,),
        base_confidence=0.5,
        match_tags=("injected", "hollowed"),
        description="A tagged process-name IOC indicating injection/hollowing.",
    ),
    MappingRule(
        rule_id="R-T1071-application-layer-protocol",
        technique_id="T1071",
        ioc_types=(IOCType.DOMAIN, IOCType.URL),
        base_confidence=0.35,
        description="A C2-style domain/URL blending into normal application traffic.",
    ),
    MappingRule(
        rule_id="R-T1105-ingress-tool-transfer",
        technique_id="T1105",
        ioc_types=(IOCType.URL, IOCType.SHA256),
        base_confidence=0.4,
        description="A download URL or transferred-file hash suggests tool ingress.",
    ),
    MappingRule(
        rule_id="R-T1041-exfil-over-c2",
        technique_id="T1041",
        ioc_types=(IOCType.DOMAIN,),
        base_confidence=0.3,
        co_occurrence_ioc_types=(IOCType.IPV4,),
        co_occurrence_boost=0.15,
        description="An outbound C2 domain with a destination IP suggests exfil channel reuse.",
    ),
    MappingRule(
        rule_id="R-T1486-data-encrypted-for-impact",
        technique_id="T1486",
        ioc_types=(IOCType.FILE_NAME,),
        base_confidence=0.45,
        match_tags=("ransomware", "encrypted"),
        description="A file name explicitly tagged ransomware/encrypted.",
    ),
    MappingRule(
        rule_id="R-T1046-network-service-discovery",
        technique_id="T1046",
        ioc_types=(IOCType.PORT,),
        base_confidence=0.4,
        co_occurrence_ioc_types=(IOCType.IPV4, IOCType.IPV6),
        co_occurrence_boost=0.2,
        description="Port IOCs across many hosts suggest service-discovery scanning.",
    ),
    MappingRule(
        rule_id="R-T1082-system-info-discovery",
        technique_id="T1082",
        ioc_types=(IOCType.HOSTNAME,),
        base_confidence=0.3,
        description="A discovered hostname is weak, generic discovery evidence.",
    ),
    MappingRule(
        rule_id="R-T1003-os-credential-dumping",
        technique_id="T1003",
        ioc_types=(IOCType.PROCESS_NAME,),
        base_confidence=0.55,
        match_tags=("credential_dump", "lsass"),
        description="A process-name IOC explicitly tagged as a credential-dumping tool.",
    ),
    MappingRule(
        rule_id="R-T1036-masquerading",
        technique_id="T1036",
        ioc_types=(IOCType.FILE_NAME,),
        base_confidence=0.35,
        description="A file name mimicking a legitimate system binary.",
    ),
    MappingRule(
        rule_id="R-T1547-boot-logon-autostart",
        technique_id="T1547",
        ioc_types=(IOCType.REGISTRY_KEY,),
        base_confidence=0.6,
        description="A registry-key IOC in a known autostart location.",
    ),
    MappingRule(
        rule_id="R-T1204-user-execution",
        technique_id="T1204",
        ioc_types=(IOCType.FILE_NAME, IOCType.URL),
        base_confidence=0.35,
        description="A malicious attachment or link relies on a user to execute it.",
    ),
    MappingRule(
        rule_id="R-T1090-proxy",
        technique_id="T1090",
        ioc_types=(IOCType.IPV4, IOCType.IPV6),
        base_confidence=0.25,
        co_occurrence_ioc_types=(IOCType.PORT,),
        co_occurrence_boost=0.2,
        description="An IP/port pair consistent with proxying C2 traffic.",
    ),
    MappingRule(
        rule_id="R-T1018-remote-system-discovery",
        technique_id="T1018",
        ioc_types=(IOCType.IPV4, IOCType.IPV6),
        base_confidence=0.3,
        co_occurrence_ioc_types=(IOCType.HOSTNAME,),
        co_occurrence_boost=0.15,
        description="IP addresses accompanied by discovered hostnames suggest network enumeration.",
    ),
)
