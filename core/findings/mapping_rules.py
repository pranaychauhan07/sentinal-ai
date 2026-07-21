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

**Tightened rules (detection-quality review):** `R-T1046-network-service-
discovery`, `R-T1082-system-info-discovery`, `R-T1036-masquerading`,
`R-T1090-proxy`, and `R-T1018-remote-system-discovery` were previously
untagged, generic co-occurrence rules — an IP+port pair, a bare hostname, or
a bare file name is true of nearly *any* log, so these fired on almost every
case regardless of whether the technique was genuinely present (verified
against a real investigation: a single SSH auth log with no scanning,
masquerading, or proxy activity at all produced mappings for all five).
Each now requires a `match_tags` value this codebase has no detector that
sets yet, making the rule correctly dormant rather than a false-positive
generator until a real, tag-producing detector exists for that specific
technique — a deliberate, documented "we don't have genuine evidence for
this yet" rather than a guess (constitution §1.7, "fail gracefully").
`R-T1204-user-execution` instead uses `require_co_occurrence=True` to gate
on a real corroborating signal (an EMAIL IOC — the phishing delivery
vector) rather than tag-gating it into permanent dormancy, since that
signal already exists in this system today. Every mapped technique also now
carries a `rule_id` and a `rationale` string
(`MitreMapping.rule_id`/`.rationale`, populated by `mapping_engine.py`) so a
consumer can see exactly which rule fired and why, not just a technique ID
and a bare confidence number.
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
    #: When `True`, `co_occurrence_ioc_types` gates whether the rule fires
    #: at all, not merely a confidence boost when present — the rule is
    #: skipped entirely for a candidate set that never observed one of
    #: those types. Distinguishes "this technique is a plausible explanation
    #: of the primary IOC type alone" (the default, boost-only behavior)
    #: from "this technique has no meaningful signal without a specific
    #: corroborating indicator" (e.g. T1204 User Execution genuinely
    #: requires a phishing-style delivery vector, not just any file/URL
    #: IOC in isolation).
    require_co_occurrence: bool = False
    description: str = ""
    #: Human-readable explanation of *why this rule requires what it
    #: requires* — surfaced verbatim in `MitreMapping.rationale`
    #: (`mapping_engine.py`) so a mapped technique's justification is never
    #: just "a rule fired," but names the actual reasoning (task
    #: requirement: "show exactly why each technique was selected").
    #: Defaults to `description` when unset, since most rules' existing
    #: `description` already states the reasoning; only rules whose firing
    #: condition needs a fuller explanation (the tag-gated ones below) set
    #: this explicitly.
    rationale_template: str = ""

    @property
    def rationale(self) -> str:
        return self.rationale_template or self.description


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
        # Tag-gated: any file name IOC (a perfectly ordinary log, config, or
        # document file) would otherwise satisfy this rule — obfuscation is
        # a property this system cannot infer from a file name alone.
        # Dormant until a real detector (encoding/packing signature) tags
        # the file.
        match_tags=("obfuscated", "packed", "encoded"),
        description="A file name explicitly tagged as obfuscated/packed/encoded.",
        rationale_template=(
            "A FILE_NAME IOC tagged 'obfuscated'/'packed'/'encoded' — confirms the file was "
            "flagged as obfuscated, not merely any file name observed in evidence."
        ),
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
        # Tag-gated (see module docstring "Tightened rules" note): a bare
        # PORT+IP pair is true of essentially any networked log line (one
        # client connecting to one service), not evidence of *discovery*
        # scanning specifically — that requires observing many distinct
        # ports/services being probed, a signal this rule table has no
        # honest way to test for from IOC type alone. Dormant until a real
        # scan-detector tags the contributing PORT IOC(s) as such, rather
        # than false-firing on every case with a port number in its logs.
        match_tags=("port_scan", "service_enumeration"),
        description=(
            "Port IOCs explicitly tagged as scan/enumeration activity, not a single "
            "client connection's port."
        ),
        rationale_template=(
            "A PORT IOC tagged 'port_scan' or 'service_enumeration' (co-occurring with an "
            "IP) — the tag confirms this port was observed as part of scanning behavior, "
            "not an incidental client connection."
        ),
    ),
    MappingRule(
        rule_id="R-T1082-system-info-discovery",
        technique_id="T1082",
        ioc_types=(IOCType.HOSTNAME,),
        base_confidence=0.3,
        # Tag-gated: a bare HOSTNAME IOC is frequently just the log's own
        # source host (where the evidence came from), not a remote host an
        # attacker *discovered* — the two are indistinguishable from IOC
        # type alone. Dormant until a real discovery-command detector
        # (e.g. `hostname`/`systeminfo`/`uname -a` execution) tags it.
        match_tags=("discovery_command_output",),
        description=(
            "A hostname IOC explicitly tagged as the output of a system-discovery command, "
            "not merely the evidence source's own host."
        ),
        rationale_template=(
            "A HOSTNAME IOC tagged 'discovery_command_output' — confirms this hostname was "
            "observed as the result of a discovery command, not just this log's own source "
            "host."
        ),
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
        # Tag-gated: any file name IOC (even a genuinely benign one) would
        # otherwise satisfy this rule — masquerading specifically requires
        # the file's name to *impersonate* a legitimate system binary
        # (e.g. "scvhost.exe" vs "svchost.exe"), a judgment this system has
        # no detector for from the file name alone yet. Dormant until one
        # exists and tags the IOC.
        match_tags=("masquerade", "system_name_mimicry"),
        description="A file name explicitly tagged as mimicking a legitimate system binary.",
        rationale_template=(
            "A FILE_NAME IOC tagged 'masquerade'/'system_name_mimicry' — confirms the name "
            "was flagged as impersonating a legitimate system binary, not merely any file "
            "name."
        ),
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
        # Requires an EMAIL IOC to actually co-occur (not merely boosts
        # confidence when present, per `require_co_occurrence`) — a bare
        # file name or URL says nothing about whether a *user* was relied
        # on to execute it; the genuinely distinguishing signal this system
        # can observe is a delivery vector (a phishing email) alongside the
        # attachment/link, the same real-world scenario `R-T1566-phishing`
        # already requires an EMAIL IOC for.
        co_occurrence_ioc_types=(IOCType.EMAIL,),
        co_occurrence_boost=0.25,
        require_co_occurrence=True,
        description=(
            "A file/URL IOC delivered alongside an email — the email is what makes "
            "'a user had to execute this' a genuine inference rather than a guess."
        ),
        rationale_template=(
            "A FILE_NAME/URL IOC co-occurring with an EMAIL IOC in this case — the email "
            "delivery vector is what distinguishes 'a user was relied on to execute this' "
            "from an arbitrary file/link with no evidence of how it reached anyone."
        ),
    ),
    MappingRule(
        rule_id="R-T1090-proxy",
        technique_id="T1090",
        ioc_types=(IOCType.IPV4, IOCType.IPV6),
        base_confidence=0.25,
        co_occurrence_ioc_types=(IOCType.PORT,),
        co_occurrence_boost=0.2,
        # Tag-gated: an IP+port pair is true of essentially every network
        # log line (any client connecting to any service) — it is not
        # distinguishing evidence of *proxying* C2 traffic specifically.
        # Dormant until a real proxy/relay detector tags the IP.
        match_tags=("proxy", "socks", "relay"),
        description="An IP explicitly tagged as proxy/relay/SOCKS infrastructure.",
        rationale_template=(
            "An IPV4/IPV6 IOC tagged 'proxy'/'socks'/'relay' — confirms this address was "
            "flagged as proxying traffic, not merely any network endpoint with a port "
            "number attached."
        ),
    ),
    MappingRule(
        rule_id="R-T1018-remote-system-discovery",
        technique_id="T1018",
        ioc_types=(IOCType.IPV4, IOCType.IPV6),
        base_confidence=0.3,
        co_occurrence_ioc_types=(IOCType.HOSTNAME,),
        co_occurrence_boost=0.15,
        # Tag-gated: an IP accompanied by a hostname is true of nearly any
        # log with a source/destination host recorded (including the
        # evidence's own host) — it is not, by itself, evidence of *remote
        # system enumeration*. Dormant until a real discovery-command
        # detector tags the IOC.
        match_tags=("discovery_command_output", "network_enumeration"),
        description=(
            "An IP explicitly tagged as the result of network/system enumeration, not "
            "merely any address accompanied by a hostname."
        ),
        rationale_template=(
            "An IPV4/IPV6 IOC tagged 'discovery_command_output'/'network_enumeration' "
            "(co-occurring with a hostname) — confirms this address was observed as the "
            "result of enumeration activity, not an incidental host reference."
        ),
    ),
)
