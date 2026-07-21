"""The deterministic Response Playbook Rule Engine — maps one normalized
finding (`core.incident_response.inputs.IncidentInputFinding`) to the set of
`ResponseCategory` values it triggers, and carries the static
title/description/phase/timeframe/base-priority template for each category.

Three matching strategies, tried in this fixed, documented order (never an
LLM guess — constitution §1.9):

1. **MITRE ATT&CK tactic ID** (`_TACTIC_CATEGORY_MAP`) — the strongest
   signal, since a tactic ID is itself already a deterministic classification
   another subsystem (`core.findings.mapping_engine`) computed.
2. **Keyword match** on the finding's title/keywords bag (`_KEYWORD_CATEGORY_MAP`)
   — a documented, narrower fallback for findings with no MITRE mapping at
   all (e.g. a Linux Advisor or OWASP Web finding, neither of which carries
   ATT&CK tactic data).
3. **Severity-only fallback** (`_SEVERITY_FALLBACK`) — the last resort for a
   finding with neither a tactic nor a keyword match; guarantees every
   MEDIUM-or-above finding still earns at least evidence preservation.

A finding may match more than one strategy; results are deduplicated,
preserving first-seen order (tactic matches before keyword matches before the
severity fallback) — this is what makes plan generation reproducible given
the same input (task requirement: "Plans must be deterministic and
reproducible").
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from core.incident_response.inputs import IncidentInputFinding
from core.incident_response.models import (
    IncidentSeverity,
    ResponseAction,
    ResponseCategory,
    ResponsePhase,
    ResponsePriority,
    ResponseTimeframe,
)

#: MITRE ATT&CK tactic ID -> the response categories that tactic's presence
#: on a finding triggers. Tactic IDs are ATT&CK's own stable identifiers
#: (https://attack.mitre.org/tactics/enterprise/), not invented here.
_TACTIC_CATEGORY_MAP: dict[str, tuple[ResponseCategory, ...]] = {
    "TA0043": (ResponseCategory.IOC_BLOCKING,),  # Reconnaissance
    "TA0042": (ResponseCategory.IOC_BLOCKING,),  # Resource Development
    "TA0001": (ResponseCategory.NETWORK_BLOCKING, ResponseCategory.IOC_BLOCKING),  # Initial Access
    "TA0002": (ResponseCategory.EDR_ACTION,),  # Execution
    "TA0003": (
        ResponseCategory.HOST_ISOLATION,
        ResponseCategory.ACCOUNT_DISABLEMENT,
    ),  # Persistence
    "TA0004": (
        ResponseCategory.ACCOUNT_DISABLEMENT,
        ResponseCategory.PATCH_PRIORITIZATION,
    ),  # Privilege Escalation
    "TA0005": (ResponseCategory.EDR_ACTION,),  # Defense Evasion
    "TA0006": (
        ResponseCategory.PASSWORD_RESET,
        ResponseCategory.ACCOUNT_DISABLEMENT,
    ),  # Credential Access
    "TA0007": (ResponseCategory.EDR_ACTION,),  # Discovery
    "TA0008": (
        ResponseCategory.NETWORK_BLOCKING,
        ResponseCategory.HOST_ISOLATION,
    ),  # Lateral Movement
    "TA0009": (ResponseCategory.EVIDENCE_PRESERVATION,),  # Collection
    "TA0011": (
        ResponseCategory.NETWORK_BLOCKING,
        ResponseCategory.IOC_BLOCKING,
        ResponseCategory.FIREWALL_UPDATE,
    ),  # Command and Control
    "TA0010": (
        ResponseCategory.NETWORK_BLOCKING,
        ResponseCategory.FIREWALL_UPDATE,
    ),  # Exfiltration
    "TA0040": (
        ResponseCategory.BACKUP_RESTORATION,
        ResponseCategory.SERVICE_SHUTDOWN,
    ),  # Impact
}

#: Keyword bag -> response categories. Lowercased substring match against
#: the finding's `title` and `keywords`. Deliberately narrow and literal
#: (no regex) — this is a documented, low-precedence fallback, not a
#: detection engine of its own.
_KEYWORD_CATEGORY_MAP: tuple[tuple[frozenset[str], tuple[ResponseCategory, ...]], ...] = (
    (
        frozenset({"brute force", "brute-force", "failed login", "failed logins"}),
        (ResponseCategory.ACCOUNT_DISABLEMENT, ResponseCategory.PASSWORD_RESET),
    ),
    (
        frozenset({"phishing", "phish"}),
        (
            ResponseCategory.ACCOUNT_DISABLEMENT,
            ResponseCategory.PASSWORD_RESET,
            ResponseCategory.IOC_BLOCKING,
        ),
    ),
    (
        frozenset({"vulnerability", "cve", "exploit", "exploitable"}),
        (ResponseCategory.PATCH_PRIORITIZATION,),
    ),
    (
        frozenset({"malware", "ransomware", "trojan", "backdoor"}),
        (
            ResponseCategory.HOST_ISOLATION,
            ResponseCategory.EDR_ACTION,
            ResponseCategory.BACKUP_RESTORATION,
        ),
    ),
    (
        frozenset({"exfiltration", "data transfer", "data exfil"}),
        (ResponseCategory.NETWORK_BLOCKING, ResponseCategory.FIREWALL_UPDATE),
    ),
    (
        frozenset({"misconfiguration", "misconfigured"}),
        (ResponseCategory.FIREWALL_UPDATE,),
    ),
)

#: Last-resort fallback keyed purely by the finding's own severity — always
#: yields at least evidence preservation for anything MEDIUM or above,
#: matching the task's "graceful degradation is mandatory" requirement:
#: a finding that matches neither a tactic nor a keyword is still acted on,
#: never silently dropped.
_SEVERITY_FALLBACK: dict[IncidentSeverity, tuple[ResponseCategory, ...]] = {
    IncidentSeverity.CRITICAL: (
        ResponseCategory.EVIDENCE_PRESERVATION,
        ResponseCategory.HOST_ISOLATION,
    ),
    IncidentSeverity.HIGH: (
        ResponseCategory.EVIDENCE_PRESERVATION,
        ResponseCategory.HOST_ISOLATION,
    ),
    IncidentSeverity.MEDIUM: (
        ResponseCategory.EVIDENCE_PRESERVATION,
        ResponseCategory.EDR_ACTION,
    ),
    IncidentSeverity.LOW: (ResponseCategory.EVIDENCE_PRESERVATION,),
    IncidentSeverity.INFO: (),
}


class CategoryTemplate(BaseModel):
    """The static, per-category template every matched
    `ResponseCategory` expands into — `phase`/`timeframe`/`base_priority`
    are defaults `risk_prioritizer.py` may escalate (never downgrade) based
    on the triggering finding's own severity."""

    model_config = ConfigDict(frozen=True)

    category: ResponseCategory
    phase: ResponsePhase
    timeframe: ResponseTimeframe
    base_priority: ResponsePriority
    title: str
    description: str
    expected_impact: str


CATEGORY_TEMPLATES: dict[ResponseCategory, CategoryTemplate] = {
    ResponseCategory.HOST_ISOLATION: CategoryTemplate(
        category=ResponseCategory.HOST_ISOLATION,
        phase=ResponsePhase.ISOLATION,
        timeframe=ResponseTimeframe.IMMEDIATE,
        base_priority=ResponsePriority.P1_IMMEDIATE,
        title="Isolate the affected host",
        description=(
            "Disconnect the affected host from the network (or quarantine via EDR) to "
            "stop further lateral movement, command-and-control, or data exfiltration "
            "while the investigation continues."
        ),
        expected_impact=(
            "Halts the affected host's network access; disrupts legitimate use of that "
            "host until it is cleared for reconnection."
        ),
    ),
    ResponseCategory.NETWORK_BLOCKING: CategoryTemplate(
        category=ResponseCategory.NETWORK_BLOCKING,
        phase=ResponsePhase.CONTAINMENT,
        timeframe=ResponseTimeframe.IMMEDIATE,
        base_priority=ResponsePriority.P1_IMMEDIATE,
        title="Block network traffic to/from the indicator",
        description=(
            "Add a network-level block (perimeter firewall, proxy, or DNS sinkhole) for "
            "the IP/domain associated with this finding."
        ),
        expected_impact=(
            "Prevents further communication with the indicator; may briefly disrupt "
            "legitimate traffic if the indicator is shared infrastructure."
        ),
    ),
    ResponseCategory.ACCOUNT_DISABLEMENT: CategoryTemplate(
        category=ResponseCategory.ACCOUNT_DISABLEMENT,
        phase=ResponsePhase.CONTAINMENT,
        timeframe=ResponseTimeframe.IMMEDIATE,
        base_priority=ResponsePriority.P2_URGENT,
        title="Disable the affected account",
        description=(
            "Temporarily disable the account associated with this finding to prevent "
            "further use of potentially compromised credentials."
        ),
        expected_impact="Blocks the affected user until credentials are reset and reviewed.",
    ),
    ResponseCategory.PASSWORD_RESET: CategoryTemplate(
        category=ResponseCategory.PASSWORD_RESET,
        phase=ResponsePhase.RECOVERY,
        timeframe=ResponseTimeframe.SHORT_TERM,
        base_priority=ResponsePriority.P2_URGENT,
        title="Force a credential reset",
        description=(
            "Force a password reset (and re-issue any associated tokens/API keys) for "
            "the affected account(s) before re-enabling access."
        ),
        expected_impact="Invalidates any credential the attacker may have obtained.",
    ),
    ResponseCategory.IOC_BLOCKING: CategoryTemplate(
        category=ResponseCategory.IOC_BLOCKING,
        phase=ResponsePhase.CONTAINMENT,
        timeframe=ResponseTimeframe.IMMEDIATE,
        base_priority=ResponsePriority.P2_URGENT,
        title="Add indicators of compromise to blocklists",
        description=(
            "Add the finding's associated IOC(s) (IP, domain, hash) to the organization's "
            "threat-intelligence blocklist so they are blocked case-wide, not just at one "
            "control point."
        ),
        expected_impact="Prevents recurrence of the same indicator elsewhere in the estate.",
    ),
    ResponseCategory.FIREWALL_UPDATE: CategoryTemplate(
        category=ResponseCategory.FIREWALL_UPDATE,
        phase=ResponsePhase.CONTAINMENT,
        timeframe=ResponseTimeframe.SHORT_TERM,
        base_priority=ResponsePriority.P3_HIGH,
        title="Update firewall/network rules",
        description=(
            "Review and tighten the firewall or network-segmentation rules implicated by "
            "this finding (e.g. an overly permissive egress rule or exposed misconfigured "
            "service)."
        ),
        expected_impact="Reduces the exposed attack surface going forward.",
    ),
    ResponseCategory.EDR_ACTION: CategoryTemplate(
        category=ResponseCategory.EDR_ACTION,
        phase=ResponsePhase.ERADICATION,
        timeframe=ResponseTimeframe.SHORT_TERM,
        base_priority=ResponsePriority.P3_HIGH,
        title="Run an EDR scan/removal action",
        description=(
            "Trigger an EDR scan of the affected host(s) and remove any identified "
            "malicious process, file, or persistence mechanism."
        ),
        expected_impact="Removes the immediate malicious artifact from the affected host.",
    ),
    ResponseCategory.PATCH_PRIORITIZATION: CategoryTemplate(
        category=ResponseCategory.PATCH_PRIORITIZATION,
        phase=ResponsePhase.ERADICATION,
        timeframe=ResponseTimeframe.LONG_TERM,
        base_priority=ResponsePriority.P4_MEDIUM,
        title="Prioritize patching the underlying vulnerability",
        description=(
            "Schedule and prioritize patching/upgrading the vulnerable component this "
            "finding implicates, ahead of the normal patch cadence."
        ),
        expected_impact="Closes the root-cause vulnerability so it cannot be re-exploited.",
    ),
    ResponseCategory.SERVICE_SHUTDOWN: CategoryTemplate(
        category=ResponseCategory.SERVICE_SHUTDOWN,
        phase=ResponsePhase.ISOLATION,
        timeframe=ResponseTimeframe.IMMEDIATE,
        base_priority=ResponsePriority.P2_URGENT,
        title="Shut down the affected service",
        description=(
            "Stop the affected service/process to prevent further impact while the "
            "investigation and eradication steps complete."
        ),
        expected_impact="Stops active impact from the service; causes a service outage.",
    ),
    ResponseCategory.BACKUP_RESTORATION: CategoryTemplate(
        category=ResponseCategory.BACKUP_RESTORATION,
        phase=ResponsePhase.RECOVERY,
        timeframe=ResponseTimeframe.SHORT_TERM,
        base_priority=ResponsePriority.P3_HIGH,
        title="Restore from a known-clean backup",
        description=(
            "Restore the affected system/data from the most recent known-clean backup "
            "predating the incident, after eradication is confirmed complete."
        ),
        expected_impact="Returns the affected system/data to a known-good state.",
    ),
    ResponseCategory.EVIDENCE_PRESERVATION: CategoryTemplate(
        category=ResponseCategory.EVIDENCE_PRESERVATION,
        phase=ResponsePhase.CONTAINMENT,
        timeframe=ResponseTimeframe.IMMEDIATE,
        base_priority=ResponsePriority.P1_IMMEDIATE,
        title="Preserve evidence",
        description=(
            "Capture forensic evidence (memory/disk image, relevant logs) for the "
            "affected system(s) before any containment action alters state."
        ),
        expected_impact="Preserves chain of custody for later analysis/legal action.",
    ),
}


def match_categories(finding: IncidentInputFinding) -> tuple[ResponseCategory, ...]:
    """Returns the deduplicated, first-seen-order categories `finding`
    triggers, per the three-strategy precedence documented in the module
    docstring. Never raises — an unmapped tactic ID or an empty keyword bag
    simply contributes nothing from that strategy (constitution §1.7)."""
    matched: dict[ResponseCategory, None] = {}

    for tactic_id in finding.mitre_tactic_ids:
        for category in _TACTIC_CATEGORY_MAP.get(tactic_id, ()):
            matched.setdefault(category, None)

    haystack = {finding.title.lower(), *(k.lower() for k in finding.keywords)}
    for keyword_set, categories in _KEYWORD_CATEGORY_MAP:
        if any(keyword in text for keyword in keyword_set for text in haystack):
            for category in categories:
                matched.setdefault(category, None)

    if not matched:
        for category in _SEVERITY_FALLBACK.get(finding.severity, ()):
            matched.setdefault(category, None)

    return tuple(matched.keys())


def build_action(finding: IncidentInputFinding, category: ResponseCategory) -> ResponseAction:
    """Expands one matched `category` into a concrete `ResponseAction`,
    substituting `finding.target` when the triggering finding named one."""
    template = CATEGORY_TEMPLATES[category]
    title = template.title
    description = template.description
    if finding.target:
        title = f"{title}: {finding.target}"
        description = f"{description} Target: {finding.target}."
    return ResponseAction(
        category=category,
        phase=template.phase,
        title=title,
        description=description,
        target=finding.target,
    )
