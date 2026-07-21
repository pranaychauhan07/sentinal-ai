"""Deterministic severity, priority, and risk-score assignment — pure
functions, unit-testable exactly like `core.threat_intel.scoring`
(constitution §1.9). No LLM reasoning anywhere in this module.
"""

from __future__ import annotations

from core.findings.models import FindingConfidence, FindingPriority, FindingSeverity, MitreMapping
from core.threat_intel.models import ScoredIOC, ThreatSeverity

#: `ThreatSeverity` -> `FindingSeverity`, a direct scale mapping (the two
#: enums intentionally share the same five-level shape, per each package's
#: own severity-scale ownership documented in `core/findings/models.py`).
_THREAT_TO_FINDING_SEVERITY: dict[ThreatSeverity, FindingSeverity] = {
    ThreatSeverity.INFO: FindingSeverity.INFO,
    ThreatSeverity.LOW: FindingSeverity.LOW,
    ThreatSeverity.MEDIUM: FindingSeverity.MEDIUM,
    ThreatSeverity.HIGH: FindingSeverity.HIGH,
    ThreatSeverity.CRITICAL: FindingSeverity.CRITICAL,
}

SEVERITY_ORDER: tuple[FindingSeverity, ...] = (
    FindingSeverity.INFO,
    FindingSeverity.LOW,
    FindingSeverity.MEDIUM,
    FindingSeverity.HIGH,
    FindingSeverity.CRITICAL,
)

#: `FindingSeverity` -> a 0-100 weight, used by `calculate_risk_score`.
_SEVERITY_SCORE_WEIGHTS: dict[FindingSeverity, float] = {
    FindingSeverity.INFO: 0.0,
    FindingSeverity.LOW: 25.0,
    FindingSeverity.MEDIUM: 50.0,
    FindingSeverity.HIGH: 75.0,
    FindingSeverity.CRITICAL: 100.0,
}

#: ATT&CK tactics whose presence escalates severity by one level when
#: confidence is high enough — these tactics represent especially
#: consequential adversary progress (data destruction, credential theft,
#: active C2), distinct from earlier-stage tactics like discovery.
_HIGH_IMPACT_TACTIC_IDS = frozenset({"TA0040", "TA0006", "TA0011"})

#: Composite confidence at or above which a high-impact tactic actually
#: escalates severity — a low-confidence mapping to a high-impact tactic
#: should not itself force a severity escalation.
_ESCALATION_CONFIDENCE_THRESHOLD = 0.6


def assign_severity(
    iocs: list[ScoredIOC], mappings: list[MitreMapping], confidence: FindingConfidence
) -> FindingSeverity:
    """The Finding's severity starts from the highest severity among its
    supporting IOCs, then escalates one level if a high-impact tactic was
    mapped with sufficient confidence."""
    if not iocs:
        raise ValueError("assign_severity requires at least one ScoredIOC.")

    base = max(
        (_THREAT_TO_FINDING_SEVERITY[ioc.record.severity] for ioc in iocs),
        key=SEVERITY_ORDER.index,
    )

    touches_high_impact_tactic = any(
        set(mapping.tactic_ids) & _HIGH_IMPACT_TACTIC_IDS for mapping in mappings
    )
    if touches_high_impact_tactic and confidence.composite >= _ESCALATION_CONFIDENCE_THRESHOLD:
        index = min(SEVERITY_ORDER.index(base) + 1, len(SEVERITY_ORDER) - 1)
        return SEVERITY_ORDER[index]
    return base


def explain_severity(
    iocs: list[ScoredIOC], mappings: list[MitreMapping], confidence: FindingConfidence
) -> str:
    """Companion to `assign_severity` — same inputs, produces the
    human-readable "why" a task-required explainability field needs,
    without changing `assign_severity`'s own signature/behavior (kept as a
    second, pure function rather than folding a string return into the
    existing one, so every existing caller of `assign_severity` is
    unaffected)."""
    if not iocs:
        return "No supporting indicators."

    base_ioc = max(
        iocs, key=lambda ioc: SEVERITY_ORDER.index(_THREAT_TO_FINDING_SEVERITY[ioc.record.severity])
    )
    base = _THREAT_TO_FINDING_SEVERITY[base_ioc.record.severity]
    base_text = (
        f"Base severity '{base.value}' from the highest-severity supporting indicator: "
        f"{base_ioc.record.ioc_type.value} {base_ioc.record.value!r} "
        f"(classified {base_ioc.record.severity.value})."
    )

    touched_tactics = sorted(
        {
            tactic_id
            for mapping in mappings
            for tactic_id in mapping.tactic_ids
            if tactic_id in _HIGH_IMPACT_TACTIC_IDS
        }
    )
    if touched_tactics and confidence.composite >= _ESCALATION_CONFIDENCE_THRESHOLD:
        return (
            f"{base_text} Escalated one level because this finding maps to high-impact "
            f"tactic(s) {', '.join(touched_tactics)} with composite confidence "
            f"{confidence.composite:.2f} (>= the {_ESCALATION_CONFIDENCE_THRESHOLD:.2f} "
            f"escalation threshold)."
        )
    if touched_tactics:
        return (
            f"{base_text} Maps to high-impact tactic(s) {', '.join(touched_tactics)}, but "
            f"composite confidence {confidence.composite:.2f} is below the "
            f"{_ESCALATION_CONFIDENCE_THRESHOLD:.2f} escalation threshold, so no escalation "
            f"was applied."
        )
    return f"{base_text} No high-impact tactic mapped, so no escalation was applied."


def assign_priority(severity: FindingSeverity, confidence: FindingConfidence) -> FindingPriority:
    """Analyst triage priority — severity dominates, confidence breaks ties
    within a severity band (task requirement: priority distinct from
    severity)."""
    if severity is FindingSeverity.CRITICAL:
        return FindingPriority.P1_CRITICAL
    if severity is FindingSeverity.HIGH:
        return (
            FindingPriority.P1_CRITICAL if confidence.composite >= 0.6 else FindingPriority.P2_HIGH
        )
    if severity is FindingSeverity.MEDIUM:
        return FindingPriority.P2_HIGH if confidence.composite >= 0.6 else FindingPriority.P3_MEDIUM
    if severity is FindingSeverity.LOW:
        return FindingPriority.P3_MEDIUM if confidence.composite >= 0.3 else FindingPriority.P4_LOW
    return FindingPriority.P4_LOW


def calculate_risk_score(severity: FindingSeverity, confidence: FindingConfidence) -> float:
    """0-100 triage/sort score — severity-weighted, confidence-moderated,
    matching `core.threat_intel.scoring.ThreatScoringEngine.score`'s
    "severity anchors the score, confidence adjusts it" shape."""
    severity_weight = _SEVERITY_SCORE_WEIGHTS[severity]
    combined = 0.6 * severity_weight + 0.4 * (confidence.composite * 100.0)
    return round(max(0.0, min(100.0, combined)), 2)
