"""Deterministic severity and priority assignment — pure functions,
unit-testable exactly like `core.threat_intel.scoring`/`core.findings.severity`
(constitution §1.9). No LLM reasoning anywhere in this module.
"""

from __future__ import annotations

from core.knowledge.cvss_calculator import CvssScore, CvssSeverity
from core.vulnerabilities.models import (
    AssetCriticality,
    VulnerabilityPriority,
    VulnerabilitySeverity,
)

#: `CvssSeverity` -> `VulnerabilitySeverity`, a direct scale mapping (the
#: two enums intentionally share the same five-level shape, per each
#: package's own severity-scale ownership — see `core.vulnerabilities.models`
#: module docstring, mirroring `core.findings.severity`'s identical
#: `ThreatSeverity` -> `FindingSeverity` mapping precedent).
_CVSS_TO_VULNERABILITY_SEVERITY: dict[CvssSeverity, VulnerabilitySeverity] = {
    CvssSeverity.INFO: VulnerabilitySeverity.INFO,
    CvssSeverity.LOW: VulnerabilitySeverity.LOW,
    CvssSeverity.MEDIUM: VulnerabilitySeverity.MEDIUM,
    CvssSeverity.HIGH: VulnerabilitySeverity.HIGH,
    CvssSeverity.CRITICAL: VulnerabilitySeverity.CRITICAL,
}

#: Nessus/OpenVAS's own 0-4 integer severity scale (both tools use this
#: identical convention), used as a fallback when a plugin reports no CVSS
#: at all (a real, common case for purely informational findings).
SCANNER_SEVERITY_CODE_MAP: dict[int, VulnerabilitySeverity] = {
    0: VulnerabilitySeverity.INFO,
    1: VulnerabilitySeverity.LOW,
    2: VulnerabilitySeverity.MEDIUM,
    3: VulnerabilitySeverity.HIGH,
    4: VulnerabilitySeverity.CRITICAL,
}

SEVERITY_ORDER: tuple[VulnerabilitySeverity, ...] = (
    VulnerabilitySeverity.INFO,
    VulnerabilitySeverity.LOW,
    VulnerabilitySeverity.MEDIUM,
    VulnerabilitySeverity.HIGH,
    VulnerabilitySeverity.CRITICAL,
)


def severity_from_cvss(cvss: CvssScore) -> VulnerabilitySeverity:
    """Direct mapping — see module-level docstring."""
    return _CVSS_TO_VULNERABILITY_SEVERITY[cvss.severity]


def severity_from_scanner_code(code: int) -> VulnerabilitySeverity:
    """Maps a raw Nessus/OpenVAS 0-4 severity code. Clamped to the known
    range rather than raising — a scanner reporting an out-of-range code is
    a documented degrade, not a hard failure (constitution §1.7)."""
    clamped = max(0, min(4, code))
    return SCANNER_SEVERITY_CODE_MAP[clamped]


def assign_priority(
    severity: VulnerabilitySeverity, asset_criticality: AssetCriticality
) -> VulnerabilityPriority:
    """Analyst triage priority — severity dominates, asset criticality
    escalates within a severity band (task requirement: priority distinct
    from severity, folding in "Asset Criticality")."""
    critical_asset = asset_criticality in (AssetCriticality.HIGH, AssetCriticality.CRITICAL)

    if severity is VulnerabilitySeverity.CRITICAL:
        return VulnerabilityPriority.P1_CRITICAL
    if severity is VulnerabilitySeverity.HIGH:
        return (
            VulnerabilityPriority.P1_CRITICAL if critical_asset else VulnerabilityPriority.P2_HIGH
        )
    if severity is VulnerabilitySeverity.MEDIUM:
        return VulnerabilityPriority.P2_HIGH if critical_asset else VulnerabilityPriority.P3_MEDIUM
    if severity is VulnerabilitySeverity.LOW:
        return VulnerabilityPriority.P3_MEDIUM if critical_asset else VulnerabilityPriority.P4_LOW
    return VulnerabilityPriority.P4_LOW
