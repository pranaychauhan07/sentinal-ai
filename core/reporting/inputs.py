"""`ReportGenerationContext` — the one normalized shape every already-computed
upstream signal is reduced to before `core/reporting` ever sees it (mirrors
`core.incident_response.inputs.IncidentInputFinding`'s role exactly).

Every field here is a value some other subsystem already computed — this
package performs no severity/risk/confidence/MITRE derivation of its own
(constitution §1.9); it only aggregates, summarizes, and validates.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ReportGenerationContext(BaseModel):
    """Normalized, already-computed case data handed to
    `report_engine.ReportGenerationEngine`. Nested `*_records` fields stay
    plain `dict[str, object]` entries — the same dict-shaped convention
    every `core/graph/state.py` `*_records` field already uses — since this
    package aggregates heterogeneous, already-typed-elsewhere data for
    display, not a new domain concept of its own."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    #: Case-wide, persisted `Finding` rows (SOC/Threat Hunting/Phishing/
    #: MITRE-derived) — the same records `IncidentResponseAgent` reads via
    #: `incident_response_finding_records`.
    findings: tuple[dict[str, object], ...] = ()
    #: Case-wide, resolved MITRE technique mappings (`mitre_mapping_records`).
    mitre_mappings: tuple[dict[str, object], ...] = ()
    #: This upload's already-scored IOCs (`extracted_indicators`).
    iocs: tuple[dict[str, object], ...] = ()
    #: This upload's normalized evidence summaries (filename/type only —
    #: never the raw content, which this package has no business rendering).
    evidence_items: tuple[dict[str, object], ...] = ()
    #: This run's ReAct trail (`thoughts`), used for the Investigation
    #: Timeline section — necessarily scoped to this run, not the case's
    #: full persisted `TimelineEvent` history (docs/adr/0024, Decision 2).
    thought_entries: tuple[dict[str, object], ...] = ()
    #: This upload's specialist-agent input records — the identical five
    #: fields `IncidentResponseAgent` already reads.
    vulnerability_records: tuple[dict[str, object], ...] = ()
    linux_security_records: tuple[dict[str, object], ...] = ()
    linux_advisory_records: tuple[dict[str, object], ...] = ()
    owasp_web_records: tuple[dict[str, object], ...] = ()
    owasp_security_records: tuple[dict[str, object], ...] = ()
    #: The case's most recently *persisted* `IncidentResponsePlan` (one run
    #: behind this run's own plan — docs/adr/0024, Decision 2) — `None` if
    #: no plan has ever been persisted for this case yet.
    incident_response_plan: dict[str, object] | None = None
    #: Count of malformed/skipped entries across every source above — feeds
    #: `confidence_calculator.py`'s discount, mirroring
    #: `core.incident_response.confidence_calculator.calculate_plan_confidence`.
    skipped_record_count: int = Field(default=0, ge=0)
