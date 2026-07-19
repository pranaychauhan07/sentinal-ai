"""`FindingGenerationEngine` — composes mapping -> aggregation -> confidence
-> severity into candidate `FindingRecord`s. This is the in-package half of
the Finding Engine pipeline the task's diagram describes; persistence,
event publication, and memory notification are the service layer's job
(`core/services/finding_service.py`), matching the exact split
`core/threat_intel`/`threat_intel_service.py` already established.

**Clustering strategy:** one candidate Finding per mapped ATT&CK technique,
grouping that mapping's `supporting_ioc_ids` as its evidence — the
simplest deterministic clustering that still satisfies "many-IOCs-to-one-
technique" and gives the deduplication stage genuinely overlapping
candidates to merge when two techniques share supporting IOCs. A future
milestone could cluster by connected components across shared IOCs instead;
documented here as a deliberate, not accidental, scope choice.
"""

from __future__ import annotations

import uuid

from core.findings.confidence_engine import ConfidenceEngine
from core.findings.evidence_aggregation import EvidenceAggregator
from core.findings.mapping_engine import MitreMappingEngine
from core.findings.models import FindingRecord
from core.findings.severity import assign_priority, assign_severity, calculate_risk_score
from core.knowledge.mitre.lookup import MitreLookup
from core.threat_intel.models import ScoredIOC, SourceReliability


class FindingGenerationEngine:
    def __init__(
        self,
        *,
        mapping_engine: MitreMappingEngine,
        lookup: MitreLookup,
        evidence_aggregator: EvidenceAggregator | None = None,
        confidence_engine: ConfidenceEngine | None = None,
    ) -> None:
        self._mapping_engine = mapping_engine
        self._lookup = lookup
        self._evidence_aggregator = evidence_aggregator or EvidenceAggregator()
        self._confidence_engine = confidence_engine or ConfidenceEngine()

    def generate(
        self,
        case_id: uuid.UUID,
        iocs: list[ScoredIOC],
        *,
        source_reliability: SourceReliability = SourceReliability.UNKNOWN,
    ) -> list[FindingRecord]:
        """Returns one candidate `FindingRecord` per mapped technique found
        across `iocs`. An IOC set that maps to nothing produces an empty
        list — never a forced, unmapped Finding (blueprint §7's MITRE Agent
        contract, restated for the deterministic engine)."""
        mappings = self._mapping_engine(iocs)
        if not mappings:
            return []

        iocs_by_id = {ioc.record.ioc_id: ioc for ioc in iocs}
        findings: list[FindingRecord] = []
        for mapping in mappings:
            supporting = [
                iocs_by_id[ioc_id] for ioc_id in mapping.supporting_ioc_ids if ioc_id in iocs_by_id
            ]
            if not supporting:
                continue

            bundle = self._evidence_aggregator.aggregate(supporting)
            confidence = self._confidence_engine.calculate(
                supporting, [mapping], source_reliability=source_reliability
            )
            severity = assign_severity(supporting, [mapping], confidence)
            priority = assign_priority(severity, confidence)
            risk_score = calculate_risk_score(severity, confidence)
            technique = self._lookup.technique_by_id(mapping.technique_id)

            findings.append(
                FindingRecord(
                    case_id=case_id,
                    title=f"{technique.name} ({technique.technique_id}) detected",
                    description=(
                        f"{len(supporting)} indicator(s) mapped to ATT&CK technique "
                        f"{technique.technique_id} ({technique.name}) with "
                        f"{mapping.confidence:.2f} mapping confidence."
                    ),
                    severity=severity,
                    confidence=confidence,
                    priority=priority,
                    evidence_refs=bundle.evidence_ids,
                    ioc_refs=bundle.ioc_ids,
                    mitre_mappings=(mapping,),
                    timeline=bundle.timeline,
                    affected_assets=bundle.affected_assets,
                    risk_score=risk_score,
                )
            )
        return findings
