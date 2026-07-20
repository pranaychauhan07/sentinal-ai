"""``FindingGenerator`` — the task's named "Finding Generator" capability:
the single place a `SourceFinding` is normalized into the unified
`SastFinding` shape (OWASP category, CWE id, severity, confidence, evidence
reference, explanation, recommended remediation), applying
`confidence_calculator.calculate_confidence` and
`evidence_mapper.map_evidence_reference`.
"""

from __future__ import annotations

from core.owasp_security.confidence_calculator import calculate_confidence
from core.owasp_security.evidence_mapper import map_evidence_reference
from core.owasp_security.models import SastFinding, SourceFinding

_DEFAULT_REMEDIATION = "Review and remediate per the finding's explanation."


class FindingGenerator:
    def generate(self, findings: list[SourceFinding]) -> list[SastFinding]:
        return [self._from_source_finding(finding) for finding in findings]

    def _from_source_finding(self, finding: SourceFinding) -> SastFinding:
        source = "python_ast_analyzer" if finding.is_ast_based else "pattern_analyzer"
        return SastFinding(
            category=finding.category,
            owasp_category=finding.owasp_category,
            cwe_id=finding.cwe_id,
            severity=finding.severity,
            confidence=calculate_confidence(finding.confidence, is_ast_based=finding.is_ast_based),
            evidence_reference=map_evidence_reference(finding),
            explanation=finding.explanation,
            recommended_remediation=finding.recommendation or _DEFAULT_REMEDIATION,
            source=source,
        )
