"""``map_evidence_reference`` — the task's named "Evidence Mapping"
capability: a small, pure function producing a human-readable evidence
reference string for one `SourceFinding`, used by `finding_generator.py`.
"""

from __future__ import annotations

from core.owasp_security.models import SourceFinding


def map_evidence_reference(finding: SourceFinding) -> str:
    if finding.line_number is not None:
        base = f"{finding.file_path}:{finding.line_number}"
    else:
        base = finding.file_path
    if finding.code_snippet:
        return f"{base}: {finding.code_snippet}"
    return base
