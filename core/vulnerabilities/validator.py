"""`VulnerabilityValidator` — the format-correctness gate every candidate
`VulnerabilityRecord` crosses before normalization (constitution §10, "input
validation ... at the boundary"), mirroring
`core.threat_intel.validator.IOCValidator`'s role for IOCs.
"""

from __future__ import annotations

from core.vulnerabilities.cve_extractor import is_valid_cve_id
from core.vulnerabilities.exceptions import MalformedVulnerabilityDataError
from core.vulnerabilities.models import VulnerabilityRecord

_MIN_PORT = 1
_MAX_PORT = 65535


class VulnerabilityValidator:
    """Stateless, deterministic validation. One instance is safe to share
    across a whole pipeline run (no internal mutable state)."""

    def validate(self, record: VulnerabilityRecord) -> None:
        """Raises `MalformedVulnerabilityDataError` if `record` fails a
        structural rule. Returns `None` on success — callers treat "did not
        raise" as the pass signal, matching
        `core.parsers.base.BaseParser.raise_if_invalid`'s convention."""
        if not record.cve_id and not record.plugin_id and not record.plugin_name:
            raise MalformedVulnerabilityDataError(
                "Vulnerability candidate has no CVE ID, plugin ID, or plugin name to "
                "identify it by.",
                details={"vuln_id": str(record.vuln_id)},
            )
        if record.cve_id is not None and not is_valid_cve_id(record.cve_id):
            raise MalformedVulnerabilityDataError(
                f"'{record.cve_id}' is not a well-formed CVE identifier.",
                details={"cve_id": record.cve_id},
            )
        if record.port is not None and not (_MIN_PORT <= record.port <= _MAX_PORT):
            raise MalformedVulnerabilityDataError(
                f"Port {record.port} is outside the valid {_MIN_PORT}-{_MAX_PORT} range.",
                details={"port": record.port},
            )

    def is_valid(self, record: VulnerabilityRecord) -> bool:
        try:
            self.validate(record)
        except MalformedVulnerabilityDataError:
            return False
        return True
