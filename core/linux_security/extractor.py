"""`LinuxSecurityAnalysisEngine` — the orchestrating pipeline (mirrors
`core.vulnerabilities.extractor.VulnerabilityExtractionEngine`'s "discovery
engine" role, extended here to run every analyzer since this framework has
no separate validate/normalize services stage split the way scan-report
extraction does — see `core/services/linux_security_service.py`'s
`LinuxSecurityPipeline` for the stage-by-stage orchestration this engine's
`analyze()` method is invoked from).

Takes `list[NormalizedEvidence]` (already filtered by the service layer to
`SSH_AUTH`/`SYSLOG` evidence types), runs `normalizer.py` then every analyzer,
and returns one `NormalizedLinuxSecurityIntel`. Includes an oversized-evidence
guard (a configurable max-records-per-artifact cap, matching
`VULNERABILITY_MAX_RECORDS_PER_ARTIFACT`'s precedent) and defends against
malformed/corrupted lines and invalid timestamps by skipping the individual
bad record (never aborting the whole artifact, constitution §1.7).
"""

from __future__ import annotations

from core.linux_security.authentication_timeline import build_timeline
from core.linux_security.confidence_engine import LinuxSecurityConfidenceEngine
from core.linux_security.cron_analyzer import CronAnalyzer
from core.linux_security.exceptions import OversizedLinuxSecurityDatasetError
from core.linux_security.finding_generator import LinuxSecurityFindingGenerator
from core.linux_security.models import (
    LinuxLogEvent,
    LinuxSecurityCandidate,
    NormalizedLinuxSecurityIntel,
)
from core.linux_security.normalizer import LinuxSecurityNormalizer
from core.linux_security.persistence_detector import detect_persistence_mechanisms
from core.linux_security.privilege_escalation import PrivilegeEscalationDetector
from core.linux_security.process_detector import scan_generic_process_lines
from core.linux_security.scoring import LinuxThreatScoringEngine, score_candidates
from core.linux_security.service_analyzer import ServiceAnalyzer
from core.linux_security.ssh_auth_analyzer import SshAuthAnalyzer
from core.linux_security.sudo_analyzer import SudoActivityAnalyzer
from core.logging import get_logger
from core.parsers.models import NormalizedEvidence

_logger = get_logger(__name__)

#: Resource-exhaustion guard for the whole artifact (constitution §10),
#: overridable per-instance, driven by
#: `Settings.linux_security_max_records_per_artifact`.
DEFAULT_MAX_RECORDS_PER_ARTIFACT = 20_000


class LinuxSecurityAnalysisEngine:
    """Orchestrates every analyzer in this package over one evidence
    artifact's normalized events. Deterministic, zero LLM calls (constitution
    §1.9)."""

    name = "linux_security_analysis_engine"
    version = "1.0.0"

    def __init__(
        self,
        *,
        max_records: int = DEFAULT_MAX_RECORDS_PER_ARTIFACT,
        ssh_auth_analyzer: SshAuthAnalyzer | None = None,
        sudo_analyzer: SudoActivityAnalyzer | None = None,
        privilege_escalation_detector: PrivilegeEscalationDetector | None = None,
        cron_analyzer: CronAnalyzer | None = None,
        service_analyzer: ServiceAnalyzer | None = None,
        confidence_engine: LinuxSecurityConfidenceEngine | None = None,
        scoring_engine: LinuxThreatScoringEngine | None = None,
    ) -> None:
        self._max_records = max_records
        self._normalizer = LinuxSecurityNormalizer()
        self._ssh_auth_analyzer = ssh_auth_analyzer or SshAuthAnalyzer()
        self._sudo_analyzer = sudo_analyzer or SudoActivityAnalyzer()
        self._privilege_escalation_detector = (
            privilege_escalation_detector or PrivilegeEscalationDetector()
        )
        self._cron_analyzer = cron_analyzer or CronAnalyzer()
        self._service_analyzer = service_analyzer or ServiceAnalyzer()
        self._confidence_engine = confidence_engine or LinuxSecurityConfidenceEngine()
        self._scoring_engine = scoring_engine or LinuxThreatScoringEngine()
        self._finding_generator = LinuxSecurityFindingGenerator()

    def analyze(self, evidence: NormalizedEvidence) -> NormalizedLinuxSecurityIntel:
        self._raise_if_oversized(len(evidence.records))

        events, skipped = self._normalizer.normalize(evidence)
        timeline = build_timeline(events)
        candidates = self._run_analyzers(events)

        scored = score_candidates(
            candidates,
            evidence_quality=evidence.confidence,
            confidence_engine=self._confidence_engine,
            scoring_engine=self._scoring_engine,
        )
        findings = self._finding_generator.generate(scored)

        return NormalizedLinuxSecurityIntel(
            evidence_id=evidence.evidence_id,
            source=evidence.source,
            extractor_name=self.name,
            extractor_version=self.version,
            candidates=tuple(scored),
            findings=tuple(findings),
            timeline=tuple(timeline),
            skipped_record_count=skipped,
            metadata={"event_count": len(events)},
        )

    def _run_analyzers(self, events: list[LinuxLogEvent]) -> list[LinuxSecurityCandidate]:
        ssh_candidates = self._ssh_auth_analyzer.analyze(events)
        sudo_candidates = self._sudo_analyzer.analyze(events)
        privesc_candidates = self._privilege_escalation_detector.analyze(events)
        cron_candidates = self._cron_analyzer.analyze(events)
        service_candidates = self._service_analyzer.analyze(events)
        generic_process_candidates = scan_generic_process_lines(events)
        persistence_candidates = detect_persistence_mechanisms(
            cron_candidates, service_candidates, privesc_candidates
        )

        return [
            *ssh_candidates,
            *sudo_candidates,
            *privesc_candidates,
            *cron_candidates,
            *service_candidates,
            *generic_process_candidates,
            *persistence_candidates,
        ]

    def _raise_if_oversized(self, count: int) -> None:
        if count > self._max_records:
            raise OversizedLinuxSecurityDatasetError(
                f"Evidence artifact contains {count} record(s), exceeding the "
                f"{self._max_records}-record analysis limit.",
                details={"count": count, "max_records": self._max_records},
            )


__all__ = ["LinuxSecurityAnalysisEngine"]
