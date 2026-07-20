"""Performance test for core/linux_security — a large synthetic log file
(tens of thousands of lines) processed within a reasonable bound, proving
the oversized-evidence guard and general throughput are sane (constitution
§11 names "large log files"/"performance tests" explicitly)."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from core.linux_security.exceptions import OversizedLinuxSecurityDatasetError
from core.linux_security.extractor import LinuxSecurityAnalysisEngine
from core.parsers.models import ChainOfCustody, EvidenceRecord, EvidenceType, NormalizedEvidence

pytestmark = pytest.mark.integration

_RECORD_COUNT = 40_000
#: Generous ceiling for a single-process synthetic run in CI — this is a
#: sanity bound against a real performance regression, not a tight SLA.
_MAX_SECONDS = 20.0


def _synthetic_evidence(record_count: int) -> NormalizedEvidence:
    base = datetime(2026, 7, 18, 0, 0, 0, tzinfo=UTC)
    records: list[EvidenceRecord] = []
    for i in range(record_count):
        bucket = i % 500
        records.append(
            EvidenceRecord(
                line_number=i + 1,
                timestamp=base + timedelta(seconds=i),
                host="web01",
                user="deploy" if bucket % 7 else "root",
                ip_address=f"203.0.113.{bucket % 250}",
                event_type="auth_failure" if bucket % 3 else "auth_success",
                raw_line="synthetic",
            )
        )
    return NormalizedEvidence(
        evidence_type=EvidenceType.SSH_AUTH,
        source="synthetic_large_auth.log",
        parser_name="ssh_auth",
        parser_version="1.0.0",
        confidence=1.0,
        records=records,
        chain_of_custody=ChainOfCustody(
            ingested_at=datetime.now(UTC),
            ingested_by="tester",
            original_filename="synthetic_large_auth.log",
            sha256="a" * 64,
            file_size_bytes=record_count * 80,
        ),
    )


def test_large_artifact_processed_within_reasonable_bound() -> None:
    evidence = _synthetic_evidence(_RECORD_COUNT)
    engine = LinuxSecurityAnalysisEngine(max_records=_RECORD_COUNT + 1)

    started = time.perf_counter()
    result = engine.analyze(evidence)
    elapsed = time.perf_counter() - started

    assert elapsed < _MAX_SECONDS, f"analysis of {_RECORD_COUNT} records took {elapsed:.2f}s"
    assert result.candidate_count > 0


def test_oversized_guard_rejects_before_doing_any_analysis_work() -> None:
    evidence = _synthetic_evidence(_RECORD_COUNT)
    engine = LinuxSecurityAnalysisEngine(max_records=100)

    started = time.perf_counter()
    with pytest.raises(OversizedLinuxSecurityDatasetError):
        engine.analyze(evidence)
    elapsed = time.perf_counter() - started

    # The guard is a length check against `evidence.records`, not a
    # per-record scan — rejection must be effectively instantaneous even
    # for a very large artifact.
    assert elapsed < 1.0
