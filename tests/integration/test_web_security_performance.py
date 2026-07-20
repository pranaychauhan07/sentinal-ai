"""Performance test for core/owasp_web — a large synthetic HTTP transcript
(multi-thousand lines) processed within a reasonable bound, proving the
oversized-input guard and general throughput are sane (constitution §11
names "large log files"/"performance tests" explicitly)."""

from __future__ import annotations

import time

import pytest

from core.owasp_web.advisory_engine import WebSecurityAdvisoryEngine
from core.owasp_web.exceptions import OversizedWebSecurityInputError

pytestmark = pytest.mark.integration

_LINE_COUNT = 5_000
#: Generous ceiling for a single-process synthetic run in CI — this is a
#: sanity bound against a real performance regression, not a tight SLA.
_MAX_SECONDS = 20.0


def _synthetic_lines(line_count: int) -> list[str]:
    lines: list[str] = []
    for i in range(line_count):
        if i % 500 == 0:
            lines.append(f"Set-Cookie: session{i}=abc; Path=/")
        elif i % 233 == 0:
            lines.append("Index of /backups")
        else:
            lines.append(f"X-Custom-Header-{i % 50}: value{i}")
    return lines


def test_large_transcript_processed_within_reasonable_bound() -> None:
    lines = _synthetic_lines(_LINE_COUNT)
    engine = WebSecurityAdvisoryEngine(max_lines=_LINE_COUNT + 1, max_total_chars=10_000_000)

    started = time.perf_counter()
    advice = engine.analyze(lines)
    elapsed = time.perf_counter() - started

    assert elapsed < _MAX_SECONDS, f"analysis of {_LINE_COUNT} lines took {elapsed:.2f}s"
    assert advice.total_line_count == _LINE_COUNT


def test_oversized_guard_rejects_before_doing_any_analysis_work() -> None:
    lines = _synthetic_lines(_LINE_COUNT)
    engine = WebSecurityAdvisoryEngine(max_lines=100, max_total_chars=10_000_000)

    started = time.perf_counter()
    with pytest.raises(OversizedWebSecurityInputError):
        engine.analyze(lines)
    elapsed = time.perf_counter() - started

    # The guard is a length check, not a per-line scan — rejection must be
    # effectively instantaneous even for a very large artifact.
    assert elapsed < 1.0
