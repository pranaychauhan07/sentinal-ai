"""Performance test for core/owasp_security — a large synthetic Python
"repository" file (multi-thousand lines) processed within a reasonable
bound, proving the oversized-input guard and general AST-analysis
throughput are sane (constitution §11 names "large log files"/"performance
tests" explicitly; the task brief names "large repositories" explicitly)."""

from __future__ import annotations

import time

import pytest

from core.owasp_security.analysis_engine import SourceCodeAnalysisEngine
from core.owasp_security.exceptions import OversizedSourceInputError

pytestmark = pytest.mark.integration

_FUNCTION_COUNT = 2_000
#: Generous ceiling for a single-process synthetic run in CI — this is a
#: sanity bound against a real performance regression, not a tight SLA.
_MAX_SECONDS = 20.0


def _synthetic_large_source(function_count: int) -> str:
    lines = ["import os", "import subprocess", ""]
    for i in range(function_count):
        if i % 100 == 0:
            lines.append(f"def handler_{i}(cmd):")
            lines.append("    os.system(cmd)")
        elif i % 233 == 0:
            lines.append(f"def runner_{i}(cmd):")
            lines.append("    subprocess.call(cmd, shell=True)")
        else:
            lines.append(f"def util_{i}(a, b):")
            lines.append("    return a + b")
    return "\n".join(lines) + "\n"


def test_large_repository_file_processed_within_reasonable_bound() -> None:
    source = _synthetic_large_source(_FUNCTION_COUNT)
    line_count = len(source.splitlines())
    engine = SourceCodeAnalysisEngine(max_lines=line_count + 1, max_total_chars=10_000_000)

    started = time.perf_counter()
    advice = engine.analyze(source, filename="big_module.py")
    elapsed = time.perf_counter() - started

    assert elapsed < _MAX_SECONDS, f"analysis of {line_count} lines took {elapsed:.2f}s"
    assert advice.total_line_count == line_count
    assert advice.parse_degraded is False
    assert len(advice.sast_findings) > 0


def test_oversized_guard_rejects_before_doing_any_analysis_work() -> None:
    source = _synthetic_large_source(_FUNCTION_COUNT)
    engine = SourceCodeAnalysisEngine(max_lines=100, max_total_chars=10_000_000)

    started = time.perf_counter()
    with pytest.raises(OversizedSourceInputError):
        engine.analyze(source, filename="big_module.py")
    elapsed = time.perf_counter() - started

    # The guard is a length check, not a per-line/AST scan — rejection must
    # be effectively instantaneous even for a very large artifact.
    assert elapsed < 1.0
