"""Unit tests for core/threat_intel/dedup.py — deduplicate_iocs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from core.threat_intel.dedup import deduplicate_iocs
from core.threat_intel.models import IOCRecord, IOCType


def _ioc(**overrides: object) -> IOCRecord:
    defaults: dict[str, object] = dict(
        ioc_type=IOCType.IPV4, value="1.2.3.4", raw_value="1.2.3.4", source="test"
    )
    defaults.update(overrides)
    return IOCRecord(**defaults)  # type: ignore[arg-type]


@pytest.mark.unit
def test_deduplicate_merges_same_type_and_value() -> None:
    candidates = [_ioc(), _ioc(), _ioc()]
    result = deduplicate_iocs(candidates)
    assert len(result) == 1


@pytest.mark.unit
def test_deduplicate_keeps_distinct_values_separate() -> None:
    candidates = [
        _ioc(value="1.2.3.4", raw_value="1.2.3.4"),
        _ioc(value="5.6.7.8", raw_value="5.6.7.8"),
    ]
    result = deduplicate_iocs(candidates)
    assert len(result) == 2


@pytest.mark.unit
def test_deduplicate_keeps_distinct_types_with_same_string_separate() -> None:
    candidates = [
        _ioc(ioc_type=IOCType.DOMAIN, value="80", raw_value="80"),
        _ioc(ioc_type=IOCType.PORT, value="80", raw_value="80"),
    ]
    result = deduplicate_iocs(candidates)
    assert len(result) == 2


@pytest.mark.unit
def test_deduplicate_merges_tags_without_duplicates() -> None:
    candidates = [_ioc(tags=("a", "b")), _ioc(tags=("b", "c"))]
    result = deduplicate_iocs(candidates)
    assert set(result[0].tags) == {"a", "b", "c"}


@pytest.mark.unit
def test_deduplicate_keeps_earliest_first_seen() -> None:
    now = datetime.now(UTC)
    earlier = now - timedelta(hours=1)
    candidates = [_ioc(first_seen=now), _ioc(first_seen=earlier)]
    result = deduplicate_iocs(candidates)
    assert result[0].first_seen == earlier


@pytest.mark.unit
def test_deduplicate_keeps_highest_confidence() -> None:
    candidates = [_ioc(confidence=0.4), _ioc(confidence=0.9)]
    result = deduplicate_iocs(candidates)
    assert result[0].confidence == 0.9


@pytest.mark.unit
def test_deduplicate_accumulates_line_numbers_in_context() -> None:
    candidates = [_ioc(line_number=1), _ioc(line_number=2)]
    result = deduplicate_iocs(candidates)
    assert set(result[0].context["line_numbers"]) == {1, 2}


@pytest.mark.unit
def test_deduplicate_empty_list_returns_empty() -> None:
    assert deduplicate_iocs([]) == []
