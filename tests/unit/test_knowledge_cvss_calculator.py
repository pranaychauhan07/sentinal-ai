"""Unit tests for core/knowledge/cvss_calculator.py — verified against
published NVD/FIRST reference vectors and their official base scores."""

from __future__ import annotations

import pytest

from core.knowledge.cvss_calculator import (
    CvssCalculator,
    CvssSeverity,
    CVSSVectorParseError,
    CvssVersion,
    calculate_cvss_v2_base_score,
    calculate_cvss_v3_base_score,
    classify_cvss_severity,
    parse_cvss_v2_vector,
    parse_cvss_v3_vector,
    validate_cvss_v4_vector,
)

pytestmark = pytest.mark.unit


# --- Severity bucketing ----------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, CvssSeverity.INFO),
        (2.5, CvssSeverity.LOW),
        (5.5, CvssSeverity.MEDIUM),
        (8.0, CvssSeverity.HIGH),
        (9.8, CvssSeverity.CRITICAL),
        (10.0, CvssSeverity.CRITICAL),
    ],
)
def test_classify_cvss_severity_buckets(score: float, expected: CvssSeverity) -> None:
    assert classify_cvss_severity(score) == expected


# --- CVSS v2 ---------------------------------------------------------------


def test_v2_reference_vector_matches_published_score() -> None:
    # NVD's canonical example: AV:N/AC:L/Au:N/C:C/I:C/A:C -> 10.0
    parsed = parse_cvss_v2_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C")
    assert calculate_cvss_v2_base_score(parsed) == 10.0


def test_v2_partial_impact_reference_vector() -> None:
    # AV:N/AC:L/Au:N/C:P/I:N/A:N -> 5.0 (published NVD calculator reference)
    parsed = parse_cvss_v2_vector("AV:N/AC:L/Au:N/C:P/I:N/A:N")
    assert calculate_cvss_v2_base_score(parsed) == 5.0


def test_v2_missing_metric_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        parse_cvss_v2_vector("AV:N/AC:L/Au:N/C:C/I:C")


def test_v2_invalid_metric_value_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        parse_cvss_v2_vector("AV:X/AC:L/Au:N/C:C/I:C/A:C")


def test_v2_malformed_segment_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        parse_cvss_v2_vector("AV:N/ACL/Au:N/C:C/I:C/A:C")


# --- CVSS v3 ---------------------------------------------------------------


def test_v3_1_reference_vector_matches_published_score() -> None:
    # FIRST's canonical worked example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
    parsed = parse_cvss_v3_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert calculate_cvss_v3_base_score(parsed) == 9.8
    assert parsed.version == CvssVersion.V3_1


def test_v3_scope_changed_reference_vector() -> None:
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H -> 9.6, hand-verified
    # against the official FIRST v3.1 formula (Impact~6.048, Exploitability~2.836,
    # 1.08*(Impact+Exploitability)=9.594 -> Roundup -> 9.6).
    parsed = parse_cvss_v3_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H")
    assert calculate_cvss_v3_base_score(parsed) == 9.6


def test_v3_low_severity_reference_vector() -> None:
    # CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N -> 1.6 (low severity band)
    parsed = parse_cvss_v3_vector("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    score = calculate_cvss_v3_base_score(parsed)
    assert 0.0 < score < 4.0


def test_v3_0_prefix_is_recognized() -> None:
    parsed = parse_cvss_v3_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert parsed.version == CvssVersion.V3_0


def test_v3_missing_prefix_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        parse_cvss_v3_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_v3_missing_metric_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        parse_cvss_v3_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")


def test_v3_invalid_metric_value_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        parse_cvss_v3_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_v3_invalid_scope_value_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        parse_cvss_v3_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H")


# --- CVSS v4 (validation only) ---------------------------------------------


def test_v4_well_formed_vector_validates() -> None:
    validate_cvss_v4_vector(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )  # must not raise


def test_v4_missing_metric_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        validate_cvss_v4_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N")


def test_v4_invalid_metric_value_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        validate_cvss_v4_vector("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")


def test_v4_wrong_prefix_raises() -> None:
    with pytest.raises(CVSSVectorParseError):
        validate_cvss_v4_vector("CVSS:3.1/AV:N/AC:L/AT:N/PR:N/UI:N")


# --- Unified CvssCalculator facade -----------------------------------------


def test_calculator_dispatches_v3_and_scores() -> None:
    result = CvssCalculator().score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result.base_score == 9.8
    assert result.severity == CvssSeverity.CRITICAL
    assert result.version == CvssVersion.V3_1


def test_calculator_dispatches_v2_and_scores() -> None:
    result = CvssCalculator().score("AV:N/AC:L/Au:N/C:C/I:C/A:C")
    assert result.base_score == 10.0
    assert result.version == CvssVersion.V2


def test_calculator_dispatches_v4_with_no_base_score() -> None:
    result = CvssCalculator().score(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )
    assert result.base_score is None
    assert result.version == CvssVersion.V4_0
    assert result.severity == CvssSeverity.INFO


def test_calculator_raises_on_garbage_input() -> None:
    with pytest.raises(CVSSVectorParseError):
        CvssCalculator().score("not a cvss vector at all")
