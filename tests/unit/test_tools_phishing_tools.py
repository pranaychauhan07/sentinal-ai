"""Unit tests for core/tools/phishing_tools.py."""

from __future__ import annotations

import pytest

from core.parsers.models import Severity
from core.tools.phishing_tools import (
    PhishingScoringInput,
    PhishingScoringTool,
    classify_phishing_risk,
    count_urgency_phrases,
    high_risk_attachments,
    sender_reply_to_mismatch,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (95.0, Severity.CRITICAL),
        (60.0, Severity.HIGH),
        (35.0, Severity.MEDIUM),
        (15.0, Severity.LOW),
        (0.0, Severity.INFO),
    ],
)
def test_classify_phishing_risk_buckets(value: float, expected: Severity) -> None:
    assert classify_phishing_risk(value) == expected


@pytest.mark.unit
def test_sender_reply_to_mismatch_true_for_different_domains() -> None:
    assert sender_reply_to_mismatch("support@amazon.com", "reply@totally-different.xyz") is True


@pytest.mark.unit
def test_sender_reply_to_mismatch_false_when_reply_to_absent() -> None:
    assert sender_reply_to_mismatch("support@amazon.com", "") is False


@pytest.mark.unit
def test_sender_reply_to_mismatch_false_for_same_domain() -> None:
    assert sender_reply_to_mismatch("support@amazon.com", "billing@amazon.com") is False


@pytest.mark.unit
def test_count_urgency_phrases_counts_distinct_phrases_once() -> None:
    subject = "URGENT: Your account has been suspended"
    body = "verify your account immediately. urgent urgent urgent."
    # "urgent" appears in subject once and 3x in body but should count once,
    # "your account has been" and "suspended" and "verify your account" each once.
    count = count_urgency_phrases(subject, body)
    assert count >= 3


@pytest.mark.unit
def test_high_risk_attachments_flags_executable_extensions() -> None:
    attachments = [
        {"filename": "invoice.pdf", "content_type": "application/pdf"},
        {"filename": "payload.exe", "content_type": "application/octet-stream"},
    ]
    assert high_risk_attachments(attachments) == ("payload.exe",)


@pytest.mark.unit
def test_high_risk_attachments_empty_for_no_attachments() -> None:
    assert high_risk_attachments([]) == ()


@pytest.mark.unit
def test_scoring_tool_combines_all_signals() -> None:
    tool = PhishingScoringTool()
    result = tool(
        PhishingScoringInput(
            from_address="support@amaz0n-security-verify.xyz",
            reply_to_address="",
            subject="URGENT: Your account has been suspended",
            body_text="Click here immediately to verify your account.",
            attachments=[{"filename": "invoice.exe", "content_type": "application/octet-stream"}],
            attributed_ioc_scores=[82.0, 40.0],
            prompt_injection_flagged=False,
        )
    )
    assert result.risk_label in (Severity.HIGH, Severity.CRITICAL)
    assert result.max_attributed_ioc_score == 82.0
    assert result.high_risk_attachments == ("invoice.exe",)
    assert len(result.indicators) >= 2


@pytest.mark.unit
def test_scoring_tool_benign_email_scores_low() -> None:
    tool = PhishingScoringTool()
    result = tool(
        PhishingScoringInput(
            from_address="notifications@github.com",
            reply_to_address="",
            subject="[repo] New pull request opened",
            body_text="A new pull request was opened. View it here: https://github.com/x/y/pull/1",
            attachments=[],
            attributed_ioc_scores=[5.0],
            prompt_injection_flagged=False,
        )
    )
    assert result.risk_score < 30.0
    assert result.risk_label in (Severity.INFO, Severity.LOW)


@pytest.mark.unit
def test_scoring_tool_deterministic() -> None:
    tool = PhishingScoringTool()
    arguments = PhishingScoringInput(from_address="a@b.com", subject="hi", body_text="hello")
    assert tool(arguments) == tool(arguments)


@pytest.mark.unit
def test_scoring_tool_clamps_at_100() -> None:
    tool = PhishingScoringTool()
    result = tool(
        PhishingScoringInput(
            from_address="a@evil.example",
            reply_to_address="b@other.example",
            subject="urgent immediately act now",
            body_text=" ".join(
                [
                    "verify your account",
                    "verify your identity",
                    "confirm your identity",
                    "suspended",
                    "permanently closed",
                    "click here",
                    "unauthorized access",
                    "limited time",
                    "failure to verify",
                    "your account has been",
                ]
            ),
            attachments=[{"filename": "x.exe", "content_type": "application/octet-stream"}],
            attributed_ioc_scores=[100.0],
            prompt_injection_flagged=True,
        )
    )
    assert result.risk_score == 100.0
    assert result.risk_label == Severity.CRITICAL
