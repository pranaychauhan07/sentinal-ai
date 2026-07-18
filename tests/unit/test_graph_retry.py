from __future__ import annotations

import pytest

from core.exceptions import ExternalServiceError, ValidationError
from core.graph.retry import RetryPolicy, run_with_retry

pytestmark = pytest.mark.unit


def test_default_policy_never_retries() -> None:
    calls = {"count": 0}

    def _always_fails() -> None:
        calls["count"] += 1
        raise ExternalServiceError("down")

    with pytest.raises(ExternalServiceError):
        run_with_retry(_always_fails, policy=RetryPolicy(), op_name="test")
    assert calls["count"] == 1


def test_retries_up_to_max_attempts_for_retryable_errors() -> None:
    calls = {"count": 0}

    def _fails_twice_then_succeeds() -> str:
        calls["count"] += 1
        if calls["count"] < 3:
            raise ExternalServiceError("transient")
        return "ok"

    policy = RetryPolicy(max_attempts=3, backoff_base_seconds=0.0)
    result = run_with_retry(_fails_twice_then_succeeds, policy=policy, op_name="test")
    assert result == "ok"
    assert calls["count"] == 3


def test_non_retryable_error_propagates_immediately() -> None:
    calls = {"count": 0}

    def _fails_with_non_retryable() -> None:
        calls["count"] += 1
        raise ValidationError("bad input")

    policy = RetryPolicy(max_attempts=3, backoff_base_seconds=0.0)
    with pytest.raises(ValidationError):
        run_with_retry(_fails_with_non_retryable, policy=policy, op_name="test")
    assert calls["count"] == 1


def test_exhausting_all_attempts_raises_the_last_error() -> None:
    policy = RetryPolicy(max_attempts=2, backoff_base_seconds=0.0)

    def _always_fails() -> None:
        raise ExternalServiceError("still down")

    with pytest.raises(ExternalServiceError):
        run_with_retry(_always_fails, policy=policy, op_name="test")
