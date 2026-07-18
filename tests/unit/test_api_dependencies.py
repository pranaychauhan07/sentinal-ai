"""Unit tests for apps/api/dependencies.py."""

from __future__ import annotations

import pytest

from apps.api.dependencies import AuthenticatedUser, get_current_user, get_settings_dependency
from core.config import Settings


@pytest.mark.unit
def test_get_current_user_returns_fixed_placeholder() -> None:
    user = get_current_user()
    assert isinstance(user, AuthenticatedUser)
    assert user.id == "local-analyst"

    # Calling it twice returns an equivalent placeholder — there is no real
    # per-request identity yet (context/03_engineering_constitution.md §6).
    assert get_current_user() == user


@pytest.mark.unit
def test_get_settings_dependency_returns_settings_instance(test_settings: Settings) -> None:
    resolved = get_settings_dependency()
    assert isinstance(resolved, Settings)
