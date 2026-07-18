"""Smoke test proving the package layout and pytest markers are wired up
correctly. Replace/supplement with real parser/tool unit tests starting
Milestone M1 (docs/roadmap.md) — this file's only job is to keep CI honest
about the harness itself working before any business logic exists.
"""

import pytest

import core


@pytest.mark.unit
def test_core_package_is_importable() -> None:
    assert core is not None
