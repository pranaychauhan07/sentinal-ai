"""Smoke test for the integration tier. Replace/supplement with real
end-to-end LangGraph investigation runs starting Milestone M1
(docs/roadmap.md) once core/graph/investigation_graph.py exists.
"""

import pytest

import apps
import core


@pytest.mark.integration
def test_core_and_apps_packages_are_importable() -> None:
    assert core is not None
    assert apps is not None
