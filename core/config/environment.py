"""Deployment environment enum shared by settings, logging, and the API layer.

A single, closed set of valid environments — see
docs/dependency-rules.md / context/03_engineering_constitution.md §2 (Enums).
"""

from __future__ import annotations

from enum import StrEnum


class Environment(StrEnum):
    """The environment the application is currently running in.

    Branches configuration behavior (log format, debug flags, CORS) in
    core/config/settings.py — never checked directly by business logic in
    core/agents, core/tools, or core/parsers.
    """

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"

    @property
    def is_production(self) -> bool:
        return self is Environment.PRODUCTION

    @property
    def is_development(self) -> bool:
        return self is Environment.DEVELOPMENT

    @property
    def is_testing(self) -> bool:
        return self is Environment.TESTING
