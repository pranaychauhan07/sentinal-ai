"""Unit tests for core/logging/config.py."""

from __future__ import annotations

import pytest

from core.config import Settings
from core.logging import configure_logging, get_logger, log_execution_time


@pytest.mark.unit
def test_configure_logging_creates_log_dir(test_settings: Settings) -> None:
    configure_logging(test_settings, force=True)
    assert test_settings.log_dir.exists()
    assert (test_settings.log_dir / "app.log").exists()


@pytest.mark.unit
def test_configure_logging_is_idempotent(test_settings: Settings) -> None:
    configure_logging(test_settings, force=True)
    root_handler_count_before = len(__import__("logging").getLogger().handlers)
    configure_logging(test_settings)  # force=False: should be a no-op the second time
    root_handler_count_after = len(__import__("logging").getLogger().handlers)
    assert root_handler_count_before == root_handler_count_after


@pytest.mark.unit
def test_get_logger_returns_usable_logger(test_settings: Settings) -> None:
    configure_logging(test_settings, force=True)
    logger = get_logger("tests.logging")
    logger.info("test_log_line", key="value")  # should not raise


@pytest.mark.unit
def test_log_execution_time_sync_function(test_settings: Settings) -> None:
    configure_logging(test_settings, force=True)

    @log_execution_time()
    def add(a: int, b: int) -> int:
        return a + b

    assert add(2, 3) == 5


@pytest.mark.unit
async def test_log_execution_time_async_function(test_settings: Settings) -> None:
    configure_logging(test_settings, force=True)

    @log_execution_time()
    async def add_async(a: int, b: int) -> int:
        return a + b

    result = await add_async(2, 3)
    assert result == 5
