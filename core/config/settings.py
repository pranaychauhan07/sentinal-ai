"""Centralized application configuration.

The single place `.env` values are read anywhere in the codebase — see
context/03_engineering_constitution.md §2 ("Configuration") and
core/config/README.md. Every other module receives configuration via
dependency injection from :func:`get_settings`, never by reading
``os.environ`` directly.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from core.config.environment import Environment

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class LLMProvider(StrEnum):
    """Supported LLM backends — see .env.example and docs/setup-guide.md."""

    OPENAI = "openai"
    GEMINI = "gemini"
    OLLAMA = "ollama"


class Settings(BaseSettings):
    """Application settings loaded from environment variables / ``.env``.

    Field names mirror ``.env.example`` exactly. Nothing outside this module
    (and :mod:`core.config.environment`) should call ``os.environ`` directly.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    app_env: Environment = Field(default=Environment.DEVELOPMENT, alias="APP_ENV")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_dir: Path = Field(default=Path("./logs"), alias="LOG_DIR")

    # --- LLM Provider ---
    llm_provider: LLMProvider = Field(default=LLMProvider.OPENAI, alias="LLM_PROVIDER")
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", alias="OPENAI_MODEL")
    google_api_key: str | None = Field(default=None, alias="GOOGLE_API_KEY")
    gemini_model: str = Field(default="gemini-1.5-pro", alias="GEMINI_MODEL")
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="llama3.1", alias="OLLAMA_MODEL")

    # --- Database ---
    database_url: str = Field(
        default="sqlite+aiosqlite:///./dev.db",
        alias="DATABASE_URL",
    )

    # --- Vector store (long-term memory) ---
    chroma_persist_dir: Path = Field(default=Path("./.chroma"), alias="CHROMA_PERSIST_DIR")

    # --- Security ---
    prompt_guard_extra_patterns: str = Field(default="", alias="PROMPT_GUARD_EXTRA_PATTERNS")

    # --- Evidence ingestion (core/parsers, core/services/evidence_service.py) ---
    evidence_max_upload_bytes: int = Field(
        default=25 * 1024 * 1024, alias="EVIDENCE_MAX_UPLOAD_BYTES"
    )
    evidence_allowed_extensions: str = Field(
        default=".log,.txt,.csv,.json,.xml,.evtx",
        alias="EVIDENCE_ALLOWED_EXTENSIONS",
    )
    evidence_storage_dir: Path = Field(
        default=Path("./data/evidence_uploads"), alias="EVIDENCE_STORAGE_DIR"
    )

    # --- Frontend / API ---
    streamlit_server_port: int = Field(default=8501, alias="STREAMLIT_SERVER_PORT")
    api_base_url: str = Field(default="http://localhost:8000", alias="API_BASE_URL")

    # --- Application metadata (not env-driven; used by /version) ---
    app_name: str = "Cyber Defense Copilot"
    app_version: str = "0.1.0"

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        normalized = value.upper()
        if normalized not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return normalized

    @property
    def prompt_guard_extra_pattern_list(self) -> list[str]:
        """Parsed comma-separated extra prompt-injection patterns."""
        return [p.strip() for p in self.prompt_guard_extra_patterns.split(",") if p.strip()]

    @property
    def evidence_allowed_extension_list(self) -> list[str]:
        """Parsed comma-separated allowlist of upload extensions."""
        return [e.strip().lower() for e in self.evidence_allowed_extensions.split(",") if e.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    def llm_is_configured(self) -> bool:
        """Whether the selected LLM provider has the credentials it needs.

        Used by the readiness endpoint (apps/api/routers/system.py) — never
        raised as a hard error at settings-load time, since Ollama requires
        no API key and CI intentionally runs with LLM_PROVIDER=ollama.
        """
        if self.llm_provider is LLMProvider.OPENAI:
            return bool(self.openai_api_key)
        if self.llm_provider is LLMProvider.GEMINI:
            return bool(self.google_api_key)
        return True  # Ollama: only requires a reachable local server, checked at call time.


@lru_cache
def get_settings() -> Settings:
    """Process-wide cached settings instance.

    ``lru_cache`` gives us a singleton without introducing mutable global
    state (context/03_engineering_constitution.md §2, "avoid global state") —
    the cache holds an immutable ``Settings`` instance, constructed once.
    """
    return Settings()
