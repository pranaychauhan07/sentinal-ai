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
        default=".log,.txt,.csv,.json,.xml,.evtx,.eml,.nessus",
        alias="EVIDENCE_ALLOWED_EXTENSIONS",
    )
    evidence_storage_dir: Path = Field(
        default=Path("./data/evidence_uploads"), alias="EVIDENCE_STORAGE_DIR"
    )

    # --- Threat intelligence (core/threat_intel, core/services/threat_intel_service.py) ---
    threat_intel_max_iocs_per_artifact: int = Field(
        default=5_000, alias="THREAT_INTEL_MAX_IOCS_PER_ARTIFACT"
    )
    threat_intel_max_regex_input_chars: int = Field(
        default=1_000_000, alias="THREAT_INTEL_MAX_REGEX_INPUT_CHARS"
    )
    threat_intel_min_confidence: float = Field(
        default=0.3, ge=0.0, le=1.0, alias="THREAT_INTEL_MIN_CONFIDENCE"
    )
    threat_intel_malicious_score_threshold: float = Field(
        default=70.0, ge=0.0, le=100.0, alias="THREAT_INTEL_MALICIOUS_SCORE_THRESHOLD"
    )
    threat_intel_suspicious_score_threshold: float = Field(
        default=40.0, ge=0.0, le=100.0, alias="THREAT_INTEL_SUSPICIOUS_SCORE_THRESHOLD"
    )
    threat_intel_enabled_providers: str = Field(default="", alias="THREAT_INTEL_ENABLED_PROVIDERS")
    threat_intel_provider_timeout_seconds: float = Field(
        default=10.0, alias="THREAT_INTEL_PROVIDER_TIMEOUT_SECONDS"
    )
    misp_base_url: str | None = Field(default=None, alias="MISP_BASE_URL")
    misp_api_key: str | None = Field(default=None, alias="MISP_API_KEY")
    alienvault_otx_api_key: str | None = Field(default=None, alias="ALIENVAULT_OTX_API_KEY")
    virustotal_api_key: str | None = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str | None = Field(default=None, alias="ABUSEIPDB_API_KEY")
    greynoise_api_key: str | None = Field(default=None, alias="GREYNOISE_API_KEY")
    opencti_base_url: str | None = Field(default=None, alias="OPENCTI_BASE_URL")
    opencti_api_key: str | None = Field(default=None, alias="OPENCTI_API_KEY")

    # --- Vulnerability assessment (core/vulnerabilities, core/services/
    # vulnerability_service.py) ---
    vulnerability_max_records_per_artifact: int = Field(
        default=20_000, alias="VULNERABILITY_MAX_RECORDS_PER_ARTIFACT"
    )

    # --- Linux security / Threat Hunting (core/linux_security, core/services/
    # linux_security_service.py, core/agents/threat_hunter_agent.py) ---
    linux_security_max_records_per_artifact: int = Field(
        default=20_000, alias="LINUX_SECURITY_MAX_RECORDS_PER_ARTIFACT"
    )
    linux_security_brute_force_threshold: int = Field(
        default=5, gt=0, alias="LINUX_SECURITY_BRUTE_FORCE_THRESHOLD"
    )
    linux_security_brute_force_window_minutes: int = Field(
        default=10, gt=0, alias="LINUX_SECURITY_BRUTE_FORCE_WINDOW_MINUTES"
    )
    linux_security_failed_login_spike_threshold: int = Field(
        default=20, gt=0, alias="LINUX_SECURITY_FAILED_LOGIN_SPIKE_THRESHOLD"
    )
    linux_security_failed_login_spike_min_sources: int = Field(
        default=3, gt=0, alias="LINUX_SECURITY_FAILED_LOGIN_SPIKE_MIN_SOURCES"
    )
    linux_security_sudo_failure_threshold: int = Field(
        default=3, gt=0, alias="LINUX_SECURITY_SUDO_FAILURE_THRESHOLD"
    )
    linux_security_sudo_failure_window_minutes: int = Field(
        default=10, gt=0, alias="LINUX_SECURITY_SUDO_FAILURE_WINDOW_MINUTES"
    )
    linux_security_escalation_chain_window_minutes: int = Field(
        default=15, gt=0, alias="LINUX_SECURITY_ESCALATION_CHAIN_WINDOW_MINUTES"
    )
    # Confidence engine weights (must sum to 1.0 — validated at construction
    # time by core.linux_security.confidence_engine.LinuxSecurityConfidenceWeights).
    linux_security_confidence_weight_pattern_match: float = Field(
        default=0.3, ge=0.0, le=1.0, alias="LINUX_SECURITY_CONFIDENCE_WEIGHT_PATTERN_MATCH"
    )
    linux_security_confidence_weight_occurrence: float = Field(
        default=0.25, ge=0.0, le=1.0, alias="LINUX_SECURITY_CONFIDENCE_WEIGHT_OCCURRENCE"
    )
    linux_security_confidence_weight_evidence_completeness: float = Field(
        default=0.25,
        ge=0.0,
        le=1.0,
        alias="LINUX_SECURITY_CONFIDENCE_WEIGHT_EVIDENCE_COMPLETENESS",
    )
    linux_security_confidence_weight_corroboration: float = Field(
        default=0.2, ge=0.0, le=1.0, alias="LINUX_SECURITY_CONFIDENCE_WEIGHT_CORROBORATION"
    )
    # Threat scoring engine weights — the task's seven named dimensions
    # (must sum to 1.0 — validated by
    # core.linux_security.scoring.LinuxSecurityScoringWeights).
    linux_security_scoring_weight_detection_confidence: float = Field(
        default=1 / 7, ge=0.0, le=1.0, alias="LINUX_SECURITY_SCORING_WEIGHT_DETECTION_CONFIDENCE"
    )
    linux_security_scoring_weight_event_frequency: float = Field(
        default=1 / 7, ge=0.0, le=1.0, alias="LINUX_SECURITY_SCORING_WEIGHT_EVENT_FREQUENCY"
    )
    linux_security_scoring_weight_severity: float = Field(
        default=1 / 7, ge=0.0, le=1.0, alias="LINUX_SECURITY_SCORING_WEIGHT_SEVERITY"
    )
    linux_security_scoring_weight_evidence_quality: float = Field(
        default=1 / 7, ge=0.0, le=1.0, alias="LINUX_SECURITY_SCORING_WEIGHT_EVIDENCE_QUALITY"
    )
    linux_security_scoring_weight_source_reliability: float = Field(
        default=1 / 7, ge=0.0, le=1.0, alias="LINUX_SECURITY_SCORING_WEIGHT_SOURCE_RELIABILITY"
    )
    linux_security_scoring_weight_ioc_correlation: float = Field(
        default=1 / 7, ge=0.0, le=1.0, alias="LINUX_SECURITY_SCORING_WEIGHT_IOC_CORRELATION"
    )
    linux_security_scoring_weight_existing_findings: float = Field(
        default=1 / 7, ge=0.0, le=1.0, alias="LINUX_SECURITY_SCORING_WEIGHT_EXISTING_FINDINGS"
    )

    # --- Linux Security Advisor (core/linux_advisor, core/services/
    # linux_advisor_service.py, core/agents/linux_security_agent.py) ---
    linux_advisor_max_lines_per_artifact: int = Field(
        default=5_000, alias="LINUX_ADVISOR_MAX_LINES_PER_ARTIFACT"
    )
    linux_advisor_max_chars_per_artifact: int = Field(
        default=500_000, alias="LINUX_ADVISOR_MAX_CHARS_PER_ARTIFACT"
    )
    # Overall risk-assessment weights (must sum to 1.0 — validated by
    # core.linux_advisor.risk_assessment.LinuxAdvisorRiskWeights).
    linux_advisor_risk_weight_highest_severity: float = Field(
        default=0.35, ge=0.0, le=1.0, alias="LINUX_ADVISOR_RISK_WEIGHT_HIGHEST_SEVERITY"
    )
    linux_advisor_risk_weight_highest_confidence: float = Field(
        default=0.2, ge=0.0, le=1.0, alias="LINUX_ADVISOR_RISK_WEIGHT_HIGHEST_CONFIDENCE"
    )
    linux_advisor_risk_weight_finding_count: float = Field(
        default=0.15, ge=0.0, le=1.0, alias="LINUX_ADVISOR_RISK_WEIGHT_FINDING_COUNT"
    )
    linux_advisor_risk_weight_critical_category: float = Field(
        default=0.2, ge=0.0, le=1.0, alias="LINUX_ADVISOR_RISK_WEIGHT_CRITICAL_CATEGORY"
    )
    linux_advisor_risk_weight_corroboration: float = Field(
        default=0.1, ge=0.0, le=1.0, alias="LINUX_ADVISOR_RISK_WEIGHT_CORROBORATION"
    )

    # --- MITRE ATT&CK knowledge (core/knowledge/mitre, core/findings) ---
    mitre_attack_data_path: Path = Field(
        default=Path("./data/mitre/raw/attack-enterprise-15.1.json"),
        alias="MITRE_ATTACK_DATA_PATH",
    )
    mitre_attack_version: str = Field(default="15.1", alias="MITRE_ATTACK_VERSION")

    # --- Finding & MITRE mapping engine (core/findings, core/services/finding_service.py) ---
    finding_mapping_min_confidence: float = Field(
        default=0.3, ge=0.0, le=1.0, alias="FINDING_MAPPING_MIN_CONFIDENCE"
    )
    finding_dedup_similarity_threshold: float = Field(
        default=0.6, ge=0.0, le=1.0, alias="FINDING_DEDUP_SIMILARITY_THRESHOLD"
    )
    finding_dedup_time_window_minutes: int = Field(
        default=60, gt=0, alias="FINDING_DEDUP_TIME_WINDOW_MINUTES"
    )
    finding_max_candidates_per_case: int = Field(
        default=2_000, alias="FINDING_MAX_CANDIDATES_PER_CASE"
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
    def threat_intel_enabled_provider_list(self) -> list[str]:
        """Parsed comma-separated list of enabled threat-intel provider
        names (e.g. `misp,virustotal`). Empty by default — no provider is
        implemented yet (docs/adr/0012 point 4)."""
        return [
            p.strip().lower() for p in self.threat_intel_enabled_providers.split(",") if p.strip()
        ]

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
