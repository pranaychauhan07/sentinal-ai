"""Settings — blueprint §13: "Model provider selection... API key entry
(never logged), per-agent verbosity." Read-only for now: every value here
is server-side, `.env`-configured (`core/config/settings.py`) — there is no
settings-mutation API yet (blueprint §3's single-analyst mode; changing a
provider/threshold means editing `.env` and restarting the process, not a
UI action, since these values are also read by `apps/api` and any running
graph — a partial in-process override here would silently diverge from
what the rest of the system actually uses).
"""

from __future__ import annotations

import streamlit as st

from apps.web.runtime import get_settings_cached
from apps.web.theme import apply_page_config
from core.config import Settings


def _has_credential(settings: Settings) -> bool:
    provider = settings.llm_provider.value
    if provider == "openai":
        return bool(settings.openai_api_key)
    if provider == "gemini":
        return bool(settings.google_api_key)
    return True  # ollama needs no API key; reachability is checked at call time


apply_page_config("Settings")

st.title("Settings")
st.caption(
    "Read-only — every value is loaded from `.env` at process startup and shared by "
    "`apps/api` and every graph run. Edit `.env` and restart to change these."
)

settings = get_settings_cached()

st.subheader("LLM Provider")
c1, c2, c3 = st.columns(3)
c1.metric("Provider", settings.llm_provider.value)
c2.metric(
    "Model",
    {
        "openai": settings.openai_model,
        "gemini": settings.gemini_model,
        "ollama": settings.ollama_model,
    }.get(settings.llm_provider.value, "—"),
)
c3.metric(
    "API key configured",
    "✅" if _has_credential(settings) else "❌ (falls back to template answers)",
)

st.subheader("Conversation")
c1, c2, c3 = st.columns(3)
c1.metric("Persistence backend", settings.conversation_persistence_backend)
c2.metric("History turn limit", settings.conversation_history_turn_limit)
c3.metric("Compression trigger (turns)", settings.conversation_compression_trigger_turns)

st.subheader("Evidence & Findings")
c1, c2, c3 = st.columns(3)
c1.metric("Max upload size", f"{settings.evidence_max_upload_bytes // (1024 * 1024)} MB")
c2.metric("Finding min confidence", f"{settings.finding_mapping_min_confidence:.0%}")
c3.metric("Max candidates / case", settings.finding_max_candidates_per_case)

st.subheader("Environment")
st.json(
    {
        "app_env": settings.app_env.value,
        "app_version": settings.app_version,
        "database": "sqlite" if settings.is_sqlite else "postgresql",
        "log_level": settings.log_level,
    }
)
