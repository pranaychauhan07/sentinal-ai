"""AI Investigation Assistant — blueprint §13's "Free-form Q&A scoped to
the current case... grounded in that case's actual findings via retrieval,
not a generic chatbot," backed by `core/conversation`'s full retrieval ->
grounding -> citation -> validation pipeline (ADR-0025/0027/0028) and its
persisted history (ADR-0029).
"""

from __future__ import annotations

import streamlit as st

from apps.web.components.case_picker import select_case
from apps.web.runtime import get_settings_cached, run_async
from apps.web.theme import apply_page_config
from core.services import conversation_service

apply_page_config("AI Analyst Chat")

st.title("AI Investigation Assistant")
case = select_case(key="chat_case_picker")

if case is not None:
    settings = get_settings_cached()
    session_state_key = f"chat_session_id::{case.id}"
    session_id = st.session_state.get(session_state_key)

    history = (
        run_async(
            lambda session: conversation_service.get_conversation_history(
                session, case_id=case.id, session_id=session_id, settings=settings
            )
        )
        if session_id
        else []
    )

    for message in history:
        with st.chat_message(message.role):
            st.markdown(message.content)
            if message.citations:
                labels = ", ".join(
                    f"`{c.get('category', '')}:{c.get('source_id', '')}`" for c in message.citations
                )
                st.caption(f"Sources: {labels}")
            if message.confidence is not None:
                st.caption(
                    f"Confidence: {message.confidence:.0%}"
                    + (" · degraded" if message.degraded else "")
                )

    question = st.chat_input("Ask about this case's evidence, findings, or MITRE mappings...")
    if question:
        with st.chat_message("user"):
            st.markdown(question)
        with st.spinner("Retrieving grounded context and generating a cited answer..."):
            result = run_async(
                lambda session: conversation_service.ask_question(
                    session,
                    case_id=case.id,
                    question=question,
                    session_id=session_id,
                    settings=settings,
                )
            )
        st.session_state[session_state_key] = result.session_id
        with st.chat_message("assistant"):
            st.markdown(result.answer_text)
            if result.citations:
                labels = ", ".join(f"`{c.category.value}:{c.source_id}`" for c in result.citations)
                st.caption(f"Sources: {labels}")
            st.caption(
                f"Confidence: {result.confidence:.0%}"
                + (" · degraded — limited evidence available" if result.degraded else "")
            )
            if result.prompt_injection_flagged:
                st.warning("This question matched a prompt-injection pattern; treated literally.")
        st.rerun()
