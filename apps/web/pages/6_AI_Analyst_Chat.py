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

#: Illustrative starting points shown only on a session with no turns yet —
#: never a claim about this specific case's actual data, just common
#: question shapes the retrieval pipeline already knows how to answer.
_SUGGESTED_PROMPTS = (
    "Summarize the findings for this case",
    "What IOCs were extracted and how were they classified?",
    "Which MITRE ATT&CK techniques were observed?",
    "What should the analyst do next?",
)


def _render_turn(
    role: str, content: str, *, citations: list, confidence: float | None, degraded: bool
) -> None:
    with st.chat_message(role):
        st.markdown(content)
        if citations:
            labels = ", ".join(
                f"`{c.get('category', '')}:{c.get('source_id', '')}`"
                if isinstance(c, dict)
                else f"`{c.category.value}:{c.source_id}`"
                for c in citations
            )
            st.caption(f"Sources: {labels}")
        if confidence is not None:
            st.caption(
                f"Confidence: {confidence:.0%}"
                + (" · degraded — limited evidence available" if degraded else "")
            )


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
        _render_turn(
            message.role,
            message.content,
            citations=message.citations,
            confidence=message.confidence,
            degraded=message.degraded,
        )

    pending_question: str | None = None
    if not history:
        st.caption("New to this case? Try one of these:")
        cols = st.columns(len(_SUGGESTED_PROMPTS))
        for col, prompt in zip(cols, _SUGGESTED_PROMPTS, strict=True):
            if col.button(prompt, key=f"suggested::{prompt}", use_container_width=True):
                pending_question = prompt

    question = (
        st.chat_input("Ask about this case's evidence, findings, or MITRE mappings...")
        or pending_question
    )
    if question:
        with st.chat_message("user"):
            st.markdown(question)

        async def _stream_and_collect(session: object) -> tuple[object, list[str]]:
            result, chunk_iterator = await conversation_service.stream_answer(
                session,
                case_id=case.id,
                question=question,
                session_id=session_id,
                settings=settings,
            )
            #: `chunk_iterator` is an async generator bound to this call's
            #: event loop (`run_async` closes it on return) — collected into
            #: a plain list here, inside the same loop, so the page can feed
            #: it to `st.write_stream` synchronously afterward.
            return result, [chunk async for chunk in chunk_iterator]

        with st.chat_message("assistant"):
            with st.spinner("Retrieving grounded context and generating a cited answer..."):
                result, chunks = run_async(_stream_and_collect)
            st.write_stream(iter(chunks))
            if result.citations:
                labels = ", ".join(f"`{c.category.value}:{c.source_id}`" for c in result.citations)
                st.caption(f"Sources: {labels}")
            st.caption(
                f"Confidence: {result.confidence:.0%}"
                + (" · degraded — limited evidence available" if result.degraded else "")
            )
            if result.prompt_injection_flagged:
                st.warning("This question matched a prompt-injection pattern; treated literally.")
        st.session_state[session_state_key] = result.session_id
        st.rerun()
