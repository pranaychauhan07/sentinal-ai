"""`ChatModelProvider` — blueprint §5's "LLM ... pluggable via a
`ModelProvider` interface," first concretely defined for this feature.

Per this session's explicit task scope ("create provider interfaces only...
do not integrate external LLM providers yet"), no OpenAI/Gemini/Ollama
client is implemented here. `core.config.settings.Settings.llm_provider`
(the `LLMProvider` `StrEnum`) already names which *backend* an operator has
selected; this module defines the *shape* every concrete backend
implementation will satisfy, plus one concrete, always-available,
non-generative implementation (`TemplateChatModelProvider`) so the whole
pipeline is runnable and testable today without any network dependency.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from core.conversation.models import ChatCompletion, PromptPayload


@runtime_checkable
class ChatModelProvider(Protocol):
    """Contract every concrete chat-completion backend implements. A future
    OpenAI/Gemini/Ollama-backed provider satisfies this Protocol and is
    injected wherever a `ChatModelProvider` is expected — a provider swap,
    never a pipeline rewrite (constitution §2, "Dependency injection")."""

    def generate(self, prompt: PromptPayload) -> ChatCompletion: ...


class TemplateChatModelProvider:
    """Deterministic, non-generative default provider: composes an answer
    directly from the ranked evidence context already assembled into
    `prompt.context_text`, never invoking any model or network call.

    This is not a stand-in that will be "replaced later out of necessity" —
    it is the structural guarantee behind docs/adr/0025's "never hallucinate
    unavailable data" requirement: the only content substrate this provider
    can draw on is verified, retrieved case data (constitution §1.9)."""

    def generate(self, prompt: PromptPayload) -> ChatCompletion:
        if prompt.context_text == "(no matching case evidence was found)":
            return ChatCompletion(
                answer_text=(
                    "I don't have enough evidence in this case yet to answer that "
                    "question. No matching findings, IOCs, MITRE mappings, reports, "
                    "or timeline events were found."
                ),
                used_source_ids=(),
            )

        lines = prompt.context_text.splitlines()
        used_source_ids: list[str] = []
        summary_lines: list[str] = []
        for line in lines:
            # Each context line is "[category:source_id] text" — see
            # PromptBuilder.render_context.
            if line.startswith("[") and "]" in line:
                header, _, text = line.partition("]")
                source_id = header[1:].split(":", 1)[-1]
                used_source_ids.append(source_id)
                summary_lines.append(text.strip())

        answer_text = (
            f"Based on {len(used_source_ids)} matching case evidence item(s): "
            + " | ".join(summary_lines)
        )
        return ChatCompletion(answer_text=answer_text, used_source_ids=tuple(used_source_ids))
