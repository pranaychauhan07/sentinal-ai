"""Narrow exception hierarchy for `core/conversation` — constitution §5
("every tool module defines its own narrow exception classes"), mirroring
`core/incident_response/exceptions.py`'s/`core/reporting/exceptions.py`'s
pattern exactly.
"""

from __future__ import annotations

from core.exceptions import ValidationError


class ConversationError(ValidationError):
    """Base class for every exception this package raises deliberately."""

    code = "CONVERSATION_ERROR"


class EmptyQuestionError(ConversationError):
    """The question handed to the pipeline is empty/whitespace-only —
    caught at the service boundary before any retrieval work happens."""

    code = "EMPTY_QUESTION"


class OversizedConversationInputError(ConversationError):
    """The number of case-data records handed to `RetrievalLayer.retrieve`
    exceeds the configured maximum — the resource-exhaustion guard for a
    pathologically large case, mirroring `core.owasp_security.exceptions.
    OversizedSourceInputError`'s identical reasoning."""

    code = "OVERSIZED_CONVERSATION_INPUT"
