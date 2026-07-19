"""File fingerprinting — SHA-256, the evidentiary identity of an uploaded
artifact (blueprint §8's `Evidence` table; used for chain-of-custody and
duplicate-upload detection via `core.db.evidence_repository.find_by_sha256`).
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict


class FileFingerprint(BaseModel):
    model_config = ConfigDict(frozen=True)

    sha256: str
    size_bytes: int


def compute_sha256(content: bytes) -> FileFingerprint:
    """Deterministic identity hash for `content`. Uses `hashlib.sha256`
    (not Python's salted builtin `hash()` — see `core/memory`'s
    `HashingTextEmbedder` docstring for why that distinction matters)."""
    digest = hashlib.sha256(content).hexdigest()
    return FileFingerprint(sha256=digest, size_bytes=len(content))
