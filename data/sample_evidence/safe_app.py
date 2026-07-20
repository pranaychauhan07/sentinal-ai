"""A deliberately clean/safe sample module — fixture data proving
core/owasp_security does not produce false positives on ordinary,
non-vulnerable code (false-positive-reduction test)."""

import hashlib
import secrets


def add(a: int, b: int) -> int:
    return a + b


def hash_for_cache_key(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def read_config() -> str:
    with open("/etc/myapp/config.toml") as handle:
        return handle.read()
