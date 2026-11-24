"""Process-startup trust root for W4's external W2.5 authority.

The W4 bundle and authority are untrusted invocation data. The HMAC key is
therefore not accepted as an argument to ``verify_small_loop_bundle``. A host
must configure this registry before admitting any bundle, from a deployment
controlled secret source. Reconfiguration with a different value is rejected;
untrusted per-bundle data can only name an already configured authority.
"""

from __future__ import annotations

from threading import Lock

from .models import W4EvidenceError


_LOCK = Lock()
_TRUSTED_KEYS: dict[tuple[str, str], bytes] = {}
_FROZEN = False


def configure_trusted_authority(*, authority_id: str, key_id: str, key: bytes) -> None:
    """Install one process trust root before verification starts.

    The function is intended for trusted startup/configuration code, not for a
    bundle adapter or model output. A repeated identical configuration is
    idempotent; replacing an existing trust root fails closed.
    """

    if not isinstance(authority_id, str) or not authority_id or "\x00" in authority_id:
        raise ValueError("authority_id must be non-empty text")
    if not isinstance(key_id, str) or not key_id or "\x00" in key_id:
        raise ValueError("key_id must be non-empty text")
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("authority key must contain at least 16 bytes")
    identity = (authority_id, key_id)
    with _LOCK:
        if _FROZEN:
            existing = _TRUSTED_KEYS.get(identity)
            if existing == key:
                return
            raise RuntimeError("trusted authority registry is frozen")
        existing = _TRUSTED_KEYS.get(identity)
        if existing is not None and existing != key:
            raise RuntimeError("trusted authority reconfiguration rejected")
        _TRUSTED_KEYS[identity] = bytes(key)


def freeze_trusted_authorities() -> None:
    """Freeze the startup trust registry before untrusted input is admitted."""

    global _FROZEN
    with _LOCK:
        _FROZEN = True


def resolve_trusted_authority(*, authority_id: str, key_id: str) -> bytes:
    """Resolve only a startup-configured key named by the authority."""

    with _LOCK:
        if not _FROZEN:
            raise W4EvidenceError("AUTHORITY_TRUST_ROOT_NOT_FROZEN")
        key = _TRUSTED_KEYS.get((authority_id, key_id))
    if key is None:
        raise W4EvidenceError("AUTHORITY_TRUST_ROOT_UNKNOWN")
    return key
