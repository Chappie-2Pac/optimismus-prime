"""W5-S7 external verification for Prime writer-generation evidence.

The S6 manifest is a cooperative, same-filesystem self-attestation.  This
module adds a separate host-configured HMAC trust root and verifies an anchor
supplied by an external caller.  The anchor is never read from the Prime
filesystem, never creates a new key, and never becomes execution authority.

The verifier requires an externally maintained last-accepted generation.  A
valid signature without that monotonic external observation is deliberately
reported as replay-unproven rather than as current evidence.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from threading import Lock
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json

from .prime_evidence import (
    PRIME_FILESYSTEM_EVIDENCE_V2_SCHEMA,
    PrimeEvidenceError,
    verify_prime_evidence_v2_capture,
)


PRIME_WRITER_ANCHOR_SCHEMA = "prime-writer-anchor-v1"
PRIME_WRITER_ANCHOR_VERIFICATION_SCHEMA = "prime-writer-anchor-verification-v1"
PRIME_WRITER_ANCHOR_PROTOCOL = "hmac-sha256-canonical-json-v1"
PRIME_EXTERNAL_ANCHOR_SCHEMA = PRIME_WRITER_ANCHOR_SCHEMA
PRIME_EXTERNAL_ANCHOR_VERIFICATION_SCHEMA = PRIME_WRITER_ANCHOR_VERIFICATION_SCHEMA
PRIME_ANCHOR_AUTHORITY_PREFIX = "prime-anchor-"

_ANCHOR_KEYS = frozenset(
    {"schema_version", "authority_id", "key_id", "payload", "payload_sha256", "authority_mac"}
)
_PAYLOAD_KEYS = frozenset(
    {
        "evidence_schema",
        "snapshot_sha256",
        "run_id",
        "run_relative_path",
        "root_binding_sha256",
        "generation",
        "generation_id",
        "covered_source_set_sha256",
    }
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_EXECUTION_FALSE = {"resume": False, "reconcile": False, "mutation": False, "network": False}

ANCHOR_ERROR_CODES = frozenset(
    {
        "PRIME_ANCHOR_NOT_OBSERVED",
        "PRIME_ANCHOR_JSON_INVALID",
        "PRIME_ANCHOR_JSON_DUPLICATE_KEY",
        "PRIME_ANCHOR_SCHEMA_INVALID",
        "PRIME_ANCHOR_PAYLOAD_HASH_INVALID",
        "PRIME_ANCHOR_TRUST_ROOT_NOT_FROZEN",
        "PRIME_ANCHOR_TRUST_ROOT_UNKNOWN",
        "PRIME_ANCHOR_SIGNATURE_INVALID",
        "PRIME_ANCHOR_EVIDENCE_INVALID",
        "PRIME_ANCHOR_EVIDENCE_SCHEMA_MISMATCH",
        "PRIME_ANCHOR_RUN_BINDING_MISMATCH",
        "PRIME_ANCHOR_RUN_PATH_MISMATCH",
        "PRIME_ANCHOR_ROOT_BINDING_MISMATCH",
        "PRIME_ANCHOR_SNAPSHOT_MISMATCH",
        "PRIME_ANCHOR_GENERATION_MISMATCH",
        "PRIME_ANCHOR_GENERATION_ID_MISMATCH",
        "PRIME_ANCHOR_SOURCE_SET_MISMATCH",
        "PRIME_ANCHOR_REPLAY_STATE_INVALID",
        "PRIME_ANCHOR_REPLAY_UNPROVEN",
        "PRIME_ANCHOR_REPLAY_OR_DOWNGRADE",
    }
)


class PrimeAnchorError(ValueError):
    """A Prime external-anchor verification failed closed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in ANCHOR_ERROR_CODES:
            raise ValueError(f"unknown Prime anchor code: {code}")
        self.code = code
        super().__init__(f"{code}: {message}")


_TRUST_LOCK = Lock()
_TRUSTED_ANCHOR_KEYS: dict[tuple[str, str], bytes] = {}
_TRUST_ROOT_FROZEN = False


def configure_trusted_prime_anchor(*, authority_id: str, key_id: str, key: bytes) -> None:
    """Configure one host trust root before untrusted anchors are admitted.

    This is startup configuration only.  The external anchor cannot provide
    or replace its own key, and reconfiguration after freezing is rejected.
    """

    if (
        not isinstance(authority_id, str)
        or _SAFE_ID.fullmatch(authority_id) is None
        or not authority_id.startswith(PRIME_ANCHOR_AUTHORITY_PREFIX)
    ):
        raise ValueError("authority_id must use the prime-anchor- scope")
    if (
        not isinstance(key_id, str)
        or _SAFE_ID.fullmatch(key_id) is None
        or not key_id.startswith(PRIME_ANCHOR_AUTHORITY_PREFIX)
    ):
        raise ValueError("key_id must use the prime-anchor- scope")
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("trusted Prime anchor key must contain at least 16 bytes")
    identity = (authority_id, key_id)
    with _TRUST_LOCK:
        if _TRUST_ROOT_FROZEN:
            if _TRUSTED_ANCHOR_KEYS.get(identity) == key:
                return
            raise RuntimeError("trusted Prime anchor registry is frozen")
        existing = _TRUSTED_ANCHOR_KEYS.get(identity)
        if existing is not None and existing != key:
            raise RuntimeError("trusted Prime anchor reconfiguration rejected")
        _TRUSTED_ANCHOR_KEYS[identity] = bytes(key)


def freeze_trusted_prime_anchors() -> None:
    """Freeze the host trust root before external anchor data is consumed."""

    global _TRUST_ROOT_FROZEN
    with _TRUST_LOCK:
        _TRUST_ROOT_FROZEN = True


def resolve_trusted_prime_anchor(*, authority_id: str, key_id: str) -> bytes:
    """Resolve only a startup-configured Prime anchor key."""

    with _TRUST_LOCK:
        if not _TRUST_ROOT_FROZEN:
            raise PrimeAnchorError("PRIME_ANCHOR_TRUST_ROOT_NOT_FROZEN", "trust root is not frozen")
        key = _TRUSTED_ANCHOR_KEYS.get((authority_id, key_id))
    if key is None:
        raise PrimeAnchorError("PRIME_ANCHOR_TRUST_ROOT_UNKNOWN", "anchor authority/key is unknown")
    return key


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def parse_prime_external_anchor(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Strictly parse an external anchor without touching the filesystem."""

    if value is None:
        raise PrimeAnchorError("PRIME_ANCHOR_NOT_OBSERVED", "external anchor is missing")
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PrimeAnchorError("PRIME_ANCHOR_JSON_INVALID", "anchor is not UTF-8") from exc
    if not isinstance(value, str):
        raise PrimeAnchorError("PRIME_ANCHOR_JSON_INVALID", "anchor object or JSON text required")
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except _DuplicateJsonKey as exc:
        raise PrimeAnchorError("PRIME_ANCHOR_JSON_DUPLICATE_KEY", f"duplicate key: {exc}") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PrimeAnchorError("PRIME_ANCHOR_JSON_INVALID", "anchor JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise PrimeAnchorError("PRIME_ANCHOR_SCHEMA_INVALID", "anchor JSON object required")
    return parsed


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PrimeAnchorError("PRIME_ANCHOR_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise PrimeAnchorError("PRIME_ANCHOR_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise PrimeAnchorError("PRIME_ANCHOR_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise PrimeAnchorError("PRIME_ANCHOR_SCHEMA_INVALID", f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise PrimeAnchorError("PRIME_ANCHOR_REPLAY_STATE_INVALID", f"{label} must be an integer >= 0")
    return value


def _validate_anchor_shape(anchor: Mapping[str, Any]) -> dict[str, Any]:
    if set(anchor) != _ANCHOR_KEYS:
        raise PrimeAnchorError("PRIME_ANCHOR_SCHEMA_INVALID", "anchor key set is not exact")
    if anchor["schema_version"] != PRIME_WRITER_ANCHOR_SCHEMA:
        raise PrimeAnchorError("PRIME_ANCHOR_SCHEMA_INVALID", "unsupported anchor schema")
    authority_id = _safe_id(anchor["authority_id"], "anchor.authority_id")
    key_id = _safe_id(anchor["key_id"], "anchor.key_id")
    payload = anchor["payload"]
    if not isinstance(payload, Mapping) or set(payload) != _PAYLOAD_KEYS:
        raise PrimeAnchorError("PRIME_ANCHOR_SCHEMA_INVALID", "anchor payload key set is not exact")
    if anchor["payload_sha256"] != canonical_hash(dict(payload)):
        raise PrimeAnchorError("PRIME_ANCHOR_PAYLOAD_HASH_INVALID", "payload hash does not match")
    if anchor["authority_mac"] is None or _HEX64.fullmatch(str(anchor["authority_mac"])) is None:
        raise PrimeAnchorError("PRIME_ANCHOR_SCHEMA_INVALID", "authority_mac must be lowercase SHA-256")
    checked_payload = {
        "evidence_schema": _text(payload["evidence_schema"], "payload.evidence_schema"),
        "snapshot_sha256": _hash64(payload["snapshot_sha256"], "payload.snapshot_sha256"),
        "run_id": _safe_id(payload["run_id"], "payload.run_id"),
        "run_relative_path": _text(payload["run_relative_path"], "payload.run_relative_path"),
        "root_binding_sha256": _hash64(payload["root_binding_sha256"], "payload.root_binding_sha256"),
        "generation": _positive_int(payload["generation"], "payload.generation"),
        "generation_id": _safe_id(payload["generation_id"], "payload.generation_id"),
        "covered_source_set_sha256": _hash64(payload["covered_source_set_sha256"], "payload.covered_source_set_sha256"),
    }
    return {
        "schema_version": PRIME_WRITER_ANCHOR_SCHEMA,
        "authority_id": authority_id,
        "key_id": key_id,
        "payload": checked_payload,
        "payload_sha256": anchor["payload_sha256"],
        "authority_mac": str(anchor["authority_mac"]),
    }


def verify_prime_external_anchor(
    capture: Mapping[str, Any],
    anchor: Mapping[str, Any] | bytes | str | None,
    *,
    last_accepted_generation: int | None,
    expected_prime_run_id: str | None = None,
) -> dict[str, Any]:
    """Verify a current external anchor against one fresh S6 V2 capture.

    ``last_accepted_generation`` is an external monotonic observation.  It is
    intentionally required: a valid MAC alone cannot distinguish a current
    anchor from a replayed older anchor.
    """

    if last_accepted_generation is None:
        raise PrimeAnchorError("PRIME_ANCHOR_REPLAY_UNPROVEN", "no external last-accepted generation was supplied")
    last_accepted_generation = _nonnegative_int(last_accepted_generation, "last_accepted_generation")
    try:
        verified_capture = verify_prime_evidence_v2_capture(capture)
    except PrimeEvidenceError as exc:
        raise PrimeAnchorError("PRIME_ANCHOR_EVIDENCE_INVALID", str(exc)) from exc
    parsed_anchor = parse_prime_external_anchor(anchor)
    checked = _validate_anchor_shape(parsed_anchor)
    key = resolve_trusted_prime_anchor(
        authority_id=checked["authority_id"],
        key_id=checked["key_id"],
    )
    mac_core = {key_name: checked[key_name] for key_name in ("schema_version", "authority_id", "key_id", "payload", "payload_sha256")}
    expected_mac = hmac.new(key, canonical_json(mac_core).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(checked["authority_mac"], expected_mac):
        raise PrimeAnchorError("PRIME_ANCHOR_SIGNATURE_INVALID", "external anchor MAC does not match")

    root = verified_capture.get("root")
    writer = verified_capture.get("writer_snapshot")
    if not isinstance(root, Mapping) or not isinstance(writer, Mapping):
        raise PrimeAnchorError("PRIME_ANCHOR_EVIDENCE_INVALID", "V2 root or writer snapshot is missing")
    payload = checked["payload"]
    if payload["evidence_schema"] != PRIME_FILESYSTEM_EVIDENCE_V2_SCHEMA:
        raise PrimeAnchorError("PRIME_ANCHOR_EVIDENCE_SCHEMA_MISMATCH", "anchor evidence schema is not V2")
    if expected_prime_run_id is not None and root.get("run_id") != expected_prime_run_id:
        raise PrimeAnchorError("PRIME_ANCHOR_RUN_BINDING_MISMATCH", "capture run does not match expected Prime run")
    if payload["run_id"] != root.get("run_id"):
        raise PrimeAnchorError("PRIME_ANCHOR_RUN_BINDING_MISMATCH", "anchor and capture run IDs differ")
    if payload["run_relative_path"] != root.get("run_relative_path"):
        raise PrimeAnchorError("PRIME_ANCHOR_RUN_PATH_MISMATCH", "anchor and capture run paths differ")
    if payload["root_binding_sha256"] != root.get("root_binding_sha256"):
        raise PrimeAnchorError("PRIME_ANCHOR_ROOT_BINDING_MISMATCH", "anchor and capture root bindings differ")
    if payload["snapshot_sha256"] != verified_capture.get("snapshot_sha256"):
        raise PrimeAnchorError("PRIME_ANCHOR_SNAPSHOT_MISMATCH", "anchor and capture snapshot hashes differ")
    if payload["generation"] != writer.get("generation"):
        raise PrimeAnchorError("PRIME_ANCHOR_GENERATION_MISMATCH", "anchor and writer generations differ")
    if payload["generation_id"] != writer.get("generation_id"):
        raise PrimeAnchorError("PRIME_ANCHOR_GENERATION_ID_MISMATCH", "anchor and writer generation IDs differ")
    if payload["covered_source_set_sha256"] != writer.get("covered_source_set_sha256"):
        raise PrimeAnchorError("PRIME_ANCHOR_SOURCE_SET_MISMATCH", "anchor and writer source-set hashes differ")
    if payload["generation"] <= last_accepted_generation:
        raise PrimeAnchorError(
            "PRIME_ANCHOR_REPLAY_OR_DOWNGRADE",
            "anchor generation is not newer than the external last-accepted generation",
        )

    result = {
        "schema_version": PRIME_WRITER_ANCHOR_VERIFICATION_SCHEMA,
        "status": "MATCHED_CURRENT",
        "attestation": "VERIFIED_EXTERNAL_HMAC",
        "trusted": True,
        "coherent": True,
        "fresh": True,
        "replay_protected": True,
        "anchor_sha256": canonical_hash(parsed_anchor),
        "authority_id": checked["authority_id"],
        "key_id": checked["key_id"],
        "run_id": payload["run_id"],
        "run_relative_path": payload["run_relative_path"],
        "root_binding_sha256": payload["root_binding_sha256"],
        "snapshot_sha256": payload["snapshot_sha256"],
        "generation": payload["generation"],
        "generation_id": payload["generation_id"],
        "covered_source_set_sha256": payload["covered_source_set_sha256"],
        "permission": "read_only",
        "external_action": False,
        "resume_allowed": False,
        "execution": dict(_EXECUTION_FALSE),
    }
    return result


def evaluate_prime_external_anchor(
    capture: Mapping[str, Any],
    anchor: Mapping[str, Any] | bytes | str | None,
    *,
    last_accepted_generation: int | None,
    expected_prime_run_id: str | None = None,
) -> dict[str, Any]:
    """Return an actionless HOLD instead of raising on untrusted input."""

    try:
        return verify_prime_external_anchor(
            capture,
            anchor,
            last_accepted_generation=last_accepted_generation,
            expected_prime_run_id=expected_prime_run_id,
        )
    except PrimeAnchorError as exc:
        return {
            "schema_version": PRIME_WRITER_ANCHOR_VERIFICATION_SCHEMA,
            "status": "HOLD",
            "reason": exc.code,
            "attestation": "UNVERIFIED_EXTERNAL_ANCHOR",
            "trusted": False,
            "coherent": False,
            "fresh": False,
            "replay_protected": False,
            "permission": "read_only",
            "external_action": False,
            "resume_allowed": False,
            "execution": dict(_EXECUTION_FALSE),
        }


__all__ = [
    "ANCHOR_ERROR_CODES",
    "PRIME_EXTERNAL_ANCHOR_SCHEMA",
    "PRIME_EXTERNAL_ANCHOR_VERIFICATION_SCHEMA",
    "PRIME_ANCHOR_AUTHORITY_PREFIX",
    "PRIME_WRITER_ANCHOR_PROTOCOL",
    "PRIME_WRITER_ANCHOR_SCHEMA",
    "PRIME_WRITER_ANCHOR_VERIFICATION_SCHEMA",
    "PrimeAnchorError",
    "configure_trusted_prime_anchor",
    "evaluate_prime_external_anchor",
    "freeze_trusted_prime_anchors",
    "parse_prime_external_anchor",
    "resolve_trusted_prime_anchor",
    "verify_prime_external_anchor",
]
