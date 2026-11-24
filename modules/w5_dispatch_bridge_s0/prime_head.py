"""W5-S8 read-only verification of an externally supplied Prime head.

S7 authenticates one externally supplied Prime writer anchor.  S8 adds the
missing *precondition observation* at the boundary where a future consumer
would otherwise be tempted to perform a queue/CAS operation.  It does not
perform that operation.  It only proves, from independently supplied
observations, that the Prime snapshot, the W5 control snapshot, the queue and
the live fenced lease agree with a signed external head.

The head and its replay state are caller supplied.  They are deliberately not
persisted here: a plain integer supplied by an untrusted caller is not an
atomic replay register.  A real consumer must later advance that state in the
same authoritative transaction as its mutation.  Until then this module can
only return read-only evidence, never consume/CAS/resume/reconcile authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from threading import Lock
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json

from .prime_anchor import verify_prime_external_anchor
from .prime_binding import (
    CONTROL_CAPTURE_KEYS,
    PrimeBindingError,
    _normalize_control_capture,
    control_from_runtime_snapshot,
)


PRIME_WRITER_HEAD_SCHEMA = "prime-writer-head-v1"
PRIME_WRITER_HEAD_VERIFICATION_SCHEMA = "prime-writer-head-verification-v1"
PRIME_WRITER_HEAD_PROTOCOL = "hmac-sha256-canonical-json-v1"
PRIME_HEAD_AUTHORITY_PREFIX = "prime-head-"

_HEAD_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "authority_id",
        "key_id",
        "payload",
        "payload_sha256",
        "authority_mac",
    }
)
_PAYLOAD_KEYS = frozenset(
    {
        "anchor_sha256",
        "prime_run_id",
        "prime_root_binding_sha256",
        "prime_snapshot_sha256",
        "prime_generation",
        "prime_generation_id",
        "prime_active_task_id",
        "prime_queue_sha256",
        "prime_policy_sha256",
        "prime_active_card_sha256",
        "prime_resume_packet_sha256",
        "prime_writer_lease_sha256",
        "w5_run_id",
        "w5_card_id",
        "w5_attempt_id",
        "w5_dispatch_id",
        "w5_runtime_sha256",
        "w5_projection_sha256",
        "w5_capture_sha256",
        "w5_queue_hash",
        "w5_policy_hash",
        "w5_card_hash",
        "w5_lease_claim_sha256",
        "w5_lease_owner_id",
        "w5_lease_expires_at",
        "w5_fencing_epoch",
        "head_sequence",
        "previous_head_sha256",
    }
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EXECUTION_FALSE = {"resume": False, "reconcile": False, "mutation": False, "network": False}

HEAD_ERROR_CODES = frozenset(
    {
        "PRIME_HEAD_NOT_OBSERVED",
        "PRIME_HEAD_JSON_INVALID",
        "PRIME_HEAD_JSON_DUPLICATE_KEY",
        "PRIME_HEAD_SCHEMA_INVALID",
        "PRIME_HEAD_PAYLOAD_HASH_INVALID",
        "PRIME_HEAD_TRUST_ROOT_NOT_FROZEN",
        "PRIME_HEAD_TRUST_ROOT_UNKNOWN",
        "PRIME_HEAD_SIGNATURE_INVALID",
        "PRIME_HEAD_ANCHOR_INVALID",
        "PRIME_HEAD_CONTROL_INVALID",
        "PRIME_HEAD_PRIME_RUN_UNBOUND",
        "PRIME_HEAD_W5_IDENTITY_UNBOUND",
        "PRIME_HEAD_SUBJECT_MISMATCH",
        "PRIME_HEAD_PRIME_EVIDENCE_MISMATCH",
        "PRIME_HEAD_W5_EVIDENCE_MISMATCH",
        "PRIME_HEAD_LEASE_EXPIRED",
        "PRIME_HEAD_REPLAY_STATE_INVALID",
        "PRIME_HEAD_REPLAY_OR_DOWNGRADE",
        "PRIME_HEAD_PARENT_MISMATCH",
        "PRIME_HEAD_CURRENT_HEAD_UNPROVEN",
        "PRIME_HEAD_CURRENT_HEAD_MISMATCH",
    }
)


class PrimeHeadError(ValueError):
    """An externally supplied W5-S8 head failed closed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in HEAD_ERROR_CODES:
            raise ValueError(f"unknown Prime head code: {code}")
        self.code = code
        super().__init__(f"{code}: {message}")


_TRUST_LOCK = Lock()
_TRUSTED_HEAD_KEYS: dict[tuple[str, str], bytes] = {}
_TRUST_ROOT_FROZEN = False


def configure_trusted_prime_head(*, authority_id: str, key_id: str, key: bytes) -> None:
    """Configure one S8 trust root before the registry is frozen.

    The S8 registry is intentionally separate from the S7 anchor registry.
    A valid S7 key therefore cannot silently become a current-head key.
    """

    if (
        not isinstance(authority_id, str)
        or _SAFE_ID.fullmatch(authority_id) is None
        or not authority_id.startswith(PRIME_HEAD_AUTHORITY_PREFIX)
    ):
        raise ValueError("authority_id must use the prime-head- scope")
    if (
        not isinstance(key_id, str)
        or _SAFE_ID.fullmatch(key_id) is None
        or not key_id.startswith(PRIME_HEAD_AUTHORITY_PREFIX)
    ):
        raise ValueError("key_id must use the prime-head- scope")
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("trusted Prime head key must contain at least 16 bytes")
    identity = (authority_id, key_id)
    with _TRUST_LOCK:
        if _TRUST_ROOT_FROZEN:
            if _TRUSTED_HEAD_KEYS.get(identity) == key:
                return
            raise RuntimeError("trusted Prime head registry is frozen")
        existing = _TRUSTED_HEAD_KEYS.get(identity)
        if existing is not None and existing != key:
            raise RuntimeError("trusted Prime head reconfiguration rejected")
        _TRUSTED_HEAD_KEYS[identity] = bytes(key)


def freeze_trusted_prime_heads() -> None:
    """Freeze the S8 trust root before untrusted head data is consumed."""

    global _TRUST_ROOT_FROZEN
    with _TRUST_LOCK:
        _TRUST_ROOT_FROZEN = True


def _resolve_trusted_prime_head(*, authority_id: str, key_id: str) -> bytes:
    with _TRUST_LOCK:
        if not _TRUST_ROOT_FROZEN:
            raise PrimeHeadError("PRIME_HEAD_TRUST_ROOT_NOT_FROZEN", "trust root is not frozen")
        key = _TRUSTED_HEAD_KEYS.get((authority_id, key_id))
    if key is None:
        raise PrimeHeadError("PRIME_HEAD_TRUST_ROOT_UNKNOWN", "head authority/key is unknown")
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


def parse_prime_writer_head(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Parse an external head without filesystem, lock, or network access."""

    if value is None:
        raise PrimeHeadError("PRIME_HEAD_NOT_OBSERVED", "external head is missing")
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PrimeHeadError("PRIME_HEAD_JSON_INVALID", "head is not UTF-8") from exc
    if not isinstance(value, str):
        raise PrimeHeadError("PRIME_HEAD_JSON_INVALID", "head object or JSON text required")
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except _DuplicateJsonKey as exc:
        raise PrimeHeadError("PRIME_HEAD_JSON_DUPLICATE_KEY", f"duplicate key: {exc}") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PrimeHeadError("PRIME_HEAD_JSON_INVALID", "head JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", "head JSON object required")
    return parsed


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise PrimeHeadError("PRIME_HEAD_REPLAY_STATE_INVALID", f"{label} must be an integer >= 0")
    return value


def _optional_hash(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _hash64(value, label)


def _validate_head_shape(head: Mapping[str, Any]) -> dict[str, Any]:
    if set(head) != _HEAD_KEYS:
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", "head key set is not exact")
    if head["schema_version"] != PRIME_WRITER_HEAD_SCHEMA:
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", "unsupported head schema")
    if head["protocol"] != PRIME_WRITER_HEAD_PROTOCOL:
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", "unsupported head protocol")
    authority_id = _safe_id(head["authority_id"], "head.authority_id")
    key_id = _safe_id(head["key_id"], "head.key_id")
    payload = head["payload"]
    if not isinstance(payload, Mapping) or set(payload) != _PAYLOAD_KEYS:
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", "head payload key set is not exact")
    if head["payload_sha256"] != canonical_hash(dict(payload)):
        raise PrimeHeadError("PRIME_HEAD_PAYLOAD_HASH_INVALID", "payload hash does not match")
    if _HEX64.fullmatch(str(head["authority_mac"])) is None:
        raise PrimeHeadError("PRIME_HEAD_SCHEMA_INVALID", "authority_mac must be lowercase SHA-256")
    checked_payload = {
        "anchor_sha256": _hash64(payload["anchor_sha256"], "payload.anchor_sha256"),
        "prime_run_id": _safe_id(payload["prime_run_id"], "payload.prime_run_id"),
        "prime_root_binding_sha256": _hash64(payload["prime_root_binding_sha256"], "payload.prime_root_binding_sha256"),
        "prime_snapshot_sha256": _hash64(payload["prime_snapshot_sha256"], "payload.prime_snapshot_sha256"),
        "prime_generation": _positive_int(payload["prime_generation"], "payload.prime_generation"),
        "prime_generation_id": _safe_id(payload["prime_generation_id"], "payload.prime_generation_id"),
        "prime_active_task_id": _safe_id(payload["prime_active_task_id"], "payload.prime_active_task_id"),
        "prime_queue_sha256": _hash64(payload["prime_queue_sha256"], "payload.prime_queue_sha256"),
        "prime_policy_sha256": _hash64(payload["prime_policy_sha256"], "payload.prime_policy_sha256"),
        "prime_active_card_sha256": _hash64(payload["prime_active_card_sha256"], "payload.prime_active_card_sha256"),
        "prime_resume_packet_sha256": _hash64(payload["prime_resume_packet_sha256"], "payload.prime_resume_packet_sha256"),
        "prime_writer_lease_sha256": _hash64(payload["prime_writer_lease_sha256"], "payload.prime_writer_lease_sha256"),
        "w5_run_id": _safe_id(payload["w5_run_id"], "payload.w5_run_id"),
        "w5_card_id": _safe_id(payload["w5_card_id"], "payload.w5_card_id"),
        "w5_attempt_id": _safe_id(payload["w5_attempt_id"], "payload.w5_attempt_id"),
        "w5_dispatch_id": _safe_id(payload["w5_dispatch_id"], "payload.w5_dispatch_id"),
        "w5_runtime_sha256": _hash64(payload["w5_runtime_sha256"], "payload.w5_runtime_sha256"),
        "w5_projection_sha256": _hash64(payload["w5_projection_sha256"], "payload.w5_projection_sha256"),
        "w5_capture_sha256": _hash64(payload["w5_capture_sha256"], "payload.w5_capture_sha256"),
        # W5-S3/S4 deliberately treats queue/policy/card references as
        # opaque controller-owned hashes.  They are compared exactly here;
        # imposing a Prime SHA-256 lexical shape would break that contract.
        "w5_queue_hash": _safe_id(payload["w5_queue_hash"], "payload.w5_queue_hash"),
        "w5_policy_hash": _safe_id(payload["w5_policy_hash"], "payload.w5_policy_hash"),
        "w5_card_hash": _safe_id(payload["w5_card_hash"], "payload.w5_card_hash"),
        "w5_lease_claim_sha256": _hash64(payload["w5_lease_claim_sha256"], "payload.w5_lease_claim_sha256"),
        "w5_lease_owner_id": _safe_id(payload["w5_lease_owner_id"], "payload.w5_lease_owner_id"),
        "w5_lease_expires_at": _positive_int(payload["w5_lease_expires_at"], "payload.w5_lease_expires_at"),
        "w5_fencing_epoch": _positive_int(payload["w5_fencing_epoch"], "payload.w5_fencing_epoch"),
        "head_sequence": _positive_int(payload["head_sequence"], "payload.head_sequence"),
        "previous_head_sha256": _optional_hash(payload["previous_head_sha256"], "payload.previous_head_sha256"),
    }
    return {
        "schema_version": PRIME_WRITER_HEAD_SCHEMA,
        "protocol": PRIME_WRITER_HEAD_PROTOCOL,
        "authority_id": authority_id,
        "key_id": key_id,
        "payload": checked_payload,
        "payload_sha256": str(head["payload_sha256"]),
        "authority_mac": str(head["authority_mac"]),
    }


def _control_observation(control_capture: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    if not isinstance(control_capture, Mapping):
        raise PrimeHeadError("PRIME_HEAD_CONTROL_INVALID", "control capture object is required")
    if set(control_capture) != CONTROL_CAPTURE_KEYS:
        raise PrimeHeadError("PRIME_HEAD_CONTROL_INVALID", "control capture key set is not exact")
    try:
        normalized = _normalize_control_capture(control_capture)
        control = control_from_runtime_snapshot(normalized["runtime"])
    except (PrimeBindingError, TypeError, ValueError) as exc:
        raise PrimeHeadError("PRIME_HEAD_CONTROL_INVALID", "control capture is not a valid S4 read-only capture") from exc

    run = control["run"]
    card = control["card"]
    attempt = control["attempt"]
    dispatch = control["dispatch"]
    lease = control["lease"]
    if (
        run["run_id"] != normalized["run_id"]
        or card["run_id"] != run["run_id"]
        or attempt["run_id"] != run["run_id"]
        or dispatch["run_id"] != run["run_id"]
        or attempt["card_id"] != card["card_id"]
        or card["active_attempt_id"] != attempt["attempt_id"]
        or attempt["dispatch_id"] != dispatch["dispatch_id"]
        or run["active_dispatch_id"] != dispatch["dispatch_id"]
        or dispatch["attempt_id"] != attempt["attempt_id"]
        or run["queue_hash"] != card["source_queue_hash"]
        or run["fencing_epoch"] != dispatch["fencing_epoch"]
        or run["fencing_epoch"] != lease["fencing_epoch"]
        or run["lease_token"] != lease["token"]
        or dispatch["owner_id"] != lease["owner_id"]
        or dispatch["lease_expires_at"] != lease["expires_at"]
    ):
        raise PrimeHeadError("PRIME_HEAD_CONTROL_INVALID", "control identity, queue or fence fields drifted")
    if lease["expires_at"] <= normalized["clock_after_epoch"]:
        raise PrimeHeadError("PRIME_HEAD_LEASE_EXPIRED", "W5 lease is not live at the captured control clock")
    return normalized, control, canonical_hash(normalized)


def _prime_observation(capture: Mapping[str, Any]) -> dict[str, Any]:
    try:
        root = capture["root"]
        parsed = capture["parsed"]
        files = capture["files"]
        session = parsed["session_state"]
        active = parsed["active_task"]
        active_task_id = session["active_task_id"]
        if active_task_id != active["task_id"]:
            raise KeyError("active task mismatch")
        if root["run_id"] != session["run_id"]:
            raise KeyError("Prime run mismatch")
        names = (
            "queue",
            "policy",
            "active_card",
            "resume_packet",
            "writer_lease",
        )
        hashes = {name: _hash64(files[name]["sha256"], f"Prime files.{name}.sha256") for name in names}
        return {
            "run_id": _safe_id(root["run_id"], "Prime root.run_id"),
            "root_binding_sha256": _hash64(root["root_binding_sha256"], "Prime root.root_binding_sha256"),
            "snapshot_sha256": _hash64(capture["snapshot_sha256"], "Prime snapshot_sha256"),
            "active_task_id": _safe_id(active_task_id, "Prime active_task_id"),
            **hashes,
        }
    except PrimeHeadError:
        raise
    except (KeyError, TypeError, AttributeError) as exc:
        raise PrimeHeadError("PRIME_HEAD_ANCHOR_INVALID", "Prime V2 capture is incomplete") from exc


def _expected_w5_identity(value: Mapping[str, Any] | None) -> dict[str, str]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"run_id", "card_id", "attempt_id", "dispatch_id"}
    ):
        raise PrimeHeadError("PRIME_HEAD_W5_IDENTITY_UNBOUND", "explicit W5 run/card/attempt/dispatch identity is required")
    return {
        key: _safe_id(value[key], f"expected_w5_identity.{key}")
        for key in ("run_id", "card_id", "attempt_id", "dispatch_id")
    }


def _expected_current_head(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"head_sequence", "head_sha256"}:
        raise PrimeHeadError("PRIME_HEAD_CURRENT_HEAD_UNPROVEN", "external current-head observation is required")
    return {
        "head_sequence": _positive_int(value["head_sequence"], "expected_current_head.head_sequence"),
        "head_sha256": _hash64(value["head_sha256"], "expected_current_head.head_sha256"),
    }


def _head_mac_core(head: Mapping[str, Any]) -> dict[str, Any]:
    return {key: head[key] for key in ("schema_version", "protocol", "authority_id", "key_id", "payload", "payload_sha256")}


def verify_prime_writer_head(
    capture: Mapping[str, Any],
    anchor: Mapping[str, Any] | bytes | str | None,
    control_capture: Mapping[str, Any],
    head: Mapping[str, Any] | bytes | str | None,
    *,
    last_accepted_generation: int | None,
    last_accepted_head_sequence: int | None,
    last_accepted_head_sha256: str | None,
    expected_current_head: Mapping[str, Any] | None,
    expected_prime_run_id: str | None,
    expected_w5_identity: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Verify a current external head and return actionless CAS evidence.

    This function intentionally does *not* update the supplied replay state.
    The state is a precondition input only; an eventual consumer must compare
    and advance it atomically with its own authoritative mutation.
    """

    if expected_prime_run_id is None:
        raise PrimeHeadError("PRIME_HEAD_PRIME_RUN_UNBOUND", "explicit Prime run identity is required")
    expected_prime_run_id = _safe_id(expected_prime_run_id, "expected_prime_run_id")
    expected_w5 = _expected_w5_identity(expected_w5_identity)
    if last_accepted_head_sequence is None:
        raise PrimeHeadError("PRIME_HEAD_REPLAY_STATE_INVALID", "last accepted head sequence is required")
    last_sequence = _nonnegative_int(last_accepted_head_sequence, "last_accepted_head_sequence")
    if last_sequence == 0:
        if last_accepted_head_sha256 is not None:
            raise PrimeHeadError("PRIME_HEAD_REPLAY_STATE_INVALID", "sequence zero must have no accepted head hash")
    else:
        _hash64(last_accepted_head_sha256, "last_accepted_head_sha256")

    try:
        anchor_result = verify_prime_external_anchor(
            capture,
            anchor,
            last_accepted_generation=last_accepted_generation,
            expected_prime_run_id=expected_prime_run_id,
        )
    except Exception as exc:
        # Do not leak S7's result as S8 authority.  The wrapper remains a
        # single, actionless HOLD boundary for all malformed/untrusted input.
        raise PrimeHeadError("PRIME_HEAD_ANCHOR_INVALID", "S7 external anchor verification failed") from exc

    parsed_head = parse_prime_writer_head(head)
    checked = _validate_head_shape(parsed_head)
    key = _resolve_trusted_prime_head(
        authority_id=checked["authority_id"],
        key_id=checked["key_id"],
    )
    expected_mac = hmac.new(
        key,
        canonical_json(_head_mac_core(checked)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(checked["authority_mac"], expected_mac):
        raise PrimeHeadError("PRIME_HEAD_SIGNATURE_INVALID", "external head MAC does not match")

    prime = _prime_observation(capture)
    normalized_control, control, control_hash = _control_observation(control_capture)
    payload = checked["payload"]
    lease = control["lease"]
    lease_claim = canonical_hash(
        {
            "run_id": control["run"]["run_id"],
            "owner_id": lease["owner_id"],
            "token": lease["token"],
            "fencing_epoch": lease["fencing_epoch"],
            "expires_at": lease["expires_at"],
        }
    )
    actual = {
        "anchor_sha256": anchor_result["anchor_sha256"],
        "prime_run_id": prime["run_id"],
        "prime_root_binding_sha256": prime["root_binding_sha256"],
        "prime_snapshot_sha256": prime["snapshot_sha256"],
        "prime_generation": anchor_result["generation"],
        "prime_generation_id": anchor_result["generation_id"],
        "prime_active_task_id": prime["active_task_id"],
        "prime_queue_sha256": prime["queue"],
        "prime_policy_sha256": prime["policy"],
        "prime_active_card_sha256": prime["active_card"],
        "prime_resume_packet_sha256": prime["resume_packet"],
        "prime_writer_lease_sha256": prime["writer_lease"],
        "w5_run_id": control["run"]["run_id"],
        "w5_card_id": control["card"]["card_id"],
        "w5_attempt_id": control["attempt"]["attempt_id"],
        "w5_dispatch_id": control["dispatch"]["dispatch_id"],
        "w5_runtime_sha256": normalized_control["runtime_sha256"],
        "w5_projection_sha256": normalized_control["projection_sha256"],
        "w5_capture_sha256": control_hash,
        "w5_queue_hash": control["run"]["queue_hash"],
        "w5_policy_hash": control["run"]["policy_hash"],
        "w5_card_hash": control["card"]["card_hash"],
        "w5_lease_claim_sha256": lease_claim,
        "w5_lease_owner_id": lease["owner_id"],
        "w5_lease_expires_at": lease["expires_at"],
        "w5_fencing_epoch": lease["fencing_epoch"],
        "head_sequence": payload["head_sequence"],
        "previous_head_sha256": payload["previous_head_sha256"],
    }
    if prime["active_task_id"] != control["card"]["card_id"]:
        raise PrimeHeadError("PRIME_HEAD_SUBJECT_MISMATCH", "Prime active task and W5 card are not explicitly mapped")
    if actual["w5_run_id"] != expected_w5["run_id"] or any(
        actual[f"w5_{key}"] != expected_w5[key]
        for key in ("card_id", "attempt_id", "dispatch_id")
    ):
        raise PrimeHeadError("PRIME_HEAD_W5_IDENTITY_UNBOUND", "control capture is not the requested W5 subject")
    for key, observed in actual.items():
        if payload[key] != observed:
            code = "PRIME_HEAD_PRIME_EVIDENCE_MISMATCH" if key.startswith("prime_") or key == "anchor_sha256" else "PRIME_HEAD_W5_EVIDENCE_MISMATCH"
            raise PrimeHeadError(code, f"head payload field {key} does not match the fresh observation")

    sequence = payload["head_sequence"]
    if sequence <= last_sequence:
        raise PrimeHeadError("PRIME_HEAD_REPLAY_OR_DOWNGRADE", "head sequence is not newer than accepted state")
    if last_sequence == 0:
        if sequence != 1 or payload["previous_head_sha256"] is not None:
            raise PrimeHeadError("PRIME_HEAD_PARENT_MISMATCH", "first head must start sequence one without a parent")
    elif sequence != last_sequence + 1 or payload["previous_head_sha256"] != last_accepted_head_sha256:
        raise PrimeHeadError("PRIME_HEAD_PARENT_MISMATCH", "head parent does not match the accepted external chain")

    head_sha256 = canonical_hash(checked)
    expected = _expected_current_head(expected_current_head)
    if expected["head_sequence"] != sequence or expected["head_sha256"] != head_sha256:
        raise PrimeHeadError("PRIME_HEAD_CURRENT_HEAD_MISMATCH", "head is not the independently observed current head")

    return {
        "schema_version": PRIME_WRITER_HEAD_VERIFICATION_SCHEMA,
        "status": "PRECONDITION_SATISFIED_READ_ONLY",
        "head_status": "MATCHED_HEAD",
        "attestation": "VERIFIED_EXTERNAL_HMAC",
        "trusted": True,
        "current_head": True,
        "replay_protected": True,
        "generation_bound": True,
        "queue_bound": True,
        "fencing_bound": True,
        "lease_live": True,
        "prime_run_id": prime["run_id"],
        "w5_run_id": control["run"]["run_id"],
        "card_id": control["card"]["card_id"],
        "attempt_id": control["attempt"]["attempt_id"],
        "dispatch_id": control["dispatch"]["dispatch_id"],
        "anchor_sha256": anchor_result["anchor_sha256"],
        "head_sha256": head_sha256,
        "head_sequence": sequence,
        "previous_head_sha256": payload["previous_head_sha256"],
        "generation": anchor_result["generation"],
        "generation_id": anchor_result["generation_id"],
        "prime_snapshot_sha256": prime["snapshot_sha256"],
        "prime_queue_sha256": prime["queue"],
        "w5_queue_hash": control["run"]["queue_hash"],
        "w5_policy_hash": control["run"]["policy_hash"],
        "w5_fencing_epoch": lease["fencing_epoch"],
        "w5_lease_claim_sha256": lease_claim,
        "permission": "read_only",
        "external_action": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "execution": dict(_EXECUTION_FALSE),
    }


def evaluate_prime_writer_head(
    capture: Mapping[str, Any],
    anchor: Mapping[str, Any] | bytes | str | None,
    control_capture: Mapping[str, Any],
    head: Mapping[str, Any] | bytes | str | None,
    *,
    last_accepted_generation: int | None,
    last_accepted_head_sequence: int | None,
    last_accepted_head_sha256: str | None,
    expected_current_head: Mapping[str, Any] | None,
    expected_prime_run_id: str | None,
    expected_w5_identity: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return a non-authoritative HOLD for every failed/untrusted input."""

    try:
        return verify_prime_writer_head(
            capture,
            anchor,
            control_capture,
            head,
            last_accepted_generation=last_accepted_generation,
            last_accepted_head_sequence=last_accepted_head_sequence,
            last_accepted_head_sha256=last_accepted_head_sha256,
            expected_current_head=expected_current_head,
            expected_prime_run_id=expected_prime_run_id,
            expected_w5_identity=expected_w5_identity,
        )
    except PrimeHeadError as exc:
        code = exc.code
    except (TypeError, ValueError, KeyError, AttributeError):
        # The evaluator is the untrusted-input boundary.  A malformed object
        # must become an ordinary HOLD, never an exception that a caller could
        # mistake for a partially verified precondition.
        code = "PRIME_HEAD_SCHEMA_INVALID"
    return {
        "schema_version": PRIME_WRITER_HEAD_VERIFICATION_SCHEMA,
        "status": "HOLD",
        "reason": code,
        "attestation": "UNVERIFIED_EXTERNAL_HEAD",
        "trusted": False,
        "current_head": False,
        "replay_protected": False,
        "permission": "read_only",
        "external_action": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "execution": dict(_EXECUTION_FALSE),
    }


__all__ = [
    "HEAD_ERROR_CODES",
    "PRIME_HEAD_AUTHORITY_PREFIX",
    "PRIME_WRITER_HEAD_PROTOCOL",
    "PRIME_WRITER_HEAD_SCHEMA",
    "PRIME_WRITER_HEAD_VERIFICATION_SCHEMA",
    "PrimeHeadError",
    "configure_trusted_prime_head",
    "evaluate_prime_writer_head",
    "freeze_trusted_prime_heads",
    "parse_prime_writer_head",
    "verify_prime_writer_head",
]
