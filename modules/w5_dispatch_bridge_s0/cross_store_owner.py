"""W5-S17 read-only replay-owner preflight.

S16 verifies an externally supplied worker/host/replay snapshot but never
advances its replay head.  S17 adds one separately authenticated observation
of the persistent replay owner and derives a deterministic CAS candidate.

This module is deliberately only a preflight boundary.  It does not reserve
an idempotency key, perform a CAS or Consume, classify a commit, issue a
receipt, start recovery, or mutate any Prime/control-plane state.  A valid
result is ``OWNER_PREVIEW_ONLY`` with ``CAS_RECHECK_REQUIRED``.  The later
owner transaction must re-read the live state and decide atomically.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json

from .cross_store_worker_attestation import (
    CrossStoreWorkerAttestationError,
    verify_worker_host_attestation,
)


OWNER_OBSERVATION_SCHEMA = "prime-cross-store-replay-owner-observation-v1"
OWNER_HEAD_SCHEMA = "prime-cross-store-replay-owner-head-v1"
OWNER_STATE_SCHEMA = "prime-replay-registry-owner-v1"
OWNER_PREFLIGHT_SCHEMA = "prime-cross-store-replay-owner-preflight-verification-v1"
OWNER_REQUEST_SCHEMA = "prime-cross-store-replay-owner-preflight-v1"
OWNER_PROTOCOL = "hmac-sha256-canonical-json-v1"
OWNER_ROLE = "replay_registry_owner_preflight_read_only"
OWNER_AUTHORITY_PREFIX = "source-replay-owner-"
OWNER_OPERATION = "ADVANCE_REPLAY"
OWNER_PARTICIPANT_IDS = frozenset({"owner_registry", "replay_head", "idempotency_index"})

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}\Z")
_EXECUTION_FALSE = {"resume": False, "reconcile": False, "mutation": False, "network": False}

OWNER_ERROR_CODES = frozenset(
    {
        "OWNER_NOT_OBSERVED",
        "OWNER_JSON_INVALID",
        "OWNER_JSON_DUPLICATE_KEY",
        "OWNER_SCHEMA_INVALID",
        "OWNER_TRUST_ROOT_NOT_FROZEN",
        "OWNER_TRUST_ROOT_UNKNOWN",
        "OWNER_SIGNATURE_INVALID",
        "OWNER_S16_INVALID",
        "OWNER_S16_UNSAFE",
        "OWNER_SCOPE_MISMATCH",
        "OWNER_HEAD_CONFLICT",
        "OWNER_ACTIVE_TRANSACTION",
        "OWNER_JOURNAL_NOT_CLEAN",
        "OWNER_REQUEST_INVALID",
    }
)

_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "attestation_id",
        "authority_id",
        "key_id",
        "protocol",
        "payload",
        "payload_sha256",
        "authority_mac",
    }
)
_OWNER_PAYLOAD_KEYS = frozenset(
    {
        "owner_id",
        "owner_instance_id",
        "snapshot_id",
        "owner_schema_version",
        "replay_namespace",
        "registry_id",
        "registry_version",
        "registry_epoch",
        "registry_sha256",
        "profile_set_sha256",
        "source_set_sha256",
        "cohort_binding_sha256",
        "host_id",
        "host_instance_id",
        "worker_epoch",
        "state_version",
        "owner_epoch",
        "fencing_epoch",
        "last_sequence",
        "last_attestation_set_sha256",
        "last_nonce_sha256",
        "head_sha256",
        "journal_status",
        "active_transaction_id_or_null",
        "active_intent_sha256_or_null",
        "idempotency_index_sha256",
        "observed_at",
        "observation_sha256",
    }
)
_REQUEST_KEYS = frozenset({"schema_version", "contract_role", "transaction_id", "idempotency_key", "operation", "safety"})
_SAFETY_KEYS = frozenset(
    {
        "read_only",
        "owner_write",
        "owner_cas",
        "owner_consume",
        "prime_consume",
        "sqlite_write",
        "queue_write",
        "lock",
        "recovery",
        "external_action",
    }
)
_JOURNAL_STATUSES = frozenset({"CLEAN", "OPEN", "IN_DOUBT", "MISSING", "DRIFT"})

_TRUSTED_KEYS: dict[tuple[str, str], bytes] = {}
_TRUST_ROOT_FROZEN = False


class CrossStoreOwnerError(ValueError):
    """A W5-S17 owner preflight failed closed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in OWNER_ERROR_CODES:
            raise ValueError(f"unknown owner error code: {code}")
        self.code = code
        super().__init__(f"{code}: {message}")


def configure_trusted_owner_authority(*, authority_id: str, key_id: str, key: bytes) -> None:
    """Configure one owner observation authority before the root is frozen."""

    if not isinstance(authority_id, str) or _SAFE_ID.fullmatch(authority_id) is None or not authority_id.startswith(OWNER_AUTHORITY_PREFIX):
        raise ValueError("authority_id must use the source-replay-owner- scope")
    if not isinstance(key_id, str) or _SAFE_ID.fullmatch(key_id) is None or not key_id.startswith(OWNER_AUTHORITY_PREFIX):
        raise ValueError("key_id must use the source-replay-owner- scope")
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("owner trust key must contain at least 16 bytes")
    identity = (authority_id, key_id)
    if _TRUST_ROOT_FROZEN:
        if _TRUSTED_KEYS.get(identity) == key:
            return
        raise RuntimeError("owner trust registry is frozen")
    existing = _TRUSTED_KEYS.get(identity)
    if existing is not None and existing != key:
        raise RuntimeError("owner trust reconfiguration rejected")
    _TRUSTED_KEYS[identity] = bytes(key)


def freeze_trusted_owner_authorities() -> None:
    """Freeze owner trust roots before untrusted observations are read."""

    global _TRUST_ROOT_FROZEN
    _TRUST_ROOT_FROZEN = True


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


def _parse(value: Mapping[str, Any] | bytes | str | None, *, missing: str, invalid: str) -> dict[str, Any]:
    if value is None:
        raise CrossStoreOwnerError(missing, "owner evidence is missing")
    if isinstance(value, Mapping):
        try:
            return copy.deepcopy(dict(value))
        except (TypeError, ValueError, copy.Error) as exc:
            raise CrossStoreOwnerError(invalid, "owner evidence could not be isolated") from exc
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CrossStoreOwnerError(invalid, "owner evidence is not UTF-8") from exc
    if not isinstance(value, str):
        raise CrossStoreOwnerError(invalid, "owner evidence object or JSON text required")
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except _DuplicateJsonKey as exc:
        raise CrossStoreOwnerError("OWNER_JSON_DUPLICATE_KEY", f"duplicate key: {exc}") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CrossStoreOwnerError(invalid, "owner evidence JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise CrossStoreOwnerError(invalid, "owner evidence JSON object required")
    return parsed


def _text(value: Any, label: str, *, code: str = "OWNER_SCHEMA_INVALID") -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CrossStoreOwnerError(code, f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str, *, code: str = "OWNER_SCHEMA_INVALID") -> str:
    value = _text(value, label, code=code)
    if _SAFE_ID.fullmatch(value) is None:
        raise CrossStoreOwnerError(code, f"{label} is not a safe identifier")
    return value


def _idempotency(value: Any, label: str) -> str:
    value = _text(value, label, code="OWNER_REQUEST_INVALID")
    if _IDEMPOTENCY.fullmatch(value) is None:
        raise CrossStoreOwnerError("OWNER_REQUEST_INVALID", f"{label} is not a safe idempotency key")
    return value


def _hash64(value: Any, label: str, *, code: str = "OWNER_SCHEMA_INVALID") -> str:
    value = _text(value, label, code=code)
    if _HEX64.fullmatch(value) is None:
        raise CrossStoreOwnerError(code, f"{label} must be lowercase SHA-256")
    return value


def _optional_hash(value: Any, label: str, *, code: str = "OWNER_SCHEMA_INVALID") -> str | None:
    if value is None:
        return None
    return _hash64(value, label, code=code)


def _nonnegative(value: Any, label: str, *, code: str = "OWNER_SCHEMA_INVALID") -> int:
    if type(value) is not int or value < 0:
        raise CrossStoreOwnerError(code, f"{label} must be an integer >= 0")
    return value


def _positive(value: Any, label: str, *, code: str = "OWNER_SCHEMA_INVALID") -> int:
    value = _nonnegative(value, label, code=code)
    if value == 0:
        raise CrossStoreOwnerError(code, f"{label} must be greater than zero")
    return value


def _boolean(value: Any, label: str, *, code: str = "OWNER_SCHEMA_INVALID") -> bool:
    if value is not True and value is not False:
        raise CrossStoreOwnerError(code, f"{label} must be a boolean")
    return value


def _exact(value: Any, keys: frozenset[str], label: str, *, code: str = "OWNER_SCHEMA_INVALID") -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise CrossStoreOwnerError(code, f"{label} keys are not exact")
    return value


def _parse_owner_envelope(value: Mapping[str, Any] | bytes | str | None) -> tuple[dict[str, Any], str]:
    parsed = _parse(value, missing="OWNER_NOT_OBSERVED", invalid="OWNER_JSON_INVALID")
    _exact(parsed, _ENVELOPE_KEYS, "owner signed envelope")
    if parsed["schema_version"] != OWNER_OBSERVATION_SCHEMA or parsed["protocol"] != OWNER_PROTOCOL:
        raise CrossStoreOwnerError("OWNER_SCHEMA_INVALID", "owner observation schema/protocol is unsupported")
    attestation_id = _safe_id(parsed["attestation_id"], "owner.attestation_id")
    authority_id = _safe_id(parsed["authority_id"], "owner.authority_id")
    key_id = _safe_id(parsed["key_id"], "owner.key_id")
    payload = parsed["payload"]
    if not isinstance(payload, Mapping):
        raise CrossStoreOwnerError("OWNER_SCHEMA_INVALID", "owner payload must be an object")
    payload = copy.deepcopy(dict(payload))
    payload_sha256 = _hash64(parsed["payload_sha256"], "owner.payload_sha256")
    if payload_sha256 != canonical_hash(payload):
        raise CrossStoreOwnerError("OWNER_SCHEMA_INVALID", "owner payload digest differs")
    if not _TRUST_ROOT_FROZEN:
        raise CrossStoreOwnerError("OWNER_TRUST_ROOT_NOT_FROZEN", "owner trust root is not frozen")
    key = _TRUSTED_KEYS.get((authority_id, key_id))
    if key is None:
        raise CrossStoreOwnerError("OWNER_TRUST_ROOT_UNKNOWN", "owner authority/key is unknown")
    core = {
        "schema_version": OWNER_OBSERVATION_SCHEMA,
        "attestation_id": attestation_id,
        "authority_id": authority_id,
        "key_id": key_id,
        "protocol": OWNER_PROTOCOL,
        "payload": payload,
        "payload_sha256": payload_sha256,
    }
    mac = _hash64(parsed["authority_mac"], "owner.authority_mac")
    expected_mac = hmac.new(key, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected_mac):
        raise CrossStoreOwnerError("OWNER_SIGNATURE_INVALID", "owner observation MAC does not match")
    envelope = {**core, "authority_mac": mac}
    return envelope, canonical_hash(envelope)


def _head_core(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": OWNER_HEAD_SCHEMA,
        "owner_id": payload["owner_id"],
        "owner_instance_id": payload["owner_instance_id"],
        "replay_namespace": payload["replay_namespace"],
        "registry_id": payload["registry_id"],
        "registry_version": payload["registry_version"],
        "registry_epoch": payload["registry_epoch"],
        "registry_sha256": payload["registry_sha256"],
        "profile_set_sha256": payload["profile_set_sha256"],
        "source_set_sha256": payload["source_set_sha256"],
        "cohort_binding_sha256": payload["cohort_binding_sha256"],
        "host_id": payload["host_id"],
        "host_instance_id": payload["host_instance_id"],
        "worker_epoch": payload["worker_epoch"],
        "state_version": payload["state_version"],
        "owner_epoch": payload["owner_epoch"],
        "fencing_epoch": payload["fencing_epoch"],
        "last_sequence": payload["last_sequence"],
        "last_attestation_set_sha256": payload["last_attestation_set_sha256"],
        "last_nonce_sha256": payload["last_nonce_sha256"],
        "idempotency_index_sha256": payload["idempotency_index_sha256"],
    }


def parse_owner_observation(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Parse and authenticate one external owner observation."""

    envelope, _ = _parse_owner_envelope(value)
    payload = _exact(envelope["payload"], _OWNER_PAYLOAD_KEYS, "owner payload")
    normalized = {
        "owner_id": _safe_id(payload["owner_id"], "owner.owner_id"),
        "owner_instance_id": _safe_id(payload["owner_instance_id"], "owner.owner_instance_id"),
        "snapshot_id": _safe_id(payload["snapshot_id"], "owner.snapshot_id"),
        "owner_schema_version": _safe_id(payload["owner_schema_version"], "owner.owner_schema_version"),
        "replay_namespace": _safe_id(payload["replay_namespace"], "owner.replay_namespace"),
        "registry_id": _safe_id(payload["registry_id"], "owner.registry_id"),
        "registry_version": _safe_id(payload["registry_version"], "owner.registry_version"),
        "registry_epoch": _nonnegative(payload["registry_epoch"], "owner.registry_epoch"),
        "registry_sha256": _hash64(payload["registry_sha256"], "owner.registry_sha256"),
        "profile_set_sha256": _hash64(payload["profile_set_sha256"], "owner.profile_set_sha256"),
        "source_set_sha256": _hash64(payload["source_set_sha256"], "owner.source_set_sha256"),
        "cohort_binding_sha256": _hash64(payload["cohort_binding_sha256"], "owner.cohort_binding_sha256"),
        "host_id": _safe_id(payload["host_id"], "owner.host_id"),
        "host_instance_id": _safe_id(payload["host_instance_id"], "owner.host_instance_id"),
        "worker_epoch": _positive(payload["worker_epoch"], "owner.worker_epoch"),
        "state_version": _positive(payload["state_version"], "owner.state_version"),
        "owner_epoch": _positive(payload["owner_epoch"], "owner.owner_epoch"),
        "fencing_epoch": _positive(payload["fencing_epoch"], "owner.fencing_epoch"),
        "last_sequence": _nonnegative(payload["last_sequence"], "owner.last_sequence"),
        "last_attestation_set_sha256": _optional_hash(payload["last_attestation_set_sha256"], "owner.last_attestation_set_sha256"),
        "last_nonce_sha256": _optional_hash(payload["last_nonce_sha256"], "owner.last_nonce_sha256"),
        "idempotency_index_sha256": _hash64(payload["idempotency_index_sha256"], "owner.idempotency_index_sha256"),
        "observed_at": _nonnegative(payload["observed_at"], "owner.observed_at"),
    }
    normalized["journal_status"] = _text(payload["journal_status"], "owner.journal_status")
    if normalized["owner_schema_version"] != OWNER_STATE_SCHEMA:
        raise CrossStoreOwnerError("OWNER_SCHEMA_INVALID", "owner state schema version is unsupported")
    normalized["active_transaction_id_or_null"] = None if payload["active_transaction_id_or_null"] is None else _safe_id(payload["active_transaction_id_or_null"], "owner.active_transaction_id_or_null")
    normalized["active_intent_sha256_or_null"] = _optional_hash(payload["active_intent_sha256_or_null"], "owner.active_intent_sha256_or_null")
    if normalized["journal_status"] not in _JOURNAL_STATUSES:
        raise CrossStoreOwnerError("OWNER_SCHEMA_INVALID", "owner journal status is unsupported")
    if (normalized["active_transaction_id_or_null"] is None) != (normalized["active_intent_sha256_or_null"] is None):
        raise CrossStoreOwnerError("OWNER_SCHEMA_INVALID", "active owner transaction and intent must be paired")
    if normalized["last_sequence"] == 0 and (normalized["last_attestation_set_sha256"] is not None or normalized["last_nonce_sha256"] is not None):
        raise CrossStoreOwnerError("OWNER_HEAD_CONFLICT", "empty owner head contains accepted material")
    if normalized["last_sequence"] > 0 and (normalized["last_attestation_set_sha256"] is None or normalized["last_nonce_sha256"] is None):
        raise CrossStoreOwnerError("OWNER_HEAD_CONFLICT", "owner head lacks accepted material")
    observation_sha256 = _hash64(payload["observation_sha256"], "owner.observation_sha256")
    if observation_sha256 != canonical_hash(normalized):
        raise CrossStoreOwnerError("OWNER_SCHEMA_INVALID", "owner observation digest differs")
    head_sha256 = _hash64(payload["head_sha256"], "owner.head_sha256")
    if head_sha256 != canonical_hash(_head_core(normalized)):
        raise CrossStoreOwnerError("OWNER_HEAD_CONFLICT", "owner head digest differs")
    return {
        "envelope": envelope,
        "envelope_sha256": canonical_hash(envelope),
        "payload": {**normalized, "head_sha256": head_sha256},
        "observation_sha256": observation_sha256,
        "head_sha256": head_sha256,
    }


def _parse_request(value: Mapping[str, Any] | None, *, transaction_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CrossStoreOwnerError("OWNER_REQUEST_INVALID", "owner preflight request is required")
    request = copy.deepcopy(dict(value))
    _exact(request, _REQUEST_KEYS, "owner preflight request", code="OWNER_REQUEST_INVALID")
    if request["schema_version"] != OWNER_REQUEST_SCHEMA or request["contract_role"] != OWNER_ROLE:
        raise CrossStoreOwnerError("OWNER_REQUEST_INVALID", "owner preflight request schema/role is unsupported")
    if _safe_id(request["transaction_id"], "request.transaction_id", code="OWNER_REQUEST_INVALID") != transaction_id:
        raise CrossStoreOwnerError("OWNER_SCOPE_MISMATCH", "request transaction differs from S16")
    if _idempotency(request["idempotency_key"], "request.idempotency_key") != request["idempotency_key"]:
        raise CrossStoreOwnerError("OWNER_REQUEST_INVALID", "idempotency key is not stable")
    if request["operation"] != OWNER_OPERATION:
        raise CrossStoreOwnerError("OWNER_REQUEST_INVALID", "only replay advance preflight is in scope")
    safety = _exact(request["safety"], _SAFETY_KEYS, "request.safety", code="OWNER_REQUEST_INVALID")
    expected = {
        "read_only": True,
        "owner_write": False,
        "owner_cas": False,
        "owner_consume": False,
        "prime_consume": False,
        "sqlite_write": False,
        "queue_write": False,
        "lock": False,
        "recovery": False,
        "external_action": False,
    }
    if {key: _boolean(safety[key], f"request.safety.{key}", code="OWNER_REQUEST_INVALID") for key in sorted(_SAFETY_KEYS)} != expected:
        raise CrossStoreOwnerError("OWNER_REQUEST_INVALID", "owner preflight requests an unsafe capability")
    return request


def _s16_context(*, worker_attestations: Mapping[str, Mapping[str, Any]], replay_observation: Mapping[str, Any], replay_floor: Mapping[str, Any], host_runtime_attestation: Mapping[str, Any], s15_input: Mapping[str, Any]) -> dict[str, Any]:
    try:
        proof = verify_worker_host_attestation(
            worker_attestations=worker_attestations,
            replay_observation=replay_observation,
            replay_floor=replay_floor,
            host_runtime_attestation=host_runtime_attestation,
            s15_input=s15_input,
        )
    except CrossStoreWorkerAttestationError as exc:
        raise CrossStoreOwnerError("OWNER_S16_INVALID", exc.code) from exc
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise CrossStoreOwnerError("OWNER_S16_INVALID", "S16 evidence is malformed") from exc
    if proof.get("read_only") is not True or proof.get("external_action") is not False:
        raise CrossStoreOwnerError("OWNER_S16_UNSAFE", "S16 proof is not strictly read-only")
    authorization = proof.get("worker_authorization")
    replay_envelope = proof.get("replay_observation")
    if not isinstance(authorization, Mapping) or not isinstance(replay_envelope, Mapping) or not isinstance(replay_envelope.get("payload"), Mapping):
        raise CrossStoreOwnerError("OWNER_S16_INVALID", "S16 authorization/replay proof is incomplete")
    replay = replay_envelope["payload"]
    required = ("transaction_id", "replay_namespace", "registry_id", "registry_version", "registry_sha256", "profile_set_sha256", "source_set_sha256", "cohort_binding_sha256", "host_id", "host_instance_id", "worker_epoch", "last_accepted_sequence", "last_accepted_attestation_set_sha256", "last_accepted_nonce_sha256", "gate_nonce_sha256")
    if any(key not in replay for key in required):
        raise CrossStoreOwnerError("OWNER_S16_INVALID", "S16 replay scope is incomplete")
    context = {
        "proof": proof,
        "transaction_id": _safe_id(replay["transaction_id"], "s16.transaction_id"),
        "replay_namespace": _safe_id(replay["replay_namespace"], "s16.replay_namespace"),
        "registry_id": _safe_id(replay["registry_id"], "s16.registry_id"),
        "registry_version": _safe_id(replay["registry_version"], "s16.registry_version"),
        "registry_epoch": _nonnegative(replay["registry_epoch"], "s16.registry_epoch"),
        "registry_sha256": _hash64(replay["registry_sha256"], "s16.registry_sha256"),
        "profile_set_sha256": _hash64(replay["profile_set_sha256"], "s16.profile_set_sha256"),
        "source_set_sha256": _hash64(replay["source_set_sha256"], "s16.source_set_sha256"),
        "cohort_binding_sha256": _hash64(replay["cohort_binding_sha256"], "s16.cohort_binding_sha256"),
        "host_id": _safe_id(replay["host_id"], "s16.host_id"),
        "host_instance_id": _safe_id(replay["host_instance_id"], "s16.host_instance_id"),
        "worker_epoch": _positive(replay["worker_epoch"], "s16.worker_epoch"),
        "accepted_sequence": _nonnegative(replay["last_accepted_sequence"], "s16.last_accepted_sequence"),
        "accepted_head_sha256": _optional_hash(replay["last_accepted_attestation_set_sha256"], "s16.last_accepted_head_sha256"),
        "accepted_nonce_sha256": _optional_hash(replay["last_accepted_nonce_sha256"], "s16.last_accepted_nonce_sha256"),
        "next_sequence": _positive(authorization.get("attestation_sequence"), "s16.attestation_sequence"),
        "next_head_sha256": _hash64(authorization.get("worker_attestation_set_sha256"), "s16.worker_set_sha256"),
        "next_nonce_sha256": _hash64(replay["gate_nonce_sha256"], "s16.gate_nonce_sha256"),
        "worker_authorization_sha256": _hash64(authorization.get("authorization_sha256"), "s16.authorization_sha256"),
        "gate_binding_sha256": _hash64(authorization.get("gate_binding_sha256"), "s16.gate_binding_sha256"),
        "s16_replay_observation_sha256": canonical_hash(replay_envelope),
        "s16_replay_floor_sha256": canonical_hash(proof["replay_floor"]),
    }
    if context["next_sequence"] != context["accepted_sequence"] + 1:
        raise CrossStoreOwnerError("OWNER_S16_INVALID", "S16 sequence is not the owner next sequence")
    return context


def _bind_owner_to_s16(owner: Mapping[str, Any], context: Mapping[str, Any]) -> None:
    for key in (
        "replay_namespace",
        "registry_id",
        "registry_version",
        "registry_sha256",
        "profile_set_sha256",
        "source_set_sha256",
        "cohort_binding_sha256",
        "host_id",
        "host_instance_id",
        "worker_epoch",
        "registry_epoch",
        "last_sequence",
        "last_attestation_set_sha256",
        "last_nonce_sha256",
    ):
        expected = context["accepted_sequence"] if key == "last_sequence" else context["accepted_head_sha256"] if key == "last_attestation_set_sha256" else context["accepted_nonce_sha256"] if key == "last_nonce_sha256" else context[key]
        if owner[key] != expected:
            code = "OWNER_HEAD_CONFLICT" if key.startswith("last_") else "OWNER_SCOPE_MISMATCH"
            raise CrossStoreOwnerError(code, f"owner observation differs at {key}")


def _candidate(*, request: Mapping[str, Any], owner: Mapping[str, Any], owner_observation_sha256: str, context: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "prime-cross-store-replay-owner-candidate-v1",
        "operation": OWNER_OPERATION,
        "transaction_id": context["transaction_id"],
        "idempotency_key": request["idempotency_key"],
        "owner_id": owner["owner_id"],
        "owner_instance_id": owner["owner_instance_id"],
        "replay_namespace": owner["replay_namespace"],
        "parent_owner_head_sha256": owner["head_sha256"],
        "expected_state_version": owner["state_version"],
        "proposed_next_state_version": owner["state_version"] + 1,
        "expected_sequence": owner["last_sequence"],
        "next_sequence": context["next_sequence"],
        "expected_attestation_set_sha256": owner["last_attestation_set_sha256"],
        "next_attestation_set_sha256": context["next_head_sha256"],
        "expected_nonce_sha256": owner["last_nonce_sha256"],
        "next_nonce_sha256": context["next_nonce_sha256"],
        "registry_id": context["registry_id"],
        "registry_version": context["registry_version"],
        "registry_epoch": context["registry_epoch"],
        "registry_sha256": context["registry_sha256"],
        "profile_set_sha256": context["profile_set_sha256"],
        "source_set_sha256": context["source_set_sha256"],
        "cohort_binding_sha256": context["cohort_binding_sha256"],
        "worker_authorization_sha256": context["worker_authorization_sha256"],
        "s16_replay_observation_sha256": context["s16_replay_observation_sha256"],
        "s16_replay_floor_sha256": context["s16_replay_floor_sha256"],
        "owner_fencing_epoch": owner["fencing_epoch"],
        "owner_observation_sha256": owner_observation_sha256,
    }


def verify_replay_owner_preflight(*, worker_attestations: Mapping[str, Mapping[str, Any]], replay_observation: Mapping[str, Any], replay_floor: Mapping[str, Any], host_runtime_attestation: Mapping[str, Any], s15_input: Mapping[str, Any], owner_observation: Mapping[str, Any] | bytes | str | None, request: Mapping[str, Any]) -> dict[str, Any]:
    """Verify S16 and one owner snapshot without invoking an owner."""

    context = _s16_context(
        worker_attestations=worker_attestations,
        replay_observation=replay_observation,
        replay_floor=replay_floor,
        host_runtime_attestation=host_runtime_attestation,
        s15_input=s15_input,
    )
    parsed_request = _parse_request(request, transaction_id=context["transaction_id"])
    owner = parse_owner_observation(owner_observation)
    payload = owner["payload"]
    _bind_owner_to_s16(payload, context)
    if payload["journal_status"] != "CLEAN":
        code = "OWNER_ACTIVE_TRANSACTION" if payload["active_transaction_id_or_null"] is not None else "OWNER_JOURNAL_NOT_CLEAN"
        raise CrossStoreOwnerError(code, "owner state needs a separate recovery decision")
    candidate = _candidate(request=parsed_request, owner=payload, owner_observation_sha256=owner["observation_sha256"], context=context)
    preflight_sha256 = canonical_hash(
        {
            "schema_version": OWNER_PREFLIGHT_SCHEMA,
            "owner_observation_sha256": owner["observation_sha256"],
            "owner_envelope_sha256": owner["envelope_sha256"],
            "worker_authorization_sha256": context["worker_authorization_sha256"],
            "candidate": candidate,
        }
    )
    return {
        "schema_version": OWNER_PREFLIGHT_SCHEMA,
        "contract_role": OWNER_ROLE,
        "status": "OWNER_PREVIEW_ONLY",
        "decision": "CAS_RECHECK_REQUIRED",
        "reason": "OWNER_STATE_MATCHED",
        "replay_status": "OWNER_OBSERVED_NOT_ADVANCED",
        "authoritative_decision": False,
        "transaction_id": context["transaction_id"],
        "idempotency_key": parsed_request["idempotency_key"],
        "owner_id": payload["owner_id"],
        "owner_instance_id": payload["owner_instance_id"],
        "owner_observation_sha256": owner["observation_sha256"],
        "owner_envelope_sha256": owner["envelope_sha256"],
        "owner_head_sha256": payload["head_sha256"],
        "owner_state_version": payload["state_version"],
        "owner_fencing_epoch": payload["fencing_epoch"],
        "worker_authorization_sha256": context["worker_authorization_sha256"],
        "worker_attestation_set_sha256": context["next_head_sha256"],
        "s16_replay_observation_sha256": context["s16_replay_observation_sha256"],
        "s16_replay_floor_sha256": context["s16_replay_floor_sha256"],
        "candidate": candidate,
        "preflight_sha256": preflight_sha256,
        "owner_state_status": "CLEAN",
        "idempotency_status": "UNRESOLVED_REQUIRES_OWNER_CAS",
        "owner_cas_required": True,
        "owner_state_advanced": False,
        "idempotency_reserved": False,
        "permission": "read_only",
        "external_action": False,
        "mutation_allowed": False,
        "cas_authorized": False,
        "consume_allowed": False,
        "recovery_allowed": False,
        "resume_allowed": False,
        "execution": dict(_EXECUTION_FALSE),
    }


def _actionless_result(status: str, reason: str) -> dict[str, Any]:
    return {
        "schema_version": OWNER_PREFLIGHT_SCHEMA,
        "contract_role": OWNER_ROLE,
        "status": status,
        "decision": status,
        "reason": reason,
        "replay_status": "HOLD",
        "authoritative_decision": False,
        "owner_state_status": "HOLD",
        "idempotency_status": "UNRESOLVED",
        "owner_cas_required": False,
        "owner_state_advanced": False,
        "idempotency_reserved": False,
        "permission": "read_only",
        "external_action": False,
        "mutation_allowed": False,
        "cas_authorized": False,
        "consume_allowed": False,
        "recovery_allowed": False,
        "resume_allowed": False,
        "execution": dict(_EXECUTION_FALSE),
    }


def evaluate_replay_owner_preflight(**kwargs: Any) -> dict[str, Any]:
    """Convert every untrusted owner-preflight input into an actionless result."""

    try:
        return verify_replay_owner_preflight(**kwargs)
    except CrossStoreOwnerError as exc:
        status = "RECOVERY_REQUIRED" if exc.code in {"OWNER_ACTIVE_TRANSACTION", "OWNER_JOURNAL_NOT_CLEAN", "OWNER_RECOVERY_REQUIRED"} else "HOLD"
        return _actionless_result(status, exc.code)
    except (AttributeError, KeyError, TypeError, ValueError):
        return _actionless_result("HOLD", "OWNER_SCHEMA_INVALID")


__all__ = [
    "CrossStoreOwnerError",
    "OWNER_AUTHORITY_PREFIX",
    "OWNER_ERROR_CODES",
    "OWNER_HEAD_SCHEMA",
    "OWNER_OBSERVATION_SCHEMA",
    "OWNER_OPERATION",
    "OWNER_PREFLIGHT_SCHEMA",
    "OWNER_PROTOCOL",
    "OWNER_ROLE",
    "OWNER_REQUEST_SCHEMA",
    "OWNER_STATE_SCHEMA",
    "configure_trusted_owner_authority",
    "evaluate_replay_owner_preflight",
    "freeze_trusted_owner_authorities",
    "parse_owner_observation",
    "verify_replay_owner_preflight",
]
