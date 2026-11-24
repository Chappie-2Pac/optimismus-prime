"""W5-S16 read-only adapter-worker, host and replay-attestation gate.

S16 is the pure boundary after W5-S15 and before the S14 producer.  It
consumes five already-serialised worker claims, one independently signed
host/runtime claim, one signed replay-head observation and one separately
signed replay floor.  Every claim is bound to the same frozen S15
authorisation, transaction, observer, source profiles, cohort, host/runtime
binding and replay epoch.

The module does not discover a host, inspect a runtime, open a source, start
a worker, persist replay state, perform a CAS/consume operation or grant an
execution capability.  A valid MAC is evidence of an external claim only;
it is not proof that an operating system, kernel, sandbox or Python callback
actually enforced the claimed read-only policy.  A valid replay observation
is checked against an external floor but is never advanced here.  Two
concurrent callers presenting the same externally valid snapshot can
therefore both pass this pure boundary until a later owner performs an
atomic consume/CAS operation.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json

from .cross_store_attestation import (
    S14_CAPTURE_KEYS,
    CrossStoreAttestationError,
    evaluate_attested_cross_store_capture,
    verify_cross_store_source_attestation,
)
from .cross_store_snapshot import SNAPSHOT_PARTICIPANT_IDS


WORKER_ATTESTATION_SCHEMA = "prime-cross-store-worker-attestation-v1"
HOST_RUNTIME_ATTESTATION_SCHEMA = "prime-cross-store-host-runtime-attestation-v1"
REPLAY_OBSERVATION_SCHEMA = "prime-cross-store-replay-observation-v1"
REPLAY_FLOOR_SCHEMA = "prime-cross-store-replay-floor-v1"
WORKER_ATTESTATION_VERIFICATION_SCHEMA = "prime-cross-store-worker-attestation-verification-v1"
WORKER_ATTESTATION_ROLE = "cross_store_worker_host_attestation_gate_read_only"
WORKER_ATTESTATION_PROTOCOL = "hmac-sha256-canonical-json-v1"
WORKER_ATTESTATION_AUTHORITY_PREFIX = "source-worker-attestation-"
HOST_RUNTIME_ATTESTATION_AUTHORITY_PREFIX = "source-host-attestation-"
REPLAY_OBSERVATION_AUTHORITY_PREFIX = "source-replay-observation-"
REPLAY_FLOOR_AUTHORITY_PREFIX = "source-replay-floor-"
WORKER_AUTHORIZATION_SCHEMA = "prime-cross-store-worker-authorization-v1"
GATE_BINDING_SCHEMA = "prime-cross-store-worker-host-binding-v1"

SIGNED_ENVELOPE_KEYS = frozenset(
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
COMMON_BINDING_KEYS = frozenset(
    {
        "transaction_id",
        "observer_sha256",
        "authorization_sha256",
        "registry_id",
        "registry_version",
        "registry_sha256",
        "profile_set_sha256",
        "source_set_sha256",
        "cohort_binding_sha256",
        "host_id",
        "host_instance_id",
        "replay_namespace",
        "gate_nonce_sha256",
        "attestation_sequence",
        "registry_epoch",
        "evidence_epoch",
        "floor_epoch",
        "worker_epoch",
        "previous_attestation_set_sha256",
    }
)
WORKER_PAYLOAD_KEYS = frozenset(
    {
        *COMMON_BINDING_KEYS,
        "participant_id",
        "adapter_id",
        "adapter_instance_id",
        "allowed_root_or_binding",
        "worker_id",
        "worker_epoch",
        "runtime_id",
        "host_binding_sha256",
        "runtime_binding_sha256",
        "adapter_code_sha256",
        "source_binding_sha256",
        "source_identity_sha256",
        "profile_sha256",
        "execution_mode",
        "read_only",
        "read_only_capability",
        "write_capability",
        "lock_capability",
        "network_capability",
        "process_capability",
        "replay_observation_sha256",
        "attestation_nonce",
        "attestation_set_sha256",
        "gate_binding_sha256",
        "state_floor_sha256",
    }
)
RUNTIME_BINDING_KEYS = frozenset(
    {
        "participant_id",
        "host_id",
        "host_instance_id",
        "runtime_id",
        "runtime_policy_sha256",
        "runtime_build_sha256",
        "read_only_capability",
        "write_capability",
        "lock_capability",
        "network_capability",
        "process_capability",
        "runtime_binding_sha256",
    }
)
HOST_POLICY_KEYS = frozenset(
    {
        "policy_id",
        "read_only_capability",
        "write_capability",
        "lock_capability",
        "network_capability",
        "process_capability",
    }
)
HOST_PAYLOAD_KEYS = frozenset(
    {
        *COMMON_BINDING_KEYS,
        "replay_observation_sha256",
        "attestation_nonce",
        "host_binding_sha256",
        "host_policy",
        "host_policy_sha256",
        "runtime_bindings",
        "runtime_set_sha256",
        "gate_binding_sha256",
        "state_floor_sha256",
    }
)
REPLAY_PAYLOAD_KEYS = frozenset(
    {
        "observation_id",
        "transaction_id",
        "observer_sha256",
        "authorization_sha256",
        "registry_id",
        "registry_version",
        "registry_sha256",
        "registry_epoch",
        "profile_set_sha256",
        "source_set_sha256",
        "cohort_binding_sha256",
        "host_id",
        "host_instance_id",
        "replay_namespace",
        "gate_nonce_sha256",
        "gate_binding_sha256",
        "evidence_epoch",
        "floor_epoch",
        "worker_epoch",
        "state_floor_sha256",
        "attestation_sequence",
        "previous_attestation_set_sha256",
        "scope_sha256",
        "last_accepted_sequence",
        "last_accepted_attestation_set_sha256",
        "last_accepted_nonce_sha256",
        "observation_sequence",
        "replay_head_sha256",
    }
)
REPLAY_FLOOR_PAYLOAD_KEYS = frozenset(
    {
        "floor_id",
        "registry_id",
        "registry_version",
        "registry_sha256",
        "registry_epoch",
        "profile_set_sha256",
        "source_set_sha256",
        "cohort_binding_sha256",
        "replay_namespace",
        "scope_sha256",
        "floor_epoch",
        "worker_epoch",
        "last_accepted_sequence",
        "last_accepted_attestation_set_sha256",
        "last_accepted_nonce_sha256",
        "replay_head_sha256",
        "floor_sha256",
    }
)
S15_INPUT_KEYS = frozenset(
    {
        "source_profiles",
        "attestation",
        "trust_registry",
        "cohort_binding",
        "s14_input",
    }
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EXECUTION_FALSE = {"mutation": False, "network": False, "reconcile": False, "resume": False}
_PARTICIPANTS = tuple(sorted(SNAPSHOT_PARTICIPANT_IDS))

WORKER_ATTESTATION_ERROR_CODES = frozenset(
    {
        "WORKER_ATTESTATION_NOT_OBSERVED",
        "WORKER_ATTESTATION_SCHEMA_INVALID",
        "WORKER_ATTESTATION_TRUST_ROOT_NOT_FROZEN",
        "WORKER_ATTESTATION_TRUST_ROOT_UNKNOWN",
        "WORKER_ATTESTATION_SIGNATURE_INVALID",
        "WORKER_ATTESTATION_PAYLOAD_INVALID",
        "WORKER_ATTESTATION_PROFILE_MISMATCH",
        "WORKER_ATTESTATION_TRANSACTION_MISMATCH",
        "WORKER_ATTESTATION_OBSERVER_MISMATCH",
        "WORKER_ATTESTATION_SOURCE_MISMATCH",
        "WORKER_ATTESTATION_COHORT_MISMATCH",
        "WORKER_ATTESTATION_RUNTIME_UNSAFE",
        "WORKER_ATTESTATION_HOST_INVALID",
        "WORKER_ATTESTATION_SET_MISMATCH",
        "WORKER_ATTESTATION_REPLAY_OBSERVATION_INVALID",
        "WORKER_ATTESTATION_REPLAY_FLOOR_INVALID",
        "WORKER_ATTESTATION_REPLAY_SCOPE_MISMATCH",
        "WORKER_ATTESTATION_REPLAY_OR_DOWNGRADE",
        "WORKER_ATTESTATION_NONCE_REUSE",
        "WORKER_ATTESTATION_EPOCH_DOWNGRADE",
        "WORKER_ATTESTATION_BINDING_MISMATCH",
        "WORKER_ATTESTATION_S15_INVALID",
    }
)


class CrossStoreWorkerAttestationError(ValueError):
    """An S16 worker/host/replay claim failed closed without a side effect."""

    def __init__(self, code: str, message: str) -> None:
        if code not in WORKER_ATTESTATION_ERROR_CODES:
            raise ValueError(f"unknown S16 worker-attestation code: {code}")
        self.code = code
        super().__init__(f"{code}: {message}")


_TRUSTED_WORKER_KEYS: dict[tuple[str, str], bytes] = {}
_TRUSTED_HOST_KEYS: dict[tuple[str, str], bytes] = {}
_TRUSTED_REPLAY_KEYS: dict[tuple[str, str], bytes] = {}
_TRUSTED_FLOOR_KEYS: dict[tuple[str, str], bytes] = {}
_WORKER_TRUST_ROOT_FROZEN = False
_HOST_TRUST_ROOT_FROZEN = False
_REPLAY_TRUST_ROOT_FROZEN = False
_FLOOR_TRUST_ROOT_FROZEN = False


def _configure_key(
    registry: dict[tuple[str, str], bytes],
    frozen: bool,
    *,
    authority_id: str,
    key_id: str,
    key: bytes,
    prefix: str,
    label: str,
) -> None:
    if (
        not isinstance(authority_id, str)
        or _SAFE_ID.fullmatch(authority_id) is None
        or not authority_id.startswith(prefix)
        or not isinstance(key_id, str)
        or _SAFE_ID.fullmatch(key_id) is None
        or not key_id.startswith(prefix)
    ):
        raise ValueError(f"{label} authority and key IDs must use the {prefix} scope")
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError(f"{label} trust key must contain at least 16 bytes")
    identity = (authority_id, key_id)
    if frozen:
        if registry.get(identity) == key:
            return
        raise RuntimeError(f"{label} trust root is frozen")
    existing = registry.get(identity)
    if existing is not None and existing != key:
        raise RuntimeError(f"{label} trust key reconfiguration rejected")
    registry[identity] = bytes(key)


def configure_trusted_worker_authority(*, authority_id: str, key_id: str, key: bytes) -> None:
    """Configure one worker-attestation key before the worker root is frozen."""

    _configure_key(
        _TRUSTED_WORKER_KEYS,
        _WORKER_TRUST_ROOT_FROZEN,
        authority_id=authority_id,
        key_id=key_id,
        key=key,
        prefix=WORKER_ATTESTATION_AUTHORITY_PREFIX,
        label="S16 worker",
    )


def configure_trusted_host_authority(*, authority_id: str, key_id: str, key: bytes) -> None:
    """Configure one independent host/runtime key before the host root freezes."""

    _configure_key(
        _TRUSTED_HOST_KEYS,
        _HOST_TRUST_ROOT_FROZEN,
        authority_id=authority_id,
        key_id=key_id,
        key=key,
        prefix=HOST_RUNTIME_ATTESTATION_AUTHORITY_PREFIX,
        label="S16 host",
    )


def configure_trusted_replay_authority(*, authority_id: str, key_id: str, key: bytes) -> None:
    """Configure one replay-observation key before the replay root freezes."""

    _configure_key(
        _TRUSTED_REPLAY_KEYS,
        _REPLAY_TRUST_ROOT_FROZEN,
        authority_id=authority_id,
        key_id=key_id,
        key=key,
        prefix=REPLAY_OBSERVATION_AUTHORITY_PREFIX,
        label="S16 replay",
    )


def configure_trusted_replay_floor_authority(*, authority_id: str, key_id: str, key: bytes) -> None:
    """Configure the independent replay-floor key before its root freezes."""

    _configure_key(
        _TRUSTED_FLOOR_KEYS,
        _FLOOR_TRUST_ROOT_FROZEN,
        authority_id=authority_id,
        key_id=key_id,
        key=key,
        prefix=REPLAY_FLOOR_AUTHORITY_PREFIX,
        label="S16 replay floor",
    )


def freeze_trusted_worker_authorities() -> None:
    """Freeze worker-attestation trust material before verification."""

    global _WORKER_TRUST_ROOT_FROZEN
    _WORKER_TRUST_ROOT_FROZEN = True


def freeze_trusted_host_authorities() -> None:
    """Freeze host/runtime trust material before verification."""

    global _HOST_TRUST_ROOT_FROZEN
    _HOST_TRUST_ROOT_FROZEN = True


def freeze_trusted_replay_authorities() -> None:
    """Freeze replay-observation trust material before verification."""

    global _REPLAY_TRUST_ROOT_FROZEN
    _REPLAY_TRUST_ROOT_FROZEN = True


def freeze_trusted_replay_floor_authorities() -> None:
    """Freeze independent replay-floor trust material before verification."""

    global _FLOOR_TRUST_ROOT_FROZEN
    _FLOOR_TRUST_ROOT_FROZEN = True


def _resolve_key(*, authority_id: str, key_id: str, kind: str) -> bytes:
    if kind == "worker":
        frozen, registry = _WORKER_TRUST_ROOT_FROZEN, _TRUSTED_WORKER_KEYS
    elif kind == "host":
        frozen, registry = _HOST_TRUST_ROOT_FROZEN, _TRUSTED_HOST_KEYS
    elif kind == "replay":
        frozen, registry = _REPLAY_TRUST_ROOT_FROZEN, _TRUSTED_REPLAY_KEYS
    elif kind == "floor":
        frozen, registry = _FLOOR_TRUST_ROOT_FROZEN, _TRUSTED_FLOOR_KEYS
    else:
        raise ValueError(f"unknown S16 trust kind: {kind}")
    if not frozen:
        raise CrossStoreWorkerAttestationError(
            "WORKER_ATTESTATION_TRUST_ROOT_NOT_FROZEN", f"S16 {kind} trust root is not frozen"
        )
    key = registry.get((authority_id, key_id))
    if key is None:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_TRUST_ROOT_UNKNOWN", "S16 authority/key is unknown")
    return key


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _optional_hash64(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _hash64(value, label)


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SCHEMA_INVALID", f"{label} must be an integer >= 0")
    return value


def _positive_integer(value: Any, label: str) -> int:
    value = _integer(value, label)
    if value == 0:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SCHEMA_INVALID", f"{label} must be greater than zero")
    return value


def _digest(value: Any, label: str) -> str:
    try:
        return canonical_hash(value)
    except Exception as exc:
        raise CrossStoreWorkerAttestationError(
            "WORKER_ATTESTATION_SCHEMA_INVALID", f"{label} is not canonical JSON"
        ) from exc


def _mac_core(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: envelope[key]
        for key in (
            "schema_version",
            "attestation_id",
            "authority_id",
            "key_id",
            "protocol",
            "payload",
            "payload_sha256",
        )
    }


def _schema_for_kind(kind: str) -> str:
    return {
        "worker": WORKER_ATTESTATION_SCHEMA,
        "host": HOST_RUNTIME_ATTESTATION_SCHEMA,
        "replay": REPLAY_OBSERVATION_SCHEMA,
        "floor": REPLAY_FLOOR_SCHEMA,
    }[kind]


def _payload_keys_for_kind(kind: str) -> frozenset[str]:
    return {
        "worker": WORKER_PAYLOAD_KEYS,
        "host": HOST_PAYLOAD_KEYS,
        "replay": REPLAY_PAYLOAD_KEYS,
        "floor": REPLAY_FLOOR_PAYLOAD_KEYS,
    }[kind]


def _validate_signed_envelope(value: Any, *, kind: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != SIGNED_ENVELOPE_KEYS:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SCHEMA_INVALID", f"{kind} signed envelope keys are not exact")
    expected_schema = _schema_for_kind(kind)
    if value["schema_version"] != expected_schema or value["protocol"] != WORKER_ATTESTATION_PROTOCOL:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SCHEMA_INVALID", f"{kind} schema/protocol is unsupported")
    attestation_id = _safe_id(value["attestation_id"], f"{kind}.attestation_id")
    authority_id = _safe_id(value["authority_id"], f"{kind}.authority_id")
    key_id = _safe_id(value["key_id"], f"{kind}.key_id")
    payload = value["payload"]
    expected_keys = _payload_keys_for_kind(kind)
    if not isinstance(payload, Mapping) or set(payload) != expected_keys:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_PAYLOAD_INVALID", f"{kind} payload keys are not exact")
    try:
        payload_digest = canonical_hash(dict(payload))
    except Exception as exc:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_PAYLOAD_INVALID", f"{kind} payload is not canonical JSON") from exc
    if _hash64(value["payload_sha256"], f"{kind}.payload_sha256") != payload_digest:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_PAYLOAD_INVALID", f"{kind} payload digest differs")
    authority_mac = _hash64(value["authority_mac"], f"{kind}.authority_mac")
    key = _resolve_key(
        authority_id=authority_id,
        key_id=key_id,
        kind="worker" if kind == "worker" else "host" if kind == "host" else "floor" if kind == "floor" else "replay",
    )
    expected_mac = hmac.new(key, canonical_json(_mac_core(value)).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(authority_mac, expected_mac):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SIGNATURE_INVALID", f"{kind} envelope MAC does not match")
    return {
        "schema_version": expected_schema,
        "attestation_id": attestation_id,
        "authority_id": authority_id,
        "key_id": key_id,
        "protocol": WORKER_ATTESTATION_PROTOCOL,
        "payload": dict(payload),
        "payload_sha256": value["payload_sha256"],
        "authority_mac": authority_mac,
    }


def _validate_common_fields(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    return {
        "transaction_id": _safe_id(value["transaction_id"], f"{label}.transaction_id"),
        "observer_sha256": _hash64(value["observer_sha256"], f"{label}.observer_sha256"),
        "authorization_sha256": _hash64(value["authorization_sha256"], f"{label}.authorization_sha256"),
        "registry_id": _safe_id(value["registry_id"], f"{label}.registry_id"),
        "registry_version": _safe_id(value["registry_version"], f"{label}.registry_version"),
        "registry_sha256": _hash64(value["registry_sha256"], f"{label}.registry_sha256"),
        "profile_set_sha256": _hash64(value["profile_set_sha256"], f"{label}.profile_set_sha256"),
        "source_set_sha256": _hash64(value["source_set_sha256"], f"{label}.source_set_sha256"),
        "cohort_binding_sha256": _hash64(value["cohort_binding_sha256"], f"{label}.cohort_binding_sha256"),
        "host_id": _safe_id(value["host_id"], f"{label}.host_id"),
        "host_instance_id": _safe_id(value["host_instance_id"], f"{label}.host_instance_id"),
        "replay_namespace": _safe_id(value["replay_namespace"], f"{label}.replay_namespace"),
        "gate_nonce_sha256": _hash64(value["gate_nonce_sha256"], f"{label}.gate_nonce_sha256"),
        "attestation_sequence": _positive_integer(value["attestation_sequence"], f"{label}.attestation_sequence"),
        "registry_epoch": _integer(value["registry_epoch"], f"{label}.registry_epoch"),
        "evidence_epoch": _positive_integer(value["evidence_epoch"], f"{label}.evidence_epoch"),
        "floor_epoch": _positive_integer(value["floor_epoch"], f"{label}.floor_epoch"),
        "worker_epoch": _positive_integer(value["worker_epoch"], f"{label}.worker_epoch"),
        "previous_attestation_set_sha256": _optional_hash64(
            value["previous_attestation_set_sha256"], f"{label}.previous_attestation_set_sha256"
        ),
    }


def _validate_worker_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    if value["execution_mode"] != "ISOLATED_READ_ONLY" or value["read_only"] is not True or value["read_only_capability"] is not True or any(
        value[key] is not False for key in ("write_capability", "lock_capability", "network_capability", "process_capability")
    ):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_RUNTIME_UNSAFE", "worker runtime is not strictly read-only")
    return {
        **_validate_common_fields(value, "worker"),
        "participant_id": _safe_id(value["participant_id"], "worker.participant_id"),
        "adapter_id": _safe_id(value["adapter_id"], "worker.adapter_id"),
        "adapter_instance_id": _safe_id(value["adapter_instance_id"], "worker.adapter_instance_id"),
        "allowed_root_or_binding": _safe_id(value["allowed_root_or_binding"], "worker.allowed_root_or_binding"),
        "worker_id": _safe_id(value["worker_id"], "worker.worker_id"),
        "runtime_id": _safe_id(value["runtime_id"], "worker.runtime_id"),
        "host_binding_sha256": _hash64(value["host_binding_sha256"], "worker.host_binding_sha256"),
        "runtime_binding_sha256": _hash64(value["runtime_binding_sha256"], "worker.runtime_binding_sha256"),
        "adapter_code_sha256": _hash64(value["adapter_code_sha256"], "worker.adapter_code_sha256"),
        "source_binding_sha256": _hash64(value["source_binding_sha256"], "worker.source_binding_sha256"),
        "source_identity_sha256": _hash64(value["source_identity_sha256"], "worker.source_identity_sha256"),
        "profile_sha256": _hash64(value["profile_sha256"], "worker.profile_sha256"),
        "execution_mode": "ISOLATED_READ_ONLY",
        "read_only": True,
        "read_only_capability": True,
        "write_capability": False,
        "lock_capability": False,
        "network_capability": False,
        "process_capability": False,
        "replay_observation_sha256": _hash64(value["replay_observation_sha256"], "worker.replay_observation_sha256"),
        "attestation_nonce": _safe_id(value["attestation_nonce"], "worker.attestation_nonce"),
        "attestation_set_sha256": _hash64(value["attestation_set_sha256"], "worker.attestation_set_sha256"),
        "gate_binding_sha256": _hash64(value["gate_binding_sha256"], "worker.gate_binding_sha256"),
        "state_floor_sha256": _hash64(value["state_floor_sha256"], "worker.state_floor_sha256"),
    }


def _validate_host_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != HOST_POLICY_KEYS:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_HOST_INVALID", "host policy keys are not exact")
    normalized = {
        "policy_id": _safe_id(value["policy_id"], "host_policy.policy_id"),
        "read_only_capability": value["read_only_capability"],
        "write_capability": value["write_capability"],
        "lock_capability": value["lock_capability"],
        "network_capability": value["network_capability"],
        "process_capability": value["process_capability"],
    }
    if normalized["read_only_capability"] is not True or any(
        normalized[key] is not False for key in ("write_capability", "lock_capability", "network_capability", "process_capability")
    ):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_RUNTIME_UNSAFE", "host policy is not strictly read-only")
    return normalized


def _validate_runtime_binding(value: Any, participant_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != RUNTIME_BINDING_KEYS:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_HOST_INVALID", f"runtime {participant_id} keys are not exact")
    normalized = {
        "participant_id": _safe_id(value["participant_id"], f"runtime.{participant_id}.participant_id"),
        "host_id": _safe_id(value["host_id"], f"runtime.{participant_id}.host_id"),
        "host_instance_id": _safe_id(value["host_instance_id"], f"runtime.{participant_id}.host_instance_id"),
        "runtime_id": _safe_id(value["runtime_id"], f"runtime.{participant_id}.runtime_id"),
        "runtime_policy_sha256": _hash64(value["runtime_policy_sha256"], f"runtime.{participant_id}.runtime_policy_sha256"),
        "runtime_build_sha256": _hash64(value["runtime_build_sha256"], f"runtime.{participant_id}.runtime_build_sha256"),
        "read_only_capability": value["read_only_capability"],
        "write_capability": value["write_capability"],
        "lock_capability": value["lock_capability"],
        "network_capability": value["network_capability"],
        "process_capability": value["process_capability"],
        "runtime_binding_sha256": _hash64(value["runtime_binding_sha256"], f"runtime.{participant_id}.runtime_binding_sha256"),
    }
    if normalized["participant_id"] != participant_id:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SET_MISMATCH", f"runtime {participant_id} participant differs")
    if normalized["read_only_capability"] is not True or any(
        normalized[key] is not False for key in ("write_capability", "lock_capability", "network_capability", "process_capability")
    ):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_RUNTIME_UNSAFE", f"runtime {participant_id} is not read-only")
    core = {key: normalized[key] for key in sorted(RUNTIME_BINDING_KEYS - {"runtime_binding_sha256"})}
    if normalized["runtime_binding_sha256"] != _digest(core, f"runtime.{participant_id}.binding"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_HOST_INVALID", f"runtime {participant_id} binding digest differs")
    return normalized


def _runtime_set_digest(runtime_bindings: Mapping[str, Mapping[str, Any]]) -> str:
    return _digest(
        {
            participant_id: {
                key: runtime_bindings[participant_id][key]
                for key in sorted(RUNTIME_BINDING_KEYS - {"runtime_binding_sha256"})
            }
            for participant_id in _PARTICIPANTS
        },
        "runtime set",
    )


def _validate_host_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    common = _validate_common_fields(value, "host")
    policy = _validate_host_policy(value["host_policy"])
    if _hash64(value["host_policy_sha256"], "host.host_policy_sha256") != _digest(policy, "host policy"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_HOST_INVALID", "host policy digest differs")
    runtime_values = value["runtime_bindings"]
    if not isinstance(runtime_values, Mapping) or set(runtime_values) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_HOST_INVALID", "runtime participant set is not exact")
    runtime_bindings = {
        participant_id: _validate_runtime_binding(runtime_values[participant_id], participant_id)
        for participant_id in _PARTICIPANTS
    }
    runtime_set_sha256 = _hash64(value["runtime_set_sha256"], "host.runtime_set_sha256")
    if runtime_set_sha256 != _runtime_set_digest(runtime_bindings):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_HOST_INVALID", "runtime set digest differs")
    normalized = {
        **common,
        "replay_observation_sha256": _hash64(value["replay_observation_sha256"], "host.replay_observation_sha256"),
        "attestation_nonce": _safe_id(value["attestation_nonce"], "host.attestation_nonce"),
        "host_binding_sha256": _hash64(value["host_binding_sha256"], "host.host_binding_sha256"),
        "host_policy": policy,
        "host_policy_sha256": _hash64(value["host_policy_sha256"], "host.host_policy_sha256"),
        "runtime_bindings": runtime_bindings,
        "runtime_set_sha256": runtime_set_sha256,
        "gate_binding_sha256": _hash64(value["gate_binding_sha256"], "host.gate_binding_sha256"),
        "state_floor_sha256": _hash64(value["state_floor_sha256"], "host.state_floor_sha256"),
    }
    host_core = {key: normalized[key] for key in sorted(HOST_PAYLOAD_KEYS - {"host_binding_sha256"})}
    if normalized["host_binding_sha256"] != _digest(host_core, "host binding"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_HOST_INVALID", "host binding digest differs")
    if _digest(normalized["attestation_nonce"], "host nonce") != normalized["gate_nonce_sha256"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "host nonce binding differs")
    return normalized


def _validate_replay_head_fields(
    value: Mapping[str, Any],
    *,
    label: str,
) -> tuple[int, str | None, str | None]:
    last_sequence = _integer(value["last_accepted_sequence"], f"{label}.last_accepted_sequence")
    last_set = _optional_hash64(value["last_accepted_attestation_set_sha256"], f"{label}.last_accepted_attestation_set_sha256")
    last_nonce = _optional_hash64(value["last_accepted_nonce_sha256"], f"{label}.last_accepted_nonce_sha256")
    if last_sequence == 0 and (last_set is not None or last_nonce is not None):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_OBSERVATION_INVALID", f"{label} empty replay head has accepted material")
    if last_sequence > 0 and (last_set is None or last_nonce is None):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_OBSERVATION_INVALID", f"{label} replay head lacks accepted material")
    return last_sequence, last_set, last_nonce


def _scope_core(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in (
            "registry_id",
            "registry_version",
            "registry_sha256",
            "profile_set_sha256",
            "source_set_sha256",
            "cohort_binding_sha256",
            "replay_namespace",
        )
    }


def _validate_replay_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    last_sequence, last_set, last_nonce = _validate_replay_head_fields(value, label="replay")
    core = {
        "observation_id": _safe_id(value["observation_id"], "replay.observation_id"),
        "transaction_id": _safe_id(value["transaction_id"], "replay.transaction_id"),
        "observer_sha256": _hash64(value["observer_sha256"], "replay.observer_sha256"),
        "authorization_sha256": _hash64(value["authorization_sha256"], "replay.authorization_sha256"),
        "registry_id": _safe_id(value["registry_id"], "replay.registry_id"),
        "registry_version": _safe_id(value["registry_version"], "replay.registry_version"),
        "registry_sha256": _hash64(value["registry_sha256"], "replay.registry_sha256"),
        "registry_epoch": _integer(value["registry_epoch"], "replay.registry_epoch"),
        "profile_set_sha256": _hash64(value["profile_set_sha256"], "replay.profile_set_sha256"),
        "source_set_sha256": _hash64(value["source_set_sha256"], "replay.source_set_sha256"),
        "cohort_binding_sha256": _hash64(value["cohort_binding_sha256"], "replay.cohort_binding_sha256"),
        "host_id": _safe_id(value["host_id"], "replay.host_id"),
        "host_instance_id": _safe_id(value["host_instance_id"], "replay.host_instance_id"),
        "replay_namespace": _safe_id(value["replay_namespace"], "replay.replay_namespace"),
        "gate_nonce_sha256": _hash64(value["gate_nonce_sha256"], "replay.gate_nonce_sha256"),
        "gate_binding_sha256": _hash64(value["gate_binding_sha256"], "replay.gate_binding_sha256"),
        "evidence_epoch": _positive_integer(value["evidence_epoch"], "replay.evidence_epoch"),
        "floor_epoch": _positive_integer(value["floor_epoch"], "replay.floor_epoch"),
        "worker_epoch": _positive_integer(value["worker_epoch"], "replay.worker_epoch"),
        "state_floor_sha256": _hash64(value["state_floor_sha256"], "replay.state_floor_sha256"),
        "attestation_sequence": _positive_integer(value["attestation_sequence"], "replay.attestation_sequence"),
        "previous_attestation_set_sha256": _optional_hash64(
            value["previous_attestation_set_sha256"], "replay.previous_attestation_set_sha256"
        ),
        "scope_sha256": _hash64(value["scope_sha256"], "replay.scope_sha256"),
        "last_accepted_sequence": last_sequence,
        "last_accepted_attestation_set_sha256": last_set,
        "last_accepted_nonce_sha256": last_nonce,
        "observation_sequence": _positive_integer(value["observation_sequence"], "replay.observation_sequence"),
        "replay_head_sha256": _hash64(value["replay_head_sha256"], "replay.replay_head_sha256"),
    }
    if core["scope_sha256"] != _digest(_scope_core(core), "replay scope"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_SCOPE_MISMATCH", "replay scope digest differs")
    replay_core = {key: core[key] for key in sorted(REPLAY_PAYLOAD_KEYS - {"replay_head_sha256"})}
    if core["replay_head_sha256"] != _digest(replay_core, "replay head"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_OBSERVATION_INVALID", "replay head digest differs")
    return core


def _validate_replay_floor_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    last_sequence, last_set, last_nonce = _validate_replay_head_fields(value, label="floor")
    core = {
        "floor_id": _safe_id(value["floor_id"], "floor.floor_id"),
        "registry_id": _safe_id(value["registry_id"], "floor.registry_id"),
        "registry_version": _safe_id(value["registry_version"], "floor.registry_version"),
        "registry_sha256": _hash64(value["registry_sha256"], "floor.registry_sha256"),
        "registry_epoch": _integer(value["registry_epoch"], "floor.registry_epoch"),
        "profile_set_sha256": _hash64(value["profile_set_sha256"], "floor.profile_set_sha256"),
        "source_set_sha256": _hash64(value["source_set_sha256"], "floor.source_set_sha256"),
        "cohort_binding_sha256": _hash64(value["cohort_binding_sha256"], "floor.cohort_binding_sha256"),
        "replay_namespace": _safe_id(value["replay_namespace"], "floor.replay_namespace"),
        "scope_sha256": _hash64(value["scope_sha256"], "floor.scope_sha256"),
        "floor_epoch": _positive_integer(value["floor_epoch"], "floor.floor_epoch"),
        "worker_epoch": _positive_integer(value["worker_epoch"], "floor.worker_epoch"),
        "last_accepted_sequence": last_sequence,
        "last_accepted_attestation_set_sha256": last_set,
        "last_accepted_nonce_sha256": last_nonce,
        "replay_head_sha256": _hash64(value["replay_head_sha256"], "floor.replay_head_sha256"),
    }
    if core["scope_sha256"] != _digest(_scope_core(core), "floor scope"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_FLOOR_INVALID", "floor scope digest differs")
    replay_core = {
        key: core[key]
        for key in (
            "registry_id",
            "registry_version",
            "registry_sha256",
            "profile_set_sha256",
            "source_set_sha256",
            "cohort_binding_sha256",
            "replay_namespace",
            "last_accepted_sequence",
            "last_accepted_attestation_set_sha256",
            "last_accepted_nonce_sha256",
        )
    }
    if core["replay_head_sha256"] != _digest(replay_core, "floor replay head"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_FLOOR_INVALID", "floor replay head digest differs")
    declared_floor = _hash64(value["floor_sha256"], "floor.floor_sha256")
    if declared_floor != _digest(core, "floor"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_FLOOR_INVALID", "floor digest differs")
    return {**core, "floor_sha256": declared_floor}


def _worker_set_digest(envelopes: Mapping[str, Mapping[str, Any]]) -> str:
    set_core: dict[str, Any] = {}
    for participant_id in _PARTICIPANTS:
        envelope = envelopes[participant_id]
        payload = envelope["payload"]
        set_core[participant_id] = {
            # The signed envelope identity is part of provenance.  Without
            # it, a newly signed claim could keep the same worker-set digest
            # and therefore the same downstream authorization/receipt hash.
            "attestation_id": envelope["attestation_id"],
            "authority_id": envelope["authority_id"],
            "key_id": envelope["key_id"],
            "protocol": envelope["protocol"],
            "payload": {key: payload[key] for key in sorted(WORKER_PAYLOAD_KEYS - {"attestation_set_sha256"})},
        }
    return _digest(set_core, "worker attestation set")


def _gate_binding_core(common: Mapping[str, Any]) -> dict[str, Any]:
    return {"schema_version": GATE_BINDING_SCHEMA, **{key: common[key] for key in sorted(COMMON_BINDING_KEYS)}}


def _validate_s16_input(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != S15_INPUT_KEYS:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_S15_INVALID", "S15 input keys are not exact")
    return value


def _snapshot_s15_input(value: Any) -> dict[str, Any]:
    """Copy static S15 material once while retaining only callback object refs."""

    value = _validate_s16_input(value)
    try:
        original_s14 = value["s14_input"]
        if not isinstance(original_s14, Mapping) or set(original_s14) != S14_CAPTURE_KEYS:
            raise ValueError("S14 input keys are not exact")
        static_s14: dict[str, Any] = {
            key: copy.deepcopy(original_s14[key])
            for key in sorted(S14_CAPTURE_KEYS - {"readers", "clock", "cohort"})
        }
        static_s14["readers"] = dict(original_s14["readers"])
        static_s14["clock"] = original_s14["clock"]
        static_s14["cohort"] = original_s14["cohort"]
        # Do not canonicalise the complete input: readers/clock/cohort are
        # deliberately external callback objects and never enter a digest.
        return {
            "source_profiles": copy.deepcopy(value["source_profiles"]),
            "attestation": copy.deepcopy(value["attestation"]),
            "trust_registry": copy.deepcopy(value["trust_registry"]),
            "cohort_binding": copy.deepcopy(value["cohort_binding"]),
            "s14_input": static_s14,
        }
    except CrossStoreWorkerAttestationError:
        raise
    except Exception as exc:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_S15_INVALID", "S15 input snapshot is not stable JSON") from exc


def _snapshot_serialized_evidence(value: Any, label: str) -> Any:
    """Freeze one externally serialised evidence object before any reads."""

    try:
        copied = copy.deepcopy(value)
        canonical_hash(copied)
        return copied
    except Exception as exc:
        raise CrossStoreWorkerAttestationError(
            "WORKER_ATTESTATION_SCHEMA_INVALID", f"{label} is not a stable serialised JSON object"
        ) from exc


def _verify_worker_host_attestation_snapshot(
    *,
    worker_attestations: Mapping[str, Mapping[str, Any]],
    replay_observation: Mapping[str, Any],
    replay_floor: Mapping[str, Any],
    host_runtime_attestation: Mapping[str, Any],
    s15_input: Mapping[str, Any],
) -> dict[str, Any]:
    """Internal pure verifier; the caller has already made the S15 snapshot."""

    try:
        s15_provenance = verify_cross_store_source_attestation(**dict(s15_input))
    except CrossStoreAttestationError as exc:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_S15_INVALID", exc.code) from exc
    except Exception as exc:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_S15_INVALID", "S15 provenance could not be verified") from exc

    if not isinstance(worker_attestations, Mapping) or set(worker_attestations) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SET_MISMATCH", "worker participant set is not exact")
    normalized_workers: dict[str, dict[str, Any]] = {}
    for participant_id in _PARTICIPANTS:
        envelope = _validate_signed_envelope(worker_attestations[participant_id], kind="worker")
        payload = _validate_worker_payload(envelope["payload"])
        if payload["participant_id"] != participant_id:
            raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SET_MISMATCH", f"worker participant {participant_id} differs")
        normalized_workers[participant_id] = {**envelope, "payload": payload}

    host_envelope = _validate_signed_envelope(host_runtime_attestation, kind="host")
    host_payload = _validate_host_payload(host_envelope["payload"])
    replay_envelope = _validate_signed_envelope(replay_observation, kind="replay")
    replay_payload = _validate_replay_payload(replay_envelope["payload"])
    floor_envelope = _validate_signed_envelope(replay_floor, kind="floor")
    floor_payload = _validate_replay_floor_payload(floor_envelope["payload"])
    normalized_host = {**host_envelope, "payload": host_payload}
    normalized_replay = {**replay_envelope, "payload": replay_payload}
    normalized_floor = {**floor_envelope, "payload": floor_payload}
    replay_observation_sha256 = _digest(normalized_replay, "replay observation")
    state_floor_sha256 = _digest(normalized_floor, "replay floor")

    transaction_id = _safe_id(s15_input["s14_input"]["transaction_id"], "transaction_id")
    observer_sha256 = _digest(s15_input["s14_input"]["observer"], "observer")
    expected_registry = {
        "registry_id": s15_provenance["registry_id"],
        "registry_version": s15_provenance["registry_version"],
        "registry_sha256": s15_provenance["registry_sha256"],
    }
    expected_scope = {
        **expected_registry,
        "profile_set_sha256": s15_provenance["profile_set_sha256"],
        "source_set_sha256": s15_provenance["source_set_sha256"],
        "cohort_binding_sha256": s15_provenance["cohort_binding_sha256"],
    }
    if any(replay_payload[key] != value for key, value in expected_scope.items()):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_SCOPE_MISMATCH", "replay scope differs from S15 provenance")
    if any(floor_payload[key] != value for key, value in expected_scope.items()):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_FLOOR_INVALID", "replay floor scope differs from S15 provenance")
    if replay_payload["state_floor_sha256"] != state_floor_sha256:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_FLOOR_INVALID", "replay observation does not name this floor")
    if replay_payload["floor_epoch"] != floor_payload["floor_epoch"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_EPOCH_DOWNGRADE", "replay floor epoch differs")
    if floor_payload["registry_epoch"] != replay_payload["registry_epoch"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_EPOCH_DOWNGRADE", "replay floor registry epoch differs")
    if floor_payload["worker_epoch"] != replay_payload["worker_epoch"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_EPOCH_DOWNGRADE", "replay floor worker epoch differs")
    for key in ("last_accepted_sequence", "last_accepted_attestation_set_sha256", "last_accepted_nonce_sha256"):
        if replay_payload[key] != floor_payload[key]:
            raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_FLOOR_INVALID", f"replay {key} differs from floor")

    authorization_sha256 = s15_provenance["authorization_sha256"]
    first = normalized_workers[_PARTICIPANTS[0]]["payload"]
    current_sequence = first["attestation_sequence"]
    current_epoch = first["registry_epoch"]
    current_nonce = first["attestation_nonce"]
    previous_set = first["previous_attestation_set_sha256"]
    s15_expected = {
        "transaction_id": transaction_id,
        "observer_sha256": observer_sha256,
        "authorization_sha256": authorization_sha256,
        **expected_registry,
        "profile_set_sha256": s15_provenance["profile_set_sha256"],
        "source_set_sha256": s15_provenance["source_set_sha256"],
        "cohort_binding_sha256": s15_provenance["cohort_binding_sha256"],
    }
    seen_instances: set[str] = set()
    seen_workers: set[str] = set()
    for participant_id in _PARTICIPANTS:
        payload = normalized_workers[participant_id]["payload"]
        for key, expected in s15_expected.items():
            if payload[key] != expected:
                code = "WORKER_ATTESTATION_TRANSACTION_MISMATCH" if key == "transaction_id" else "WORKER_ATTESTATION_OBSERVER_MISMATCH" if key == "observer_sha256" else "WORKER_ATTESTATION_COHORT_MISMATCH" if key == "cohort_binding_sha256" else "WORKER_ATTESTATION_BINDING_MISMATCH"
                raise CrossStoreWorkerAttestationError(code, f"worker {participant_id} differs at {key}")
        if payload["replay_observation_sha256"] != replay_observation_sha256 or payload["state_floor_sha256"] != state_floor_sha256:
            raise CrossStoreWorkerAttestationError(
                "WORKER_ATTESTATION_BINDING_MISMATCH",
                f"worker {participant_id} names a foreign replay/floor digest",
            )
        if any(payload[key] != first[key] for key in COMMON_BINDING_KEYS) or payload["attestation_nonce"] != current_nonce:
            raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SET_MISMATCH", f"worker set differs at common replay state ({participant_id})")
        if payload["adapter_instance_id"] in seen_instances or payload["worker_id"] in seen_workers:
            raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SET_MISMATCH", "worker or adapter instance is duplicated")
        seen_instances.add(payload["adapter_instance_id"])
        seen_workers.add(payload["worker_id"])
        profile = s15_provenance["profiles"][participant_id]
        source_identity = s15_input["s14_input"]["source_identities"][participant_id]
        expected_profile = {
            "adapter_id": profile["adapter_id"],
            "allowed_root_or_binding": profile["allowed_root_or_binding"],
            "adapter_code_sha256": profile["adapter_code_sha256"],
            "source_binding_sha256": profile["source_binding_sha256"],
            "profile_sha256": profile["profile_sha256"],
            "source_identity_sha256": _hash64(source_identity["source_identity_sha256"], f"source.{participant_id}.identity"),
        }
        for key, expected in expected_profile.items():
            if payload[key] != expected:
                raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_PROFILE_MISMATCH", f"worker {participant_id} differs at {key}")

    common_first = {key: first[key] for key in sorted(COMMON_BINDING_KEYS)}
    if first["gate_nonce_sha256"] != _digest(current_nonce, "worker nonce"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "worker nonce binding differs")
    if first["gate_binding_sha256"] != _digest(_gate_binding_core(common_first), "gate binding"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "worker gate binding differs")
    if any(normalized_workers[participant_id]["payload"]["gate_binding_sha256"] != first["gate_binding_sha256"] for participant_id in _PARTICIPANTS):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "worker gate bindings differ")

    if current_sequence != replay_payload["last_accepted_sequence"] + 1:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_OR_DOWNGRADE", "worker sequence is not the next external sequence")
    if previous_set != replay_payload["last_accepted_attestation_set_sha256"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_OR_DOWNGRADE", "worker parent does not match replay head")
    if _digest(current_nonce, "worker nonce") == replay_payload["last_accepted_nonce_sha256"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_NONCE_REUSE", "worker nonce was already accepted")
    if current_epoch < replay_payload["registry_epoch"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_EPOCH_DOWNGRADE", "worker registry epoch is older than replay head")
    if current_epoch == replay_payload["registry_epoch"] and replay_payload["registry_sha256"] != expected_registry["registry_sha256"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_REPLAY_SCOPE_MISMATCH", "registry changed without an epoch advance")

    for label, evidence in (("host", host_payload), ("replay", replay_payload)):
        for key in COMMON_BINDING_KEYS:
            if evidence[key] != first[key]:
                raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", f"{label} differs at {key}")
        for key, expected in s15_expected.items():
            if evidence[key] != expected:
                raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", f"{label} differs at {key}")
    if host_payload["attestation_nonce"] != current_nonce:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "host nonce differs")
    if host_payload["replay_observation_sha256"] != replay_observation_sha256:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "host replay observation differs")
    if host_payload["state_floor_sha256"] != state_floor_sha256 or host_payload["gate_binding_sha256"] != first["gate_binding_sha256"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "host common binding differs")
    if replay_payload["gate_binding_sha256"] != first["gate_binding_sha256"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "replay gate binding differs")

    host_common = {key: host_payload[key] for key in sorted(COMMON_BINDING_KEYS)}
    if host_payload["gate_binding_sha256"] != _digest(_gate_binding_core(host_common), "host gate binding"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "host gate binding digest differs")
    replay_common = {key: replay_payload[key] for key in sorted(COMMON_BINDING_KEYS)}
    if replay_payload["gate_binding_sha256"] != _digest(_gate_binding_core(replay_common), "replay gate binding"):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "replay gate binding digest differs")
    if host_payload["host_id"] != first["host_id"] or host_payload["host_instance_id"] != first["host_instance_id"]:
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", "worker host identity differs")

    for participant_id in _PARTICIPANTS:
        worker = normalized_workers[participant_id]["payload"]
        runtime = host_payload["runtime_bindings"][participant_id]
        if worker["host_binding_sha256"] != host_payload["host_binding_sha256"] or worker["runtime_id"] != runtime["runtime_id"] or worker["runtime_binding_sha256"] != runtime["runtime_binding_sha256"]:
            raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_BINDING_MISMATCH", f"worker/runtime binding differs for {participant_id}")
        if any(runtime[key] != worker[key] for key in ("host_id", "host_instance_id", "read_only_capability", "write_capability", "lock_capability", "network_capability", "process_capability")):
            raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_RUNTIME_UNSAFE", f"runtime/worker policy differs for {participant_id}")

    worker_set_sha256 = _worker_set_digest(normalized_workers)
    if any(normalized_workers[participant_id]["payload"]["attestation_set_sha256"] != worker_set_sha256 for participant_id in _PARTICIPANTS):
        raise CrossStoreWorkerAttestationError("WORKER_ATTESTATION_SET_MISMATCH", "worker set digest differs")

    authorization_core = {
        "schema_version": WORKER_AUTHORIZATION_SCHEMA,
        "s15_authorization_sha256": authorization_sha256,
        "replay_observation_sha256": replay_observation_sha256,
        "replay_floor_sha256": state_floor_sha256,
        "worker_attestation_set_sha256": worker_set_sha256,
        "host_binding_sha256": host_payload["host_binding_sha256"],
        "runtime_set_sha256": host_payload["runtime_set_sha256"],
        "gate_binding_sha256": first["gate_binding_sha256"],
        "attestation_sequence": current_sequence,
        "registry_epoch": current_epoch,
        "evidence_epoch": first["evidence_epoch"],
        "floor_epoch": first["floor_epoch"],
        "registry_sha256": expected_registry["registry_sha256"],
        "profile_set_sha256": s15_provenance["profile_set_sha256"],
        "source_set_sha256": s15_provenance["source_set_sha256"],
        "cohort_binding_sha256": s15_provenance["cohort_binding_sha256"],
        "bindings": {
            participant_id: {
                key: normalized_workers[participant_id]["payload"][key]
                for key in ("adapter_instance_id", "worker_id", "host_binding_sha256", "runtime_binding_sha256")
            }
            for participant_id in _PARTICIPANTS
        },
    }
    worker_authorization = {**authorization_core, "authorization_sha256": _digest(authorization_core, "worker authorization")}
    return {
        "schema_version": WORKER_ATTESTATION_SCHEMA,
        "worker_attestation_set_sha256": worker_set_sha256,
        "replay_observation_sha256": replay_observation_sha256,
        "replay_floor_sha256": state_floor_sha256,
        "attestation_sequence": current_sequence,
        "registry_epoch": current_epoch,
        "worker_attestations": normalized_workers,
        "host_runtime_attestation": normalized_host,
        "replay_observation": normalized_replay,
        "replay_floor": normalized_floor,
        "worker_authorization": worker_authorization,
        "worker_authorization_sha256": worker_authorization["authorization_sha256"],
        "read_only": True,
        "external_action": False,
    }


def verify_worker_host_attestation(
    *,
    worker_attestations: Mapping[str, Mapping[str, Any]],
    replay_observation: Mapping[str, Any],
    replay_floor: Mapping[str, Any],
    host_runtime_attestation: Mapping[str, Any],
    s15_input: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify S16 and S15 evidence without invoking S14 callbacks."""

    snapshot = _snapshot_s15_input(s15_input)
    return _verify_worker_host_attestation_snapshot(
        worker_attestations=_snapshot_serialized_evidence(worker_attestations, "worker attestations"),
        replay_observation=_snapshot_serialized_evidence(replay_observation, "replay observation"),
        replay_floor=_snapshot_serialized_evidence(replay_floor, "replay floor"),
        host_runtime_attestation=_snapshot_serialized_evidence(host_runtime_attestation, "host/runtime attestation"),
        s15_input=snapshot,
    )


def _actionless_result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    result = {
        "schema_version": WORKER_ATTESTATION_VERIFICATION_SCHEMA,
        "contract_role": WORKER_ATTESTATION_ROLE,
        "status": status,
        "reason": reason,
        "worker_provenance_status": "HOLD",
        "replay_status": "HOLD",
        "permission": "read_only",
        "external_action": False,
        "mutation_allowed": False,
        "authoritative_decision": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "execution": dict(_EXECUTION_FALSE),
    }
    result.update(extra)
    return result


def evaluate_worker_attested_cross_store_capture(
    *,
    worker_attestations: Mapping[str, Mapping[str, Any]],
    replay_observation: Mapping[str, Any],
    replay_floor: Mapping[str, Any],
    host_runtime_attestation: Mapping[str, Any],
    s15_input: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one immutable S16 snapshot, then invoke S15 exactly once."""

    try:
        snapshot = _snapshot_s15_input(s15_input)
        worker_proof = _verify_worker_host_attestation_snapshot(
            worker_attestations=_snapshot_serialized_evidence(worker_attestations, "worker attestations"),
            replay_observation=_snapshot_serialized_evidence(replay_observation, "replay observation"),
            replay_floor=_snapshot_serialized_evidence(replay_floor, "replay floor"),
            host_runtime_attestation=_snapshot_serialized_evidence(host_runtime_attestation, "host/runtime attestation"),
            s15_input=snapshot,
        )
    except CrossStoreWorkerAttestationError as exc:
        return _actionless_result("HOLD", exc.code)
    except Exception:
        return _actionless_result("HOLD", "WORKER_ATTESTATION_SCHEMA_INVALID")
    try:
        s15_result = evaluate_attested_cross_store_capture(**dict(snapshot))
    except Exception:
        return _actionless_result("HOLD", "WORKER_ATTESTATION_S15_INVALID")
    status = s15_result.get("status", "HOLD")
    reason = s15_result.get("reason", "WORKER_ATTESTATION_S15_INVALID")
    if status not in {"CAPTURED_READ_ONLY", "HOLD", "RECOVERY_REQUIRED"}:
        return _actionless_result("HOLD", "WORKER_ATTESTATION_S15_INVALID")
    return _actionless_result(
        status,
        reason,
        worker_provenance_status="VALIDATED_READ_ONLY",
        replay_status="EXTERNALLY_CHECKED_NOT_ADVANCED",
        worker_authorization=worker_proof["worker_authorization"],
        worker_authorization_sha256=worker_proof["worker_authorization_sha256"],
        worker_proof=worker_proof,
        s15_result=s15_result,
        provenance_status=s15_result.get("provenance_status", "HOLD"),
    )


__all__ = [
    "CrossStoreWorkerAttestationError",
    "GATE_BINDING_SCHEMA",
    "HOST_RUNTIME_ATTESTATION_AUTHORITY_PREFIX",
    "HOST_RUNTIME_ATTESTATION_SCHEMA",
    "REPLAY_FLOOR_AUTHORITY_PREFIX",
    "REPLAY_FLOOR_SCHEMA",
    "REPLAY_OBSERVATION_AUTHORITY_PREFIX",
    "REPLAY_OBSERVATION_SCHEMA",
    "WORKER_ATTESTATION_AUTHORITY_PREFIX",
    "WORKER_ATTESTATION_ERROR_CODES",
    "WORKER_ATTESTATION_PROTOCOL",
    "WORKER_ATTESTATION_ROLE",
    "WORKER_ATTESTATION_SCHEMA",
    "WORKER_ATTESTATION_VERIFICATION_SCHEMA",
    "WORKER_AUTHORIZATION_SCHEMA",
    "configure_trusted_host_authority",
    "configure_trusted_replay_authority",
    "configure_trusted_replay_floor_authority",
    "configure_trusted_worker_authority",
    "evaluate_worker_attested_cross_store_capture",
    "freeze_trusted_host_authorities",
    "freeze_trusted_replay_authorities",
    "freeze_trusted_replay_floor_authorities",
    "freeze_trusted_worker_authorities",
    "verify_worker_host_attestation",
]
