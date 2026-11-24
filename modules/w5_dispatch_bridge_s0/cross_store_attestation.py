"""W5-S15 immutable source-profile and attestation gate.

S15 is a provenance boundary in front of the W5-S14 producer.  It accepts a
host-frozen registry and an externally authenticated, canonical profile claim,
binds that claim to one transaction, observer, source set and capture cohort,
and invokes S14 only after every provenance check has passed.

The registry and its key material are supplied by the process-startup trust
boundary.  This module never discovers a source, opens a path or database,
acquires a lock, starts a process, uses a transport or changes a registry.
Even a valid MAC is evidence only; it does not make an adapter authoritative
and does not grant any execution capability.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from threading import Lock
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json

from .cross_store_capture import evaluate_cross_store_capture
from .cross_store_snapshot import SNAPSHOT_PARTICIPANT_IDS


CROSS_STORE_ATTESTATION_SCHEMA = "prime-cross-store-source-attestation-v1"
CROSS_STORE_ATTESTATION_VERIFICATION_SCHEMA = "prime-cross-store-source-attestation-verification-v1"
CROSS_STORE_ATTESTATION_ROLE = "cross_store_source_attestation_gate_read_only"
SOURCE_PROFILE_SCHEMA = "prime-cross-store-source-profile-v1"
SOURCE_REGISTRY_SCHEMA = "prime-cross-store-source-registry-v1"
SOURCE_AUTHORIZATION_SCHEMA = "prime-cross-store-source-authorization-v1"
SOURCE_PROFILE_CURSOR_SCHEMA = "prime-cross-store-cursor-v1"
SOURCE_ATTESTATION_PROTOCOL = "hmac-sha256-canonical-json-v1"
SOURCE_ATTESTATION_AUTHORITY_PREFIX = "source-attestation-"

SOURCE_IDENTITY_KEYS = frozenset(
    {
        "participant_id",
        "source_kind",
        "source_id",
        "source_instance_id",
        "source_schema",
        "snapshot_id",
        "snapshot_mode",
        "source_identity_sha256",
    }
)
SOURCE_PROFILE_KEYS = frozenset(
    {
        "schema_version",
        "participant_id",
        "adapter_version",
        "source_kind",
        "source_id",
        "source_instance_id",
        "source_schema",
        "adapter_id",
        "allowed_root_or_binding",
        "adapter_code_sha256",
        "source_binding_sha256",
        "snapshot_mode",
        "cursor_schema",
        "capabilities",
        "profile_sha256",
    }
)
PROFILE_CAPABILITY_KEYS = frozenset(
    {
        "read_only_capability",
        "write_capability",
        "lock_capability",
        "network_capability",
        "process_capability",
    }
)
SOURCE_CAPABILITY_KEYS = frozenset(
    {
        "adapter_id",
        "allowed_root_or_binding",
        "read_only_capability",
        "write_capability",
        "lock_capability",
        "network_capability",
        "process_capability",
    }
)
COHORT_BINDING_KEYS = frozenset(
    {
        "capture_id",
        "sequence_domain",
        "sequence_no",
        "barrier_id",
        "clock_domain_id",
        "clock_sample_id",
        "cohort_id",
        "cohort_revision",
        "fence_sha256",
        "lease_sha256",
        "generation_vector",
    }
)
GENERATION_KEYS = frozenset({"generation", "generation_id"})
TRUST_REGISTRY_KEYS = frozenset(
    {
        "schema_version",
        "registry_id",
        "registry_version",
        "frozen",
        "profile_set_sha256",
        "registry_sha256",
    }
)
ATTESTATION_KEYS = frozenset(
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
ATTESTATION_PAYLOAD_KEYS = frozenset(
    {
        "transaction_id",
        "observer_id",
        "observer_instance_id",
        "observer_sha256",
        "registry_id",
        "registry_version",
        "registry_sha256",
        "profile_set_sha256",
        "source_set_sha256",
        "capture_context_sha256",
        "cohort_binding_sha256",
        "attestation_nonce",
    }
)
S14_CAPTURE_KEYS = frozenset(
    {
        "transaction_id",
        "observer",
        "source_identities",
        "readers",
        "source_capabilities",
        "capture_context",
        "clock",
        "cohort",
        "expected_projection_manifest",
        "fence",
        "replay",
        "s12_input",
    }
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_RECOVERY_SOURCE_CODES = frozenset(
    {
        "CAPTURE_SOURCE_DRIFT",
        "CAPTURE_TOCTOU_DETECTED",
        "CAPTURE_CLOCK_DRIFT",
        "CAPTURE_FENCE_DRIFT",
        "CAPTURE_LEASE_DRIFT",
        "CAPTURE_GENERATION_DRIFT",
        "CAPTURE_LEASE_EXPIRED",
        "SNAPSHOT_SOURCE_DRIFT",
        "SNAPSHOT_TOCTOU_DETECTED",
        "SNAPSHOT_CAPTURE_COHORT_INVALID",
        "SNAPSHOT_FENCE_DRIFT",
        "SNAPSHOT_LEASE_EXPIRED",
    }
)
ATTESTATION_ERROR_CODES = frozenset(
    {
        "ATTESTATION_NOT_OBSERVED",
        "ATTESTATION_SCHEMA_INVALID",
        "ATTESTATION_PROFILE_INVALID",
        "ATTESTATION_PROFILE_DRIFT",
        "ATTESTATION_REGISTRY_INVALID",
        "ATTESTATION_REGISTRY_NOT_FROZEN",
        "ATTESTATION_TRUST_ROOT_UNKNOWN",
        "ATTESTATION_SIGNATURE_INVALID",
        "ATTESTATION_PAYLOAD_INVALID",
        "ATTESTATION_TRANSACTION_MISMATCH",
        "ATTESTATION_OBSERVER_MISMATCH",
        "ATTESTATION_SOURCE_SET_MISMATCH",
        "ATTESTATION_COHORT_MISMATCH",
        "ATTESTATION_CAPABILITY_MISMATCH",
        "ATTESTATION_S14_INPUT_INVALID",
    }
)


class CrossStoreAttestationError(ValueError):
    """An S15 provenance claim failed closed without a side effect."""

    def __init__(self, code: str, message: str) -> None:
        if code not in ATTESTATION_ERROR_CODES:
            raise ValueError(f"unknown S15 attestation code: {code}")
        self.code = code
        super().__init__(f"{code}: {message}")


_TRUST_LOCK = Lock()
_TRUSTED_SOURCE_KEYS: dict[tuple[str, str], bytes] = {}
_TRUST_ROOT_FROZEN = False


def configure_trusted_source_authority(*, authority_id: str, key_id: str, key: bytes) -> None:
    """Configure one S15 trust key before the process trust root is frozen."""

    if (
        not isinstance(authority_id, str)
        or _SAFE_ID.fullmatch(authority_id) is None
        or not authority_id.startswith(SOURCE_ATTESTATION_AUTHORITY_PREFIX)
        or not isinstance(key_id, str)
        or _SAFE_ID.fullmatch(key_id) is None
        or not key_id.startswith(SOURCE_ATTESTATION_AUTHORITY_PREFIX)
    ):
        raise ValueError("S15 authority and key IDs must use the source-attestation- scope")
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("S15 trust key must contain at least 16 bytes")
    identity = (authority_id, key_id)
    with _TRUST_LOCK:
        if _TRUST_ROOT_FROZEN:
            if _TRUSTED_SOURCE_KEYS.get(identity) == key:
                return
            raise RuntimeError("S15 trust root is frozen")
        existing = _TRUSTED_SOURCE_KEYS.get(identity)
        if existing is not None and existing != key:
            raise RuntimeError("S15 trust key reconfiguration rejected")
        _TRUSTED_SOURCE_KEYS[identity] = bytes(key)


def freeze_trusted_source_authorities() -> None:
    """Freeze the process-startup S15 trust root before verification."""

    global _TRUST_ROOT_FROZEN
    with _TRUST_LOCK:
        _TRUST_ROOT_FROZEN = True


def _resolve_trusted_source_key(*, authority_id: str, key_id: str) -> bytes:
    with _TRUST_LOCK:
        if not _TRUST_ROOT_FROZEN:
            raise CrossStoreAttestationError("ATTESTATION_REGISTRY_NOT_FROZEN", "S15 trust root is not frozen")
        key = _TRUSTED_SOURCE_KEYS.get((authority_id, key_id))
    if key is None:
        raise CrossStoreAttestationError("ATTESTATION_TRUST_ROOT_UNKNOWN", "S15 authority/key is unknown")
    return key


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CrossStoreAttestationError("ATTESTATION_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise CrossStoreAttestationError("ATTESTATION_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise CrossStoreAttestationError("ATTESTATION_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CrossStoreAttestationError("ATTESTATION_SCHEMA_INVALID", f"{label} must be an integer >= 0")
    return value


def _copy_json(value: Any, label: str) -> Any:
    try:
        # canonical_hash also rejects non-JSON values and hostile mapping shapes.
        import copy

        copied = copy.deepcopy(value)
        canonical_hash(copied)
        return copied
    except Exception as exc:
        raise CrossStoreAttestationError("ATTESTATION_SCHEMA_INVALID", f"{label} is not canonical JSON") from exc


def _digest(value: Any, label: str) -> str:
    try:
        return canonical_hash(value)
    except Exception as exc:
        raise CrossStoreAttestationError("ATTESTATION_SCHEMA_INVALID", f"{label} is not canonical JSON") from exc


def _validate_observer(value: Any) -> dict[str, str]:
    observer_keys = frozenset({"observer_id", "observer_instance_id", "implementation_id", "mode"})
    if not isinstance(value, Mapping) or set(value) != observer_keys:
        raise CrossStoreAttestationError("ATTESTATION_OBSERVER_MISMATCH", "observer keys are not exact")
    if value["mode"] != "READ_ONLY_IMPORT":
        raise CrossStoreAttestationError("ATTESTATION_OBSERVER_MISMATCH", "observer is not read-only")
    return {
        "observer_id": _safe_id(value["observer_id"], "observer.observer_id"),
        "observer_instance_id": _safe_id(value["observer_instance_id"], "observer.observer_instance_id"),
        "implementation_id": _safe_id(value["implementation_id"], "observer.implementation_id"),
        "mode": "READ_ONLY_IMPORT",
    }


def _validate_source_identities(value: Any) -> tuple[dict[str, dict[str, Any]], str]:
    if not isinstance(value, Mapping) or set(value) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreAttestationError("ATTESTATION_SOURCE_SET_MISMATCH", "source participant set is not exact")
    normalized: dict[str, dict[str, Any]] = {}
    source_ids: list[str] = []
    source_instances: set[str] = set()
    snapshots: set[str] = set()
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        item = value[participant_id]
        if not isinstance(item, Mapping) or set(item) != SOURCE_IDENTITY_KEYS:
            raise CrossStoreAttestationError("ATTESTATION_SOURCE_SET_MISMATCH", f"source {participant_id} keys are not exact")
        if item["participant_id"] != participant_id:
            raise CrossStoreAttestationError("ATTESTATION_SOURCE_SET_MISMATCH", f"source {participant_id} participant drift")
        identity = {
            "participant_id": participant_id,
            "source_kind": _safe_id(item["source_kind"], f"source.{participant_id}.source_kind"),
            "source_id": _safe_id(item["source_id"], f"source.{participant_id}.source_id"),
            "source_instance_id": _safe_id(item["source_instance_id"], f"source.{participant_id}.source_instance_id"),
            "source_schema": _safe_id(item["source_schema"], f"source.{participant_id}.source_schema"),
            "snapshot_id": _safe_id(item["snapshot_id"], f"source.{participant_id}.snapshot_id"),
            "snapshot_mode": _safe_id(item["snapshot_mode"], f"source.{participant_id}.snapshot_mode"),
        }
        if identity["snapshot_mode"] != "FROZEN_EXPORT":
            raise CrossStoreAttestationError("ATTESTATION_SOURCE_SET_MISMATCH", f"source {participant_id} is not frozen")
        declared = _hash64(item["source_identity_sha256"], f"source.{participant_id}.source_identity_sha256")
        if declared != _digest(identity, f"source.{participant_id}.identity"):
            raise CrossStoreAttestationError("ATTESTATION_SOURCE_SET_MISMATCH", f"source {participant_id} identity digest mismatch")
        if identity["source_id"] in source_ids or identity["source_instance_id"] in source_instances or identity["snapshot_id"] in snapshots:
            raise CrossStoreAttestationError("ATTESTATION_SOURCE_SET_MISMATCH", "source identity is duplicated")
        source_ids.append(identity["source_id"])
        source_instances.add(identity["source_instance_id"])
        snapshots.add(identity["snapshot_id"])
        normalized[participant_id] = {**identity, "source_identity_sha256": declared}
    return normalized, _digest(sorted(source_ids), "source set")


def _validate_profile(participant_id: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != SOURCE_PROFILE_KEYS:
        raise CrossStoreAttestationError("ATTESTATION_PROFILE_INVALID", f"profile {participant_id} keys are not exact")
    if value["schema_version"] != SOURCE_PROFILE_SCHEMA or value["participant_id"] != participant_id:
        raise CrossStoreAttestationError("ATTESTATION_PROFILE_INVALID", f"profile {participant_id} schema/participant mismatch")
    capabilities = value["capabilities"]
    if not isinstance(capabilities, Mapping) or set(capabilities) != PROFILE_CAPABILITY_KEYS:
        raise CrossStoreAttestationError("ATTESTATION_PROFILE_INVALID", f"profile {participant_id} capabilities are not exact")
    normalized_capabilities = {key: capabilities[key] for key in sorted(PROFILE_CAPABILITY_KEYS)}
    if normalized_capabilities["read_only_capability"] is not True or any(
        normalized_capabilities[key] is not False
        for key in sorted(PROFILE_CAPABILITY_KEYS - {"read_only_capability"})
    ):
        raise CrossStoreAttestationError("ATTESTATION_CAPABILITY_MISMATCH", f"profile {participant_id} is not read-only")
    core = {
        "schema_version": SOURCE_PROFILE_SCHEMA,
        "participant_id": participant_id,
        "adapter_version": _safe_id(value["adapter_version"], f"profile.{participant_id}.adapter_version"),
        "source_kind": _safe_id(value["source_kind"], f"profile.{participant_id}.source_kind"),
        "source_id": _safe_id(value["source_id"], f"profile.{participant_id}.source_id"),
        "source_instance_id": _safe_id(value["source_instance_id"], f"profile.{participant_id}.source_instance_id"),
        "source_schema": _safe_id(value["source_schema"], f"profile.{participant_id}.source_schema"),
        "adapter_id": _safe_id(value["adapter_id"], f"profile.{participant_id}.adapter_id"),
        "allowed_root_or_binding": _safe_id(value["allowed_root_or_binding"], f"profile.{participant_id}.allowed_root_or_binding"),
        "adapter_code_sha256": _hash64(value["adapter_code_sha256"], f"profile.{participant_id}.adapter_code_sha256"),
        "source_binding_sha256": _hash64(value["source_binding_sha256"], f"profile.{participant_id}.source_binding_sha256"),
        "snapshot_mode": _safe_id(value["snapshot_mode"], f"profile.{participant_id}.snapshot_mode"),
        "cursor_schema": _safe_id(value["cursor_schema"], f"profile.{participant_id}.cursor_schema"),
        "capabilities": normalized_capabilities,
    }
    if core["cursor_schema"] != SOURCE_PROFILE_CURSOR_SCHEMA or core["snapshot_mode"] != "FROZEN_EXPORT":
        raise CrossStoreAttestationError("ATTESTATION_PROFILE_INVALID", f"profile {participant_id} cursor/snapshot schema unsupported")
    declared = _hash64(value["profile_sha256"], f"profile.{participant_id}.profile_sha256")
    if declared != _digest(core, f"profile.{participant_id}"):
        raise CrossStoreAttestationError("ATTESTATION_PROFILE_INVALID", f"profile {participant_id} digest mismatch")
    return {**core, "profile_sha256": declared}


def _validate_profiles(value: Any) -> tuple[dict[str, dict[str, Any]], str]:
    if not isinstance(value, Mapping) or set(value) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreAttestationError("ATTESTATION_PROFILE_INVALID", "profile participant set is not exact")
    profiles = {
        participant_id: _validate_profile(participant_id, value[participant_id])
        for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS)
    }
    adapter_ids = [profiles[participant_id]["adapter_id"] for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS)]
    binding_digests = [profiles[participant_id]["source_binding_sha256"] for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS)]
    if len(set(adapter_ids)) != len(adapter_ids) or len(set(binding_digests)) != len(binding_digests):
        raise CrossStoreAttestationError("ATTESTATION_PROFILE_DRIFT", "adapter or source binding is duplicated")
    return profiles, _digest(profiles, "profile set")


def _validate_source_capabilities(
    value: Any,
    profiles: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreAttestationError("ATTESTATION_CAPABILITY_MISMATCH", "S14 capability set is not exact")
    normalized: dict[str, dict[str, Any]] = {}
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        capability = value[participant_id]
        if not isinstance(capability, Mapping) or set(capability) != SOURCE_CAPABILITY_KEYS:
            raise CrossStoreAttestationError("ATTESTATION_CAPABILITY_MISMATCH", f"S14 capability {participant_id} is not exact")
        normalized[participant_id] = {
            key: (capability[key] if key not in {"adapter_id", "allowed_root_or_binding"} else _safe_id(capability[key], f"capability.{participant_id}.{key}"))
            for key in sorted(SOURCE_CAPABILITY_KEYS)
        }
        profile = profiles[participant_id]
        if normalized[participant_id]["adapter_id"] != profile["adapter_id"] or normalized[participant_id]["allowed_root_or_binding"] != profile["allowed_root_or_binding"]:
            raise CrossStoreAttestationError("ATTESTATION_CAPABILITY_MISMATCH", f"S14 capability {participant_id} differs from profile")
        if normalized[participant_id]["read_only_capability"] is not True or any(
            normalized[participant_id][key] is not False
            for key in ("write_capability", "lock_capability", "network_capability", "process_capability")
        ):
            raise CrossStoreAttestationError("ATTESTATION_CAPABILITY_MISMATCH", f"S14 capability {participant_id} is not boolean read-only")
        if any(normalized[participant_id][key] != profile["capabilities"][key] for key in sorted(PROFILE_CAPABILITY_KEYS)):
            raise CrossStoreAttestationError("ATTESTATION_CAPABILITY_MISMATCH", f"S14 capability {participant_id} differs from attested capability")
    return normalized


def _validate_capture_context(value: Any) -> dict[str, Any]:
    keys = frozenset({"capture_id", "sequence_domain", "sequence_no", "barrier_id", "clock_domain_id", "clock_sample_id"})
    if not isinstance(value, Mapping) or set(value) != keys:
        raise CrossStoreAttestationError("ATTESTATION_COHORT_MISMATCH", "capture context keys are not exact")
    return {
        "capture_id": _safe_id(value["capture_id"], "capture.capture_id"),
        "sequence_domain": _safe_id(value["sequence_domain"], "capture.sequence_domain"),
        "sequence_no": _integer(value["sequence_no"], "capture.sequence_no"),
        "barrier_id": _safe_id(value["barrier_id"], "capture.barrier_id"),
        "clock_domain_id": _safe_id(value["clock_domain_id"], "capture.clock_domain_id"),
        "clock_sample_id": _safe_id(value["clock_sample_id"], "capture.clock_sample_id"),
    }


def _validate_cohort_binding(
    value: Any,
    *,
    capture_context: Mapping[str, Any],
    fence: Any,
    s12_input: Any,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != COHORT_BINDING_KEYS:
        raise CrossStoreAttestationError("ATTESTATION_COHORT_MISMATCH", "cohort binding keys are not exact")
    context = _validate_capture_context(capture_context)
    normalized = {
        **context,
        "cohort_id": _safe_id(value["cohort_id"], "cohort.cohort_id"),
        "cohort_revision": _safe_id(value["cohort_revision"], "cohort.cohort_revision"),
        "fence_sha256": _hash64(value["fence_sha256"], "cohort.fence_sha256"),
        "lease_sha256": _hash64(value["lease_sha256"], "cohort.lease_sha256"),
    }
    if normalized["fence_sha256"] != _digest(fence, "cohort.fence"):
        raise CrossStoreAttestationError("ATTESTATION_COHORT_MISMATCH", "cohort fence differs from S14 fence")
    if not isinstance(s12_input, Mapping) or "lease" not in s12_input:
        raise CrossStoreAttestationError("ATTESTATION_COHORT_MISMATCH", "S12 lease is missing")
    if normalized["lease_sha256"] != _digest(s12_input["lease"], "cohort.lease"):
        raise CrossStoreAttestationError("ATTESTATION_COHORT_MISMATCH", "cohort lease differs from S12 lease")
    generation_vector = value["generation_vector"]
    if not isinstance(generation_vector, Mapping) or set(generation_vector) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreAttestationError("ATTESTATION_COHORT_MISMATCH", "generation vector participant set is not exact")
    normalized_generation: dict[str, dict[str, Any]] = {}
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        item = generation_vector[participant_id]
        if not isinstance(item, Mapping) or set(item) != GENERATION_KEYS:
            raise CrossStoreAttestationError("ATTESTATION_COHORT_MISMATCH", f"generation {participant_id} is not exact")
        normalized_generation[participant_id] = {
            "generation": _integer(item["generation"], f"cohort.generation.{participant_id}.generation"),
            "generation_id": _hash64(item["generation_id"], f"cohort.generation.{participant_id}.generation_id"),
        }
    normalized["generation_vector"] = normalized_generation
    return normalized


def _validate_registry(value: Any, profile_set_sha256: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != TRUST_REGISTRY_KEYS:
        raise CrossStoreAttestationError("ATTESTATION_REGISTRY_INVALID", "trust registry keys are not exact")
    if value["schema_version"] != SOURCE_REGISTRY_SCHEMA or value["frozen"] is not True:
        raise CrossStoreAttestationError("ATTESTATION_REGISTRY_NOT_FROZEN", "source registry is not frozen")
    registry_id = _safe_id(value["registry_id"], "registry.registry_id")
    registry_version = _safe_id(value["registry_version"], "registry.registry_version")
    declared_profiles = _hash64(value["profile_set_sha256"], "registry.profile_set_sha256")
    if declared_profiles != profile_set_sha256:
        raise CrossStoreAttestationError("ATTESTATION_REGISTRY_INVALID", "registry profile digest differs")
    core = {
        "schema_version": SOURCE_REGISTRY_SCHEMA,
        "registry_id": registry_id,
        "registry_version": registry_version,
        "frozen": True,
        "profile_set_sha256": declared_profiles,
    }
    if _hash64(value["registry_sha256"], "registry.registry_sha256") != _digest(core, "registry"):
        raise CrossStoreAttestationError("ATTESTATION_REGISTRY_INVALID", "registry digest mismatch")
    return {**core, "registry_sha256": _digest(core, "registry")}


def _validate_attestation(
    value: Any,
    *,
    expected_transaction_id: str,
    expected_observer: Mapping[str, str],
    registry: Mapping[str, Any],
    profile_set_sha256: str,
    source_set_sha256: str,
    capture_context_sha256: str,
    cohort_binding_sha256: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != ATTESTATION_KEYS:
        raise CrossStoreAttestationError("ATTESTATION_SCHEMA_INVALID", "attestation keys are not exact")
    if value["schema_version"] != CROSS_STORE_ATTESTATION_SCHEMA or value["protocol"] != SOURCE_ATTESTATION_PROTOCOL:
        raise CrossStoreAttestationError("ATTESTATION_SCHEMA_INVALID", "attestation schema/protocol is unsupported")
    attestation_id = _safe_id(value["attestation_id"], "attestation.attestation_id")
    authority_id = _safe_id(value["authority_id"], "attestation.authority_id")
    key_id = _safe_id(value["key_id"], "attestation.key_id")
    trusted_key = _resolve_trusted_source_key(authority_id=authority_id, key_id=key_id)
    payload = value["payload"]
    if not isinstance(payload, Mapping) or set(payload) != ATTESTATION_PAYLOAD_KEYS:
        raise CrossStoreAttestationError("ATTESTATION_PAYLOAD_INVALID", "attestation payload keys are not exact")
    if _hash64(value["payload_sha256"], "attestation.payload_sha256") != _digest(dict(payload), "attestation.payload"):
        raise CrossStoreAttestationError("ATTESTATION_PAYLOAD_INVALID", "attestation payload digest mismatch")
    authority_mac = _hash64(value["authority_mac"], "attestation.authority_mac")
    mac_core = {
        "schema_version": CROSS_STORE_ATTESTATION_SCHEMA,
        "attestation_id": attestation_id,
        "authority_id": authority_id,
        "key_id": key_id,
        "protocol": SOURCE_ATTESTATION_PROTOCOL,
        "payload": dict(payload),
        "payload_sha256": value["payload_sha256"],
    }
    expected_mac = hmac.new(
        trusted_key, canonical_json(mac_core).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(authority_mac, expected_mac):
        raise CrossStoreAttestationError("ATTESTATION_SIGNATURE_INVALID", "attestation MAC does not match")
    checks = {
        "transaction_id": expected_transaction_id,
        "observer_id": expected_observer["observer_id"],
        "observer_instance_id": expected_observer["observer_instance_id"],
        "observer_sha256": _digest(expected_observer, "observer"),
        "registry_id": registry["registry_id"],
        "registry_version": registry["registry_version"],
        "registry_sha256": registry["registry_sha256"],
        "profile_set_sha256": profile_set_sha256,
        "source_set_sha256": source_set_sha256,
        "capture_context_sha256": capture_context_sha256,
        "cohort_binding_sha256": cohort_binding_sha256,
    }
    for key, expected in checks.items():
        actual = payload[key]
        if actual != expected:
            code = (
                "ATTESTATION_TRANSACTION_MISMATCH"
                if key == "transaction_id"
                else "ATTESTATION_OBSERVER_MISMATCH"
                if key.startswith("observer")
                else "ATTESTATION_REGISTRY_INVALID"
                if key.startswith("registry")
                else "ATTESTATION_SOURCE_SET_MISMATCH"
                if key in {"profile_set_sha256", "source_set_sha256"}
                else "ATTESTATION_COHORT_MISMATCH"
                if key in {"capture_context_sha256", "cohort_binding_sha256"}
                else "ATTESTATION_PAYLOAD_INVALID"
            )
            raise CrossStoreAttestationError(code, f"attestation {key} differs from current capture")
    _safe_id(payload["attestation_nonce"], "attestation.attestation_nonce")
    return {
        "schema_version": CROSS_STORE_ATTESTATION_SCHEMA,
        "attestation_id": attestation_id,
        "authority_id": authority_id,
        "key_id": key_id,
        "protocol": SOURCE_ATTESTATION_PROTOCOL,
        "payload": dict(payload),
        "payload_sha256": value["payload_sha256"],
        "authority_mac": authority_mac,
    }


def verify_cross_store_source_attestation(
    *,
    source_profiles: Mapping[str, Mapping[str, Any]],
    attestation: Mapping[str, Any],
    trust_registry: Mapping[str, Any],
    cohort_binding: Mapping[str, Any],
    s14_input: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify one frozen S15 provenance claim without invoking S14."""

    if not isinstance(s14_input, Mapping) or set(s14_input) != S14_CAPTURE_KEYS:
        raise CrossStoreAttestationError("ATTESTATION_S14_INPUT_INVALID", "S14 input keys are not exact")
    transaction_id = _safe_id(s14_input["transaction_id"], "transaction_id")
    observer = _validate_observer(s14_input["observer"])
    sources, source_set_sha256 = _validate_source_identities(s14_input["source_identities"])
    profiles, profile_set_sha256 = _validate_profiles(source_profiles)
    capabilities = _validate_source_capabilities(s14_input["source_capabilities"], profiles)
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        source = sources[participant_id]
        profile = profiles[participant_id]
        for key in ("source_kind", "source_id", "source_instance_id", "source_schema"):
            if profile[key] != source[key]:
                raise CrossStoreAttestationError("ATTESTATION_PROFILE_DRIFT", f"profile {participant_id} differs at {key}")
    context = _validate_capture_context(s14_input["capture_context"])
    normalized_cohort = _validate_cohort_binding(
        cohort_binding,
        capture_context=context,
        fence=s14_input["fence"],
        s12_input=s14_input["s12_input"],
    )
    normalized_registry = _validate_registry(trust_registry, profile_set_sha256)
    capture_context_sha256 = _digest(context, "capture context")
    cohort_binding_sha256 = _digest(normalized_cohort, "cohort binding")
    normalized_attestation = _validate_attestation(
        attestation,
        expected_transaction_id=transaction_id,
        expected_observer=observer,
        registry=normalized_registry,
        profile_set_sha256=profile_set_sha256,
        source_set_sha256=source_set_sha256,
        capture_context_sha256=capture_context_sha256,
        cohort_binding_sha256=cohort_binding_sha256,
    )
    authorization_core = {
        "schema_version": SOURCE_AUTHORIZATION_SCHEMA,
        "attestation_id": normalized_attestation["attestation_id"],
        "authority_id": normalized_attestation["authority_id"],
        "key_id": normalized_attestation["key_id"],
        "payload_sha256": normalized_attestation["payload_sha256"],
        "transaction_id": transaction_id,
        "observer_sha256": _digest(observer, "observer"),
        "registry_sha256": normalized_registry["registry_sha256"],
        "profile_set_sha256": profile_set_sha256,
        "source_set_sha256": source_set_sha256,
        "capture_context_sha256": capture_context_sha256,
        "cohort_binding_sha256": cohort_binding_sha256,
    }
    authorization = {
        **authorization_core,
        "authorization_sha256": _digest(authorization_core, "authorization"),
    }
    return {
        "attestation_id": normalized_attestation["attestation_id"],
        "authority_id": normalized_attestation["authority_id"],
        "key_id": normalized_attestation["key_id"],
        "registry_id": normalized_registry["registry_id"],
        "registry_version": normalized_registry["registry_version"],
        "registry_sha256": normalized_registry["registry_sha256"],
        "profile_set_sha256": profile_set_sha256,
        "source_set_sha256": source_set_sha256,
        "capture_context_sha256": capture_context_sha256,
        "cohort_binding_sha256": cohort_binding_sha256,
        "authorization": authorization,
        "authorization_sha256": authorization["authorization_sha256"],
        "profiles": profiles,
        "capabilities": capabilities,
        "cohort_binding": normalized_cohort,
        "read_only": True,
        "external_action": False,
    }


def _actionless_result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    result = {
        "schema_version": CROSS_STORE_ATTESTATION_VERIFICATION_SCHEMA,
        "contract_role": CROSS_STORE_ATTESTATION_ROLE,
        "status": status,
        "reason": reason,
        "provenance_status": "HOLD",
        "permission": "read_only",
        "external_action": False,
        "mutation_allowed": False,
        "authoritative_decision": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "execution": {"mutation": False, "network": False, "reconcile": False, "resume": False},
    }
    result.update(extra)
    return result


def evaluate_attested_cross_store_capture(
    *,
    source_profiles: Mapping[str, Mapping[str, Any]],
    attestation: Mapping[str, Any],
    trust_registry: Mapping[str, Any],
    cohort_binding: Mapping[str, Any],
    s14_input: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate S15 provenance, then invoke S14 exactly once if valid."""

    try:
        provenance = verify_cross_store_source_attestation(
            source_profiles=source_profiles,
            attestation=attestation,
            trust_registry=trust_registry,
            cohort_binding=cohort_binding,
            s14_input=s14_input,
        )
    except CrossStoreAttestationError as exc:
        return _actionless_result("HOLD", exc.code)
    except Exception:
        return _actionless_result("HOLD", "ATTESTATION_SCHEMA_INVALID")
    try:
        capture_result = evaluate_cross_store_capture(**dict(s14_input))
    except Exception:
        return _actionless_result("HOLD", "ATTESTATION_S14_INPUT_INVALID")
    status = capture_result.get("status", "HOLD")
    reason = capture_result.get("reason", "CAPTURE_SCHEMA_INVALID")
    if status not in {"CAPTURED_READ_ONLY", "HOLD", "RECOVERY_REQUIRED"}:
        return _actionless_result("HOLD", "ATTESTATION_S14_INPUT_INVALID")
    return _actionless_result(
        status,
        reason,
        provenance_status="VALIDATED_READ_ONLY",
        provenance=provenance,
        capture_result=capture_result,
    )


__all__ = [
    "ATTESTATION_ERROR_CODES",
    "CROSS_STORE_ATTESTATION_ROLE",
    "CROSS_STORE_ATTESTATION_SCHEMA",
    "CROSS_STORE_ATTESTATION_VERIFICATION_SCHEMA",
    "CrossStoreAttestationError",
    "SOURCE_ATTESTATION_AUTHORITY_PREFIX",
    "SOURCE_ATTESTATION_PROTOCOL",
    "SOURCE_AUTHORIZATION_SCHEMA",
    "SOURCE_PROFILE_CURSOR_SCHEMA",
    "SOURCE_PROFILE_SCHEMA",
    "SOURCE_REGISTRY_SCHEMA",
    "configure_trusted_source_authority",
    "evaluate_attested_cross_store_capture",
    "freeze_trusted_source_authorities",
    "verify_cross_store_source_attestation",
]
