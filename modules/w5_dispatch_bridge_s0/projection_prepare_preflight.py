"""W5-S22 read-only Projection-Prepare preflight.

This card defines the smallest honest boundary after the S21 local Prepare
journal.  It rereads the S21 scope and receipt, binds two independent
Before-State observations for all five participants, and validates the four
writer identities, local-CAS declaration, lease/fence, generation and
idempotency bindings.  It never calls a writer, opens a participant store,
persists a pending marker, emits a receipt, or claims a Projection commit.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Mapping, Protocol

from modules.w4_small_loop_s0 import canonical_hash, canonical_json


PROJECTION_PREFLIGHT_SCHEMA = "prime-projection-prepare-preflight-v1"
PROJECTION_PREFLIGHT_ROLE = "projection_prepare_preflight_read_only"
PROJECTION_PREPARE_ELIGIBLE = "PROJECTION_PREPARE_ELIGIBLE"
PROJECTION_PREPARE_PENDING_DEFERRED = "PROJECTION_PENDING_DEFERRED"
PROJECTION_COMMITTED_DEFERRED = "COMMITTED_DEFERRED"
OBSERVATION_ROLE = "OBSERVATION"
WRITE_ROLE = "WRITE"
OBSERVED_EFFECT_NONE = "NONE"
CROSS_STORE_ATOMICITY_NOT_CLAIMED = "NOT_CLAIMED"
PARTICIPANT_IDS = frozenset(
    {"control_plane", "knowledge_ledger", "prime_ledger", "prime_queue", "receipt_projection"}
)
WRITE_PARTICIPANTS = frozenset({"control_plane", "prime_ledger", "prime_queue", "receipt_projection"})
OBSERVATION_PARTICIPANTS = frozenset({"knowledge_ledger"})
_EXPECTED_ROLES = {**{item: WRITE_ROLE for item in WRITE_PARTICIPANTS}, "knowledge_ledger": OBSERVATION_ROLE}
_EXPECTED_OPERATIONS = {
    "control_plane": "cas",
    "knowledge_ledger": "observe",
    "prime_ledger": "replace",
    "prime_queue": "replace",
    "receipt_projection": "seal",
}
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_RECEIPT_ALLOWED_STATUSES = frozenset({"PREPARED", "REPLAYED"})
_SOURCE_KEYS = frozenset({"adapter_id", "adapter_instance_id", "store_id", "root_binding_sha256", "schema_version"})
_WRITER_KEYS = frozenset(
    {
        "writer_id",
        "writer_instance_id",
        "writer_epoch",
        "write_capability",
        "local_atomicity",
        "writer_schema",
        "target_id",
    }
)
_OBSERVATION_KEYS = frozenset(
    {
        "observation_id",
        "observer_id",
        "observer_instance_id",
        "sequence",
        "observed_at",
        "lease",
        "before",
        "source_cursor_sha256",
    }
)
_LEASE_KEYS = frozenset(
    {"owner_id", "owner_instance_id", "owner_epoch", "fencing_epoch", "token_sha256", "expires_at"}
)
_CAS_KEYS = frozenset(
    {
        "protocol",
        "target_id",
        "transaction_id",
        "receipt_key",
        "idempotency_key",
        "intent_sha256",
        "expected_before",
        "expected_before_sha256",
        "expected_after",
        "expected_after_sha256",
        "fencing_epoch",
        "source_cursor_sha256",
    }
)
_SAFETY_FALSE = {
    "authoritative_decision": False,
    "authoritative_prepared": False,
    "projection_pending_allowed": False,
    "cas_authorized": False,
    "mutation_allowed": False,
    "mutation_performed": False,
    "external_mutation_performed": False,
    "receipt_emitted": False,
    "receipt_committed": False,
    "consume_allowed": False,
    "recovery_started": False,
    "resume_allowed": False,
    "external_action": False,
}


class ProjectionPreflightJournal(Protocol):
    """The read-only part of the S21 journal used by this card."""

    def read_scope(self) -> Mapping[str, Any]: ...

    def read_receipt(self, receipt_key: str) -> Mapping[str, Any]: ...


class ProjectionPreparePreflightError(ValueError):
    """An S22 input or live S21 readback failed closed."""

    def __init__(self, reason: str, *, recovery_required: bool = False) -> None:
        self.reason = reason
        self.recovery_required = recovery_required
        super().__init__(reason)


def _copy_json(value: Any, label: str) -> Any:
    try:
        isolated = copy.deepcopy(value)
        canonical_json(isolated)
        return isolated
    except (TypeError, ValueError, copy.Error) as exc:
        raise ProjectionPreparePreflightError(f"{label}_NOT_CANONICAL") from exc


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ProjectionPreparePreflightError(f"{label}_INVALID")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise ProjectionPreparePreflightError(f"{label}_INVALID")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise ProjectionPreparePreflightError(f"{label}_INVALID")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ProjectionPreparePreflightError(f"{label}_INVALID")
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    if set(value) != set(expected):
        raise ProjectionPreparePreflightError(f"{label}_KEYS_INVALID")


def _result(
    status: str,
    reason: str,
    *,
    transaction_state: str = "PREPARED",
    receipt_key: str | None = None,
    receipt_id: str | None = None,
    transaction_id: str | None = None,
    idempotency_key: str | None = None,
    receipt_intent_sha256: str | None = None,
    projection_manifest_sha256: str | None = None,
    projection_set_sha256: str | None = None,
    participant_attestations_sha256: str | None = None,
    writer_set_sha256: str | None = None,
    s21_status: str | None = None,
) -> dict[str, Any]:
    eligible = status == PROJECTION_PREPARE_ELIGIBLE
    result = {
        "schema_version": PROJECTION_PREFLIGHT_SCHEMA,
        "contract_role": PROJECTION_PREFLIGHT_ROLE,
        "status": status,
        "decision": "PROJECTION_COMMIT_DEFERRED" if eligible else "HOLD",
        "reason": reason,
        "transaction_state": transaction_state,
        "permission": "read_only_projection_prepare_preflight",
        "s21_status": s21_status,
        "s21_prepared": s21_status in _RECEIPT_ALLOWED_STATUSES,
        "projection_prepare_eligible": eligible,
        "projection_pending_state": PROJECTION_PREPARE_PENDING_DEFERRED,
        "projection_commit_state": PROJECTION_COMMITTED_DEFERRED,
        "receipt_key": receipt_key,
        "receipt_id": receipt_id,
        "transaction_id": transaction_id,
        "idempotency_key": idempotency_key,
        "receipt_intent_sha256": receipt_intent_sha256,
        "projection_manifest_sha256": projection_manifest_sha256,
        "projection_set_sha256": projection_set_sha256,
        "participant_attestations_sha256": participant_attestations_sha256,
        "writer_set_sha256": writer_set_sha256,
        "observed_effect_state": OBSERVED_EFFECT_NONE,
        "cross_store_atomicity": CROSS_STORE_ATOMICITY_NOT_CLAIMED,
        "execution": {
            "journal_read": True,
            "participant_read": True,
            "writer": False,
            "projection": False,
            "receipt": False,
            "consume": False,
            "recovery": False,
            "resume": False,
            "network": False,
        },
    }
    result.update(_SAFETY_FALSE)
    return result


def _validate_s21(
    journal: ProjectionPreflightJournal,
    receipt_key: str,
    *,
    now: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    requested_key = _safe_id(receipt_key, "receipt_key")
    try:
        scope = _copy_json(journal.read_scope(), "s21_scope")
        receipt = _copy_json(journal.read_receipt(requested_key), "s21_receipt")
    except ProjectionPreparePreflightError:
        raise
    except Exception as exc:  # pragma: no cover - defensive boundary around foreign journal implementations
        raise ProjectionPreparePreflightError("S21_READBACK_UNAVAILABLE", recovery_required=True) from exc
    if not isinstance(scope, Mapping) or not isinstance(receipt, Mapping):
        raise ProjectionPreparePreflightError("S21_READBACK_INVALID", recovery_required=True)
    if receipt.get("status") in {"RECOVERY_REQUIRED", "IN_DOUBT", "QUARANTINED"}:
        raise ProjectionPreparePreflightError("S21_READBACK_UNAVAILABLE", recovery_required=True)
    if receipt.get("status") not in _RECEIPT_ALLOWED_STATUSES:
        raise ProjectionPreparePreflightError("S21_NOT_PREPARED")
    if receipt.get("transaction_state") != "PREPARED":
        raise ProjectionPreparePreflightError("S21_STATE_NOT_PREPARED", recovery_required=True)
    for key in ("authoritative_prepared", "idempotency_reserved"):
        if receipt.get(key) is not True:
            raise ProjectionPreparePreflightError(f"S21_{key.upper()}_MISSING")
    for key in (
        "authoritative_decision",
        "receipt_emitted",
        "receipt_committed",
        "consume_allowed",
        "mutation_allowed",
        "mutation_performed",
        "external_mutation_performed",
        "recovery_started",
        "resume_allowed",
        "external_action",
    ):
        if receipt.get(key) is not False:
            raise ProjectionPreparePreflightError(f"S21_UNSAFE_FLAG_{key}", recovery_required=True)
    intent = receipt.get("receipt_intent")
    core = receipt.get("receipt_core")
    if not isinstance(intent, Mapping) or not isinstance(core, Mapping):
        raise ProjectionPreparePreflightError("S21_INTENT_OR_CORE_MISSING", recovery_required=True)
    intent = _copy_json(intent, "s21_receipt_intent")
    core = _copy_json(core, "s21_receipt_core")
    if canonical_hash(intent) != receipt.get("receipt_intent_sha256"):
        raise ProjectionPreparePreflightError("S21_INTENT_DIGEST_DRIFT", recovery_required=True)
    if core.get("receipt_key") != requested_key or intent.get("receipt_key") != requested_key:
        raise ProjectionPreparePreflightError("S21_RECEIPT_KEY_MISMATCH", recovery_required=True)
    if core.get("receipt_id") != receipt.get("receipt_id"):
        raise ProjectionPreparePreflightError("S21_RECEIPT_ID_MISMATCH", recovery_required=True)
    participants = intent.get("participants")
    effect_set = intent.get("effect_set")
    if not isinstance(participants, Mapping) or set(participants) != set(PARTICIPANT_IDS):
        raise ProjectionPreparePreflightError("S21_PARTICIPANT_SET_INVALID", recovery_required=True)
    if not isinstance(effect_set, list) or len(effect_set) != len(PARTICIPANT_IDS):
        raise ProjectionPreparePreflightError("S21_EFFECT_SET_INVALID", recovery_required=True)
    operation_by_participant: dict[str, str] = {}
    for effect in effect_set:
        if not isinstance(effect, Mapping):
            raise ProjectionPreparePreflightError("S21_EFFECT_SET_INVALID", recovery_required=True)
        participant_id = _safe_id(effect.get("participant_id"), "effect.participant_id")
        if participant_id in operation_by_participant or participant_id not in PARTICIPANT_IDS:
            raise ProjectionPreparePreflightError("S21_EFFECT_SET_INVALID", recovery_required=True)
        operation_by_participant[participant_id] = _text(effect.get("operation"), "effect.operation")
    if operation_by_participant != _EXPECTED_OPERATIONS:
        raise ProjectionPreparePreflightError("S21_EFFECT_POLICY_INVALID", recovery_required=True)
    if scope.get("journal_status") != "CLEAN":
        raise ProjectionPreparePreflightError("S21_SCOPE_NOT_CLEAN", recovery_required=True)
    for key in ("transaction_id", "projection_manifest_sha256", "projection_set_sha256", "owner_id", "owner_instance_id"):
        _text(scope.get(key), f"s21_scope.{key}")
    for key in ("transaction_id", "projection_manifest_sha256", "projection_set_sha256", "owner_id", "owner_instance_id"):
        if intent.get(key) != scope.get(key):
            raise ProjectionPreparePreflightError(f"S21_SCOPE_{key.upper()}_MISMATCH", recovery_required=True)
    for key in ("owner_epoch", "fencing_epoch"):
        _integer(scope.get(key), f"s21_scope.{key}")
        _integer(intent.get(key), f"s21_intent.{key}")
        if int(intent[key]) != int(scope[key]):
            raise ProjectionPreparePreflightError(f"S21_SCOPE_{key.upper()}_MISMATCH", recovery_required=True)
    _hash64(scope.get("lease_token_sha256"), "s21_scope.lease_token_sha256")
    lease_expires_at = _integer(scope.get("lease_expires_at"), "s21_scope.lease_expires_at")
    if lease_expires_at <= now:
        raise ProjectionPreparePreflightError("S21_LEASE_EXPIRED")
    if canonical_hash(participants) != receipt.get("participant_witness_sha256"):
        raise ProjectionPreparePreflightError("S21_PARTICIPANT_DIGEST_DRIFT", recovery_required=True)
    if core.get("participants") != participants:
        raise ProjectionPreparePreflightError("S21_CORE_PARTICIPANT_DRIFT", recovery_required=True)
    return dict(scope), dict(receipt), {**dict(intent), "participants": dict(participants), "effect_set": list(effect_set)}


def _validate_source_identity(value: Any, participant_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProjectionPreparePreflightError(f"{participant_id}_SOURCE_IDENTITY_INVALID")
    _exact_keys(value, _SOURCE_KEYS, f"{participant_id}.source_identity")
    result = {key: _text(value[key], f"{participant_id}.source_identity.{key}") for key in ("adapter_id", "adapter_instance_id", "store_id", "schema_version")}
    result["root_binding_sha256"] = _hash64(value["root_binding_sha256"], f"{participant_id}.source_identity.root_binding_sha256")
    return result


def _validate_lease(value: Any, *, scope: Mapping[str, Any], participant_id: str, now: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProjectionPreparePreflightError(f"{participant_id}_LEASE_INVALID")
    _exact_keys(value, _LEASE_KEYS, f"{participant_id}.lease")
    result = {
        "owner_id": _safe_id(value["owner_id"], f"{participant_id}.lease.owner_id"),
        "owner_instance_id": _safe_id(value["owner_instance_id"], f"{participant_id}.lease.owner_instance_id"),
        "owner_epoch": _integer(value["owner_epoch"], f"{participant_id}.lease.owner_epoch"),
        "fencing_epoch": _integer(value["fencing_epoch"], f"{participant_id}.lease.fencing_epoch"),
        "token_sha256": _hash64(value["token_sha256"], f"{participant_id}.lease.token_sha256"),
        "expires_at": _integer(value["expires_at"], f"{participant_id}.lease.expires_at"),
    }
    for key in ("owner_id", "owner_instance_id", "owner_epoch", "fencing_epoch", "token_sha256"):
        scope_key = "lease_token_sha256" if key == "token_sha256" else key
        if result[key] != scope.get(scope_key):
            raise ProjectionPreparePreflightError(f"{participant_id}_LEASE_{key.upper()}_MISMATCH")
    if result["expires_at"] != int(scope["lease_expires_at"]):
        raise ProjectionPreparePreflightError(f"{participant_id}_LEASE_EXPIRY_MISMATCH")
    if result["expires_at"] <= now:
        raise ProjectionPreparePreflightError(f"{participant_id}_LEASE_EXPIRED")
    return result


def _validate_attestation(
    participant_id: str,
    value: Any,
    *,
    intent: Mapping[str, Any],
    scope: Mapping[str, Any],
    now: int,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProjectionPreparePreflightError(f"{participant_id}_ATTESTATION_INVALID")
    required_keys = frozenset({"participant_id", "role", "source_identity", "writer_identity", "observations", "before_state_cas"})
    _exact_keys(value, required_keys, f"{participant_id}.attestation")
    if _safe_id(value.get("participant_id"), f"{participant_id}.participant_id") != participant_id:
        raise ProjectionPreparePreflightError(f"{participant_id}_ID_MISMATCH")
    expected_role = _EXPECTED_ROLES[participant_id]
    if value.get("role") != expected_role:
        raise ProjectionPreparePreflightError(f"{participant_id}_ROLE_MISMATCH")
    source = _validate_source_identity(value.get("source_identity"), participant_id)
    writer = value.get("writer_identity")
    if expected_role == WRITE_ROLE:
        if not isinstance(writer, Mapping):
            raise ProjectionPreparePreflightError(f"{participant_id}_WRITER_IDENTITY_MISSING")
        _exact_keys(writer, _WRITER_KEYS, f"{participant_id}.writer_identity")
        writer_result = {
            "writer_id": _safe_id(writer["writer_id"], f"{participant_id}.writer_id"),
            "writer_instance_id": _safe_id(writer["writer_instance_id"], f"{participant_id}.writer_instance_id"),
            "writer_epoch": _integer(writer["writer_epoch"], f"{participant_id}.writer_epoch"),
            "write_capability": writer["write_capability"],
            "local_atomicity": _text(writer["local_atomicity"], f"{participant_id}.local_atomicity"),
            "writer_schema": _text(writer["writer_schema"], f"{participant_id}.writer_schema"),
            "target_id": _safe_id(writer["target_id"], f"{participant_id}.writer.target_id"),
        }
        if writer_result["write_capability"] is not True or writer_result["local_atomicity"] != "BEFORE_CAS_AFTER_MARKER":
            raise ProjectionPreparePreflightError(f"{participant_id}_WRITER_CAPABILITY_INVALID")
        if writer_result["target_id"] != participant_id:
            raise ProjectionPreparePreflightError(f"{participant_id}_WRITER_TARGET_MISMATCH")
    else:
        if writer is not None:
            raise ProjectionPreparePreflightError("KNOWLEDGE_LEDGER_WRITER_FORBIDDEN")
        writer_result = None

    observations = value.get("observations")
    if not isinstance(observations, list) or len(observations) != 2:
        raise ProjectionPreparePreflightError(f"{participant_id}_DOUBLE_OBSERVATION_REQUIRED")
    expected_before = intent["participants"][participant_id].get("expected_before")
    expected_after = intent["participants"][participant_id].get("expected_after")
    if not isinstance(expected_before, Mapping) or not isinstance(expected_after, Mapping):
        raise ProjectionPreparePreflightError(f"{participant_id}_INTENT_STATES_INVALID", recovery_required=True)
    normalized_observations: list[dict[str, Any]] = []
    observation_ids: set[str] = set()
    observer_instances: set[str] = set()
    cursors: set[str] = set()
    for index, observation in enumerate(observations):
        if not isinstance(observation, Mapping):
            raise ProjectionPreparePreflightError(f"{participant_id}_OBSERVATION_INVALID")
        _exact_keys(observation, _OBSERVATION_KEYS, f"{participant_id}.observation")
        observation_id = _safe_id(observation["observation_id"], f"{participant_id}.observation_id")
        observer_id = _safe_id(observation["observer_id"], f"{participant_id}.observer_id")
        observer_instance_id = _safe_id(observation["observer_instance_id"], f"{participant_id}.observer_instance_id")
        if observation_id in observation_ids or observer_instance_id in observer_instances:
            raise ProjectionPreparePreflightError(f"{participant_id}_OBSERVERS_NOT_INDEPENDENT")
        observation_ids.add(observation_id)
        observer_instances.add(observer_instance_id)
        sequence = _integer(observation["sequence"], f"{participant_id}.sequence", minimum=1)
        observed_at = _integer(observation["observed_at"], f"{participant_id}.observed_at")
        if observed_at > now:
            raise ProjectionPreparePreflightError(f"{participant_id}_OBSERVATION_FROM_FUTURE")
        lease = _validate_lease(observation["lease"], scope=scope, participant_id=participant_id, now=now)
        before = _copy_json(observation["before"], f"{participant_id}.before")
        if before != expected_before:
            raise ProjectionPreparePreflightError(f"{participant_id}_BEFORE_STATE_MISMATCH")
        cursor = _hash64(observation["source_cursor_sha256"], f"{participant_id}.source_cursor_sha256")
        cursors.add(cursor)
        normalized_observations.append(
            {
                "observation_id": observation_id,
                "observer_id": observer_id,
                "observer_instance_id": observer_instance_id,
                "sequence": sequence,
                "observed_at": observed_at,
                "lease": lease,
                "before": before,
                "source_cursor_sha256": cursor,
            }
        )
        if index == 1 and sequence <= normalized_observations[0]["sequence"]:
            raise ProjectionPreparePreflightError(f"{participant_id}_OBSERVATION_SEQUENCE_NOT_MONOTONIC")
    if len(cursors) != 1:
        raise ProjectionPreparePreflightError(f"{participant_id}_SOURCE_CURSOR_DRIFT")

    cas = value.get("before_state_cas")
    if not isinstance(cas, Mapping):
        raise ProjectionPreparePreflightError(f"{participant_id}_BEFORE_CAS_MISSING")
    _exact_keys(cas, _CAS_KEYS, f"{participant_id}.before_state_cas")
    expected_intent_hash = canonical_hash(intent)
    expected_before_hash = canonical_hash(expected_before)
    expected_after_hash = canonical_hash(expected_after)
    if cas.get("protocol") != "before-state-cas-v1":
        raise ProjectionPreparePreflightError(f"{participant_id}_BEFORE_CAS_PROTOCOL_INVALID")
    for key, expected in (
        ("target_id", participant_id),
        ("transaction_id", intent["transaction_id"]),
        ("receipt_key", intent["receipt_key"]),
        ("idempotency_key", intent["idempotency_key"]),
        ("intent_sha256", expected_intent_hash),
        ("expected_before_sha256", expected_before_hash),
        ("expected_after_sha256", expected_after_hash),
        ("fencing_epoch", scope["fencing_epoch"]),
        ("source_cursor_sha256", next(iter(cursors))),
    ):
        if cas.get(key) != expected:
            raise ProjectionPreparePreflightError(f"{participant_id}_BEFORE_CAS_{key.upper()}_MISMATCH")
    if cas.get("expected_before") != expected_before or cas.get("expected_after") != expected_after:
        raise ProjectionPreparePreflightError(f"{participant_id}_BEFORE_CAS_STATE_MISMATCH")
    if _integer(expected_after.get("version"), f"{participant_id}.expected_after.version") <= _integer(expected_before.get("version"), f"{participant_id}.expected_before.version"):
        raise ProjectionPreparePreflightError(f"{participant_id}_AFTER_VERSION_NOT_ADVANCED")
    if _integer(expected_after.get("generation"), f"{participant_id}.expected_after.generation") <= _integer(expected_before.get("generation"), f"{participant_id}.expected_before.generation"):
        raise ProjectionPreparePreflightError(f"{participant_id}_AFTER_GENERATION_NOT_ADVANCED")
    if expected_after.get("parent_hash") != expected_before.get("state_sha256"):
        raise ProjectionPreparePreflightError(f"{participant_id}_AFTER_PARENT_MISMATCH")
    return {
        "participant_id": participant_id,
        "role": expected_role,
        "operation": _EXPECTED_OPERATIONS[participant_id],
        "source_identity": source,
        "writer_identity": writer_result,
        "observations": normalized_observations,
        "before_state_cas": _copy_json(cas, f"{participant_id}.before_state_cas"),
    }


def evaluate_projection_prepare_preflight(
    journal: ProjectionPreflightJournal,
    *,
    receipt_key: str,
    participant_attestations: Mapping[str, Any],
    now: int,
) -> dict[str, Any]:
    """Read S21 and validate a complete, actionless Projection-Prepare plan."""

    try:
        now = _integer(now, "now")
        scope, receipt, intent = _validate_s21(journal, receipt_key, now=now)
        if not isinstance(participant_attestations, Mapping):
            raise ProjectionPreparePreflightError("PARTICIPANT_ATTESTATIONS_INVALID")
        if set(participant_attestations) != set(PARTICIPANT_IDS):
            raise ProjectionPreparePreflightError("PARTICIPANT_ATTESTATION_SET_INVALID")
        normalized = {
            participant_id: _validate_attestation(
                participant_id,
                participant_attestations[participant_id],
                intent=intent,
                scope=scope,
                now=now,
            )
            for participant_id in sorted(PARTICIPANT_IDS)
        }
        attestations_digest = canonical_hash(normalized)
        writer_set_digest = canonical_hash(
            {
                participant_id: normalized[participant_id]["writer_identity"]
                for participant_id in sorted(WRITE_PARTICIPANTS)
            }
        )
        result = _result(
            PROJECTION_PREPARE_ELIGIBLE,
            "PROJECTION_PREPARE_READ_ONLY_ELIGIBLE",
            transaction_state="PREPARED",
            receipt_key=intent["receipt_key"],
            receipt_id=receipt.get("receipt_id"),
            transaction_id=intent["transaction_id"],
            idempotency_key=intent["idempotency_key"],
            receipt_intent_sha256=receipt.get("receipt_intent_sha256"),
            projection_manifest_sha256=intent["projection_manifest_sha256"],
            projection_set_sha256=intent["projection_set_sha256"],
            participant_attestations_sha256=attestations_digest,
            writer_set_sha256=writer_set_digest,
            s21_status=receipt.get("status"),
        )
        result["participant_ids"] = sorted(PARTICIPANT_IDS)
        result["writer_participant_ids"] = sorted(WRITE_PARTICIPANTS)
        result["observation_participant_ids"] = sorted(OBSERVATION_PARTICIPANTS)
        result["attestation_contract"] = normalized
        result["preflight_digest"] = canonical_hash(
            {
                "schema_version": PROJECTION_PREFLIGHT_SCHEMA,
                "receipt_key": intent["receipt_key"],
                "transaction_id": intent["transaction_id"],
                "receipt_intent_sha256": receipt.get("receipt_intent_sha256"),
                "participant_attestations_sha256": attestations_digest,
                "writer_set_sha256": writer_set_digest,
            }
        )
        return result
    except ProjectionPreparePreflightError as exc:
        status = "RECOVERY_REQUIRED" if exc.recovery_required else "HOLD"
        return _result(status, exc.reason)
    except Exception:  # pragma: no cover - defensive boundary
        return _result("RECOVERY_REQUIRED", "S22_UNEXPECTED_SCHEMA_OR_READBACK_ERROR")


__all__ = [
    "CROSS_STORE_ATOMICITY_NOT_CLAIMED",
    "OBSERVATION_PARTICIPANTS",
    "OBSERVATION_ROLE",
    "PROJECTION_COMMITTED_DEFERRED",
    "PROJECTION_PREPARE_ELIGIBLE",
    "PROJECTION_PREPARE_PENDING_DEFERRED",
    "PROJECTION_PREFLIGHT_ROLE",
    "PROJECTION_PREFLIGHT_SCHEMA",
    "ProjectionPreparePreflightError",
    "WRITE_PARTICIPANTS",
    "WRITE_ROLE",
    "evaluate_projection_prepare_preflight",
]
