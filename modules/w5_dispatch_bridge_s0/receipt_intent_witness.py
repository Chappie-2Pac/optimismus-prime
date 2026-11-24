"""W5-S20 read-only receipt-intent and witness contract.

S19 proves that one S18 owner commit and one frozen five-participant
projection set are internally revalidated.  S20 turns that proof into a
deterministic *future receipt intent* without persisting the intent, emitting
a receipt, reserving an idempotency key, or authorizing consume.  A later
mutating card must re-run S19 immediately before its own commit window.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json

from .cross_store_receipt_provenance import verify_receipt_provenance
from .cross_store_snapshot import (
    CrossStoreSnapshotError,
    SNAPSHOT_PARTICIPANT_IDS,
    evaluate_cross_store_snapshot,
    parse_cross_store_snapshot,
)
from .replay_owner_store import ReplayOwnerStore


RECEIPT_INTENT_WITNESS_SCHEMA = "prime-cross-store-receipt-intent-witness-v1"
RECEIPT_INTENT_WITNESS_ROLE = "cross_store_receipt_intent_witness_read_only"
RECEIPT_INTENT_KIND = "cross_store_provenance"
RECEIPT_INTENT_STATE = "PENDING_SEPARATE_COMMIT"
FUTURE_COMMIT_PHASES = (
    "PREPARED",
    "PROJECTION_PENDING",
    "IN_DOUBT",
    "RECOVERY_REQUIRED",
    "QUARANTINED",
    "COMMITTED",
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_INTENT_KEYS = frozenset(
    {
        "schema_version",
        "contract_role",
        "receipt_key",
        "receipt_kind",
        "receipt_state",
        "transaction_id",
        "idempotency_key",
        "operation",
        "provenance_sha256",
        "s15_authorization_sha256",
        "worker_authorization_sha256",
        "s16_replay_observation_sha256",
        "s16_replay_floor_sha256",
        "s17_preflight_sha256",
        "s17_owner_observation_sha256",
        "s18_result_sha256",
        "s18_transition_sha256",
        "s18_operation_record_sha256",
        "s18_idempotency_index_sha256_after",
        "s18_commit_witness_sha256",
        "s18_head_before_sha256",
        "s18_head_after_sha256",
        "s18_state_version_before",
        "s18_state_version_after",
        "owner_id",
        "owner_instance_id",
        "owner_epoch",
        "fencing_epoch",
        "projection_manifest_sha256",
        "projection_set_sha256",
        "subject_binding",
        "effect_set",
        "participants",
        "future_commit_phases",
        "safety",
    }
)
_SAFETY_KEYS = frozenset(
    {
        "read_only",
        "intent_persisted",
        "receipt_emitted",
        "receipt_committed",
        "consume_allowed",
        "consume_committed",
        "mutation_performed",
        "recovery_started",
        "external_action",
    }
)
_SAFETY_FALSE_KEYS = tuple(sorted(_SAFETY_KEYS - {"read_only"}))
_EXECUTION_FALSE = {
    "consume": False,
    "receipt": False,
    "recovery": False,
    "resume": False,
    "reconcile": False,
    "mutation": False,
    "process": False,
    "network": False,
}
_RECOVERY_SNAPSHOT_CODES = frozenset(
    {
        "SNAPSHOT_SOURCE_DRIFT",
        "SNAPSHOT_TOCTOU_DETECTED",
        "SNAPSHOT_FENCE_DRIFT",
        "SNAPSHOT_LEASE_EXPIRED",
        "SNAPSHOT_CAPTURE_COHORT_INVALID",
    }
)


class ReceiptIntentWitnessError(ValueError):
    """Internal S20 validation failure; public output remains actionless."""

    def __init__(self, reason: str, *, recovery: bool = False) -> None:
        self.reason = reason
        self.recovery = recovery
        super().__init__(reason)


def _actionless(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    result = {
        "schema_version": RECEIPT_INTENT_WITNESS_SCHEMA,
        "contract_role": RECEIPT_INTENT_WITNESS_ROLE,
        "status": status,
        "decision": "HOLD" if status != "RECEIPT_INTENT_REVALIDATED" else "RECEIPT_COMMIT_RECHECK_REQUIRED",
        "reason": reason,
        "authoritative_decision": False,
        "authoritative_prepared": False,
        "permission": "read_only",
        "intent_derived": False,
        "witness_validated": False,
        "intent_persisted": False,
        "receipt_emitted": False,
        "receipt_committed": False,
        "mutation_allowed": False,
        "mutation_window_open": False,
        "mutation_performed": False,
        "idempotency_reserved": False,
        "consume_allowed": False,
        "consume_committed": False,
        "cas_authorized": False,
        "recovery_allowed": False,
        "recovery_started": False,
        "resume_allowed": False,
        "external_action": False,
        "execution": dict(_EXECUTION_FALSE),
    }
    result.update(extra)
    return result


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ReceiptIntentWitnessError(f"{label}_INVALID")
    return value


def _hash64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ReceiptIntentWitnessError(f"{label}_INVALID")
    return value


def _copy_json(value: Any, label: str) -> Any:
    try:
        isolated = copy.deepcopy(value)
        canonical_json(isolated)
        return isolated
    except (TypeError, ValueError, copy.Error) as exc:
        raise ReceiptIntentWitnessError(f"{label}_INVALID") from exc


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def parse_receipt_intent(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Parse and isolate one caller-supplied future receipt intent."""

    if value is None:
        raise ReceiptIntentWitnessError("INTENT_MISSING")
    if isinstance(value, Mapping):
        return _copy_json(dict(value), "intent")
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReceiptIntentWitnessError("INTENT_JSON_INVALID") from exc
    if not isinstance(value, str):
        raise ReceiptIntentWitnessError("INTENT_JSON_INVALID")
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except _DuplicateJsonKey as exc:
        raise ReceiptIntentWitnessError("INTENT_JSON_DUPLICATE_KEY") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ReceiptIntentWitnessError("INTENT_JSON_INVALID") from exc
    if not isinstance(parsed, dict):
        raise ReceiptIntentWitnessError("INTENT_SCHEMA_INVALID")
    return _copy_json(parsed, "intent")


def _validate_safety(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SAFETY_KEYS:
        raise ReceiptIntentWitnessError("INTENT_SAFETY_INVALID")
    if value.get("read_only") is not True or any(value.get(key) is not False for key in _SAFETY_FALSE_KEYS):
        raise ReceiptIntentWitnessError("INTENT_SAFETY_UNSAFE")
    return {key: bool(value[key]) for key in sorted(value)}


def _expected_participants(evaluated: Mapping[str, Any]) -> dict[str, Any]:
    fixture = evaluated.get("fixture")
    if not isinstance(fixture, Mapping):
        raise ReceiptIntentWitnessError("PROJECTION_FIXTURE_MISSING", recovery=True)
    participants = fixture.get("participants")
    if not isinstance(participants, Mapping) or set(participants) != set(SNAPSHOT_PARTICIPANT_IDS):
        raise ReceiptIntentWitnessError("PROJECTION_PARTICIPANTS_INVALID", recovery=True)
    return _copy_json(dict(participants), "participants")


def _expected_intent(
    intent: Mapping[str, Any],
    *,
    provenance: Mapping[str, Any],
    evaluated: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    if set(intent) != _INTENT_KEYS:
        raise ReceiptIntentWitnessError("INTENT_SCHEMA_INVALID")
    if intent["schema_version"] != RECEIPT_INTENT_WITNESS_SCHEMA or intent["contract_role"] != RECEIPT_INTENT_WITNESS_ROLE:
        raise ReceiptIntentWitnessError("INTENT_SCHEMA_INVALID")
    if intent["receipt_kind"] != RECEIPT_INTENT_KIND or intent["receipt_state"] != RECEIPT_INTENT_STATE:
        raise ReceiptIntentWitnessError("INTENT_STATE_INVALID")
    core = provenance.get("provenance_core")
    if not isinstance(core, Mapping) or canonical_hash(core) != provenance.get("provenance_sha256"):
        raise ReceiptIntentWitnessError("S19_PROVENANCE_DIGEST_INVALID", recovery=True)
    receipt_key = _safe_id(intent["receipt_key"], "RECEIPT_KEY")
    if receipt_key == core.get("idempotency_key"):
        raise ReceiptIntentWitnessError("RECEIPT_KEYSPACE_COLLISION")
    s16 = core.get("s16")
    s17 = core.get("s17")
    s18 = core.get("s18")
    projection = core.get("projection")
    witness = s18.get("owner_commit_witness") if isinstance(s18, Mapping) else None
    if not isinstance(s16, Mapping) or not isinstance(s17, Mapping) or not isinstance(s18, Mapping) or not isinstance(projection, Mapping) or not isinstance(witness, Mapping):
        raise ReceiptIntentWitnessError("S19_PROVENANCE_INCOMPLETE", recovery=True)
    direct_bindings = {
        "transaction_id": core["transaction_id"],
        "idempotency_key": core["idempotency_key"],
        "operation": core["operation"],
        "provenance_sha256": provenance["provenance_sha256"],
        "s15_authorization_sha256": s16["s15_authorization_sha256"],
        "worker_authorization_sha256": s16["worker_authorization_sha256"],
        "s16_replay_observation_sha256": s16["s16_replay_observation_sha256"],
        "s16_replay_floor_sha256": s16["s16_replay_floor_sha256"],
        "s17_preflight_sha256": s17["preflight_sha256"],
        "s17_owner_observation_sha256": s17["owner_observation_sha256"],
        "s18_result_sha256": s18["result_sha256"],
        "s18_transition_sha256": s18["transition_sha256"],
        "s18_operation_record_sha256": s18["operation_record_sha256"],
        "s18_idempotency_index_sha256_after": s18["idempotency_index_sha256_after"],
        "s18_commit_witness_sha256": s18["owner_commit_witness_sha256"],
        "s18_head_before_sha256": s18["head_before_sha256"],
        "s18_head_after_sha256": s18["head_after_sha256"],
        "s18_state_version_before": s18["state_version_before"],
        "s18_state_version_after": s18["state_version_after"],
        "owner_id": witness["revalidation_state"]["owner_id"],
        "owner_instance_id": witness["revalidation_state"]["owner_instance_id"],
        "owner_epoch": witness["revalidation_state"]["owner_epoch"],
        "fencing_epoch": s18["fencing_epoch"],
        "projection_manifest_sha256": projection["projection_manifest_sha256"],
        "projection_set_sha256": projection["projection_set_sha256"],
    }
    for key, expected in direct_bindings.items():
        actual = intent.get(key)
        if actual != expected:
            raise ReceiptIntentWitnessError(f"INTENT_{key.upper()}_DRIFT")
        if key.endswith("sha256"):
            _hash64(actual, key)
    subject_binding = evaluated["fixture"]["bindings"]["subject_binding"]
    effect_set = evaluated["fixture"]["bindings"]["effect_set"]
    if canonical_hash(subject_binding) != projection["subject_binding_sha256"]:
        raise ReceiptIntentWitnessError("PROJECTION_SUBJECT_DIGEST_DRIFT", recovery=True)
    if canonical_hash(effect_set) != projection["effect_sha256"]:
        raise ReceiptIntentWitnessError("PROJECTION_EFFECT_DIGEST_DRIFT", recovery=True)
    if intent["subject_binding"] != subject_binding or intent["effect_set"] != effect_set:
        raise ReceiptIntentWitnessError("INTENT_SUBJECT_OR_EFFECT_DRIFT")
    participants = _expected_participants(evaluated)
    if intent["participants"] != participants:
        raise ReceiptIntentWitnessError("INTENT_PARTICIPANT_DRIFT", recovery=True)
    manifest = snapshot.get("expected_projection_manifest")
    if not isinstance(manifest, Mapping) or manifest.get("manifest_sha256") != projection["projection_manifest_sha256"]:
        raise ReceiptIntentWitnessError("PROJECTION_MANIFEST_DRIFT", recovery=True)
    if list(intent["future_commit_phases"]) != list(FUTURE_COMMIT_PHASES):
        raise ReceiptIntentWitnessError("INTENT_COMMIT_PHASES_INVALID")
    _validate_safety(intent["safety"])
    normalized = _copy_json(dict(intent), "intent")
    normalized["receipt_key"] = receipt_key
    normalized["future_commit_phases"] = list(FUTURE_COMMIT_PHASES)
    normalized["safety"] = _validate_safety(intent["safety"])
    return normalized


def verify_receipt_intent_witness(
    store: ReplayOwnerStore,
    *,
    worker_attestations: Mapping[str, Mapping[str, Any]],
    replay_observation: Mapping[str, Any],
    replay_floor: Mapping[str, Any],
    host_runtime_attestation: Mapping[str, Any],
    s15_input: Mapping[str, Any],
    owner_observation: Mapping[str, Any] | bytes | str | None,
    request: Mapping[str, Any],
    cross_store_snapshot: Mapping[str, Any] | bytes | str | None,
    receipt_intent: Mapping[str, Any] | bytes | str | None,
) -> dict[str, Any]:
    """Freshly revalidate S19 and validate one non-persisted receipt intent."""

    provenance = verify_receipt_provenance(
        store,
        worker_attestations=worker_attestations,
        replay_observation=replay_observation,
        replay_floor=replay_floor,
        host_runtime_attestation=host_runtime_attestation,
        s15_input=s15_input,
        owner_observation=owner_observation,
        request=request,
        cross_store_snapshot=cross_store_snapshot,
    )
    if provenance.get("status") != "PROVENANCE_REVALIDATED":
        return _actionless(
            provenance.get("status", "HOLD"),
            f"S19_{provenance.get('reason', 'PROVENANCE_INVALID')}",
            provenance_status=provenance.get("status"),
        )
    try:
        evaluated = evaluate_cross_store_snapshot(cross_store_snapshot)
        snapshot = parse_cross_store_snapshot(cross_store_snapshot)
        intent = parse_receipt_intent(receipt_intent)
        normalized = _expected_intent(intent, provenance=provenance, evaluated=evaluated, snapshot=snapshot)
    except ReceiptIntentWitnessError as exc:
        return _actionless("RECOVERY_REQUIRED" if exc.recovery else "HOLD", exc.reason)
    except CrossStoreSnapshotError as exc:
        return _actionless("RECOVERY_REQUIRED" if exc.code in _RECOVERY_SNAPSHOT_CODES else "HOLD", exc.code)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        return _actionless("HOLD", "S20_SCHEMA_INVALID")
    intent_sha256 = canonical_hash(normalized)
    witness = {
        "schema_version": RECEIPT_INTENT_WITNESS_SCHEMA,
        "receipt_intent_sha256": intent_sha256,
        "receipt_key": normalized["receipt_key"],
        "provenance_sha256": provenance["provenance_sha256"],
        "s18_commit_witness_sha256": normalized["s18_commit_witness_sha256"],
        "projection_manifest_sha256": normalized["projection_manifest_sha256"],
        "projection_set_sha256": normalized["projection_set_sha256"],
        "subject_binding_sha256": canonical_hash(normalized["subject_binding"]),
        "effect_sha256": canonical_hash(normalized["effect_set"]),
        "participant_witness_sha256": canonical_hash(normalized["participants"]),
        "fencing_epoch": normalized["fencing_epoch"],
        "future_commit_phases": list(FUTURE_COMMIT_PHASES),
    }
    return _actionless(
        "RECEIPT_INTENT_REVALIDATED",
        "RECEIPT_INTENT_READY_FOR_SEPARATE_COMMIT",
        provenance_status="PROVENANCE_REVALIDATED",
        intent_derived=True,
        witness_validated=True,
        provenance_sha256=provenance["provenance_sha256"],
        receipt_intent_sha256=intent_sha256,
        receipt_intent=normalized,
        receipt_intent_witness=witness,
        future_commit_requires_fresh_revalidation=True,
    )


__all__ = [
    "FUTURE_COMMIT_PHASES",
    "RECEIPT_INTENT_KIND",
    "RECEIPT_INTENT_STATE",
    "RECEIPT_INTENT_WITNESS_ROLE",
    "RECEIPT_INTENT_WITNESS_SCHEMA",
    "parse_receipt_intent",
    "verify_receipt_intent_witness",
]
