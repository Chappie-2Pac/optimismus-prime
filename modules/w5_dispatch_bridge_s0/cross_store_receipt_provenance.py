"""W5-S19 read-only receipt-provenance revalidation.

This module is the evidence boundary after the S18 owner CAS.  It rechecks
S16/S17, reads an already committed S18 operation through the store's
read-only APIs, and validates the existing S13/S12 frozen projection.  It
returns a canonical provenance core for a later receipt/consume card, but it
never emits a receipt, authorizes consume, repairs recovery, or mutates any
store.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash

from .cross_store_owner import (
    CrossStoreOwnerError,
    OWNER_OPERATION as S17_OWNER_OPERATION,
    OWNER_PREFLIGHT_SCHEMA,
    parse_owner_observation,
    verify_replay_owner_preflight,
)
from .cross_store_snapshot import (
    CROSS_STORE_SNAPSHOT_SCHEMA,
    CrossStoreSnapshotError,
    evaluate_cross_store_snapshot,
    parse_cross_store_snapshot,
)
from .cross_store_worker_attestation import CrossStoreWorkerAttestationError, verify_worker_host_attestation
from .replay_owner_store import (
    OWNER_INTENT_SCHEMA,
    OWNER_OPERATION,
    OWNER_OPERATION_RECORD_SCHEMA,
    OWNER_STORE_SCHEMA,
    OWNER_TRANSITION_SCHEMA,
    SCHEMA_FINGERPRINT,
    ReplayOwnerStore,
    ReplayOwnerStoreError,
)


RECEIPT_PROVENANCE_SCHEMA = "prime-cross-store-receipt-provenance-authorization-v1"
RECEIPT_PROVENANCE_ROLE = "cross_store_receipt_provenance_read_only"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_SCOPE_BINDING_KEYS = (
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
)
_RECOVERY_OWNER_CODES = frozenset({"OWNER_ACTIVE_TRANSACTION", "OWNER_JOURNAL_NOT_CLEAN"})


class ReceiptProvenanceError(ValueError):
    """Internal S19 validation failure; public evaluation remains actionless."""

    def __init__(self, reason: str, *, recovery: bool = False) -> None:
        self.reason = reason
        self.recovery = recovery
        super().__init__(reason)


def _actionless(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    result = {
        "schema_version": RECEIPT_PROVENANCE_SCHEMA,
        "contract_role": RECEIPT_PROVENANCE_ROLE,
        "status": status,
        "decision": "HOLD" if status != "PROVENANCE_REVALIDATED" else "ATOMIC_CONSUME_RECHECK_REQUIRED",
        "reason": reason,
        "authoritative_decision": False,
        "permission": "read_only",
        "mutation_allowed": False,
        "mutation_performed": False,
        "receipt_emitted": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "recovery_allowed": False,
        "resume_allowed": False,
        "external_action": False,
        "execution": {
            "consume": False,
            "receipt": False,
            "recovery": False,
            "resume": False,
            "reconcile": False,
            "mutation": False,
            "process": False,
            "network": False,
        },
    }
    result.update(extra)
    return result


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ReceiptProvenanceError(f"{label} is not a safe identifier")
    return value


def _hash64(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ReceiptProvenanceError(f"{label} is not a lowercase SHA-256")
    return value


def _readonly_s17(proof: Mapping[str, Any], owner: Mapping[str, Any]) -> dict[str, Any]:
    if (
        proof.get("schema_version") != OWNER_PREFLIGHT_SCHEMA
        or proof.get("status") != "OWNER_PREVIEW_ONLY"
        or proof.get("decision") != "CAS_RECHECK_REQUIRED"
        or proof.get("authoritative_decision") is not False
        or proof.get("owner_state_advanced") is not False
        or proof.get("idempotency_reserved") is not False
        or proof.get("cas_authorized") is not False
        or proof.get("consume_allowed") is not False
        or proof.get("owner_cas_required") is not True
    ):
        raise ReceiptProvenanceError("S17_PROVENANCE_DRIFT")
    candidate = proof.get("candidate")
    if not isinstance(candidate, Mapping) or not isinstance(owner, Mapping):
        raise ReceiptProvenanceError("S17_PROVENANCE_DRIFT")
    if candidate.get("operation") != S17_OWNER_OPERATION or candidate.get("operation") != OWNER_OPERATION:
        raise ReceiptProvenanceError("S17_OPERATION_MISMATCH")
    if candidate.get("owner_id") != owner.get("owner_id") or candidate.get("owner_instance_id") != owner.get("owner_instance_id"):
        raise ReceiptProvenanceError("S17_OWNER_IDENTITY_MISMATCH")
    return copy.deepcopy(dict(candidate))


def _scope_binding(candidate: Mapping[str, Any], owner: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return {key: copy.deepcopy(candidate[key] if key in candidate else owner[key]) for key in _SCOPE_BINDING_KEYS}
    except KeyError as exc:
        raise ReceiptProvenanceError("S17_SCOPE_BINDING_INCOMPLETE") from exc


def _expected_s18_intent_hash(
    store: ReplayOwnerStore,
    *,
    candidate: Mapping[str, Any],
    owner: Mapping[str, Any],
    proof: Mapping[str, Any],
) -> str:
    binding = _scope_binding(candidate, owner)
    intent = {
        "schema_version": "prime-cross-store-replay-owner-s17-intent-v1",
        "s17_preflight_sha256": proof["preflight_sha256"],
        "owner_observation_sha256": proof["owner_observation_sha256"],
        "worker_authorization_sha256": proof["worker_authorization_sha256"],
        "s16_replay_observation_sha256": proof["s16_replay_observation_sha256"],
        "s16_replay_floor_sha256": proof["s16_replay_floor_sha256"],
        "candidate": copy.deepcopy(dict(candidate)),
    }
    material = {
        "schema_version": OWNER_INTENT_SCHEMA,
        "scope_id": store.scope_id,
        "scope_binding_sha256": canonical_hash(binding),
        "transaction_id": candidate["transaction_id"],
        "idempotency_key": candidate["idempotency_key"],
        "operation": OWNER_OPERATION,
        "intent": intent,
        "expected_state_version": candidate["expected_state_version"],
        "expected_head_sha256": candidate["parent_owner_head_sha256"],
        "expected_sequence": candidate["expected_sequence"],
        "next_sequence": candidate["next_sequence"],
        "next_attestation_set_sha256": candidate["next_attestation_set_sha256"],
        "next_nonce_sha256": candidate["next_nonce_sha256"],
        "expected_next_head_sha256": None,
    }
    return canonical_hash(material)


def _revalidate_owner_commit(
    store: ReplayOwnerStore,
    *,
    candidate: Mapping[str, Any],
    owner: Mapping[str, Any],
    proof: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        state_before = store.read_state(store.scope_id)
        resolution = store.resolve_operation(store.scope_id, candidate["idempotency_key"])
        state_after = store.read_state(store.scope_id)
    except ReplayOwnerStoreError as exc:
        raise ReceiptProvenanceError("OWNER_INTEGRITY_FAILURE", recovery=True) from exc
    if state_before != state_after:
        raise ReceiptProvenanceError("OWNER_REVALIDATION_RACE")
    if state_after.get("journal_status") != "CLEAN":
        raise ReceiptProvenanceError("OWNER_JOURNAL_QUARANTINED", recovery=True)
    if resolution.get("status") != "REPLAYED":
        raise ReceiptProvenanceError("OWNER_COMMIT_NOT_FOUND", recovery=True)
    original = resolution.get("original_result")
    if not isinstance(original, Mapping):
        raise ReceiptProvenanceError("OWNER_RESULT_DRIFT", recovery=True)
    if original.get("status") != "OWNER_CAS_COMMITTED":
        raise ReceiptProvenanceError("OWNER_RESULT_NOT_COMMITTED", recovery=True)
    if original.get("intent_sha256") != _expected_s18_intent_hash(store, candidate=candidate, owner=owner, proof=proof):
        raise ReceiptProvenanceError("OWNER_INTENT_CONFLICT")
    expected = {
        "scope_id": store.scope_id,
        "idempotency_key": candidate["idempotency_key"],
        "transaction_id": candidate["transaction_id"],
        "operation": OWNER_OPERATION,
        "state_version_before": candidate["expected_state_version"],
        "state_version_after": candidate["expected_state_version"] + 1,
        "sequence_before": candidate["expected_sequence"],
        "sequence_after": candidate["next_sequence"],
        "head_before_sha256": candidate["parent_owner_head_sha256"],
        "fencing_epoch": candidate["owner_fencing_epoch"],
    }
    for key, value in expected.items():
        if original.get(key) != value:
            raise ReceiptProvenanceError("OWNER_RESULT_DRIFT", recovery=True)
    if state_after["scope_binding"] != _scope_binding(candidate, owner):
        raise ReceiptProvenanceError("OWNER_SCOPE_DRIFT", recovery=True)
    state_expectations = {
        "state_version": expected["state_version_after"],
        "sequence": expected["sequence_after"],
        "attestation_set_sha256": candidate["next_attestation_set_sha256"],
        "nonce_sha256": candidate["next_nonce_sha256"],
        "owner_id": owner["owner_id"],
        "owner_instance_id": owner["owner_instance_id"],
        "owner_epoch": owner["owner_epoch"],
        "fencing_epoch": candidate["owner_fencing_epoch"],
        "head_sha256": original.get("head_after_sha256"),
        "idempotency_index_sha256": original.get("idempotency_index_sha256_after"),
    }
    if any(state_after.get(key) != value for key, value in state_expectations.items()):
        raise ReceiptProvenanceError("OWNER_STATE_MOVED", recovery=True)
    if int(original["state_version_after"]) <= int(state_after["baseline_state_version"]):
        raise ReceiptProvenanceError("OWNER_BASELINE_ONLY", recovery=True)
    if int(state_after["baseline_state_version"]) != int(original["state_version_before"]):
        raise ReceiptProvenanceError("OWNER_BASELINE_DRIFT", recovery=True)
    stored_result = dict(original)
    result_record_hash = stored_result.pop("operation_record_sha256", None)
    stored_result.pop("idempotency_index_sha256_after", None)
    result_sha256 = canonical_hash(stored_result)
    _hash64(result_record_hash, "operation_record_sha256")
    operation_record = {
        "schema_version": OWNER_OPERATION_RECORD_SCHEMA,
        "scope_id": original["scope_id"],
        "idempotency_key": original["idempotency_key"],
        "transaction_id": original["transaction_id"],
        "operation": original["operation"],
        "intent_sha256": original["intent_sha256"],
        "state_version_before": original["state_version_before"],
        "state_version_after": original["state_version_after"],
        "sequence_before": original["sequence_before"],
        "sequence_after": original["sequence_after"],
        "head_before_sha256": original["head_before_sha256"],
        "head_after_sha256": original["head_after_sha256"],
        "fencing_epoch": original["fencing_epoch"],
        "result_sha256": result_sha256,
        "idempotency_index_after_sha256": original["idempotency_index_sha256_after"],
        "transition_sha256": original["transition_sha256"],
    }
    if canonical_hash(operation_record) != result_record_hash:
        raise ReceiptProvenanceError("OWNER_OPERATION_RECORD_DRIFT", recovery=True)
    transition = {
        "schema_version": OWNER_TRANSITION_SCHEMA,
        "scope_id": original["scope_id"],
        "after_state_version": original["state_version_after"],
        "transaction_id": original["transaction_id"],
        "idempotency_key": original["idempotency_key"],
        "parent_head_sha256": original["head_before_sha256"],
        "new_head_sha256": original["head_after_sha256"],
        "before_state_version": original["state_version_before"],
        "fencing_epoch": original["fencing_epoch"],
        "parent_transition_sha256": original["parent_transition_sha256"],
    }
    if canonical_hash(transition) != original["transition_sha256"]:
        raise ReceiptProvenanceError("OWNER_TRANSITION_DRIFT", recovery=True)
    if original["parent_transition_sha256"] is not None:
        _hash64(original["parent_transition_sha256"], "parent_transition_sha256")
    store_identity_sha256 = canonical_hash(
        {
            "schema_version": OWNER_STORE_SCHEMA,
            "scope_id": store.scope_id,
            "db_path": str(store.db_path.resolve(strict=False)),
        }
    )
    scope_binding = copy.deepcopy(state_after["scope_binding"])
    if canonical_hash(scope_binding) != canonical_hash(_scope_binding(candidate, owner)):
        raise ReceiptProvenanceError("OWNER_SCOPE_DRIFT", recovery=True)
    witness = {
        "schema_version": "prime-cross-store-s18-owner-commit-witness-v1",
        "store_schema_version": OWNER_STORE_SCHEMA,
        "schema_fingerprint": SCHEMA_FINGERPRINT,
        "store_identity_sha256": store_identity_sha256,
        "scope_id": store.scope_id,
        "scope_binding": scope_binding,
        "scope_binding_sha256": canonical_hash(scope_binding),
        "journal_status": state_after["journal_status"],
        "baseline_state_version": state_after["baseline_state_version"],
        "revalidation_state": {
            key: state_after[key]
            for key in (
                "state_version",
                "sequence",
                "attestation_set_sha256",
                "nonce_sha256",
                "head_sha256",
                "idempotency_index_sha256",
                "owner_id",
                "owner_instance_id",
                "owner_epoch",
                "fencing_epoch",
            )
        },
        "operation": {
            key: original[key]
            for key in (
                "scope_id",
                "idempotency_key",
                "transaction_id",
                "operation",
                "intent_sha256",
                "state_version_before",
                "state_version_after",
                "sequence_before",
                "sequence_after",
                "head_before_sha256",
                "head_after_sha256",
                "fencing_epoch",
            )
        },
        "result_sha256": result_sha256,
        "idempotency_index_after_sha256": original["idempotency_index_sha256_after"],
        "transition": transition,
        "transition_sha256": original["transition_sha256"],
        "operation_record": operation_record,
        "operation_record_sha256": result_record_hash,
    }
    _hash64(SCHEMA_FINGERPRINT, "schema_fingerprint")
    _hash64(store_identity_sha256, "store_identity_sha256")
    _hash64(original["idempotency_index_sha256_after"], "idempotency_index_sha256_after")
    _hash64(original["transition_sha256"], "transition_sha256")
    _hash64(result_sha256, "result_sha256")
    return dict(state_after), dict(original), {
        "result_sha256": result_sha256,
        "operation_record": operation_record,
        "witness": witness,
    }


def _projection_binding(snapshot: Mapping[str, Any], evaluated: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    if evaluated.get("status") != "ADAPTED_READ_ONLY":
        status = evaluated.get("status")
        raise ReceiptProvenanceError(
            f"PROJECTION_{evaluated.get('reason', 'INVALID')}",
            recovery=status == "RECOVERY_REQUIRED",
        )
    classification = evaluated.get("classification")
    if not isinstance(classification, Mapping) or classification.get("status") != "COMMITTED" or classification.get("commit_evidence_sufficient_read_only") is not True:
        raise ReceiptProvenanceError("PROJECTION_NOT_COMMITTED", recovery=True)
    if evaluated.get("consume_allowed") is not False or evaluated.get("cas_authorized") is not False or evaluated.get("mutation_allowed") is not False:
        raise ReceiptProvenanceError("PROJECTION_UNSAFE_RESULT")
    for key in ("source_set", "capture"):
        if evaluated.get("source_gates", {}).get(key) is not True:
            raise ReceiptProvenanceError("PROJECTION_GATE_INCOMPLETE")
    if evaluated.get("source_gates", {}).get("safety") is not True or evaluated.get("toctou_gate", {}).get("verified") is not True or evaluated.get("fence_gate", {}).get("live") is not True:
        raise ReceiptProvenanceError("PROJECTION_GATE_INCOMPLETE")
    required_classification = ("bindings_verified", "effect_set_verified", "marker_verified", "marker_phase_verified", "fencing_verified", "trace_verified", "lease_valid")
    if any(classification.get(key) is not True for key in required_classification):
        raise ReceiptProvenanceError("PROJECTION_COMMIT_EVIDENCE_INCOMPLETE", recovery=True)
    fixture = evaluated.get("fixture")
    if not isinstance(fixture, Mapping) or fixture.get("transaction_id") != candidate["transaction_id"]:
        raise ReceiptProvenanceError("PROJECTION_TRANSACTION_MISMATCH")
    if fixture.get("observed_fencing_epoch") != candidate["owner_fencing_epoch"] or fixture.get("fault_hook_or_null") is not None:
        raise ReceiptProvenanceError("PROJECTION_FENCE_OR_FAULT_MISMATCH", recovery=True)
    observations = snapshot.get("observations")
    if not isinstance(observations, Mapping):
        raise ReceiptProvenanceError("PROJECTION_OBSERVATIONS_MISSING", recovery=True)
    manifest = snapshot.get("expected_projection_manifest")
    if not isinstance(manifest, Mapping):
        raise ReceiptProvenanceError("PROJECTION_MANIFEST_MISSING", recovery=True)
    manifest_sha256 = _hash64(manifest.get("manifest_sha256"), "expected_projection_manifest.manifest_sha256")
    records = []
    for participant_id in sorted(observations):
        observation = observations[participant_id]
        if not isinstance(observation, Mapping):
            raise ReceiptProvenanceError("PROJECTION_RECORD_INCOMPLETE", recovery=True)
        bundle = observation.get("observed")
        cursor = observation.get("source_cursor")
        projection = bundle.get("observed") if isinstance(bundle, Mapping) else None
        if not isinstance(bundle, Mapping) or not isinstance(projection, Mapping) or not isinstance(cursor, Mapping):
            raise ReceiptProvenanceError("PROJECTION_RECORD_INCOMPLETE", recovery=True)
        records.append(
            {
                "participant_id": participant_id,
                "source_id": observation["source_id"],
                "source_identity_sha256": observation["source_identity_sha256"],
                "snapshot_id": observation["snapshot_id"],
                "source_cursor_sha256": observation["source_cursor_sha256"],
                "observed_sha256": observation["observed_sha256"],
                "version": projection["version"],
                "generation": projection["generation"],
                "generation_id": projection["generation_id"],
                "state_sha256": projection["state_sha256"],
                "journal_sha256": projection["journal_sha256"],
                "parent_hash": projection["parent_hash"],
            }
        )
    projection_set_sha256 = canonical_hash(records)
    return {
        "schema_version": CROSS_STORE_SNAPSHOT_SCHEMA,
        "transaction_id": candidate["transaction_id"],
        "snapshot_envelope_sha256": evaluated["snapshot_envelope_sha256"],
        "fixture_sha256": evaluated["fixture_sha256"],
        "hook_trace_sha256": fixture["hook_trace_digest"],
        "participant_observations_sha256": fixture["observed_participant_observations_sha256"],
        "effect_sha256": fixture["observed_effect_digest"],
        "fencing_epoch": fixture["observed_fencing_epoch"],
        "projection_manifest_sha256": manifest_sha256,
        "capture_id": snapshot["capture"]["capture_id"],
        "capture_sequence_no": snapshot["capture"]["sequence_no"],
        "barrier_id": snapshot["capture"]["barrier_id"],
        "source_set_sha256": snapshot["source_set_sha256"],
        "projection_set_sha256": projection_set_sha256,
        "participants": records,
        "subject_binding_sha256": canonical_hash(fixture["bindings"]["subject_binding"]),
    }


def verify_receipt_provenance(
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
) -> dict[str, Any]:
    """Revalidate S16/S17/S18 and frozen projections without authorizing action."""

    try:
        s16_proof = verify_worker_host_attestation(
            worker_attestations=worker_attestations,
            replay_observation=replay_observation,
            replay_floor=replay_floor,
            host_runtime_attestation=host_runtime_attestation,
            s15_input=s15_input,
        )
        worker_authorization = s16_proof.get("worker_authorization")
        if (
            s16_proof.get("read_only") is not True
            or s16_proof.get("external_action") is not False
            or not isinstance(worker_authorization, Mapping)
        ):
            raise ReceiptProvenanceError("S16_PROVENANCE_DRIFT")
        proof = verify_replay_owner_preflight(
            worker_attestations=worker_attestations,
            replay_observation=replay_observation,
            replay_floor=replay_floor,
            host_runtime_attestation=host_runtime_attestation,
            s15_input=s15_input,
            owner_observation=owner_observation,
            request=request,
        )
        if s16_proof.get("worker_authorization_sha256") != proof.get("worker_authorization_sha256"):
            raise ReceiptProvenanceError("S16_S17_AUTHORIZATION_MISMATCH")
        s15_authorization_sha256 = _hash64(
            worker_authorization.get("s15_authorization_sha256"),
            "s15_authorization_sha256",
        )
        parsed_owner = parse_owner_observation(owner_observation)
        owner = parsed_owner["payload"]
        candidate = _readonly_s17(proof, owner)
        evaluated_projection = evaluate_cross_store_snapshot(cross_store_snapshot)
        normalized_snapshot = parse_cross_store_snapshot(cross_store_snapshot)
        projection = _projection_binding(normalized_snapshot, evaluated_projection, candidate)
        state, original, record = _revalidate_owner_commit(store, candidate=candidate, owner=owner, proof=proof)
    except ReceiptProvenanceError as exc:
        return _actionless("RECOVERY_REQUIRED" if exc.recovery else "HOLD", exc.reason)
    except CrossStoreWorkerAttestationError as exc:
        return _actionless("HOLD", getattr(exc, "code", "S16_PROVENANCE_INVALID"))
    except CrossStoreOwnerError as exc:
        return _actionless("RECOVERY_REQUIRED" if getattr(exc, "code", "") in _RECOVERY_OWNER_CODES else "HOLD", getattr(exc, "code", "S17_PROVENANCE_INVALID"))
    except CrossStoreSnapshotError as exc:
        return _actionless("RECOVERY_REQUIRED" if exc.code.startswith("SNAPSHOT_") and exc.code in {"SNAPSHOT_SOURCE_DRIFT", "SNAPSHOT_TOCTOU_DETECTED", "SNAPSHOT_FENCE_DRIFT", "SNAPSHOT_LEASE_EXPIRED", "SNAPSHOT_CAPTURE_COHORT_INVALID"} else "HOLD", exc.code)
    except (AttributeError, KeyError, TypeError, ValueError, ReplayOwnerStoreError):
        return _actionless("HOLD", "S19_SCHEMA_INVALID")

    core = {
        "schema_version": RECEIPT_PROVENANCE_SCHEMA,
        "transaction_id": candidate["transaction_id"],
        "idempotency_key": candidate["idempotency_key"],
        "operation": OWNER_OPERATION,
        "s16": {
            "s15_authorization_sha256": s15_authorization_sha256,
            "worker_authorization_sha256": proof["worker_authorization_sha256"],
            "s16_replay_observation_sha256": proof["s16_replay_observation_sha256"],
            "s16_replay_floor_sha256": proof["s16_replay_floor_sha256"],
        },
        "s17": {
            "preflight_sha256": proof["preflight_sha256"],
            "owner_observation_sha256": proof["owner_observation_sha256"],
            "candidate": copy.deepcopy(candidate),
        },
        "s18": {
            "result_sha256": record["result_sha256"],
            "transition_sha256": original["transition_sha256"],
            "operation_record_sha256": original["operation_record_sha256"],
            "idempotency_index_sha256_after": original["idempotency_index_sha256_after"],
            "state_version_before": original["state_version_before"],
            "state_version_after": original["state_version_after"],
            "head_before_sha256": original["head_before_sha256"],
            "head_after_sha256": original["head_after_sha256"],
            "fencing_epoch": original["fencing_epoch"],
            "owner_commit_witness": record["witness"],
            "owner_commit_witness_sha256": canonical_hash(record["witness"]),
        },
        "projection": projection,
    }
    provenance_sha256 = canonical_hash(core)
    return _actionless(
        "PROVENANCE_REVALIDATED",
        "OWNER_AND_PROJECTIONS_REVALIDATED",
        owner_resolution_status="REPLAYED",
        owner_state_version=state["state_version"],
        owner_head_sha256=state["head_sha256"],
        projection_status="COMMITTED_READ_ONLY",
        receipt_provenance_status="READY_FOR_SEPARATE_RECEIPT_COMMIT",
        provenance_sha256=provenance_sha256,
        provenance_core=core,
        result_sha256=record["result_sha256"],
        transition_sha256=original["transition_sha256"],
        operation_record_sha256=original["operation_record_sha256"],
        projection_set_sha256=projection["projection_set_sha256"],
    )


__all__ = ["RECEIPT_PROVENANCE_ROLE", "RECEIPT_PROVENANCE_SCHEMA", "verify_receipt_provenance"]
