"""W5-S25 read-only handoff/fence-rotation preflight.

This module observes a fully materialized S24 scope/operation/transaction
snapshot and validates a proposed handoff grant without accepting it.  It
never changes the queue, the Queue-Writer database, a transaction marker, an
owner, a lease or a fencing epoch.  A structurally valid candidate remains a
preview until a separate trusted authority and an atomic S25-B writer exist.
"""

from __future__ import annotations

import copy
import hashlib
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json


HANDOFF_PREFLIGHT_SCHEMA = "prime-queue-handoff-preflight-v1"
HANDOFF_PREFLIGHT_ROLE = "queue_handoff_preflight_read_only"
HANDOFF_OBSERVATION_SCHEMA = "prime-queue-handoff-observation-v1"
HANDOFF_PREVIEW_ONLY = "HANDOFF_PREVIEW_ONLY"
HANDOFF_RECHECK_REQUIRED = "HANDOFF_RECHECK_REQUIRED"
HANDOFF_HOLD = "HOLD"
HANDOFF_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
CROSS_STORE_ATOMICITY_NOT_CLAIMED = "NOT_CLAIMED"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_HANDOFF_KINDS = frozenset({"COOPERATIVE_RELEASE", "AUTHORIZED_TERMINATION", "ADJUDICATED_RECOVERY"})
_ACTIVE_PHASES = frozenset({"PREPARED", "EXECUTING", "RECOVERY"})
_ACTIVE_STATES = frozenset({"PREPARED", "IN_DOUBT", "RECOVERY_REQUIRED"})
_TRANSACTION_STATES = frozenset({"EXACT", "INVALID", "MALFORMED", "FOREIGN", "UNKNOWN"})
_TERMINAL_MARKERS = frozenset({"ABSENT", "COMMITTED", "ABORTED"})

_ROOT_KEYS = frozenset({"root_binding_sha256", "active_scope_id", "active_fencing_epoch"})
_SCOPE_KEYS = frozenset(
    {
        "scope_id",
        "root_binding_sha256",
        "owner_id",
        "owner_instance_id",
        "owner_epoch",
        "fencing_epoch",
        "lease_token_sha256",
        "lease_expires_at",
        "scope_status",
        "active_operation_id",
        "active_phase",
        "event_seq",
    }
)
_OPERATION_KEYS = frozenset(
    {
        "transaction_id",
        "idempotency_key",
        "intent_sha256",
        "state",
        "expected_queue_sha256",
        "after_queue_sha256",
    }
)
_TRANSACTION_KEYS = frozenset(
    {"status", "manifest_sha256", "before_sha256", "after_sha256", "queue_sha256", "terminal_marker"}
)
_OBSERVATION_KEYS = frozenset(
    {
        "schema_version",
        "observation_id",
        "observed_at",
        "root_binding_sha256",
        "root",
        "scope",
        "operation",
        "transaction",
        "db_integrity",
        "schema_objects_valid",
        "observation_sha256",
    }
)
_GRANT_KEYS = frozenset(
    {
        "schema_version",
        "handoff_id",
        "authority_id",
        "authority_epoch",
        "authority_proof",
        "root_binding_sha256",
        "scope_id",
        "transaction_id",
        "idempotency_key",
        "intent_sha256",
        "expected_active_phase",
        "expected_operation_state",
        "expected_event_seq",
        "old_owner_id",
        "old_owner_instance_id",
        "old_owner_epoch",
        "old_fencing_epoch",
        "old_lease_token_sha256",
        "old_lease_expires_at",
        "new_owner_id",
        "new_owner_instance_id",
        "new_owner_epoch",
        "new_fencing_epoch",
        "new_lease_token_sha256",
        "new_lease_expires_at",
        "handoff_kind",
        "liveness_evidence_sha256",
        "reason",
        "issued_at",
    }
)


class HandoffPreflightError(ValueError):
    """Malformed observation or candidate grant; no mutation is authorized."""

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
        raise HandoffPreflightError(f"{label}_NOT_CANONICAL") from exc


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise HandoffPreflightError(f"{label}_INVALID")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise HandoffPreflightError(f"{label}_INVALID")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise HandoffPreflightError(f"{label}_INVALID")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise HandoffPreflightError(f"{label}_INVALID")
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    if set(value) != set(expected):
        raise HandoffPreflightError(f"{label}_KEYS_INVALID")


def _result(
    status: str,
    reason: str,
    *,
    observation_sha256: str | None = None,
    candidate_sha256: str | None = None,
) -> dict[str, Any]:
    preview = status == HANDOFF_PREVIEW_ONLY
    return {
        "schema_version": HANDOFF_PREFLIGHT_SCHEMA,
        "contract_role": HANDOFF_PREFLIGHT_ROLE,
        "status": status,
        "decision": HANDOFF_RECHECK_REQUIRED if preview else "HOLD",
        "reason": reason,
        "permission": "read_only_handoff_preflight",
        "observation_sha256": observation_sha256,
        "candidate_sha256": candidate_sha256,
        "observation_verified": False,
        "source_attestation": "SELF_CONSISTENT_CLAIM_ONLY",
        "handoff_preview_eligible": preview,
        "authority_verified": False,
        "handoff_allowed": False,
        "mutation_allowed": False,
        "owner_rotation_performed": False,
        "queue_mutation_performed": False,
        "recovery_allowed": False,
        "resume_allowed": False,
        "receipt_emitted": False,
        "receipt_committed": False,
        "consume_allowed": False,
        "cross_store_atomicity": CROSS_STORE_ATOMICITY_NOT_CLAIMED,
        "execution": {
            "observation_read": True,
            "handoff_writer": False,
            "scope_write": False,
            "queue_write": False,
            "marker_write": False,
            "recovery": False,
            "network": False,
        },
    }


def _observation_digest(observation: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in observation.items() if key != "observation_sha256"}
    return canonical_hash(unsigned)


def build_handoff_observation(
    *,
    observation_id: str,
    observed_at: int,
    root: Mapping[str, Any],
    scope: Mapping[str, Any],
    operation: Mapping[str, Any],
    transaction: Mapping[str, Any],
    db_integrity: str = "OK",
    schema_objects_valid: bool = True,
) -> dict[str, Any]:
    """Create a canonical read-only observation from already-read state."""

    for value, label in ((root, "root"), (scope, "scope"), (operation, "operation"), (transaction, "transaction")):
        if not isinstance(value, Mapping):
            raise HandoffPreflightError(f"{label}_INVALID")
    if type(schema_objects_valid) is not bool:
        raise HandoffPreflightError("schema_objects_valid_INVALID")
    observation = {
        "schema_version": HANDOFF_OBSERVATION_SCHEMA,
        "observation_id": _safe_id(observation_id, "observation_id"),
        "observed_at": _integer(observed_at, "observed_at"),
        "root_binding_sha256": _hash64(root.get("root_binding_sha256"), "root_binding_sha256"),
        "root": _copy_json(root, "root"),
        "scope": _copy_json(scope, "scope"),
        "operation": _copy_json(operation, "operation"),
        "transaction": _copy_json(transaction, "transaction"),
        "db_integrity": _text(db_integrity, "db_integrity"),
        "schema_objects_valid": schema_objects_valid is True,
    }
    observation["observation_sha256"] = _observation_digest(observation)
    return observation


def _validate_observation(observation: Mapping[str, Any], *, now: int) -> dict[str, Any]:
    _exact_keys(observation, _OBSERVATION_KEYS, "observation")
    if observation["schema_version"] != HANDOFF_OBSERVATION_SCHEMA:
        raise HandoffPreflightError("OBSERVATION_SCHEMA_INVALID", recovery_required=True)
    _safe_id(observation["observation_id"], "observation_id")
    observed_at = _integer(observation["observed_at"], "observed_at")
    if observed_at > now:
        raise HandoffPreflightError("OBSERVATION_FROM_FUTURE")
    root = observation["root"]
    scope = observation["scope"]
    operation = observation["operation"]
    transaction = observation["transaction"]
    if not all(isinstance(value, Mapping) for value in (root, scope, operation, transaction)):
        raise HandoffPreflightError("OBSERVATION_NESTED_VALUE_INVALID", recovery_required=True)
    _exact_keys(root, _ROOT_KEYS, "root")
    _exact_keys(scope, _SCOPE_KEYS, "scope")
    _exact_keys(operation, _OPERATION_KEYS, "operation")
    _exact_keys(transaction, _TRANSACTION_KEYS, "transaction")
    root_binding = _hash64(observation["root_binding_sha256"], "root_binding_sha256")
    if root_binding != root["root_binding_sha256"] or root_binding != scope["root_binding_sha256"]:
        raise HandoffPreflightError("ROOT_BINDING_DRIFT", recovery_required=True)
    if root["active_scope_id"] != scope["scope_id"]:
        raise HandoffPreflightError("ROOT_SCOPE_DRIFT", recovery_required=True)
    _integer(root["active_fencing_epoch"], "active_fencing_epoch", minimum=1)
    if root["active_fencing_epoch"] != scope["fencing_epoch"]:
        raise HandoffPreflightError("ROOT_FENCE_DRIFT", recovery_required=True)
    _safe_id(scope["scope_id"], "scope_id")
    _safe_id(scope["owner_id"], "owner_id")
    _safe_id(scope["owner_instance_id"], "owner_instance_id")
    _integer(scope["owner_epoch"], "owner_epoch", minimum=1)
    _integer(scope["fencing_epoch"], "fencing_epoch", minimum=1)
    _integer(scope["event_seq"], "event_seq")
    _hash64(scope["lease_token_sha256"], "lease_token_sha256")
    _integer(scope["lease_expires_at"], "lease_expires_at")
    _text(scope["scope_status"], "scope_status")
    if scope["active_operation_id"] != operation["transaction_id"]:
        raise HandoffPreflightError("ACTIVE_OPERATION_DRIFT", recovery_required=True)
    if not isinstance(scope["active_phase"], str) or scope["active_phase"] not in _ACTIVE_PHASES:
        raise HandoffPreflightError("ACTIVE_PHASE_INVALID", recovery_required=True)
    _safe_id(operation["transaction_id"], "transaction_id")
    _safe_id(operation["idempotency_key"], "idempotency_key")
    _hash64(operation["intent_sha256"], "intent_sha256")
    if not isinstance(operation["state"], str) or operation["state"] not in _ACTIVE_STATES:
        raise HandoffPreflightError("OPERATION_STATE_NOT_ACTIVE", recovery_required=True)
    _hash64(operation["expected_queue_sha256"], "expected_queue_sha256")
    _hash64(operation["after_queue_sha256"], "after_queue_sha256")
    if not isinstance(transaction["status"], str) or transaction["status"] not in _TRANSACTION_STATES:
        raise HandoffPreflightError("TRANSACTION_STATUS_INVALID", recovery_required=True)
    _hash64(transaction["manifest_sha256"], "manifest_sha256")
    _hash64(transaction["before_sha256"], "before_sha256")
    _hash64(transaction["after_sha256"], "after_sha256")
    _hash64(transaction["queue_sha256"], "queue_sha256")
    if not isinstance(transaction["terminal_marker"], str) or transaction["terminal_marker"] not in _TERMINAL_MARKERS:
        raise HandoffPreflightError("TRANSACTION_MARKER_INVALID", recovery_required=True)
    if (
        transaction["before_sha256"] != operation["expected_queue_sha256"]
        or transaction["after_sha256"] != operation["after_queue_sha256"]
        or transaction["queue_sha256"] not in {operation["expected_queue_sha256"], operation["after_queue_sha256"]}
    ):
        raise HandoffPreflightError("TRANSACTION_INTENT_BINDING_DRIFT", recovery_required=True)
    if transaction["terminal_marker"] == "COMMITTED" and transaction["queue_sha256"] != operation["after_queue_sha256"]:
        raise HandoffPreflightError("COMMITTED_MARKER_HASH_CONFLICT", recovery_required=True)
    if transaction["terminal_marker"] == "ABORTED" and transaction["queue_sha256"] != operation["expected_queue_sha256"]:
        raise HandoffPreflightError("ABORTED_MARKER_HASH_CONFLICT", recovery_required=True)
    if operation["state"] == "RECOVERY_REQUIRED":
        raise HandoffPreflightError("OPERATION_ALREADY_RECOVERY_REQUIRED", recovery_required=True)
    if observation["db_integrity"] != "OK" or observation["schema_objects_valid"] is not True:
        raise HandoffPreflightError("SOURCE_DB_INTEGRITY_UNAVAILABLE", recovery_required=True)
    if _observation_digest(observation) != observation["observation_sha256"]:
        raise HandoffPreflightError("OBSERVATION_DIGEST_DRIFT", recovery_required=True)
    return dict(observation)


def _validate_grant(
    grant: Mapping[str, Any],
    observation: Mapping[str, Any],
    *,
    new_lease_token: str,
    now: int,
) -> str:
    _exact_keys(grant, _GRANT_KEYS, "handoff_grant")
    if grant["schema_version"] != "prime-queue-handoff-grant-v1":
        raise HandoffPreflightError("HANDOFF_GRANT_SCHEMA_INVALID")
    for key in ("handoff_id", "authority_id", "scope_id", "transaction_id", "idempotency_key"):
        _safe_id(grant[key], key)
    _integer(grant["authority_epoch"], "authority_epoch", minimum=1)
    _text(grant["authority_proof"], "authority_proof")
    for key in (
        "root_binding_sha256",
        "intent_sha256",
        "old_lease_token_sha256",
        "new_lease_token_sha256",
        "liveness_evidence_sha256",
    ):
        _hash64(grant[key], key)
    for key in ("old_owner_id", "old_owner_instance_id", "new_owner_id", "new_owner_instance_id"):
        _safe_id(grant[key], key)
    for key in ("old_owner_epoch", "old_fencing_epoch", "new_owner_epoch", "new_fencing_epoch"):
        _integer(grant[key], key, minimum=1)
    _integer(grant["old_lease_expires_at"], "old_lease_expires_at")
    _integer(grant["new_lease_expires_at"], "new_lease_expires_at")
    _safe_id(grant["expected_active_phase"], "expected_active_phase")
    if grant["expected_active_phase"] not in _ACTIVE_PHASES:
        raise HandoffPreflightError("HANDOFF_EXPECTED_PHASE_INVALID")
    if not isinstance(grant["expected_operation_state"], str) or grant["expected_operation_state"] not in _ACTIVE_STATES:
        raise HandoffPreflightError("HANDOFF_EXPECTED_STATE_INVALID")
    if not isinstance(grant["handoff_kind"], str) or grant["handoff_kind"] not in _HANDOFF_KINDS:
        raise HandoffPreflightError("HANDOFF_KIND_INVALID")
    _text(grant["reason"], "reason")
    _integer(grant["issued_at"], "issued_at")
    if grant["issued_at"] > now:
        raise HandoffPreflightError("HANDOFF_GRANT_FROM_FUTURE")
    scope = observation["scope"]
    operation = observation["operation"]
    if grant["root_binding_sha256"] != observation["root_binding_sha256"]:
        raise HandoffPreflightError("HANDOFF_ROOT_BINDING_MISMATCH")
    if grant["scope_id"] != scope["scope_id"] or grant["transaction_id"] != operation["transaction_id"]:
        raise HandoffPreflightError("HANDOFF_OPERATION_BINDING_MISMATCH")
    if grant["idempotency_key"] != operation["idempotency_key"] or grant["intent_sha256"] != operation["intent_sha256"]:
        raise HandoffPreflightError("HANDOFF_INTENT_BINDING_MISMATCH")
    if grant["expected_active_phase"] != scope["active_phase"] or grant["expected_operation_state"] != operation["state"]:
        raise HandoffPreflightError("HANDOFF_ACTIVE_STATE_DRIFT")
    _integer(grant["expected_event_seq"], "expected_event_seq")
    if grant["expected_event_seq"] != scope["event_seq"]:
        raise HandoffPreflightError("HANDOFF_EVENT_SEQUENCE_DRIFT")
    old_values = {
        "old_owner_id": scope["owner_id"],
        "old_owner_instance_id": scope["owner_instance_id"],
        "old_owner_epoch": scope["owner_epoch"],
        "old_fencing_epoch": scope["fencing_epoch"],
        "old_lease_token_sha256": scope["lease_token_sha256"],
        "old_lease_expires_at": scope["lease_expires_at"],
    }
    if any(grant[key] != value for key, value in old_values.items()):
        raise HandoffPreflightError("HANDOFF_SOURCE_FENCE_STALE")
    if grant["new_fencing_epoch"] != grant["old_fencing_epoch"] + 1:
        raise HandoffPreflightError("HANDOFF_FENCING_EPOCH_NOT_MONOTONIC")
    if grant["new_owner_epoch"] <= grant["old_owner_epoch"]:
        raise HandoffPreflightError("HANDOFF_OWNER_EPOCH_NOT_MONOTONIC")
    if (grant["new_owner_id"], grant["new_owner_instance_id"]) == (
        grant["old_owner_id"],
        grant["old_owner_instance_id"],
    ):
        raise HandoffPreflightError("HANDOFF_OWNER_NOT_FRESH")
    new_lease_token = _text(new_lease_token, "new_lease_token")
    if hashlib.sha256(new_lease_token.encode("utf-8")).hexdigest() != grant["new_lease_token_sha256"]:
        raise HandoffPreflightError("HANDOFF_NEW_LEASE_MISMATCH")
    if len(new_lease_token) < 16:
        raise HandoffPreflightError("HANDOFF_NEW_LEASE_TOO_SHORT")
    if grant["new_lease_token_sha256"] == grant["old_lease_token_sha256"]:
        raise HandoffPreflightError("HANDOFF_LEASE_REUSED")
    if grant["new_lease_expires_at"] <= now:
        raise HandoffPreflightError("HANDOFF_NEW_LEASE_EXPIRED")
    return canonical_hash(
        {
            "grant": {key: grant[key] for key in sorted(grant) if key != "authority_proof"},
            "authority_proof_sha256": hashlib.sha256(grant["authority_proof"].encode("utf-8")).hexdigest(),
        }
    )


def evaluate_handoff_preflight(
    observation: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    new_lease_token: str,
    now: int,
) -> dict[str, Any]:
    """Evaluate a handoff candidate without authorizing or performing it."""

    try:
        now = _integer(now, "now")
        observation_copy = _copy_json(observation, "observation")
        grant_copy = _copy_json(grant, "handoff_grant")
        if not isinstance(observation_copy, Mapping) or not isinstance(grant_copy, Mapping):
            raise HandoffPreflightError("HANDOFF_INPUT_INVALID", recovery_required=True)
        observation_copy = _validate_observation(observation_copy, now=now)
        scope_status = observation_copy["scope"]["scope_status"]
        if not isinstance(scope_status, str) or scope_status not in {"CLEAN", "IN_DOUBT", "RECOVERY_REQUIRED", "QUARANTINED"}:
            raise HandoffPreflightError("SOURCE_SCOPE_STATUS_INVALID", recovery_required=True)
        if scope_status == "RECOVERY_REQUIRED":
            raise HandoffPreflightError("SOURCE_ALREADY_RECOVERY_REQUIRED", recovery_required=True)
        if scope_status != "IN_DOUBT":
            raise HandoffPreflightError("HANDOFF_SCOPE_NOT_IN_DOUBT")
        if observation_copy["transaction"]["status"] != "EXACT":
            raise HandoffPreflightError("HANDOFF_TRANSACTION_NOT_EXACT", recovery_required=True)
        grant_digest = _validate_grant(grant_copy, observation_copy, new_lease_token=new_lease_token, now=now)
        candidate_digest = canonical_hash(
            {
                "observation_sha256": observation_copy["observation_sha256"],
                "grant_sha256": grant_digest,
                "new_lease_token_sha256": grant_copy["new_lease_token_sha256"],
            }
        )
        return _result(
            HANDOFF_PREVIEW_ONLY,
            "STRUCTURAL_HANDOFF_CANDIDATE_REQUIRES_TRUSTED_AUTHORITY_RECHECK",
            observation_sha256=observation_copy["observation_sha256"],
            candidate_sha256=candidate_digest,
        )
    except HandoffPreflightError as exc:
        status = HANDOFF_RECOVERY_REQUIRED if exc.recovery_required else HANDOFF_HOLD
        return _result(status, exc.reason)


__all__ = [
    "HANDOFF_HOLD",
    "HANDOFF_OBSERVATION_SCHEMA",
    "HANDOFF_PREFLIGHT_ROLE",
    "HANDOFF_PREFLIGHT_SCHEMA",
    "HANDOFF_PREVIEW_ONLY",
    "HANDOFF_RECOVERY_REQUIRED",
    "HandoffPreflightError",
    "build_handoff_observation",
    "evaluate_handoff_preflight",
]
