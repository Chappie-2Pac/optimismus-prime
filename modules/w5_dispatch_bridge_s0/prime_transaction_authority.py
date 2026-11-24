"""W5-S11 read-only authoritative transaction contract and recovery classifier.

This is the first safe S11 step.  It validates a caller-supplied mutation
contract and classifies a caller-supplied recovery observation.  It does not
open SQLite, read or write Prime files, acquire a lock, reserve an idempotency
key, recover a journal, or authorize a mutation.  The future executor must
repeat every check against live participants inside its own fenced protocol.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash


PRIME_AUTHORITATIVE_COORDINATOR_SCHEMA = "prime-authoritative-coordinator-v2"
PRIME_AUTHORITATIVE_COORDINATOR_VERIFICATION_SCHEMA = "prime-authoritative-coordinator-verification-v2"
PRIME_AUTHORITATIVE_RECOVERY_SCHEMA = "prime-authoritative-recovery-v1"
PRIME_AUTHORITATIVE_COMMIT_MARKER_SCHEMA = "prime-authoritative-commit-marker-v1"
PRIME_TRANSACTION_AUTHORITY_ROLE = "authoritative_transaction_contract_read_only"
PARTICIPANT_IDS = frozenset({"prime_queue", "prime_ledger", "knowledge_ledger", "control_plane", "receipt_projection"})
EFFECT_MODES = frozenset({"CONTROL_PLANE_ONLY", "PRIME_PROJECTION", "PRIME_CONSUME"})
OPERATIONS = frozenset({"accept_reviewed_card", "consume_card", "project_queue"})
RECOVERY_STATES = frozenset({"PREPARED", "COMMITTING", "IN_DOUBT"})
PARTICIPANT_STATES = frozenset({"BEFORE", "AFTER", "UNKNOWN", "DRIFT"})
JOURNAL_STATES = frozenset({"CLEAN_BEFORE", "CLEAN_AFTER", "OPEN", "DRIFT", "MISSING"})
MARKER_STATES = frozenset({"ABSENT", "VALID", "CONFLICT"})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CONTRACT_KEYS = frozenset(
    {
        "schema_version",
        "contract_role",
        "transaction_id",
        "idempotency_key",
        "operation",
        "effect_mode",
        "subject",
        "subject_binding",
        "provenance",
        "context_gate",
        "continuity_gate",
        "review_binding",
        "subagent_admission",
        "precondition_plan_sha256",
        "participant_observations_sha256",
        "effect_set",
        "effect_digest",
        "expected_before",
        "expected_after",
        "lease",
        "required_rechecks",
        "acceptance_enabled",
        "next_card_intent_id_or_null",
        "safety",
    }
)
_SUBJECT_KEYS = frozenset(
    {
        "project_id",
        "goal_id",
        "run_id",
        "plan_id",
        "plan_version",
        "task_id",
        "card_id",
        "attempt_id",
        "dispatch_id",
        "receipt_id_or_null",
        "review_id_or_null",
    }
)
_SUBJECT_BINDING_KEYS = frozenset(
    {
        "goal_version",
        "goal_hash",
        "non_goals_hash",
        "scope_gate_id",
        "project_profile_hash",
        "path_policy_hash",
        "source_manifest_hash",
        "task_hash",
        "plan_hash",
        "card_hash",
        "source_queue_hash",
        "input_snapshot_id",
        "input_snapshot_hash",
        "context_pack_id",
        "pack_version",
        "base_snapshot_id",
        "context_pack_hash",
    }
)
_PROVENANCE_KEYS = frozenset(
    {
        "repository_id",
        "repository_commit_hash",
        "repository_tree_hash",
        "dirty_tree_manifest_hash",
        "test_manifest_hash",
        "evidence_hash",
        "evidence_set_hash",
        "knowledge_ledger_head_hash",
        "provenance_manifest_hash",
        "derivation_trace_hash",
        "source_refs",
        "source_refs_hash",
        "provenance_status",
        "provenance_digest",
    }
)
_PROVENANCE_STATUS_KEYS = frozenset({"structural_provenance_verified", "content_supported", "temporal_valid", "derivation_traced"})
_CONTEXT_GATE_KEYS = frozenset(
    {
        "context_pack_id",
        "pack_version",
        "base_snapshot_id",
        "compression_version",
        "loss_ledger_hash",
        "context_pack_hash",
        "critical_context_recall",
        "task_loss",
        "decision_loss",
        "blocker_loss",
        "provenance_loss",
        "contradiction_rate",
        "reconstruction_test_id",
        "context_gate_digest",
    }
)
_CONTINUITY_GATE_KEYS = frozenset(
    {
        "run_budget_hash",
        "budget_counters",
        "deadline_policy_hash",
        "deadline_at",
        "heartbeat_deadline_at",
        "last_heartbeat_at",
        "checkpoint_id_or_null",
        "checkpoint_hash",
        "resume_point_id_or_null",
        "last_committed_event_id",
        "progress_signature",
        "progress_signature_count",
        "no_progress_window",
        "retry_budget",
        "error_budget",
        "replan_budget",
        "projection_pending_deadline",
        "continuity_digest",
    }
)
_BUDGET_COUNTER_KEYS = frozenset({"retry", "error", "replan"})
_REVIEW_BINDING_KEYS = frozenset(
    {
        "enabled",
        "review_domain_id_or_null",
        "reviewer_identity_or_null",
        "reviewer_process_identity_or_null",
        "criteria_hash_or_null",
        "review_input_manifest_hash_or_null",
        "review_decision_hash_or_null",
        "scheduler_snapshot_hash_or_null",
        "candidate_set_hash_or_null",
        "selection_policy_hash_or_null",
        "dependency_snapshot_hash_or_null",
        "wave_sequence_no",
        "previous_acceptance_transaction_id_or_null",
    }
)
_SUBAGENT_ADMISSION_KEYS = frozenset(
    {
        "enabled",
        "parent_run_id",
        "parent_attempt_id",
        "child_count",
        "max_children",
        "max_depth",
        "parallelism",
        "role",
        "worker_interface_version",
        "child_run_id_or_null",
        "child_attempt_id_or_null",
        "child_dispatch_id_or_null",
        "child_input_snapshot_hash_or_null",
        "child_context_pack_hash_or_null",
        "capability_set_hash_or_null",
        "path_policy_hash_or_null",
        "resource_budget_hash_or_null",
        "merge_policy_hash_or_null",
        "failure_isolation_policy",
        "expected_utility",
        "estimated_cost",
    }
)
_EFFECT_KEYS = frozenset(
    {"participant_id", "target_id", "operation", "mode", "before_sha256", "after_sha256", "before_version", "after_version"}
)
_EFFECT_OPERATION_POLICY = {
    "CONTROL_PLANE_ONLY": {
        "control_plane": frozenset({"cas", "prepare", "record"}),
        "receipt_projection": frozenset({"record", "seal"}),
    },
    "PRIME_PROJECTION": {
        "control_plane": frozenset({"cas", "prepare"}),
        "prime_queue": frozenset({"replace", "project"}),
        "prime_ledger": frozenset({"replace", "project"}),
        "receipt_projection": frozenset({"record", "seal"}),
    },
    "PRIME_CONSUME": {
        "control_plane": frozenset({"cas", "prepare"}),
        "prime_queue": frozenset({"replace", "consume"}),
        "prime_ledger": frozenset({"replace", "consume"}),
        "receipt_projection": frozenset({"record", "seal"}),
    },
}
_PARTICIPANT_EXPECTATION_KEYS = frozenset({"state_sha256", "journal_sha256", "version", "generation", "parent_hash"})
_LEASE_KEYS = frozenset({"owner_id", "token_sha256", "expires_at", "fencing_epoch"})
_RECHECK_KEYS = frozenset({"atomic_commit", "participant", "queue_journal", "lease", "fencing", "receipts"})
_SAFETY_KEYS = frozenset({"read_only", "lock_held", "reservation", "mutation_performed", "authoritative_commit"})
_RECOVERY_KEYS = frozenset(
    {
        "schema_version",
        "transaction_id",
        "expected_contract_digest",
        "observed_contract_digest",
        "expected_subject_binding_digest",
        "observed_subject_binding_digest",
        "expected_precondition_plan_sha256",
        "observed_precondition_plan_sha256",
        "expected_participant_observations_sha256",
        "observed_participant_observations_sha256",
        "expected_effect_digest",
        "observed_effect_digest",
        "expected_before",
        "expected_after",
        "observed_participants",
        "expected_marker_commitment_sha256",
        "observed_marker_commitment_sha256",
        "observed_state",
        "participant_states",
        "journal_states",
        "marker_states",
        "expected_fencing_epoch",
        "observed_fencing_epoch",
        "lease_valid",
    }
)

AUTHORITY_ERROR_CODES = frozenset(
    {
        "PRIME_TX_AUTHORITY_NOT_OBSERVED",
        "PRIME_TX_AUTHORITY_JSON_INVALID",
        "PRIME_TX_AUTHORITY_JSON_DUPLICATE_KEY",
        "PRIME_TX_AUTHORITY_SCHEMA_INVALID",
        "PRIME_TX_AUTHORITY_UNSAFE_REQUEST",
        "PRIME_TX_AUTHORITY_EFFECT_UNDEFINED",
        "PRIME_TX_AUTHORITY_EFFECT_DIGEST_MISMATCH",
        "PRIME_TX_AUTHORITY_EFFECT_SCOPE_INVALID",
        "PRIME_TX_AUTHORITY_SUBJECT_BINDING_INVALID",
        "PRIME_TX_AUTHORITY_P0_DISABLED",
        "PRIME_TX_AUTHORITY_PRIME_CONSUME_UNIMPLEMENTED",
        "PRIME_TX_AUTHORITY_FENCE_INVALID",
        "PRIME_TX_AUTHORITY_PARTICIPANT_MISMATCH",
        "PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE",
        "PRIME_TX_AUTHORITY_RECOVERY_REQUIRED",
        "PRIME_TX_AUTHORITY_RECOVERY_CONFLICT",
        "PRIME_TX_AUTHORITY_CONTEXT_GATE_INVALID",
        "PRIME_TX_AUTHORITY_PROVENANCE_INVALID",
        "PRIME_TX_AUTHORITY_CONTINUITY_INVALID",
        "PRIME_TX_AUTHORITY_REVIEW_INVALID",
        "PRIME_TX_AUTHORITY_P2_DISABLED",
    }
)


class PrimeTransactionAuthorityError(ValueError):
    """A read-only S11 contract or recovery observation failed closed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in AUTHORITY_ERROR_CODES:
            raise ValueError(f"unknown S11 authority code: {code}")
        self.code = code
        super().__init__(f"{code}: {message}")


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


def parse_authoritative_transaction_contract(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    if value is None:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_NOT_OBSERVED", "transaction contract is missing")
    if isinstance(value, Mapping):
        try:
            return copy.deepcopy(dict(value))
        except (TypeError, ValueError, copy.Error) as exc:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", "contract could not be isolated") from exc
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_JSON_INVALID", "contract is not UTF-8") from exc
    if not isinstance(value, str):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_JSON_INVALID", "contract object or JSON text required")
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except _DuplicateJsonKey as exc:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_JSON_DUPLICATE_KEY", f"duplicate key: {exc}") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_JSON_INVALID", "contract JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", "contract JSON object required")
    return parsed


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _optional_safe_id(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _safe_id(value, label)


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _optional_hash(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _hash64(value, label)


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", f"{label} must be an integer >= 0")
    return value


def _bounded_rate(value: Any, label: str) -> int:
    value = _nonnegative_int(value, label)
    if value > 10_000:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", f"{label} must be between 0 and 10000")
    return value


def _validate_subject(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _SUBJECT_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", "contract subject keys are not exact")
    normalized: dict[str, Any] = {}
    for key in sorted(_SUBJECT_KEYS):
        if key.endswith("_or_null"):
            normalized[key] = _optional_safe_id(value[key], f"subject.{key}")
        else:
            normalized[key] = _safe_id(value[key], f"subject.{key}")
    return normalized


def _validate_subject_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SUBJECT_BINDING_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", "subject_binding keys are not exact")
    return {
        "goal_version": _nonnegative_int(value["goal_version"], "subject_binding.goal_version"),
        "goal_hash": _hash64(value["goal_hash"], "subject_binding.goal_hash"),
        "non_goals_hash": _hash64(value["non_goals_hash"], "subject_binding.non_goals_hash"),
        "scope_gate_id": _safe_id(value["scope_gate_id"], "subject_binding.scope_gate_id"),
        "project_profile_hash": _hash64(value["project_profile_hash"], "subject_binding.project_profile_hash"),
        "path_policy_hash": _hash64(value["path_policy_hash"], "subject_binding.path_policy_hash"),
        "source_manifest_hash": _hash64(value["source_manifest_hash"], "subject_binding.source_manifest_hash"),
        "task_hash": _hash64(value["task_hash"], "subject_binding.task_hash"),
        "plan_hash": _hash64(value["plan_hash"], "subject_binding.plan_hash"),
        "card_hash": _hash64(value["card_hash"], "subject_binding.card_hash"),
        "source_queue_hash": _hash64(value["source_queue_hash"], "subject_binding.source_queue_hash"),
        "input_snapshot_id": _safe_id(value["input_snapshot_id"], "subject_binding.input_snapshot_id"),
        "input_snapshot_hash": _hash64(value["input_snapshot_hash"], "subject_binding.input_snapshot_hash"),
        "context_pack_id": _safe_id(value["context_pack_id"], "subject_binding.context_pack_id"),
        "pack_version": _nonnegative_int(value["pack_version"], "subject_binding.pack_version"),
        "base_snapshot_id": _safe_id(value["base_snapshot_id"], "subject_binding.base_snapshot_id"),
        "context_pack_hash": _hash64(value["context_pack_hash"], "subject_binding.context_pack_hash"),
    }


def _validate_provenance(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _PROVENANCE_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_PROVENANCE_INVALID", "provenance keys are not exact")
    refs = value["source_refs"]
    if not isinstance(refs, list):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_PROVENANCE_INVALID", "source_refs must be a unique list")
    normalized_refs = [_safe_id(ref, f"provenance.source_refs[{index}]") for index, ref in enumerate(refs)]
    if not normalized_refs or len(set(normalized_refs)) != len(normalized_refs):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_PROVENANCE_INVALID", "source_refs must be a unique list")
    status = value["provenance_status"]
    if not isinstance(status, Mapping) or set(status) != _PROVENANCE_STATUS_KEYS or any(item is not True for item in status.values()):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_PROVENANCE_INVALID", "all provenance status gates must be true")
    normalized = {
        "repository_id": _safe_id(value["repository_id"], "provenance.repository_id"),
        "repository_commit_hash": _hash64(value["repository_commit_hash"], "provenance.repository_commit_hash"),
        "repository_tree_hash": _hash64(value["repository_tree_hash"], "provenance.repository_tree_hash"),
        "dirty_tree_manifest_hash": _hash64(value["dirty_tree_manifest_hash"], "provenance.dirty_tree_manifest_hash"),
        "test_manifest_hash": _hash64(value["test_manifest_hash"], "provenance.test_manifest_hash"),
        "evidence_hash": _hash64(value["evidence_hash"], "provenance.evidence_hash"),
        "evidence_set_hash": _hash64(value["evidence_set_hash"], "provenance.evidence_set_hash"),
        "knowledge_ledger_head_hash": _hash64(value["knowledge_ledger_head_hash"], "provenance.knowledge_ledger_head_hash"),
        "provenance_manifest_hash": _hash64(value["provenance_manifest_hash"], "provenance.provenance_manifest_hash"),
        "derivation_trace_hash": _hash64(value["derivation_trace_hash"], "provenance.derivation_trace_hash"),
        "source_refs": sorted(normalized_refs),
        "provenance_status": {key: True for key in sorted(_PROVENANCE_STATUS_KEYS)},
    }
    source_refs_hash = _hash64(value["source_refs_hash"], "provenance.source_refs_hash")
    if source_refs_hash != canonical_hash(normalized_refs):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_PROVENANCE_INVALID", "source_refs_hash does not match source_refs")
    normalized["source_refs_hash"] = source_refs_hash
    digest = _hash64(value["provenance_digest"], "provenance.provenance_digest")
    if digest != canonical_hash(normalized):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_PROVENANCE_INVALID", "provenance_digest does not match provenance content")
    normalized["provenance_digest"] = digest
    return normalized


def _validate_context_gate(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CONTEXT_GATE_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTEXT_GATE_INVALID", "context_gate keys are not exact")
    loss_keys = ("task_loss", "decision_loss", "blocker_loss", "provenance_loss")
    if any(value[key] is not False for key in loss_keys):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTEXT_GATE_INVALID", "critical context loss requires HOLD")
    recall = _bounded_rate(value["critical_context_recall"], "context_gate.critical_context_recall")
    contradiction = _bounded_rate(value["contradiction_rate"], "context_gate.contradiction_rate")
    if recall < 10_000 or contradiction != 0:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTEXT_GATE_INVALID", "context reconstruction is not complete")
    normalized = {
        "context_pack_id": _safe_id(value["context_pack_id"], "context_gate.context_pack_id"),
        "pack_version": _nonnegative_int(value["pack_version"], "context_gate.pack_version"),
        "base_snapshot_id": _safe_id(value["base_snapshot_id"], "context_gate.base_snapshot_id"),
        "compression_version": _safe_id(value["compression_version"], "context_gate.compression_version"),
        "loss_ledger_hash": _hash64(value["loss_ledger_hash"], "context_gate.loss_ledger_hash"),
        "context_pack_hash": _hash64(value["context_pack_hash"], "context_gate.context_pack_hash"),
        "critical_context_recall": recall,
        "task_loss": False,
        "decision_loss": False,
        "blocker_loss": False,
        "provenance_loss": False,
        "contradiction_rate": contradiction,
        "reconstruction_test_id": _safe_id(value["reconstruction_test_id"], "context_gate.reconstruction_test_id"),
    }
    digest = _hash64(value["context_gate_digest"], "context_gate.context_gate_digest")
    if digest != canonical_hash(normalized):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTEXT_GATE_INVALID", "context_gate_digest does not match context content")
    normalized["context_gate_digest"] = digest
    return normalized


def _validate_continuity_gate(value: Any, effect_mode: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CONTINUITY_GATE_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTINUITY_INVALID", "continuity_gate keys are not exact")
    counters = value["budget_counters"]
    if not isinstance(counters, Mapping) or set(counters) != _BUDGET_COUNTER_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTINUITY_INVALID", "budget_counters keys are not exact")
    normalized_counters = {key: _nonnegative_int(counters[key], f"continuity_gate.budget_counters.{key}") for key in sorted(_BUDGET_COUNTER_KEYS)}
    deadline_at = _nonnegative_int(value["deadline_at"], "continuity_gate.deadline_at")
    heartbeat_deadline_at = _nonnegative_int(value["heartbeat_deadline_at"], "continuity_gate.heartbeat_deadline_at")
    last_heartbeat_at = _nonnegative_int(value["last_heartbeat_at"], "continuity_gate.last_heartbeat_at")
    projection_pending_deadline = _nonnegative_int(value["projection_pending_deadline"], "continuity_gate.projection_pending_deadline")
    if heartbeat_deadline_at < last_heartbeat_at or deadline_at < heartbeat_deadline_at:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTINUITY_INVALID", "continuity deadlines are not ordered")
    if effect_mode == "PRIME_PROJECTION" and projection_pending_deadline == 0:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTINUITY_INVALID", "projection needs a pending deadline")
    no_progress_window = _nonnegative_int(value["no_progress_window"], "continuity_gate.no_progress_window")
    progress_signature_count = _nonnegative_int(value["progress_signature_count"], "continuity_gate.progress_signature_count")
    if no_progress_window == 0 or progress_signature_count >= no_progress_window:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTINUITY_INVALID", "no-progress budget is exhausted")
    retry_budget = _nonnegative_int(value["retry_budget"], "continuity_gate.retry_budget")
    error_budget = _nonnegative_int(value["error_budget"], "continuity_gate.error_budget")
    replan_budget = _nonnegative_int(value["replan_budget"], "continuity_gate.replan_budget")
    if (
        normalized_counters["retry"] > retry_budget
        or normalized_counters["error"] > error_budget
        or normalized_counters["replan"] > replan_budget
    ):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTINUITY_INVALID", "continuity budget is exhausted")
    normalized = {
        "run_budget_hash": _hash64(value["run_budget_hash"], "continuity_gate.run_budget_hash"),
        "budget_counters": normalized_counters,
        "deadline_policy_hash": _hash64(value["deadline_policy_hash"], "continuity_gate.deadline_policy_hash"),
        "deadline_at": deadline_at,
        "heartbeat_deadline_at": heartbeat_deadline_at,
        "last_heartbeat_at": last_heartbeat_at,
        "checkpoint_id_or_null": _optional_safe_id(value["checkpoint_id_or_null"], "continuity_gate.checkpoint_id_or_null"),
        "checkpoint_hash": _hash64(value["checkpoint_hash"], "continuity_gate.checkpoint_hash"),
        "resume_point_id_or_null": _optional_safe_id(value["resume_point_id_or_null"], "continuity_gate.resume_point_id_or_null"),
        "last_committed_event_id": _safe_id(value["last_committed_event_id"], "continuity_gate.last_committed_event_id"),
        "progress_signature": _hash64(value["progress_signature"], "continuity_gate.progress_signature"),
        "progress_signature_count": progress_signature_count,
        "no_progress_window": no_progress_window,
        "retry_budget": retry_budget,
        "error_budget": error_budget,
        "projection_pending_deadline": projection_pending_deadline,
        "replan_budget": replan_budget,
    }
    digest = _hash64(value["continuity_digest"], "continuity_gate.continuity_digest")
    if digest != canonical_hash(normalized):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTINUITY_INVALID", "continuity_digest does not match continuity content")
    normalized["continuity_digest"] = digest
    return normalized


def _validate_review_binding(value: Any, operation: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _REVIEW_BINDING_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_REVIEW_INVALID", "review_binding keys are not exact")
    enabled = value["enabled"]
    if enabled is not True and enabled is not False:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_REVIEW_INVALID", "review_binding.enabled must be boolean")
    id_keys = ("review_domain_id_or_null", "reviewer_identity_or_null", "reviewer_process_identity_or_null", "previous_acceptance_transaction_id_or_null")
    hash_keys = ("criteria_hash_or_null", "review_input_manifest_hash_or_null", "review_decision_hash_or_null", "scheduler_snapshot_hash_or_null", "candidate_set_hash_or_null", "selection_policy_hash_or_null", "dependency_snapshot_hash_or_null")
    normalized: dict[str, Any] = {"enabled": enabled}
    for key in id_keys:
        normalized[key] = _optional_safe_id(value[key], f"review_binding.{key}")
    for key in hash_keys:
        normalized[key] = _optional_hash(value[key], f"review_binding.{key}")
    normalized["wave_sequence_no"] = _nonnegative_int(value["wave_sequence_no"], "review_binding.wave_sequence_no")
    if operation == "accept_reviewed_card" and not enabled:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_REVIEW_INVALID", "accept_reviewed_card needs an independent review binding")
    if not enabled:
        if any(normalized[key] is not None for key in id_keys + hash_keys) or normalized["wave_sequence_no"] != 0:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_REVIEW_INVALID", "disabled review binding must be empty")
    elif any(normalized[key] is None for key in id_keys[:3] + hash_keys):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_REVIEW_INVALID", "enabled review binding is incomplete")
    return normalized


def _validate_subagent_admission(value: Any, subject: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SUBAGENT_ADMISSION_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_P2_DISABLED", "subagent admission keys are not exact")
    if value["enabled"] is not False:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_P2_DISABLED", "P2 subagent admission is not part of S11")
    if value["parent_run_id"] != subject["run_id"] or value["parent_attempt_id"] != subject["attempt_id"]:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_P2_DISABLED", "subagent parent is not the transaction subject")
    if (
        value["child_count"] != 0
        or value["parallelism"] is not False
        or value["max_depth"] != 0
        or value["max_children"] != 0
        or value["role"] != "NONE"
        or value["worker_interface_version"] != "NONE"
        or value["failure_isolation_policy"] != "NONE"
        or value["expected_utility"] != 0
        or value["estimated_cost"] != 0
    ):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_P2_DISABLED", "P0/P1 require zero children and no parallelism")
    nullable = ("child_run_id_or_null", "child_attempt_id_or_null", "child_dispatch_id_or_null", "child_input_snapshot_hash_or_null", "child_context_pack_hash_or_null", "capability_set_hash_or_null", "path_policy_hash_or_null", "resource_budget_hash_or_null", "merge_policy_hash_or_null")
    if any(value[key] is not None for key in nullable):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_P2_DISABLED", "disabled subagent admission must have no child binding")
    return {
        "enabled": False,
        "parent_run_id": _safe_id(value["parent_run_id"], "subagent_admission.parent_run_id"),
        "parent_attempt_id": _safe_id(value["parent_attempt_id"], "subagent_admission.parent_attempt_id"),
        "child_count": 0,
        "max_children": _nonnegative_int(value["max_children"], "subagent_admission.max_children"),
        "max_depth": 0,
        "parallelism": False,
        "role": _safe_id(value["role"], "subagent_admission.role"),
        "worker_interface_version": _safe_id(value["worker_interface_version"], "subagent_admission.worker_interface_version"),
        **{key: None for key in nullable},
        "failure_isolation_policy": _safe_id(value["failure_isolation_policy"], "subagent_admission.failure_isolation_policy"),
        "expected_utility": _nonnegative_int(value["expected_utility"], "subagent_admission.expected_utility"),
        "estimated_cost": _nonnegative_int(value["estimated_cost"], "subagent_admission.estimated_cost"),
    }


def _validate_participant_expectations(value: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != PARTICIPANT_IDS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_PARTICIPANT_MISMATCH", f"{label} participant set is not exact")
    normalized: dict[str, dict[str, Any]] = {}
    for participant_id in sorted(PARTICIPANT_IDS):
        item = value[participant_id]
        if not isinstance(item, Mapping) or set(item) != _PARTICIPANT_EXPECTATION_KEYS:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", f"{label}.{participant_id} is incomplete")
        normalized[participant_id] = {
            "state_sha256": _hash64(item["state_sha256"], f"{label}.{participant_id}.state_sha256"),
            "journal_sha256": _hash64(item["journal_sha256"], f"{label}.{participant_id}.journal_sha256"),
            "version": _nonnegative_int(item["version"], f"{label}.{participant_id}.version"),
            "generation": _nonnegative_int(item["generation"], f"{label}.{participant_id}.generation"),
            "parent_hash": _optional_hash(item["parent_hash"], f"{label}.{participant_id}.parent_hash"),
        }
    return normalized


def _validate_effect_set(value: Any, effect_mode: str) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(value, list):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", "effect_set must be a list")
    if effect_mode != "CONTROL_PLANE_ONLY" and not value:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", "mutating effect mode needs a non-empty effect_set")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != _EFFECT_KEYS:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", f"effect_set[{index}] is incomplete")
        participant_id = _safe_id(item["participant_id"], f"effect_set[{index}].participant_id")
        if participant_id not in PARTICIPANT_IDS:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_PARTICIPANT_MISMATCH", f"effect_set[{index}] participant is unknown")
        operation = _safe_id(item["operation"], f"effect_set[{index}].operation")
        mode = _safe_id(item["mode"], f"effect_set[{index}].mode")
        if mode != effect_mode:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", f"effect_set[{index}] mode does not match effect_mode")
        allowed_operations = _EFFECT_OPERATION_POLICY.get(effect_mode, {}).get(participant_id, frozenset())
        if operation not in allowed_operations:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_SCOPE_INVALID", f"effect_set[{index}] participant/operation is outside the effect policy")
        normalized.append(
            {
                "participant_id": participant_id,
                "target_id": _safe_id(item["target_id"], f"effect_set[{index}].target_id"),
                "operation": operation,
                "mode": mode,
                "before_sha256": _hash64(item["before_sha256"], f"effect_set[{index}].before_sha256"),
                "after_sha256": _hash64(item["after_sha256"], f"effect_set[{index}].after_sha256"),
                "before_version": _nonnegative_int(item["before_version"], f"effect_set[{index}].before_version"),
                "after_version": _nonnegative_int(item["after_version"], f"effect_set[{index}].after_version"),
            }
        )
    if len({(item["participant_id"], item["target_id"]) for item in normalized}) != len(normalized):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", "effect_set targets are duplicated")
    normalized.sort(key=lambda item: (item["participant_id"], item["target_id"], item["operation"]))
    return normalized, canonical_hash(normalized)


def _validate_effect_alignment(
    effects: list[dict[str, Any]],
    before: Mapping[str, Mapping[str, Any]],
    after: Mapping[str, Mapping[str, Any]],
    effect_mode: str,
) -> None:
    for index, effect in enumerate(effects):
        participant_id = effect["participant_id"]
        before_item = before[participant_id]
        after_item = after[participant_id]
        if effect["before_sha256"] != before_item["state_sha256"] or effect["before_version"] != before_item["version"]:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", f"effect_set[{index}] before-state does not match participant expectation")
        if effect["after_sha256"] != after_item["state_sha256"] or effect["after_version"] != after_item["version"]:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", f"effect_set[{index}] after-state does not match participant expectation")
        if effect_mode != "CONTROL_PLANE_ONLY" and effect["after_version"] <= effect["before_version"]:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", f"effect_set[{index}] does not advance its version")
        if effect_mode != "CONTROL_PLANE_ONLY" and after_item["generation"] <= before_item["generation"]:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", f"effect_set[{index}] does not advance its generation")
        if after_item["parent_hash"] is not None and after_item["parent_hash"] != before_item["state_sha256"]:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", f"effect_set[{index}] parent hash does not bind the before-state")


def _validate_lease(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _LEASE_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_FENCE_INVALID", "lease contract is incomplete")
    expires_at = _nonnegative_int(value["expires_at"], "lease.expires_at")
    if expires_at == 0:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_FENCE_INVALID", "lease must have a positive expiry")
    return {
        "owner_id": _safe_id(value["owner_id"], "lease.owner_id"),
        "token_sha256": _hash64(value["token_sha256"], "lease.token_sha256"),
        "expires_at": expires_at,
        "fencing_epoch": _nonnegative_int(value["fencing_epoch"], "lease.fencing_epoch"),
    }


def _validate_rechecks(value: Any) -> dict[str, bool]:
    if not isinstance(value, Mapping) or set(value) != _RECHECK_KEYS or any(item is not True for item in value.values()):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_UNSAFE_REQUEST", "all authoritative rechecks must be true")
    return {key: True for key in sorted(_RECHECK_KEYS)}


def _validate_safety(value: Any) -> dict[str, bool]:
    if not isinstance(value, Mapping) or set(value) != _SAFETY_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", "safety contract is not exact")
    if value["read_only"] is not True or any(value[key] is not False for key in ("lock_held", "reservation", "mutation_performed", "authoritative_commit")):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_UNSAFE_REQUEST", "first S11 step must be actionless")
    return {
        "read_only": True,
        "lock_held": False,
        "reservation": False,
        "mutation_performed": False,
        "authoritative_commit": False,
    }


def verify_authoritative_transaction_contract(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Validate a future S11 contract without granting mutation authority."""

    contract = parse_authoritative_transaction_contract(value)
    if set(contract) != _CONTRACT_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", "contract key set is not exact")
    if contract["schema_version"] != PRIME_AUTHORITATIVE_COORDINATOR_SCHEMA:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", "unsupported coordinator schema")
    if contract["contract_role"] != PRIME_TRANSACTION_AUTHORITY_ROLE:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_UNSAFE_REQUEST", "contract role is executable")
    transaction_id = _safe_id(contract["transaction_id"], "transaction_id")
    idempotency_key = _safe_id(contract["idempotency_key"], "idempotency_key")
    operation = _safe_id(contract["operation"], "operation")
    if operation not in OPERATIONS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", "unsupported operation")
    effect_mode = _safe_id(contract["effect_mode"], "effect_mode")
    if effect_mode not in EFFECT_MODES:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SCHEMA_INVALID", "unsupported effect mode")
    if effect_mode == "PRIME_CONSUME":
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_PRIME_CONSUME_UNIMPLEMENTED", "Prime consume is not implemented")
    if operation == "project_queue" and effect_mode != "PRIME_PROJECTION":
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_SCOPE_INVALID", "project_queue requires PRIME_PROJECTION")
    subject = _validate_subject(contract["subject"])
    subject_binding = _validate_subject_binding(contract["subject_binding"])
    provenance = _validate_provenance(contract["provenance"])
    context_gate = _validate_context_gate(contract["context_gate"])
    if (
        context_gate["context_pack_id"] != subject_binding["context_pack_id"]
        or context_gate["pack_version"] != subject_binding["pack_version"]
        or context_gate["base_snapshot_id"] != subject_binding["base_snapshot_id"]
        or context_gate["context_pack_hash"] != subject_binding["context_pack_hash"]
    ):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_CONTEXT_GATE_INVALID", "context_gate is not bound to subject_binding")
    continuity_gate = _validate_continuity_gate(contract["continuity_gate"], effect_mode)
    review_binding = _validate_review_binding(contract["review_binding"], operation)
    subagent_admission = _validate_subagent_admission(contract["subagent_admission"], subject)
    precondition_plan_sha256 = _hash64(contract["precondition_plan_sha256"], "precondition_plan_sha256")
    if precondition_plan_sha256 != subject_binding["plan_hash"]:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_SUBJECT_BINDING_INVALID", "precondition plan is not the bound plan hash")
    participant_observations_sha256 = _hash64(contract["participant_observations_sha256"], "participant_observations_sha256")
    effects, effect_digest = _validate_effect_set(contract["effect_set"], effect_mode)
    if operation == "accept_reviewed_card" and not effects:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_UNDEFINED", "accept_reviewed_card needs a concrete control-plane effect")
    declared_effect_digest = _hash64(contract["effect_digest"], "effect_digest")
    if declared_effect_digest != effect_digest:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_EFFECT_DIGEST_MISMATCH", "effect digest does not match effect_set")
    before = _validate_participant_expectations(contract["expected_before"], "expected_before")
    after = _validate_participant_expectations(contract["expected_after"], "expected_after")
    _validate_effect_alignment(effects, before, after, effect_mode)
    lease = _validate_lease(contract["lease"])
    rechecks = _validate_rechecks(contract["required_rechecks"])
    safety = _validate_safety(contract["safety"])
    if contract["acceptance_enabled"] is not False:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_P0_DISABLED", "Acceptance remains disabled for the read-only step")
    if contract["next_card_intent_id_or_null"] is not None:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_P0_DISABLED", "next_card_intent is disabled for the read-only step")
    normalized = {
        "schema_version": PRIME_AUTHORITATIVE_COORDINATOR_SCHEMA,
        "contract_role": PRIME_TRANSACTION_AUTHORITY_ROLE,
        "transaction_id": transaction_id,
        "idempotency_key": idempotency_key,
        "operation": operation,
        "effect_mode": effect_mode,
        "subject": subject,
        "subject_binding": subject_binding,
        "provenance": provenance,
        "context_gate": context_gate,
        "continuity_gate": continuity_gate,
        "review_binding": review_binding,
        "subagent_admission": subagent_admission,
        "precondition_plan_sha256": precondition_plan_sha256,
        "participant_observations_sha256": participant_observations_sha256,
        "effect_set": effects,
        "effect_digest": effect_digest,
        "expected_before": before,
        "expected_after": after,
        "lease": lease,
        "required_rechecks": rechecks,
        "acceptance_enabled": False,
        "next_card_intent_id_or_null": None,
        "safety": safety,
    }
    return {
        "schema_version": PRIME_AUTHORITATIVE_COORDINATOR_VERIFICATION_SCHEMA,
        "contract_role": PRIME_TRANSACTION_AUTHORITY_ROLE,
        "status": "CONTRACT_VALIDATED_READ_ONLY",
        "transaction_id": transaction_id,
        "request_digest": canonical_hash(normalized),
        "effect_digest": effect_digest,
        "subject": subject,
        "subject_binding_digest": canonical_hash(subject_binding),
        "provenance_digest": canonical_hash(provenance),
        "context_gate_digest": canonical_hash(context_gate),
        "continuity_gate_digest": canonical_hash(continuity_gate),
        "review_binding_digest": canonical_hash(review_binding),
        "subagent_admission_digest": canonical_hash(subagent_admission),
        "effect_mode": effect_mode,
        "transaction_state": "PREPARED",
        "required_next_state": "COMMIT_RECHECK_REQUIRED",
        "authoritative_prepared": False,
        "idempotency_reserved": False,
        "mutation_window_open": False,
        "mutation_performed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "permission": "read_only",
        "external_action": False,
        "resume_allowed": False,
        "execution": {"resume": False, "reconcile": False, "mutation": False, "network": False},
    }


def _parse_recovery(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    if value is None:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery observation is missing")
    if isinstance(value, Mapping):
        try:
            return copy.deepcopy(dict(value))
        except (TypeError, ValueError, copy.Error) as exc:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery observation could not be isolated") from exc
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery observation is not UTF-8") from exc
    if not isinstance(value, str):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery object or JSON text required")
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except _DuplicateJsonKey as exc:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_CONFLICT", f"duplicate recovery key: {exc}") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery JSON object required")
    return parsed


def classify_authoritative_recovery(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Classify a supplied recovery snapshot; never perform recovery."""

    observation = _parse_recovery(value)
    if set(observation) != _RECOVERY_KEYS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery key set is not exact")
    if observation["schema_version"] != PRIME_AUTHORITATIVE_RECOVERY_SCHEMA:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "unsupported recovery schema")
    transaction_id = _safe_id(observation["transaction_id"], "recovery.transaction_id")
    expected_contract_digest = _hash64(observation["expected_contract_digest"], "recovery.expected_contract_digest")
    observed_contract_digest = _hash64(observation["observed_contract_digest"], "recovery.observed_contract_digest")
    expected_subject_binding_digest = _hash64(observation["expected_subject_binding_digest"], "recovery.expected_subject_binding_digest")
    observed_subject_binding_digest = _hash64(observation["observed_subject_binding_digest"], "recovery.observed_subject_binding_digest")
    expected_precondition_plan_sha256 = _hash64(observation["expected_precondition_plan_sha256"], "recovery.expected_precondition_plan_sha256")
    observed_precondition_plan_sha256 = _hash64(observation["observed_precondition_plan_sha256"], "recovery.observed_precondition_plan_sha256")
    expected_participant_observations_sha256 = _hash64(observation["expected_participant_observations_sha256"], "recovery.expected_participant_observations_sha256")
    observed_participant_observations_sha256 = _hash64(observation["observed_participant_observations_sha256"], "recovery.observed_participant_observations_sha256")
    expected_effect_digest = _hash64(observation["expected_effect_digest"], "recovery.expected_effect_digest")
    observed_effect_digest = _hash64(observation["observed_effect_digest"], "recovery.observed_effect_digest")
    expected_marker_commitment_sha256 = _hash64(observation["expected_marker_commitment_sha256"], "recovery.expected_marker_commitment_sha256")
    observed_marker_commitment_sha256 = _hash64(observation["observed_marker_commitment_sha256"], "recovery.observed_marker_commitment_sha256")
    expected_before = _validate_participant_expectations(observation["expected_before"], "recovery.expected_before")
    expected_after = _validate_participant_expectations(observation["expected_after"], "recovery.expected_after")
    observed_participants = _validate_participant_expectations(observation["observed_participants"], "recovery.observed_participants")
    observed_state = _safe_id(observation["observed_state"], "recovery.observed_state")
    if observed_state not in RECOVERY_STATES:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery state is not classifiable")
    participant_states = observation["participant_states"]
    journal_states = observation["journal_states"]
    marker_states = observation["marker_states"]
    if not isinstance(participant_states, Mapping) or set(participant_states) != PARTICIPANT_IDS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery participant set is not exact")
    if not isinstance(journal_states, Mapping) or set(journal_states) != PARTICIPANT_IDS:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery journal set is not exact")
    required_markers = {"coordinator", "prime_queue", "prime_ledger", "knowledge_ledger", "receipt"}
    if not isinstance(marker_states, Mapping) or set(marker_states) != required_markers:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery marker set is not exact")
    for key, state in participant_states.items():
        if state not in PARTICIPANT_STATES:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", f"invalid participant state: {key}")
    for key, state in journal_states.items():
        if state not in JOURNAL_STATES:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", f"invalid journal state: {key}")
    for key, state in marker_states.items():
        if state not in MARKER_STATES:
            raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", f"invalid marker state: {key}")
    expected_epoch = _nonnegative_int(observation["expected_fencing_epoch"], "recovery.expected_fencing_epoch")
    observed_epoch = _nonnegative_int(observation["observed_fencing_epoch"], "recovery.observed_fencing_epoch")
    if observation["lease_valid"] is not True and observation["lease_valid"] is not False:
        raise PrimeTransactionAuthorityError("PRIME_TX_AUTHORITY_RECOVERY_UNOBSERVABLE", "recovery lease_valid must be boolean")

    all_before = all(state == "BEFORE" for state in participant_states.values())
    all_after = all(state == "AFTER" for state in participant_states.values())
    journals_before = all(state == "CLEAN_BEFORE" for state in journal_states.values())
    journals_after = all(state == "CLEAN_AFTER" for state in journal_states.values())
    markers_absent = all(state == "ABSENT" for state in marker_states.values())
    markers_valid = all(state == "VALID" for state in marker_states.values())
    fence_matches = expected_epoch == observed_epoch and observation["lease_valid"] is True
    binding_matches = (
        expected_contract_digest == observed_contract_digest
        and expected_subject_binding_digest == observed_subject_binding_digest
        and expected_precondition_plan_sha256 == observed_precondition_plan_sha256
        and expected_participant_observations_sha256 == observed_participant_observations_sha256
        and expected_effect_digest == observed_effect_digest
        and expected_marker_commitment_sha256 == observed_marker_commitment_sha256
    )
    participant_observation_hashes_match = (
        expected_participant_observations_sha256 == canonical_hash(observed_participants)
        and observed_participant_observations_sha256 == canonical_hash(observed_participants)
    )
    binding_matches = binding_matches and participant_observation_hashes_match
    before_matches = observed_participants == expected_before
    after_matches = observed_participants == expected_after

    # The projection/marker evidence is not allowed to silently override an
    # explicitly uncertain lifecycle observation.  In particular, an
    # IN_DOUBT claim must remain recoverable even when a hostile caller also
    # supplies a complete-looking after projection.  PREPARED is compatible
    # with an exact before-state, but not with an exact after-state.
    before_state_compatible = observed_state in {"PREPARED", "COMMITTING"}
    after_state_compatible = observed_state == "COMMITTING"
    if all_before and journals_before and markers_absent and binding_matches and before_matches and before_state_compatible:
        status = "ABORTED_SAFE"
        transaction_state = "ABORTED"
        reason = "all participants remain at the bound before-state"
    elif all_after and journals_after and markers_valid and fence_matches and binding_matches and after_matches and after_state_compatible:
        status = "COMMITTED_PROVEN"
        transaction_state = "COMMITTED"
        reason = "all bound participants and immutable markers prove the exact after-state"
    else:
        status = "RECOVERY_REQUIRED"
        transaction_state = "IN_DOUBT"
        reason = "participant, journal, marker or fencing evidence is mixed, missing, stale or conflicting"

    return {
        "schema_version": PRIME_AUTHORITATIVE_RECOVERY_SCHEMA,
        "contract_role": PRIME_TRANSACTION_AUTHORITY_ROLE,
        "status": status,
        "transaction_id": transaction_id,
        "effect_digest": expected_effect_digest,
        "transaction_state": transaction_state,
        "reason": reason,
        "classification_role": "READ_ONLY_CLASSIFICATION",
        "binding_verified": binding_matches,
        "participant_observation_hashes_verified": participant_observation_hashes_match,
        "participant_projection_verified": before_matches or after_matches,
        "commit_evidence_sufficient_read_only": status == "COMMITTED_PROVEN",
        "authoritative_decision": False,
        "mutation_allowed": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "permission": "read_only",
        "external_action": False,
        "execution": {"resume": False, "reconcile": False, "mutation": False, "network": False},
        "expected_fencing_epoch": expected_epoch,
        "observed_fencing_epoch": observed_epoch,
    }


def evaluate_authoritative_transaction_contract(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Convert every invalid S11 contract into an actionless HOLD."""

    try:
        return verify_authoritative_transaction_contract(value)
    except PrimeTransactionAuthorityError as exc:
        return {
            "schema_version": PRIME_AUTHORITATIVE_COORDINATOR_VERIFICATION_SCHEMA,
            "contract_role": PRIME_TRANSACTION_AUTHORITY_ROLE,
            "status": "HOLD",
            "reason": exc.code,
            "transaction_state": "RECOVERY_REQUIRED" if exc.code.startswith("PRIME_TX_AUTHORITY_RECOVERY") else "PREPARED",
            "authoritative_prepared": False,
            "idempotency_reserved": False,
            "mutation_window_open": False,
            "mutation_performed": False,
            "consume_allowed": False,
            "cas_authorized": False,
            "permission": "read_only",
            "external_action": False,
            "resume_allowed": False,
            "execution": {"resume": False, "reconcile": False, "mutation": False, "network": False},
        }
    except (AttributeError, KeyError, TypeError, ValueError):
        return {
            "schema_version": PRIME_AUTHORITATIVE_COORDINATOR_VERIFICATION_SCHEMA,
            "contract_role": PRIME_TRANSACTION_AUTHORITY_ROLE,
            "status": "HOLD",
            "reason": "PRIME_TX_AUTHORITY_SCHEMA_INVALID",
            "transaction_state": "PREPARED",
            "authoritative_prepared": False,
            "idempotency_reserved": False,
            "mutation_window_open": False,
            "mutation_performed": False,
            "consume_allowed": False,
            "cas_authorized": False,
            "permission": "read_only",
            "external_action": False,
            "resume_allowed": False,
            "execution": {"resume": False, "reconcile": False, "mutation": False, "network": False},
        }


__all__ = [
    "AUTHORITY_ERROR_CODES",
    "EFFECT_MODES",
    "PARTICIPANT_IDS",
    "PRIME_AUTHORITATIVE_COMMIT_MARKER_SCHEMA",
    "PRIME_AUTHORITATIVE_COORDINATOR_SCHEMA",
    "PRIME_AUTHORITATIVE_COORDINATOR_VERIFICATION_SCHEMA",
    "PRIME_AUTHORITATIVE_RECOVERY_SCHEMA",
    "PRIME_TRANSACTION_AUTHORITY_ROLE",
    "PrimeTransactionAuthorityError",
    "classify_authoritative_recovery",
    "evaluate_authoritative_transaction_contract",
    "parse_authoritative_transaction_contract",
    "verify_authoritative_transaction_contract",
]
