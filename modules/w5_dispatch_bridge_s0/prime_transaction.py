"""W5-S9 read-only preparation of an authoritative Consume/CAS contract.

This module is deliberately a *prepare* boundary.  It derives and verifies
the exact preconditions a future authoritative transaction would have to
compare inside one commit window.  It does not open a database, acquire a
queue lock, write a journal, advance replay state, consume a card, or create
new authority.

The important distinction is intentional:

``PREPARE_ONLY_READ_ONLY`` means "these are the values that must be compared
atomically later".  It never means "the mutation is authorized now".
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash

from .prime_binding import (
    CONTROL_CAPTURE_KEYS,
    PrimeBindingError,
    _normalize_control_capture,
    control_from_runtime_snapshot,
)
from .prime_head import verify_prime_writer_head


PRIME_CONSUME_PRECONDITIONS_SCHEMA = "prime-consume-preconditions-v1"
PRIME_CONSUME_PRECONDITIONS_VERIFICATION_SCHEMA = "prime-consume-preconditions-verification-v1"
PRIME_CONSUME_OPERATION = "consume_card"

_PLAN_KEYS = frozenset({"schema_version", "contract_role", "operation", "idempotency_key", "subject", "expected", "safety"})
_SUBJECT_KEYS = frozenset({"prime_run_id", "w5_run_id", "card_id", "attempt_id", "dispatch_id"})
_SAFETY_KEYS = frozenset(
    {
        "requires_commit_recheck",
        "requires_queue_journal_recheck",
        "queue_journal_observed",
        "reservation",
        "lock_held",
        "mutation_performed",
        "cross_store_atomicity",
    }
)
_PREPARE_SAFETY = {
    "requires_commit_recheck": True,
    "requires_queue_journal_recheck": True,
    "queue_journal_observed": False,
    "reservation": False,
    "lock_held": False,
    "mutation_performed": False,
    "cross_store_atomicity": "not_claimed",
}
_EXPECTED_KEYS = frozenset(
    {
        "prime_head_sha256",
        "head_sequence",
        "generation",
        "generation_id",
        "prime_snapshot_sha256",
        "prime_anchor_sha256",
        "prime_root_binding_sha256",
        "prime_active_task_id",
        "prime_run_relative_path",
        "prime_queue_sha256",
        "prime_policy_sha256",
        "prime_active_card_sha256",
        "prime_resume_packet_sha256",
        "prime_writer_lease_sha256",
        "prime_previous_head_sha256",
        "last_accepted_generation",
        "last_accepted_head_sequence",
        "last_accepted_head_sha256",
        "w5_capture_sha256",
        "w5_runtime_sha256",
        "w5_projection_sha256",
        "w5_queue_hash",
        "w5_policy_hash",
        "w5_card_hash",
        "w5_lease_claim_sha256",
        "w5_lease_owner_id",
        "w5_lease_expires_at",
        "w5_fencing_epoch",
        "w5_attempt_command_ref",
        "w5_input_snapshot_ref",
        "w5_context_pack_ref",
        "w5_deadline_policy_ref",
        "w5_dispatch_command_ref",
        "w5_receipts_sha256",
        "w5_commit_markers_sha256",
        "control_runtime_anchor_sha256",
        "control_history_tail_sha256",
        "control_marker_commitments_sha256",
        "control_last_committed_event_id",
        "control_clock_after_epoch",
        "run_state",
        "card_state",
        "card_state_version",
        "attempt_state",
        "attempt_state_version",
        "dispatch_state",
        "dispatch_row_version",
    }
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}\Z")
_EXECUTION_FALSE = {"resume": False, "reconcile": False, "mutation": False, "network": False}
_S8_TRUE_FLAGS = (
    "trusted",
    "current_head",
    "replay_protected",
    "generation_bound",
    "queue_bound",
    "fencing_bound",
    "lease_live",
)
_S8_FALSE_FLAGS = ("external_action", "resume_allowed", "consume_allowed", "cas_authorized")

TRANSACTION_ERROR_CODES = frozenset(
    {
        "PRIME_TX_PLAN_NOT_OBSERVED",
        "PRIME_TX_PLAN_JSON_INVALID",
        "PRIME_TX_PLAN_JSON_DUPLICATE_KEY",
        "PRIME_TX_PLAN_SCHEMA_INVALID",
        "PRIME_TX_OPERATION_UNSUPPORTED",
        "PRIME_TX_IDEMPOTENCY_INVALID",
        "PRIME_TX_S8_NOT_SATISFIED",
        "PRIME_TX_SUBJECT_MISMATCH",
        "PRIME_TX_CONTROL_INVALID",
        "PRIME_TX_PRECONDITION_MISMATCH",
        "PRIME_TX_VERSION_MISSING",
        "PRIME_TX_UNSAFE_EXECUTION_REQUEST",
    }
)


class PrimeTransactionError(ValueError):
    """A S9 transaction plan failed closed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in TRANSACTION_ERROR_CODES:
            raise ValueError(f"unknown Prime transaction code: {code}")
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


def parse_prime_consume_plan(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Strictly parse a caller-supplied prepare plan without filesystem access."""

    if value is None:
        raise PrimeTransactionError("PRIME_TX_PLAN_NOT_OBSERVED", "transaction plan is missing")
    if isinstance(value, Mapping):
        try:
            return copy.deepcopy(dict(value))
        except (TypeError, ValueError, copy.Error) as exc:
            raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", "plan could not be isolated") from exc
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PrimeTransactionError("PRIME_TX_PLAN_JSON_INVALID", "plan is not UTF-8") from exc
    if not isinstance(value, str):
        raise PrimeTransactionError("PRIME_TX_PLAN_JSON_INVALID", "plan object or JSON text required")
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except _DuplicateJsonKey as exc:
        raise PrimeTransactionError("PRIME_TX_PLAN_JSON_DUPLICATE_KEY", f"duplicate key: {exc}") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PrimeTransactionError("PRIME_TX_PLAN_JSON_INVALID", "plan JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", "plan JSON object required")
    return parsed


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise PrimeTransactionError("PRIME_TX_VERSION_MISSING", f"{label} must be an integer >= 0")
    return value


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _optional_hash(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _hash64(value, label)


def _freeze_prepare_inputs(
    capture: Mapping[str, Any],
    anchor: Any,
    control_capture: Mapping[str, Any],
    head: Any,
    s8_kwargs: Mapping[str, Any],
) -> tuple[Any, Any, Any, Any, dict[str, Any]]:
    """Isolate one observation for both S8 and S9 derivation.

    S9 cannot lock the Prime filesystem and must not pretend that a deep copy
    is a database transaction.  It does, however, ensure that a caller-side
    mutation between the two pure verification stages cannot silently turn
    S8 evidence for observation A into a plan for observation B.
    """

    if not isinstance(capture, Mapping) or not isinstance(control_capture, Mapping) or not isinstance(s8_kwargs, Mapping):
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "prepare observations must be mappings")
    try:
        return (
            copy.deepcopy(capture),
            copy.deepcopy(anchor),
            copy.deepcopy(control_capture),
            copy.deepcopy(head),
            copy.deepcopy(dict(s8_kwargs)),
        )
    except (TypeError, ValueError, copy.Error) as exc:
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "prepare observations could not be isolated") from exc


def _validate_plan_shape(plan: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(plan, Mapping) or set(plan) != _PLAN_KEYS:
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", "plan key set is not exact")
    if plan["schema_version"] != PRIME_CONSUME_PRECONDITIONS_SCHEMA:
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", "unsupported plan schema")
    if plan["contract_role"] != "precondition_bundle_only":
        raise PrimeTransactionError("PRIME_TX_UNSAFE_EXECUTION_REQUEST", "S9 is not an executable transaction effect")
    if plan["operation"] != PRIME_CONSUME_OPERATION:
        raise PrimeTransactionError("PRIME_TX_OPERATION_UNSUPPORTED", "only single-card consume preparation is supported")
    idempotency_key = _text(plan["idempotency_key"], "plan.idempotency_key")
    if _IDEMPOTENCY.fullmatch(idempotency_key) is None:
        raise PrimeTransactionError("PRIME_TX_IDEMPOTENCY_INVALID", "idempotency key is not safe")
    subject = plan["subject"]
    if not isinstance(subject, Mapping) or set(subject) != _SUBJECT_KEYS:
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", "plan.subject key set is not exact")
    checked_subject = {
        key: _safe_id(subject[key], f"plan.subject.{key}")
        for key in sorted(_SUBJECT_KEYS)
    }
    safety = plan["safety"]
    if not isinstance(safety, Mapping) or set(safety) != _SAFETY_KEYS:
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", "plan.safety key set is not exact")
    if safety["requires_commit_recheck"] is not True:
        raise PrimeTransactionError("PRIME_TX_UNSAFE_EXECUTION_REQUEST", "commit recheck is mandatory")
    if safety["requires_queue_journal_recheck"] is not True:
        raise PrimeTransactionError("PRIME_TX_UNSAFE_EXECUTION_REQUEST", "queue journal recheck is mandatory")
    if safety["queue_journal_observed"] is not False:
        raise PrimeTransactionError("PRIME_TX_UNSAFE_EXECUTION_REQUEST", "S9 does not observe or reserve a queue journal")
    for key in ("reservation", "lock_held", "mutation_performed"):
        if safety[key] is not False:
            raise PrimeTransactionError("PRIME_TX_UNSAFE_EXECUTION_REQUEST", f"plan.safety.{key} must be false")
    if safety["cross_store_atomicity"] != "not_claimed":
        raise PrimeTransactionError("PRIME_TX_UNSAFE_EXECUTION_REQUEST", "cross-store atomicity is not established by S9")
    expected = plan["expected"]
    if not isinstance(expected, Mapping) or set(expected) != _EXPECTED_KEYS:
        raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", "plan.expected key set is not exact")
    checked_expected: dict[str, Any] = {}
    hash_fields = {
        key
        for key in _EXPECTED_KEYS
        if (key.endswith("_sha256") or key.endswith("_claim_sha256"))
        and key not in {"last_accepted_head_sha256", "prime_previous_head_sha256"}
    }
    text_fields = {
        "generation_id",
        "w5_queue_hash",
        "w5_policy_hash",
        "w5_card_hash",
        "w5_lease_owner_id",
        "w5_attempt_command_ref",
        "w5_input_snapshot_ref",
        "w5_context_pack_ref",
        "w5_deadline_policy_ref",
        "w5_dispatch_command_ref",
        "prime_active_task_id",
        "prime_run_relative_path",
        "run_state",
        "card_state",
        "attempt_state",
        "dispatch_state",
    }
    nonnegative_fields = {
        "last_accepted_generation",
        "last_accepted_head_sequence",
        "card_state_version",
        "attempt_state_version",
        "dispatch_row_version",
    }
    positive_fields = {"head_sequence", "generation", "w5_lease_expires_at", "w5_fencing_epoch"}
    nonnegative_fields.add("control_clock_after_epoch")
    for key in sorted(_EXPECTED_KEYS):
        if key in hash_fields:
            checked_expected[key] = _hash64(expected[key], f"plan.expected.{key}")
        elif key in text_fields:
            checked_expected[key] = _text(expected[key], f"plan.expected.{key}")
        elif key in nonnegative_fields:
            checked_expected[key] = _nonnegative_int(expected[key], f"plan.expected.{key}")
        elif key in positive_fields:
            checked_expected[key] = _positive_int(expected[key], f"plan.expected.{key}")
        elif key in {"last_accepted_head_sha256", "prime_previous_head_sha256"}:
            checked_expected[key] = _optional_hash(expected[key], f"plan.expected.{key}")
        elif key == "control_last_committed_event_id":
            checked_expected[key] = _optional_text(expected[key], f"plan.expected.{key}")
        else:  # pragma: no cover - exact field set makes this unreachable
            raise PrimeTransactionError("PRIME_TX_PLAN_SCHEMA_INVALID", f"unsupported expected field: {key}")
    return {
        "schema_version": PRIME_CONSUME_PRECONDITIONS_SCHEMA,
        "contract_role": "precondition_bundle_only",
        "operation": PRIME_CONSUME_OPERATION,
        "idempotency_key": idempotency_key,
        "subject": checked_subject,
        "expected": checked_expected,
        "safety": dict(_PREPARE_SAFETY),
    }


def _control_prepare_observation(control_capture: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(control_capture, Mapping) or set(control_capture) != CONTROL_CAPTURE_KEYS:
        raise PrimeTransactionError("PRIME_TX_CONTROL_INVALID", "S4 control capture key set is not exact")
    try:
        normalized = _normalize_control_capture(control_capture)
        control = control_from_runtime_snapshot(normalized["runtime"])
    except (PrimeBindingError, TypeError, ValueError) as exc:
        raise PrimeTransactionError("PRIME_TX_CONTROL_INVALID", "S4 control capture is invalid") from exc
    runtime = normalized["runtime"]
    runtime_run = runtime["run"]
    run = control["run"]
    card = control["card"]
    attempt = control["attempt"]
    dispatch = control["dispatch"]
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
        or run["fencing_epoch"] != control["lease"]["fencing_epoch"]
        or run["lease_token"] != control["lease"]["token"]
        or dispatch["owner_id"] != control["lease"]["owner_id"]
        or dispatch["lease_expires_at"] != control["lease"]["expires_at"]
    ):
        raise PrimeTransactionError("PRIME_TX_CONTROL_INVALID", "control identity/CAS fields drifted")
    for section, required in (("run", ("state", "last_committed_event_id")), ("cards", ("state", "state_version")), ("attempts", ("state", "state_version")), ("dispatches", ("state", "row_version"))):
        value = runtime.get(section)
        if section == "run":
            value = runtime.get("run")
        elif isinstance(value, list) and len(value) == 1:
            value = value[0]
        if not isinstance(value, Mapping) or any(key not in value for key in required):
            raise PrimeTransactionError("PRIME_TX_VERSION_MISSING", f"control {section} version/state fields are missing")
    if runtime_run["last_committed_event_id"] != normalized["runtime_anchor"]["last_committed_event_id"]:
        raise PrimeTransactionError("PRIME_TX_CONTROL_INVALID", "runtime and anchor event cursors drifted")
    _text(run["state"], "control.run.state")
    _optional_text(runtime_run["last_committed_event_id"], "control.run.last_committed_event_id")
    _text(card["state"], "control.card.state")
    _nonnegative_int(runtime["cards"][0]["state_version"], "control.card.state_version")
    _text(attempt["state"], "control.attempt.state")
    _nonnegative_int(runtime["attempts"][0]["state_version"], "control.attempt.state_version")
    _text(dispatch["state"], "control.dispatch.state")
    _nonnegative_int(runtime["dispatches"][0]["row_version"], "control.dispatch.row_version")
    if control["lease"]["expires_at"] <= normalized["clock_after_epoch"]:
        raise PrimeTransactionError("PRIME_TX_CONTROL_INVALID", "control lease is not live")
    return normalized, control


def _derive_expected(
    capture: Mapping[str, Any],
    control_capture: Mapping[str, Any],
    s8: Mapping[str, Any],
    s8_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    normalized, control = _control_prepare_observation(control_capture)
    replay = _s8_kwargs(s8_kwargs)
    runtime = normalized["runtime"]
    run = runtime["run"]
    card = runtime["cards"][0]
    attempt = runtime["attempts"][0]
    dispatch = runtime["dispatches"][0]
    lease = control["lease"]
    files = capture.get("files")
    if not isinstance(files, Mapping):
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "Prime file evidence is missing")
    try:
        prime_files = {
            name: _hash64(files[name]["sha256"], f"Prime files.{name}.sha256")
            for name in ("policy", "active_card", "resume_packet", "writer_lease")
        }
    except (KeyError, TypeError) as exc:
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "required Prime sidecar evidence is missing") from exc
    history = normalized["runtime_anchor_history"]
    if not history:
        raise PrimeTransactionError("PRIME_TX_CONTROL_INVALID", "control anchor history is empty")
    expected = {
        "prime_head_sha256": s8["head_sha256"],
        "head_sequence": s8["head_sequence"],
        "generation": s8["generation"],
        "generation_id": s8["generation_id"],
        "prime_snapshot_sha256": s8["prime_snapshot_sha256"],
        "prime_anchor_sha256": s8["anchor_sha256"],
        "prime_root_binding_sha256": capture["root"]["root_binding_sha256"],
        "prime_active_task_id": capture["parsed"]["session_state"]["active_task_id"],
        "prime_run_relative_path": capture["root"]["run_relative_path"],
        "prime_queue_sha256": s8["prime_queue_sha256"],
        "prime_policy_sha256": prime_files["policy"],
        "prime_active_card_sha256": prime_files["active_card"],
        "prime_resume_packet_sha256": prime_files["resume_packet"],
        "prime_writer_lease_sha256": prime_files["writer_lease"],
        "w5_capture_sha256": canonical_hash(normalized),
        "w5_runtime_sha256": normalized["runtime_sha256"],
        "w5_projection_sha256": normalized["projection_sha256"],
        "w5_queue_hash": control["run"]["queue_hash"],
        "w5_policy_hash": control["run"]["policy_hash"],
        "w5_card_hash": control["card"]["card_hash"],
        "w5_lease_claim_sha256": canonical_hash(
            {
                "run_id": control["run"]["run_id"],
                "owner_id": lease["owner_id"],
                "token": lease["token"],
                "fencing_epoch": lease["fencing_epoch"],
                "expires_at": lease["expires_at"],
            }
        ),
        "w5_lease_owner_id": lease["owner_id"],
        "w5_lease_expires_at": lease["expires_at"],
        "w5_fencing_epoch": lease["fencing_epoch"],
        "w5_attempt_command_ref": attempt["command_hash"],
        "w5_input_snapshot_ref": attempt["input_snapshot_hash"],
        "w5_context_pack_ref": attempt["context_pack_hash"],
        "w5_deadline_policy_ref": attempt["deadline_policy_hash"],
        "w5_dispatch_command_ref": dispatch["command_hash"],
        "w5_receipts_sha256": canonical_hash(runtime.get("receipts", [])),
        "w5_commit_markers_sha256": canonical_hash(runtime.get("commit_markers", [])),
        "prime_previous_head_sha256": s8["previous_head_sha256"],
        "last_accepted_generation": replay["last_accepted_generation"],
        "last_accepted_head_sequence": replay["last_accepted_head_sequence"],
        "last_accepted_head_sha256": replay["last_accepted_head_sha256"],
        "control_runtime_anchor_sha256": canonical_hash(normalized["runtime_anchor"]),
        "control_history_tail_sha256": canonical_hash(history[-1]),
        "control_marker_commitments_sha256": canonical_hash(normalized["marker_commitments"]),
        "control_last_committed_event_id": normalized["runtime_anchor"]["last_committed_event_id"],
        "control_clock_after_epoch": normalized["clock_after_epoch"],
        "run_state": run["state"],
        "card_state": card["state"],
        "card_state_version": card["state_version"],
        "attempt_state": attempt["state"],
        "attempt_state_version": attempt["state_version"],
        "dispatch_state": dispatch["state"],
        "dispatch_row_version": dispatch["row_version"],
    }
    try:
        _hash64(expected["prime_root_binding_sha256"], "expected.prime_root_binding_sha256")
        for key in ("w5_receipts_sha256", "w5_commit_markers_sha256"):
            _hash64(expected[key], f"expected.{key}")
        for key in ("card_state_version", "attempt_state_version", "dispatch_row_version"):
            _nonnegative_int(expected[key], f"expected.{key}")
    except PrimeTransactionError:
        raise
    except (KeyError, TypeError) as exc:
        raise PrimeTransactionError("PRIME_TX_VERSION_MISSING", "authoritative state version is missing") from exc
    return expected


def _s8_kwargs(kwargs: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "last_accepted_generation",
        "last_accepted_head_sequence",
        "last_accepted_head_sha256",
        "expected_current_head",
        "expected_prime_run_id",
        "expected_w5_identity",
    }
    if set(kwargs) != required:
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "S8 replay/current-head arguments are incomplete")
    return dict(kwargs)


def _verify_s8(capture: Mapping[str, Any], anchor: Any, control_capture: Mapping[str, Any], head: Any, s8_kwargs: Mapping[str, Any]) -> dict[str, Any]:
    try:
        result = verify_prime_writer_head(capture, anchor, control_capture, head, **_s8_kwargs(s8_kwargs))
    except Exception as exc:
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "S8 verification could not be completed") from exc
    required_result_fields = {
        "prime_run_id",
        "w5_run_id",
        "card_id",
        "attempt_id",
        "dispatch_id",
        "anchor_sha256",
        "head_sha256",
        "head_sequence",
        "generation",
        "generation_id",
        "prime_snapshot_sha256",
        "prime_queue_sha256",
        "previous_head_sha256",
        "w5_fencing_epoch",
    }
    if not isinstance(result, Mapping) or not required_result_fields.issubset(result):
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "S8 result is incomplete")
    if (
        result.get("status") != "PRECONDITION_SATISFIED_READ_ONLY"
        or result.get("permission") != "read_only"
        or any(result.get(key) is not True for key in _S8_TRUE_FLAGS)
        or any(result.get(key) is not False for key in _S8_FALSE_FLAGS)
        or not isinstance(result.get("execution"), Mapping)
        or set(result["execution"]) != set(_EXECUTION_FALSE)
        or any(value is not False for value in result["execution"].values())
    ):
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "S8 did not produce a safe read-only precondition")
    return result


def build_prime_consume_plan(
    capture: Mapping[str, Any],
    anchor: Any,
    control_capture: Mapping[str, Any],
    head: Any,
    *,
    idempotency_key: str,
    s8_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive a prepare-only plan from one freshly verified S8 observation."""

    frozen_capture, frozen_anchor, frozen_control, frozen_head, frozen_s8_kwargs = _freeze_prepare_inputs(
        capture,
        anchor,
        control_capture,
        head,
        s8_kwargs,
    )
    try:
        derivation_capture = copy.deepcopy(frozen_capture)
        derivation_control = copy.deepcopy(frozen_control)
        derivation_s8_kwargs = copy.deepcopy(frozen_s8_kwargs)
    except (TypeError, ValueError, copy.Error) as exc:
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "prepare observations could not be duplicated") from exc
    s8 = _verify_s8(frozen_capture, frozen_anchor, frozen_control, frozen_head, frozen_s8_kwargs)
    if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
        raise PrimeTransactionError("PRIME_TX_IDEMPOTENCY_INVALID", "idempotency key is not safe")
    try:
        expected = _derive_expected(derivation_capture, derivation_control, s8, derivation_s8_kwargs)
    except PrimeTransactionError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "S9 could not derive a complete precondition bundle") from exc
    subject = {
        "prime_run_id": s8["prime_run_id"],
        "w5_run_id": s8["w5_run_id"],
        "card_id": s8["card_id"],
        "attempt_id": s8["attempt_id"],
        "dispatch_id": s8["dispatch_id"],
    }
    plan = {
        "schema_version": PRIME_CONSUME_PRECONDITIONS_SCHEMA,
        "contract_role": "precondition_bundle_only",
        "operation": PRIME_CONSUME_OPERATION,
        "idempotency_key": idempotency_key,
        "subject": subject,
        "expected": expected,
        "safety": dict(_PREPARE_SAFETY),
    }
    return _validate_plan_shape(plan)


def verify_prime_consume_plan(
    capture: Mapping[str, Any],
    anchor: Any,
    control_capture: Mapping[str, Any],
    head: Any,
    plan: Mapping[str, Any] | bytes | str | None,
    *,
    s8_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify a plan against fresh S8 evidence without opening a commit window."""

    frozen_capture, frozen_anchor, frozen_control, frozen_head, frozen_s8_kwargs = _freeze_prepare_inputs(
        capture,
        anchor,
        control_capture,
        head,
        s8_kwargs,
    )
    try:
        derivation_capture = copy.deepcopy(frozen_capture)
        derivation_control = copy.deepcopy(frozen_control)
        derivation_s8_kwargs = copy.deepcopy(frozen_s8_kwargs)
    except (TypeError, ValueError, copy.Error) as exc:
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "prepare observations could not be duplicated") from exc
    s8 = _verify_s8(frozen_capture, frozen_anchor, frozen_control, frozen_head, frozen_s8_kwargs)
    checked_plan = _validate_plan_shape(parse_prime_consume_plan(plan))
    expected_subject = {
        "prime_run_id": s8["prime_run_id"],
        "w5_run_id": s8["w5_run_id"],
        "card_id": s8["card_id"],
        "attempt_id": s8["attempt_id"],
        "dispatch_id": s8["dispatch_id"],
    }
    if checked_plan["subject"] != expected_subject:
        raise PrimeTransactionError("PRIME_TX_SUBJECT_MISMATCH", "plan subject is not the fresh S8 subject")
    try:
        expected = _derive_expected(derivation_capture, derivation_control, s8, derivation_s8_kwargs)
    except PrimeTransactionError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise PrimeTransactionError("PRIME_TX_S8_NOT_SATISFIED", "S9 could not derive a complete precondition bundle") from exc
    if checked_plan["expected"] != expected:
        raise PrimeTransactionError("PRIME_TX_PRECONDITION_MISMATCH", "plan preconditions do not match fresh evidence")
    plan_hash = canonical_hash(checked_plan)
    precondition_hash = canonical_hash(checked_plan["expected"])
    return {
        "schema_version": PRIME_CONSUME_PRECONDITIONS_VERIFICATION_SCHEMA,
        "status": "PREPARE_ONLY_READ_ONLY",
        "contract_role": "precondition_bundle_only",
        "operation": PRIME_CONSUME_OPERATION,
        "transaction_authority": "DEFERRED_TO_ATOMIC_CONSUMER",
        "mutation_window_open": False,
        "atomic_commit_required": True,
        "idempotency_bound": True,
        "requires_commit_recheck": True,
        "requires_queue_journal_recheck": True,
        "queue_journal_observed": False,
        "reservation": False,
        "lock_held": False,
        "mutation_performed": False,
        "cross_store_atomicity": "not_claimed",
        "plan_sha256": plan_hash,
        "precondition_sha256": precondition_hash,
        "s8_verification_sha256": canonical_hash(s8),
        "subject": expected_subject,
        "head_sequence": s8["head_sequence"],
        "generation": s8["generation"],
        "fencing_epoch": s8["w5_fencing_epoch"],
        "permission": "read_only",
        "external_action": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "execution": dict(_EXECUTION_FALSE),
    }


def evaluate_prime_consume_plan(
    capture: Mapping[str, Any],
    anchor: Any,
    control_capture: Mapping[str, Any],
    head: Any,
    plan: Mapping[str, Any] | bytes | str | None,
    *,
    s8_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Convert every malformed or stale plan into an actionless HOLD."""

    try:
        return verify_prime_consume_plan(
            capture,
            anchor,
            control_capture,
            head,
            plan,
            s8_kwargs=s8_kwargs,
        )
    except PrimeTransactionError as exc:
        code = exc.code
    except (TypeError, ValueError, KeyError, AttributeError):
        code = "PRIME_TX_PLAN_SCHEMA_INVALID"
    return {
        "schema_version": PRIME_CONSUME_PRECONDITIONS_VERIFICATION_SCHEMA,
        "status": "HOLD",
        "reason": code,
        "contract_role": "precondition_bundle_only",
        "transaction_authority": "NONE",
        "mutation_window_open": False,
        "atomic_commit_required": True,
        "requires_commit_recheck": True,
        "requires_queue_journal_recheck": True,
        "queue_journal_observed": False,
        "reservation": False,
        "lock_held": False,
        "mutation_performed": False,
        "cross_store_atomicity": "not_claimed",
        "permission": "read_only",
        "external_action": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "execution": dict(_EXECUTION_FALSE),
    }


__all__ = [
    "PRIME_CONSUME_OPERATION",
    "PRIME_CONSUME_PRECONDITIONS_SCHEMA",
    "PRIME_CONSUME_PRECONDITIONS_VERIFICATION_SCHEMA",
    "TRANSACTION_ERROR_CODES",
    "PrimeTransactionError",
    "build_prime_consume_plan",
    "evaluate_prime_consume_plan",
    "parse_prime_consume_plan",
    "verify_prime_consume_plan",
]
