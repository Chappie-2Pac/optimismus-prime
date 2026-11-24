"""W5-S10 read-only participant/coordinator preview.

S9 binds one fresh Prime/W5 observation.  S10 adds a second, still
non-authoritative boundary: a caller may provide read-only observations of the
Prime queue journal, Prime ledger transaction journal, ControlPlane
transaction state and receipt/marker projection.  This module checks that
those observations agree with the S9 plan and produces a deterministic
preview for a *future* atomic coordinator.

It deliberately does not discover the observations itself.  The existing
queue and Prime transaction helpers acquire locks or write recovery markers;
the ControlPlane transaction helper opens ``BEGIN IMMEDIATE``.  Calling any
of those from this layer would turn a preview into an authority leak.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash

from .prime_transaction import (
    PrimeTransactionError,
    parse_prime_consume_plan,
    verify_prime_consume_plan,
)


PRIME_TRANSACTION_PARTICIPANT_PREVIEW_SCHEMA = "prime-transaction-participant-preview-v1"
PRIME_TRANSACTION_PARTICIPANT_PREVIEW_VERIFICATION_SCHEMA = "prime-transaction-participant-preview-verification-v1"
PRIME_TRANSACTION_PREVIEW_ROLE = "transaction_preview_only"
PARTICIPANT_IDS = frozenset({"prime_queue", "prime_ledger", "control_plane", "receipt_projection"})
PARTICIPANT_SCHEMA = "prime-transaction-participant-observation-v1"
JOURNAL_SCHEMA = "prime-transaction-journal-observation-v1"
PARTICIPANT_STATUS = "OBSERVED_READ_ONLY"
JOURNAL_CLEAN = "CLEAN"
_PREVIEW_KEYS = frozenset(
    {
        "schema_version",
        "contract_role",
        "status",
        "s9_verification_sha256",
        "plan_sha256",
        "participant_observations_sha256",
        "preview_id",
        "prepare_digest",
        "subject",
        "participant_ids",
        "participant_journal_statuses",
        "coordinator_state",
        "required_next_state",
        "failure_states",
        "atomic_commit_required",
        "participant_recheck_required",
        "queue_journal_recheck_required",
        "lease_recheck_required",
        "fencing_recheck_required",
        "receipt_recheck_required",
        "effect_defined",
        "expected_after_observed",
        "authoritative_prepared",
        "idempotency_reserved",
        "transaction_authority",
        "mutation_window_open",
        "reservation",
        "lock_held",
        "mutation_performed",
        "cross_store_atomicity",
        "permission",
        "external_action",
        "resume_allowed",
        "consume_allowed",
        "cas_authorized",
        "execution",
    }
)
_PARTICIPANT_KEYS = frozenset({"schema_version", "participant_id", "status", "before", "journal", "safety"})
_JOURNAL_KEYS = frozenset(
    {"schema_version", "journal_kind", "status", "journal_sha256", "open_transaction_ids", "recovery_required"}
)
_SAFETY_KEYS = frozenset(
    {"read_only", "lock_held", "reservation", "mutation_performed", "write_authority", "atomicity_claimed"}
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EXECUTION_FALSE = {"resume": False, "reconcile": False, "mutation": False, "network": False}
_JOURNAL_KINDS = {
    "prime_queue": "prime_queue_journal",
    "prime_ledger": "prime_ledger_journal",
    "control_plane": "control_plane_transaction_state",
    "receipt_projection": "receipt_marker_projection",
}
_FAILURE_STATES = ["ABORTED", "UNCERTAIN", "RECOVERY_REQUIRED", "QUARANTINED"]

PREVIEW_ERROR_CODES = frozenset(
    {
        "PRIME_TX_PREVIEW_NOT_OBSERVED",
        "PRIME_TX_PREVIEW_JSON_INVALID",
        "PRIME_TX_PREVIEW_JSON_DUPLICATE_KEY",
        "PRIME_TX_PREVIEW_SCHEMA_INVALID",
        "PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST",
        "PRIME_TX_PREVIEW_S9_NOT_SATISFIED",
        "PRIME_TX_PREVIEW_PLAN_MISMATCH",
        "PRIME_TX_PREVIEW_SUBJECT_MISMATCH",
        "PRIME_TX_PREVIEW_PARTICIPANT_SET_INVALID",
        "PRIME_TX_PREVIEW_JOURNAL_UNOBSERVABLE",
        "PRIME_TX_PREVIEW_RECOVERY_REQUIRED",
        "PRIME_TX_PREVIEW_PRECONDITION_MISMATCH",
    }
)


class PrimeTransactionPreviewError(ValueError):
    """A W5-S10 participant preview failed closed."""

    def __init__(self, code: str, message: str, *, cause_code: str | None = None) -> None:
        if code not in PREVIEW_ERROR_CODES:
            raise ValueError(f"unknown Prime transaction preview code: {code}")
        self.code = code
        self.cause_code = cause_code
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


def parse_prime_transaction_preview(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Strictly isolate and parse a caller-supplied preview."""

    if value is None:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_NOT_OBSERVED", "transaction preview is missing")
    if isinstance(value, Mapping):
        try:
            return copy.deepcopy(dict(value))
        except (TypeError, ValueError, copy.Error) as exc:
            raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", "preview could not be isolated") from exc
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_JSON_INVALID", "preview is not UTF-8") from exc
    if not isinstance(value, str):
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_JSON_INVALID", "preview object or JSON text required")
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except _DuplicateJsonKey as exc:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_JSON_DUPLICATE_KEY", f"duplicate key: {exc}") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_JSON_INVALID", "preview JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", "preview JSON object required")
    return parsed


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", f"{label} must be an integer >= 0")
    return value


def _freeze_inputs(
    capture: Mapping[str, Any],
    anchor: Any,
    control_capture: Mapping[str, Any],
    head: Any,
    plan: Mapping[str, Any] | bytes | str | None,
    participants: Mapping[str, Any],
    s8_kwargs: Mapping[str, Any],
) -> tuple[Any, Any, Any, Any, Any, dict[str, Any], dict[str, Any]]:
    if not isinstance(participants, Mapping) or not isinstance(s8_kwargs, Mapping):
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", "participants and S8 arguments must be mappings")
    try:
        return (
            copy.deepcopy(capture),
            copy.deepcopy(anchor),
            copy.deepcopy(control_capture),
            copy.deepcopy(head),
            copy.deepcopy(plan),
            copy.deepcopy(dict(participants)),
            copy.deepcopy(dict(s8_kwargs)),
        )
    except (TypeError, ValueError, copy.Error) as exc:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", "preview inputs could not be isolated") from exc


def _expected_before(participant_id: str, expected: Mapping[str, Any]) -> dict[str, Any]:
    if participant_id == "prime_queue":
        return {"queue_sha256": expected["prime_queue_sha256"]}
    if participant_id == "prime_ledger":
        return {
            key: expected[key]
            for key in (
                "prime_head_sha256",
                "prime_anchor_sha256",
                "prime_snapshot_sha256",
                "prime_root_binding_sha256",
                "prime_active_task_id",
                "prime_run_relative_path",
                "prime_queue_sha256",
                "prime_policy_sha256",
                "prime_active_card_sha256",
                "prime_resume_packet_sha256",
                "prime_writer_lease_sha256",
                "prime_previous_head_sha256",
            )
        }
    if participant_id == "control_plane":
        return {
            "runtime_sha256": expected["w5_runtime_sha256"],
            "projection_sha256": expected["w5_projection_sha256"],
            "capture_sha256": expected["w5_capture_sha256"],
            "runtime_anchor_sha256": expected["control_runtime_anchor_sha256"],
            "history_tail_sha256": expected["control_history_tail_sha256"],
            "marker_commitments_sha256": expected["control_marker_commitments_sha256"],
            "queue_hash": expected["w5_queue_hash"],
            "policy_hash": expected["w5_policy_hash"],
            "card_hash": expected["w5_card_hash"],
            "lease_claim_sha256": expected["w5_lease_claim_sha256"],
            "lease_owner_id": expected["w5_lease_owner_id"],
            "lease_expires_at": expected["w5_lease_expires_at"],
            "fencing_epoch": expected["w5_fencing_epoch"],
            "last_committed_event_id": expected["control_last_committed_event_id"],
            "clock_after_epoch": expected["control_clock_after_epoch"],
            "run_state": expected["run_state"],
            "card_state": expected["card_state"],
            "card_state_version": expected["card_state_version"],
            "attempt_state": expected["attempt_state"],
            "attempt_state_version": expected["attempt_state_version"],
            "dispatch_state": expected["dispatch_state"],
            "dispatch_row_version": expected["dispatch_row_version"],
        }
    if participant_id == "receipt_projection":
        return {
            "receipts_sha256": expected["w5_receipts_sha256"],
            "commit_markers_sha256": expected["w5_commit_markers_sha256"],
            "history_tail_sha256": expected["control_history_tail_sha256"],
            "marker_commitments_sha256": expected["control_marker_commitments_sha256"],
            "last_committed_event_id": expected["control_last_committed_event_id"],
        }
    raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_PARTICIPANT_SET_INVALID", f"unknown participant: {participant_id}")


def _validate_journal(value: Mapping[str, Any], participant_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _JOURNAL_KEYS:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_JOURNAL_UNOBSERVABLE", f"{participant_id} journal schema is incomplete")
    if value["schema_version"] != JOURNAL_SCHEMA or value["journal_kind"] != _JOURNAL_KINDS[participant_id]:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_JOURNAL_UNOBSERVABLE", f"{participant_id} journal kind is unsupported")
    status = _text(value["status"], f"{participant_id}.journal.status")
    _hash64(value["journal_sha256"], f"{participant_id}.journal.journal_sha256")
    open_ids = value["open_transaction_ids"]
    if not isinstance(open_ids, list) or any(not isinstance(item, str) or _SAFE_ID.fullmatch(item) is None for item in open_ids):
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_JOURNAL_UNOBSERVABLE", f"{participant_id} journal inventory is invalid")
    if open_ids != sorted(set(open_ids)):
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_JOURNAL_UNOBSERVABLE", f"{participant_id} journal inventory is not canonical")
    if value["recovery_required"] is not False:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_RECOVERY_REQUIRED", f"{participant_id} requires recovery")
    if status != JOURNAL_CLEAN or open_ids:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_RECOVERY_REQUIRED", f"{participant_id} has an open or non-clean journal")
    return {
        "schema_version": JOURNAL_SCHEMA,
        "journal_kind": _JOURNAL_KINDS[participant_id],
        "status": JOURNAL_CLEAN,
        "journal_sha256": value["journal_sha256"],
        "open_transaction_ids": [],
        "recovery_required": False,
    }


def _validate_safety(value: Mapping[str, Any], participant_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _SAFETY_KEYS:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", f"{participant_id} safety schema is not exact")
    if value["read_only"] is not True:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST", f"{participant_id} is not read-only")
    for key in ("lock_held", "reservation", "mutation_performed", "write_authority", "atomicity_claimed"):
        if value[key] is not False:
            raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST", f"{participant_id}.safety.{key} must be false")
    return {
        "read_only": True,
        "lock_held": False,
        "reservation": False,
        "mutation_performed": False,
        "write_authority": False,
        "atomicity_claimed": False,
    }


def _validate_before(value: Mapping[str, Any], expected: Mapping[str, Any], participant_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(expected):
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", f"{participant_id}.before key set is not exact")
    for key, observed in value.items():
        target = expected[key]
        if key in {"prime_previous_head_sha256"}:
            if observed is not None:
                _hash64(observed, f"{participant_id}.before.{key}")
        elif key.endswith("_sha256"):
            _hash64(observed, f"{participant_id}.before.{key}")
        elif key in {"card_state_version", "attempt_state_version", "dispatch_row_version", "clock_after_epoch", "fencing_epoch", "lease_expires_at"}:
            _nonnegative_int(observed, f"{participant_id}.before.{key}")
        elif key == "last_committed_event_id":
            _optional_text(observed, f"{participant_id}.before.{key}")
        else:
            _text(observed, f"{participant_id}.before.{key}")
        if observed != target:
            raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_PRECONDITION_MISMATCH", f"{participant_id}.before.{key} drifted")
    return copy.deepcopy(dict(expected))


def _validate_participants(participants: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    if set(participants) != PARTICIPANT_IDS:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_PARTICIPANT_SET_INVALID", "participant set is not exact")
    normalized: dict[str, Any] = {}
    for participant_id in sorted(PARTICIPANT_IDS):
        value = participants[participant_id]
        if not isinstance(value, Mapping) or set(value) != _PARTICIPANT_KEYS:
            raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_PARTICIPANT_SET_INVALID", f"{participant_id} observation is incomplete")
        if value["schema_version"] != PARTICIPANT_SCHEMA or value["participant_id"] != participant_id:
            raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_PARTICIPANT_SET_INVALID", f"{participant_id} identity is invalid")
        if value["status"] != PARTICIPANT_STATUS:
            raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_PRECONDITION_MISMATCH", f"{participant_id} is not a read-only observation")
        normalized[participant_id] = {
            "schema_version": PARTICIPANT_SCHEMA,
            "participant_id": participant_id,
            "status": PARTICIPANT_STATUS,
            "before": _validate_before(value["before"], _expected_before(participant_id, expected), participant_id),
            "journal": _validate_journal(value["journal"], participant_id),
            "safety": _validate_safety(value["safety"], participant_id),
        }
    return normalized


def _fresh_s9(
    capture: Mapping[str, Any],
    anchor: Any,
    control_capture: Mapping[str, Any],
    head: Any,
    plan: Any,
    *,
    s8_kwargs: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        s9 = verify_prime_consume_plan(capture, anchor, control_capture, head, plan, s8_kwargs=s8_kwargs)
    except PrimeTransactionError as exc:
        raise PrimeTransactionPreviewError(
            "PRIME_TX_PREVIEW_S9_NOT_SATISFIED",
            "fresh S9 verification failed",
            cause_code=exc.code,
        ) from exc
    try:
        checked_plan = parse_prime_consume_plan(plan)
    except PrimeTransactionError as exc:
        raise PrimeTransactionPreviewError(
            "PRIME_TX_PREVIEW_S9_NOT_SATISFIED",
            "S9 plan could not be parsed after verification",
            cause_code=exc.code,
        ) from exc
    return s9, checked_plan


def _build_preview(s9: Mapping[str, Any], plan: Mapping[str, Any], participants: Mapping[str, Any]) -> dict[str, Any]:
    participant_digest = canonical_hash(participants)
    plan_hash = canonical_hash(plan)
    s9_digest = canonical_hash(s9)
    digest = canonical_hash(
        {
            "plan_sha256": plan_hash,
            "participant_observations_sha256": participant_digest,
            "s9_verification_sha256": s9_digest,
        }
    )
    preview = {
        "schema_version": PRIME_TRANSACTION_PARTICIPANT_PREVIEW_VERIFICATION_SCHEMA,
        "contract_role": PRIME_TRANSACTION_PREVIEW_ROLE,
        "status": "PARTICIPANT_PREVIEW_ONLY_READ_ONLY",
        "s9_verification_sha256": s9_digest,
        "plan_sha256": plan_hash,
        "participant_observations_sha256": participant_digest,
        "preview_id": f"preview-{digest[:32]}",
        "prepare_digest": digest,
        "subject": copy.deepcopy(dict(plan["subject"])),
        "participant_ids": sorted(PARTICIPANT_IDS),
        "participant_journal_statuses": {key: JOURNAL_CLEAN for key in sorted(PARTICIPANT_IDS)},
        "coordinator_state": "PREPARED",
        "required_next_state": "COMMIT_RECHECK_REQUIRED",
        "failure_states": list(_FAILURE_STATES),
        "atomic_commit_required": True,
        "participant_recheck_required": True,
        "queue_journal_recheck_required": True,
        "lease_recheck_required": True,
        "fencing_recheck_required": True,
        "receipt_recheck_required": True,
        "effect_defined": False,
        "expected_after_observed": False,
        "authoritative_prepared": False,
        "idempotency_reserved": False,
        "transaction_authority": "DEFERRED_TO_ATOMIC_COORDINATOR",
        "mutation_window_open": False,
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
    return preview


def _validate_preview_shape(preview: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(preview, Mapping) or set(preview) != _PREVIEW_KEYS:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", "preview key set is not exact")
    if preview["schema_version"] != PRIME_TRANSACTION_PARTICIPANT_PREVIEW_VERIFICATION_SCHEMA:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", "unsupported preview schema")
    if preview["contract_role"] != PRIME_TRANSACTION_PREVIEW_ROLE:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST", "preview role is executable")
    if preview["status"] != "PARTICIPANT_PREVIEW_ONLY_READ_ONLY":
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", "preview status is not read-only")
    for key in ("s9_verification_sha256", "plan_sha256", "participant_observations_sha256", "prepare_digest"):
        _hash64(preview[key], f"preview.{key}")
    _safe_id(preview["preview_id"], "preview.preview_id")
    subject = preview["subject"]
    if not isinstance(subject, Mapping) or set(subject) != {"prime_run_id", "w5_run_id", "card_id", "attempt_id", "dispatch_id"}:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SUBJECT_MISMATCH", "preview subject is incomplete")
    checked_subject = {key: _safe_id(subject[key], f"preview.subject.{key}") for key in sorted(subject)}
    ids = preview["participant_ids"]
    if ids != sorted(PARTICIPANT_IDS):
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_PARTICIPANT_SET_INVALID", "preview participant IDs are not exact")
    statuses = preview["participant_journal_statuses"]
    if statuses != {key: JOURNAL_CLEAN for key in sorted(PARTICIPANT_IDS)}:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_RECOVERY_REQUIRED", "preview journal status is not clean")
    if preview["coordinator_state"] != "PREPARED" or preview["required_next_state"] != "COMMIT_RECHECK_REQUIRED":
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST", "preview coordinator state is executable")
    if preview["failure_states"] != _FAILURE_STATES:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SCHEMA_INVALID", "preview failure state contract drifted")
    for key in (
        "atomic_commit_required",
        "participant_recheck_required",
        "queue_journal_recheck_required",
        "lease_recheck_required",
        "fencing_recheck_required",
        "receipt_recheck_required",
    ):
        if preview[key] is not True:
            raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST", f"preview.{key} must be true")
    for key in (
        "effect_defined",
        "expected_after_observed",
        "authoritative_prepared",
        "idempotency_reserved",
        "mutation_window_open",
        "reservation",
        "lock_held",
        "mutation_performed",
        "external_action",
        "resume_allowed",
        "consume_allowed",
        "cas_authorized",
    ):
        if preview[key] is not False:
            raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST", f"preview.{key} must be false")
    if preview["transaction_authority"] != "DEFERRED_TO_ATOMIC_COORDINATOR" or preview["cross_store_atomicity"] != "not_claimed":
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST", "preview claims transaction authority")
    if preview["permission"] != "read_only":
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST", "preview permission is not read-only")
    execution = preview["execution"]
    if not isinstance(execution, Mapping) or set(execution) != set(_EXECUTION_FALSE) or any(value is not False for value in execution.values()):
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST", "preview execution flags are not actionless")
    return {
        **dict(preview),
        "subject": checked_subject,
        "participant_ids": sorted(PARTICIPANT_IDS),
        "participant_journal_statuses": {key: JOURNAL_CLEAN for key in sorted(PARTICIPANT_IDS)},
        "failure_states": list(_FAILURE_STATES),
        "execution": dict(_EXECUTION_FALSE),
    }


def build_prime_transaction_preview(
    capture: Mapping[str, Any],
    anchor: Any,
    control_capture: Mapping[str, Any],
    head: Any,
    plan: Mapping[str, Any] | bytes | str | None,
    *,
    participants: Mapping[str, Any],
    s8_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a participant preview after fresh S9 verification."""

    frozen_capture, frozen_anchor, frozen_control, frozen_head, frozen_plan, frozen_participants, frozen_s8 = _freeze_inputs(
        capture, anchor, control_capture, head, plan, participants, s8_kwargs
    )
    s9, checked_plan = _fresh_s9(
        frozen_capture,
        frozen_anchor,
        frozen_control,
        frozen_head,
        frozen_plan,
        s8_kwargs=frozen_s8,
    )
    normalized = _validate_participants(frozen_participants, checked_plan["expected"])
    return _build_preview(s9, checked_plan, normalized)


def verify_prime_transaction_preview(
    capture: Mapping[str, Any],
    anchor: Any,
    control_capture: Mapping[str, Any],
    head: Any,
    plan: Mapping[str, Any] | bytes | str | None,
    preview: Mapping[str, Any] | bytes | str | None,
    *,
    participants: Mapping[str, Any],
    s8_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify a preview against fresh S9 and participant observations."""

    frozen_capture, frozen_anchor, frozen_control, frozen_head, frozen_plan, frozen_participants, frozen_s8 = _freeze_inputs(
        capture, anchor, control_capture, head, plan, participants, s8_kwargs
    )
    s9, checked_plan = _fresh_s9(
        frozen_capture,
        frozen_anchor,
        frozen_control,
        frozen_head,
        frozen_plan,
        s8_kwargs=frozen_s8,
    )
    normalized = _validate_participants(frozen_participants, checked_plan["expected"])
    expected = _build_preview(s9, checked_plan, normalized)
    checked_preview = _validate_preview_shape(parse_prime_transaction_preview(preview))
    if checked_preview["subject"] != expected["subject"]:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_SUBJECT_MISMATCH", "preview subject does not match fresh S9")
    if checked_preview != expected:
        raise PrimeTransactionPreviewError("PRIME_TX_PREVIEW_PLAN_MISMATCH", "preview does not match fresh S9/participant evidence")
    return expected


def evaluate_prime_transaction_preview(
    capture: Mapping[str, Any],
    anchor: Any,
    control_capture: Mapping[str, Any],
    head: Any,
    plan: Mapping[str, Any] | bytes | str | None,
    preview: Mapping[str, Any] | bytes | str | None,
    *,
    participants: Mapping[str, Any],
    s8_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Return actionless HOLD for every failed preview condition."""

    try:
        return verify_prime_transaction_preview(
            capture,
            anchor,
            control_capture,
            head,
            plan,
            preview,
            participants=participants,
            s8_kwargs=s8_kwargs,
        )
    except PrimeTransactionPreviewError as exc:
        result = {
            "schema_version": PRIME_TRANSACTION_PARTICIPANT_PREVIEW_VERIFICATION_SCHEMA,
            "contract_role": PRIME_TRANSACTION_PREVIEW_ROLE,
            "status": "HOLD",
            "reason": exc.code,
            "transaction_authority": "NONE",
            "mutation_window_open": False,
            "atomic_commit_required": True,
            "permission": "read_only",
            "external_action": False,
            "resume_allowed": False,
            "consume_allowed": False,
            "cas_authorized": False,
            "execution": dict(_EXECUTION_FALSE),
        }
        if exc.cause_code is not None:
            result["cause_code"] = exc.cause_code
        return result
    except (TypeError, ValueError, KeyError, AttributeError):
        return {
            "schema_version": PRIME_TRANSACTION_PARTICIPANT_PREVIEW_VERIFICATION_SCHEMA,
            "contract_role": PRIME_TRANSACTION_PREVIEW_ROLE,
            "status": "HOLD",
            "reason": "PRIME_TX_PREVIEW_SCHEMA_INVALID",
            "transaction_authority": "NONE",
            "mutation_window_open": False,
            "atomic_commit_required": True,
            "permission": "read_only",
            "external_action": False,
            "resume_allowed": False,
            "consume_allowed": False,
            "cas_authorized": False,
            "execution": dict(_EXECUTION_FALSE),
        }


__all__ = [
    "JOURNAL_SCHEMA",
    "PARTICIPANT_IDS",
    "PARTICIPANT_SCHEMA",
    "PREVIEW_ERROR_CODES",
    "PRIME_TRANSACTION_PARTICIPANT_PREVIEW_SCHEMA",
    "PRIME_TRANSACTION_PARTICIPANT_PREVIEW_VERIFICATION_SCHEMA",
    "PRIME_TRANSACTION_PREVIEW_ROLE",
    "PrimeTransactionPreviewError",
    "build_prime_transaction_preview",
    "evaluate_prime_transaction_preview",
    "parse_prime_transaction_preview",
    "verify_prime_transaction_preview",
]
