"""W5-S12 pure Cross-Store fixture and T0-T5 classification harness.

The harness consumes an isolated, caller-supplied observation.  It never
opens SQLite or a file, acquires a lock, starts a process, performs recovery,
or writes a reservation/marker.  Its job is narrower and deliberately
boring: verify that a synthetic fixture is internally coherent, then classify
the observed point in a T0-T5 trace.

The v2 fixture binds hashes to the supplied canonical material instead of
accepting a bag of caller-supplied digests.  This does not prove that a live
store really had that state; only a live, independently fenced observer can
do that.  It does prevent the harness itself from turning self-consistent,
but semantically unrelated digest strings into commit evidence.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash


CROSS_STORE_FIXTURE_SCHEMA = "prime-cross-store-fixture-v2"
CROSS_STORE_FIXTURE_VERIFICATION_SCHEMA = "prime-cross-store-fixture-verification-v2"
CROSS_STORE_FIXTURE_ROLE = "cross_store_fixture_read_only"
CROSS_STORE_PARTICIPANT_IDS = frozenset(
    {"control_plane", "knowledge_ledger", "prime_ledger", "prime_queue", "receipt_projection"}
)
HOOK_IDS = (
    "T0.before_prepare",
    "T0.after_prepare",
    "T1.coordinator_prepared",
    "T2.prime_prepared",
    "T2.after_replace",
    "T3.sqlite_before_commit",
    "T3.sqlite_after_commit",
    "T4.prime_projection_before_replace",
    "T4.prime_projection_after_replace",
    "T5.before_final_marker",
    "T5.after_final_marker",
)
HOOK_PARTICIPANTS = {
    "T0.before_prepare": "coordinator",
    "T0.after_prepare": "coordinator",
    "T1.coordinator_prepared": "control_plane",
    "T2.prime_prepared": "prime_ledger",
    "T2.after_replace": "prime_ledger",
    "T3.sqlite_before_commit": "control_plane",
    "T3.sqlite_after_commit": "control_plane",
    "T4.prime_projection_before_replace": "prime_queue",
    "T4.prime_projection_after_replace": "prime_queue",
    "T5.before_final_marker": "receipt_projection",
    "T5.after_final_marker": "receipt_projection",
}
_ALL_BEFORE_STATES = {participant_id: "BEFORE" for participant_id in sorted(CROSS_STORE_PARTICIPANT_IDS)}
_ALL_AFTER_STATES = {participant_id: "AFTER" for participant_id in sorted(CROSS_STORE_PARTICIPANT_IDS)}
_EXPECTED_HOOK_AFTER_STATES = {
    "T0.before_prepare": dict(_ALL_BEFORE_STATES),
    "T0.after_prepare": dict(_ALL_BEFORE_STATES),
    "T1.coordinator_prepared": dict(_ALL_BEFORE_STATES),
    "T2.prime_prepared": dict(_ALL_BEFORE_STATES),
    "T2.after_replace": {**_ALL_BEFORE_STATES, "prime_ledger": "AFTER"},
    "T3.sqlite_before_commit": {**_ALL_BEFORE_STATES, "prime_ledger": "AFTER"},
    "T3.sqlite_after_commit": {**_ALL_BEFORE_STATES, "prime_ledger": "AFTER", "control_plane": "AFTER"},
    "T4.prime_projection_before_replace": {
        **_ALL_BEFORE_STATES,
        "prime_ledger": "AFTER",
        "control_plane": "AFTER",
    },
    "T4.prime_projection_after_replace": {
        **_ALL_BEFORE_STATES,
        "prime_ledger": "AFTER",
        "prime_queue": "AFTER",
        "control_plane": "AFTER",
    },
    "T5.before_final_marker": {
        **_ALL_BEFORE_STATES,
        "prime_ledger": "AFTER",
        "prime_queue": "AFTER",
        "control_plane": "AFTER",
        "knowledge_ledger": "AFTER",
    },
    "T5.after_final_marker": dict(_ALL_AFTER_STATES),
}
_EFFECT_OPERATION_POLICY = {
    "control_plane": "cas",
    "knowledge_ledger": "observe",
    "prime_ledger": "replace",
    "prime_queue": "replace",
    "receipt_projection": "seal",
}
PREPARED_PREFIX_LENGTH = HOOK_IDS.index("T2.prime_prepared") + 1
FIXTURE_PARTICIPANT_PROJECTION_KEYS = frozenset(
    {
        "state",
        "journal",
        "state_sha256",
        "journal_sha256",
        "version",
        "generation",
        "generation_id",
        "parent_hash",
    }
)
FIXTURE_PARTICIPANT_BUNDLE_KEYS = frozenset({"expected_before", "expected_after", "observed"})
FIXTURE_BINDING_KEYS = frozenset({"contract", "subject_binding", "effect_set", "marker"})
FIXTURE_EFFECT_KEYS = frozenset(
    {
        "participant_id",
        "target_id",
        "operation",
        "before_sha256",
        "after_sha256",
        "before_version",
        "after_version",
        "before_generation",
        "after_generation",
    }
)
FIXTURE_LEASE_KEYS = frozenset(
    {"owner_id", "token_sha256", "issued_at", "observed_at", "expires_at", "fencing_epoch"}
)
FIXTURE_HOOK_KEYS = frozenset(
    {
        "hook_id",
        "sequence",
        "invocation",
        "transaction_id",
        "participant_id",
        "fencing_epoch",
        "before_states",
        "after_states",
        "before_sha256",
        "after_sha256",
        "event_cursor",
        "journal_generation",
        "parent_event_sha256",
        "event_sha256",
        "status",
    }
)
FIXTURE_SAFETY_KEYS = frozenset(
    {"read_only", "lock_held", "reservation", "mutation_performed", "authoritative_commit"}
)
FIXTURE_KEYS = frozenset(
    {
        "schema_version",
        "contract_role",
        "transaction_id",
        "expected_contract_digest",
        "observed_contract_digest",
        "expected_subject_binding_digest",
        "observed_subject_binding_digest",
        "expected_effect_digest",
        "observed_effect_digest",
        "expected_participant_observations_sha256",
        "observed_participant_observations_sha256",
        "expected_marker_commitment_sha256",
        "observed_marker_commitment_sha256",
        "expected_fencing_epoch",
        "observed_fencing_epoch",
        "participants",
        "bindings",
        "lease",
        "hook_trace",
        "hook_trace_digest",
        "fault_hook_or_null",
        "safety",
    }
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HOOK_STATUS = "OBSERVED"
_EVENT_STATES = frozenset({"BEFORE", "AFTER"})
_MARKER_STATES = frozenset({"PENDING", "COMMITTED"})
_EXECUTION_FALSE = {"resume": False, "reconcile": False, "mutation": False, "network": False}

FIXTURE_ERROR_CODES = frozenset(
    {
        "PRIME_FIXTURE_NOT_OBSERVED",
        "PRIME_FIXTURE_JSON_INVALID",
        "PRIME_FIXTURE_JSON_DUPLICATE_KEY",
        "PRIME_FIXTURE_SCHEMA_INVALID",
        "PRIME_FIXTURE_BINDING_CONFLICT",
        "PRIME_FIXTURE_PARTICIPANT_INVALID",
        "PRIME_FIXTURE_EFFECT_INVALID",
        "PRIME_FIXTURE_HOOK_INVALID",
        "PRIME_FIXTURE_FENCE_INVALID",
        "PRIME_FIXTURE_UNSAFE_REQUEST",
        "PRIME_FIXTURE_RECOVERY_REQUIRED",
    }
)


class CrossStoreFixtureError(ValueError):
    """A supplied S12 fixture failed closed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in FIXTURE_ERROR_CODES:
            raise ValueError(f"unknown S12 fixture code: {code}")
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


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", f"{label} must be an integer >= 0")
    return value


def _canonical_digest(value: Any, label: str) -> str:
    try:
        return canonical_hash(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", f"{label} is not canonical JSON") from exc


def _copy_json(value: Any, label: str) -> Any:
    copied = copy.deepcopy(value)
    _canonical_digest(copied, label)
    return copied


def _optional_hash(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _hash64(value, label)


def _optional_safe_id(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _safe_id(value, label)


def parse_cross_store_fixture(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Isolate a caller-supplied fixture without performing external action."""

    if value is None:
        raise CrossStoreFixtureError("PRIME_FIXTURE_NOT_OBSERVED", "fixture is missing")
    if isinstance(value, Mapping):
        try:
            return copy.deepcopy(dict(value))
        except (TypeError, ValueError, copy.Error) as exc:
            raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", "fixture could not be isolated") from exc
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CrossStoreFixtureError("PRIME_FIXTURE_JSON_INVALID", "fixture is not UTF-8") from exc
    if not isinstance(value, str):
        raise CrossStoreFixtureError("PRIME_FIXTURE_JSON_INVALID", "fixture object or JSON text required")
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except _DuplicateJsonKey as exc:
        raise CrossStoreFixtureError("PRIME_FIXTURE_JSON_DUPLICATE_KEY", f"duplicate key: {exc}") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CrossStoreFixtureError("PRIME_FIXTURE_JSON_INVALID", "fixture JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", "fixture JSON object required")
    return parsed


def _validate_projection(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != FIXTURE_PARTICIPANT_PROJECTION_KEYS:
        raise CrossStoreFixtureError("PRIME_FIXTURE_PARTICIPANT_INVALID", f"{label} projection keys are not exact")
    state = _copy_json(value["state"], f"{label}.state")
    journal = _copy_json(value["journal"], f"{label}.journal")
    state_digest = _hash64(value["state_sha256"], f"{label}.state_sha256")
    journal_digest = _hash64(value["journal_sha256"], f"{label}.journal_sha256")
    if state_digest != _canonical_digest(state, f"{label}.state"):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", f"{label}.state_sha256 does not bind state")
    if journal_digest != _canonical_digest(journal, f"{label}.journal"):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", f"{label}.journal_sha256 does not bind journal")
    return {
        "state": state,
        "journal": journal,
        "state_sha256": state_digest,
        "journal_sha256": journal_digest,
        "version": _nonnegative_int(value["version"], f"{label}.version"),
        "generation": _nonnegative_int(value["generation"], f"{label}.generation"),
        "generation_id": _hash64(value["generation_id"], f"{label}.generation_id"),
        "parent_hash": _optional_hash(value["parent_hash"], f"{label}.parent_hash"),
    }


def _validate_participants(value: Any) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != CROSS_STORE_PARTICIPANT_IDS:
        raise CrossStoreFixtureError("PRIME_FIXTURE_PARTICIPANT_INVALID", "participant set is not exact")
    normalized: dict[str, dict[str, Any]] = {}
    states: dict[str, str] = {}
    for participant_id in sorted(CROSS_STORE_PARTICIPANT_IDS):
        item = value[participant_id]
        if not isinstance(item, Mapping) or set(item) != FIXTURE_PARTICIPANT_BUNDLE_KEYS:
            raise CrossStoreFixtureError("PRIME_FIXTURE_PARTICIPANT_INVALID", f"{participant_id} bundle keys are not exact")
        before = _validate_projection(item["expected_before"], f"participants.{participant_id}.expected_before")
        after = _validate_projection(item["expected_after"], f"participants.{participant_id}.expected_after")
        if after["version"] <= before["version"] or after["generation"] <= before["generation"]:
            raise CrossStoreFixtureError("PRIME_FIXTURE_PARTICIPANT_INVALID", f"{participant_id} after version/generation is not newer")
        if after["parent_hash"] != before["state_sha256"]:
            raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", f"{participant_id} after parent is not before state")
        if after["generation_id"] == before["generation_id"]:
            raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", f"{participant_id} generation id was reused")
        observed = item["observed"]
        if observed is None:
            normalized_observed = None
            state = "UNKNOWN"
        else:
            normalized_observed = _validate_projection(observed, f"participants.{participant_id}.observed")
            if normalized_observed == before:
                state = "BEFORE"
            elif normalized_observed == after:
                state = "AFTER"
            else:
                state = "DRIFT"
        normalized[participant_id] = {
            "expected_before": before,
            "expected_after": after,
            "observed": normalized_observed,
        }
        states[participant_id] = state
    return normalized, states


def _validate_effect_set(value: Any, participants: Mapping[str, Mapping[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(value, list) or not value:
        raise CrossStoreFixtureError("PRIME_FIXTURE_EFFECT_INVALID", "effect_set must be a non-empty list")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != FIXTURE_EFFECT_KEYS:
            raise CrossStoreFixtureError("PRIME_FIXTURE_EFFECT_INVALID", f"effect_set[{index}] keys are not exact")
        participant_id = _safe_id(item["participant_id"], f"effect_set[{index}].participant_id")
        if participant_id not in CROSS_STORE_PARTICIPANT_IDS or participant_id in seen:
            raise CrossStoreFixtureError("PRIME_FIXTURE_EFFECT_INVALID", f"effect_set participant is duplicate or unknown: {participant_id}")
        seen.add(participant_id)
        target_id = _safe_id(item["target_id"], f"effect_set[{index}].target_id")
        operation = _safe_id(item["operation"], f"effect_set[{index}].operation")
        if operation != _EFFECT_OPERATION_POLICY[participant_id]:
            raise CrossStoreFixtureError(
                "PRIME_FIXTURE_BINDING_CONFLICT",
                f"effect_set[{index}] violates the S11 read-only projection policy",
            )
        expected = participants[participant_id]
        before = expected["expected_before"]
        after = expected["expected_after"]
        effect = {
            "participant_id": participant_id,
            "target_id": target_id,
            "operation": operation,
            "before_sha256": _hash64(item["before_sha256"], f"effect_set[{index}].before_sha256"),
            "after_sha256": _hash64(item["after_sha256"], f"effect_set[{index}].after_sha256"),
            "before_version": _nonnegative_int(item["before_version"], f"effect_set[{index}].before_version"),
            "after_version": _nonnegative_int(item["after_version"], f"effect_set[{index}].after_version"),
            "before_generation": _nonnegative_int(item["before_generation"], f"effect_set[{index}].before_generation"),
            "after_generation": _nonnegative_int(item["after_generation"], f"effect_set[{index}].after_generation"),
        }
        if (
            effect["before_sha256"] != before["state_sha256"]
            or effect["after_sha256"] != after["state_sha256"]
            or effect["before_version"] != before["version"]
            or effect["after_version"] != after["version"]
            or effect["before_generation"] != before["generation"]
            or effect["after_generation"] != after["generation"]
        ):
            raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", f"effect_set[{index}] does not cover participant transition")
        normalized.append(effect)
    if seen != set(CROSS_STORE_PARTICIPANT_IDS):
        raise CrossStoreFixtureError("PRIME_FIXTURE_EFFECT_INVALID", "effect_set does not cover every participant exactly once")
    normalized.sort(key=lambda item: (item["participant_id"], item["target_id"], item["operation"]))
    return normalized, _canonical_digest(normalized, "effect_set")


def _validate_state_map(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != CROSS_STORE_PARTICIPANT_IDS:
        raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", f"{label} participant state set is not exact")
    normalized: dict[str, str] = {}
    for participant_id in sorted(CROSS_STORE_PARTICIPANT_IDS):
        state = value[participant_id]
        if state not in _EVENT_STATES:
            raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", f"{label}.{participant_id} state is invalid")
        normalized[participant_id] = state
    return normalized


def _event_commitment_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in event.items() if key != "event_sha256"}


def _validate_hook_trace(value: Any, transaction_id: str, expected_fencing_epoch: int) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(value, list) or not value or len(value) > len(HOOK_IDS):
        raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "hook_trace must be a non-empty canonical prefix")
    normalized: list[dict[str, Any]] = []
    cursors: set[str] = set()
    previous_after: dict[str, str] | None = None
    previous_event_hash: str | None = None
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != FIXTURE_HOOK_KEYS:
            raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", f"hook_trace[{index}] keys are not exact")
        hook_id = _safe_id(item["hook_id"], f"hook_trace[{index}].hook_id")
        if hook_id != HOOK_IDS[index] or HOOK_PARTICIPANTS[hook_id] != item["participant_id"]:
            raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", f"hook_trace[{index}] is not the canonical T0-T5 prefix")
        sequence = _nonnegative_int(item["sequence"], f"hook_trace[{index}].sequence")
        invocation = _nonnegative_int(item["invocation"], f"hook_trace[{index}].invocation")
        if sequence != index + 1 or invocation != 1:
            raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", f"hook_trace[{index}] sequence/invocation is not canonical")
        if item["transaction_id"] != transaction_id:
            raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "hook transaction_id differs from fixture")
        participant_id = _safe_id(item["participant_id"], f"hook_trace[{index}].participant_id")
        fencing_epoch = _nonnegative_int(item["fencing_epoch"], f"hook_trace[{index}].fencing_epoch")
        if fencing_epoch != expected_fencing_epoch:
            raise CrossStoreFixtureError("PRIME_FIXTURE_FENCE_INVALID", "hook fencing epoch differs from fixture")
        before_states = _validate_state_map(item["before_states"], f"hook_trace[{index}].before_states")
        after_states = _validate_state_map(item["after_states"], f"hook_trace[{index}].after_states")
        if after_states != _EXPECTED_HOOK_AFTER_STATES[hook_id]:
            raise CrossStoreFixtureError(
                "PRIME_FIXTURE_HOOK_INVALID",
                f"{hook_id} contains an impossible participant transition",
            )
        if index == 0:
            if any(state != "BEFORE" for state in before_states.values()):
                raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "first hook does not start at all-before")
            if item["parent_event_sha256"] is not None:
                raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "first hook has a parent event")
        elif before_states != previous_after or item["parent_event_sha256"] != previous_event_hash:
            raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", f"hook_trace[{index}] breaks the event chain")
        for state_participant in CROSS_STORE_PARTICIPANT_IDS:
            if previous_after is not None and previous_after[state_participant] == "AFTER" and after_states[state_participant] != "AFTER":
                raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "hook trace contains an ABA transition")
        cursor = _safe_id(item["event_cursor"], f"hook_trace[{index}].event_cursor")
        if cursor in cursors:
            raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "hook event cursor is duplicated")
        cursors.add(cursor)
        journal_generation = _nonnegative_int(item["journal_generation"], f"hook_trace[{index}].journal_generation")
        if journal_generation != sequence:
            raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "hook journal generation is not contiguous")
        if item["status"] != _HOOK_STATUS:
            raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "hook status must be OBSERVED")
        before_digest = _hash64(item["before_sha256"], f"hook_trace[{index}].before_sha256")
        after_digest = _hash64(item["after_sha256"], f"hook_trace[{index}].after_sha256")
        if before_digest != _canonical_digest(before_states, f"hook_trace[{index}].before_states"):
            raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "hook before digest does not bind state map")
        if after_digest != _canonical_digest(after_states, f"hook_trace[{index}].after_states"):
            raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "hook after digest does not bind state map")
        event = {
            "hook_id": hook_id,
            "sequence": sequence,
            "invocation": invocation,
            "transaction_id": transaction_id,
            "participant_id": participant_id,
            "fencing_epoch": fencing_epoch,
            "before_states": before_states,
            "after_states": after_states,
            "before_sha256": before_digest,
            "after_sha256": after_digest,
            "event_cursor": cursor,
            "journal_generation": journal_generation,
            "parent_event_sha256": _optional_hash(item["parent_event_sha256"], f"hook_trace[{index}].parent_event_sha256"),
            "event_sha256": _hash64(item["event_sha256"], f"hook_trace[{index}].event_sha256"),
            "status": _HOOK_STATUS,
        }
        if event["event_sha256"] != _canonical_digest(_event_commitment_payload(event), f"hook_trace[{index}]"):
            raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "hook event digest does not bind event content")
        normalized.append(event)
        previous_after = after_states
        previous_event_hash = event["event_sha256"]
    return normalized, _canonical_digest(normalized, "hook_trace")


def _validate_lease(value: Any, transaction_id: str, expected_epoch: int) -> tuple[dict[str, Any], bool, bool]:
    if not isinstance(value, Mapping) or set(value) != FIXTURE_LEASE_KEYS:
        raise CrossStoreFixtureError("PRIME_FIXTURE_FENCE_INVALID", "lease keys are not exact")
    normalized = {
        "owner_id": _safe_id(value["owner_id"], "lease.owner_id"),
        "token_sha256": _hash64(value["token_sha256"], "lease.token_sha256"),
        "issued_at": _nonnegative_int(value["issued_at"], "lease.issued_at"),
        "observed_at": _nonnegative_int(value["observed_at"], "lease.observed_at"),
        "expires_at": _nonnegative_int(value["expires_at"], "lease.expires_at"),
        "fencing_epoch": _nonnegative_int(value["fencing_epoch"], "lease.fencing_epoch"),
    }
    expected_token = _canonical_digest(
        {"transaction_id": transaction_id, "owner": normalized["owner_id"]}, "lease.token_binding"
    )
    if normalized["token_sha256"] != expected_token:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "lease token is not bound to transaction and owner")
    lease_live = normalized["issued_at"] <= normalized["observed_at"] < normalized["expires_at"]
    epoch_match = normalized["fencing_epoch"] == expected_epoch
    return normalized, lease_live, epoch_match


def _validate_marker(
    value: Any,
    transaction_id: str,
    effect_digest: str,
    participant_digest: str,
    fencing_epoch: int,
) -> tuple[dict[str, Any], str]:
    marker_keys = frozenset({"transaction_id", "effect_digest", "participant_observations_sha256", "fencing_epoch", "status"})
    if not isinstance(value, Mapping) or set(value) != marker_keys:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "marker material keys are not exact")
    normalized = {
        "transaction_id": _safe_id(value["transaction_id"], "bindings.marker.transaction_id"),
        "effect_digest": _hash64(value["effect_digest"], "bindings.marker.effect_digest"),
        "participant_observations_sha256": _hash64(
            value["participant_observations_sha256"], "bindings.marker.participant_observations_sha256"
        ),
        "fencing_epoch": _nonnegative_int(value["fencing_epoch"], "bindings.marker.fencing_epoch"),
        "status": _text(value["status"], "bindings.marker.status"),
    }
    if normalized["transaction_id"] != transaction_id or normalized["effect_digest"] != effect_digest:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "marker is bound to another transaction/effect")
    if normalized["participant_observations_sha256"] != participant_digest or normalized["fencing_epoch"] != fencing_epoch:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "marker is not bound to observed participants/fence")
    if normalized["status"] not in _MARKER_STATES:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "marker status is unknown")
    return normalized, _canonical_digest(normalized, "bindings.marker")


def _validate_subject_binding_material(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "subject_binding material must be an object")
    if set(value) == {"subject", "subject_binding"}:
        subject = value["subject"]
        subject_binding = value["subject_binding"]
        if not isinstance(subject, Mapping) or not isinstance(subject_binding, Mapping):
            raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "composite subject material is malformed")
        for key in ("project_id", "goal_id", "run_id", "plan_id", "task_id", "card_id", "attempt_id", "dispatch_id"):
            _safe_id(subject.get(key), f"bindings.subject_binding.subject.{key}")
        return {
            "subject": _copy_json(subject, "bindings.subject_binding.subject"),
            "subject_binding": _copy_json(subject_binding, "bindings.subject_binding.subject_binding"),
        }
    required = {
        "project_id",
        "goal_id",
        "task_id",
        "plan_id",
        "card_id",
        "attempt_id",
        "dispatch_id",
    }
    if not required.issubset(set(value)):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "subject_binding misses S11 identity edges")
    normalized = _copy_json(value, "bindings.subject_binding")
    for key in sorted(required):
        _safe_id(normalized[key], f"bindings.subject_binding.{key}")
    return normalized


def _validate_s11_contract_material(value: Any, transaction_id: str, subject_binding: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract material must be an object")
    required = {
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
        "subagent_admission",
        "acceptance_enabled",
        "safety",
    }
    if not required.issubset(set(value)):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract is not an S11-v2 material binding")
    if value["schema_version"] != "prime-authoritative-coordinator-v2":
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract schema is not S11-v2")
    if value["contract_role"] != "authoritative_transaction_contract_read_only":
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract role is not read-only S11")
    if _safe_id(value["transaction_id"], "bindings.contract.transaction_id") != transaction_id:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract transaction differs from fixture")
    _safe_id(value["idempotency_key"], "bindings.contract.idempotency_key")
    if value["operation"] != "project_queue" or value["effect_mode"] != "PRIME_PROJECTION":
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "S12 only accepts read-only PRIME_PROJECTION/project_queue")
    subject = value["subject"]
    if not isinstance(subject, Mapping):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract subject is not an object")
    for key in ("project_id", "goal_id", "run_id", "plan_id", "task_id", "card_id", "attempt_id", "dispatch_id"):
        _safe_id(subject.get(key), f"bindings.contract.subject.{key}")
    if set(subject_binding) == {"subject", "subject_binding"}:
        if (
            copy.deepcopy(dict(subject_binding["subject"])) != copy.deepcopy(dict(subject))
            or copy.deepcopy(dict(subject_binding["subject_binding"])) != copy.deepcopy(dict(value["subject_binding"]))
        ):
            raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "composite contract subject differs from fixture subject")
    elif copy.deepcopy(dict(value["subject_binding"])) != copy.deepcopy(dict(subject_binding)):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract subject_binding differs from fixture subject")
    provenance = value["provenance"]
    if not isinstance(provenance, Mapping) or not provenance.get("source_refs"):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract provenance has no source references")
    provenance_status = provenance.get("provenance_status")
    if not isinstance(provenance_status, Mapping) or any(provenance_status.get(key) is not True for key in (
        "structural_provenance_verified", "content_supported", "temporal_valid", "derivation_traced"
    )):
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract provenance is not fully verified")
    context_gate = value["context_gate"]
    if not isinstance(context_gate, Mapping) or any(context_gate.get(key) is not False for key in (
        "task_loss", "decision_loss", "blocker_loss", "provenance_loss"
    )) or context_gate.get("contradiction_rate") != 0:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "contract context gate is not loss-free")
    admission = value["subagent_admission"]
    if not isinstance(admission, Mapping) or admission.get("enabled") is not False or admission.get("child_count") != 0 or admission.get("parallelism") is not False or admission.get("max_depth") != 0:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "S11 P2 admission is not hard-disabled")
    if value["acceptance_enabled"] is not False:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "P0 acceptance is enabled in fixture contract")
    safety = value["safety"]
    if not isinstance(safety, Mapping) or safety.get("read_only") is not True or any(
        safety.get(key) is not False for key in ("lock_held", "reservation", "mutation_performed", "authoritative_commit")
    ):
        raise CrossStoreFixtureError("PRIME_FIXTURE_UNSAFE_REQUEST", "S11 contract safety is not actionless")
    for key, expected in {
        "external_action": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "mutation_performed": False,
    }.items():
        if key in value and value[key] is not expected:
            raise CrossStoreFixtureError("PRIME_FIXTURE_UNSAFE_REQUEST", f"contract {key} is unsafe")
    return _copy_json(value, "bindings.contract")


def _validate_bindings(
    value: Any,
    transaction_id: str,
    participants: Mapping[str, Mapping[str, Any]],
    participant_digest: str,
    fencing_epoch: int,
) -> tuple[dict[str, Any], str, str, str, bool]:
    if not isinstance(value, Mapping) or set(value) != FIXTURE_BINDING_KEYS:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "binding material keys are not exact")
    contract = _copy_json(value["contract"], "bindings.contract")
    subject = _validate_subject_binding_material(value["subject_binding"])
    effects, effect_digest = _validate_effect_set(value["effect_set"], participants)
    marker, marker_digest = _validate_marker(value["marker"], transaction_id, effect_digest, participant_digest, fencing_epoch)
    normalized = {"contract": contract, "subject_binding": subject, "effect_set": effects, "marker": marker}
    return (
        normalized,
        _canonical_digest(contract, "bindings.contract"),
        _canonical_digest(subject, "bindings.subject_binding"),
        effect_digest,
        marker_digest == _canonical_digest(marker, "bindings.marker"),
    )


def _validate_safety(value: Any) -> dict[str, bool]:
    if not isinstance(value, Mapping) or set(value) != FIXTURE_SAFETY_KEYS:
        raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", "fixture safety keys are not exact")
    if value["read_only"] is not True or any(
        value[key] is not False for key in ("lock_held", "reservation", "mutation_performed", "authoritative_commit")
    ):
        raise CrossStoreFixtureError("PRIME_FIXTURE_UNSAFE_REQUEST", "fixture must remain actionless")
    return {
        "read_only": True,
        "lock_held": False,
        "reservation": False,
        "mutation_performed": False,
        "authoritative_commit": False,
    }


def _default_effect_set(participants: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    effects = []
    for participant_id in sorted(CROSS_STORE_PARTICIPANT_IDS):
        before = participants[participant_id]["expected_before"]
        after = participants[participant_id]["expected_after"]
        effects.append(
            {
                "participant_id": participant_id,
                "target_id": participant_id,
                "operation": _EFFECT_OPERATION_POLICY[participant_id],
                "before_sha256": before["state_sha256"],
                "after_sha256": after["state_sha256"],
                "before_version": before["version"],
                "after_version": after["version"],
                "before_generation": before["generation"],
                "after_generation": after["generation"],
            }
        )
    return effects


def build_cross_store_hook_trace(
    *,
    transaction_id: str,
    fencing_epoch: int,
    state_after_by_hook: Mapping[str, Mapping[str, str]] | None = None,
    event_cursor_prefix: str = "event",
) -> list[dict[str, Any]]:
    """Create a deterministic synthetic T0-T5 event chain for tests."""

    transaction_id = _safe_id(transaction_id, "transaction_id")
    fencing_epoch = _nonnegative_int(fencing_epoch, "fencing_epoch")
    cursor_prefix = _safe_id(event_cursor_prefix, "event_cursor_prefix")
    before = dict(_ALL_BEFORE_STATES)
    snapshots: dict[str, dict[str, str]] = {
        hook_id: dict(states) for hook_id, states in _EXPECTED_HOOK_AFTER_STATES.items()
    }
    if state_after_by_hook is not None:
        for hook_id, states in state_after_by_hook.items():
            if hook_id not in HOOK_IDS or not isinstance(states, Mapping):
                raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "custom hook state map is invalid")
            snapshots[hook_id] = _validate_state_map(states, f"state_after_by_hook.{hook_id}")
    events: list[dict[str, Any]] = []
    previous_after = before
    previous_hash: str | None = None
    for index, hook_id in enumerate(HOOK_IDS):
        after = snapshots[hook_id]
        if after != _EXPECTED_HOOK_AFTER_STATES[hook_id]:
            raise CrossStoreFixtureError(
                "PRIME_FIXTURE_HOOK_INVALID",
                f"{hook_id} contains an impossible participant transition",
            )
        event = {
            "hook_id": hook_id,
            "sequence": index + 1,
            "invocation": 1,
            "transaction_id": transaction_id,
            "participant_id": HOOK_PARTICIPANTS[hook_id],
            "fencing_epoch": fencing_epoch,
            "before_states": dict(previous_after),
            "after_states": dict(after),
            "before_sha256": _canonical_digest(previous_after, f"{hook_id}.before_states"),
            "after_sha256": _canonical_digest(after, f"{hook_id}.after_states"),
            "event_cursor": f"{cursor_prefix}-{index + 1:03d}",
            "journal_generation": index + 1,
            "parent_event_sha256": previous_hash,
            "status": _HOOK_STATUS,
        }
        event["event_sha256"] = _canonical_digest(event, hook_id)
        events.append(event)
        previous_after = after
        previous_hash = event["event_sha256"]
    return events


def build_cross_store_fixture(
    *,
    transaction_id: str,
    fencing_epoch: int,
    participants: Mapping[str, Any],
    hook_trace: list[Mapping[str, Any]],
    contract_material: Any | None = None,
    subject_binding_material: Any | None = None,
    effect_set: list[Mapping[str, Any]] | None = None,
    marker_material: Mapping[str, Any] | None = None,
    lease: Mapping[str, Any] | None = None,
    lease_valid: bool = True,
    contract_digest: str | None = None,
    subject_binding_digest: str | None = None,
    effect_digest: str | None = None,
) -> dict[str, Any]:
    """Build an isolated fixture; this helper performs no external action."""

    transaction_id = _safe_id(transaction_id, "transaction_id")
    fencing_epoch = _nonnegative_int(fencing_epoch, "fencing_epoch")
    if lease_valid is not True and lease_valid is not False:
        raise CrossStoreFixtureError("PRIME_FIXTURE_FENCE_INVALID", "lease_valid must be boolean")
    normalized_participants, _ = _validate_participants(participants)
    observed_digest = _canonical_digest(
        {key: normalized_participants[key]["observed"] for key in sorted(normalized_participants)},
        "participants.observed",
    )
    effects = _default_effect_set(normalized_participants) if effect_set is None else copy.deepcopy(list(effect_set))
    normalized_effects, calculated_effect_digest = _validate_effect_set(effects, normalized_participants)
    if effect_digest is not None and _hash64(effect_digest, "effect_digest") != calculated_effect_digest:
        raise CrossStoreFixtureError("PRIME_FIXTURE_BINDING_CONFLICT", "declared effect_digest differs from effect material")
    if contract_material is None:
        contract_material = {
            "opaque_reference": _hash64(contract_digest, "contract_digest") if contract_digest is not None else transaction_id
        }
    if subject_binding_material is None:
        subject_binding_material = {
            "opaque_reference": _hash64(subject_binding_digest, "subject_binding_digest") if subject_binding_digest is not None else transaction_id
        }
    contract_material = _copy_json(contract_material, "bindings.contract")
    subject_binding_material = _copy_json(subject_binding_material, "bindings.subject_binding")
    calculated_contract_digest = _canonical_digest(contract_material, "bindings.contract")
    calculated_subject_digest = _canonical_digest(subject_binding_material, "bindings.subject_binding")
    if lease is None:
        lease = {
            "owner_id": "fixture-owner",
            "token_sha256": _canonical_digest({"transaction_id": transaction_id, "owner": "fixture-owner"}, "lease.token"),
            "issued_at": 100,
            "observed_at": 150 if lease_valid else 200,
            "expires_at": 200,
            "fencing_epoch": fencing_epoch,
        }
    normalized_lease = copy.deepcopy(dict(lease))
    if lease_valid is False:
        normalized_lease["observed_at"] = normalized_lease.get("expires_at", 0)
    marker = dict(marker_material) if marker_material is not None else {
        "transaction_id": transaction_id,
        "effect_digest": calculated_effect_digest,
        "participant_observations_sha256": observed_digest,
        "fencing_epoch": fencing_epoch,
        "status": "COMMITTED" if len(hook_trace) == len(HOOK_IDS) else "PENDING",
    }
    marker["transaction_id"] = transaction_id
    marker["effect_digest"] = calculated_effect_digest
    marker["participant_observations_sha256"] = observed_digest
    marker["fencing_epoch"] = fencing_epoch
    normalized_marker, marker_digest = _validate_marker(
        marker, transaction_id, calculated_effect_digest, observed_digest, fencing_epoch
    )
    normalized_hooks, hook_digest = _validate_hook_trace(hook_trace, transaction_id, fencing_epoch)
    fixture = {
        "schema_version": CROSS_STORE_FIXTURE_SCHEMA,
        "contract_role": CROSS_STORE_FIXTURE_ROLE,
        "transaction_id": transaction_id,
        "expected_contract_digest": calculated_contract_digest,
        "observed_contract_digest": calculated_contract_digest,
        "expected_subject_binding_digest": calculated_subject_digest,
        "observed_subject_binding_digest": calculated_subject_digest,
        "expected_effect_digest": calculated_effect_digest,
        "observed_effect_digest": calculated_effect_digest,
        "expected_participant_observations_sha256": observed_digest,
        "observed_participant_observations_sha256": observed_digest,
        "expected_marker_commitment_sha256": marker_digest,
        "observed_marker_commitment_sha256": marker_digest,
        "expected_fencing_epoch": fencing_epoch,
        "observed_fencing_epoch": fencing_epoch,
        "participants": normalized_participants,
        "bindings": {
            "contract": contract_material,
            "subject_binding": subject_binding_material,
            "effect_set": normalized_effects,
            "marker": normalized_marker,
        },
        "lease": normalized_lease,
        "hook_trace": normalized_hooks,
        "hook_trace_digest": hook_digest,
        "fault_hook_or_null": None,
        "safety": {
            "read_only": True,
            "lock_held": False,
            "reservation": False,
            "mutation_performed": False,
            "authoritative_commit": False,
        },
    }
    classify_cross_store_fixture(fixture)
    return fixture


def inject_cross_store_fault(value: Mapping[str, Any] | bytes | str, hook_id: str) -> dict[str, Any]:
    """Model a one-shot crash by truncating to a canonical hook prefix."""

    fixture = parse_cross_store_fixture(value)
    hook_id = _safe_id(hook_id, "fault_hook")
    if hook_id not in HOOK_IDS:
        raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "unknown T0-T5 fault hook")
    index = HOOK_IDS.index(hook_id)
    trace = fixture.get("hook_trace")
    if not isinstance(trace, list) or len(trace) <= index:
        raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "fault hook is not present in fixture trace")
    fixture["hook_trace"] = copy.deepcopy(trace[: index + 1])
    fixture["hook_trace_digest"] = _canonical_digest(fixture["hook_trace"], "hook_trace")
    last_states = fixture["hook_trace"][-1]["after_states"]
    participants = fixture["participants"]
    for participant_id in sorted(CROSS_STORE_PARTICIPANT_IDS):
        state = last_states[participant_id]
        participants[participant_id]["observed"] = copy.deepcopy(
            participants[participant_id]["expected_after" if state == "AFTER" else "expected_before"]
        )
    observed_digest = _canonical_digest(
        {key: participants[key]["observed"] for key in sorted(participants)}, "participants.observed"
    )
    fixture["expected_participant_observations_sha256"] = observed_digest
    fixture["observed_participant_observations_sha256"] = observed_digest
    marker = fixture["bindings"]["marker"]
    marker["participant_observations_sha256"] = observed_digest
    marker["status"] = "COMMITTED" if hook_id == HOOK_IDS[-1] else "PENDING"
    marker_digest = _canonical_digest(marker, "bindings.marker")
    fixture["expected_marker_commitment_sha256"] = marker_digest
    fixture["observed_marker_commitment_sha256"] = marker_digest
    fixture["fault_hook_or_null"] = hook_id
    return fixture


def _binding_verified(
    observation: Mapping[str, Any],
    participants: Mapping[str, Mapping[str, Any]],
    bindings: Mapping[str, Any],
    calculated_contract_digest: str,
    calculated_subject_digest: str,
    calculated_effect_digest: str,
    calculated_marker_digest: str,
) -> bool:
    observed_participants = {key: item["observed"] for key, item in participants.items()}
    expected_observations = observation["expected_participant_observations_sha256"]
    observed_observations = observation["observed_participant_observations_sha256"]
    return (
        observation["expected_contract_digest"] == observation["observed_contract_digest"] == calculated_contract_digest
        and observation["expected_subject_binding_digest"] == observation["observed_subject_binding_digest"] == calculated_subject_digest
        and observation["expected_effect_digest"] == observation["observed_effect_digest"] == calculated_effect_digest
        and observation["expected_marker_commitment_sha256"] == observation["observed_marker_commitment_sha256"] == calculated_marker_digest
        and expected_observations == observed_observations == _canonical_digest(observed_participants, "participants.observed")
        and bindings["marker"]["participant_observations_sha256"] == observed_observations
    )


def _actionless_result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    result = {
        "schema_version": CROSS_STORE_FIXTURE_VERIFICATION_SCHEMA,
        "contract_role": CROSS_STORE_FIXTURE_ROLE,
        "status": status,
        "classification_role": "READ_ONLY_CLASSIFICATION",
        "reason": reason,
        "mutation_allowed": False,
        "authoritative_decision": False,
        "permission": "read_only",
        "external_action": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "execution": dict(_EXECUTION_FALSE),
    }
    result.update(extra)
    return result


def classify_cross_store_fixture(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Classify a T0-T5 trace without replay, recovery, or external action."""

    fixture = parse_cross_store_fixture(value)
    if set(fixture) != FIXTURE_KEYS:
        raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", "fixture keys are not exact")
    if fixture["schema_version"] != CROSS_STORE_FIXTURE_SCHEMA or fixture["contract_role"] != CROSS_STORE_FIXTURE_ROLE:
        raise CrossStoreFixtureError("PRIME_FIXTURE_SCHEMA_INVALID", "unsupported fixture schema or role")
    transaction_id = _safe_id(fixture["transaction_id"], "transaction_id")
    expected_contract_digest = _hash64(fixture["expected_contract_digest"], "expected_contract_digest")
    observed_contract_digest = _hash64(fixture["observed_contract_digest"], "observed_contract_digest")
    expected_subject_digest = _hash64(fixture["expected_subject_binding_digest"], "expected_subject_binding_digest")
    observed_subject_digest = _hash64(fixture["observed_subject_binding_digest"], "observed_subject_binding_digest")
    expected_effect_digest = _hash64(fixture["expected_effect_digest"], "expected_effect_digest")
    observed_effect_digest = _hash64(fixture["observed_effect_digest"], "observed_effect_digest")
    expected_participant_digest = _hash64(
        fixture["expected_participant_observations_sha256"], "expected_participant_observations_sha256"
    )
    observed_participant_digest = _hash64(
        fixture["observed_participant_observations_sha256"], "observed_participant_observations_sha256"
    )
    expected_marker_digest = _hash64(fixture["expected_marker_commitment_sha256"], "expected_marker_commitment_sha256")
    observed_marker_digest = _hash64(fixture["observed_marker_commitment_sha256"], "observed_marker_commitment_sha256")
    expected_epoch = _nonnegative_int(fixture["expected_fencing_epoch"], "expected_fencing_epoch")
    observed_epoch = _nonnegative_int(fixture["observed_fencing_epoch"], "observed_fencing_epoch")
    participants, participant_states = _validate_participants(fixture["participants"])
    participant_observation_digest = _canonical_digest(
        {key: participants[key]["observed"] for key in sorted(participants)}, "participants.observed"
    )
    bindings, calculated_contract_digest, calculated_subject_digest, calculated_effect_digest, marker_shape_verified = _validate_bindings(
        fixture["bindings"], transaction_id, participants, participant_observation_digest, expected_epoch
    )
    _validate_s11_contract_material(bindings["contract"], transaction_id, bindings["subject_binding"])
    marker, calculated_marker_digest = _validate_marker(
        bindings["marker"], transaction_id, calculated_effect_digest, participant_observation_digest, expected_epoch
    )
    lease, lease_live, lease_epoch_match = _validate_lease(fixture["lease"], transaction_id, expected_epoch)
    hook_trace, calculated_hook_digest = _validate_hook_trace(fixture["hook_trace"], transaction_id, expected_epoch)
    declared_hook_digest = _hash64(fixture["hook_trace_digest"], "hook_trace_digest")
    fault_hook = _optional_safe_id(fixture["fault_hook_or_null"], "fault_hook_or_null")
    if fault_hook is not None:
        if fault_hook not in HOOK_IDS or hook_trace[-1]["hook_id"] != fault_hook:
            raise CrossStoreFixtureError("PRIME_FIXTURE_HOOK_INVALID", "fault hook must be the last observed canonical hook")
    safety = _validate_safety(fixture["safety"])
    last_states = hook_trace[-1]["after_states"]
    state_chain_verified = all(last_states[key] == participant_states[key] for key in CROSS_STORE_PARTICIPANT_IDS)
    all_after_trace = len(hook_trace) == len(HOOK_IDS) and all(state == "AFTER" for state in last_states.values())
    marker_phase_verified = (marker["status"] == "COMMITTED") == all_after_trace
    bindings_verified = _binding_verified(
        {
            "expected_contract_digest": expected_contract_digest,
            "observed_contract_digest": observed_contract_digest,
            "expected_subject_binding_digest": expected_subject_digest,
            "observed_subject_binding_digest": observed_subject_digest,
            "expected_effect_digest": expected_effect_digest,
            "observed_effect_digest": observed_effect_digest,
            "expected_marker_commitment_sha256": expected_marker_digest,
            "observed_marker_commitment_sha256": observed_marker_digest,
            "expected_participant_observations_sha256": expected_participant_digest,
            "observed_participant_observations_sha256": observed_participant_digest,
        },
        participants,
        bindings,
        calculated_contract_digest,
        calculated_subject_digest,
        calculated_effect_digest,
        calculated_marker_digest,
    )
    fence_verified = lease_live and lease_epoch_match and expected_epoch == observed_epoch == lease["fencing_epoch"] and all(
        event["fencing_epoch"] == expected_epoch for event in hook_trace
    )
    trace_verified = declared_hook_digest == calculated_hook_digest and state_chain_verified
    effect_set_verified = all(participant_states[participant_id] in {"BEFORE", "AFTER"} for participant_id in CROSS_STORE_PARTICIPANT_IDS)
    all_before = all(state == "BEFORE" for state in participant_states.values())
    all_after = all(state == "AFTER" for state in participant_states.values())
    prefix_length = len(hook_trace)
    marker_verified = (
        expected_marker_digest == observed_marker_digest == calculated_marker_digest
        and marker["effect_digest"] == calculated_effect_digest
        and marker["status"] == "COMMITTED"
    )
    common = {
        "transaction_id": transaction_id,
        "fault_hook_or_null": fault_hook,
        "hook_trace_digest": calculated_hook_digest,
        "participant_states": participant_states,
        "bindings_verified": bindings_verified,
        "effect_set_verified": effect_set_verified,
        "marker_verified": marker_verified,
        "marker_phase_verified": marker_phase_verified,
        "fencing_verified": fence_verified,
        "trace_verified": trace_verified,
        "lease_valid": lease_live,
        "observed_participant_observations_sha256": participant_observation_digest,
        "safety": safety,
    }
    if not bindings_verified or not marker_shape_verified or not marker_phase_verified or not fence_verified or not trace_verified or not effect_set_verified:
        return _actionless_result(
            "RECOVERY_REQUIRED",
            "fixture binding, effect, fencing or hook-trace commitment conflicts",
            **common,
        )
    if all_after and prefix_length == len(HOOK_IDS) and marker_verified:
        return _actionless_result(
            "COMMITTED",
            "all participants are after and the complete T0-T5 trace plus marker is committed",
            commit_evidence_sufficient_read_only=True,
            **common,
        )
    if all_before and prefix_length <= PREPARED_PREFIX_LENGTH:
        return _actionless_result(
            "PREPARED",
            "the trace stops before the first replace/SQLite effect",
            **common,
        )
    if prefix_length > PREPARED_PREFIX_LENGTH and prefix_length < len(HOOK_IDS):
        reason = (
            "PROJECTION_PENDING"
            if participant_states["control_plane"] == "AFTER" and participant_states["prime_queue"] == "BEFORE"
            else "effect-capable hook observed without final marker"
        )
        return _actionless_result("IN_DOUBT", reason, **common)
    return _actionless_result(
        "RECOVERY_REQUIRED",
        "participant state and T0-T5 progress do not form a safe classification",
        **common,
    )


def evaluate_cross_store_fixture(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Turn malformed or conflicting fixtures into an actionless HOLD."""

    try:
        return classify_cross_store_fixture(value)
    except CrossStoreFixtureError as exc:
        return _actionless_result("HOLD", exc.code)
    except (AttributeError, KeyError, TypeError, ValueError):
        return _actionless_result("HOLD", "PRIME_FIXTURE_SCHEMA_INVALID")


__all__ = [
    "CROSS_STORE_FIXTURE_ROLE",
    "CROSS_STORE_FIXTURE_SCHEMA",
    "CROSS_STORE_FIXTURE_VERIFICATION_SCHEMA",
    "CROSS_STORE_PARTICIPANT_IDS",
    "CrossStoreFixtureError",
    "FIXTURE_ERROR_CODES",
    "HOOK_IDS",
    "HOOK_PARTICIPANTS",
    "build_cross_store_fixture",
    "build_cross_store_hook_trace",
    "classify_cross_store_fixture",
    "evaluate_cross_store_fixture",
    "inject_cross_store_fault",
    "parse_cross_store_fixture",
]
