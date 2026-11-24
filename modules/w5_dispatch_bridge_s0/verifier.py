"""Read-only W5-S0 dispatch-bridge verifier.

W2.5 currently exposes C1-C4 evidence but does not expose a canonical
``CONTINUE`` event or a separate worker-claim entity. W5 therefore accepts
those two records only as explicitly labelled, externally authenticated
evidence. It never promotes them into W2.5 runtime state and never starts a
process.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping

from modules.w4_small_loop_s0.authority import resolve_trusted_authority
from modules.w4_small_loop_s0.models import W4EvidenceError
from modules.w4_small_loop_s0.w25_compat import (
    _exact_int,
    _hash64,
    _mapping,
    _text,
    canonical_hash,
    canonical_json,
)

from .models import DispatchBridgeResult, W5EvidenceError, W5IncompatibleSource


BUNDLE_SCHEMA = "w5-dispatch-bridge-bundle.v1"
SOURCE_CONTRACT = {
    "kind": "w25-s0",
    "version": "w25-s0",
    "canonicalization": "json-sortkeys-v1",
}
POLICY_SCHEMA = "w5-bridge-policy.v1"
AUTHORITY_SCHEMA = "w5-w25-bridge-authority.v1"
CONTINUE_SCHEMA = "w5-continue-intent.v1"
WORKER_CLAIM_SCHEMA = "w5-worker-claim.v1"
PROCESS_ACK_SCHEMA = "w5-process-ack.v1"
REPLAY_SCHEMA = "w5-dispatch-replay.v1"
FAKE_BOOT_ID = "fake-boot-w25-s0"
ACK_WINDOW_SECONDS = 60

RUNTIME_KEYS = {
    "projects",
    "run",
    "cards",
    "attempts",
    "dispatches",
    "receipts",
    "reviews",
    "acceptance_txns",
    "commit_markers",
    "events",
    "next_card_intents",
    "counts",
}
TOP_LEVEL_KEYS = {
    "schema",
    "source",
    "runtime",
    "bridge_policy",
    "continue_intent",
    "worker_claim",
    "process_ack",
    "replay_evidence",
    "state_witnesses",
}
AUTHORITY_KEYS = {
    "schema",
    "authority_id",
    "key_id",
    "authority_hash",
    "authority_mac",
    "run_id",
    "card_id",
    "attempt_id",
    "dispatch_id",
    "fencing_epoch",
    "policy_hash",
    "runtime_hash",
    "state_witness_hash",
    "event_chain_hash",
    "marker_commitments",
    "continue_hash",
    "worker_claim_hash",
    "process_ack_hash",
    "replay_hash",
    "executor",
}
IDENTITY_FIELDS = (
    "pid",
    "process_starttime",
    "boot_id",
    "pidfd_ref",
    "cgroup_ref",
    "run_token",
    "fencing_epoch",
    "command_hash",
)
ACK_WAIT_STATES = {"SPAWN_REQUESTED", "ACK_TIMEOUT", "DISPATCH_UNCONFIRMED", "RECONCILING"}
PROJECTION_TABLES = (
    "projects",
    "runs",
    "cards",
    "attempts",
    "dispatches",
    "receipts",
    "reviews",
    "acceptance_txns",
    "next_card_intents",
)
RAW_PROJECTION_FIELDS = {
    "projects": {
        "project_id", "profile_version", "canonical_root", "discovery_root", "path_policy_hash",
        "autonomy_level", "status", "source_manifest_hash", "created_at", "updated_at",
    },
    "runs": {
        "run_id", "project_id", "goal_id", "plan_id", "plan_version", "mode", "state", "queue_hash",
        "policy_hash", "context_pack_hash", "lease_token", "lease_owner_id", "lease_expires_at",
        "last_heartbeat_at", "fencing_epoch", "last_committed_event_id", "resume_point_id",
        "active_dispatch_id", "budget_json", "next_action_json", "input_spec_json", "created_at", "updated_at",
    },
    "cards": {
        "card_id", "project_id", "run_id", "goal_id", "plan_id", "plan_version", "card_hash",
        "source_queue_hash", "title", "objective", "non_goals_json", "dependencies_json", "postconditions_json",
        "capability_set_hash", "state", "state_version", "active_attempt_id", "attempt_ids_json",
        "acceptance_txn_id", "next_card_intent_id", "created_at", "updated_at",
    },
    "attempts": {
        "attempt_id", "attempt_no", "card_id", "run_id", "retry_of", "state", "result", "state_version",
        "last_transition_event_id", "dispatch_id", "input_snapshot_hash", "context_pack_hash", "worker_id",
        "command_hash", "progress_signature", "progress_signature_count", "artifact_manifest_hash", "receipt_id",
        "review_id", "deadline_at", "heartbeat_deadline_at", "last_heartbeat_at", "deadline_policy_hash",
        "started_at", "finished_at", "created_at", "updated_at",
    },
    "dispatches": {
        "dispatch_id", "dispatch_key", "idempotency_key", "attempt_id", "run_id", "state", "run_token",
        "fencing_epoch", "owner_id", "command_hash", "pid", "process_starttime", "boot_id", "pidfd_ref",
        "cgroup_ref", "ack_deadline_at", "lease_expires_at", "heartbeat_at", "spawn_attempt_no",
        "max_spawn_attempts", "executor_kind", "row_version", "created_at", "updated_at",
    },
    "receipts": set(),
    "reviews": set(),
    "acceptance_txns": set(),
    "next_card_intents": set(),
}
RUNTIME_ROW_FIELDS = {
    "projects": RAW_PROJECTION_FIELDS["projects"],
    "runs": RAW_PROJECTION_FIELDS["runs"],
    "cards": RAW_PROJECTION_FIELDS["cards"] | {"non_goals", "dependencies", "postconditions", "attempt_ids"},
    "attempts": RAW_PROJECTION_FIELDS["attempts"],
    "dispatches": RAW_PROJECTION_FIELDS["dispatches"],
}
MARKER_ROW_FIELDS = {"run_id", "commit_point", "operation_key", "status", "marker_hash", "payload_json", "created_at", "payload"}
EVENT_ROW_FIELDS = {"event_id", "event_no", "run_id", "entity_type", "entity_id", "event_type", "from_state", "to_state", "payload_json", "created_at", "payload"}
STATE_WITNESS_OPERATIONS = (
    "run-admit",
    "dispatch-intent",
    "claim-lease",
    "spawn-request",
    "executor-ack",
)
FORBIDDEN_AFTER_ACK_EVENTS = {
    "DISPATCH_RUNNING",
    "ATTEMPT_RUNNING",
    "CARD_IN_PROGRESS",
    "RUN_RUNNING",
    "CHECKPOINT_CREATED",
    "ATTEMPT_SUBMITTED",
    "RECEIPT_SEALED",
    "RECEIPT_VERIFIED",
    "REVIEW_REQUESTED",
    "P0_NEXT_CARD_DISABLED",
    "P0_RUN_COMPLETE_DISABLED",
}
EXPECTED_MARKERS = {
    "run-admit": ("C0", "COMMITTED"),
    "dispatch-intent": ("C1", "COMMITTED"),
    "claim-lease": ("C2", "COMMITTED"),
    "spawn-request": ("C3", "COMMITTED"),
    "executor-ack": ("C4", "COMMITTED"),
}


class W5BridgeBlocked(W5EvidenceError):
    """The source is operationally waiting for a valid process acknowledgement."""


def _required_keys(value: Mapping[str, Any], required: set[str], label: str) -> None:
    missing = required - set(value)
    extra = set(value) - required
    if missing:
        raise W5EvidenceError(f"{label}: missing {sorted(missing)}")
    if extra:
        raise W5EvidenceError(f"{label}: unknown fields {sorted(extra)}")


def _bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise W5EvidenceError(f"{label}: boolean required")
    return value


def _payload(value: Mapping[str, Any], label: str) -> Mapping[str, Any]:
    payload = value.get("payload")
    payload_json = value.get("payload_json")
    parsed_payload = None
    if payload_json is not None and not isinstance(payload_json, str):
        raise W5EvidenceError(f"{label}: payload_json must be a string")
    if isinstance(payload_json, str):
        try:
            parsed_payload = json.loads(payload_json)
        except (TypeError, ValueError) as exc:
            raise W5EvidenceError(f"{label}: payload JSON invalid") from exc
    if payload is None:
        payload = parsed_payload
    elif parsed_payload is not None and canonical_json(_mapping(payload, f"{label}.payload")) != canonical_json(_mapping(parsed_payload, f"{label}.payload_json")):
        raise W5EvidenceError(f"{label}: payload/payload_json mismatch")
    return _mapping(payload, f"{label}.payload")


def _verify_policy(value: Any) -> dict[str, Any]:
    policy = _mapping(value, "bridge_policy")
    expected = {
        "schema": POLICY_SCHEMA,
        "phase": "C0-C4",
        "max_cards": 1,
        "max_dispatches": 1,
        "max_workers": 1,
        "require_ack_before_running": True,
        "allow_following_card": False,
        "process_mode": "fake-only",
        "continue_replay": "idempotent",
    }
    _required_keys(policy, set(expected), "bridge_policy")
    if canonical_json(policy) != canonical_json(expected):
        raise W5EvidenceError("BRIDGE_POLICY_DRIFT")
    return dict(expected)


def _identity_from_dispatch(dispatch: Mapping[str, Any]) -> dict[str, Any]:
    identity: dict[str, Any] = {}
    identity["pid"] = _exact_int(dispatch.get("pid"), "dispatch.pid", minimum=1)
    for field in ("process_starttime", "boot_id", "pidfd_ref", "cgroup_ref", "run_token", "command_hash"):
        identity[field] = _text(dispatch.get(field), f"dispatch.{field}")
    identity["fencing_epoch"] = _exact_int(dispatch.get("fencing_epoch"), "dispatch.fencing_epoch", minimum=1)
    if identity["command_hash"] != dispatch.get("command_hash"):
        raise W5EvidenceError("dispatch identity command hash drift")
    return identity


def _derive_fake_identity(dispatch: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "dispatch_id": dispatch["dispatch_id"],
        "run_token": dispatch["run_token"],
        "fencing_epoch": dispatch["fencing_epoch"],
        "command_hash": dispatch["command_hash"],
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return {
        "pid": 40000 + int(digest[:8], 16) % 20000,
        "process_starttime": digest[8:24],
        "boot_id": FAKE_BOOT_ID,
        "pidfd_ref": f"fake-pidfd:{digest[24:40]}",
        "cgroup_ref": f"fake-cgroup:{digest[40:56]}",
        "run_token": dispatch["run_token"],
        "fencing_epoch": dispatch["fencing_epoch"],
        "command_hash": dispatch["command_hash"],
    }


def _normalize_ack_identity(value: Any, label: str) -> dict[str, Any]:
    raw = _mapping(value, label)
    required = {"pid", "starttime", "boot_id", "pidfd_ref", "cgroup_ref", "run_token", "fencing_epoch", "command_hash"}
    _required_keys(raw, required, label)
    return {
        "pid": _exact_int(raw["pid"], f"{label}.pid", minimum=1),
        "process_starttime": _text(raw["starttime"], f"{label}.starttime"),
        "boot_id": _text(raw["boot_id"], f"{label}.boot_id"),
        "pidfd_ref": _text(raw["pidfd_ref"], f"{label}.pidfd_ref"),
        "cgroup_ref": _text(raw["cgroup_ref"], f"{label}.cgroup_ref"),
        "run_token": _text(raw["run_token"], f"{label}.run_token"),
        "fencing_epoch": _exact_int(raw["fencing_epoch"], f"{label}.fencing_epoch", minimum=1),
        "command_hash": _text(raw["command_hash"], f"{label}.command_hash"),
    }


def _projection(value: Any, label: str) -> dict[str, list[dict[str, Any]]]:
    projection = _mapping(value, label)
    _required_keys(projection, set(PROJECTION_TABLES), label)
    normalized: dict[str, list[dict[str, Any]]] = {}
    for table in PROJECTION_TABLES:
        rows = projection[table]
        if not isinstance(rows, list):
            raise W5EvidenceError(f"{label}.{table}: list required")
        normalized_rows: list[dict[str, Any]] = []
        for index, raw in enumerate(rows):
            row = dict(_mapping(raw, f"{label}.{table}[{index}]"))
            if set(row) != RAW_PROJECTION_FIELDS[table]:
                raise W5EvidenceError(f"{label}.{table}[{index}]: W2.5 projection schema drift")
            normalized_rows.append(row)
        normalized[table] = normalized_rows
    return normalized


def _raw_runtime_projection(runtime: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Recover the W2.5 raw SQL projection from its enriched snapshot rows."""

    projection: dict[str, list[dict[str, Any]]] = {}
    for table in PROJECTION_TABLES:
        runtime_key = "run" if table == "runs" else table
        rows = runtime.get(runtime_key)
        if table == "runs" and isinstance(rows, Mapping):
            rows = [rows]
        if table == "projects":
            if not isinstance(rows, list):
                raise W5EvidenceError("runtime.projects: list required")
        elif not isinstance(rows, list):
            raise W5EvidenceError(f"runtime.{runtime_key}: list required")
        raw_rows: list[dict[str, Any]] = []
        for index, raw in enumerate(rows):
            row = dict(_mapping(raw, f"runtime.{table}[{index}]"))
            if set(row) != RUNTIME_ROW_FIELDS[table]:
                raise W5EvidenceError(f"runtime.{table}[{index}]: W2.5 snapshot schema drift")
            # ControlPlane.snapshot keeps the original SQLite *_json column
            # and adds a parsed alias.  The marker projection hashes only the
            # original SQLite row, so remove those derived aliases.
            for key in tuple(row):
                if not key.endswith("_json") and f"{key}_json" in row:
                    del row[key]
            raw_rows.append(row)
        projection[table] = raw_rows
    return projection


def _verify_markers(runtime: Mapping[str, Any], run_id: str, dispatch_id: str, attempt_id: str) -> dict[str, Mapping[str, Any]]:
    markers = runtime.get("commit_markers")
    if not isinstance(markers, list):
        raise W5EvidenceError("runtime.commit_markers: list required")
    by_operation: dict[str, Mapping[str, Any]] = {}
    for raw in markers:
        marker = _mapping(raw, "commit_marker")
        if set(marker) != MARKER_ROW_FIELDS:
            raise W5EvidenceError("commit_marker: W2.5 snapshot schema drift")
        operation = _text(marker.get("operation_key"), "commit_marker.operation_key")
        if operation in by_operation:
            raise W5EvidenceError("duplicate W5 commit marker")
        by_operation[operation] = marker
        commit_point = _text(marker.get("commit_point"), f"commit_marker[{operation}].commit_point")
        status = _text(marker.get("status"), f"commit_marker[{operation}].status")
        payload = _payload(marker, f"commit_marker[{operation}]")
        expected_hash = canonical_hash(
            {
                "run_id": run_id,
                "commit_point": commit_point,
                "operation_key": operation,
                "status": status,
                "payload": dict(payload),
            }
        )
        if marker.get("marker_hash") != expected_hash:
            raise W5EvidenceError(f"commit marker hash drift: {operation}")
        for field in ("_before_state_hash", "_after_state_hash"):
            _hash64(payload.get(field), f"commit_marker[{operation}].payload.{field}")
        _text(payload.get("_after_event_id"), f"commit_marker[{operation}].payload._after_event_id")

    if set(by_operation) != set(EXPECTED_MARKERS):
        raise W5EvidenceError("W5 requires exactly the C0-C4 marker set")
    for operation, (commit_point, status) in EXPECTED_MARKERS.items():
        marker = by_operation[operation]
        if marker.get("commit_point") != commit_point or marker.get("status") != status:
            raise W5EvidenceError(f"W5 marker contract drift: {operation}")

    dispatch_payload = _payload(by_operation["dispatch-intent"], "dispatch-intent")
    if dispatch_payload.get("dispatch_id") != dispatch_id or dispatch_payload.get("attempt_id") != attempt_id:
        raise W5EvidenceError("C1 dispatch identity drift")
    claim_payload = _payload(by_operation["claim-lease"], "claim-lease")
    spawn_payload = _payload(by_operation["spawn-request"], "spawn-request")
    ack_payload = _payload(by_operation["executor-ack"], "executor-ack")
    if spawn_payload.get("dispatch_id") != dispatch_id or ack_payload.get("dispatch_id") != dispatch_id:
        raise W5EvidenceError("C3/C4 dispatch identity drift")
    if not claim_payload.get("owner_id"):
        raise W5EvidenceError("C2 controller lease claim malformed")
    _exact_int(claim_payload.get("fencing_epoch"), "claim-lease.payload.fencing_epoch", minimum=1)
    if not isinstance(ack_payload.get("identity"), Mapping):
        raise W5EvidenceError("C4 executor identity missing")
    return by_operation


def _verify_marker_payload_bindings(
    markers: Mapping[str, Mapping[str, Any]],
    *,
    run: Mapping[str, Any],
    card: Mapping[str, Any],
    attempt: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    identity: Mapping[str, Any],
) -> None:
    c1 = _payload(markers["dispatch-intent"], "dispatch-intent")
    if c1.get("attempt_id") != attempt["attempt_id"] or c1.get("dispatch_id") != dispatch["dispatch_id"] or c1.get("idempotency_key") != dispatch["idempotency_key"]:
        raise W5EvidenceError("C1 marker payload binding drift")
    c2 = _payload(markers["claim-lease"], "claim-lease")
    if c2.get("owner_id") != run["lease_owner_id"] or _exact_int(c2.get("fencing_epoch"), "C2 marker fencing_epoch", minimum=1) != run["fencing_epoch"]:
        raise W5EvidenceError("C2 marker lease binding drift")
    c3 = _payload(markers["spawn-request"], "spawn-request")
    if c3.get("dispatch_id") != dispatch["dispatch_id"] or c3.get("run_token") != dispatch["run_token"] or _exact_int(c3.get("spawn_attempt_no"), "C3 marker spawn_attempt_no", minimum=1) != 1:
        raise W5EvidenceError("C3 marker spawn binding drift")
    c4 = _payload(markers["executor-ack"], "executor-ack")
    if c4.get("dispatch_id") != dispatch["dispatch_id"] or _normalize_ack_identity(c4.get("identity"), "C4 marker identity") != dict(identity):
        raise W5EvidenceError("C4 marker ack binding drift")


def _verify_events(
    runtime: Mapping[str, Any],
    run_id: str,
    dispatch_id: str,
    attempt_id: str,
    identity: Mapping[str, Any],
    *,
    dispatch_key: str,
    idempotency_key: str,
    owner_id: str,
    fencing_epoch: int,
) -> dict[str, Any]:
    events = runtime.get("events")
    if not isinstance(events, list) or not events:
        raise W5EvidenceError("runtime.events: non-empty list required")
    by_no: dict[int, Mapping[str, Any]] = {}
    for expected_no, raw in enumerate(events, 1):
        event = _mapping(raw, f"event[{expected_no - 1}]")
        if set(event) != EVENT_ROW_FIELDS:
            raise W5EvidenceError(f"event[{expected_no - 1}]: W2.5 snapshot schema drift")
        event_no = _exact_int(event.get("event_no"), f"event[{expected_no - 1}].event_no", minimum=1)
        if event_no != expected_no or event_no in by_no:
            raise W5EvidenceError("W5 event history is not contiguous")
        if event.get("run_id") != run_id:
            raise W5EvidenceError("foreign event in W5 bridge history")
        _text(event.get("event_id"), f"event[{expected_no - 1}].event_id")
        by_no[event_no] = event
    expected_types = [
        "RUN_CREATED",
        "PROJECT_ACTIVE",
        "RUN_PREFLIGHT",
        "RUN_READY",
        "CARD_CREATED",
        "CARD_WAITING",
        "CARD_READY",
        "ATTEMPT_CREATED",
        "ATTEMPT_ADMITTED",
        "DISPATCH_INTENDED",
        "RUN_DISPATCHING",
        "DISPATCH_CLAIMED",
        "CARD_CLAIMED",
        "SPAWN_REQUESTED",
        "EXECUTOR_ACKED",
        "ATTEMPT_STARTING",
    ]
    if [by_no[number].get("event_type") for number in sorted(by_no)] != expected_types:
        raise W5EvidenceError("W5 C0-C4 event sequence drift or unknown event")

    def one(event_type: str) -> Mapping[str, Any]:
        matches = [event for event in by_no.values() if event.get("event_type") == event_type]
        if len(matches) != 1:
            raise W5EvidenceError(f"W5 requires exactly one {event_type} event")
        return matches[0]

    intent = one("DISPATCH_INTENDED")
    claim = one("DISPATCH_CLAIMED")
    spawn = one("SPAWN_REQUESTED")
    ack = one("EXECUTOR_ACKED")
    starting = one("ATTEMPT_STARTING")
    ordered = [int(event["event_no"]) for event in (intent, claim, spawn, ack, starting)]
    if ordered != sorted(ordered) or len(set(ordered)) != len(ordered):
        raise W5EvidenceError("W5 C1-C4 event order drift")
    for event, expected_entity, expected_id in (
        (intent, "Dispatch", dispatch_id),
        (claim, "Dispatch", dispatch_id),
        (spawn, "Dispatch", dispatch_id),
        (ack, "Dispatch", dispatch_id),
        (starting, "Attempt", attempt_id),
    ):
        if event.get("entity_type") != expected_entity or event.get("entity_id") != expected_id:
            raise W5EvidenceError("W5 event entity binding drift")
    if (intent.get("from_state"), intent.get("to_state")) != (None, "DISPATCH_INTENDED"):
        raise W5EvidenceError("DISPATCH_INTENDED transition drift")
    if (claim.get("from_state"), claim.get("to_state")) != ("DISPATCH_INTENDED", "CLAIMED"):
        raise W5EvidenceError("DISPATCH_CLAIMED transition drift")
    if (spawn.get("from_state"), spawn.get("to_state")) != ("CLAIMED", "SPAWN_REQUESTED"):
        raise W5EvidenceError("SPAWN_REQUESTED transition drift")
    if (ack.get("from_state"), ack.get("to_state")) != ("SPAWN_REQUESTED", "EXECUTOR_ACKED"):
        raise W5EvidenceError("EXECUTOR_ACKED transition drift")
    if (starting.get("from_state"), starting.get("to_state")) != ("ADMITTED", "STARTING"):
        raise W5EvidenceError("ATTEMPT_STARTING transition drift")
    intent_payload = _payload(intent, "DISPATCH_INTENDED")
    if intent_payload.get("dispatch_key") != dispatch_key or intent_payload.get("idempotency_key") != idempotency_key:
        raise W5EvidenceError("DISPATCH_INTENDED payload binding drift")
    claim_payload = _payload(claim, "DISPATCH_CLAIMED")
    if claim_payload.get("owner_id") != owner_id or _exact_int(claim_payload.get("fencing_epoch"), "DISPATCH_CLAIMED.payload.fencing_epoch", minimum=1) != fencing_epoch:
        raise W5EvidenceError("DISPATCH_CLAIMED payload binding drift")
    spawn_payload = _payload(spawn, "SPAWN_REQUESTED")
    if spawn_payload.get("run_token") != identity["run_token"] or spawn_payload.get("command_hash") != identity["command_hash"]:
        raise W5EvidenceError("SPAWN_REQUESTED payload binding drift")
    ack_payload = _payload(ack, "EXECUTOR_ACKED")
    if _normalize_ack_identity(ack_payload, "EXECUTOR_ACKED.identity") != dict(identity):
        raise W5EvidenceError("executor acknowledgement identity drift")
    if any(event.get("event_type") in FORBIDDEN_AFTER_ACK_EVENTS for event in by_no.values()):
        raise W5EvidenceError("W5 contains C5 or later runtime event")
    return {
        "events": by_no,
        "dispatch_intent_event_id": intent["event_id"],
        "spawn_event_no": spawn["event_no"],
        "ack_event_id": ack["event_id"],
        "ack_event_no": ack["event_no"],
        "starting_event_id": starting["event_id"],
    }


def _verify_marker_event_witness(markers: Mapping[str, Mapping[str, Any]], event_info: Mapping[str, Any]) -> None:
    events = event_info["events"]
    by_id = {event["event_id"]: event for event in events.values()}
    expected_types = {
        "run-admit": "CARD_READY",
        "dispatch-intent": "RUN_DISPATCHING",
        "claim-lease": "CARD_CLAIMED",
        "spawn-request": "SPAWN_REQUESTED",
        "executor-ack": "ATTEMPT_STARTING",
    }
    previous_no = 0
    for operation, event_type in expected_types.items():
        event_id = _payload(markers[operation], operation)["_after_event_id"]
        event = by_id.get(event_id)
        if event is None or event.get("event_type") != event_type or int(event["event_no"]) <= previous_no:
            raise W5EvidenceError(f"{operation} marker event witness drift")
        previous_no = int(event["event_no"])


def _phase_row(projection: Mapping[str, list[dict[str, Any]]], table: str, phase: str) -> dict[str, Any]:
    rows = projection[table]
    if len(rows) != 1:
        raise W5EvidenceError(f"{phase} projection requires one {table} row")
    return rows[0]


def _verify_phase_shape(
    operation: str,
    projection: Mapping[str, list[dict[str, Any]]],
    *,
    run_id: str,
    card_id: str,
    attempt_id: str,
    dispatch_id: str,
) -> None:
    project = _phase_row(projection, "projects", operation)
    run = _phase_row(projection, "runs", operation)
    card = _phase_row(projection, "cards", operation)
    if project.get("status") != "ACTIVE" or run.get("run_id") != run_id or card.get("card_id") != card_id:
        raise W5EvidenceError(f"{operation} projection identity/state drift")
    if run.get("project_id") != project.get("project_id") or card.get("run_id") != run_id:
        raise W5EvidenceError(f"{operation} projection provenance drift")
    for table in ("receipts", "reviews", "acceptance_txns", "next_card_intents"):
        if projection[table]:
            raise W5EvidenceError(f"{operation} projection leaks post-C4 table: {table}")

    if operation == "run-admit":
        if run.get("state") != "READY" or card.get("state") != "READY" or projection["attempts"] or projection["dispatches"]:
            raise W5EvidenceError("C0 projection shape drift")
        return

    attempt = _phase_row(projection, "attempts", operation)
    dispatch = _phase_row(projection, "dispatches", operation)
    if attempt.get("attempt_id") != attempt_id or dispatch.get("dispatch_id") != dispatch_id:
        raise W5EvidenceError(f"{operation} attempt/dispatch identity drift")
    if attempt.get("run_id") != run_id or attempt.get("card_id") != card_id or dispatch.get("run_id") != run_id or dispatch.get("attempt_id") != attempt_id:
        raise W5EvidenceError(f"{operation} attempt/dispatch provenance drift")

    expected = {
        "dispatch-intent": ("DISPATCHING", "READY", "ADMITTED", "DISPATCH_INTENDED"),
        "claim-lease": ("DISPATCHING", "CLAIMED", "ADMITTED", "CLAIMED"),
        "spawn-request": ("DISPATCHING", "CLAIMED", "ADMITTED", "SPAWN_REQUESTED"),
        "executor-ack": ("DISPATCHING", "CLAIMED", "STARTING", "EXECUTOR_ACKED"),
    }
    expected_states = expected.get(operation)
    if expected_states is None or (run.get("state"), card.get("state"), attempt.get("state"), dispatch.get("state")) != expected_states:
        raise W5EvidenceError(f"{operation} projection state drift")


def _verify_state_witnesses(value: Any, runtime: Mapping[str, Any], info: Mapping[str, Any]) -> dict[str, dict[str, dict[str, list[dict[str, Any]]]]]:
    raw_witnesses = _mapping(value, "state_witnesses")
    _required_keys(raw_witnesses, set(STATE_WITNESS_OPERATIONS), "state_witnesses")
    witnesses: dict[str, dict[str, dict[str, list[dict[str, Any]]]]] = {}
    for operation in STATE_WITNESS_OPERATIONS:
        witness = _mapping(raw_witnesses[operation], f"state_witnesses.{operation}")
        _required_keys(witness, {"before_projection", "after_projection"}, f"state_witnesses.{operation}")
        before = _projection(witness["before_projection"], f"state_witnesses.{operation}.before_projection")
        after = _projection(witness["after_projection"], f"state_witnesses.{operation}.after_projection")
        marker_payload = _payload(info["markers"][operation], operation)
        if canonical_hash(before) != marker_payload["_before_state_hash"] or canonical_hash(after) != marker_payload["_after_state_hash"]:
            raise W5EvidenceError(f"{operation} marker state witness drift")
        witnesses[operation] = {"before_projection": before, "after_projection": after}

    previous_operation: str | None = None
    for operation in STATE_WITNESS_OPERATIONS:
        if previous_operation is not None and witnesses[previous_operation]["after_projection"] != witnesses[operation]["before_projection"]:
            raise W5EvidenceError(f"state witness boundary discontinuity: {previous_operation}->{operation}")
        previous_operation = operation

    first_before = witnesses[STATE_WITNESS_OPERATIONS[0]]["before_projection"]
    if any(first_before[table] for table in PROJECTION_TABLES):
        raise W5EvidenceError("C0 before-projection is not empty")

    for operation in STATE_WITNESS_OPERATIONS:
        _verify_phase_shape(
            operation,
            witnesses[operation]["after_projection"],
            run_id=info["run_id"],
            card_id=info["card_id"],
            attempt_id=info["attempt_id"],
            dispatch_id=info["dispatch_id"],
        )

    final_projection = witnesses["executor-ack"]["after_projection"]
    runtime_projection = _raw_runtime_projection(runtime)
    if final_projection != runtime_projection:
        raise W5EvidenceError("C4 state witness does not match runtime projection")
    return witnesses


def _verify_ack_wait_basics(
    *,
    run: Mapping[str, Any],
    card: Mapping[str, Any],
    attempt: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    run_id: str,
    card_id: str,
    attempt_id: str,
    dispatch_id: str,
    epoch: int,
    lease_expires_at: int,
) -> None:
    if attempt.get("run_id") != run_id or attempt.get("card_id") != card_id or attempt.get("dispatch_id") != dispatch_id:
        raise W5EvidenceError("ACK_WAIT attempt binding drift")
    if attempt.get("state") not in {"ADMITTED", "STARTING", "UNCERTAIN"}:
        raise W5EvidenceError("ACK_WAIT attempt state drift")
    if attempt.get("attempt_no") != 1 or attempt.get("retry_of") is not None:
        raise W5EvidenceError("ACK_WAIT attempt retry drift")
    if dispatch_id != f"dispatch-{attempt_id}" or dispatch.get("attempt_id") != attempt_id or dispatch.get("run_id") != run_id:
        raise W5EvidenceError("ACK_WAIT dispatch identity drift")
    if dispatch.get("dispatch_key") != f"dispatch-key:{run_id}:{card_id}:001" or dispatch.get("idempotency_key") != f"idempotency:{run_id}:{card_id}:001":
        raise W5EvidenceError("ACK_WAIT idempotency drift")
    if dispatch.get("run_token") != f"run-token:{run_id}:{attempt_id}" or dispatch.get("owner_id") != run.get("lease_owner_id"):
        raise W5EvidenceError("ACK_WAIT lease owner/token drift")
    if dispatch.get("fencing_epoch") != epoch or dispatch.get("lease_expires_at") != lease_expires_at or dispatch.get("ack_deadline_at") != lease_expires_at:
        raise W5EvidenceError("ACK_WAIT fencing/deadline drift")
    if dispatch.get("spawn_attempt_no") != 1 or dispatch.get("max_spawn_attempts") != 1 or dispatch.get("row_version") != 0 or dispatch.get("executor_kind") != "fake":
        raise W5EvidenceError("ACK_WAIT replay/executor contract drift")
    if attempt.get("command_hash") != dispatch.get("command_hash"):
        raise W5EvidenceError("ACK_WAIT command binding drift")
    identity_values = [dispatch.get(field) for field in ("pid", "process_starttime", "boot_id", "pidfd_ref", "cgroup_ref")]
    if attempt.get("state") == "ADMITTED":
        if any(value is not None for value in identity_values) or attempt.get("worker_id") is not None:
            raise W5EvidenceError("ACK_WAIT pre-ack identity drift")
    elif any(value is None for value in identity_values):
        raise W5EvidenceError("ACK_WAIT partial executor identity")
    else:
        identity = _identity_from_dispatch(dispatch)
        if identity != _derive_fake_identity(dispatch) or attempt.get("worker_id") != "fake-executor":
            raise W5EvidenceError("ACK_WAIT executor identity drift")


def _verify_runtime(runtime: Any) -> dict[str, Any]:
    runtime = _mapping(runtime, "runtime")
    _required_keys(runtime, RUNTIME_KEYS, "runtime")
    run = _mapping(runtime.get("run"), "runtime.run")
    projects = runtime.get("projects")
    cards = runtime.get("cards")
    attempts = runtime.get("attempts")
    dispatches = runtime.get("dispatches")
    for value, label in ((projects, "runtime.projects"), (cards, "runtime.cards"), (attempts, "runtime.attempts"), (dispatches, "runtime.dispatches")):
        if not isinstance(value, list) or len(value) != 1:
            raise W5EvidenceError(f"{label}: exactly one row required")
    for value, label in ((runtime["receipts"], "runtime.receipts"), (runtime["reviews"], "runtime.reviews"), (runtime["acceptance_txns"], "runtime.acceptance_txns"), (runtime["next_card_intents"], "runtime.next_card_intents")):
        if not isinstance(value, list):
            raise W5EvidenceError(f"{label}: list required")
        if value:
            raise W5EvidenceError(f"{label}: W5 C1-C4 must be empty")
    counts = _mapping(runtime.get("counts"), "runtime.counts")
    _required_keys(counts, {"runs", "cards", "attempts", "dispatches", "receipts", "events"}, "runtime.counts")
    expected_counts = {"runs": 1, "cards": 1, "attempts": 1, "dispatches": 1, "receipts": 0, "events": len(runtime["events"])}
    if dict(counts) != expected_counts:
        raise W5EvidenceError("runtime counts drift")

    project = _mapping(projects[0], "runtime.project")
    card = _mapping(cards[0], "runtime.card")
    attempt = _mapping(attempts[0], "runtime.attempt")
    dispatch = _mapping(dispatches[0], "runtime.dispatch")
    run_id = _text(run.get("run_id"), "run.run_id")
    card_id = _text(card.get("card_id"), "card.card_id")
    attempt_id = _text(attempt.get("attempt_id"), "attempt.attempt_id")
    dispatch_id = _text(dispatch.get("dispatch_id"), "dispatch.dispatch_id")
    for field in ("project_id", "goal_id", "plan_id", "plan_version", "queue_hash", "policy_hash", "context_pack_hash"):
        _text(run.get(field), f"run.{field}")
    if run.get("state") != "DISPATCHING":
        raise W5EvidenceError("W5 run is not DISPATCHING")
    if project.get("project_id") != run.get("project_id") or project.get("status") != "ACTIVE":
        raise W5EvidenceError("project bridge state/provenance drift")
    if run.get("active_dispatch_id") != dispatch_id:
        raise W5EvidenceError("run active dispatch drift")
    epoch = _exact_int(run.get("fencing_epoch"), "run.fencing_epoch", minimum=1)
    owner_id = _text(run.get("lease_owner_id"), "run.lease_owner_id")
    lease_token = _text(run.get("lease_token"), "run.lease_token")
    lease_expires_at = _exact_int(run.get("lease_expires_at"), "run.lease_expires_at", minimum=0)
    if lease_token != f"lease:{run_id}:epoch:{epoch}":
        raise W5EvidenceError("run lease token drift")

    if card.get("run_id") != run_id or card.get("state") != "CLAIMED" or card.get("active_attempt_id") != attempt_id:
        raise W5EvidenceError("card bridge state/binding drift")
    if card.get("source_queue_hash") != run.get("queue_hash") or card.get("acceptance_txn_id") is not None or card.get("next_card_intent_id") is not None:
        raise W5EvidenceError("card boundary drift")
    card_hash = _text(card.get("card_hash"), "card.card_hash")
    if dispatch_id != f"dispatch-{attempt_id}" or dispatch.get("attempt_id") != attempt_id or dispatch.get("run_id") != run_id:
        raise W5EvidenceError("dispatch identity drift")
    if dispatch.get("state") in ACK_WAIT_STATES and attempt.get("state") in {"ADMITTED", "STARTING", "UNCERTAIN"}:
        _verify_ack_wait_basics(
            run=run,
            card=card,
            attempt=attempt,
            dispatch=dispatch,
            run_id=run_id,
            card_id=card_id,
            attempt_id=attempt_id,
            dispatch_id=dispatch_id,
            epoch=epoch,
            lease_expires_at=lease_expires_at,
        )
        raise W5EvidenceError("ACK_WAIT_REQUIRES_EXPLICIT_BLOCKED_BUNDLE")
    if attempt.get("run_id") != run_id or attempt.get("card_id") != card_id or attempt.get("state") != "STARTING" or attempt.get("result") is not None:
        raise W5EvidenceError("attempt bridge state/binding drift")
    if type(attempt.get("attempt_no")) is not int or attempt.get("attempt_no") != 1 or attempt.get("retry_of") is not None or attempt.get("dispatch_id") != dispatch_id:
        raise W5EvidenceError("attempt identity/retry drift")
    _exact_int(attempt.get("state_version"), "attempt.state_version", minimum=0)
    _text(attempt.get("worker_id"), "attempt.worker_id")
    if attempt.get("worker_id") != "fake-executor":
        raise W5EvidenceError("W2.5 fake worker identity drift")
    for field in ("input_snapshot_hash", "context_pack_hash", "command_hash", "deadline_policy_hash"):
        _text(attempt.get(field), f"attempt.{field}")
    _text(attempt.get("last_transition_event_id"), "attempt.last_transition_event_id")

    if dispatch.get("state") in ACK_WAIT_STATES:
        raise W5EvidenceError("ACK_WAIT_REQUIRES_EXPLICIT_BLOCKED_BUNDLE")
    if dispatch.get("state") != "EXECUTOR_ACKED":
        raise W5EvidenceError("dispatch is not EXECUTOR_ACKED")
    if dispatch.get("dispatch_key") != f"dispatch-key:{run_id}:{card_id}:001" or dispatch.get("idempotency_key") != f"idempotency:{run_id}:{card_id}:001":
        raise W5EvidenceError("dispatch idempotency key drift")
    if dispatch.get("run_token") != f"run-token:{run_id}:{attempt_id}" or dispatch.get("owner_id") != owner_id:
        raise W5EvidenceError("dispatch lease owner/token drift")
    if dispatch.get("fencing_epoch") != epoch or dispatch.get("lease_expires_at") != lease_expires_at:
        raise W5EvidenceError("dispatch fencing/lease drift")
    if dispatch.get("ack_deadline_at") != lease_expires_at:
        raise W5EvidenceError("dispatch ack deadline drift")
    if type(dispatch.get("spawn_attempt_no")) is not int or type(dispatch.get("max_spawn_attempts")) is not int or type(dispatch.get("row_version")) is not int or dispatch.get("spawn_attempt_no") != 1 or dispatch.get("max_spawn_attempts") != 1 or dispatch.get("row_version") != 0:
        raise W5EvidenceError("dispatch replay budget drift")
    if dispatch.get("executor_kind") != "fake":
        raise W5EvidenceError("W5-S0 accepts only the fake executor boundary")
    if attempt.get("command_hash") != dispatch.get("command_hash"):
        raise W5EvidenceError("attempt/dispatch command binding drift")
    identity = _identity_from_dispatch(dispatch)
    markers = _verify_markers(runtime, run_id, dispatch_id, attempt_id)
    marker_identity = _normalize_ack_identity(_payload(markers["executor-ack"], "executor-ack").get("identity"), "executor-ack.identity")
    if marker_identity != identity:
        raise W5EvidenceError("C4 marker executor identity drift")
    if identity != _derive_fake_identity(dispatch):
        raise W5EvidenceError("fake executor identity reconstruction drift")
    _verify_marker_payload_bindings(markers, run=run, card=card, attempt=attempt, dispatch=dispatch, identity=identity)
    event_info = _verify_events(
        runtime,
        run_id,
        dispatch_id,
        attempt_id,
        identity,
        dispatch_key=dispatch["dispatch_key"],
        idempotency_key=dispatch["idempotency_key"],
        owner_id=owner_id,
        fencing_epoch=epoch,
    )
    _verify_marker_event_witness(markers, event_info)
    if attempt.get("state_version") != 2 or attempt.get("last_transition_event_id") != event_info["starting_event_id"]:
        raise W5EvidenceError("attempt STARTING version/event drift")
    last_event = event_info["events"][max(event_info["events"])]
    if run.get("last_committed_event_id") != last_event["event_id"]:
        raise W5EvidenceError("run event anchor drift")
    return {
        "run": run,
        "card": card,
        "attempt": attempt,
        "dispatch": dispatch,
        "identity": identity,
        "markers": markers,
        "events": event_info,
        "run_id": run_id,
        "card_id": card_id,
        "attempt_id": attempt_id,
        "dispatch_id": dispatch_id,
        "epoch": epoch,
        "card_hash": card_hash,
        "owner_id": owner_id,
    }


def _verify_continue(value: Any, info: Mapping[str, Any]) -> dict[str, Any]:
    item = _mapping(value, "continue_intent")
    required = {"schema", "continue_id", "ordinal", "actor_id", "actor_session_id", "run_id", "card_id", "card_hash", "attempt_id", "dispatch_id", "dispatch_key", "idempotency_key", "expected_pre_state_hash", "expected_fencing_epoch", "intent"}
    _required_keys(item, required, "continue_intent")
    if item["schema"] != CONTINUE_SCHEMA or item["intent"] != "CONTINUE" or _exact_int(item["ordinal"], "continue_intent.ordinal", minimum=1) != 1:
        raise W5EvidenceError("CONTINUE contract drift")
    for field in ("continue_id", "actor_id", "actor_session_id", "run_id", "card_id", "card_hash", "attempt_id", "dispatch_id", "dispatch_key", "idempotency_key"):
        _text(item.get(field), f"continue_intent.{field}")
    if item["run_id"] != info["run_id"] or item["card_id"] != info["card_id"] or item["card_hash"] != info["card_hash"] or item["attempt_id"] != info["attempt_id"] or item["dispatch_id"] != info["dispatch_id"]:
        raise W5EvidenceError("CONTINUE identity drift")
    if item["dispatch_key"] != info["dispatch"]["dispatch_key"] or item["idempotency_key"] != info["dispatch"]["idempotency_key"]:
        raise W5EvidenceError("CONTINUE dispatch-key drift")
    if _hash64(item["expected_pre_state_hash"], "continue_intent.expected_pre_state_hash") != _payload(info["markers"]["dispatch-intent"], "dispatch-intent")["_before_state_hash"]:
        raise W5EvidenceError("CONTINUE pre-state witness drift")
    if _exact_int(item["expected_fencing_epoch"], "continue_intent.expected_fencing_epoch", minimum=1) != info["epoch"]:
        raise W5EvidenceError("CONTINUE fencing epoch drift")
    return dict(item)


def _verify_worker_claim(value: Any, info: Mapping[str, Any]) -> dict[str, Any]:
    item = _mapping(value, "worker_claim")
    required = {"schema", "claim_id", "worker_id", "worker_session_id", "worker_backend", "run_id", "card_id", "attempt_id", "dispatch_id", "run_token", "fencing_epoch", "command_hash", "claim_epoch", "claim_before_ack_event_no", "provenance", "status"}
    _required_keys(item, required, "worker_claim")
    if item["schema"] != WORKER_CLAIM_SCHEMA or item["status"] != "CLAIMED" or item["provenance"] != "external-authority-only":
        raise W5EvidenceError("worker claim contract drift")
    for field in ("claim_id", "worker_id", "worker_session_id", "worker_backend", "run_id", "card_id", "attempt_id", "dispatch_id", "run_token", "command_hash"):
        _text(item.get(field), f"worker_claim.{field}")
    if item["run_id"] != info["run_id"] or item["card_id"] != info["card_id"] or item["attempt_id"] != info["attempt_id"] or item["dispatch_id"] != info["dispatch_id"]:
        raise W5EvidenceError("worker claim identity drift")
    if item["worker_id"] != info["attempt"]["worker_id"] or item["run_token"] != info["dispatch"]["run_token"] or item["command_hash"] != info["dispatch"]["command_hash"] or _exact_int(item["fencing_epoch"], "worker_claim.fencing_epoch", minimum=1) != info["epoch"]:
        raise W5EvidenceError("worker claim lease/command drift")
    if item["worker_id"] == info["owner_id"]:
        raise W5EvidenceError("worker claim is not distinct from controller owner")
    claim_epoch = _exact_int(item["claim_epoch"], "worker_claim.claim_epoch", minimum=0)
    claim_before_ack = _exact_int(item["claim_before_ack_event_no"], "worker_claim.claim_before_ack_event_no", minimum=1)
    if (
        claim_before_ack < info["events"]["spawn_event_no"]
        or claim_before_ack >= info["events"]["ack_event_no"]
        or claim_epoch < info["dispatch"]["ack_deadline_at"] - ACK_WINDOW_SECONDS
        or claim_epoch >= info["dispatch"]["ack_deadline_at"]
    ):
        raise W5EvidenceError("worker claim ordering/deadline witness drift")
    return dict(item)


def _verify_process_ack(value: Any, info: Mapping[str, Any]) -> dict[str, Any]:
    item = _mapping(value, "process_ack")
    required = {"schema", "ack_id", "dispatch_id", "attempt_id", "worker_id", "ack_event_id", "ack_event_no", "ack_epoch", "ack_deadline_at", "status", "identity"}
    _required_keys(item, required, "process_ack")
    if item["schema"] != PROCESS_ACK_SCHEMA or item["status"] != "EXECUTOR_ACKED":
        raise W5EvidenceError("process ack contract drift")
    for field in ("ack_id", "dispatch_id", "attempt_id", "worker_id", "ack_event_id"):
        _text(item.get(field), f"process_ack.{field}")
    if item["dispatch_id"] != info["dispatch_id"] or item["attempt_id"] != info["attempt_id"] or item["worker_id"] != info["attempt"]["worker_id"]:
        raise W5EvidenceError("process ack identity drift")
    if _exact_int(item["ack_event_no"], "process_ack.ack_event_no", minimum=1) != info["events"]["ack_event_no"] or item["ack_event_id"] != info["events"]["ack_event_id"]:
        raise W5EvidenceError("process ack event witness drift")
    ack_epoch = _exact_int(item["ack_epoch"], "process_ack.ack_epoch", minimum=0)
    ack_deadline = _exact_int(item["ack_deadline_at"], "process_ack.ack_deadline_at", minimum=0)
    if ack_deadline != info["dispatch"]["ack_deadline_at"] or not ack_deadline - ACK_WINDOW_SECONDS <= ack_epoch < ack_deadline:
        raise W5EvidenceError("process ack is late or deadline-bound incorrectly")
    identity = _mapping(item["identity"], "process_ack.identity")
    _required_keys(identity, set(IDENTITY_FIELDS), "process_ack.identity")
    if dict(identity) != info["identity"]:
        raise W5EvidenceError("process ack executor identity drift")
    return dict(item)


def _verify_replay(value: Any, info: Mapping[str, Any], runtime_hash: str) -> dict[str, Any]:
    replay = _mapping(value, "replay_evidence")
    required = {"schema", "continue_id", "first_continue_id", "second_continue_id", "first_continue_hash", "second_continue_hash", "second_continue_outcome", "continue_calls", "first_runtime_hash", "second_runtime_hash", "first_event_count", "second_event_count", "first_attempt_count", "second_attempt_count", "first_dispatch_count", "second_dispatch_count", "first_spawn_request_count", "second_spawn_request_count", "first_ack_count", "second_ack_count", "status", "no_duplicate_dispatch", "no_duplicate_spawn"}
    _required_keys(replay, required, "replay_evidence")
    if replay["schema"] != REPLAY_SCHEMA or replay["status"] != "IDEMPOTENT_REPLAY":
        raise W5EvidenceError("dispatch replay contract drift")
    _text(replay["continue_id"], "replay_evidence.continue_id")
    if replay["continue_id"] != _text(info["continue"]["continue_id"], "continue_intent.continue_id"):
        raise W5EvidenceError("replay continue identity drift")
    if replay["first_continue_id"] != replay["continue_id"] or replay["second_continue_id"] != replay["continue_id"]:
        raise W5EvidenceError("replay per-call Continue identity drift")
    expected_continue_hash = canonical_hash(info["continue"])
    if replay["first_continue_hash"] != expected_continue_hash or replay["second_continue_hash"] != expected_continue_hash:
        raise W5EvidenceError("replay per-call Continue hash drift")
    if replay["second_continue_outcome"] != "IDEMPOTENT_REPLAY":
        raise W5EvidenceError("replay second-call outcome drift")
    if _exact_int(replay["continue_calls"], "replay_evidence.continue_calls", minimum=0) != 2:
        raise W5EvidenceError("W5 requires one initial Continue and one idempotent replay")
    for field in ("first_runtime_hash", "second_runtime_hash"):
        _hash64(replay[field], f"replay_evidence.{field}")
    if replay["first_runtime_hash"] != runtime_hash or replay["second_runtime_hash"] != runtime_hash:
        raise W5EvidenceError("replay runtime hash drift")
    expected_counts = {
        "first_event_count": len(info["events"]["events"]),
        "second_event_count": len(info["events"]["events"]),
        "first_attempt_count": 1,
        "second_attempt_count": 1,
        "first_dispatch_count": 1,
        "second_dispatch_count": 1,
        "first_spawn_request_count": 1,
        "second_spawn_request_count": 1,
        "first_ack_count": 1,
        "second_ack_count": 1,
    }
    for field, expected in expected_counts.items():
        if _exact_int(replay[field], f"replay_evidence.{field}", minimum=0) != expected:
            raise W5EvidenceError(f"replay evidence drift: {field}")
    if not _bool(replay["no_duplicate_dispatch"], "replay_evidence.no_duplicate_dispatch") or not _bool(replay["no_duplicate_spawn"], "replay_evidence.no_duplicate_spawn"):
        raise W5EvidenceError("duplicate dispatch/spawn was not proven absent")
    return dict(replay)


def _verify_authority(
    authority: Any,
    *,
    info: Mapping[str, Any],
    policy: Mapping[str, Any],
    continue_intent: Mapping[str, Any],
    worker_claim: Mapping[str, Any],
    process_ack: Mapping[str, Any],
    replay: Mapping[str, Any],
    runtime_hash: str,
    state_witness_hash: str,
) -> None:
    authority = _mapping(authority, "authority")
    _required_keys(authority, AUTHORITY_KEYS, "authority")
    if authority["schema"] != AUTHORITY_SCHEMA:
        raise W5EvidenceError("AUTHORITY_SCHEMA_UNSUPPORTED")
    authority_id = _text(authority["authority_id"], "authority.authority_id")
    key_id = _text(authority["key_id"], "authority.key_id")
    trusted_key = resolve_trusted_authority(authority_id=authority_id, key_id=key_id)
    if authority["run_id"] != info["run_id"] or authority["card_id"] != info["card_id"] or authority["attempt_id"] != info["attempt_id"] or authority["dispatch_id"] != info["dispatch_id"] or _exact_int(authority["fencing_epoch"], "authority.fencing_epoch", minimum=1) != info["epoch"]:
        raise W5EvidenceError("bridge authority identity drift")
    authority_core = {key: authority[key] for key in AUTHORITY_KEYS if key not in {"authority_hash", "authority_mac"}}
    if _hash64(authority["authority_hash"], "authority.authority_hash") != canonical_hash(authority_core):
        raise W5EvidenceError("AUTHORITY_HASH_DRIFT")
    expected_mac = hmac.new(trusted_key, canonical_json(authority_core).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(_hash64(authority["authority_mac"], "authority.authority_mac"), expected_mac):
        raise W5EvidenceError("AUTHORITY_MAC_INVALID")
    if authority["policy_hash"] != canonical_hash(policy) or authority["runtime_hash"] != runtime_hash or authority["state_witness_hash"] != state_witness_hash:
        raise W5EvidenceError("bridge authority policy/runtime drift")
    if authority["event_chain_hash"] != canonical_hash([info["events"]["events"][number] for number in sorted(info["events"]["events"])]):
        raise W5EvidenceError("AUTHORITY_EVENT_CHAIN_DRIFT")
    marker_commitments = _mapping(authority["marker_commitments"], "authority.marker_commitments")
    if set(marker_commitments) != set(info["markers"]):
        raise W5EvidenceError("authority marker commitment set drift")
    for operation, marker in info["markers"].items():
        if marker_commitments.get(operation) != marker.get("marker_hash"):
            raise W5EvidenceError(f"authority marker commitment drift: {operation}")
    if authority["continue_hash"] != canonical_hash(continue_intent) or authority["worker_claim_hash"] != canonical_hash(worker_claim) or authority["process_ack_hash"] != canonical_hash(process_ack) or authority["replay_hash"] != canonical_hash(replay):
        raise W5EvidenceError("authority external evidence hash drift")
    executor = _mapping(authority["executor"], "authority.executor")
    _required_keys(executor, {"worker_id", "worker_session_id", "worker_backend", "controller_owner_id", "identity_hash"}, "authority.executor")
    if executor["worker_id"] != worker_claim["worker_id"] or executor["worker_session_id"] != worker_claim["worker_session_id"] or executor["worker_backend"] != worker_claim["worker_backend"] or executor["controller_owner_id"] != info["owner_id"] or executor["identity_hash"] != canonical_hash(info["identity"]):
        raise W5EvidenceError("authority executor binding drift")


def verify_dispatch_bridge_bundle(bundle: Mapping[str, Any], *, authority: Mapping[str, Any] | None = None) -> DispatchBridgeResult:
    """Verify one externalized Continue→C1-C4 bridge and never execute it."""

    try:
        bundle = _mapping(bundle, "bundle")
        _required_keys(bundle, TOP_LEVEL_KEYS, "bundle")
        if bundle.get("schema") != BUNDLE_SCHEMA:
            raise W5EvidenceError("BUNDLE_SCHEMA_UNSUPPORTED")
        source = _mapping(bundle.get("source"), "source")
        if dict(source) != SOURCE_CONTRACT:
            raise W5IncompatibleSource("INCOMPATIBLE_SOURCE")
        if authority is None:
            raise W5EvidenceError("AUTHORITY_REQUIRED")
        policy = _verify_policy(bundle["bridge_policy"])
        info = _verify_runtime(bundle["runtime"])
        state_witnesses = _verify_state_witnesses(bundle["state_witnesses"], bundle["runtime"], info)
        continue_intent = _verify_continue(bundle["continue_intent"], info)
        worker_claim = _verify_worker_claim(bundle["worker_claim"], info)
        if continue_intent["actor_session_id"] == worker_claim["worker_session_id"] or continue_intent["actor_id"] == worker_claim["worker_id"]:
            raise W5EvidenceError("Continue actor and worker claim are not independent")
        process_ack = _verify_process_ack(bundle["process_ack"], info)
        if worker_claim["claim_epoch"] > process_ack["ack_epoch"]:
            raise W5EvidenceError("worker claim was observed after process acknowledgement")
        runtime_hash = canonical_hash(bundle["runtime"])
        replay = dict(bundle["replay_evidence"])
        replay["continue_id"] = replay.get("continue_id")
        info_for_replay = {**info, "continue": continue_intent}
        replay = _verify_replay(replay, info_for_replay, runtime_hash)
        _verify_authority(
            authority,
            info=info,
            policy=policy,
            continue_intent=continue_intent,
            worker_claim=worker_claim,
            process_ack=process_ack,
            replay=replay,
            runtime_hash=runtime_hash,
            state_witness_hash=canonical_hash(state_witnesses),
        )
        return DispatchBridgeResult(
            status="BRIDGE_VERIFIED",
            bridge={
                "run_id": info["run_id"],
                "card_id": info["card_id"],
                "attempt_id": info["attempt_id"],
                "dispatch_id": info["dispatch_id"],
                "controller_claim": "C2_DISPATCH_CLAIMED",
                "worker_claim": worker_claim["claim_id"],
                "process_ack": process_ack["ack_id"],
                "state": {
                    "run": info["run"]["state"],
                    "card": info["card"]["state"],
                    "attempt": info["attempt"]["state"],
                    "dispatch": info["dispatch"]["state"],
                },
            },
            replay=replay,
        )
    except W5IncompatibleSource as exc:
        return DispatchBridgeResult(status="INCOMPATIBLE_SOURCE", findings=(str(exc),))
    except W5BridgeBlocked as exc:
        return DispatchBridgeResult(status="BLOCKED", findings=(str(exc),))
    except (W5EvidenceError, W4EvidenceError, AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        return DispatchBridgeResult(status="INVALID_EVIDENCE", findings=(str(exc),))
