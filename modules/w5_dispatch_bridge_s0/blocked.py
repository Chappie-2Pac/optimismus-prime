"""Explicit W5-S1 C0-C3 ACK-wait evidence contract.

This verifier is intentionally separate from the verified C4 bridge. A
blocked dispatch is not represented by mutating a C4 bundle and hoping the
caller classifies it correctly: it has its own schema, four markers, fourteen
events, no worker/process acknowledgement and an authenticated observation.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path
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
from .source_attestation import verify_source_attestation
from .verifier import (
    ACK_WAIT_STATES,
    EVENT_ROW_FIELDS,
    MARKER_ROW_FIELDS,
    PROJECTION_TABLES,
    RAW_PROJECTION_FIELDS,
    RUNTIME_KEYS,
    RUNTIME_ROW_FIELDS,
    SOURCE_CONTRACT,
    _payload,
    _projection,
    _raw_runtime_projection,
    _required_keys,
)


BLOCKED_BUNDLE_SCHEMA = "w5-blocked-ack-bundle.v1"
BLOCKED_POLICY_SCHEMA = "w5-bridge-blocked-policy.v1"
BLOCKED_OBSERVATION_SCHEMA = "w5-blocked-ack-observation.v1"
MISSING_EVIDENCE_SCHEMA = "w5-missing-ack-evidence.v1"
BLOCKED_REPLAY_SCHEMA = "w5-blocked-ack-replay.v1"
BLOCKED_AUTHORITY_SCHEMA = "w5-w25-blocked-authority.v1"
BLOCKED_MARKERS = {
    "run-admit": ("C0", "COMMITTED"),
    "dispatch-intent": ("C1", "COMMITTED"),
    "claim-lease": ("C2", "COMMITTED"),
    "spawn-request": ("C3", "COMMITTED"),
}
BLOCKED_OPERATIONS = tuple(BLOCKED_MARKERS)
BLOCKED_EVENT_TYPES = [
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
]
BLOCKED_AUTHORITY_KEYS = {
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
    "replay_hash",
    "blocked_ack_hash",
    "missing_evidence_hash",
    "source_attestation_hash",
    "bundle_schema_hash",
}
BLOCKED_TOP_LEVEL_KEYS = {
    "schema",
    "source",
    "runtime",
    "bridge_policy",
    "continue_intent",
    "replay_evidence",
    "blocked_ack",
    "missing_evidence",
    "state_witnesses",
    "source_attestation",
}


def _verify_blocked_policy(value: Any) -> dict[str, Any]:
    policy = _mapping(value, "bridge_policy")
    expected = {
        "schema": BLOCKED_POLICY_SCHEMA,
        "phase": "C0-C3",
        "max_cards": 1,
        "max_dispatches": 1,
        "max_workers": 1,
        "require_ack_before_running": True,
        "allow_following_card": False,
        "process_mode": "fake-only",
        "blocked_reason": "ACK_NOT_CONFIRMED",
    }
    _required_keys(policy, set(expected), "bridge_policy")
    if canonical_json(policy) != canonical_json(expected):
        raise W5EvidenceError("BLOCKED_POLICY_DRIFT")
    return dict(expected)


def _verify_blocked_runtime(runtime: Any) -> dict[str, Any]:
    runtime = _mapping(runtime, "runtime")
    _required_keys(runtime, RUNTIME_KEYS, "runtime")
    projects = runtime.get("projects")
    cards = runtime.get("cards")
    attempts = runtime.get("attempts")
    dispatches = runtime.get("dispatches")
    for value, label in ((projects, "runtime.projects"), (cards, "runtime.cards"), (attempts, "runtime.attempts"), (dispatches, "runtime.dispatches")):
        if not isinstance(value, list) or len(value) != 1:
            raise W5EvidenceError(f"{label}: exactly one row required")
    for value, label in ((runtime["receipts"], "runtime.receipts"), (runtime["reviews"], "runtime.reviews"), (runtime["acceptance_txns"], "runtime.acceptance_txns"), (runtime["next_card_intents"], "runtime.next_card_intents")):
        if not isinstance(value, list) or value:
            raise W5EvidenceError(f"{label}: blocked C0-C3 must be empty")
    counts = _mapping(runtime.get("counts"), "runtime.counts")
    _required_keys(counts, {"runs", "cards", "attempts", "dispatches", "receipts", "events"}, "runtime.counts")
    if dict(counts) != {"runs": 1, "cards": 1, "attempts": 1, "dispatches": 1, "receipts": 0, "events": 14}:
        raise W5EvidenceError("blocked runtime counts drift")
    events = runtime.get("events")
    if not isinstance(events, list) or len(events) != 14:
        raise W5EvidenceError("blocked runtime requires exactly C0-C3 events")

    project = _mapping(projects[0], "runtime.project")
    run = _mapping(runtime.get("run"), "runtime.run")
    card = _mapping(cards[0], "runtime.card")
    attempt = _mapping(attempts[0], "runtime.attempt")
    dispatch = _mapping(dispatches[0], "runtime.dispatch")
    run_id = _text(run.get("run_id"), "run.run_id")
    card_id = _text(card.get("card_id"), "card.card_id")
    attempt_id = _text(attempt.get("attempt_id"), "attempt.attempt_id")
    dispatch_id = _text(dispatch.get("dispatch_id"), "dispatch.dispatch_id")
    if project.get("project_id") != run.get("project_id") or project.get("status") != "ACTIVE":
        raise W5EvidenceError("blocked project provenance drift")
    if run.get("state") != "DISPATCHING" or run.get("active_dispatch_id") != dispatch_id:
        raise W5EvidenceError("blocked run state drift")
    epoch = _exact_int(run.get("fencing_epoch"), "run.fencing_epoch", minimum=1)
    owner_id = _text(run.get("lease_owner_id"), "run.lease_owner_id")
    lease_expires_at = _exact_int(run.get("lease_expires_at"), "run.lease_expires_at", minimum=0)
    if run.get("lease_token") != f"lease:{run_id}:epoch:{epoch}":
        raise W5EvidenceError("blocked lease token drift")
    if card.get("run_id") != run_id or card.get("state") != "CLAIMED" or card.get("active_attempt_id") != attempt_id:
        raise W5EvidenceError("blocked card state/binding drift")
    if card.get("acceptance_txn_id") is not None or card.get("next_card_intent_id") is not None:
        raise W5EvidenceError("blocked card boundary drift")
    if attempt.get("run_id") != run_id or attempt.get("card_id") != card_id or attempt.get("state") != "ADMITTED" or attempt.get("state_version") != 1:
        raise W5EvidenceError("blocked attempt state/binding drift")
    if attempt.get("attempt_id") != attempt_id or attempt.get("attempt_no") != 1 or attempt.get("retry_of") is not None or attempt.get("dispatch_id") != dispatch_id or attempt.get("worker_id") is not None:
        raise W5EvidenceError("blocked attempt identity drift")
    if dispatch_id != f"dispatch-{attempt_id}" or dispatch.get("run_id") != run_id or dispatch.get("attempt_id") != attempt_id:
        raise W5EvidenceError("blocked dispatch identity drift")
    if dispatch.get("state") != "SPAWN_REQUESTED" or dispatch.get("dispatch_key") != f"dispatch-key:{run_id}:{card_id}:001" or dispatch.get("idempotency_key") != f"idempotency:{run_id}:{card_id}:001":
        raise W5EvidenceError("blocked dispatch state/idempotency drift")
    if dispatch.get("run_token") != f"run-token:{run_id}:{attempt_id}" or dispatch.get("owner_id") != owner_id or dispatch.get("fencing_epoch") != epoch:
        raise W5EvidenceError("blocked dispatch lease binding drift")
    if dispatch.get("lease_expires_at") != lease_expires_at or dispatch.get("ack_deadline_at") != lease_expires_at:
        raise W5EvidenceError("blocked dispatch deadline drift")
    if dispatch.get("spawn_attempt_no") != 1 or dispatch.get("max_spawn_attempts") != 1 or dispatch.get("executor_kind") != "fake" or dispatch.get("row_version") != 0:
        raise W5EvidenceError("blocked dispatch replay budget drift")
    if attempt.get("command_hash") != dispatch.get("command_hash"):
        raise W5EvidenceError("blocked command binding drift")
    if any(dispatch.get(field) is not None for field in ("pid", "process_starttime", "boot_id", "pidfd_ref", "cgroup_ref")):
        raise W5EvidenceError("blocked dispatch has an executor identity before ACK")
    if run.get("last_committed_event_id") != events[-1].get("event_id"):
        raise W5EvidenceError("blocked event anchor drift")
    return {
        "runtime": runtime,
        "run": run,
        "project": project,
        "card": card,
        "attempt": attempt,
        "dispatch": dispatch,
        "run_id": run_id,
        "card_id": card_id,
        "attempt_id": attempt_id,
        "dispatch_id": dispatch_id,
        "epoch": epoch,
        "owner_id": owner_id,
        "events": events,
    }


def _verify_blocked_events(info: Mapping[str, Any]) -> dict[str, Any]:
    events = info["events"]
    by_no: dict[int, Mapping[str, Any]] = {}
    event_ids: set[str] = set()
    for expected_no, raw in enumerate(events, 1):
        event = _mapping(raw, f"event[{expected_no - 1}]")
        if set(event) != EVENT_ROW_FIELDS:
            raise W5EvidenceError("blocked event schema drift")
        event_no = _exact_int(event.get("event_no"), f"event[{expected_no - 1}].event_no", minimum=1)
        if event_no != expected_no or event.get("run_id") != info["run_id"]:
            raise W5EvidenceError("blocked event sequence/run drift")
        event_id = _text(event.get("event_id"), f"event[{expected_no - 1}].event_id")
        if event_id in event_ids:
            raise W5EvidenceError("blocked event identity is duplicated")
        event_ids.add(event_id)
        by_no[event_no] = event
    if [by_no[number].get("event_type") for number in range(1, 15)] != BLOCKED_EVENT_TYPES:
        raise W5EvidenceError("blocked C0-C3 event sequence drift")
    identities = [
        ("Run", info["run_id"]),
        ("Project", info["project"]["project_id"]),
        ("Run", info["run_id"]),
        ("Run", info["run_id"]),
        ("Card", info["card_id"]),
        ("Card", info["card_id"]),
        ("Card", info["card_id"]),
        ("Attempt", info["attempt_id"]),
        ("Attempt", info["attempt_id"]),
        ("Dispatch", info["dispatch_id"]),
        ("Run", info["run_id"]),
        ("Dispatch", info["dispatch_id"]),
        ("Card", info["card_id"]),
        ("Dispatch", info["dispatch_id"]),
    ]
    transitions = [
        (None, "CREATED"),
        ("READY", "ACTIVE"),
        ("CREATED", "PREFLIGHT"),
        ("PREFLIGHT", "READY"),
        (None, "DRAFT"),
        ("DRAFT", "WAITING"),
        ("WAITING", "READY"),
        (None, "CREATED"),
        ("CREATED", "ADMITTED"),
        (None, "DISPATCH_INTENDED"),
        ("READY", "DISPATCHING"),
        ("DISPATCH_INTENDED", "CLAIMED"),
        ("READY", "CLAIMED"),
        ("CLAIMED", "SPAWN_REQUESTED"),
    ]
    for event, (entity_type, entity_id), transition in zip(events, identities, transitions):
        if (event.get("entity_type"), event.get("entity_id")) != (entity_type, entity_id) or (event.get("from_state"), event.get("to_state")) != transition:
            raise W5EvidenceError("blocked event entity/transition drift")
        _payload(event, f"event[{event['event_no']}]" )
    intent = by_no[10]
    claim = by_no[12]
    spawn = by_no[14]
    intent_payload = _payload(intent, "DISPATCH_INTENDED")
    if intent_payload.get("dispatch_key") != info["dispatch"]["dispatch_key"] or intent_payload.get("idempotency_key") != info["dispatch"]["idempotency_key"]:
        raise W5EvidenceError("blocked dispatch-intent payload drift")
    claim_payload = _payload(claim, "DISPATCH_CLAIMED")
    if claim_payload.get("owner_id") != info["owner_id"] or claim_payload.get("fencing_epoch") != info["epoch"]:
        raise W5EvidenceError("blocked claim payload drift")
    spawn_payload = _payload(spawn, "SPAWN_REQUESTED")
    if spawn_payload.get("run_token") != info["dispatch"]["run_token"] or spawn_payload.get("command_hash") != info["dispatch"]["command_hash"]:
        raise W5EvidenceError("blocked spawn payload drift")
    return {"events": by_no, "spawn_event_id": spawn["event_id"], "spawn_event_no": spawn["event_no"]}


def _verify_blocked_markers(runtime: Mapping[str, Any], info: Mapping[str, Any], event_info: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    markers = runtime.get("commit_markers")
    if not isinstance(markers, list):
        raise W5EvidenceError("blocked commit_markers: list required")
    by_operation: dict[str, Mapping[str, Any]] = {}
    for raw in markers:
        marker = _mapping(raw, "blocked.commit_marker")
        if set(marker) != MARKER_ROW_FIELDS:
            raise W5EvidenceError("blocked marker schema drift")
        if marker.get("run_id") != info["run_id"]:
            raise W5EvidenceError("blocked marker run binding drift")
        operation = _text(marker.get("operation_key"), "blocked.marker.operation_key")
        if operation in by_operation:
            raise W5EvidenceError("duplicate blocked marker")
        by_operation[operation] = marker
        payload = _payload(marker, f"blocked.marker.{operation}")
        expected_hash = canonical_hash({
            "run_id": info["run_id"],
            "commit_point": marker.get("commit_point"),
            "operation_key": operation,
            "status": marker.get("status"),
            "payload": dict(payload),
        })
        if marker.get("marker_hash") != expected_hash:
            raise W5EvidenceError(f"blocked marker hash drift: {operation}")
        _hash64(payload.get("_before_state_hash"), f"blocked.marker.{operation}.before")
        _hash64(payload.get("_after_state_hash"), f"blocked.marker.{operation}.after")
        _text(payload.get("_after_event_id"), f"blocked.marker.{operation}.after_event_id")
    if set(by_operation) != set(BLOCKED_MARKERS):
        raise W5EvidenceError("blocked bundle requires exactly C0-C3 markers")
    for operation, (commit_point, status) in BLOCKED_MARKERS.items():
        marker = by_operation[operation]
        if marker.get("commit_point") != commit_point or marker.get("status") != status:
            raise W5EvidenceError(f"blocked marker contract drift: {operation}")
    events_by_id = {event["event_id"]: event for event in event_info["events"].values()}
    expected_event_types = {
        "run-admit": "CARD_READY",
        "dispatch-intent": "RUN_DISPATCHING",
        "claim-lease": "CARD_CLAIMED",
        "spawn-request": "SPAWN_REQUESTED",
    }
    previous_event_no = 0
    for operation in BLOCKED_OPERATIONS:
        payload = _payload(by_operation[operation], operation)
        after_event_id = _text(payload.get("_after_event_id"), f"blocked.marker.{operation}.after_event_id")
        event = events_by_id.get(after_event_id)
        if event is None or event.get("event_type") != expected_event_types[operation] or event.get("run_id") != info["run_id"] or event["event_no"] <= previous_event_no:
            raise W5EvidenceError(f"blocked marker event witness drift: {operation}")
        previous_event_no = event["event_no"]
    c1 = _payload(by_operation["dispatch-intent"], "dispatch-intent")
    c2 = _payload(by_operation["claim-lease"], "claim-lease")
    c3 = _payload(by_operation["spawn-request"], "spawn-request")
    if c1.get("dispatch_id") != info["dispatch_id"] or c1.get("attempt_id") != info["attempt_id"] or c1.get("idempotency_key") != info["dispatch"]["idempotency_key"]:
        raise W5EvidenceError("blocked C1 marker binding drift")
    if c2.get("owner_id") != info["owner_id"] or c2.get("fencing_epoch") != info["epoch"]:
        raise W5EvidenceError("blocked C2 marker binding drift")
    if c3.get("dispatch_id") != info["dispatch_id"] or c3.get("run_token") != info["dispatch"]["run_token"] or c3.get("spawn_attempt_no") != 1:
        raise W5EvidenceError("blocked C3 marker binding drift")
    return by_operation


def _verify_blocked_witnesses(value: Any, info: Mapping[str, Any], markers: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    raw = _mapping(value, "state_witnesses")
    _required_keys(raw, set(BLOCKED_OPERATIONS), "state_witnesses")
    witnesses: dict[str, Any] = {}
    for operation in BLOCKED_OPERATIONS:
        witness = _mapping(raw[operation], f"state_witnesses.{operation}")
        _required_keys(witness, {"before_projection", "after_projection"}, f"state_witnesses.{operation}")
        before = _projection(witness["before_projection"], f"state_witnesses.{operation}.before")
        after = _projection(witness["after_projection"], f"state_witnesses.{operation}.after")
        payload = _payload(markers[operation], operation)
        if canonical_hash(before) != payload["_before_state_hash"] or canonical_hash(after) != payload["_after_state_hash"]:
            raise W5EvidenceError(f"blocked state witness drift: {operation}")
        witnesses[operation] = {"before_projection": before, "after_projection": after}
    for previous, current in zip(BLOCKED_OPERATIONS, BLOCKED_OPERATIONS[1:]):
        if witnesses[previous]["after_projection"] != witnesses[current]["before_projection"]:
            raise W5EvidenceError(f"blocked witness discontinuity: {previous}->{current}")
    if any(witnesses["run-admit"]["before_projection"][table] for table in PROJECTION_TABLES):
        raise W5EvidenceError("blocked C0 before-projection is not empty")
    expected = {
        "run-admit": ("READY", "READY", 0, 0),
        "dispatch-intent": ("DISPATCHING", "READY", 1, "DISPATCH_INTENDED"),
        "claim-lease": ("DISPATCHING", "CLAIMED", 1, "CLAIMED"),
        "spawn-request": ("DISPATCHING", "CLAIMED", 1, "SPAWN_REQUESTED"),
    }
    for operation, states in expected.items():
        projection = witnesses[operation]["after_projection"]
        if len(projection["projects"]) != 1 or len(projection["runs"]) != 1 or len(projection["cards"]) != 1:
            raise W5EvidenceError(f"blocked projection cardinality drift: {operation}")
        if projection["projects"][0].get("status") != "ACTIVE" or projection["runs"][0].get("state") != states[0] or projection["cards"][0].get("state") != states[1]:
            raise W5EvidenceError(f"blocked projection state drift: {operation}")
        if operation == "run-admit":
            if projection["attempts"] or projection["dispatches"]:
                raise W5EvidenceError("blocked C0 projection unexpectedly contains dispatch state")
        else:
            if len(projection["attempts"]) != states[2] or len(projection["dispatches"]) != states[2] or projection["attempts"][0].get("state") != "ADMITTED" or projection["dispatches"][0].get("state") != states[3]:
                raise W5EvidenceError(f"blocked projection attempt/dispatch drift: {operation}")
    if witnesses["spawn-request"]["after_projection"] != _raw_runtime_projection(info["runtime"]):
        raise W5EvidenceError("blocked C3 projection/runtime drift")
    return witnesses


def _verify_blocked_continue(value: Any, info: Mapping[str, Any], markers: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    item = _mapping(value, "continue_intent")
    required = {"schema", "continue_id", "ordinal", "actor_id", "actor_session_id", "run_id", "card_id", "card_hash", "attempt_id", "dispatch_id", "dispatch_key", "idempotency_key", "expected_pre_state_hash", "expected_fencing_epoch", "intent"}
    _required_keys(item, required, "continue_intent")
    if item.get("schema") != "w5-continue-intent.v1" or item.get("intent") != "CONTINUE" or item.get("ordinal") != 1:
        raise W5EvidenceError("blocked Continue contract drift")
    for field in ("continue_id", "actor_id", "actor_session_id", "run_id", "card_id", "card_hash", "attempt_id", "dispatch_id", "dispatch_key", "idempotency_key"):
        _text(item.get(field), f"continue_intent.{field}")
    if item.get("run_id") != info["run_id"] or item.get("card_id") != info["card_id"] or item.get("attempt_id") != info["attempt_id"] or item.get("dispatch_id") != info["dispatch_id"] or item.get("card_hash") != info["card"]["card_hash"]:
        raise W5EvidenceError("blocked Continue identity drift")
    if item.get("dispatch_key") != info["dispatch"]["dispatch_key"] or item.get("idempotency_key") != info["dispatch"]["idempotency_key"]:
        raise W5EvidenceError("blocked Continue idempotency drift")
    if item.get("expected_pre_state_hash") != _payload(markers["dispatch-intent"], "dispatch-intent")["_before_state_hash"] or item.get("expected_fencing_epoch") != info["epoch"]:
        raise W5EvidenceError("blocked Continue pre-state/fence drift")
    return dict(item)


def _timestamp_epoch(value: Any, label: str) -> int:
    timestamp = _text(value, label)
    normalized = f"{timestamp[:-1]}+00:00" if timestamp.endswith("Z") else timestamp
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise W5EvidenceError(f"{label}: invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise W5EvidenceError(f"{label}: timezone required")
    return int(parsed.astimezone(timezone.utc).timestamp())


def _verify_blocked_observation(value: Any, info: Mapping[str, Any], event_info: Mapping[str, Any]) -> dict[str, Any]:
    item = _mapping(value, "blocked_observation")
    required = {"schema", "status", "reason", "run_id", "card_id", "attempt_id", "dispatch_id", "dispatch_state", "observed_event_id", "observed_event_no", "ack_deadline_at", "observed_epoch"}
    _required_keys(item, required, "blocked_observation")
    if item.get("schema") != BLOCKED_OBSERVATION_SCHEMA or item.get("status") != "BLOCKED" or item.get("reason") != "ACK_NOT_CONFIRMED":
        raise W5EvidenceError("blocked observation contract drift")
    if (item.get("run_id"), item.get("card_id"), item.get("attempt_id"), item.get("dispatch_id")) != (info["run_id"], info["card_id"], info["attempt_id"], info["dispatch_id"]):
        raise W5EvidenceError("blocked observation identity drift")
    if item.get("dispatch_state") != info["dispatch"]["state"] or item.get("observed_event_id") != event_info["spawn_event_id"] or item.get("observed_event_no") != event_info["spawn_event_no"]:
        raise W5EvidenceError("blocked observation event/state drift")
    ack_deadline_at = _exact_int(item.get("ack_deadline_at"), "blocked_observation.ack_deadline_at", minimum=0)
    observed_epoch = _exact_int(item.get("observed_epoch"), "blocked_observation.observed_epoch", minimum=0)
    spawn_event = event_info["events"][event_info["spawn_event_no"]]
    spawn_epoch = _timestamp_epoch(spawn_event.get("created_at"), "SPAWN_REQUESTED.created_at")
    if ack_deadline_at != info["dispatch"]["ack_deadline_at"] or not ack_deadline_at - 60 <= observed_epoch < ack_deadline_at or observed_epoch <= spawn_epoch:
        raise W5EvidenceError("blocked observation deadline/timestamp drift")
    return dict(item)


def _verify_missing_evidence(value: Any) -> dict[str, Any]:
    item = _mapping(value, "missing_evidence")
    required = {"schema", "worker_claim", "process_ack", "executor_ack_event", "executor_ack_marker", "runtime_process_identity"}
    _required_keys(item, required, "missing_evidence")
    expected = {
        "schema": MISSING_EVIDENCE_SCHEMA,
        "worker_claim": "ABSENT",
        "process_ack": "ABSENT",
        "executor_ack_event": "ABSENT",
        "executor_ack_marker": "ABSENT",
        "runtime_process_identity": "ABSENT",
    }
    if dict(item) != expected:
        raise W5EvidenceError("missing ACK evidence contract drift")
    return dict(item)


def _verify_blocked_replay(value: Any, info: Mapping[str, Any], continue_intent: Mapping[str, Any], runtime_hash: str) -> dict[str, Any]:
    replay = _mapping(value, "replay_evidence")
    required = {
        "schema", "continue_id", "first_continue_id", "second_continue_id", "first_continue_hash", "second_continue_hash",
        "second_continue_outcome", "continue_calls", "first_runtime_hash", "second_runtime_hash", "first_event_count",
        "second_event_count", "first_attempt_count", "second_attempt_count", "first_dispatch_count", "second_dispatch_count",
        "first_spawn_request_count", "second_spawn_request_count", "first_ack_count", "second_ack_count", "status",
        "no_duplicate_dispatch", "no_duplicate_spawn",
    }
    _required_keys(replay, required, "replay_evidence")
    if replay.get("schema") != BLOCKED_REPLAY_SCHEMA or replay.get("status") != "IDEMPOTENT_REPLAY" or replay.get("second_continue_outcome") != "IDEMPOTENT_REPLAY":
        raise W5EvidenceError("blocked replay contract drift")
    if replay.get("continue_id") != continue_intent.get("continue_id") or replay.get("first_continue_id") != replay.get("continue_id") or replay.get("second_continue_id") != replay.get("continue_id"):
        raise W5EvidenceError("blocked replay Continue identity drift")
    expected_continue_hash = canonical_hash(continue_intent)
    if replay.get("first_continue_hash") != expected_continue_hash or replay.get("second_continue_hash") != expected_continue_hash:
        raise W5EvidenceError("blocked replay Continue hash drift")
    if _exact_int(replay.get("continue_calls"), "replay_evidence.continue_calls", minimum=0) != 2 or replay.get("first_runtime_hash") != runtime_hash or replay.get("second_runtime_hash") != runtime_hash:
        raise W5EvidenceError("blocked replay runtime/call drift")
    expected_counts = {
        "first_event_count": 14, "second_event_count": 14,
        "first_attempt_count": 1, "second_attempt_count": 1,
        "first_dispatch_count": 1, "second_dispatch_count": 1,
        "first_spawn_request_count": 0, "second_spawn_request_count": 0,
        "first_ack_count": 0, "second_ack_count": 0,
    }
    for field, expected in expected_counts.items():
        if _exact_int(replay.get(field), f"replay_evidence.{field}", minimum=0) != expected:
            raise W5EvidenceError(f"blocked replay count drift: {field}")
    if type(replay.get("no_duplicate_dispatch")) is not bool or type(replay.get("no_duplicate_spawn")) is not bool or not replay.get("no_duplicate_dispatch") or not replay.get("no_duplicate_spawn"):
        raise W5EvidenceError("blocked replay duplicate effect")
    return dict(replay)


def _verify_blocked_authority(
    authority: Any,
    *,
    info: Mapping[str, Any],
    policy: Mapping[str, Any],
    markers: Mapping[str, Mapping[str, Any]],
    witnesses: Mapping[str, Any],
    continue_intent: Mapping[str, Any],
    replay: Mapping[str, Any],
    blocked_ack: Mapping[str, Any],
    missing_evidence: Mapping[str, Any],
    source_attestation: Mapping[str, Any],
) -> None:
    authority = _mapping(authority, "authority")
    _required_keys(authority, BLOCKED_AUTHORITY_KEYS, "authority")
    if authority.get("schema") != BLOCKED_AUTHORITY_SCHEMA:
        raise W5EvidenceError("BLOCKED_AUTHORITY_SCHEMA_UNSUPPORTED")
    authority_id = _text(authority.get("authority_id"), "authority.authority_id")
    key_id = _text(authority.get("key_id"), "authority.key_id")
    trusted_key = resolve_trusted_authority(authority_id=authority_id, key_id=key_id)
    if (authority.get("run_id"), authority.get("card_id"), authority.get("attempt_id"), authority.get("dispatch_id"), authority.get("fencing_epoch")) != (info["run_id"], info["card_id"], info["attempt_id"], info["dispatch_id"], info["epoch"]):
        raise W5EvidenceError("blocked authority identity drift")
    core = {key: authority[key] for key in BLOCKED_AUTHORITY_KEYS if key not in {"authority_hash", "authority_mac"}}
    if authority.get("authority_hash") != canonical_hash(core):
        raise W5EvidenceError("BLOCKED_AUTHORITY_HASH_DRIFT")
    expected_mac = hmac.new(trusted_key, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(authority.get("authority_mac")), expected_mac):
        raise W5EvidenceError("BLOCKED_AUTHORITY_MAC_INVALID")
    runtime_hash = canonical_hash(info["runtime"])
    if authority.get("policy_hash") != canonical_hash(policy) or authority.get("runtime_hash") != runtime_hash or authority.get("source_attestation_hash") != canonical_hash(source_attestation) or authority.get("bundle_schema_hash") != canonical_hash(BLOCKED_BUNDLE_SCHEMA):
        raise W5EvidenceError("blocked authority policy/runtime/source drift")
    if authority.get("state_witness_hash") != canonical_hash(witnesses) or authority.get("event_chain_hash") != canonical_hash(info["events"]):
        raise W5EvidenceError("blocked authority witness/event drift")
    commitments = _mapping(authority.get("marker_commitments"), "authority.marker_commitments")
    if set(commitments) != set(markers) or any(commitments.get(operation) != marker.get("marker_hash") for operation, marker in markers.items()):
        raise W5EvidenceError("blocked authority marker drift")
    if authority.get("continue_hash") != canonical_hash(continue_intent) or authority.get("replay_hash") != canonical_hash(replay) or authority.get("blocked_ack_hash") != canonical_hash(blocked_ack) or authority.get("missing_evidence_hash") != canonical_hash(missing_evidence):
        raise W5EvidenceError("blocked authority external evidence drift")


def verify_blocked_ack_bundle_s1(
    bundle: Mapping[str, Any],
    *,
    authority: Mapping[str, Any] | None = None,
    source_root: str | Path | None = None,
) -> DispatchBridgeResult:
    """Verify one explicit pre-C4 ACK-wait observation."""

    try:
        bundle = _mapping(bundle, "bundle")
        _required_keys(bundle, BLOCKED_TOP_LEVEL_KEYS, "bundle")
        if bundle.get("schema") != BLOCKED_BUNDLE_SCHEMA:
            raise W5IncompatibleSource("BLOCKED_BUNDLE_SCHEMA_UNSUPPORTED")
        if dict(_mapping(bundle.get("source"), "source")) != SOURCE_CONTRACT:
            raise W5IncompatibleSource("INCOMPATIBLE_SOURCE")
        if authority is None:
            raise W5EvidenceError("AUTHORITY_REQUIRED")
        source_attestation = verify_source_attestation(bundle["source_attestation"], source_root=source_root)
        policy = _verify_blocked_policy(bundle["bridge_policy"])
        info = _verify_blocked_runtime(bundle["runtime"])
        event_info = _verify_blocked_events(info)
        markers = _verify_blocked_markers(info["runtime"], info, event_info)
        witnesses = _verify_blocked_witnesses(bundle["state_witnesses"], info, markers)
        continue_intent = _verify_blocked_continue(bundle["continue_intent"], info, markers)
        blocked_ack = _verify_blocked_observation(bundle["blocked_ack"], info, event_info)
        missing_evidence = _verify_missing_evidence(bundle["missing_evidence"])
        replay = _verify_blocked_replay(bundle["replay_evidence"], info, continue_intent, canonical_hash(info["runtime"]))
        _verify_blocked_authority(
            authority,
            info=info,
            policy=policy,
            markers=markers,
            witnesses=witnesses,
            continue_intent=continue_intent,
            replay=replay,
            blocked_ack=blocked_ack,
            missing_evidence=missing_evidence,
            source_attestation=source_attestation,
        )
        return DispatchBridgeResult(
            status="BLOCKED",
            findings=("ACK_NOT_CONFIRMED",),
            bridge={
                "run_id": info["run_id"],
                "card_id": info["card_id"],
                "attempt_id": info["attempt_id"],
                "dispatch_id": info["dispatch_id"],
                "state": {
                    "run": info["run"]["state"],
                    "card": info["card"]["state"],
                    "attempt": info["attempt"]["state"],
                    "dispatch": info["dispatch"]["state"],
                },
                "source_attestation_hash": canonical_hash(source_attestation),
            },
        )
    except W5IncompatibleSource as exc:
        return DispatchBridgeResult(status="INCOMPATIBLE_SOURCE", findings=(str(exc),))
    except (W5EvidenceError, W4EvidenceError, AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        return DispatchBridgeResult(status="INVALID_EVIDENCE", findings=(str(exc),))


verify_ack_wait_bundle_s1 = verify_blocked_ack_bundle_s1
