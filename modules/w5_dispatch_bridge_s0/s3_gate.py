"""Deterministic W5-S3 HOLD/RECONCILE/RESUME evidence gate.

The gate is deliberately a decision-only boundary.  It re-verifies the
source-attested W5-S1 bundle, checks the S2 observation against that result,
and compares the result with an independently captured control snapshot.
It never calls a controller, executor, lease operation or transport.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash

from .blocked import verify_blocked_ack_bundle_s1
from .mother_observation import (
    MotherObservationError,
    build_mother_observation,
    verify_mother_observation,
)
from .s1 import verify_dispatch_bridge_bundle_s1


HRR_INPUT_SCHEMA = "w5-hrr-input-v1"
HRR_DECISION_SCHEMA = "w5-hrr-decision-v1"
DECISIONS = frozenset({"HOLD", "RECONCILE", "RESUME"})
DECISION_REASONS = frozenset(
    {
        "INVALID_INPUT",
        "INCOMPATIBLE_SOURCE",
        "INVALID_EVIDENCE",
        "OBSERVATION_MISMATCH",
        "W5_RESULT_NOT_RESUMABLE",
        "OBSERVATION_CONTEXT_MISSING",
        "IDENTITY_DRIFT",
        "FENCE_DRIFT",
        "COMMAND_DRIFT",
        "QUEUE_DRIFT",
        "POLICY_DRIFT",
        "SPAWN_BUDGET_DRIFT",
        "ACCEPTANCE_LEAK",
        "CONTROL_DRIFT",
        "CONTROL_TIME_DRIFT",
        "LIVE_RUNTIME_DRIFT",
        "PROCESS_IDENTITY_DRIFT",
        "STALE_LEASE",
        "UNEXPECTED_CANDIDATE",
        "FOREIGN_IDENTITY",
        "LATE_ACK",
        "ACK_BEFORE_SPAWN",
        "OBSERVATION_FROM_FUTURE",
        "C4_VERIFIED",
        "IDENTITY_REQUIRES_RECONCILIATION",
        "ACK_NOT_CONFIRMED",
    }
)
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
BOUND_ID_FIELDS = ("run_id", "card_id", "attempt_id", "dispatch_id")
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_TEXT = 512

HRR_INPUT_KEYS = frozenset(
    {
        "schema_version",
        "now_epoch",
        "w5_bundle",
        "w5_authority",
        "w5_observation",
        "live_runtime",
        "control",
        "candidate_identity",
        "candidate_observed_epoch",
    }
)
CONTROL_KEYS = frozenset({"run", "card", "attempt", "dispatch", "lease", "runtime_hash"})
RUN_KEYS = frozenset(
    {"run_id", "state", "active_dispatch_id", "queue_hash", "policy_hash", "fencing_epoch", "lease_token"}
)
CARD_KEYS = frozenset(
    {
        "card_id",
        "run_id",
        "state",
        "active_attempt_id",
        "acceptance_txn_id",
        "next_card_intent_id",
        "card_hash",
        "source_queue_hash",
    }
)
ATTEMPT_KEYS = frozenset(
    {
        "attempt_id",
        "attempt_no",
        "retry_of",
        "run_id",
        "card_id",
        "state",
        "dispatch_id",
        "worker_id",
        "command_hash",
        "input_snapshot_hash",
        "context_pack_hash",
        "deadline_policy_hash",
    }
)
DISPATCH_KEYS = frozenset(
    {
        "dispatch_id",
        "run_id",
        "attempt_id",
        "state",
        "run_token",
        "owner_id",
        "fencing_epoch",
        "command_hash",
        "ack_deadline_at",
        "lease_expires_at",
        "spawn_requested_at_epoch",
        "spawn_attempt_no",
        "max_spawn_attempts",
        "process_identity",
    }
)
LEASE_KEYS = frozenset({"owner_id", "token", "fencing_epoch", "expires_at"})
DECISION_KEYS = frozenset(
    {
        "schema_version",
        "decision",
        "reason",
        "identity",
        "state",
        "fencing_epoch",
        "source_attestation_hash",
        "control_snapshot_sha256",
        "permission",
        "external_action",
        "execution",
    }
)
STATE_KEYS = frozenset({"run", "card", "attempt", "dispatch"})
OUTPUT_EXECUTION_KEYS = frozenset(
    {"mutation", "spawn", "lease_reclaim", "acceptance", "next_card", "network"}
)
FALSE_EXECUTION = {key: False for key in sorted(OUTPUT_EXECUTION_KEYS)}


class HrrGateError(ValueError):
    """The HRR input is malformed and cannot be considered evidence."""


class _GateReject(HrrGateError):
    """A structurally valid input contradicts a safety binding."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HrrGateError(f"{label}: object required")
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    keys = set(value)
    if any(not isinstance(key, str) for key in keys):
        raise HrrGateError(f"{label}: field names must be strings")
    missing = expected - keys
    extra = keys - expected
    if missing or extra:
        raise HrrGateError(
            f"{label}: schema drift; missing={sorted(missing)} extra={sorted(extra)}"
        )


def _text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_TEXT
        or any(ord(char) < 32 for char in value)
    ):
        raise HrrGateError(f"{label}: non-empty text required")
    return value


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise HrrGateError(f"{label}: integer >= {minimum} required")
    return value


def _sha256(value: Any, label: str) -> str:
    value = _text(value, label)
    if SHA256_HEX.fullmatch(value) is None:
        raise HrrGateError(f"{label}: lowercase SHA256 required")
    return value


def _timestamp_epoch(value: Any, label: str) -> int:
    value = _text(value, label)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HrrGateError(f"{label}: ISO timestamp required") from exc
    if parsed.tzinfo is None:
        raise HrrGateError(f"{label}: timezone required")
    return int(parsed.astimezone(timezone.utc).timestamp())


def _identity(value: Any, label: str) -> dict[str, Any]:
    value = _mapping(value, label)
    _exact_keys(value, frozenset(IDENTITY_FIELDS), label)
    return {
        "pid": _integer(value["pid"], f"{label}.pid", minimum=1),
        "process_starttime": _text(value["process_starttime"], f"{label}.process_starttime"),
        "boot_id": _text(value["boot_id"], f"{label}.boot_id"),
        "pidfd_ref": _text(value["pidfd_ref"], f"{label}.pidfd_ref"),
        "cgroup_ref": _text(value["cgroup_ref"], f"{label}.cgroup_ref"),
        "run_token": _text(value["run_token"], f"{label}.run_token"),
        "fencing_epoch": _integer(value["fencing_epoch"], f"{label}.fencing_epoch", minimum=1),
        "command_hash": _text(value["command_hash"], f"{label}.command_hash"),
    }


def _optional_identity(value: Any, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    return _identity(value, label)


def _validate_control(value: Any) -> dict[str, Any]:
    value = _mapping(value, "control")
    _exact_keys(value, CONTROL_KEYS, "control")

    run = _mapping(value["run"], "control.run")
    _exact_keys(run, RUN_KEYS, "control.run")
    run_copy = {
        "run_id": _text(run["run_id"], "control.run.run_id"),
        "state": _text(run["state"], "control.run.state"),
        "active_dispatch_id": _text(run["active_dispatch_id"], "control.run.active_dispatch_id"),
        "queue_hash": _text(run["queue_hash"], "control.run.queue_hash"),
        "policy_hash": _text(run["policy_hash"], "control.run.policy_hash"),
        "fencing_epoch": _integer(run["fencing_epoch"], "control.run.fencing_epoch", minimum=1),
        "lease_token": _text(run["lease_token"], "control.run.lease_token"),
    }

    card = _mapping(value["card"], "control.card")
    _exact_keys(card, CARD_KEYS, "control.card")
    card_copy = {
        "card_id": _text(card["card_id"], "control.card.card_id"),
        "run_id": _text(card["run_id"], "control.card.run_id"),
        "state": _text(card["state"], "control.card.state"),
        "active_attempt_id": _text(card["active_attempt_id"], "control.card.active_attempt_id"),
        "acceptance_txn_id": _optional_text(card["acceptance_txn_id"], "control.card.acceptance_txn_id"),
        "next_card_intent_id": _optional_text(card["next_card_intent_id"], "control.card.next_card_intent_id"),
        "card_hash": _text(card["card_hash"], "control.card.card_hash"),
        "source_queue_hash": _text(card["source_queue_hash"], "control.card.source_queue_hash"),
    }

    attempt = _mapping(value["attempt"], "control.attempt")
    _exact_keys(attempt, ATTEMPT_KEYS, "control.attempt")
    attempt_copy = {
        "attempt_id": _text(attempt["attempt_id"], "control.attempt.attempt_id"),
        "attempt_no": _integer(attempt["attempt_no"], "control.attempt.attempt_no", minimum=1),
        "retry_of": _optional_text(attempt["retry_of"], "control.attempt.retry_of"),
        "run_id": _text(attempt["run_id"], "control.attempt.run_id"),
        "card_id": _text(attempt["card_id"], "control.attempt.card_id"),
        "state": _text(attempt["state"], "control.attempt.state"),
        "dispatch_id": _text(attempt["dispatch_id"], "control.attempt.dispatch_id"),
        "worker_id": _optional_text(attempt["worker_id"], "control.attempt.worker_id"),
        "command_hash": _text(attempt["command_hash"], "control.attempt.command_hash"),
        "input_snapshot_hash": _text(attempt["input_snapshot_hash"], "control.attempt.input_snapshot_hash"),
        "context_pack_hash": _text(attempt["context_pack_hash"], "control.attempt.context_pack_hash"),
        "deadline_policy_hash": _text(attempt["deadline_policy_hash"], "control.attempt.deadline_policy_hash"),
    }

    dispatch = _mapping(value["dispatch"], "control.dispatch")
    _exact_keys(dispatch, DISPATCH_KEYS, "control.dispatch")
    dispatch_copy = {
        "dispatch_id": _text(dispatch["dispatch_id"], "control.dispatch.dispatch_id"),
        "run_id": _text(dispatch["run_id"], "control.dispatch.run_id"),
        "attempt_id": _text(dispatch["attempt_id"], "control.dispatch.attempt_id"),
        "state": _text(dispatch["state"], "control.dispatch.state"),
        "run_token": _text(dispatch["run_token"], "control.dispatch.run_token"),
        "owner_id": _text(dispatch["owner_id"], "control.dispatch.owner_id"),
        "fencing_epoch": _integer(dispatch["fencing_epoch"], "control.dispatch.fencing_epoch", minimum=1),
        "command_hash": _text(dispatch["command_hash"], "control.dispatch.command_hash"),
        "ack_deadline_at": _integer(dispatch["ack_deadline_at"], "control.dispatch.ack_deadline_at", minimum=1),
        "lease_expires_at": _integer(dispatch["lease_expires_at"], "control.dispatch.lease_expires_at", minimum=1),
        "spawn_requested_at_epoch": _integer(
            dispatch["spawn_requested_at_epoch"],
            "control.dispatch.spawn_requested_at_epoch",
            minimum=0,
        ),
        "spawn_attempt_no": _integer(dispatch["spawn_attempt_no"], "control.dispatch.spawn_attempt_no", minimum=0),
        "max_spawn_attempts": _integer(dispatch["max_spawn_attempts"], "control.dispatch.max_spawn_attempts", minimum=1),
        "process_identity": _optional_identity(dispatch["process_identity"], "control.dispatch.process_identity"),
    }

    lease = _mapping(value["lease"], "control.lease")
    _exact_keys(lease, LEASE_KEYS, "control.lease")
    lease_copy = {
        "owner_id": _text(lease["owner_id"], "control.lease.owner_id"),
        "token": _text(lease["token"], "control.lease.token"),
        "fencing_epoch": _integer(lease["fencing_epoch"], "control.lease.fencing_epoch", minimum=1),
        "expires_at": _integer(lease["expires_at"], "control.lease.expires_at", minimum=1),
    }
    return {
        "run": run_copy,
        "card": card_copy,
        "attempt": attempt_copy,
        "dispatch": dispatch_copy,
        "lease": lease_copy,
        "runtime_hash": _sha256(value["runtime_hash"], "control.runtime_hash"),
    }


def _validate_candidate(value: Any, observed: Any) -> tuple[dict[str, Any] | None, int | None]:
    if value is None:
        if observed is not None:
            raise HrrGateError("candidate_observed_epoch requires candidate_identity")
        return None, None
    candidate = _identity(value, "candidate_identity")
    if observed is None:
        raise HrrGateError("candidate_identity requires candidate_observed_epoch")
    return candidate, _integer(observed, "candidate_observed_epoch", minimum=0)


def _validated_input(value: Any) -> dict[str, Any]:
    value = _mapping(value, "hrr_input")
    _exact_keys(value, HRR_INPUT_KEYS, "hrr_input")
    if value["schema_version"] != HRR_INPUT_SCHEMA:
        raise HrrGateError("hrr_input.schema_version unsupported")
    now_epoch = _integer(value["now_epoch"], "hrr_input.now_epoch", minimum=0)
    control = _validate_control(value["control"])
    candidate, observed = _validate_candidate(
        value["candidate_identity"], value["candidate_observed_epoch"]
    )
    return {
        "now_epoch": now_epoch,
        "w5_bundle": _mapping(value["w5_bundle"], "hrr_input.w5_bundle"),
        "w5_authority": _mapping(value["w5_authority"], "hrr_input.w5_authority"),
        "w5_observation": _mapping(value["w5_observation"], "hrr_input.w5_observation"),
        "live_runtime": _mapping(value["live_runtime"], "hrr_input.live_runtime"),
        "control": control,
        "candidate_identity": candidate,
        "candidate_observed_epoch": observed,
    }


def _decision(
    *,
    decision: str,
    reason: str,
    identity: Mapping[str, Any] | None = None,
    state: Mapping[str, Any] | None = None,
    fencing_epoch: int | None = None,
    source_attestation_hash: str | None = None,
    control_snapshot_sha256: str | None = None,
) -> dict[str, Any]:
    if decision not in DECISIONS:
        raise ValueError(f"unsupported decision: {decision}")
    return {
        "schema_version": HRR_DECISION_SCHEMA,
        "decision": decision,
        "reason": reason,
        "identity": dict(identity) if identity is not None else None,
        "state": dict(state) if state is not None else None,
        "fencing_epoch": fencing_epoch,
        "source_attestation_hash": source_attestation_hash,
        "control_snapshot_sha256": control_snapshot_sha256,
        "permission": "read_only",
        "external_action": False,
        "execution": dict(FALSE_EXECUTION),
    }


def _control_hash(control: Mapping[str, Any]) -> str:
    return canonical_hash(control)


def _verify_w5(bundle: Mapping[str, Any], authority: Mapping[str, Any], *, source_root: str | Path | None):
    schema = bundle.get("schema")
    if schema == "w5-dispatch-bridge-bundle.v2-source-attested":
        return verify_dispatch_bridge_bundle_s1(
            bundle, authority=authority, source_root=source_root
        )
    if schema == "w5-blocked-ack-bundle.v1":
        return verify_blocked_ack_bundle_s1(
            bundle, authority=authority, source_root=source_root
        )
    return None


def _raw_runtime(bundle: Mapping[str, Any]) -> Mapping[str, Any]:
    if "runtime" in bundle:
        runtime = _mapping(bundle.get("runtime"), "w5_bundle.runtime")
    else:
        runtime = _mapping(bundle, "live_runtime")
    for key in ("run", "cards", "attempts", "dispatches"):
        if key not in runtime:
            raise _GateReject("CONTROL_SNAPSHOT_DRIFT")
    if not isinstance(runtime["cards"], list) or len(runtime["cards"]) != 1:
        raise _GateReject("CONTROL_SNAPSHOT_DRIFT")
    if not isinstance(runtime["attempts"], list) or len(runtime["attempts"]) != 1:
        raise _GateReject("CONTROL_SNAPSHOT_DRIFT")
    if not isinstance(runtime["dispatches"], list) or len(runtime["dispatches"]) != 1:
        raise _GateReject("CONTROL_SNAPSHOT_DRIFT")
    return runtime


def _assert_bindings(
    *,
    result: Any,
    observation: Mapping[str, Any],
    bundle: Mapping[str, Any],
    live_runtime: Mapping[str, Any],
    control: Mapping[str, Any],
) -> None:
    if result.status not in {"BRIDGE_VERIFIED", "BLOCKED"}:
        raise _GateReject("W5_RESULT_NOT_RESUMABLE")
    identity = observation.get("identity")
    state = observation.get("state")
    if not isinstance(identity, Mapping) or not isinstance(state, Mapping):
        raise _GateReject("OBSERVATION_CONTEXT_MISSING")
    run = control["run"]
    card = control["card"]
    attempt = control["attempt"]
    dispatch = control["dispatch"]
    lease = control["lease"]
    for key, owner in (
        ("run_id", run),
        ("card_id", card),
        ("attempt_id", attempt),
        ("dispatch_id", dispatch),
    ):
        if identity[key] != owner[key]:
            raise _GateReject("IDENTITY_DRIFT")
    if run["active_dispatch_id"] != dispatch["dispatch_id"]:
        raise _GateReject("IDENTITY_DRIFT")
    if card["run_id"] != run["run_id"] or card["active_attempt_id"] != attempt["attempt_id"]:
        raise _GateReject("IDENTITY_DRIFT")
    if attempt["run_id"] != run["run_id"] or attempt["card_id"] != card["card_id"]:
        raise _GateReject("IDENTITY_DRIFT")
    if attempt["dispatch_id"] != dispatch["dispatch_id"]:
        raise _GateReject("IDENTITY_DRIFT")
    if dispatch["run_id"] != run["run_id"] or dispatch["attempt_id"] != attempt["attempt_id"]:
        raise _GateReject("IDENTITY_DRIFT")
    if (
        run["fencing_epoch"] != dispatch["fencing_epoch"]
        or dispatch["fencing_epoch"] != lease["fencing_epoch"]
        or run["lease_token"] != lease["token"]
        or lease["owner_id"] != dispatch["owner_id"]
        or dispatch["ack_deadline_at"] != dispatch["lease_expires_at"]
        or dispatch["lease_expires_at"] != lease["expires_at"]
    ):
        raise _GateReject("FENCE_DRIFT")
    if lease["token"] != f"lease:{run['run_id']}:epoch:{lease['fencing_epoch']}":
        raise _GateReject("FENCE_DRIFT")
    if dispatch["run_token"] != f"run-token:{run['run_id']}:{attempt['attempt_id']}":
        raise _GateReject("FENCE_DRIFT")
    if attempt["command_hash"] != dispatch["command_hash"]:
        raise _GateReject("COMMAND_DRIFT")
    if run["queue_hash"] != card["source_queue_hash"]:
        raise _GateReject("QUEUE_DRIFT")
    if attempt["deadline_policy_hash"] != run["policy_hash"]:
        raise _GateReject("POLICY_DRIFT")
    if dispatch["spawn_attempt_no"] != 1 or dispatch["max_spawn_attempts"] != 1:
        raise _GateReject("SPAWN_BUDGET_DRIFT")
    if card["acceptance_txn_id"] is not None or card["next_card_intent_id"] is not None:
        raise _GateReject("ACCEPTANCE_LEAK")

    expected_state = {key: state[key] for key in STATE_KEYS}
    actual_state = {
        "run": run["state"],
        "card": card["state"],
        "attempt": attempt["state"],
        "dispatch": dispatch["state"],
    }
    if actual_state != expected_state:
        raise _GateReject("CONTROL_DRIFT")

    runtime = _raw_runtime(bundle)
    live = _raw_runtime(live_runtime)
    if canonical_hash(live) != canonical_hash(runtime):
        raise _GateReject("LIVE_RUNTIME_DRIFT")
    if control["runtime_hash"] != canonical_hash(live):
        raise _GateReject("LIVE_RUNTIME_DRIFT")
    events = live.get("events")
    if not isinstance(events, list):
        raise _GateReject("CONTROL_TIME_DRIFT")
    spawn_events = [event for event in events if isinstance(event, Mapping) and event.get("event_type") == "SPAWN_REQUESTED"]
    if len(spawn_events) != 1:
        raise _GateReject("CONTROL_TIME_DRIFT")
    spawn_event = _mapping(spawn_events[0], "live_runtime.spawn_event")
    if spawn_event.get("run_id") != run["run_id"]:
        raise _GateReject("CONTROL_TIME_DRIFT")
    try:
        spawn_epoch = _timestamp_epoch(
            spawn_event.get("created_at"), "live_runtime.spawn_event.created_at"
        )
    except HrrGateError as exc:
        raise _GateReject("CONTROL_TIME_DRIFT") from exc
    if dispatch["spawn_requested_at_epoch"] != spawn_epoch:
        raise _GateReject("CONTROL_TIME_DRIFT")
    raw_run = _mapping(live["run"], "live_runtime.run")
    raw_card = _mapping(live["cards"][0], "live_runtime.card")
    raw_attempt = _mapping(live["attempts"][0], "live_runtime.attempt")
    raw_dispatch = _mapping(live["dispatches"][0], "live_runtime.dispatch")
    comparisons = (
        (run["run_id"], raw_run.get("run_id")),
        (run["state"], raw_run.get("state")),
        (run["active_dispatch_id"], raw_run.get("active_dispatch_id")),
        (run["queue_hash"], raw_run.get("queue_hash")),
        (run["policy_hash"], raw_run.get("policy_hash")),
        (run["fencing_epoch"], raw_run.get("fencing_epoch")),
        (run["lease_token"], raw_run.get("lease_token")),
        (card["card_id"], raw_card.get("card_id")),
        (card["run_id"], raw_card.get("run_id")),
        (card["state"], raw_card.get("state")),
        (card["card_hash"], raw_card.get("card_hash")),
        (card["source_queue_hash"], raw_card.get("source_queue_hash")),
        (attempt["attempt_id"], raw_attempt.get("attempt_id")),
        (attempt["attempt_no"], raw_attempt.get("attempt_no")),
        (attempt["run_id"], raw_attempt.get("run_id")),
        (attempt["card_id"], raw_attempt.get("card_id")),
        (attempt["state"], raw_attempt.get("state")),
        (attempt["dispatch_id"], raw_attempt.get("dispatch_id")),
        (attempt["worker_id"], raw_attempt.get("worker_id")),
        (attempt["command_hash"], raw_attempt.get("command_hash")),
        (attempt["input_snapshot_hash"], raw_attempt.get("input_snapshot_hash")),
        (attempt["context_pack_hash"], raw_attempt.get("context_pack_hash")),
        (attempt["deadline_policy_hash"], raw_attempt.get("deadline_policy_hash")),
        (dispatch["dispatch_id"], raw_dispatch.get("dispatch_id")),
        (dispatch["run_id"], raw_dispatch.get("run_id")),
        (dispatch["attempt_id"], raw_dispatch.get("attempt_id")),
        (dispatch["state"], raw_dispatch.get("state")),
        (dispatch["run_token"], raw_dispatch.get("run_token")),
        (dispatch["owner_id"], raw_dispatch.get("owner_id")),
        (dispatch["fencing_epoch"], raw_dispatch.get("fencing_epoch")),
        (dispatch["command_hash"], raw_dispatch.get("command_hash")),
        (dispatch["ack_deadline_at"], raw_dispatch.get("ack_deadline_at")),
        (dispatch["lease_expires_at"], raw_dispatch.get("lease_expires_at")),
        (dispatch["spawn_attempt_no"], raw_dispatch.get("spawn_attempt_no")),
        (dispatch["max_spawn_attempts"], raw_dispatch.get("max_spawn_attempts")),
    )
    if any(actual != expected for actual, expected in comparisons):
        raise _GateReject("LIVE_RUNTIME_DRIFT")

    raw_identity = None
    raw_identity_fields = ("pid", "process_starttime", "boot_id", "pidfd_ref", "cgroup_ref")
    if any(raw_dispatch.get(field) is not None for field in raw_identity_fields):
        raw_identity = {
            "pid": raw_dispatch.get("pid"),
            "process_starttime": raw_dispatch.get("process_starttime"),
            "boot_id": raw_dispatch.get("boot_id"),
            "pidfd_ref": raw_dispatch.get("pidfd_ref"),
            "cgroup_ref": raw_dispatch.get("cgroup_ref"),
            "run_token": raw_dispatch.get("run_token"),
            "fencing_epoch": raw_dispatch.get("fencing_epoch"),
            "command_hash": raw_dispatch.get("command_hash"),
        }
        if any(raw_identity[field] is None for field in raw_identity_fields):
            raise _GateReject("PROCESS_IDENTITY_DRIFT")
        raw_identity = _identity(raw_identity, "w5_bundle.runtime.dispatch.process_identity")
    if dispatch["process_identity"] != raw_identity:
        raise _GateReject("PROCESS_IDENTITY_DRIFT")
    if result.status == "BRIDGE_VERIFIED":
        if attempt["worker_id"] is None or raw_identity is None:
            raise _GateReject("PROCESS_IDENTITY_DRIFT")
    else:
        if attempt["worker_id"] is not None or raw_identity is not None:
            raise _GateReject("PROCESS_IDENTITY_DRIFT")


def evaluate_hrr(
    value: Mapping[str, Any],
    *,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Evaluate one immutable W5-S3 input and return a decision-only result.

    ``RESUME`` means only that the evidence is sufficient for a later,
    separately implemented resume action.  All returned execution flags are
    false, including for ``RESUME``.
    """

    control_hash: str | None = None
    control: Mapping[str, Any] | None = None
    try:
        item = _validated_input(value)
        control = item["control"]
        control_hash = _control_hash(control)
    except HrrGateError:
        return _decision(decision="HOLD", reason="INVALID_INPUT")

    try:
        result = _verify_w5(
            item["w5_bundle"], item["w5_authority"], source_root=source_root
        )
        if result is None:
            return _decision(
                decision="HOLD",
                reason="INCOMPATIBLE_SOURCE",
                control_snapshot_sha256=control_hash,
            )
        expected_observation = build_mother_observation(result)
        supplied_observation = verify_mother_observation(item["w5_observation"])
        if supplied_observation != expected_observation:
            return _decision(
                decision="HOLD",
                reason="OBSERVATION_MISMATCH",
                control_snapshot_sha256=control_hash,
            )
    except (
        MotherObservationError,
        HrrGateError,
        AttributeError,
        IndexError,
        KeyError,
        TypeError,
        ValueError,
        OSError,
    ):
        return _decision(
            decision="HOLD",
            reason="INVALID_EVIDENCE",
            control_snapshot_sha256=control_hash,
        )

    if result.status == "INCOMPATIBLE_SOURCE":
        return _decision(
            decision="HOLD",
            reason="INCOMPATIBLE_SOURCE",
            control_snapshot_sha256=control_hash,
        )
    if result.status == "INVALID_EVIDENCE":
        return _decision(
            decision="HOLD",
            reason="INVALID_EVIDENCE",
            control_snapshot_sha256=control_hash,
        )

    try:
        _assert_bindings(
            result=result,
            observation=expected_observation,
            bundle=item["w5_bundle"],
            live_runtime=item["live_runtime"],
            control=control,
        )
    except _GateReject as exc:
        return _decision(
            decision="HOLD",
            reason=exc.reason,
            identity=expected_observation.get("identity"),
            state=expected_observation.get("state"),
            fencing_epoch=control["run"]["fencing_epoch"],
            source_attestation_hash=expected_observation.get("source_attestation_hash"),
            control_snapshot_sha256=control_hash,
        )
    except HrrGateError:
        return _decision(
            decision="HOLD",
            reason="LIVE_RUNTIME_DRIFT",
            identity=expected_observation.get("identity"),
            state=expected_observation.get("state"),
            fencing_epoch=control["run"]["fencing_epoch"],
            source_attestation_hash=expected_observation.get("source_attestation_hash"),
            control_snapshot_sha256=control_hash,
        )

    identity = expected_observation["identity"]
    state = expected_observation["state"]
    fencing_epoch = control["run"]["fencing_epoch"]
    source_hash = expected_observation["source_attestation_hash"]
    now_epoch = item["now_epoch"]
    deadline = control["dispatch"]["ack_deadline_at"]
    if result.status == "BRIDGE_VERIFIED":
        if item["candidate_identity"] is not None:
            return _decision(
                decision="HOLD",
                reason="UNEXPECTED_CANDIDATE",
                identity=identity,
                state=state,
                fencing_epoch=fencing_epoch,
                source_attestation_hash=source_hash,
                control_snapshot_sha256=control_hash,
            )
        if control["lease"]["expires_at"] <= now_epoch:
            return _decision(
                decision="HOLD",
                reason="STALE_LEASE",
                identity=identity,
                state=state,
                fencing_epoch=fencing_epoch,
                source_attestation_hash=source_hash,
                control_snapshot_sha256=control_hash,
            )
        return _decision(
            decision="RESUME",
            reason="C4_VERIFIED",
            identity=identity,
            state=state,
            fencing_epoch=fencing_epoch,
            source_attestation_hash=source_hash,
            control_snapshot_sha256=control_hash,
        )

    candidate = item["candidate_identity"]
    observed = item["candidate_observed_epoch"]
    if candidate is not None:
        expected = control["dispatch"]["process_identity"]
        if (
            candidate["run_token"] != control["dispatch"]["run_token"]
            or candidate["fencing_epoch"] != control["dispatch"]["fencing_epoch"]
            or candidate["command_hash"] != control["dispatch"]["command_hash"]
        ):
            return _decision(
                decision="HOLD",
                reason="FOREIGN_IDENTITY",
                identity=identity,
                state=state,
                fencing_epoch=fencing_epoch,
                source_attestation_hash=source_hash,
                control_snapshot_sha256=control_hash,
            )
        if observed is None or observed >= deadline:
            return _decision(
                decision="HOLD",
                reason="LATE_ACK",
                identity=identity,
                state=state,
                fencing_epoch=fencing_epoch,
                source_attestation_hash=source_hash,
                control_snapshot_sha256=control_hash,
            )
        if observed > now_epoch:
            return _decision(
                decision="HOLD",
                reason="OBSERVATION_FROM_FUTURE",
                identity=identity,
                state=state,
                fencing_epoch=fencing_epoch,
                source_attestation_hash=source_hash,
                control_snapshot_sha256=control_hash,
            )
        if observed <= control["dispatch"]["spawn_requested_at_epoch"]:
            return _decision(
                decision="HOLD",
                reason="ACK_BEFORE_SPAWN",
                identity=identity,
                state=state,
                fencing_epoch=fencing_epoch,
                source_attestation_hash=source_hash,
                control_snapshot_sha256=control_hash,
            )
        if control["lease"]["expires_at"] <= now_epoch:
            return _decision(
                decision="HOLD",
                reason="STALE_LEASE",
                identity=identity,
                state=state,
                fencing_epoch=fencing_epoch,
                source_attestation_hash=source_hash,
                control_snapshot_sha256=control_hash,
            )
        if expected is not None:
            return _decision(
                decision="HOLD",
                reason="CONTROL_DRIFT",
                identity=identity,
                state=state,
                fencing_epoch=fencing_epoch,
                source_attestation_hash=source_hash,
                control_snapshot_sha256=control_hash,
            )
        return _decision(
            decision="RECONCILE",
            reason="IDENTITY_REQUIRES_RECONCILIATION",
            identity=identity,
            state=state,
            fencing_epoch=fencing_epoch,
            source_attestation_hash=source_hash,
            control_snapshot_sha256=control_hash,
        )

    if now_epoch >= deadline:
        return _decision(
            decision="HOLD",
            reason="STALE_LEASE",
            identity=identity,
            state=state,
            fencing_epoch=fencing_epoch,
            source_attestation_hash=source_hash,
            control_snapshot_sha256=control_hash,
        )
    return _decision(
        decision="HOLD",
        reason="ACK_NOT_CONFIRMED",
        identity=identity,
        state=state,
        fencing_epoch=fencing_epoch,
        source_attestation_hash=source_hash,
        control_snapshot_sha256=control_hash,
    )


def verify_hrr_decision(
    value: Mapping[str, Any],
    *,
    input_value: Mapping[str, Any] | None = None,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Validate output shape, optionally by recomputing the concrete input.

    Without ``input_value`` this remains a shape/semantic check only and is
    never an authority token.  A future adapter must pass the freshly read
    input so the decision is recomputed rather than trusted from storage.
    """

    value = _mapping(value, "hrr_decision")
    _exact_keys(value, DECISION_KEYS, "hrr_decision")
    if value["schema_version"] != HRR_DECISION_SCHEMA or value["decision"] not in DECISIONS:
        raise HrrGateError("hrr_decision schema or decision unsupported")
    reason = _text(value["reason"], "hrr_decision.reason")
    if reason not in DECISION_REASONS:
        raise HrrGateError("hrr_decision.reason unsupported")
    identity_value = value["identity"]
    state_value = value["state"]
    if value["identity"] is not None:
        identity = _mapping(value["identity"], "hrr_decision.identity")
        if set(identity) != set(BOUND_ID_FIELDS):
            raise HrrGateError("hrr_decision.identity must contain only bound IDs")
        for key in BOUND_ID_FIELDS:
            _text(identity[key], f"hrr_decision.identity.{key}")
    if value["state"] is not None:
        state = _mapping(value["state"], "hrr_decision.state")
        _exact_keys(state, STATE_KEYS, "hrr_decision.state")
        for key in STATE_KEYS:
            _text(state[key], f"hrr_decision.state.{key}")
    epoch = value["fencing_epoch"]
    if epoch is not None:
        _integer(epoch, "hrr_decision.fencing_epoch", minimum=1)
    source = value["source_attestation_hash"]
    if source is not None:
        _sha256(source, "hrr_decision.source_attestation_hash")
    control_hash = value["control_snapshot_sha256"]
    if control_hash is not None:
        _sha256(control_hash, "hrr_decision.control_snapshot_sha256")
    if value["permission"] != "read_only" or value["external_action"] is not False:
        raise HrrGateError("hrr_decision is not read-only")
    execution = _mapping(value["execution"], "hrr_decision.execution")
    _exact_keys(execution, OUTPUT_EXECUTION_KEYS, "hrr_decision.execution")
    if any(type(execution[key]) is not bool or execution[key] is not False for key in OUTPUT_EXECUTION_KEYS):
        raise HrrGateError("hrr_decision execution flags must all be false")
    if value["decision"] == "RESUME":
        if (
            reason != "C4_VERIFIED"
            or identity_value is None
            or state_value is None
            or epoch is None
            or source is None
            or control_hash is None
            or dict(state_value) != {
                "run": "DISPATCHING",
                "card": "CLAIMED",
                "attempt": "STARTING",
                "dispatch": "EXECUTOR_ACKED",
            }
        ):
            raise HrrGateError("RESUME decision lacks the C4 evidence boundary")
    if value["decision"] == "RECONCILE":
        if (
            reason != "IDENTITY_REQUIRES_RECONCILIATION"
            or identity_value is None
            or state_value is None
            or epoch is None
            or source is None
            or control_hash is None
            or dict(state_value) != {
                "run": "DISPATCHING",
                "card": "CLAIMED",
                "attempt": "ADMITTED",
                "dispatch": "SPAWN_REQUESTED",
            }
        ):
            raise HrrGateError("RECONCILE decision lacks the pre-C4 evidence boundary")
    normalized = {
        "schema_version": HRR_DECISION_SCHEMA,
        "decision": value["decision"],
        "reason": reason,
        "identity": dict(value["identity"]) if value["identity"] is not None else None,
        "state": dict(value["state"]) if value["state"] is not None else None,
        "fencing_epoch": epoch,
        "source_attestation_hash": source,
        "control_snapshot_sha256": control_hash,
        "permission": "read_only",
        "external_action": False,
        "execution": dict(FALSE_EXECUTION),
    }
    if input_value is not None:
        expected = evaluate_hrr(input_value, source_root=source_root)
        if expected != normalized:
            raise HrrGateError("hrr_decision does not match freshly evaluated input")
    return normalized


__all__ = [
    "DECISIONS",
    "HRR_DECISION_SCHEMA",
    "HRR_INPUT_SCHEMA",
    "HrrGateError",
    "evaluate_hrr",
    "verify_hrr_decision",
]
