"""Read-only W4-S0 verifier for one bounded Prime card.

The verifier consumes a sealed bundle assembled by an adapter. It does not
open a database, read a run directory, invoke a process, or write a receipt.
W2.5 remains the runtime authority; W4-S0 only reconstructs and binds its
evidence before preparing an external review request.
"""

from __future__ import annotations

import json
import hashlib
import hmac
from typing import Any, Mapping

from .authority import resolve_trusted_authority
from .models import VerificationResult, W4EvidenceError, W4IncompatibleSource
from .review_prep import prepare_review
from .tool_circuit import verify_tool_trace
from .w25_compat import (
    _exact_int,
    _hash64,
    _mapping,
    _opaque,
    _string_list,
    _text,
    canonical_attempt_state_hash,
    canonical_hash,
    canonical_json,
    verify_artifact_evidence,
    verify_receipt_pair,
)


BUNDLE_SCHEMA = "w4-small-loop-bundle.v1"
SOURCE_CONTRACT = {
    "kind": "w25-s0",
    "version": "w25-s0",
    "canonicalization": "json-sortkeys-v1",
}
POLICY_SCHEMA = "w4-loop-policy.v1"
AUTHORITY_SCHEMA = "w4-w25-authority.v1"
REQUIRED_BUNDLE_KEYS = {
    "schema",
    "source",
    "runtime",
    "evidence",
    "loop_policy",
    "tool_trace",
    "review_request",
}


def _required_keys(value: Mapping[str, Any], required: set[str], label: str) -> None:
    missing = required - set(value)
    extra = set(value) - required
    if missing:
        raise W4EvidenceError(f"{label}: missing {sorted(missing)}")
    if extra:
        raise W4EvidenceError(f"{label}: unknown fields {sorted(extra)}")


def _run_budget(run: Mapping[str, Any]) -> Mapping[str, Any]:
    value = run.get("budget")
    if value is None:
        value = run.get("budget_json")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise W4EvidenceError("run budget JSON invalid") from exc
    return _mapping(value, "run.budget")


def _verify_loop_policy(policy: Mapping[str, Any], run: Mapping[str, Any]) -> dict[str, Any]:
    policy = _mapping(policy, "loop_policy")
    required = {
        "schema",
        "admission_budget",
        "max_turns",
        "max_tool_calls",
        "no_progress_limit",
        "same_failure_limit",
        "consecutive_failure_limit",
        "allowed_tools",
        "budget_epoch",
        "budget_hash",
    }
    _required_keys(policy, required, "loop_policy")
    if policy["schema"] != POLICY_SCHEMA:
        raise W4EvidenceError("LOOP_POLICY_SCHEMA_UNSUPPORTED")
    admission_budget = _mapping(policy["admission_budget"], "loop_policy.admission_budget")
    if canonical_json(admission_budget) != canonical_json(_run_budget(run)):
        raise W4EvidenceError("BUDGET_ADMISSION_DRIFT")
    max_turns = _exact_int(policy["max_turns"], "loop_policy.max_turns", minimum=1)
    max_tool_calls = _exact_int(policy["max_tool_calls"], "loop_policy.max_tool_calls", minimum=0)
    no_progress_limit = _exact_int(policy["no_progress_limit"], "loop_policy.no_progress_limit", minimum=1)
    same_failure_limit = _exact_int(policy["same_failure_limit"], "loop_policy.same_failure_limit", minimum=1)
    consecutive_failure_limit = _exact_int(policy["consecutive_failure_limit"], "loop_policy.consecutive_failure_limit", minimum=1)
    if max_turns > 20 or max_tool_calls > 256 or no_progress_limit > 10:
        raise W4EvidenceError("loop policy exceeds W4 bounds")
    if same_failure_limit != 2 or consecutive_failure_limit != 6:
        raise W4EvidenceError("W4 failure thresholds are fixed")
    allowed_tools = _string_list(policy["allowed_tools"], "loop_policy.allowed_tools")
    if not 1 <= len(allowed_tools) <= 64 or len(set(allowed_tools)) != len(allowed_tools):
        raise W4EvidenceError("loop_policy.allowed_tools invalid")
    budget_epoch = _text(policy["budget_epoch"], "loop_policy.budget_epoch")
    core = {
        "admission_budget": dict(admission_budget),
        "max_turns": max_turns,
        "max_tool_calls": max_tool_calls,
        "no_progress_limit": no_progress_limit,
        "same_failure_limit": same_failure_limit,
        "consecutive_failure_limit": consecutive_failure_limit,
        "allowed_tools": list(allowed_tools),
        "budget_epoch": budget_epoch,
    }
    if _hash64(policy["budget_hash"], "loop_policy.budget_hash") != canonical_hash(core):
        raise W4EvidenceError("LOOP_POLICY_HASH_DRIFT")
    return {**core, "budget_hash": policy["budget_hash"]}


def _verify_runtime(runtime: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    runtime = _mapping(runtime, "runtime")
    run = _mapping(runtime.get("run"), "runtime.run")
    cards = runtime.get("cards")
    attempts = runtime.get("attempts")
    dispatches = runtime.get("dispatches")
    receipts = runtime.get("receipts")
    reviews = runtime.get("reviews")
    acceptance = runtime.get("acceptance_txns")
    next_cards = runtime.get("next_card_intents")
    markers = runtime.get("commit_markers")
    for value, label in ((cards, "runtime.cards"), (attempts, "runtime.attempts"), (dispatches, "runtime.dispatches"), (receipts, "runtime.receipts"), (reviews, "runtime.reviews"), (acceptance, "runtime.acceptance_txns"), (next_cards, "runtime.next_card_intents"), (markers, "runtime.commit_markers")):
        if not isinstance(value, list):
            raise W4EvidenceError(f"{label}: list required")
    if len(cards) != 1 or len(attempts) != 1 or len(dispatches) != 1:
        raise W4EvidenceError("W4-S0 requires exactly one card/attempt/dispatch")
    card, attempt, dispatch = _mapping(cards[0], "runtime.card"), _mapping(attempts[0], "runtime.attempt"), _mapping(dispatches[0], "runtime.dispatch")
    for field in ("run_id", "project_id", "goal_id", "plan_id", "plan_version", "queue_hash", "policy_hash", "context_pack_hash"):
        _text(run.get(field), f"run.{field}")
    if run.get("state") != "VERIFYING":
        raise W4EvidenceError("W4 requires P0 run state VERIFYING")
    if card.get("state") != "SUBMITTED" or card.get("acceptance_txn_id") is not None or card.get("next_card_intent_id") is not None:
        raise W4EvidenceError("card is not the P0 pre-review state")
    if attempt.get("state") != "EVIDENCE_VERIFIED" or attempt.get("result") != "EVIDENCE_VERIFIED":
        raise W4EvidenceError("attempt is not EVIDENCE_VERIFIED")
    if attempt.get("attempt_no") != 1 or attempt.get("retry_of") is not None:
        raise W4EvidenceError("W4-S0 accepts only the W2.5 first attempt")
    if dispatch.get("state") != "COMPLETED" or dispatch.get("attempt_id") != attempt.get("attempt_id"):
        raise W4EvidenceError("dispatch is not the completed W2.5 dispatch")
    if card.get("run_id") != run.get("run_id") or attempt.get("run_id") != run.get("run_id") or dispatch.get("run_id") != run.get("run_id"):
        raise W4EvidenceError("runtime run binding drift")
    if card.get("card_id") != attempt.get("card_id") or card.get("active_attempt_id") != attempt.get("attempt_id"):
        raise W4EvidenceError("runtime card/attempt binding drift")
    if attempt.get("dispatch_id") != dispatch.get("dispatch_id"):
        raise W4EvidenceError("runtime attempt/dispatch binding drift")
    if card.get("source_queue_hash") != run.get("queue_hash"):
        raise W4EvidenceError("runtime card queue binding drift")
    if card.get("plan_version") != run.get("plan_version") or attempt.get("context_pack_hash") != run.get("context_pack_hash"):
        raise W4EvidenceError("runtime plan/context binding drift")
    if attempt.get("deadline_policy_hash") != run.get("policy_hash"):
        raise W4EvidenceError("runtime deadline policy drift")
    if not acceptance or any(not isinstance(item, Mapping) for item in acceptance):
        raise W4EvidenceError("acceptance transaction projection malformed")
    if any(item.get("state") == "COMMITTED" or item.get("acceptance_enabled") != 0 for item in acceptance):
        raise W4EvidenceError("acceptance is not fail-closed")
    if next_cards:
        raise W4EvidenceError("next_card_intent exists in W4-S0")
    if len(reviews) != 1 or not isinstance(reviews[0], Mapping) or reviews[0].get("state") != "NOT_REQUESTED" or reviews[0].get("decision") is not None:
        raise W4EvidenceError("W2.5 review gate was already used")
    if any(not isinstance(item, Mapping) for item in markers):
        raise W4EvidenceError("commit marker projection malformed")
    by_operation = {item.get("operation_key"): item for item in markers}
    for operation in ("review-decision", "acceptance-gate", "next-card-intent", "run-complete"):
        if by_operation.get(operation, {}).get("status") != "SUPPRESSED":
            raise W4EvidenceError(f"W2.5 {operation} gate is not suppressed")
    return run, card, attempt, dispatch


def _verify_authority(
    authority: Mapping[str, Any],
    *,
    runtime: Mapping[str, Any],
    run: Mapping[str, Any],
    card: Mapping[str, Any],
    attempt: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    policy: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    checkpoint_state: Mapping[str, Any],
    review_request: Mapping[str, Any],
    tool_trace: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind W4 to a separately supplied W2.5 authority snapshot.

    A self-consistent runtime dictionary is not an authority root. The
    adapter must provide this object from the live/ sealed W2.5 source. W4
    verifies its own canonical hash and then uses its marker, budget,
    checkpoint and identity commitments as external expectations.
    """

    authority = _mapping(authority, "authority")
    required = {
        "schema",
        "authority_id",
        "key_id",
        "authority_hash",
        "authority_mac",
        "run_id",
        "card_id",
        "attempt_id",
        "budget",
        "budget_hash",
        "budget_epoch",
        "marker_commitments",
        "checkpoint",
        "event_chain_hash",
        "tool_trace_hash",
        "final",
        "executor",
        "review",
    }
    _required_keys(authority, required, "authority")
    if authority["schema"] != AUTHORITY_SCHEMA:
        raise W4EvidenceError("AUTHORITY_SCHEMA_UNSUPPORTED")
    authority_id = _text(authority["authority_id"], "authority.authority_id")
    key_id = _text(authority["key_id"], "authority.key_id")
    if authority["run_id"] != run["run_id"] or authority["card_id"] != card["card_id"] or authority["attempt_id"] != attempt["attempt_id"]:
        raise W4EvidenceError("authority identity drift")
    trusted_key = resolve_trusted_authority(authority_id=authority_id, key_id=key_id)
    authority_core = {key: authority[key] for key in required if key not in {"authority_hash", "authority_mac"}}
    if _hash64(authority["authority_hash"], "authority.authority_hash") != canonical_hash(authority_core):
        raise W4EvidenceError("AUTHORITY_HASH_DRIFT")
    expected_mac = hmac.new(trusted_key, canonical_json(authority_core).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(_hash64(authority["authority_mac"], "authority.authority_mac"), expected_mac):
        raise W4EvidenceError("AUTHORITY_MAC_INVALID")
    if _hash64(authority["tool_trace_hash"], "authority.tool_trace_hash") != canonical_hash(tool_trace):
        raise W4EvidenceError("AUTHORITY_TOOL_TRACE_DRIFT")
    authority_budget = _mapping(authority["budget"], "authority.budget")
    if canonical_json(authority_budget) != canonical_json(_run_budget(run)) or canonical_json(authority_budget) != canonical_json(policy["admission_budget"]):
        raise W4EvidenceError("AUTHORITY_BUDGET_DRIFT")
    if authority["budget_hash"] != policy["budget_hash"] or authority["budget_epoch"] != policy["budget_epoch"]:
        raise W4EvidenceError("AUTHORITY_POLICY_BINDING_DRIFT")

    markers = runtime.get("commit_markers")
    events = runtime.get("events")
    if not isinstance(markers, list) or not isinstance(events, list):
        raise W4EvidenceError("runtime marker/event history required")
    marker_by_operation: dict[str, Mapping[str, Any]] = {}
    for marker in markers:
        marker = _mapping(marker, "commit_marker")
        operation = _text(marker.get("operation_key"), "commit_marker.operation_key")
        if operation in marker_by_operation:
            raise W4EvidenceError("duplicate commit marker operation")
        marker_by_operation[operation] = marker
        payload = marker.get("payload")
        if payload is None and isinstance(marker.get("payload_json"), str):
            try:
                payload = json.loads(marker["payload_json"])
            except ValueError as exc:
                raise W4EvidenceError("commit marker payload JSON invalid") from exc
        payload = _mapping(payload, f"commit_marker[{operation}].payload")
        expected_marker_hash = canonical_hash(
            {
                "run_id": run["run_id"],
                "commit_point": marker.get("commit_point"),
                "operation_key": operation,
                "status": marker.get("status"),
                "payload": dict(payload),
            }
        )
        if marker.get("marker_hash") != expected_marker_hash:
            raise W4EvidenceError(f"commit marker hash drift: {operation}")
    commitments = _mapping(authority["marker_commitments"], "authority.marker_commitments")
    if set(commitments) != set(marker_by_operation):
        raise W4EvidenceError("marker commitment set drift")
    for operation, marker in marker_by_operation.items():
        if commitments.get(operation) != marker.get("marker_hash"):
            raise W4EvidenceError(f"marker commitment drift: {operation}")

    event_by_no: dict[int, Mapping[str, Any]] = {}
    for expected_no, raw_event in enumerate(events, 1):
        event = _mapping(raw_event, f"event[{expected_no - 1}]")
        event_no = _exact_int(event.get("event_no"), "event.event_no", minimum=1)
        if event_no != expected_no or event_no in event_by_no:
            raise W4EvidenceError("event history is not contiguous")
        if event.get("run_id") != run["run_id"]:
            raise W4EvidenceError("foreign event in runtime history")
        _text(event.get("event_id"), "event.event_id")
        event_by_no[event_no] = event
    if _hash64(authority["event_chain_hash"], "authority.event_chain_hash") != canonical_hash([event_by_no[number] for number in sorted(event_by_no)]):
        raise W4EvidenceError("AUTHORITY_EVENT_CHAIN_DRIFT")
    running_events = [
        event
        for event in event_by_no.values()
        if event.get("entity_type") == "Attempt"
        and event.get("entity_id") == attempt["attempt_id"]
        and event.get("event_type") == "ATTEMPT_RUNNING"
    ]
    if len(running_events) != 1:
        raise W4EvidenceError("authoritative ATTEMPT_RUNNING event missing or duplicated")
    running_event = running_events[0]
    if running_event.get("from_state") != "STARTING" or running_event.get("to_state") != "RUNNING":
        raise W4EvidenceError("ATTEMPT_RUNNING transition drift")
    running_no = int(running_event["event_no"])
    state_version = sum(
        1
        for event in event_by_no.values()
        if int(event["event_no"]) <= running_no
        and event.get("entity_type") == "Attempt"
        and event.get("entity_id") == attempt["attempt_id"]
        and event.get("from_state") is not None
    )
    expected_checkpoint = _mapping(authority["checkpoint"], "authority.checkpoint")
    for field in ("checkpoint_id", "state_hash"):
        if checkpoint.get(field) != expected_checkpoint.get(field):
            raise W4EvidenceError(f"authority checkpoint drift: {field}")
    if checkpoint_state.get("state_version") != expected_checkpoint.get("state_version") or checkpoint_state.get("last_transition_event_id") != expected_checkpoint.get("last_transition_event_id"):
        raise W4EvidenceError("checkpoint state witness/authority drift")
    if expected_checkpoint.get("state_version") != state_version or expected_checkpoint.get("last_transition_event_id") != running_event.get("event_id"):
        raise W4EvidenceError("checkpoint is not anchored to ATTEMPT_RUNNING")

    final = _mapping(authority["final"], "authority.final")
    final_required = {
        "attempt_state_hash",
        "state",
        "result",
        "state_version",
        "last_transition_event_id",
        "receipt_id",
        "receipt_hash",
        "receipt_body_hash",
        "progress_signature",
    }
    _required_keys(final, final_required, "authority.final")
    final_state_hash = canonical_attempt_state_hash(attempt)
    if final["attempt_state_hash"] != final_state_hash or final["state"] != attempt.get("state") or final["result"] != attempt.get("result") or final["state_version"] != attempt.get("state_version") or final["last_transition_event_id"] != attempt.get("last_transition_event_id"):
        raise W4EvidenceError("final attempt authority drift")
    final_events = [
        event
        for event in event_by_no.values()
        if event.get("entity_type") == "Attempt"
        and event.get("entity_id") == attempt["attempt_id"]
        and event.get("event_type") == "ATTEMPT_EVIDENCE_VERIFIED"
    ]
    if len(final_events) != 1:
        raise W4EvidenceError("authoritative ATTEMPT_EVIDENCE_VERIFIED event missing or duplicated")
    final_event = final_events[0]
    if final_event.get("from_state") != "SUBMITTED" or final_event.get("to_state") != "EVIDENCE_VERIFIED" or final_event.get("event_id") != final["last_transition_event_id"] or int(final_event["event_no"]) <= running_no:
        raise W4EvidenceError("final attempt transition drift")
    if any(
        int(event["event_no"]) > int(final_event["event_no"])
        and event.get("entity_type") == "Attempt"
        and event.get("entity_id") == attempt["attempt_id"]
        and event.get("from_state") is not None
        for event in event_by_no.values()
    ):
        raise W4EvidenceError("final attempt transition is not terminal")
    final_state_version = sum(
        1
        for event in event_by_no.values()
        if int(event["event_no"]) <= int(final_event["event_no"])
        and event.get("entity_type") == "Attempt"
        and event.get("entity_id") == attempt["attempt_id"]
        and event.get("from_state") is not None
    )
    if final_state_version != final["state_version"]:
        raise W4EvidenceError("final attempt state-version history drift")
    validation_receipts = [receipt for receipt in runtime.get("receipts", []) if isinstance(receipt, Mapping) and receipt.get("receipt_kind") == "validation"]
    if len(validation_receipts) != 1:
        raise W4EvidenceError("authoritative validation receipt missing or duplicated")
    validation = validation_receipts[0]
    validation_core = _mapping(validation.get("core"), "validation_receipt.core")
    if validation.get("receipt_id") != final["receipt_id"] or validation.get("receipt_hash") != final["receipt_hash"] or validation.get("receipt_body_hash") != final["receipt_body_hash"] or validation.get("progress_signature") != final["progress_signature"] or validation_core.get("canonical_state_hash") != final_state_hash:
        raise W4EvidenceError("final receipt authority drift")

    executor = _mapping(authority["executor"], "authority.executor")
    for field in ("worker_id", "session_id", "backend"):
        _text(executor.get(field), f"authority.executor.{field}")
    if executor["worker_id"] != attempt.get("worker_id") or executor["backend"] != dispatch.get("executor_kind"):
        raise W4EvidenceError("executor authority binding drift")
    review = _mapping(authority["review"], "authority.review")
    for field in ("review_domain_id", "reviewer_id", "reviewer_session_id", "reviewer_backend"):
        _text(review.get(field), f"authority.review.{field}")
    for field in ("review_domain_id", "reviewer_id", "reviewer_session_id", "reviewer_backend"):
        if review_request.get(field) != review[field]:
            raise W4EvidenceError(f"reviewer authority binding drift: {field}")
    if review_request.get("executor_session_id") != executor["session_id"]:
        raise W4EvidenceError("executor session authority drift")
    if review["reviewer_id"] == executor["worker_id"] or review["reviewer_session_id"] == executor["session_id"] or review["reviewer_backend"] == executor["backend"]:
        raise W4EvidenceError("review authority is not independent")
    return {"authority_id": authority_id, "authority_hash": authority["authority_hash"], "running_event_id": running_event["event_id"], "final_event_id": final_event["event_id"], "marker_count": len(marker_by_operation)}


def _verify_progress_history(history: Any, validation_receipt: Mapping[str, Any], policy: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(history, list) or not history:
        raise W4EvidenceError("progress_history: non-empty list required")
    if len(history) > policy["max_turns"]:
        raise W4EvidenceError("PROGRESS_TURN_BUDGET_EXCEEDED")
    previous: str | None = None
    duplicate_run = 0
    last: Mapping[str, Any] | None = None
    history_length = len(history)
    for expected_turn, raw in enumerate(history, 1):
        item = _mapping(raw, f"progress_history[{expected_turn - 1}]")
        if item.get("turn_no") != expected_turn or item.get("attempt_no") != 1:
            raise W4EvidenceError("progress history sequence/attempt drift")
        canonical_state_hash = _hash64(item.get("canonical_state_hash"), "progress.canonical_state_hash")
        receipt_body_hash = _hash64(item.get("receipt_body_hash"), "progress.receipt_body_hash")
        artifact_hashes = _string_list(item.get("artifact_hashes"), "progress.artifact_hashes")
        validation_result = _mapping(item.get("validation_result"), "progress.validation_result")
        next_state = _text(item.get("next_state"), "progress.next_state")
        expected = canonical_hash(
            {
                "card_id": validation_receipt["card_id"],
                "attempt_id": validation_receipt["attempt_id"],
                "attempt_no": 1,
                "canonical_state_hash": canonical_state_hash,
                "artifact_hashes": sorted(artifact_hashes),
                "validation_result": dict(validation_result),
                "receipt_body_hash": receipt_body_hash,
                "next_state": next_state,
            }
        )
        supplied = _hash64(item.get("progress_signature"), "progress.progress_signature")
        if supplied != expected:
            raise W4EvidenceError("PROGRESS_SIGNATURE_DRIFT")
        if previous == supplied:
            duplicate_run += 1
        else:
            duplicate_run = 1
        previous = supplied
        last = item
        if duplicate_run >= policy["no_progress_limit"] and expected_turn != history_length:
            raise W4EvidenceError("NO_PROGRESS_HISTORY_CONTINUES")
    assert last is not None
    if previous != validation_receipt.get("progress_signature"):
        raise W4EvidenceError("progress history/final receipt drift")
    if duplicate_run >= policy["no_progress_limit"]:
        if last.get("next_state") not in {"NO_PROGRESS", "BLOCKED"}:
            raise W4EvidenceError("repeated progress signature was projected as success")
        return {"status": "NO_PROGRESS", "last_signature": previous, "last_turn": len(history), "duplicate_run": duplicate_run}
    return {"status": "OK", "last_signature": previous, "last_turn": len(history), "duplicate_run": duplicate_run}


def _verify_checkpoint(
    checkpoint: Mapping[str, Any],
    checkpoint_state: Mapping[str, Any],
    *,
    run: Mapping[str, Any],
    card: Mapping[str, Any],
    attempt: Mapping[str, Any],
    dispatch: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    checkpoint = _mapping(checkpoint, "checkpoint")
    checkpoint_state = _mapping(checkpoint_state, "checkpoint_state")
    required = {"checkpoint_id", "attempt_id", "attempt_no", "state_hash", "receipt_id", "payload", "payload_hash", "parent_checkpoint_hash", "bindings", "created_at", "checkpoint_hash"}
    _required_keys(checkpoint, required, "checkpoint")
    if checkpoint["attempt_id"] != attempt["attempt_id"] or checkpoint["attempt_no"] != 1:
        raise W4EvidenceError("checkpoint attempt binding drift")
    if checkpoint["checkpoint_id"] != f"checkpoint-{attempt['attempt_id']}-001":
        raise W4EvidenceError("unsupported W2.5 checkpoint identity")
    if checkpoint["receipt_id"] is not None or checkpoint["parent_checkpoint_hash"] is not None:
        raise W4EvidenceError("W2.5 first checkpoint has unexpected parent/receipt")
    payload = _mapping(checkpoint["payload"], "checkpoint.payload")
    if payload != {"executor": "fake", "dispatch_id": dispatch["dispatch_id"], "state": "RUNNING"}:
        raise W4EvidenceError("checkpoint payload drift")
    if _hash64(checkpoint["payload_hash"], "checkpoint.payload_hash") != canonical_hash(payload):
        raise W4EvidenceError("checkpoint payload hash drift")
    if checkpoint_state.get("attempt_id") != attempt["attempt_id"] or checkpoint_state.get("card_id") != card["card_id"]:
        raise W4EvidenceError("checkpoint state identity drift")
    if checkpoint_state.get("state") != "RUNNING" or checkpoint_state.get("result") is not None:
        raise W4EvidenceError("checkpoint state is not the W2.5 running state")
    expected_state_hash = canonical_attempt_state_hash(checkpoint_state)
    if _hash64(checkpoint["state_hash"], "checkpoint.state_hash") != expected_state_hash:
        raise W4EvidenceError("checkpoint state hash drift")
    bindings = _mapping(checkpoint["bindings"], "checkpoint.bindings")
    expected_bindings = {
        "run_id": run["run_id"],
        "card_id": card["card_id"],
        "attempt_id": attempt["attempt_id"],
        "plan_version": run["plan_version"],
        "queue_hash": run["queue_hash"],
        "policy_hash": run["policy_hash"],
        "context_pack_hash": run["context_pack_hash"],
        "input_snapshot_hash": attempt["input_snapshot_hash"],
        "capability_set_hash": card["capability_set_hash"],
        "budget_hash": policy["budget_hash"],
        "fencing_epoch": run["fencing_epoch"],
    }
    if dict(bindings) != expected_bindings:
        raise W4EvidenceError("checkpoint admission bindings drift")
    checkpoint_core = {key: checkpoint[key] for key in required if key != "checkpoint_hash"}
    if _hash64(checkpoint["checkpoint_hash"], "checkpoint.checkpoint_hash") != canonical_hash(checkpoint_core):
        raise W4EvidenceError("checkpoint wrapper hash drift")
    return {
        "checkpoint_id": checkpoint["checkpoint_id"],
        "state_hash": checkpoint["state_hash"],
        "payload_hash": checkpoint["payload_hash"],
        "checkpoint_hash": checkpoint["checkpoint_hash"],
        "turn_no": 1,
    }


def verify_small_loop_bundle(bundle: Mapping[str, Any], *, authority: Mapping[str, Any] | None = None) -> VerificationResult:
    """Verify a sealed W4-S0 bundle and prepare, but never perform, review.

    ``authority`` is deliberately separate from the bundle. Without a live
    or separately sealed W2.5 authority snapshot, a self-consistent dictionary
    is not sufficient for ``READY_FOR_REVIEW``.
    """

    try:
        bundle = _mapping(bundle, "bundle")
        _required_keys(bundle, REQUIRED_BUNDLE_KEYS, "bundle")
        if bundle.get("schema") != BUNDLE_SCHEMA:
            raise W4EvidenceError("BUNDLE_SCHEMA_UNSUPPORTED")
        source = _mapping(bundle.get("source"), "source")
        if dict(source) != SOURCE_CONTRACT:
            raise W4IncompatibleSource("INCOMPATIBLE_SOURCE")
        if authority is None:
            raise W4EvidenceError("AUTHORITY_REQUIRED")
        run, card, attempt, dispatch = _verify_runtime(bundle["runtime"])
        policy = _verify_loop_policy(bundle["loop_policy"], run)
        evidence = _mapping(bundle["evidence"], "evidence")
        _verify_authority(
            authority,
            runtime=bundle["runtime"],
            run=run,
            card=card,
            attempt=attempt,
            dispatch=dispatch,
            policy=policy,
            checkpoint=_mapping(evidence.get("checkpoint"), "evidence.checkpoint"),
            checkpoint_state=_mapping(evidence.get("checkpoint_state"), "evidence.checkpoint_state"),
            review_request=_mapping(bundle["review_request"], "review_request"),
            tool_trace=_mapping(bundle["tool_trace"], "tool_trace"),
        )
        identity = {
            "run_id": run["run_id"],
            "attempt_id": attempt["attempt_id"],
            "capability_set_hash": card["capability_set_hash"],
            "policy_hash": run["policy_hash"],
            "budget_hash": policy["budget_hash"],
        }
        receipt_info = verify_receipt_pair(bundle["runtime"])
        artifact_info = verify_artifact_evidence(bundle["runtime"], evidence, receipt_info)
        progress_info = _verify_progress_history(evidence.get("progress_history"), receipt_info["validation"], policy)
        checkpoint_info = _verify_checkpoint(
            evidence.get("checkpoint"),
            evidence.get("checkpoint_state"),
            run=run,
            card=card,
            attempt=attempt,
            dispatch=dispatch,
            policy=policy,
        )
        circuit_info = verify_tool_trace(bundle["tool_trace"], identity=identity, policy=policy)
        if circuit_info["status"] == "OPEN":
            return VerificationResult(
                status="BLOCKED",
                findings=("TOOL_CIRCUIT_OPEN",),
                receipt=receipt_info["validation"],
                checkpoint=checkpoint_info,
                progress=progress_info,
                tool_circuit=circuit_info,
            )
        if progress_info["status"] == "NO_PROGRESS":
            return VerificationResult(
                status="BLOCKED",
                findings=("NO_PROGRESS",),
                receipt=receipt_info["validation"],
                checkpoint=checkpoint_info,
                progress=progress_info,
                tool_circuit=circuit_info,
            )
        review = prepare_review(
            runtime=bundle["runtime"],
            receipt=receipt_info["validation"],
            checkpoint=evidence["checkpoint"],
            artifact_evidence=artifact_info,
            progress=progress_info,
            review_request=bundle["review_request"],
        )
        return VerificationResult(
            status="READY_FOR_REVIEW",
            findings=(),
            review_preparation=review,
            receipt=receipt_info["validation"],
            checkpoint=checkpoint_info,
            progress=progress_info,
            tool_circuit=circuit_info,
        )
    except W4IncompatibleSource as exc:
        return VerificationResult(status="INCOMPATIBLE_SOURCE", findings=(str(exc),))
    except (W4EvidenceError, AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        return VerificationResult(status="INVALID_EVIDENCE", findings=(str(exc),))
