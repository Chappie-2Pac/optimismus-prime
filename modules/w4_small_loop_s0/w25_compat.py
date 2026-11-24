"""Pure compatibility helpers for the existing W2.5-S0 hash contract.

This module deliberately does not import or mutate the W2.5 controller. It
reconstructs the already-published canonical JSON/hash formulas from sealed
data so W4 can verify them without creating a second runtime authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from .models import W4EvidenceError


HEX64 = re.compile(r"[0-9a-f]{64}\Z")
OPAQUE_IDENTITY_FIELDS = {
    "queue_hash",
    "policy_hash",
    "card_hash",
    "context_pack_hash",
    "capability_set_hash",
    "input_snapshot_hash",
    "command_hash",
    "artifact_manifest_hash",
}


def canonical_json(value: Any) -> str:
    """Match W2.5's sort-key, compact, UTF-8 JSON serialization exactly."""

    return json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise W4EvidenceError(f"{label}: object required")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise W4EvidenceError(f"{label}: non-empty text required")
    return value


def _opaque(value: Any, label: str) -> str:
    # W2.5 fixtures intentionally use stable labels such as
    # ``queue-hash-w25-s0``. They are opaque identity values here; only W4's
    # derived cryptographic fields are required to be 64-hex hashes.
    return _text(value, label)


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if HEX64.fullmatch(value) is None:
        raise W4EvidenceError(f"{label}: lowercase SHA-256 required")
    return value


def _exact_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise W4EvidenceError(f"{label}: integer >= {minimum} required")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise W4EvidenceError(f"{label}: string list required")
    return list(value)


def canonical_attempt_state_hash(attempt: Mapping[str, Any]) -> str:
    """Reproduce ControlPlane.canonical_attempt_state_hash exactly."""

    attempt = _mapping(attempt, "attempt_state")
    _text(attempt.get("attempt_id"), "attempt_state.attempt_id")
    _text(attempt.get("card_id"), "attempt_state.card_id")
    _text(attempt.get("state"), "attempt_state.state")
    state_version = _exact_int(attempt.get("state_version"), "attempt_state.state_version")
    last_event = attempt.get("last_transition_event_id")
    if last_event is not None:
        _text(last_event, "attempt_state.last_transition_event_id")
    result = attempt.get("result")
    if result is not None:
        _text(result, "attempt_state.result")
    return canonical_hash(
        {
            "entity_type": "Attempt",
            "attempt_id": attempt["attempt_id"],
            "card_id": attempt["card_id"],
            "state": attempt["state"],
            "state_version": state_version,
            "last_transition_event_id": last_event,
            "result": result,
        }
    )


RECEIPT_CORE_FIELDS = (
    "receipt_id",
    "receipt_kind",
    "state",
    "run_id",
    "dispatch_id",
    "attempt_id",
    "card_id",
    "parent_receipt_id",
    "plan_version",
    "queue_hash",
    "card_hash",
    "input_snapshot_hash",
    "review_id",
    "policy_hash",
    "capability_set_hash",
    "command_hash",
    "artifact_manifest_hash",
    "validator_id",
    "validator_version",
    "result",
    "next_action",
    "artifact_hashes",
    "validation_result",
    "created_at",
    "sealed_at",
    "verified_at",
    "commit_txn_id",
    "canonical_state_hash",
)


def _nullable_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def receipt_core_from_row(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Rebuild ``receipt_core`` from columns, never trusting ``core``."""

    receipt = _mapping(receipt, "receipt")
    # W2.5 stores canonical_state_hash inside core_json rather than as a
    # separate SQL column. It is still verified below by comparing the whole
    # supplied core with the reconstruction and by binding it to Attempt.
    supplied_core = receipt.get("core")
    supplied_core = _mapping(supplied_core, "receipt.core")
    for key in ("receipt_id", "receipt_kind", "state", "run_id", "attempt_id", "card_id", "result", "created_at"):
        _text(receipt.get(key), f"receipt.{key}")
    for key in (
        "dispatch_id",
        "parent_receipt_id",
        "plan_version",
        "review_id",
        "validator_id",
        "validator_version",
        "sealed_at",
        "verified_at",
        "commit_txn_id",
    ):
        _nullable_text(receipt.get(key), f"receipt.{key}")
    # ``context_pack_hash`` is a runtime/attempt binding but is deliberately
    # not a member of W2.5's receipt_core. Do not invent it in the replay.
    for key in ("queue_hash", "policy_hash", "card_hash", "input_snapshot_hash", "capability_set_hash"):
        _opaque(receipt.get(key), f"receipt.{key}")
    artifact_manifest_hash = receipt.get("artifact_manifest_hash")
    if artifact_manifest_hash is not None:
        _opaque(artifact_manifest_hash, "receipt.artifact_manifest_hash")
    next_action = _mapping(receipt.get("next_action"), "receipt.next_action")
    validation_result = _mapping(receipt.get("validation_result"), "receipt.validation_result")
    artifact_hashes = _string_list(receipt.get("artifact_hashes"), "receipt.artifact_hashes")
    canonical_state_hash = _hash64(supplied_core.get("canonical_state_hash"), "receipt.core.canonical_state_hash")
    core = {
        "receipt_id": receipt["receipt_id"],
        "receipt_kind": receipt["receipt_kind"],
        "state": receipt["state"],
        "run_id": receipt["run_id"],
        "dispatch_id": receipt.get("dispatch_id"),
        "attempt_id": receipt["attempt_id"],
        "card_id": receipt["card_id"],
        "parent_receipt_id": receipt.get("parent_receipt_id"),
        "plan_version": receipt.get("plan_version"),
        "queue_hash": receipt["queue_hash"],
        "card_hash": receipt["card_hash"],
        "input_snapshot_hash": receipt["input_snapshot_hash"],
        "review_id": receipt.get("review_id"),
        "policy_hash": receipt["policy_hash"],
        "capability_set_hash": receipt["capability_set_hash"],
        "command_hash": receipt.get("command_hash"),
        "artifact_manifest_hash": artifact_manifest_hash,
        "validator_id": receipt.get("validator_id"),
        "validator_version": receipt.get("validator_version"),
        "result": receipt["result"],
        "next_action": dict(next_action),
        "artifact_hashes": sorted(artifact_hashes),
        "validation_result": dict(validation_result),
        "created_at": receipt["created_at"],
        "sealed_at": receipt.get("sealed_at"),
        "verified_at": receipt.get("verified_at"),
        "commit_txn_id": receipt.get("commit_txn_id"),
        "canonical_state_hash": canonical_state_hash,
    }
    if canonical_json(supplied_core) != canonical_json(core):
        raise W4EvidenceError("RECEIPT_CORE_DRIFT")
    return core


def reconstruct_receipt_hashes(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Reproduce the W2.5 body, progress and final receipt hashes."""

    core = receipt_core_from_row(receipt)
    body_hash = canonical_hash(core)
    result = core["result"]
    next_state = result if result in {"SUBMITTED", "EVIDENCE_VERIFIED"} else core["state"]
    progress_payload = {
        "card_id": core["card_id"],
        "attempt_id": core["attempt_id"],
        # W2.5-S0 is intentionally single-attempt and hard-codes this value.
        "attempt_no": 1,
        "canonical_state_hash": core["canonical_state_hash"],
        "artifact_hashes": sorted(core["artifact_hashes"]),
        "validation_result": core["validation_result"],
        "receipt_body_hash": body_hash,
        "next_state": next_state,
    }
    progress_signature = canonical_hash(progress_payload)
    receipt_hash = canonical_hash({**core, "progress_signature": progress_signature})
    stored = {
        "receipt_body_hash": _hash64(receipt.get("receipt_body_hash"), "receipt.receipt_body_hash"),
        "progress_signature": _hash64(receipt.get("progress_signature"), "receipt.progress_signature"),
        "receipt_hash": _hash64(receipt.get("receipt_hash"), "receipt.receipt_hash"),
    }
    return {
        "core": core,
        "receipt_body_hash": body_hash,
        "progress_payload": progress_payload,
        "progress_signature": progress_signature,
        "receipt_hash": receipt_hash,
        "stored": stored,
        "valid": stored == {
            "receipt_body_hash": body_hash,
            "progress_signature": progress_signature,
            "receipt_hash": receipt_hash,
        },
    }


def _same_binding(left: Mapping[str, Any], right: Mapping[str, Any], fields: tuple[str, ...], label: str) -> None:
    for field in fields:
        if left.get(field) != right.get(field):
            raise W4EvidenceError(f"{label}.{field}: binding drift")


def verify_receipt_pair(runtime: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact one-execution/one-validation W2.5 P0 pair."""

    runtime = _mapping(runtime, "runtime")
    runs = runtime.get("run")
    cards = runtime.get("cards")
    attempts = runtime.get("attempts")
    dispatches = runtime.get("dispatches")
    receipts = runtime.get("receipts")
    if not isinstance(runs, Mapping) or not isinstance(cards, list) or not isinstance(attempts, list) or not isinstance(dispatches, list) or not isinstance(receipts, list):
        raise W4EvidenceError("W2.5 runtime projection shape invalid")
    if len(cards) != 1 or len(attempts) != 1 or len(dispatches) != 1 or len(receipts) != 2:
        raise W4EvidenceError("W2.5-S0 requires exactly one card, attempt, dispatch and two receipts")
    card, attempt, dispatch = cards[0], attempts[0], dispatches[0]
    _mapping(card, "card")
    _mapping(attempt, "attempt")
    _mapping(dispatch, "dispatch")
    bindings = (
        "project_id",
        "run_id",
        "goal_id",
        "plan_id",
        "plan_version",
    )
    _same_binding(runs, card, bindings, "run/card")
    _same_binding(card, attempt, ("run_id", "card_id"), "card/attempt")
    _same_binding(attempt, dispatch, ("run_id", "attempt_id"), "attempt/dispatch")
    if card.get("source_queue_hash") != runs.get("queue_hash"):
        raise W4EvidenceError("run/card queue binding drift")
    if card.get("card_hash") is None or attempt.get("command_hash") is None:
        raise W4EvidenceError("W2.5 identity fields missing")
    for field in ("queue_hash", "policy_hash", "context_pack_hash", "card_hash", "capability_set_hash", "input_snapshot_hash", "command_hash"):
        _opaque(runs.get(field) if field in {"queue_hash", "policy_hash", "context_pack_hash"} else (card.get(field) if field in {"card_hash", "capability_set_hash"} else attempt.get(field)), f"binding.{field}")
    expected_attempt_state = canonical_attempt_state_hash(attempt)
    by_kind: dict[str, Mapping[str, Any]] = {}
    for receipt in receipts:
        _mapping(receipt, "receipt")
        kind = _text(receipt.get("receipt_kind"), "receipt.receipt_kind")
        if kind in by_kind:
            raise W4EvidenceError("duplicate W2.5 receipt kind")
        by_kind[kind] = receipt
        _same_binding(receipt, runs, ("run_id", "plan_version", "queue_hash", "policy_hash"), "receipt/run")
        _same_binding(receipt, card, ("card_id", "card_hash"), "receipt/card")
        _same_binding(receipt, attempt, ("attempt_id", "input_snapshot_hash", "command_hash"), "receipt/attempt")
        if receipt.get("dispatch_id") != dispatch.get("dispatch_id") or receipt.get("capability_set_hash") != card.get("capability_set_hash"):
            raise W4EvidenceError("receipt dispatch/capability binding drift")
    if set(by_kind) != {"execution", "validation"}:
        raise W4EvidenceError("W2.5 execution and validation receipts required")
    rebuilt = {kind: reconstruct_receipt_hashes(receipt) for kind, receipt in by_kind.items()}
    if not all(item["valid"] for item in rebuilt.values()):
        raise W4EvidenceError("W2.5 receipt hash reconstruction failed")
    execution, validation = by_kind["execution"], by_kind["validation"]
    if execution.get("state") != "SEALED" or execution.get("result") != "SUBMITTED":
        raise W4EvidenceError("execution receipt is not the W2.5 sealed submission")
    if validation.get("state") != "VERIFIED" or validation.get("result") != "EVIDENCE_VERIFIED":
        raise W4EvidenceError("validation receipt is not EVIDENCE_VERIFIED")
    if validation.get("parent_receipt_id") != execution.get("receipt_id"):
        raise W4EvidenceError("validation receipt parent binding drift")
    if rebuilt["validation"]["core"]["canonical_state_hash"] != expected_attempt_state:
        raise W4EvidenceError("validation receipt does not bind current attempt state")
    if validation.get("artifact_manifest_hash") != attempt.get("artifact_manifest_hash"):
        raise W4EvidenceError("validation receipt/attempt manifest drift")
    if validation.get("artifact_hashes") != execution.get("artifact_hashes"):
        raise W4EvidenceError("execution/validation artifact list drift")
    return {
        "execution": execution,
        "validation": validation,
        "execution_rebuilt": rebuilt["execution"],
        "validation_rebuilt": rebuilt["validation"],
        "attempt_state_hash": expected_attempt_state,
    }


def verify_artifact_evidence(runtime: Mapping[str, Any], evidence: Mapping[str, Any], receipt_info: Mapping[str, Any]) -> dict[str, Any]:
    """Check W2.5 artifact-manifest semantics without opening files."""

    attempt = runtime["attempts"][0]
    validation = receipt_info["validation"]
    manifest = _mapping(evidence.get("artifact_manifest"), "artifact_manifest")
    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, list):
        raise W4EvidenceError("artifacts: list required")
    manifest_hash = _opaque(manifest.get("artifact_manifest_hash"), "artifact_manifest.artifact_manifest_hash")
    if manifest_hash != validation.get("artifact_manifest_hash") or manifest_hash != attempt.get("artifact_manifest_hash"):
        raise W4EvidenceError("artifact manifest binding drift")
    if manifest.get("attempt_id") != attempt.get("attempt_id"):
        raise W4EvidenceError("artifact manifest attempt drift")
    artifact_hashes = _string_list(manifest.get("artifact_hashes"), "artifact_manifest.artifact_hashes")
    if sorted(artifact_hashes) != sorted(validation.get("artifact_hashes", [])):
        raise W4EvidenceError("artifact manifest hash list drift")
    scope = manifest.get("scope")
    if not isinstance(scope, str) or not scope:
        raise W4EvidenceError("artifact_manifest.scope: non-empty string required")
    recomputed_manifest = canonical_hash({"attempt_id": attempt["attempt_id"], "artifact_hashes": sorted(artifact_hashes), "scope": scope})
    if recomputed_manifest != manifest_hash:
        raise W4EvidenceError("artifact manifest hash reconstruction failed")
    if len(artifacts) != len(artifact_hashes):
        raise W4EvidenceError("artifact row count does not match manifest")
    rows: list[tuple[str, str]] = []
    for artifact in artifacts:
        artifact = _mapping(artifact, "artifact")
        if artifact.get("attempt_id") != attempt["attempt_id"] or artifact.get("artifact_manifest_hash") != manifest_hash:
            raise W4EvidenceError("foreign artifact provenance")
        artifact_hash = _hash64(artifact.get("artifact_hash"), "artifact.artifact_hash")
        scope_ref = _text(artifact.get("scope_ref"), "artifact.scope_ref")
        rows.append((artifact_hash, scope_ref))
    if sorted(item[0] for item in rows) != sorted(artifact_hashes):
        raise W4EvidenceError("artifact rows do not match manifest hashes")
    expected_refs = sorted(f"fake://p0/{attempt['attempt_id']}/{ordinal}" for ordinal in range(1, len(rows) + 1))
    if sorted(item[1] for item in rows) != expected_refs:
        raise W4EvidenceError("artifact scope reference drift")
    return {
        "artifact_manifest_hash": manifest_hash,
        "artifact_hashes": sorted(artifact_hashes),
        "scope": scope,
        "count": len(rows),
    }
