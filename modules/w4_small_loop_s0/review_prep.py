"""Construct a review request without performing review or acceptance."""

from __future__ import annotations

from typing import Any, Mapping

from .models import W4EvidenceError
from .w25_compat import _exact_int, _hash64, _mapping, _text, canonical_hash


REVIEW_PREP_SCHEMA = "w4-review-preparation.v1"


def prepare_review(
    *,
    runtime: Mapping[str, Any],
    receipt: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    artifact_evidence: Mapping[str, Any],
    progress: Mapping[str, Any],
    review_request: Mapping[str, Any],
) -> dict[str, Any]:
    """Create a deterministic pending-review packet.

    The result intentionally has no ``decision`` other than ``PENDING`` and
    no W2.5 ``review_id``. It is a handoff artifact, never an acceptance path.
    """

    runtime = _mapping(runtime, "runtime")
    run = _mapping(runtime.get("run"), "runtime.run")
    card = _mapping(runtime.get("cards", [])[0], "runtime.card")
    attempt = _mapping(runtime.get("attempts", [])[0], "runtime.attempt")
    request = _mapping(review_request, "review_request")
    review_domain_id = _text(request.get("review_domain_id"), "review_request.review_domain_id")
    if review_domain_id == "p0-review-disabled":
        raise W4EvidenceError("W4 review preparation requires an explicit review domain")
    reviewer_id = _text(request.get("reviewer_id"), "review_request.reviewer_id")
    reviewer_session_id = _text(request.get("reviewer_session_id"), "review_request.reviewer_session_id")
    reviewer_backend = _text(request.get("reviewer_backend"), "review_request.reviewer_backend")
    executor_session_id = _text(request.get("executor_session_id"), "review_request.executor_session_id")
    worker_id = _text(attempt.get("worker_id"), "attempt.worker_id")
    if reviewer_id == worker_id:
        raise W4EvidenceError("SELF_ACCEPT_REVIEWER_ID")
    if reviewer_session_id == executor_session_id:
        raise W4EvidenceError("SELF_ACCEPT_REVIEWER_SESSION")
    criteria = request.get("criteria")
    if not isinstance(criteria, list) or not 1 <= len(criteria) <= 64 or any(not isinstance(item, str) or not item for item in criteria):
        raise W4EvidenceError("review_request.criteria: bounded non-empty string list required")
    if len(set(criteria)) != len(criteria):
        raise W4EvidenceError("review_request.criteria: duplicate criterion")
    if request.get("decision") not in (None, "PENDING"):
        raise W4EvidenceError("review preparation cannot carry a review decision")
    if request.get("acceptance") not in (None, False):
        raise W4EvidenceError("review preparation cannot carry acceptance")
    receipt_hash = _hash64(receipt.get("receipt_hash"), "receipt.receipt_hash")
    progress_signature = _hash64(receipt.get("progress_signature"), "receipt.progress_signature")
    checkpoint_state_hash = _hash64(checkpoint.get("state_hash"), "checkpoint.state_hash")
    artifact_manifest_hash = _text(artifact_evidence.get("artifact_manifest_hash"), "artifact_evidence.artifact_manifest_hash")
    progress_hash = _hash64(progress.get("last_signature"), "progress.last_signature")
    if progress_hash != progress_signature:
        raise W4EvidenceError("review preparation progress/receipt drift")
    criteria_hash = canonical_hash(criteria)
    core = {
        "schema": REVIEW_PREP_SCHEMA,
        "run_id": _text(run.get("run_id"), "run.run_id"),
        "card_id": _text(card.get("card_id"), "card.card_id"),
        "attempt_id": _text(attempt.get("attempt_id"), "attempt.attempt_id"),
        "card_hash": _text(card.get("card_hash"), "card.card_hash"),
        "artifact_manifest_hash": artifact_manifest_hash,
        "receipt_hash": receipt_hash,
        "progress_signature": progress_signature,
        "checkpoint_state_hash": checkpoint_state_hash,
        "criteria_hash": criteria_hash,
        "review_domain_id": review_domain_id,
        "reviewer_id": reviewer_id,
        "reviewer_session_id": reviewer_session_id,
        "reviewer_backend": reviewer_backend,
        "self_accept": False,
        "decision": "PENDING",
    }
    prep_hash = canonical_hash(core)
    return {
        **core,
        "prep_id": f"w4-prep-{prep_hash}",
        "prep_hash": prep_hash,
        "criteria": list(criteria),
        "accepted": False,
    }
