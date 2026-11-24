"""Pure S25I design-time validator for an unimplemented authority proposal.

The proposal is treated as untrusted input.  A complete proposal can be
classified as design-only, but this module never verifies a signature, issues
a fence, attempts a CAS, or persists a quarantine decision.
"""

from __future__ import annotations

from typing import Any, Mapping


HARNESS_SCHEMA = "prime-queue-authority-boundary-v1"
OBSERVE_ONLY = "OBSERVE_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
MANUAL_REVIEW = "MANUAL_REVIEW"
CAS_NOT_ATTEMPTED = "CAS_NOT_ATTEMPTED"
FENCE_NOT_ISSUED = "FENCE_NOT_ISSUED"
HOLD = "HOLD"
NOT_CLAIMED = "NOT_CLAIMED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"

_REQUIRED_FIELDS = (
    "authority_id",
    "authority_key_id",
    "authority_sequence",
    "grant_id",
    "action",
    "root_binding",
    "store_instance_id",
    "authority_store_id",
    "scope_id",
    "transaction_id",
    "idempotency_key",
    "observation_digest",
    "observation_id",
    "expected_subject_generation",
    "expected_event_head",
    "expected_handoff_head",
    "expected_subject_fence",
    "lease_id",
    "not_before",
    "expires_at",
    "allowed_transition",
)
_DANGER_FLAGS = (
    "generation_reused",
    "aba_detected",
    "foreign_writer_observed",
    "reopen_gap",
    "cas_precondition_mismatch",
)


def _output(status: str, decision: str, reason: str, *, gaps: list[str], complete: bool = False) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVE_ONLY,
        "status": status,
        "decision": decision,
        "reason": reason,
        "audit_gaps": list(gaps),
        "proposal_complete": complete,
        "authority_claim": NOT_CLAIMED,
        "signature_claim": NOT_CLAIMED,
        "cas_claim": CAS_NOT_ATTEMPTED,
        "fence_authority": NOT_CLAIMED,
        "fence_observation": FENCE_NOT_ISSUED,
        "write_authorized": False,
        "cas_attempted": False,
        "fence_issued": False,
        "quarantine_persisted": False,
        "recovery_authority": False,
        "resume_allowed": False,
        "mutation_allowed": False,
        "cross_store_atomicity": NOT_CLAIMED,
        "foreign_writer_identity": NOT_CLAIMED,
    }


def evaluate_authority_proposal(proposal: Mapping[str, Any], *, now: int) -> dict[str, Any]:
    """Classify a proposed authority contract without implementing authority."""

    if not isinstance(proposal, Mapping):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "PROPOSAL_NOT_MAPPING", gaps=["PROPOSAL_TYPE"])
    missing = [key for key in _REQUIRED_FIELDS if not proposal.get(key)]
    if missing:
        return _output(
            RECOVERY_REQUIRED,
            MANUAL_REVIEW,
            "PROPOSAL_INCOMPLETE",
            gaps=[f"MISSING_{key.upper()}" for key in missing],
        )
    if proposal.get("action") != "PERSIST_QUARANTINE":
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "ACTION_NOT_NARROW", gaps=["ACTION"])
    if proposal.get("authority_store_id") == proposal.get("store_instance_id"):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "AUTHORITY_NOT_INDEPENDENT", gaps=["SAME_AUTHORITY_STORE"])
    try:
        authority_sequence = int(proposal["authority_sequence"])
    except (TypeError, ValueError):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "AUTHORITY_SEQUENCE_INVALID", gaps=["AUTHORITY_SEQUENCE"])
    if authority_sequence <= 0:
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "AUTHORITY_SEQUENCE_INVALID", gaps=["AUTHORITY_SEQUENCE"])
    try:
        not_before = int(proposal["not_before"])
        expires_at = int(proposal["expires_at"])
    except (TypeError, ValueError):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "LEASE_WINDOW_INVALID", gaps=["LEASE_WINDOW"])
    if expires_at <= not_before:
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "LEASE_WINDOW_INVALID", gaps=["LEASE_ORDER"])
    if int(now) < not_before or int(now) >= expires_at:
        return _output(HOLD, HOLD, "AUTHORITY_LEASE_NOT_CURRENT", gaps=["LEASE_FRESHNESS"])
    transition = proposal.get("allowed_transition")
    if transition != {
        "from": ["PREPARED", "IN_DOUBT", "RECOVERY_REQUIRED"],
        "to": "QUARANTINED",
    }:
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "TRANSITION_NOT_NARROW", gaps=["ALLOWED_TRANSITION"])
    generation = proposal.get("expected_subject_generation")
    if not isinstance(generation, Mapping):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "GENERATION_PROOF_MISSING", gaps=["GENERATION_MAPPING"])
    for key in ("db_identity", "queue_identity", "event_head", "handoff_head", "fencing_epoch"):
        if not generation.get(key):
            return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "GENERATION_PROOF_INCOMPLETE", gaps=[f"GENERATION_{key.upper()}"])
    subject_fence = proposal.get("expected_subject_fence")
    if not isinstance(subject_fence, Mapping):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "FENCE_PROOF_MISSING", gaps=["FENCE_MAPPING"])
    for key in ("owner_epoch", "fencing_epoch", "lease_token_sha256"):
        if not subject_fence.get(key):
            return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "FENCE_PROOF_INCOMPLETE", gaps=[f"FENCE_{key.upper()}"])
    for flag in _DANGER_FLAGS:
        if proposal.get(flag) is True:
            return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, f"{flag.upper()}_DETECTED", gaps=[flag.upper()])
    if proposal.get("signature_valid") is True or proposal.get("authority_signature"):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "SIGNATURE_UNVERIFIED", gaps=["SIGNATURE_VERIFIER_ABSENT"])
    return _output(
        NOT_CLAIMED,
        DESIGN_ONLY,
        "INDEPENDENT_AUTHORITY_NOT_IMPLEMENTED",
        gaps=[],
        complete=True,
    )


__all__ = [
    "CAS_NOT_ATTEMPTED",
    "DESIGN_ONLY",
    "FENCE_NOT_ISSUED",
    "HARNESS_SCHEMA",
    "HOLD",
    "MANUAL_REVIEW",
    "NOT_CLAIMED",
    "RECOVERY_REQUIRED",
    "evaluate_authority_proposal",
]
