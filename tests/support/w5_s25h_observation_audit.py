"""Test-only S25H audit gate for consuming S25G observations.

This module is deliberately a pure validator.  It does not observe a writer,
open a file or database, persist a decision, issue a CAS, or create a fence.
Its only purpose is to prevent an underspecified S25G result from being
mistaken for authority by a later consumer.
"""

from __future__ import annotations

from typing import Any, Mapping

from modules.w5_dispatch_bridge_s0.recovery_eligibility import (
    RECOVERY_ELIGIBLE,
    RECOVERY_HOLD,
    RECOVERY_REQUIRED,
)
from support.w5_s25e_harness import CLAIMED, HOLD, NOT_CLAIMED
from support.w5_s25g_quarantine_harness import (
    OBSERVE_ONLY as S25G_OBSERVE_ONLY,
    QUARANTINE_NOT_REQUIRED,
    QUARANTINE_REQUIRED,
)


HARNESS_SCHEMA = "prime-queue-authority-decision-v1"
S25G_SCHEMA = "prime-queue-quarantine-observer-v1"
S25G_ELIGIBILITY_SCHEMA = "prime-queue-recovery-eligibility-v1"
S25G_ELIGIBILITY_ROLE = "prime_queue_recovery_eligibility_read_only"
MANUAL_QUARANTINE_REVIEW = "MANUAL_QUARANTINE_REVIEW"
PERSISTENCE_NOT_AUTHORIZED = "PERSISTENCE_NOT_AUTHORIZED"
READBACK_ONLY = "READBACK_ONLY"
CAS_NOT_ATTEMPTED = "CAS_NOT_ATTEMPTED"
FENCE_OBSERVED_AT_SNAPSHOT = "OBSERVED_AT_SNAPSHOT"


def _output(
    status: str,
    decision: str,
    reason: str,
    *,
    gaps: list[str],
    local_evidence: str = NOT_CLAIMED,
    persistence_claim: str = NOT_CLAIMED,
    fence_observation: str = NOT_CLAIMED,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": S25G_OBSERVE_ONLY,
        "status": status,
        "decision": decision,
        "reason": reason,
        "audit_gaps": list(gaps),
        "local_evidence": local_evidence,
        "persistence_claim": persistence_claim,
        "authority_claim": NOT_CLAIMED,
        "cas_claim": CAS_NOT_ATTEMPTED,
        "fence_observation": fence_observation,
        "fence_authority": NOT_CLAIMED,
        "persistence_allowed": False,
        "cas_allowed": False,
        "fence_issue_allowed": False,
        "quarantine_written": False,
        "recovery_authority": False,
        "resume_allowed": False,
        "mutation_allowed": False,
        "cross_store_atomicity": NOT_CLAIMED,
        "foreign_writer_identity": NOT_CLAIMED,
    }


def _claimed_gaps(
    observation: Mapping[str, Any],
    *,
    expected_scope_id: str,
    expected_handoff_id: str,
) -> list[str]:
    gaps: list[str] = []
    if observation.get("schema_version") != S25G_SCHEMA:
        gaps.append("S25G_SCHEMA_UNVERIFIED")
    if observation.get("observation_mode") != S25G_OBSERVE_ONLY:
        gaps.append("S25G_OBSERVATION_MODE_UNVERIFIED")
    if observation.get("status") != CLAIMED:
        gaps.append("S25G_STATUS_NOT_CLAIMED")
    if observation.get("decision") != QUARANTINE_NOT_REQUIRED:
        gaps.append("S25G_DECISION_NOT_LOCAL_ONLY")
    if observation.get("evidence_status") != RECOVERY_ELIGIBLE:
        gaps.append("S25G_ELIGIBILITY_NOT_POSITIVE")
    if observation.get("claim_scope") != "LOCAL_READ_ONLY_BOUNDARY_EVIDENCE":
        gaps.append("S25G_CLAIM_SCOPE_UNVERIFIED")
    if observation.get("drift") != []:
        gaps.append("S25G_DRIFT_PRESENT")
    if observation.get("evidence_gaps") != []:
        gaps.append("S25G_EVIDENCE_GAPS_PRESENT")
    if not observation.get("before_digest") or observation.get("before_digest") != observation.get("after_digest"):
        gaps.append("S25G_BOUNDARY_DIGEST_UNSTABLE")
    if not isinstance(observation.get("db_before_identity"), Mapping):
        gaps.append("S25G_DB_BEFORE_IDENTITY_MISSING")
    if not isinstance(observation.get("db_after_identity"), Mapping):
        gaps.append("S25G_DB_AFTER_IDENTITY_MISSING")
    if observation.get("db_before_identity") != observation.get("db_after_identity"):
        gaps.append("S25G_DB_IDENTITY_DRIFT")

    reopen = observation.get("reopen")
    if not isinstance(reopen, Mapping):
        gaps.append("S25G_REOPEN_MISSING")
    else:
        if reopen.get("status") != CLAIMED:
            gaps.append("S25G_REOPEN_NOT_CLAIMED")
        if reopen.get("claim_scope") != "READABILITY_SCHEMA_INTEGRITY_ONLY":
            gaps.append("S25G_REOPEN_SCOPE_UNVERIFIED")
        if reopen.get("journal_mode") != "wal":
            gaps.append("S25G_REOPEN_JOURNAL_MODE_UNVERIFIED")
        if reopen.get("synchronous") != 2:
            gaps.append("S25G_REOPEN_SYNCHRONOUS_UNVERIFIED")
        if reopen.get("integrity_check") != "ok":
            gaps.append("S25G_REOPEN_INTEGRITY_UNVERIFIED")
        if reopen.get("foreign_key_check") != []:
            gaps.append("S25G_REOPEN_FOREIGN_KEY_UNVERIFIED")

    eligibility = observation.get("eligibility")
    if not isinstance(eligibility, Mapping):
        gaps.append("S25G_ELIGIBILITY_MISSING")
        return gaps
    if eligibility.get("schema_version") != S25G_ELIGIBILITY_SCHEMA:
        gaps.append("S25C_SCHEMA_UNVERIFIED")
    if eligibility.get("contract_role") != S25G_ELIGIBILITY_ROLE:
        gaps.append("S25C_ROLE_UNVERIFIED")
    if eligibility.get("decision") != "RECOVERY_ELIGIBILITY_ONLY":
        gaps.append("S25C_DECISION_UNVERIFIED")
    if eligibility.get("status") != RECOVERY_ELIGIBLE:
        gaps.append("S25C_STATUS_NOT_ELIGIBLE")
    if eligibility.get("scope_id") != expected_scope_id:
        gaps.append("S25C_SCOPE_BINDING_MISMATCH")
    if eligibility.get("handoff_id") != expected_handoff_id:
        gaps.append("S25C_HANDOFF_BINDING_MISMATCH")
    if eligibility.get("operation_state") == "QUARANTINED":
        gaps.append("QUARANTINE_STATE_PRESENT")
    for key in (
        "read_only",
        "snapshot_verified",
        "recovery_eligible",
        "handoff_event_verified",
        "root_scope_claim_verified",
        "operation_verified",
        "marker_verified",
        "transaction_verified",
        "queue_hash_verified",
        "fence_verified",
        "lease_verified",
        "queue_read_stable",
    ):
        if eligibility.get(key) is not True:
            gaps.append(f"S25C_{key.upper()}_NOT_VERIFIED")
    for key in (
        "recovery_authority",
        "recovery_allowed",
        "recovery_execution_allowed",
        "recovery_started",
        "resume_allowed",
        "mutation_allowed",
        "mutation_performed",
        "queue_mutation_performed",
        "marker_write_performed",
        "receipt_emitted",
        "receipt_committed",
        "consume_allowed",
        "global_commit",
    ):
        if eligibility.get(key) is not False:
            gaps.append(f"S25C_{key.upper()}_NOT_FALSE")
    if eligibility.get("cross_store_atomicity") != NOT_CLAIMED:
        gaps.append("S25C_CROSS_STORE_NOT_CLAIMED")

    for key in (
        "recovery_authority",
        "quarantine_authority",
        "mutation_allowed",
        "resume_allowed",
        "quarantine_written",
    ):
        if observation.get(key) is not False:
            gaps.append(f"S25G_{key.upper()}_NOT_FALSE")
    for key in (
        "foreign_writer_authority",
        "sqlite_writer_authority",
        "boundary_coherence",
        "reopen_causality",
        "cross_store_atomicity",
    ):
        if observation.get(key) != NOT_CLAIMED:
            gaps.append(f"S25G_{key.upper()}_NOT_CLAIMED")
    return gaps


def audit_quarantine_observation(
    observation: Mapping[str, Any],
    *,
    expected_scope_id: str,
    expected_handoff_id: str,
) -> dict[str, Any]:
    """Validate one S25G result without granting persistence authority."""

    if not isinstance(observation, Mapping):
        return _output(RECOVERY_REQUIRED, MANUAL_QUARANTINE_REVIEW, "OBSERVATION_NOT_MAPPING", gaps=["OBSERVATION_TYPE"])
    status = observation.get("status")
    if observation.get("quarantine_written") is True:
        return _output(
            RECOVERY_REQUIRED,
            MANUAL_QUARANTINE_REVIEW,
            "UNEXPECTED_QUARANTINE_WRITE_CLAIM",
            gaps=["S25G_QUARANTINE_WRITE_CLAIM"],
        )
    if status == HOLD:
        return _output(HOLD, HOLD, str(observation.get("reason", "S25G_HOLD")), gaps=[])
    if status == NOT_CLAIMED:
        return _output(NOT_CLAIMED, OBSERVE_ONLY, "S25G_NOT_CLAIMED", gaps=[])
    if status == RECOVERY_REQUIRED:
        return _output(RECOVERY_REQUIRED, MANUAL_QUARANTINE_REVIEW, "S25G_QUARANTINE_REQUIRED", gaps=[])
    if status != CLAIMED:
        return _output(RECOVERY_REQUIRED, MANUAL_QUARANTINE_REVIEW, "S25G_STATUS_INVALID", gaps=["S25G_STATUS"])
    if not expected_scope_id or not expected_handoff_id:
        return _output(RECOVERY_REQUIRED, MANUAL_QUARANTINE_REVIEW, "TARGET_BINDING_MISSING", gaps=["TARGET_BINDING"])

    gaps = _claimed_gaps(
        observation,
        expected_scope_id=expected_scope_id,
        expected_handoff_id=expected_handoff_id,
    )
    if gaps:
        return _output(RECOVERY_REQUIRED, MANUAL_QUARANTINE_REVIEW, "S25G_CLAIM_NOT_CONSUMABLE", gaps=gaps)
    return _output(
        CLAIMED,
        PERSISTENCE_NOT_AUTHORIZED,
        "LOCAL_READ_ONLY_EVIDENCE_ONLY",
        gaps=[],
        local_evidence=CLAIMED,
        persistence_claim=READBACK_ONLY,
        fence_observation=FENCE_OBSERVED_AT_SNAPSHOT,
    )


__all__ = [
    "CAS_NOT_ATTEMPTED",
    "FENCE_OBSERVED_AT_SNAPSHOT",
    "HARNESS_SCHEMA",
    "MANUAL_QUARANTINE_REVIEW",
    "PERSISTENCE_NOT_AUTHORIZED",
    "READBACK_ONLY",
    "audit_quarantine_observation",
]
