"""Test-only read-only Foreign-Writer/Quarantine decision observer."""

from __future__ import annotations

import hashlib
from pathlib import Path
import stat
from typing import Any, Mapping

from modules.w5_dispatch_bridge_s0.recovery_eligibility import (
    RECOVERY_ELIGIBLE,
    RECOVERY_ELIGIBILITY_ROLE,
    RECOVERY_ELIGIBILITY_SCHEMA,
    RECOVERY_HOLD,
    RECOVERY_REQUIRED,
    evaluate_recovery_eligibility,
)

from support.w5_s25e_harness import (
    CLAIMED,
    HOLD,
    NOT_CLAIMED,
    reopen_read_only,
    snapshot_writer_store,
)


HARNESS_SCHEMA = "prime-queue-quarantine-observer-v1"
QUARANTINE_REQUIRED = "QUARANTINE_REQUIRED"
QUARANTINE_NOT_REQUIRED = "QUARANTINE_NOT_REQUIRED_FOR_OBSERVED_SNAPSHOT"
OBSERVE_ONLY = "OBSERVE_ONLY"


def path_identity(path: Path) -> dict[str, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "link_count": int(info.st_nlink),
        "size": int(info.st_size),
        "mode": int(stat.S_IMODE(info.st_mode)),
    }


def _projection_digest(snapshot: Mapping[str, Any]) -> str:
    return hashlib.sha256(repr(snapshot).encode("utf-8")).hexdigest()


def _drift(before: Mapping[str, Any], after: Mapping[str, Any], before_db: Any, after_db: Any) -> list[str]:
    reasons: list[str] = []
    if before.get("queue_sha256") != after.get("queue_sha256"):
        reasons.append("QUEUE_CONTENT_DRIFT")
    if before.get("queue_identity") != after.get("queue_identity"):
        reasons.append("QUEUE_IDENTITY_DRIFT")
    if before.get("lock_identity") != after.get("lock_identity"):
        reasons.append("LOCK_IDENTITY_DRIFT")
    if before_db != after_db:
        reasons.append("DB_IDENTITY_DRIFT")
    if before.get("db", {}).get("tables_sha256") != after.get("db", {}).get("tables_sha256"):
        reasons.append("DB_PROJECTION_DRIFT")
    if before.get("transactions") != after.get("transactions"):
        reasons.append("TRANSACTION_PROJECTION_DRIFT")
    return reasons


def _positive_evidence_gaps(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    db_before: Mapping[str, int] | None,
    db_after: Mapping[str, int] | None,
    eligibility: Mapping[str, Any],
    reopen: Mapping[str, Any],
) -> list[str]:
    """Return missing positive-evidence fields instead of inferring them."""

    gaps: list[str] = []
    snapshot_keys = ("queue_sha256", "queue_identity", "queue_size", "lock_identity", "db", "transactions")
    db_keys = (
        "tables_sha256",
        "journal_mode",
        "synchronous",
        "integrity_check",
        "foreign_key_check",
        "row_counts",
    )
    for label, snapshot in (("BEFORE", before), ("AFTER", after)):
        for key in snapshot_keys:
            if key not in snapshot:
                gaps.append(f"{label}_MISSING_{key.upper()}")
        projection = snapshot.get("db")
        if not isinstance(projection, Mapping):
            gaps.append(f"{label}_MISSING_DB_PROJECTION")
        else:
            for key in db_keys:
                if key not in projection:
                    gaps.append(f"{label}_MISSING_DB_{key.upper()}")
        if snapshot.get("queue_sha256") is None:
            gaps.append(f"{label}_MISSING_QUEUE_DIGEST")
        if snapshot.get("queue_identity") is None:
            gaps.append(f"{label}_MISSING_QUEUE_IDENTITY")
        if snapshot.get("lock_identity") is None:
            gaps.append(f"{label}_MISSING_LOCK_IDENTITY")
    identity_keys = ("device", "inode", "link_count", "size", "mode")
    for label, identity in (("DB_BEFORE", db_before), ("DB_AFTER", db_after)):
        if not isinstance(identity, Mapping):
            gaps.append(f"{label}_MISSING_IDENTITY")
        else:
            for key in identity_keys:
                if key not in identity:
                    gaps.append(f"{label}_MISSING_{key.upper()}")

    if eligibility.get("schema_version") != RECOVERY_ELIGIBILITY_SCHEMA:
        gaps.append("ELIGIBILITY_SCHEMA_UNVERIFIED")
    if eligibility.get("contract_role") != RECOVERY_ELIGIBILITY_ROLE:
        gaps.append("ELIGIBILITY_ROLE_UNVERIFIED")
    required_true = (
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
    )
    for key in required_true:
        if eligibility.get(key) is not True:
            gaps.append(f"ELIGIBILITY_{key.upper()}_NOT_VERIFIED")
    required_false = (
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
    )
    for key in required_false:
        if eligibility.get(key) is not False:
            gaps.append(f"ELIGIBILITY_{key.upper()}_NOT_FALSE")
    if eligibility.get("cross_store_atomicity") != NOT_CLAIMED:
        gaps.append("ELIGIBILITY_CROSS_STORE_NOT_CLAIMED")
    for key in ("scope_id", "handoff_id", "transaction_id", "idempotency_key", "queue_sha256"):
        if not eligibility.get(key):
            gaps.append(f"ELIGIBILITY_MISSING_{key.upper()}")
    if eligibility.get("operation_state") == "QUARANTINED":
        gaps.append("ALREADY_QUARANTINED_STATE")

    reopen_keys = (
        "status",
        "claim_scope",
        "journal_mode",
        "synchronous",
        "integrity_check",
        "foreign_key_check",
        "tables",
        "indexes",
        "triggers",
    )
    for key in reopen_keys:
        if key not in reopen:
            gaps.append(f"REOPEN_MISSING_{key.upper()}")
    if reopen.get("claim_scope") != "READABILITY_SCHEMA_INTEGRITY_ONLY":
        gaps.append("REOPEN_SCOPE_UNVERIFIED")
    if reopen.get("journal_mode") != "wal":
        gaps.append("REOPEN_JOURNAL_MODE_UNVERIFIED")
    if reopen.get("synchronous") != 2:
        gaps.append("REOPEN_SYNCHRONOUS_UNVERIFIED")
    if reopen.get("integrity_check") != "ok":
        gaps.append("REOPEN_INTEGRITY_UNVERIFIED")
    if reopen.get("foreign_key_check") != []:
        gaps.append("REOPEN_FOREIGN_KEY_UNVERIFIED")
    return gaps


def classify_quarantine_boundary(
    *,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    db_before: Mapping[str, int] | None,
    db_after: Mapping[str, int] | None,
    eligibility: Mapping[str, Any],
    reopen: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify caller-supplied read-only evidence without mutating it."""

    drift = _drift(before, after, db_before, db_after)
    evidence_status = eligibility.get("status")
    gaps: list[str] = []
    if evidence_status == RECOVERY_HOLD:
        status = HOLD
        decision = HOLD
        reason = str(eligibility.get("reason", "RECOVERY_HOLD"))
    elif evidence_status != RECOVERY_ELIGIBLE:
        status = RECOVERY_REQUIRED
        decision = QUARANTINE_REQUIRED
        reason = str(eligibility.get("reason", "RECOVERY_REQUIRED"))
    elif drift:
        status = RECOVERY_REQUIRED
        decision = QUARANTINE_REQUIRED
        reason = "BOUNDARY_DRIFT_AFTER_ELIGIBILITY"
    elif reopen.get("status") != CLAIMED:
        status = RECOVERY_REQUIRED
        decision = QUARANTINE_REQUIRED
        reason = "REOPEN_NOT_STABLE"
    elif (gaps := _positive_evidence_gaps(before, after, db_before, db_after, eligibility, reopen)):
        status = RECOVERY_REQUIRED
        decision = QUARANTINE_REQUIRED
        reason = "INCOMPLETE_POSITIVE_EVIDENCE"
    else:
        status = CLAIMED
        decision = QUARANTINE_NOT_REQUIRED
        reason = "LOCAL_EVIDENCE_COHERENT_ONLY"
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVE_ONLY,
        "status": status,
        "decision": decision,
        "reason": reason,
        "evidence_status": evidence_status,
        "evidence_reason": eligibility.get("reason"),
        "eligibility": dict(eligibility),
        "before_digest": _projection_digest(before),
        "after_digest": _projection_digest(after),
        "drift": drift,
        "evidence_gaps": gaps if evidence_status == RECOVERY_ELIGIBLE else [],
        "reopen": dict(reopen),
        "db_before_identity": db_before,
        "db_after_identity": db_after,
        "claim_scope": "LOCAL_READ_ONLY_BOUNDARY_EVIDENCE" if status == CLAIMED else None,
        "recovery_authority": False,
        "quarantine_authority": False,
        "mutation_allowed": False,
        "resume_allowed": False,
        "automatic_repair_performed": False,
        "foreign_writer_authority": NOT_CLAIMED,
        "sqlite_writer_authority": NOT_CLAIMED,
        "lock_inode_aba": NOT_CLAIMED,
        "queue_path_aba": NOT_CLAIMED,
        "cross_store_atomicity": NOT_CLAIMED,
        "foreign_repair_performed": NOT_CLAIMED,
        "boundary_coherence": NOT_CLAIMED,
        "reopen_causality": NOT_CLAIMED,
        "quarantine_written": False,
    }


def observe_quarantine_boundary(
    writer: Any,
    *,
    scope_id: str,
    handoff_id: str,
    lease_token: str,
    now: int,
) -> dict[str, Any]:
    """Combine public S25C evidence with independent read-only projections."""

    before = snapshot_writer_store(writer)
    db_before = path_identity(writer.db_path)
    try:
        eligibility = evaluate_recovery_eligibility(
            writer,
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=now,
        )
    except Exception as exc:
        eligibility = {"status": RECOVERY_REQUIRED, "reason": f"OBSERVER_EVALUATION_{type(exc).__name__}"}
    after = snapshot_writer_store(writer)
    db_after = path_identity(writer.db_path)
    return classify_quarantine_boundary(
        before=before,
        after=after,
        db_before=db_before,
        db_after=db_after,
        eligibility=eligibility,
        reopen=reopen_read_only(writer),
    )


__all__ = [
    "HARNESS_SCHEMA",
    "OBSERVE_ONLY",
    "QUARANTINE_NOT_REQUIRED",
    "QUARANTINE_REQUIRED",
    "classify_quarantine_boundary",
    "observe_quarantine_boundary",
    "path_identity",
]
