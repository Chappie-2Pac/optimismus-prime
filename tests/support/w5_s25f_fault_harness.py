"""Test-only deterministic S25F return-ambiguity and interleaving harness.

The helpers deliberately distinguish a simulated uncertain return from a
durability claim.  They may delegate one existing local S25D operation or one
explicit adversarial SQLite write inside an isolated fixture, but they never
repair, resume, reconcile, or publish the resulting state.
"""

from __future__ import annotations

from contextlib import contextmanager
import sqlite3
from typing import Any, Iterator, Mapping
from unittest.mock import patch

from mcp import prime_writes

from modules.w5_dispatch_bridge_s0.recovery_executor import (
    RECOVERY_REQUIRED,
    RecoveryExecutor,
)
from modules.w5_dispatch_bridge_s0.prime_queue_writer import PrimeQueueWriter

from support.w5_s25e_harness import (
    CLAIMED,
    NOT_CLAIMED,
    reopen_read_only,
    snapshot_writer_store,
)


HARNESS_SCHEMA = "prime-queue-durability-fault-harness-v1"
HOLD = "HOLD"
RETURN_AMBIGUOUS = "RETURN_AMBIGUOUS"
REOPEN_INCONCLUSIVE = "REOPEN_INCONCLUSIVE"
FOREIGN_SQLITE_DRIFT = "FOREIGN_SQLITE_DRIFT"
SQLITE_VFS_FAULT_UNAVAILABLE = "SQLITE_VFS_FAULT_UNAVAILABLE"


class _DurableReturnAmbiguousState:
    """Delegate one real marker write, then lose its return value."""

    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate
        self.fired = False

    def durable_new(self, path: Any, payload: bytes) -> None:
        self._delegate.durable_new(path, payload)
        if not self.fired:
            self.fired = True
            raise RuntimeError("SIMULATED_MARKER_RETURN_AMBIGUOUS")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


class _CommitReturnAmbiguousConnection:
    """Delegate commits until explicitly armed at the state-mark boundary."""

    def __init__(self, delegate: sqlite3.Connection) -> None:
        self._delegate = delegate
        self.armed = False
        self.fired = False

    def commit(self) -> None:
        self._delegate.commit()
        if self.armed and not self.fired:
            self.fired = True
            raise RuntimeError("SIMULATED_SQLITE_COMMIT_RETURN_AMBIGUOUS")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


class _CommitAmbiguityExecutor(RecoveryExecutor):
    def __init__(self, writer: PrimeQueueWriter, connection: _CommitReturnAmbiguousConnection) -> None:
        super().__init__(writer)
        self._connection = connection

    def _fault(self, point: str) -> None:
        if point == "before_state_mark":
            self._connection.armed = True
        return super()._fault(point)


class _ForeignWriterExecutor(RecoveryExecutor):
    def __init__(self, writer: PrimeQueueWriter, *, scope_id: str, idempotency_key: str) -> None:
        super().__init__(writer)
        self._scope_id = scope_id
        self._idempotency_key = idempotency_key
        self.injected = False

    def _fault(self, point: str) -> None:
        if point == "before_state_mark" and not self.injected:
            self.injected = True
            connection = sqlite3.connect(str(self.writer.db_path), isolation_level=None, timeout=1.0)
            try:
                connection.execute(
                    "UPDATE prime_queue_writer_operations SET state='COMMITTED' WHERE scope_id=? AND idempotency_key=?",
                    (self._scope_id, self._idempotency_key),
                )
            finally:
                connection.close()
        return super()._fault(point)


def _fault_record(
    *,
    fault_seam: str,
    reason: str,
    observed: Mapping[str, Any] | None,
    foreign_writer: bool = False,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "status": RECOVERY_REQUIRED,
        "reason": reason,
        "fault_seam": fault_seam,
        "observed_s25d_status": observed.get("status") if observed is not None else None,
        "observed_s25d_reason": observed.get("reason") if observed is not None else None,
        "durability_claim": NOT_CLAIMED,
        "foreign_writer_authority": NOT_CLAIMED if foreign_writer else NOT_CLAIMED,
        "reopen_causality": NOT_CLAIMED,
        "cross_store_atomicity": NOT_CLAIMED,
        "foreign_repair_performed": NOT_CLAIMED,
        "automatic_repair_performed": False,
        "observed": dict(observed) if observed is not None else None,
    }


def run_marker_return_ambiguity(
    writer: PrimeQueueWriter,
    *,
    scope_id: str,
    handoff_id: str,
    lease_token: str,
    now: int,
) -> dict[str, Any]:
    """Run public S25D with one marker-return ambiguity, without retrying."""

    delegate = prime_writes._state()
    fault_state = _DurableReturnAmbiguousState(delegate)
    try:
        with patch.object(prime_writes, "_state", return_value=fault_state):
            observed = RecoveryExecutor(writer).resolve(
                scope_id=scope_id,
                handoff_id=handoff_id,
                lease_token=lease_token,
                now=now,
            )
    except Exception as exc:
        observed = {"status": RECOVERY_REQUIRED, "reason": type(exc).__name__, "detail": str(exc)}
    return _fault_record(
        fault_seam="marker_after_durable_new_before_return",
        reason=RETURN_AMBIGUOUS,
        observed=observed,
    )


def run_sqlite_commit_return_ambiguity(
    writer: PrimeQueueWriter,
    *,
    scope_id: str,
    handoff_id: str,
    lease_token: str,
    now: int,
) -> dict[str, Any]:
    """Run public S25D with a post-commit return ambiguity at state mark."""

    delegate = writer.conn
    fault_connection = _CommitReturnAmbiguousConnection(delegate)
    writer.conn = fault_connection  # type: ignore[assignment]
    try:
        try:
            observed = _CommitAmbiguityExecutor(writer, fault_connection).resolve(
                scope_id=scope_id,
                handoff_id=handoff_id,
                lease_token=lease_token,
                now=now,
            )
        except Exception as exc:
            observed = {"status": RECOVERY_REQUIRED, "reason": type(exc).__name__, "detail": str(exc)}
    finally:
        writer.conn = delegate
    return _fault_record(
        fault_seam="sqlite_commit_after_commit_before_return",
        reason=RETURN_AMBIGUOUS,
        observed=observed,
    )


def run_foreign_writer_interleave(
    writer: PrimeQueueWriter,
    *,
    scope_id: str,
    handoff_id: str,
    lease_token: str,
    idempotency_key: str,
    now: int,
) -> dict[str, Any]:
    """Inject one raw SQLite state write immediately before S25D state mark."""

    try:
        observed = _ForeignWriterExecutor(
            writer,
            scope_id=scope_id,
            idempotency_key=idempotency_key,
        ).resolve(
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=now,
        )
    except Exception as exc:
        observed = {"status": RECOVERY_REQUIRED, "reason": type(exc).__name__, "detail": str(exc)}
    return _fault_record(
        fault_seam="foreign_sqlite_after_revalidation_before_state_mark",
        reason=FOREIGN_SQLITE_DRIFT,
        observed=observed,
        foreign_writer=True,
    )


def classify_reopen_snapshot(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    reopen: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify local reopen/readback without making a causal durability claim."""

    queue_drift = before.get("queue_sha256") != after.get("queue_sha256") or before.get("queue_identity") != after.get("queue_identity")
    db_drift = before.get("db", {}).get("tables_sha256") != after.get("db", {}).get("tables_sha256")
    if reopen.get("status") != CLAIMED or queue_drift or db_drift:
        status = RECOVERY_REQUIRED
        reason = "REOPEN_SNAPSHOT_DRIFT"
    else:
        status = NOT_CLAIMED
        reason = REOPEN_INCONCLUSIVE
    return {
        "schema_version": HARNESS_SCHEMA,
        "status": status,
        "reason": reason,
        "durability_claim": NOT_CLAIMED,
        "reopen_causality": NOT_CLAIMED,
        "reopen": dict(reopen),
        "foreign_writer_authority": NOT_CLAIMED,
        "cross_store_atomicity": NOT_CLAIMED,
    }


def capture_reopen_snapshot(writer: PrimeQueueWriter) -> dict[str, Any]:
    """Return an isolated local before/after readback for a caller-owned case."""

    before = snapshot_writer_store(writer)
    reopen = reopen_read_only(writer)
    after = snapshot_writer_store(writer)
    result = classify_reopen_snapshot(before, after, reopen)
    result["before"] = before
    result["after"] = after
    return result


__all__ = [
    "FOREIGN_SQLITE_DRIFT",
    "HOLD",
    "HARNESS_SCHEMA",
    "REOPEN_INCONCLUSIVE",
    "RETURN_AMBIGUOUS",
    "SQLITE_VFS_FAULT_UNAVAILABLE",
    "capture_reopen_snapshot",
    "classify_reopen_snapshot",
    "run_foreign_writer_interleave",
    "run_marker_return_ambiguity",
    "run_sqlite_commit_return_ambiguity",
]
