"""W5-S25D bounded executor for an accepted local Queue recovery handoff.

The executor is intentionally a separate orchestration boundary.  It uses
one already-open :class:`PrimeQueueWriter`, the existing queue lock and the
read-only S25C evidence contract.  It never starts a normal execution phase,
replaces ``QUEUE.json``, opens another writer, or touches a receipt, ledger,
projection or consume store.

Every recovery mutation is preceded by a fresh S25C revalidation while the
exclusive queue lock remains held.  The lock is retained from the first
revalidation through the local transaction marker and SQLite state marker so
cooperating handoffs cannot enter between those boundaries.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Mapping

from modules.w4_small_loop_s0 import canonical_hash

from .prime_queue_writer import (
    QUEUE_MUTATION_FALSE,
    QUEUE_MUTATION_TRUE,
    QUEUE_MUTATION_UNKNOWN,
    PrimeQueueWriter,
    PrimeQueueWriterError,
)
from .recovery_eligibility import (
    RECOVERY_ELIGIBLE,
    RecoveryEligibilityPreflight,
)


RECOVERY_EXECUTOR_SCHEMA = "prime-queue-recovery-executor-v1"
RECOVERY_EXECUTOR_ROLE = "prime_queue_recovery_executor_accepted_handoff_only"
RECOVERY_COMMITTED = "RECOVERY_COMMITTED"
RECOVERY_ABORTED = "RECOVERY_ABORTED"
RECOVERY_REPLAYED = "REPLAYED"
RECOVERY_HOLD = "HOLD"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
RECOVERY_EXECUTOR_FAULT_POINTS = frozenset(
    {
        "before_claim",
        "after_claim",
        "before_terminal_marker",
        "after_terminal_marker",
        "before_state_mark",
        "after_state_mark",
    }
)


class RecoveryExecutorError(ValueError):
    """Invalid executor input or a failed closed local recovery check."""


class InjectedRecoveryExecutorCrash(RuntimeError):
    """Deterministic test-only crash at an S25D mutation boundary."""

    def __init__(self, point: str) -> None:
        self.point = point
        super().__init__(point)


class _QueueLockUnavailable(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class _ExecutionStop(Exception):
    def __init__(self, result: Mapping[str, Any]) -> None:
        self.result = dict(result)
        super().__init__(str(result.get("reason", "RECOVERY_REVALIDATION_FAILED")))


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RecoveryExecutorError(f"{label}_INVALID")
    return value


def _now_value(value: Any, label: str = "now") -> int:
    if type(value) is not int or value < 0:
        raise RecoveryExecutorError(f"{label}_INVALID")
    return value


class RecoveryExecutor:
    """Execute only the local recovery contract of one accepted handoff."""

    def __init__(
        self,
        writer: PrimeQueueWriter,
        *,
        clock: Any | None = None,
        fault_points: set[str] | frozenset[str] | None = None,
    ) -> None:
        if not isinstance(writer, PrimeQueueWriter):
            raise RecoveryExecutorError("WRITER_INVALID")
        if clock is not None and not callable(clock):
            raise RecoveryExecutorError("CLOCK_INVALID")
        points = set(fault_points or ())
        if not points.issubset(RECOVERY_EXECUTOR_FAULT_POINTS):
            raise RecoveryExecutorError("FAULT_POINT_INVALID")
        self.writer = writer
        self.clock = clock or writer.clock
        self.fault_points = points
        self.preflight = RecoveryEligibilityPreflight(writer, clock=self.clock)
        self._stages: list[dict[str, Any]] = []
        self._last_preflight: dict[str, Any] | None = None
        self._started = False
        self._state_written = False
        self._transaction_marker_written = False
        self._historical_queue_evidence = QUEUE_MUTATION_UNKNOWN
        self._initial_now: int | None = None
        self._initial_now_consumed = False

    @contextmanager
    def _exclusive_queue_lock(self) -> Iterator[int]:
        """Borrow the existing lock file without creating any artifact."""

        control = self.writer.root / "Plan" / "local-ai" / "control"
        lock_path = control / "queue.lock"
        if (
            control.is_symlink()
            or not control.is_dir()
            or lock_path.is_symlink()
            or not lock_path.is_file()
        ):
            raise _QueueLockUnavailable("QUEUE_LOCK_NOT_AVAILABLE")
        fd: int | None = None
        try:
            fd = os.open(str(lock_path), os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            raise _QueueLockUnavailable("QUEUE_LOCK_NOT_AVAILABLE") from exc
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise _QueueLockUnavailable("QUEUE_WRITER_ACTIVE") from exc
            except OSError as exc:
                raise _QueueLockUnavailable("QUEUE_LOCK_NOT_AVAILABLE") from exc
            yield fd
        finally:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _now_for_check(self) -> int | None:
        if self._initial_now is not None and not self._initial_now_consumed:
            self._initial_now_consumed = True
            return self._initial_now
        return None

    def _fault(self, point: str) -> None:
        if point in self.fault_points:
            raise InjectedRecoveryExecutorCrash(point)

    def _revalidate(
        self,
        *,
        stage: str,
        scope_id: str,
        handoff_id: str,
        lease_token: str,
    ) -> dict[str, Any]:
        result = self.preflight._evaluate_borrowed_lock(
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=self._now_for_check(),
        )
        self._last_preflight = result
        self._stages.append(
            {
                "stage": stage,
                "status": result.get("status"),
                "reason": result.get("reason"),
                "transaction_state": result.get("transaction_state"),
                "queue_sha256": result.get("queue_sha256"),
            }
        )
        if result.get("status") != RECOVERY_ELIGIBLE:
            raise _ExecutionStop(result)
        return result

    @staticmethod
    def _fence_from_preflight(result: Mapping[str, Any], lease_token: str) -> dict[str, Any]:
        required = ("owner_id", "owner_instance_id", "owner_epoch", "fencing_epoch")
        if any(result.get(key) is None for key in required):
            raise PrimeQueueWriterError("RECOVERY_FENCE_EVIDENCE_MISSING")
        return {
            "owner_id": result["owner_id"],
            "owner_instance_id": result["owner_instance_id"],
            "owner_epoch": int(result["owner_epoch"]),
            "fencing_epoch": int(result["fencing_epoch"]),
            "lease_token": lease_token,
        }

    @staticmethod
    def _terminal_marker_is_bound(cursor: Any, row: Mapping[str, Any]) -> None:
        markers = cursor.execute(
            "SELECT * FROM prime_queue_writer_markers WHERE scope_id=? AND idempotency_key=?",
            (row["scope_id"], row["idempotency_key"]),
        ).fetchall()
        terminal = [marker for marker in markers if marker["marker_kind"] == row["state"]]
        if len(terminal) != 1:
            raise PrimeQueueWriterError("REPLAY_TERMINAL_MARKER_INVALID")
        marker = terminal[0]
        try:
            payload = json.loads(marker["payload_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PrimeQueueWriterError("REPLAY_TERMINAL_MARKER_INVALID") from exc
        if not isinstance(payload, Mapping) or canonical_hash(payload) != marker["marker_hash"]:
            raise PrimeQueueWriterError("REPLAY_TERMINAL_MARKER_INVALID")
        if payload.get("intent_sha256") != row["intent_sha256"] or payload.get("state") != row["state"]:
            raise PrimeQueueWriterError("REPLAY_TERMINAL_MARKER_UNBOUND")
        expected_queue = (
            row["after_queue_sha256"]
            if row["state"] == "COMMITTED"
            else row["expected_queue_sha256"]
        )
        if payload.get("queue_sha256") != expected_queue:
            raise PrimeQueueWriterError("REPLAY_TERMINAL_MARKER_UNBOUND")

    def _terminal_replay(
        self,
        *,
        scope_id: str,
        handoff_id: str,
        lease_token: str,
    ) -> dict[str, Any] | None:
        """Read back a completed local recovery without starting a new one."""

        try:
            with self.writer._read_transaction() as cursor:
                RecoveryEligibilityPreflight._assert_schema(cursor)
                scope = self.writer._scope_row(cursor, scope_id)
                self.writer._assert_scope_integrity(cursor, scope)
                RecoveryEligibilityPreflight._assert_handoff_event_chain(cursor, scope_id)
                handoff = cursor.execute(
                    "SELECT * FROM prime_queue_writer_handoff_events WHERE scope_id=? AND handoff_id=?",
                    (scope_id, handoff_id),
                ).fetchone()
                if handoff is None:
                    return None
                latest = cursor.execute(
                    "SELECT handoff_id FROM prime_queue_writer_handoff_events WHERE scope_id=? ORDER BY handoff_seq DESC LIMIT 1",
                    (scope_id,),
                ).fetchone()
                if latest is None or latest["handoff_id"] != handoff_id:
                    return None
                operation = cursor.execute(
                    "SELECT * FROM prime_queue_writer_operations WHERE scope_id=? AND transaction_id=? AND idempotency_key=?",
                    (scope_id, handoff["transaction_id"], handoff["idempotency_key"]),
                ).fetchone()
                if operation is None or operation["state"] not in {"COMMITTED", "ABORTED"}:
                    return None
                try:
                    payload = json.loads(handoff["payload_json"])
                    intent = json.loads(operation["operation_json"])
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise PrimeQueueWriterError("REPLAY_BINDING_INVALID") from exc
                if not isinstance(payload, Mapping) or not isinstance(intent, Mapping):
                    raise PrimeQueueWriterError("REPLAY_BINDING_INVALID")
                target = payload.get("target")
                if (
                    handoff["event_type"] != "HANDOFF_ACCEPTED_RECOVERY"
                    or payload.get("event_type") != "HANDOFF_ACCEPTED_RECOVERY"
                    or payload.get("handoff_id") != handoff_id
                    or payload.get("transaction_id") != operation["transaction_id"]
                    or payload.get("idempotency_key") != operation["idempotency_key"]
                    or payload.get("intent_sha256") != operation["intent_sha256"]
                    or not isinstance(target, Mapping)
                    or target.get("root_binding_sha256") != scope["root_binding_sha256"]
                    or target.get("owner_id") != scope["owner_id"]
                    or target.get("owner_instance_id") != scope["owner_instance_id"]
                    or int(target.get("owner_epoch", -1)) != int(scope["owner_epoch"])
                    or int(target.get("fencing_epoch", -1)) != int(scope["fencing_epoch"])
                    or target.get("lease_token_sha256") != scope["lease_token_sha256"]
                    or int(target.get("lease_expires_at", -1)) != int(scope["lease_expires_at"])
                ):
                    raise PrimeQueueWriterError("REPLAY_HANDOFF_BINDING_DRIFT")
                replay_evidence = {
                    "status": "REPLAY_REVALIDATED",
                    "scope_id": scope_id,
                    "handoff_id": handoff_id,
                    "transaction_id": operation["transaction_id"],
                    "idempotency_key": operation["idempotency_key"],
                    "handoff_seq": int(handoff["handoff_seq"]),
                    "handoff_event_sha256": handoff["event_sha256"],
                    "grant_sha256": handoff["grant_sha256"],
                    "observation_sha256": handoff["observation_sha256"],
                    "owner_id": scope["owner_id"],
                    "owner_instance_id": scope["owner_instance_id"],
                    "owner_epoch": int(scope["owner_epoch"]),
                    "fencing_epoch": int(scope["fencing_epoch"]),
                    "operation_state": str(operation["state"]),
                }
                if hashlib.sha256(lease_token.encode("utf-8")).hexdigest() != scope["lease_token_sha256"]:
                    return self._output(
                        RECOVERY_HOLD,
                        "RECOVERY_LEASE_TOKEN_MISMATCH",
                        scope_id=scope_id,
                        handoff_id=handoff_id,
                        transaction_id=operation["transaction_id"],
                        idempotency_key=operation["idempotency_key"],
                        operation_state=str(operation["state"]),
                        preflight=replay_evidence,
                    )
                initial_now = self._now_for_check()
                now = initial_now if initial_now is not None else _now_value(self.clock(), "clock")
                if int(scope["lease_expires_at"]) <= now:
                    return self._output(
                        RECOVERY_HOLD,
                        "RECOVERY_LEASE_EXPIRED",
                        scope_id=scope_id,
                        handoff_id=handoff_id,
                        transaction_id=operation["transaction_id"],
                        idempotency_key=operation["idempotency_key"],
                        operation_state=str(operation["state"]),
                        preflight=replay_evidence,
                    )
                if (
                    scope["scope_status"] != "CLEAN"
                    or scope["active_operation_id"] is not None
                    or scope["active_phase"] != "IDLE"
                    or canonical_hash(intent) != operation["intent_sha256"]
                ):
                    raise PrimeQueueWriterError("REPLAY_SCOPE_OR_INTENT_DRIFT")
                self._terminal_marker_is_bound(cursor, operation)
                row = operation
                queue_hash = self.writer._queue_hash()
                if row["state"] == "COMMITTED":
                    if queue_hash != row["after_queue_sha256"] or not self.writer._matching_committed_transaction(row):
                        raise PrimeQueueWriterError("REPLAY_COMMITTED_EVIDENCE_DRIFT")
                    transaction_state = "AFTER"
                    evidence = QUEUE_MUTATION_TRUE
                else:
                    exact, other_open, invalid = self.writer._transaction_details(row)
                    if exact is None or other_open or invalid:
                        raise PrimeQueueWriterError("REPLAY_EXACT_TRANSACTION_MISSING")
                    if queue_hash != row["expected_queue_sha256"] or not self.writer._matching_aborted_transaction(row):
                        raise PrimeQueueWriterError("REPLAY_ABORTED_EVIDENCE_DRIFT")
                    transaction_state = "BEFORE"
                    evidence = QUEUE_MUTATION_FALSE
                expected_performed = int(evidence == QUEUE_MUTATION_TRUE)
                if (
                    row["queue_mutation_evidence"] != evidence
                    or int(row["queue_mutation_performed"]) != expected_performed
                ):
                    raise PrimeQueueWriterError("REPLAY_QUEUE_EVIDENCE_DRIFT")
                replay_evidence["transaction_state"] = transaction_state
                replay_evidence["queue_sha256"] = queue_hash
                self._stages.append(
                    {
                        "stage": "terminal_replay",
                        "status": RECOVERY_REPLAYED,
                        "reason": "RECOVERY_TERMINAL_STATE_REVALIDATED_READ_ONLY",
                        "transaction_state": transaction_state,
                        "queue_sha256": queue_hash,
                    }
                )
                return self._output(
                    RECOVERY_REPLAYED,
                    "RECOVERY_TERMINAL_STATE_REVALIDATED_READ_ONLY",
                    scope_id=scope_id,
                    handoff_id=handoff_id,
                    transaction_id=operation["transaction_id"],
                    idempotency_key=operation["idempotency_key"],
                    operation_state=str(operation["state"]),
                    transaction_state=transaction_state,
                    queue_hash=queue_hash,
                    queue_mutation_evidence=evidence,
                    preflight=replay_evidence,
                    transaction_marker_written=True,
                    state_written=False,
                    started=False,
                    replay=True,
                )
        except _ExecutionStop:
            raise
        except (PrimeQueueWriterError, OSError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
            return self._output(
                RECOVERY_REQUIRED,
                str(exc) or "REPLAY_REVALIDATION_FAILED",
                scope_id=scope_id,
                handoff_id=handoff_id,
                started=False,
            )
        except Exception as exc:
            return self._output(
                RECOVERY_REQUIRED,
                str(getattr(exc, "reason", "")) or "REPLAY_REVALIDATION_FAILED",
                scope_id=scope_id,
                handoff_id=handoff_id,
                started=False,
            )

    def _output(
        self,
        status: str,
        reason: str,
        *,
        preflight: Mapping[str, Any] | None = None,
        scope_id: str | None = None,
        handoff_id: str | None = None,
        transaction_id: str | None = None,
        idempotency_key: str | None = None,
        operation_state: str | None = None,
        transaction_state: str | None = None,
        queue_hash: str | None = None,
        queue_mutation_evidence: str | None = None,
        transaction_marker_written: bool | None = None,
        state_written: bool | None = None,
        started: bool | None = None,
        replay: bool = False,
    ) -> dict[str, Any]:
        evidence = queue_mutation_evidence or self._historical_queue_evidence
        result = {
            "schema_version": RECOVERY_EXECUTOR_SCHEMA,
            "contract_role": RECOVERY_EXECUTOR_ROLE,
            "status": status,
            "decision": "RECOVERY_RESOLVED" if status in {RECOVERY_COMMITTED, RECOVERY_ABORTED, RECOVERY_REPLAYED} else "HOLD",
            "reason": reason,
            "permission": "queue_recovery_local" if status in {RECOVERY_COMMITTED, RECOVERY_ABORTED} else "read_only",
            "scope_id": scope_id if scope_id is not None else (preflight or {}).get("scope_id"),
            "handoff_id": handoff_id if handoff_id is not None else (preflight or {}).get("handoff_id"),
            "transaction_id": transaction_id if transaction_id is not None else (preflight or {}).get("transaction_id"),
            "idempotency_key": idempotency_key if idempotency_key is not None else (preflight or {}).get("idempotency_key"),
            "handoff_seq": (preflight or {}).get("handoff_seq"),
            "handoff_event_sha256": (preflight or {}).get("handoff_event_sha256"),
            "grant_sha256": (preflight or {}).get("grant_sha256"),
            "observation_sha256": (preflight or {}).get("observation_sha256"),
            "owner_id": (preflight or {}).get("owner_id"),
            "owner_instance_id": (preflight or {}).get("owner_instance_id"),
            "owner_epoch": (preflight or {}).get("owner_epoch"),
            "fencing_epoch": (preflight or {}).get("fencing_epoch"),
            "operation_state": operation_state if operation_state is not None else (preflight or {}).get("operation_state"),
            "transaction_state": transaction_state if transaction_state is not None else (preflight or {}).get("transaction_state"),
            "queue_sha256": queue_hash if queue_hash is not None else (preflight or {}).get("queue_sha256"),
            "preflight_status": (preflight or {}).get("status"),
            "revalidation_stages": list(self._stages),
            "read_only": status not in {RECOVERY_COMMITTED, RECOVERY_ABORTED},
            "recovery_authority": False,
            "recovery_eligible": status == RECOVERY_ELIGIBLE,
            "recovery_execution_allowed": False,
            "recovery_execution_performed": status in {RECOVERY_COMMITTED, RECOVERY_ABORTED},
            "recovery_started": self._started if started is None else started,
            "resume_allowed": status == RECOVERY_HOLD,
            "retry_allowed": status == RECOVERY_HOLD,
            "manual_reconcile_required": status == RECOVERY_REQUIRED,
            "mutation_allowed": False,
            "mutation_performed": self._state_written if state_written is None else state_written,
            "queue_file_mutation_performed": False,
            "queue_mutation_performed": False,
            "queue_mutation_evidence": evidence,
            "historical_queue_mutation_performed": {
                QUEUE_MUTATION_TRUE: True,
                QUEUE_MUTATION_FALSE: False,
                QUEUE_MUTATION_UNKNOWN: None,
            }.get(evidence),
            "transaction_marker_written": (
                self._transaction_marker_written
                if transaction_marker_written is None
                else transaction_marker_written
            ),
            "local_queue_transaction_marker_written": (
                self._transaction_marker_written
                if transaction_marker_written is None
                else transaction_marker_written
            ),
            "sqlite_state_written": self._state_written if state_written is None else state_written,
            "replayed": replay,
            "receipt_emitted": False,
            "receipt_committed": False,
            "consume_allowed": False,
            "global_commit": False,
            "cross_store_atomicity": "NOT_CLAIMED",
            "path_toctou": "COOPERATIVE_EXCLUSIVE_LOCK_ONLY",
            "path_toctou_claimed": False,
            "foreign_writer_protection": "NOT_CLAIMED",
            "sqlite_writer_authority": "COOPERATIVE_LOCK_ONLY",
            "lock_inode_identity": "NOT_CLAIMED",
            "queue_path_aba": "NOT_CLAIMED",
            "execution": {
                "queue_file_write": False,
                "queue_transaction_marker_write": bool(
                    self._transaction_marker_written
                    if transaction_marker_written is None
                    else transaction_marker_written
                ),
                "sqlite_state_write": bool(self._state_written if state_written is None else state_written),
                "receipt": False,
                "ledger": False,
                "projection": False,
                "consume": False,
                "cross_store": False,
            },
        }
        if status == RECOVERY_REPLAYED:
            result["permission"] = "read_only"
        return result

    def resolve(
        self,
        *,
        scope_id: str,
        handoff_id: str,
        lease_token: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Resolve one accepted handoff or return a classified hold."""

        try:
            scope_id = _text(scope_id, "scope_id")
            handoff_id = _text(handoff_id, "handoff_id")
            lease_token = _text(lease_token, "lease_token")
            self._initial_now = _now_value(now) if now is not None else None
            self._initial_now_consumed = False
            with self._exclusive_queue_lock() as queue_lock_fd:
                replay = self._terminal_replay(
                    scope_id=scope_id,
                    handoff_id=handoff_id,
                    lease_token=lease_token,
                )
                if replay is not None:
                    return replay
                evidence = self._revalidate(
                    stage="before_claim",
                    scope_id=scope_id,
                    handoff_id=handoff_id,
                    lease_token=lease_token,
                )
                row = self.writer._read_operation_row(scope_id, evidence["idempotency_key"])
                if row["state"] not in {"PREPARED", "IN_DOUBT"}:
                    raise PrimeQueueWriterError("RECOVERY_OPERATION_NOT_PENDING")
                fence = self._fence_from_preflight(evidence, lease_token)
                self._fault("before_claim")
                self.writer._claim_phase(
                    scope_id=scope_id,
                    transaction_id=evidence["transaction_id"],
                    phase="RECOVERY",
                    **fence,
                    allowed_previous=frozenset({"RECOVERY"}),
                )
                self._started = True
                self._fault("after_claim")

                def before_terminal_marker() -> None:
                    self._revalidate(
                        stage="before_terminal_marker",
                        scope_id=scope_id,
                        handoff_id=handoff_id,
                        lease_token=lease_token,
                    )
                    self._fault("before_terminal_marker")

                def after_terminal_marker() -> None:
                    self._transaction_marker_written = True
                    self._revalidate(
                        stage="after_terminal_marker",
                        scope_id=scope_id,
                        handoff_id=handoff_id,
                        lease_token=lease_token,
                    )
                    self._fault("after_terminal_marker")

                recovery = self.writer._recover_exact_transaction(
                    row,
                    before_terminal_marker=before_terminal_marker,
                    after_terminal_marker=after_terminal_marker,
                    queue_lock_fd=queue_lock_fd,
                )
                if recovery == "UNKNOWN":
                    self._historical_queue_evidence = QUEUE_MUTATION_UNKNOWN
                    try:
                        self._revalidate(
                            stage="unknown_recovery",
                            scope_id=scope_id,
                            handoff_id=handoff_id,
                            lease_token=lease_token,
                        )
                    except _ExecutionStop as stop:
                        return self._output(
                            str(stop.result.get("status", RECOVERY_REQUIRED)),
                            str(stop.result.get("reason", "RECOVERY_EXACT_TRANSACTION_UNRESOLVED")),
                            preflight=stop.result,
                            started=True,
                        )
                    return self._output(
                        RECOVERY_REQUIRED,
                        "RECOVERY_EXACT_TRANSACTION_UNRESOLVED",
                        preflight=self._last_preflight,
                        started=True,
                    )
                self._historical_queue_evidence = (
                    QUEUE_MUTATION_TRUE if recovery == "COMMITTED" else QUEUE_MUTATION_FALSE
                )
                self._revalidate(
                    stage="before_state_mark",
                    scope_id=scope_id,
                    handoff_id=handoff_id,
                    lease_token=lease_token,
                )
                self._fault("before_state_mark")
                marked = self.writer._mark_state(
                    scope_id=scope_id,
                    idempotency_key=evidence["idempotency_key"],
                    state="COMMITTED" if recovery == "COMMITTED" else "ABORTED",
                    reason=(
                        "QUEUE_RECOVERY_CONFIRMED_COMMITTED"
                        if recovery == "COMMITTED"
                        else "QUEUE_RECOVERY_CONFIRMED_BEFORE_ONLY"
                    ),
                    queue_mutation_performed=recovery == "COMMITTED",
                    queue_mutation_evidence=self._historical_queue_evidence,
                    result={"recovered": True, "executor": RECOVERY_EXECUTOR_SCHEMA},
                    transaction_id=evidence["transaction_id"],
                    required_active_phase="RECOVERY",
                    fence=fence,
                )
                self._state_written = True
                expected_status = "QUEUE_COMMITTED" if recovery == "COMMITTED" else "QUEUE_ABORTED"
                expected_evidence = QUEUE_MUTATION_TRUE if recovery == "COMMITTED" else QUEUE_MUTATION_FALSE
                if (
                    not isinstance(marked, Mapping)
                    or marked.get("status") != expected_status
                    or marked.get("queue_mutation_evidence") != expected_evidence
                    or bool(marked.get("queue_mutation_performed")) != (recovery == "COMMITTED")
                    or not isinstance(marked.get("result"), Mapping)
                    or not isinstance(marked["result"].get("result"), Mapping)
                    or marked["result"]["result"].get("executor") != RECOVERY_EXECUTOR_SCHEMA
                ):
                    return self._output(
                        RECOVERY_REQUIRED,
                        "RECOVERY_STATE_MARK_NOT_TERMINAL",
                        preflight=self._last_preflight,
                        scope_id=scope_id,
                        handoff_id=handoff_id,
                        transaction_id=evidence["transaction_id"],
                        idempotency_key=evidence["idempotency_key"],
                        operation_state=str(marked.get("status", "IN_DOUBT")),
                        transaction_state="AFTER" if recovery == "COMMITTED" else "BEFORE",
                        queue_mutation_evidence=QUEUE_MUTATION_UNKNOWN,
                        transaction_marker_written=True,
                        state_written=True,
                        started=True,
                    )
                self._fault("after_state_mark")
                return self._output(
                    RECOVERY_COMMITTED if recovery == "COMMITTED" else RECOVERY_ABORTED,
                    "RECOVERY_COMMITTED" if recovery == "COMMITTED" else "RECOVERY_ABORTED",
                    preflight=self._last_preflight,
                    scope_id=scope_id,
                    handoff_id=handoff_id,
                    transaction_id=evidence["transaction_id"],
                    idempotency_key=evidence["idempotency_key"],
                    operation_state="COMMITTED" if recovery == "COMMITTED" else "ABORTED",
                    transaction_state="AFTER" if recovery == "COMMITTED" else "BEFORE",
                    queue_hash=marked.get("queue_sha256") if isinstance(marked, Mapping) else evidence.get("queue_sha256"),
                    queue_mutation_evidence=self._historical_queue_evidence,
                    transaction_marker_written=True,
                    state_written=True,
                    started=True,
                )
        except InjectedRecoveryExecutorCrash:
            raise
        except _ExecutionStop as stop:
            return self._output(
                str(stop.result.get("status", RECOVERY_REQUIRED)),
                str(stop.result.get("reason", "RECOVERY_REVALIDATION_FAILED")),
                preflight=stop.result,
                started=self._started,
            )
        except _QueueLockUnavailable as exc:
            return self._output(RECOVERY_HOLD, exc.reason, scope_id=scope_id, handoff_id=handoff_id)
        except (PrimeQueueWriterError, OSError, sqlite3.Error, TypeError, ValueError, json.JSONDecodeError) as exc:
            return self._output(
                RECOVERY_REQUIRED,
                str(exc) or "RECOVERY_EXECUTION_FAILED",
                preflight=self._last_preflight,
                scope_id=scope_id,
                handoff_id=handoff_id,
                started=self._started,
            )
        except Exception as exc:
            return self._output(
                RECOVERY_REQUIRED,
                f"RECOVERY_EXECUTION_UNEXPECTED_{type(exc).__name__}",
                preflight=self._last_preflight,
                scope_id=scope_id,
                handoff_id=handoff_id,
                started=self._started,
            )


def execute_recovery(
    writer: PrimeQueueWriter,
    *,
    scope_id: str,
    handoff_id: str,
    lease_token: str,
    now: int | None = None,
    fault_points: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    """Convenience wrapper for one explicit S25D executor instance."""

    return RecoveryExecutor(writer, fault_points=fault_points).resolve(
        scope_id=scope_id,
        handoff_id=handoff_id,
        lease_token=lease_token,
        now=now,
    )


__all__ = [
    "InjectedRecoveryExecutorCrash",
    "RECOVERY_ABORTED",
    "RECOVERY_COMMITTED",
    "RECOVERY_EXECUTOR_FAULT_POINTS",
    "RECOVERY_EXECUTOR_ROLE",
    "RECOVERY_EXECUTOR_SCHEMA",
    "RECOVERY_HOLD",
    "RECOVERY_REPLAYED",
    "RECOVERY_REQUIRED",
    "RecoveryExecutor",
    "RecoveryExecutorError",
    "execute_recovery",
]
