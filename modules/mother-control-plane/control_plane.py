"""Isolated W2.5-S0 SQLite control plane.

This module is a proof harness, not a production launcher.  It implements one
P0 card up to ``Receipt.VERIFIED`` and ``Attempt.EVIDENCE_VERIFIED``.  No
subprocess, socket, local model server, port, ``/proc`` or real worker is
reachable from this file.  The fake executor is injected as a data-only
object.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable, Iterator, Mapping, Optional

try:  # Supports both package imports and the test loader's sys.path import.
    from .fake_executor import FakeExecutor, FakeProcessIdentity
    from .fault_injection import FaultPlan, InjectedCrash
except ImportError:  # pragma: no cover - exercised by the standalone test loader
    from fake_executor import FakeExecutor, FakeProcessIdentity
    from fault_injection import FaultPlan, InjectedCrash


SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "001_w0_core.sql"
FIXED_NOW = "2026-01-01T00:00:00Z"
FIXED_EPOCH = 1767225600


class ControlPlaneError(RuntimeError):
    """Base class for deterministic control-plane failures."""


class StateConflict(ControlPlaneError):
    """A transition or idempotency request conflicts with canonical state."""


class EvidenceError(ControlPlaneError):
    """Receipt, artifact, or scope evidence cannot be verified."""


class FencingError(ControlPlaneError):
    """A stale owner/lease attempted a write."""


class P0Disabled(ControlPlaneError):
    """A caller attempted the W6-only acceptance path during P0."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _json(value: Any) -> str:
    return canonical_json(value)


def _parse(value: Optional[str], default: Any = None) -> Any:
    if value is None:
        return default
    return json.loads(value)


def _row(row: Optional[sqlite3.Row]) -> Optional[dict[str, Any]]:
    return dict(row) if row is not None else None


@dataclass(frozen=True)
class FixedClock:
    """Stable clock used by default so repeated fixtures have equal hashes."""

    now_value: str = FIXED_NOW
    epoch_value: int = FIXED_EPOCH

    def now(self) -> str:
        return self.now_value

    def epoch(self) -> int:
        return self.epoch_value


PROJECT_TRANSITIONS = {
    "DISCOVERED": {"REGISTERED", "QUARANTINED"},
    "REGISTERED": {"READY"},
    "READY": {"ACTIVE"},
    "ACTIVE": {"WAITING", "PAUSED", "BLOCKED", "RECOVERY_REQUIRED", "READY", "QUARANTINED"},
    "WAITING": {"ACTIVE", "PAUSED", "BLOCKED"},
    "BLOCKED": {"READY", "QUARANTINED", "ARCHIVED"},
    "RECOVERY_REQUIRED": {"READY", "QUARANTINED", "ARCHIVED"},
    "PAUSED": set(),
    "QUARANTINED": set(),
    "ARCHIVED": set(),
}

RUN_TRANSITIONS = {
    "CREATED": {"PREFLIGHT"},
    "PREFLIGHT": {"READY", "RECOVERY_REQUIRED", "FAILED"},
    "READY": {"DISPATCHING", "PAUSED", "BLOCKED", "FAILED"},
    "DISPATCHING": {"RUNNING", "RECOVERY_REQUIRED", "PAUSED", "FAILED"},
    "RUNNING": {"VERIFYING", "PAUSED", "BLOCKED", "RECOVERY_REQUIRED", "FAILED"},
    "VERIFYING": {"REVIEW_PENDING", "PAUSED", "BLOCKED", "RECOVERY_REQUIRED", "FAILED"},
    "REVIEW_PENDING": {"ADVANCING", "PAUSED", "BLOCKED"},
    "ADVANCING": {"DISPATCHING", "WAITING", "COMPLETED", "BLOCKED"},
    "WAITING": {"DISPATCHING", "PAUSED", "BLOCKED"},
    "RECOVERY_REQUIRED": {"RUNNING", "READY", "PAUSED", "BLOCKED", "ABORTED", "FAILED"},
    "PAUSED": set(),
    "BLOCKED": set(),
    "FAILED": set(),
    "ABORTED": set(),
    "COMPLETED": set(),
}

CARD_TRANSITIONS = {
    "DRAFT": {"WAITING", "CANCELLED"},
    "WAITING": {"READY", "PAUSED", "BLOCKED", "CANCELLED"},
    "READY": {"CLAIMED", "PAUSED", "BLOCKED", "CANCELLED"},
    "CLAIMED": {"IN_PROGRESS", "PAUSED", "BLOCKED", "CANCELLED"},
    "IN_PROGRESS": {"SUBMITTED", "RETRY_READY", "BLOCKED", "PAUSED"},
    "SUBMITTED": {"REVIEW_PENDING", "RETRY_READY", "BLOCKED"},
    "REVIEW_PENDING": {"DONE", "RETRY_READY", "BLOCKED"},
    "RETRY_READY": {"READY"},
    "PAUSED": set(),
    "BLOCKED": set(),
    "DONE": set(),
    "CANCELLED": set(),
}

ATTEMPT_TRANSITIONS = {
    "CREATED": {"ADMITTED"},
    "ADMITTED": {"STARTING", "ABORTED", "BLOCKED"},
    "STARTING": {"RUNNING", "UNCERTAIN", "FAILED"},
    "RUNNING": {"CHECKPOINTED", "SUBMITTED", "UNCERTAIN", "FAILED", "ABORTED", "RETRYABLE", "BLOCKED"},
    "CHECKPOINTED": {"RUNNING", "RETRYABLE", "BLOCKED"},
    "SUBMITTED": {"EVIDENCE_VERIFIED", "RETRYABLE", "BLOCKED"},
    "EVIDENCE_VERIFIED": {"REVIEW_PENDING"},
    "REVIEW_PENDING": {"ACCEPTED", "REJECTED", "RETRYABLE", "BLOCKED"},
    "UNCERTAIN": {"RETRYABLE", "BLOCKED", "ABORTED"},
    "REJECTED": {"RETRYABLE", "BLOCKED"},
    "RETRYABLE": set(),
    "FAILED": set(),
    "ABORTED": set(),
    "ACCEPTED": set(),
    "BLOCKED": set(),
}

DISPATCH_TRANSITIONS = {
    "DISPATCH_INTENDED": {"CLAIMED"},
    "CLAIMED": {"SPAWN_REQUESTED", "CANCELLED", "BLOCKED"},
    "SPAWN_REQUESTED": {"EXECUTOR_ACKED", "ACK_TIMEOUT", "DISPATCH_UNCONFIRMED", "RECONCILING"},
    "EXECUTOR_ACKED": {"RUNNING", "RECONCILING", "FAILED"},
    "RUNNING": {"EXIT_REPORTED", "RECONCILING", "FAILED"},
    "EXIT_REPORTED": {"COMPLETED", "RECONCILING", "FAILED"},
    "ACK_TIMEOUT": {"RECONCILING"},
    "DISPATCH_UNCONFIRMED": {"RECONCILING"},
    "RECONCILING": {"EXECUTOR_ACKED", "RUNNING", "EXIT_REPORTED", "EXPIRED", "FAILED", "BLOCKED"},
    "CANCELLED": set(),
    "EXPIRED": set(),
    "FAILED": set(),
    "BLOCKED": set(),
    "COMPLETED": set(),
}

P0_MARKER_CONTRACT = {
    "run-admit": ("C0", "COMMITTED"),
    "dispatch-intent": ("C1", "COMMITTED"),
    "claim-lease": ("C2", "COMMITTED"),
    "spawn-request": ("C3", "COMMITTED"),
    "executor-ack": ("C4", "COMMITTED"),
    "checkpoint": ("C5", "COMMITTED"),
    "submission": ("C6", "COMMITTED"),
    "receipt-verify": ("C7", "COMMITTED"),
    "review-decision": ("C8", "SUPPRESSED"),
    "acceptance-gate": ("C9", "SUPPRESSED"),
    "next-card-intent": ("C10", "SUPPRESSED"),
    "run-complete": ("C11", "SUPPRESSED"),
}


class ControlPlane:
    """One-card SQLite controller with deterministic replay and recovery."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        clock: FixedClock | Any | None = None,
        fault_plan: FaultPlan | None = None,
        executor: FakeExecutor | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.clock = clock or FixedClock()
        self.fault = fault_plan or FaultPlan.none()
        self.fault.validate()
        self.executor = executor or FakeExecutor()
        self.hook_trace: list[str] = []
        # A C3 commit in this controller session is the only point at which
        # the following C4 call is allowed to issue the first fake spawn.
        # After a close/reopen, a durable SPAWN_REQUESTED row is reconciled by
        # deterministic identity adoption instead of issuing a second request.
        self._spawn_request_context: set[str] = set()
        self.conn = sqlite3.connect(self.db_path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self.conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "ControlPlane":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = self.conn.cursor()
            yield cursor
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        finally:
            cursor.close()

    def _hook(self, run_id: str | None, commit_point: str, hook: str) -> None:
        fault_id = f"{commit_point}.{hook}"
        self.hook_trace.append(fault_id)
        self.fault.trip(commit_point, hook)

    def _persist_injected_fault(self, run_id: str | None, fault_id: str) -> None:
        commit_point, _, hook = fault_id.partition(".")
        with self._transaction() as cur:
            cur.execute(
                "INSERT INTO fault_observations(run_id,commit_point,hook,injected,created_at) VALUES (?,?,?,?,?)",
                (run_id, commit_point, hook, 1, self.clock.now()),
            )

    def _marker(self, run_id: str, operation_key: str) -> Optional[dict[str, Any]]:
        return _row(
            self.conn.execute(
                "SELECT * FROM commit_markers WHERE run_id=? AND operation_key=?",
                (run_id, operation_key),
            ).fetchone()
        )

    def _assert_marker_commitments_cursor(self, cur: sqlite3.Cursor, run_id: str) -> None:
        markers = {
            (row["operation_key"]): row["marker_hash"]
            for row in cur.execute(
                "SELECT operation_key,marker_hash FROM commit_markers WHERE run_id=?",
                (run_id,),
            ).fetchall()
        }
        commitments = {
            (row["operation_key"]): row["marker_hash"]
            for row in cur.execute(
                "SELECT operation_key,marker_hash FROM marker_commitments WHERE run_id=?",
                (run_id,),
            ).fetchall()
        }
        if markers != commitments:
            raise EvidenceError(f"commit marker commitment drift: {run_id}")
        for row in cur.execute(
            "SELECT operation_key,commit_point,status FROM commit_markers WHERE run_id=?",
            (run_id,),
        ).fetchall():
            expected = P0_MARKER_CONTRACT.get(row["operation_key"])
            if expected is None or (row["commit_point"], row["status"]) != expected:
                raise EvidenceError(f"unknown or invalid P0 commit marker: {row['operation_key']}")

    def _assert_marker_commitments(self, run_id: str) -> None:
        cur = self.conn.cursor()
        try:
            self._assert_marker_commitments_cursor(cur, run_id)
        finally:
            cur.close()

    def _runtime_projection(self, cur: sqlite3.Cursor, run_id: str) -> dict[str, Any]:
        """Return the hashable state projection used by commit markers.

        Event sequence numbers and wall-clock fields are intentionally absent:
        they describe history, not the canonical state that a phase changed.
        """

        projections = {
            "projects": ("*", "project_id"),
            "runs": ("*", "run_id"),
            "cards": ("*", "card_id"),
            "attempts": ("*", "attempt_id"),
            "dispatches": ("*", "dispatch_id"),
            "receipts": ("*", "receipt_id"),
            "reviews": ("*", "review_id"),
            "acceptance_txns": ("*", "acceptance_txn_id"),
            "next_card_intents": ("*", "next_card_intent_id"),
        }
        output: dict[str, Any] = {}
        for table, (columns, order_column) in projections.items():
            if table == "projects":
                rows = cur.execute(
                    f"SELECT {columns} FROM {table} WHERE project_id=(SELECT project_id FROM runs WHERE run_id=?) ORDER BY {order_column}",
                    (run_id,),
                ).fetchall()
            else:
                rows = cur.execute(
                    f"SELECT {columns} FROM {table} WHERE run_id=? ORDER BY {order_column}",
                    (run_id,),
                ).fetchall()
            output[table] = [dict(row) for row in rows]
        return output

    def _runtime_projection_hash(self, cur: sqlite3.Cursor, run_id: str) -> str:
        return canonical_hash(self._runtime_projection(cur, run_id))

    def _assert_terminal_state_seal_cursor(self, cur: sqlite3.Cursor, run_id: str) -> None:
        """Validate the final P0 state against the immutable C11 commitment."""

        marker = cur.execute(
            "SELECT commit_point,operation_key,status,marker_hash,payload_json FROM commit_markers WHERE run_id=? AND operation_key='run-complete'",
            (run_id,),
        ).fetchone()
        if marker is None:
            return
        commitment = cur.execute(
            "SELECT marker_hash FROM marker_commitments WHERE run_id=? AND operation_key='run-complete'",
            (run_id,),
        ).fetchone()
        if commitment is None or commitment[0] != marker["marker_hash"]:
            raise EvidenceError(f"terminal marker commitment drift: {run_id}")
        payload = _parse(marker["payload_json"], {})
        expected_marker_hash = canonical_hash(
            {
                "run_id": run_id,
                "commit_point": marker["commit_point"],
                "operation_key": marker["operation_key"],
                "status": marker["status"],
                "payload": payload,
            }
        )
        if expected_marker_hash != marker["marker_hash"]:
            raise EvidenceError(f"terminal marker hash drift: {run_id}")
        if payload.get("_after_state_hash") != self._runtime_projection_hash(cur, run_id):
            raise StateConflict(f"terminal P0 state drift: {run_id}")

    def _assert_terminal_state_seal(self, run_id: str) -> None:
        cur = self.conn.cursor()
        try:
            self._assert_terminal_state_seal_cursor(cur, run_id)
        finally:
            cur.close()

    def _assert_runtime_anchor_cursor(self, cur: sqlite3.Cursor, run_id: str) -> None:
        anchor = cur.execute(
            "SELECT projection_hash,last_committed_event_id FROM runtime_anchors WHERE run_id=?",
            (run_id,),
        ).fetchone()
        history = cur.execute(
            "SELECT projection_hash,last_committed_event_id FROM runtime_anchor_history WHERE run_id=? ORDER BY anchor_no DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        if (anchor is None) != (history is None):
            raise StateConflict(f"runtime anchor history drift for {run_id}")
        if anchor is not None and (
            anchor["projection_hash"] != history["projection_hash"]
            or anchor["last_committed_event_id"] != history["last_committed_event_id"]
            or anchor["projection_hash"] != self._runtime_projection_hash(cur, run_id)
        ):
            raise StateConflict(f"runtime projection drift for {run_id}")

    def _assert_runtime_anchor(self, run_id: str) -> None:
        cur = self.conn.cursor()
        try:
            self._assert_runtime_anchor_cursor(cur, run_id)
        finally:
            cur.close()

    def _set_runtime_anchor(self, cur: sqlite3.Cursor, run_id: str) -> str:
        projection_hash = self._runtime_projection_hash(cur, run_id)
        event_row = cur.execute(
            "SELECT last_committed_event_id FROM runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if event_row is None:
            raise StateConflict(f"run missing for runtime anchor: {run_id}")
        previous = cur.execute(
            "SELECT COALESCE(MAX(anchor_no),0) FROM runtime_anchor_history WHERE run_id=?",
            (run_id,),
        ).fetchone()
        anchor_no = int(previous[0]) + 1
        cur.execute(
            "INSERT INTO runtime_anchor_history(run_id,anchor_no,projection_hash,last_committed_event_id,created_at) VALUES (?,?,?,?,?)",
            (run_id, anchor_no, projection_hash, event_row[0], self.clock.now()),
        )
        cur.execute(
            "INSERT INTO runtime_anchors(run_id,projection_hash,last_committed_event_id,updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(run_id) DO UPDATE SET projection_hash=excluded.projection_hash,last_committed_event_id=excluded.last_committed_event_id,updated_at=excluded.updated_at",
            (run_id, projection_hash, event_row[0], self.clock.now()),
        )
        return projection_hash

    def _phase(
        self,
        run_id: str,
        commit_point: str,
        operation_key: str,
        mutation: Callable[[sqlite3.Cursor], Mapping[str, Any] | None],
        *,
        status: str = "COMMITTED",
    ) -> dict[str, Any]:
        self._assert_marker_commitments(run_id)
        self._assert_runtime_anchor(run_id)
        self._assert_terminal_state_seal(run_id)
        existing = self._marker(run_id, operation_key)
        if existing is not None:
            payload = _parse(existing["payload_json"], {})
            expected = canonical_hash(
                {
                    "run_id": run_id,
                    "commit_point": existing["commit_point"],
                    "operation_key": operation_key,
                    "status": existing["status"],
                    "payload": payload,
                }
            )
            if expected != existing["marker_hash"]:
                raise EvidenceError(f"commit marker hash drift: {operation_key}")
            later_exists = self.conn.execute(
                "SELECT 1 FROM commit_markers WHERE run_id=? AND CAST(SUBSTR(commit_point,2) AS INTEGER)>?",
                (run_id, int(commit_point[1:])),
            ).fetchone()
            current_event = self.conn.execute("SELECT last_committed_event_id FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if later_exists is None and payload.get("_after_state_hash"):
                after_event_id = payload.get("_after_event_id")
                later_events = []
                if after_event_id and current_event is not None and current_event[0] != after_event_id:
                    after_event = self.conn.execute(
                        "SELECT event_no FROM events WHERE event_id=? AND run_id=?",
                        (after_event_id, run_id),
                    ).fetchone()
                    if after_event is not None:
                        later_events = [
                            str(row[0])
                            for row in self.conn.execute(
                                "SELECT event_type FROM events WHERE run_id=? AND event_no>? ORDER BY event_no",
                                (run_id, int(after_event[0])),
                            ).fetchall()
                        ]
                # Reconciliation may legitimately append its own audit events
                # between C3's marker and C4.  Any other post-marker event on
                # the terminal P0 projection is treated as drift.
                recovery_events_only = bool(later_events) and all(
                    event_type.startswith("RECONCILE_")
                    or event_type in {"DISPATCH_UNCONFIRMED", "DISPATCH_RECONCILING", "RUN_RECOVERY_REQUIRED"}
                    for event_type in later_events
                )
                if not later_events or not recovery_events_only:
                    current_cursor = self.conn.cursor()
                    try:
                        current_hash = self._runtime_projection_hash(current_cursor, run_id)
                    finally:
                        current_cursor.close()
                    if current_hash != payload["_after_state_hash"]:
                        raise StateConflict(f"canonical state drift after {operation_key}")
            return payload

        try:
            self._hook(run_id, commit_point, "before_prepare")
            with self._transaction() as cur:
                self._assert_marker_commitments_cursor(cur, run_id)
                self._assert_runtime_anchor_cursor(cur, run_id)
                self._assert_terminal_state_seal_cursor(cur, run_id)
                if cur.execute(
                    "SELECT 1 FROM commit_markers WHERE run_id=? AND operation_key=?",
                    (run_id, operation_key),
                ).fetchone():
                    return _parse(
                        cur.execute(
                            "SELECT payload_json FROM commit_markers WHERE run_id=? AND operation_key=?",
                            (run_id, operation_key),
                        ).fetchone()[0],
                    )
                self._hook(run_id, commit_point, "after_prepare")
                before_state_hash = self._runtime_projection_hash(cur, run_id)
                result = dict(mutation(cur) or {})
                after_state_hash = self._runtime_projection_hash(cur, run_id)
                after_event_id = cur.execute("SELECT last_committed_event_id FROM runs WHERE run_id=?", (run_id,)).fetchone()[0]
                result["_before_state_hash"] = before_state_hash
                result["_after_state_hash"] = after_state_hash
                result["_after_event_id"] = after_event_id
                self._set_runtime_anchor(cur, run_id)
                self._hook(run_id, commit_point, "before_replace")
                self._hook(run_id, commit_point, "after_replace")
                self._hook(run_id, commit_point, "before_commit_marker")
                marker_payload = {
                    "run_id": run_id,
                    "commit_point": commit_point,
                    "operation_key": operation_key,
                    "status": status,
                    "payload": result,
                }
                marker_hash = canonical_hash(marker_payload)
                cur.execute(
                    "INSERT INTO commit_markers(run_id,commit_point,operation_key,status,marker_hash,payload_json,created_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        run_id,
                        commit_point,
                        operation_key,
                        status,
                        marker_hash,
                        _json(result),
                        self.clock.now(),
                    ),
                )
                cur.execute(
                    "INSERT INTO marker_commitments(run_id,operation_key,marker_hash,created_at) VALUES (?,?,?,?)",
                    (run_id, operation_key, marker_hash, self.clock.now()),
                )
            self._hook(run_id, commit_point, "after_commit_marker")
            return result
        except InjectedCrash as exc:
            # The crash itself is simulated, but its identity survives the
            # rollback so recovery can prove which hook was exercised.
            self._persist_injected_fault(run_id, exc.fault_id)
            raise

    def _next_event(self, cur: sqlite3.Cursor) -> tuple[str, int]:
        cur.execute("UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='event_seq'")
        number = int(cur.execute("SELECT value FROM meta WHERE key='event_seq'").fetchone()[0])
        return f"event-{number:06d}", number

    def _record_event(
        self,
        cur: sqlite3.Cursor,
        *,
        run_id: str,
        entity_type: str,
        entity_id: str,
        event_type: str,
        from_state: str | None,
        to_state: str | None,
        payload: Mapping[str, Any] | None = None,
    ) -> str:
        event_id, event_no = self._next_event(cur)
        cur.execute(
            "INSERT INTO events(event_id,event_no,run_id,entity_type,entity_id,event_type,from_state,to_state,payload_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                event_no,
                run_id,
                entity_type,
                entity_id,
                event_type,
                from_state,
                to_state,
                _json(dict(payload or {})),
                self.clock.now(),
            ),
        )
        cur.execute(
            "UPDATE runs SET last_committed_event_id=?,updated_at=? WHERE run_id=?",
            (event_id, self.clock.now(), run_id),
        )
        return event_id

    def _transition_run(
        self,
        cur: sqlite3.Cursor,
        run_id: str,
        to_state: str,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
    ) -> str | None:
        row = cur.execute("SELECT state FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise StateConflict(f"unknown run: {run_id}")
        from_state = row[0]
        if from_state == to_state:
            return None
        if to_state not in RUN_TRANSITIONS.get(from_state, set()):
            raise StateConflict(f"Run {from_state} -> {to_state} is forbidden")
        event_id = self._record_event(
            cur,
            run_id=run_id,
            entity_type="Run",
            entity_id=run_id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            payload=payload,
        )
        cur.execute("UPDATE runs SET state=?,updated_at=? WHERE run_id=?", (to_state, self.clock.now(), run_id))
        return event_id

    def _transition_project(
        self,
        cur: sqlite3.Cursor,
        run_id: str,
        project_id: str,
        to_state: str,
        event_type: str,
    ) -> str | None:
        row = cur.execute("SELECT status FROM projects WHERE project_id=?", (project_id,)).fetchone()
        if row is None:
            raise StateConflict(f"unknown project: {project_id}")
        from_state = row[0]
        if from_state == to_state:
            return None
        if to_state not in PROJECT_TRANSITIONS.get(from_state, set()):
            raise StateConflict(f"Project {from_state} -> {to_state} is forbidden")
        event_id = self._record_event(
            cur,
            run_id=run_id,
            entity_type="Project",
            entity_id=project_id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
        )
        cur.execute("UPDATE projects SET status=?,updated_at=? WHERE project_id=?", (to_state, self.clock.now(), project_id))
        return event_id

    def _transition_card(
        self,
        cur: sqlite3.Cursor,
        run_id: str,
        card_id: str,
        to_state: str,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
    ) -> str | None:
        row = cur.execute("SELECT state,state_version FROM cards WHERE card_id=?", (card_id,)).fetchone()
        if row is None:
            raise StateConflict(f"unknown card: {card_id}")
        from_state = row[0]
        if from_state == to_state:
            return None
        if to_state not in CARD_TRANSITIONS.get(from_state, set()):
            raise StateConflict(f"Card {from_state} -> {to_state} is forbidden")
        event_id = self._record_event(
            cur,
            run_id=run_id,
            entity_type="Card",
            entity_id=card_id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            payload=payload,
        )
        cur.execute(
            "UPDATE cards SET state=?,state_version=state_version+1,updated_at=? WHERE card_id=?",
            (to_state, self.clock.now(), card_id),
        )
        return event_id

    def _transition_attempt(
        self,
        cur: sqlite3.Cursor,
        run_id: str,
        attempt_id: str,
        to_state: str,
        event_type: str,
        *,
        result: str | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> str | None:
        row = cur.execute("SELECT state,state_version,result FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        if row is None:
            raise StateConflict(f"unknown attempt: {attempt_id}")
        from_state = row[0]
        if from_state == to_state:
            return None
        if to_state not in ATTEMPT_TRANSITIONS.get(from_state, set()):
            raise StateConflict(f"Attempt {from_state} -> {to_state} is forbidden")
        if result is not None and result not in {"SUBMITTED", "EVIDENCE_VERIFIED", "NO_PROGRESS", "TIMEOUT", "FAILED", "REJECTED", "BLOCKED"}:
            raise StateConflict(f"invalid attempt result: {result}")
        event_id = self._record_event(
            cur,
            run_id=run_id,
            entity_type="Attempt",
            entity_id=attempt_id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            payload=payload,
        )
        cur.execute(
            "UPDATE attempts SET state=?,state_version=state_version+1,last_transition_event_id=?,result=COALESCE(?,result),updated_at=? WHERE attempt_id=?",
            (to_state, event_id, result, self.clock.now(), attempt_id),
        )
        return event_id

    def _transition_dispatch(
        self,
        cur: sqlite3.Cursor,
        run_id: str,
        dispatch_id: str,
        to_state: str,
        event_type: str,
        payload: Mapping[str, Any] | None = None,
    ) -> str | None:
        row = cur.execute("SELECT state FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
        if row is None:
            raise StateConflict(f"unknown dispatch: {dispatch_id}")
        from_state = row[0]
        if from_state == to_state:
            return None
        if to_state not in DISPATCH_TRANSITIONS.get(from_state, set()):
            raise StateConflict(f"Dispatch {from_state} -> {to_state} is forbidden")
        event_id = self._record_event(
            cur,
            run_id=run_id,
            entity_type="Dispatch",
            entity_id=dispatch_id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            payload=payload,
        )
        cur.execute("UPDATE dispatches SET state=?,updated_at=? WHERE dispatch_id=?", (to_state, self.clock.now(), dispatch_id))
        return event_id

    def create_project(self, spec: Mapping[str, Any]) -> str:
        project_id = str(spec["project_id"])
        now = self.clock.now()
        values = {
            "profile_version": str(spec.get("profile_version", "w25-s0")),
            "canonical_root": str(spec.get("canonical_root", "/isolated/fake-project")),
            "discovery_root": spec.get("discovery_root"),
            "path_policy_hash": str(spec.get("path_policy_hash", canonical_hash({"paths": "isolated"}))),
            "autonomy_level": str(spec.get("autonomy_level", "A0")),
            "source_manifest_hash": str(spec.get("source_manifest_hash", canonical_hash({"source": project_id}))),
        }
        with self._transaction() as cur:
            existing = cur.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
            if existing is not None:
                for key in ("profile_version", "canonical_root", "path_policy_hash", "source_manifest_hash"):
                    if existing[key] != values[key]:
                        raise StateConflict(f"project provenance conflict: {project_id}:{key}")
                return project_id
            cur.execute(
                "INSERT INTO projects(project_id,profile_version,canonical_root,discovery_root,path_policy_hash,autonomy_level,status,source_manifest_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    project_id,
                    values["profile_version"],
                    values["canonical_root"],
                    values["discovery_root"],
                    values["path_policy_hash"],
                    values["autonomy_level"],
                    "DISCOVERED",
                    values["source_manifest_hash"],
                    now,
                    now,
                ),
            )
            # Project registration is fixture/bootstrap work performed before
            # a Run exists (the event table is Run-scoped).  Materialize the
            # complete W0 path here; the Run-scoped ACTIVE transition is
            # audited atomically by C0 below.
            cur.execute("UPDATE projects SET status='REGISTERED',updated_at=? WHERE project_id=?", (now, project_id))
            cur.execute("UPDATE projects SET status='READY',updated_at=? WHERE project_id=?", (now, project_id))
        return project_id

    @staticmethod
    def _spec_with_defaults(spec: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(spec)
        required = ("project_id", "run_id", "card_id", "goal_id", "plan_id", "plan_version")
        missing = [key for key in required if not result.get(key)]
        if missing:
            raise ValueError(f"missing fixture fields: {', '.join(missing)}")
        result.setdefault("mode", "card")
        result.setdefault("queue_hash", canonical_hash({"queue": result["card_id"]}))
        result.setdefault("policy_hash", canonical_hash({"policy": "w0-p0"}))
        result.setdefault("card_hash", canonical_hash({"card": result["card_id"], "objective": result.get("objective", "") }))
        result.setdefault("capability_set_hash", canonical_hash({"capabilities": []}))
        result.setdefault("input_snapshot_hash", canonical_hash({"snapshot": result["card_id"]}))
        result.setdefault("context_pack_hash", canonical_hash({"context": result["card_id"]}))
        result.setdefault("command_hash", canonical_hash({"command": "fake-executor"}))
        result.setdefault("title", "W2.5-S0 fake card")
        result.setdefault("objective", "prove one deterministic P0 card")
        result.setdefault("non_goals", ["real worker", "network", "DONE"])
        result.setdefault("dependencies", [])
        result.setdefault("postconditions", ["receipt_verified", "evidence_verified"])
        result.setdefault("budget", {"attempts": 1, "walltime": 60})
        result.setdefault("next_action", {"action": "stop", "reason": "p0-boundary"})
        return result

    def _ensure_run_and_card(self, spec: Mapping[str, Any]) -> str:
        spec = self._spec_with_defaults(spec)
        run_id = str(spec["run_id"])
        card_id = str(spec["card_id"])
        self.create_project(spec)

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            project = cur.execute("SELECT status FROM projects WHERE project_id=?", (spec["project_id"],)).fetchone()
            if project is None:
                raise StateConflict(f"project missing: {spec['project_id']}")
            run = cur.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if run is None:
                cur.execute(
                    "INSERT INTO runs(run_id,project_id,goal_id,plan_id,plan_version,mode,state,queue_hash,policy_hash,context_pack_hash,lease_token,lease_owner_id,lease_expires_at,last_heartbeat_at,fencing_epoch,last_committed_event_id,resume_point_id,active_dispatch_id,budget_json,next_action_json,input_spec_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        run_id,
                        spec["project_id"],
                        spec["goal_id"],
                        spec["plan_id"],
                        spec["plan_version"],
                        spec["mode"],
                        "CREATED",
                        spec["queue_hash"],
                        spec["policy_hash"],
                        spec["context_pack_hash"],
                        None,
                        None,
                        None,
                        None,
                        1,
                        None,
                        None,
                        None,
                        _json(spec["budget"]),
                        _json(spec["next_action"]),
                        _json(spec),
                        self.clock.now(),
                        self.clock.now(),
                    ),
                )
                self._record_event(cur, run_id=run_id, entity_type="Run", entity_id=run_id, event_type="RUN_CREATED", from_state=None, to_state="CREATED", payload={"admit_key": run_id})
                run = cur.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            else:
                for key in ("project_id", "goal_id", "plan_id", "plan_version", "queue_hash", "policy_hash", "context_pack_hash"):
                    expected = spec[key]
                    if run[key] != expected:
                        raise StateConflict(f"run provenance conflict: {run_id}:{key}")

            self._transition_project(cur, run_id, str(spec["project_id"]), "ACTIVE", "PROJECT_ACTIVE")
            self._transition_run(cur, run_id, "PREFLIGHT", "RUN_PREFLIGHT")
            self._transition_run(cur, run_id, "READY", "RUN_READY")

            card = cur.execute("SELECT * FROM cards WHERE card_id=?", (card_id,)).fetchone()
            if card is None:
                cur.execute(
                    "INSERT INTO cards(card_id,project_id,run_id,goal_id,plan_id,plan_version,card_hash,source_queue_hash,title,objective,non_goals_json,dependencies_json,postconditions_json,capability_set_hash,state,state_version,active_attempt_id,attempt_ids_json,acceptance_txn_id,next_card_intent_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        card_id,
                        spec["project_id"],
                        run_id,
                        spec["goal_id"],
                        spec["plan_id"],
                        spec["plan_version"],
                        spec["card_hash"],
                        spec["queue_hash"],
                        spec["title"],
                        spec["objective"],
                        _json(spec["non_goals"]),
                        _json(spec["dependencies"]),
                        _json(spec["postconditions"]),
                        spec["capability_set_hash"],
                        "DRAFT",
                        0,
                        None,
                        _json([]),
                        None,
                        None,
                        self.clock.now(),
                        self.clock.now(),
                    ),
                )
                self._record_event(cur, run_id=run_id, entity_type="Card", entity_id=card_id, event_type="CARD_CREATED", from_state=None, to_state="DRAFT", payload={"card_hash": spec["card_hash"]})
                self._transition_card(cur, run_id, card_id, "WAITING", "CARD_WAITING")
                self._transition_card(cur, run_id, card_id, "READY", "CARD_READY")
            else:
                if card["run_id"] != run_id or card["card_hash"] != spec["card_hash"]:
                    raise StateConflict(f"card identity/provenance conflict: {card_id}")
            return {"run_id": run_id, "card_id": card_id, "admitted": True}

        self._phase(run_id, "C0", "run-admit", mutation)
        return run_id

    def _dispatch_intent(self, spec: Mapping[str, Any]) -> None:
        spec = self._spec_with_defaults(spec)
        run_id, card_id = str(spec["run_id"]), str(spec["card_id"])
        attempt_id = f"attempt-{card_id}-001"
        dispatch_id = f"dispatch-{attempt_id}"
        dispatch_key = f"dispatch-key:{run_id}:{card_id}:001"
        idempotency_key = f"idempotency:{run_id}:{card_id}:001"

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            run = cur.execute("SELECT state,fencing_epoch FROM runs WHERE run_id=?", (run_id,)).fetchone()
            card = cur.execute("SELECT state FROM cards WHERE card_id=?", (card_id,)).fetchone()
            if run is None or card is None:
                raise StateConflict("C0 must be admitted before C1")
            if card[0] not in {"READY", "CLAIMED", "IN_PROGRESS", "SUBMITTED", "REVIEW_PENDING"}:
                raise StateConflict(f"card cannot receive dispatch intent from {card[0]}")
            attempt = cur.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if attempt is None:
                cur.execute(
                    "INSERT INTO attempts(attempt_id,attempt_no,card_id,run_id,retry_of,state,result,state_version,last_transition_event_id,dispatch_id,input_snapshot_hash,context_pack_hash,worker_id,command_hash,progress_signature,progress_signature_count,artifact_manifest_hash,receipt_id,review_id,deadline_at,heartbeat_deadline_at,last_heartbeat_at,deadline_policy_hash,started_at,finished_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        attempt_id,
                        1,
                        card_id,
                        run_id,
                        None,
                        "CREATED",
                        None,
                        0,
                        None,
                        dispatch_id,
                        spec["input_snapshot_hash"],
                        spec["context_pack_hash"],
                        None,
                        spec["command_hash"],
                        None,
                        0,
                        None,
                        None,
                        None,
                        self.clock.epoch() + 60,
                        self.clock.epoch() + 30,
                        None,
                        spec["policy_hash"],
                        None,
                        None,
                        self.clock.now(),
                        self.clock.now(),
                    ),
                )
                self._record_event(cur, run_id=run_id, entity_type="Attempt", entity_id=attempt_id, event_type="ATTEMPT_CREATED", from_state=None, to_state="CREATED", payload={"attempt_no": 1})
                self._transition_attempt(cur, run_id, attempt_id, "ADMITTED", "ATTEMPT_ADMITTED")
                cur.execute("UPDATE cards SET active_attempt_id=?,attempt_ids_json=?,updated_at=? WHERE card_id=?", (attempt_id, _json([attempt_id]), self.clock.now(), card_id))
            else:
                if attempt["input_snapshot_hash"] != spec["input_snapshot_hash"] or attempt["command_hash"] != spec["command_hash"]:
                    raise StateConflict("attempt idempotency/provenance conflict")

            dispatch = cur.execute("SELECT * FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
            if dispatch is None:
                run_token = f"run-token:{run_id}:{attempt_id}"
                cur.execute(
                    "INSERT INTO dispatches(dispatch_id,dispatch_key,idempotency_key,attempt_id,run_id,state,run_token,fencing_epoch,owner_id,command_hash,pid,process_starttime,boot_id,pidfd_ref,cgroup_ref,ack_deadline_at,lease_expires_at,heartbeat_at,spawn_attempt_no,max_spawn_attempts,executor_kind,row_version,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        dispatch_id,
                        dispatch_key,
                        idempotency_key,
                        attempt_id,
                        run_id,
                        "DISPATCH_INTENDED",
                        run_token,
                        run["fencing_epoch"],
                        "p0-controller",
                        spec["command_hash"],
                        None,
                        None,
                        None,
                        None,
                        None,
                        self.clock.epoch() + 60,
                        self.clock.epoch() + 60,
                        None,
                        0,
                        1,
                        "fake",
                        0,
                        self.clock.now(),
                        self.clock.now(),
                    ),
                )
                self._record_event(cur, run_id=run_id, entity_type="Dispatch", entity_id=dispatch_id, event_type="DISPATCH_INTENDED", from_state=None, to_state="DISPATCH_INTENDED", payload={"dispatch_key": dispatch_key, "idempotency_key": idempotency_key})
                cur.execute("UPDATE attempts SET dispatch_id=? WHERE attempt_id=?", (dispatch_id, attempt_id))
            else:
                if dispatch["idempotency_key"] != idempotency_key or dispatch["command_hash"] != spec["command_hash"]:
                    raise StateConflict("IDEMPOTENCY_CONFLICT")
            self._transition_run(cur, run_id, "DISPATCHING", "RUN_DISPATCHING")
            cur.execute("UPDATE runs SET active_dispatch_id=?,updated_at=? WHERE run_id=?", (dispatch_id, self.clock.now(), run_id))
            return {"attempt_id": attempt_id, "dispatch_id": dispatch_id, "idempotency_key": idempotency_key}

        self._phase(run_id, "C1", "dispatch-intent", mutation)

    def _claim_lease(self, spec: Mapping[str, Any]) -> None:
        run_id, card_id = str(spec["run_id"]), str(spec["card_id"])
        dispatch_id, attempt_id = f"dispatch-attempt-{card_id}-001", f"attempt-{card_id}-001"

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            dispatch = cur.execute("SELECT * FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
            run = cur.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if dispatch is None or run is None:
                raise StateConflict("C1 must create dispatch before C2")
            if dispatch["state"] == "DISPATCH_INTENDED":
                epoch = int(run["fencing_epoch"])
                lease_token = f"lease:{run_id}:epoch:{epoch}"
                expiry = self.clock.epoch() + 60
                self._transition_dispatch(cur, run_id, dispatch_id, "CLAIMED", "DISPATCH_CLAIMED", {"owner_id": "p0-controller", "fencing_epoch": epoch})
                cur.execute("UPDATE dispatches SET owner_id=?,fencing_epoch=?,lease_expires_at=?,heartbeat_at=?,updated_at=? WHERE dispatch_id=?", ("p0-controller", epoch, expiry, self.clock.now(), self.clock.now(), dispatch_id))
                cur.execute("UPDATE runs SET lease_token=?,lease_owner_id=?,lease_expires_at=?,last_heartbeat_at=?,updated_at=? WHERE run_id=?", (lease_token, "p0-controller", expiry, self.clock.now(), self.clock.now(), run_id))
                self._transition_card(cur, run_id, card_id, "CLAIMED", "CARD_CLAIMED")
            elif dispatch["state"] != "CLAIMED":
                raise StateConflict(f"unexpected dispatch state for C2: {dispatch['state']}")
            return {"dispatch_id": dispatch_id, "attempt_id": attempt_id, "owner_id": "p0-controller", "fencing_epoch": int(run["fencing_epoch"])}

        self._phase(run_id, "C2", "claim-lease", mutation)

    def _spawn_request(self, spec: Mapping[str, Any]) -> None:
        run_id, card_id = str(spec["run_id"]), str(spec["card_id"])
        dispatch_id = f"dispatch-attempt-{card_id}-001"

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            dispatch = cur.execute("SELECT * FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
            if dispatch is None or dispatch["state"] != "CLAIMED":
                if dispatch is not None and dispatch["state"] == "SPAWN_REQUESTED":
                    return {"dispatch_id": dispatch_id, "spawn_attempt_no": dispatch["spawn_attempt_no"]}
                raise StateConflict("C2 must claim dispatch before C3")
            attempt_no = int(dispatch["spawn_attempt_no"]) + 1
            if attempt_no > int(dispatch["max_spawn_attempts"]):
                raise StateConflict("max_spawn_attempts exhausted")
            self._transition_dispatch(cur, run_id, dispatch_id, "SPAWN_REQUESTED", "SPAWN_REQUESTED", {"run_token": dispatch["run_token"], "command_hash": dispatch["command_hash"]})
            cur.execute("UPDATE dispatches SET spawn_attempt_no=?,updated_at=? WHERE dispatch_id=?", (attempt_no, self.clock.now(), dispatch_id))
            return {"dispatch_id": dispatch_id, "spawn_attempt_no": attempt_no, "run_token": dispatch["run_token"]}

        had_marker = self._marker(run_id, "spawn-request") is not None
        self._phase(run_id, "C3", "spawn-request", mutation)
        if not had_marker:
            self._spawn_request_context.add(dispatch_id)

    def _rehydrate_identity(self, dispatch_id: str, *, derive_unconfirmed: bool = False) -> FakeProcessIdentity | None:
        row = self.conn.execute("SELECT * FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
        if row is None:
            raise StateConflict(f"unknown dispatch: {dispatch_id}")
        existing = self.executor.identity_for(dispatch_id)
        if existing is not None:
            if (
                existing.run_token != row["run_token"]
                or existing.fencing_epoch != int(row["fencing_epoch"])
                or existing.command_hash != row["command_hash"]
            ):
                raise FencingError(f"stale executor identity: {dispatch_id}")
            return existing
        if row["pid"] is not None:
            identity = FakeProcessIdentity(
                pid=int(row["pid"]),
                starttime=str(row["process_starttime"]),
                boot_id=str(row["boot_id"]),
                pidfd_ref=str(row["pidfd_ref"]),
                cgroup_ref=str(row["cgroup_ref"]),
                run_token=str(row["run_token"]),
                fencing_epoch=int(row["fencing_epoch"]),
                command_hash=str(row["command_hash"]),
            )
            self.executor.adopt(dispatch_id, identity)
            return identity
        if derive_unconfirmed and row["state"] in {"SPAWN_REQUESTED", "DISPATCH_UNCONFIRMED", "RECONCILING"} and int(row["spawn_attempt_no"]) >= 1:
            identity = self.executor.derive_identity(
                dispatch_id=dispatch_id,
                run_token=row["run_token"],
                fencing_epoch=int(row["fencing_epoch"]),
                command_hash=row["command_hash"],
            )
            self.executor.adopt(dispatch_id, identity)
            return identity
        return None

    def _identity(self, dispatch_id: str) -> FakeProcessIdentity:
        row = self.conn.execute("SELECT * FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
        if row is None:
            raise StateConflict(f"unknown dispatch: {dispatch_id}")
        rehydrated = self._rehydrate_identity(dispatch_id)
        if rehydrated is not None:
            return rehydrated
        if row["state"] in {"SPAWN_REQUESTED", "DISPATCH_UNCONFIRMED", "RECONCILING"} and int(row["spawn_attempt_no"]) >= 1:
            # C3 is durable.  If the current session did not issue the
            # request, this is a reopen/recovery path.  C3's after-marker
            # crash is the one exception: the request had not reached C4 yet.
            c3_after_marker = self.conn.execute(
                "SELECT 1 FROM fault_observations WHERE run_id=? AND commit_point='C3' AND hook='after_commit_marker'",
                (row["run_id"],),
            ).fetchone()
            if dispatch_id in self._spawn_request_context or c3_after_marker is not None:
                return self.executor.spawn(
                    dispatch_id=dispatch_id,
                    run_token=row["run_token"],
                    fencing_epoch=int(row["fencing_epoch"]),
                    command_hash=row["command_hash"],
                )
            identity = self.executor.derive_identity(
                dispatch_id=dispatch_id,
                run_token=row["run_token"],
                fencing_epoch=int(row["fencing_epoch"]),
                command_hash=row["command_hash"],
            )
            self.executor.adopt(dispatch_id, identity)
            return identity
        return self.executor.spawn(
            dispatch_id=dispatch_id,
            run_token=row["run_token"],
            fencing_epoch=int(row["fencing_epoch"]),
            command_hash=row["command_hash"],
        )

    def _rehydrate_identity_under_fence(self, run_id: str, dispatch_id: str) -> None:
        """Adopt persisted fake identity only while holding the DB fence."""

        with self._transaction() as cur:
            self._assert_runtime_anchor_cursor(cur, run_id)
            run = cur.execute(
                "SELECT lease_owner_id,lease_token,lease_expires_at,fencing_epoch FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            dispatch = cur.execute(
                "SELECT fencing_epoch FROM dispatches WHERE dispatch_id=? AND run_id=?",
                (dispatch_id, run_id),
            ).fetchone()
            if run is None or dispatch is None:
                raise StateConflict(f"missing fence identity for {dispatch_id}")
            self._assert_fencing_cursor(
                cur,
                run_id,
                owner_id=str(run["lease_owner_id"]),
                lease_token=str(run["lease_token"]),
                fencing_epoch=int(run["fencing_epoch"]),
            )
            if int(dispatch["fencing_epoch"]) != int(run["fencing_epoch"]):
                raise FencingError(f"dispatch fence mismatch: {dispatch_id}")
            identity = self._rehydrate_identity(dispatch_id, derive_unconfirmed=True)
            if identity is not None and identity.fencing_epoch != int(run["fencing_epoch"]):
                raise FencingError(f"stale executor identity: {dispatch_id}")

    def _executor_ack(self, spec: Mapping[str, Any]) -> None:
        run_id, card_id = str(spec["run_id"]), str(spec["card_id"])
        dispatch_id, attempt_id = f"dispatch-attempt-{card_id}-001", f"attempt-{card_id}-001"
        lease = self.lease_snapshot(run_id)
        self.assert_fencing(
            run_id,
            owner_id=str(lease["lease_owner_id"]),
            lease_token=str(lease["lease_token"]),
            fencing_epoch=int(lease["fencing_epoch"]),
        )
        expected_owner_id = str(lease["lease_owner_id"])
        expected_lease_token = str(lease["lease_token"])
        expected_fencing_epoch = int(lease["fencing_epoch"])

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            self._assert_fencing_cursor(
                cur,
                run_id,
                owner_id=expected_owner_id,
                lease_token=expected_lease_token,
                fencing_epoch=expected_fencing_epoch,
            )
            dispatch = cur.execute("SELECT * FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
            if dispatch is None:
                raise StateConflict("C3 must create spawn request before C4")
            identity = self._identity(dispatch_id)
            self.executor.acknowledge(dispatch_id, identity)
            if dispatch["state"] == "EXECUTOR_ACKED":
                return {"dispatch_id": dispatch_id, "identity": identity.as_dict()}
            if dispatch["state"] != "SPAWN_REQUESTED":
                raise StateConflict(f"unexpected dispatch state for C4: {dispatch['state']}")
            if identity.run_token != dispatch["run_token"] or identity.fencing_epoch != dispatch["fencing_epoch"] or identity.command_hash != dispatch["command_hash"]:
                raise EvidenceError("executor ack identity mismatch")
            self._transition_dispatch(cur, run_id, dispatch_id, "EXECUTOR_ACKED", "EXECUTOR_ACKED", identity.as_dict())
            cur.execute(
                "UPDATE dispatches SET pid=?,process_starttime=?,boot_id=?,pidfd_ref=?,cgroup_ref=?,heartbeat_at=?,updated_at=? WHERE dispatch_id=?",
                (identity.pid, identity.starttime, identity.boot_id, identity.pidfd_ref, identity.cgroup_ref, self.clock.now(), self.clock.now(), dispatch_id),
            )
            self._transition_attempt(cur, run_id, attempt_id, "STARTING", "ATTEMPT_STARTING")
            cur.execute("UPDATE attempts SET worker_id=?,started_at=? WHERE attempt_id=?", ("fake-executor", self.clock.now(), attempt_id))
            return {"dispatch_id": dispatch_id, "identity": identity.as_dict()}

        self._phase(run_id, "C4", "executor-ack", mutation)

    def _checkpoint(self, spec: Mapping[str, Any]) -> None:
        run_id, card_id = str(spec["run_id"]), str(spec["card_id"])
        dispatch_id, attempt_id = f"dispatch-attempt-{card_id}-001", f"attempt-{card_id}-001"
        lease = self.lease_snapshot(run_id)
        self.assert_fencing(
            run_id,
            owner_id=str(lease["lease_owner_id"]),
            lease_token=str(lease["lease_token"]),
            fencing_epoch=int(lease["fencing_epoch"]),
        )
        expected_owner_id = str(lease["lease_owner_id"])
        expected_lease_token = str(lease["lease_token"])
        expected_fencing_epoch = int(lease["fencing_epoch"])

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            self._assert_fencing_cursor(
                cur,
                run_id,
                owner_id=expected_owner_id,
                lease_token=expected_lease_token,
                fencing_epoch=expected_fencing_epoch,
            )
            dispatch = cur.execute("SELECT * FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
            attempt = cur.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if dispatch is None or attempt is None:
                raise StateConflict("C4 must ack executor before C5")
            if dispatch["state"] not in {"EXECUTOR_ACKED", "RUNNING"}:
                raise StateConflict(f"unexpected dispatch state for C5: {dispatch['state']}")
            identity = self._identity(dispatch_id)
            self.executor.mark_running(dispatch_id, identity)
            if dispatch["state"] == "RUNNING":
                checkpoint = cur.execute("SELECT * FROM checkpoints WHERE attempt_id=?", (attempt_id,)).fetchone()
                if checkpoint:
                    return {"checkpoint_id": checkpoint["checkpoint_id"], "state_hash": checkpoint["state_hash"]}
            self._transition_dispatch(cur, run_id, dispatch_id, "RUNNING", "DISPATCH_RUNNING", identity.as_dict())
            self._transition_attempt(cur, run_id, attempt_id, "RUNNING", "ATTEMPT_RUNNING")
            self._transition_card(cur, run_id, str(spec["card_id"]), "IN_PROGRESS", "CARD_IN_PROGRESS")
            self._transition_run(cur, run_id, "RUNNING", "RUN_RUNNING")
            attempt_after = cur.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            state_hash = self.canonical_attempt_state_hash(_row(attempt_after))
            checkpoint_id = f"checkpoint-{attempt_id}-001"
            cur.execute(
                "INSERT INTO checkpoints(checkpoint_id,attempt_id,state_hash,receipt_id,payload_json,created_at) VALUES (?,?,?,?,?,?)",
                (checkpoint_id, attempt_id, state_hash, None, _json({"executor": "fake", "dispatch_id": dispatch_id, "state": "RUNNING"}), self.clock.now()),
            )
            return {"checkpoint_id": checkpoint_id, "state_hash": state_hash}

        had_marker = self._marker(run_id, "checkpoint") is not None
        self._phase(run_id, "C5", "checkpoint", mutation)
        if had_marker:
            self._rehydrate_identity_under_fence(run_id, dispatch_id)

    def _artifact_data(self, spec: Mapping[str, Any], attempt_id: str) -> tuple[str, list[str]]:
        artifact_hashes = [canonical_hash({"attempt_id": attempt_id, "artifact": "fake-output", "ordinal": 1})]
        return canonical_hash({"attempt_id": attempt_id, "artifact_hashes": artifact_hashes, "scope": "fake://p0"}), artifact_hashes

    def _receipt_core(
        self,
        *,
        receipt_id: str,
        receipt_kind: str,
        state: str,
        run_id: str,
        dispatch_id: str | None,
        attempt_id: str | None,
        card_id: str | None,
        parent_receipt_id: str | None,
        plan_version: str | None,
        queue_hash: str | None,
        card_hash: str | None,
        input_snapshot_hash: str | None,
        review_id: str | None,
        policy_hash: str,
        capability_set_hash: str,
        command_hash: str | None,
        artifact_manifest_hash: str | None,
        validator_id: str | None,
        validator_version: str | None,
        result: str,
        next_action: Mapping[str, Any],
        artifact_hashes: list[str],
        validation_result: Mapping[str, Any],
        created_at: str,
        sealed_at: str | None,
        verified_at: str | None,
        commit_txn_id: str | None,
        canonical_state_hash: str,
    ) -> dict[str, Any]:
        # This is the exact immutable input to receipt_body_hash.  The three
        # derived hash fields are deliberately absent.
        return {
            "receipt_id": receipt_id,
            "receipt_kind": receipt_kind,
            "state": state,
            "run_id": run_id,
            "dispatch_id": dispatch_id,
            "attempt_id": attempt_id,
            "card_id": card_id,
            "parent_receipt_id": parent_receipt_id,
            "plan_version": plan_version,
            "queue_hash": queue_hash,
            "card_hash": card_hash,
            "input_snapshot_hash": input_snapshot_hash,
            "review_id": review_id,
            "policy_hash": policy_hash,
            "capability_set_hash": capability_set_hash,
            "command_hash": command_hash,
            "artifact_manifest_hash": artifact_manifest_hash,
            "validator_id": validator_id,
            "validator_version": validator_version,
            "result": result,
            "next_action": dict(next_action),
            "artifact_hashes": sorted(artifact_hashes),
            "validation_result": dict(validation_result),
            "created_at": created_at,
            "sealed_at": sealed_at,
            "verified_at": verified_at,
            "commit_txn_id": commit_txn_id,
            "canonical_state_hash": canonical_state_hash,
        }

    def _seal_receipt(self, core: Mapping[str, Any]) -> tuple[str, str, str]:
        body_hash = canonical_hash(core)
        progress_payload = {
            "card_id": core["card_id"],
            "attempt_id": core["attempt_id"],
            "attempt_no": 1,
            "canonical_state_hash": core["canonical_state_hash"],
            "artifact_hashes": sorted(core["artifact_hashes"]),
            "validation_result": core["validation_result"],
            "receipt_body_hash": body_hash,
            "next_state": core["result"] if core["result"] in {"SUBMITTED", "EVIDENCE_VERIFIED"} else core["state"],
        }
        progress_signature = canonical_hash(progress_payload)
        receipt_hash = canonical_hash({**dict(core), "progress_signature": progress_signature})
        return body_hash, progress_signature, receipt_hash

    def _insert_receipt(
        self,
        cur: sqlite3.Cursor,
        *,
        spec: Mapping[str, Any],
        receipt_id: str,
        receipt_kind: str,
        state: str,
        run_id: str,
        dispatch_id: str,
        attempt_id: str,
        card_id: str,
        parent_receipt_id: str | None,
        artifact_manifest_hash: str,
        artifact_hashes: list[str],
        result: str,
        next_action: Mapping[str, Any],
        validation_result: Mapping[str, Any],
        validator_id: str | None,
        validator_version: str | None,
        canonical_state_hash: str,
        sealed_at: str | None,
        verified_at: str | None,
    ) -> dict[str, Any]:
        existing = cur.execute("SELECT * FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        core = self._receipt_core(
            receipt_id=receipt_id,
            receipt_kind=receipt_kind,
            state=state,
            run_id=run_id,
            dispatch_id=dispatch_id,
            attempt_id=attempt_id,
            card_id=card_id,
            parent_receipt_id=parent_receipt_id,
            plan_version=spec["plan_version"],
            queue_hash=spec["queue_hash"],
            card_hash=spec["card_hash"],
            input_snapshot_hash=spec["input_snapshot_hash"],
            review_id=None,
            policy_hash=spec["policy_hash"],
            capability_set_hash=spec["capability_set_hash"],
            command_hash=spec["command_hash"],
            artifact_manifest_hash=artifact_manifest_hash,
            validator_id=validator_id,
            validator_version=validator_version,
            result=result,
            next_action=next_action,
            artifact_hashes=artifact_hashes,
            validation_result=validation_result,
            created_at=self.clock.now(),
            sealed_at=sealed_at,
            verified_at=verified_at,
            commit_txn_id=None,
            canonical_state_hash=canonical_state_hash,
        )
        body_hash, progress_signature, receipt_hash = self._seal_receipt(core)
        if existing is not None:
            if existing["receipt_hash"] != receipt_hash or existing["receipt_body_hash"] != body_hash:
                raise EvidenceError(f"receipt replay/hash conflict: {receipt_id}")
            return _row(existing) or {}
        cur.execute(
            "INSERT INTO receipts(receipt_id,receipt_kind,state,run_id,dispatch_id,attempt_id,card_id,parent_receipt_id,plan_version,queue_hash,card_hash,input_snapshot_hash,review_id,policy_hash,capability_set_hash,command_hash,artifact_manifest_hash,validator_id,validator_version,result,next_action_json,artifact_hashes_json,validation_result_json,created_at,sealed_at,verified_at,commit_txn_id,receipt_body_hash,progress_signature,receipt_hash,core_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                receipt_id,
                receipt_kind,
                state,
                run_id,
                dispatch_id,
                attempt_id,
                card_id,
                parent_receipt_id,
                spec["plan_version"],
                spec["queue_hash"],
                spec["card_hash"],
                spec["input_snapshot_hash"],
                None,
                spec["policy_hash"],
                spec["capability_set_hash"],
                spec["command_hash"],
                artifact_manifest_hash,
                validator_id,
                validator_version,
                result,
                _json(next_action),
                _json(sorted(artifact_hashes)),
                _json(validation_result),
                self.clock.now(),
                sealed_at,
                verified_at,
                None,
                body_hash,
                progress_signature,
                receipt_hash,
                _json(core),
            ),
        )
        return _row(cur.execute("SELECT * FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()) or {}

    def _submission(self, spec: Mapping[str, Any]) -> None:
        spec = self._spec_with_defaults(spec)
        run_id, card_id = str(spec["run_id"]), str(spec["card_id"])
        dispatch_id, attempt_id = f"dispatch-attempt-{card_id}-001", f"attempt-{card_id}-001"
        lease = self.lease_snapshot(run_id)
        self.assert_fencing(
            run_id,
            owner_id=str(lease["lease_owner_id"]),
            lease_token=str(lease["lease_token"]),
            fencing_epoch=int(lease["fencing_epoch"]),
        )
        expected_owner_id = str(lease["lease_owner_id"])
        expected_lease_token = str(lease["lease_token"])
        expected_fencing_epoch = int(lease["fencing_epoch"])
        artifact_manifest_hash, artifact_hashes = self._artifact_data(spec, attempt_id)
        execution_receipt_id = f"receipt-execution-{attempt_id}"

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            self._assert_fencing_cursor(
                cur,
                run_id,
                owner_id=expected_owner_id,
                lease_token=expected_lease_token,
                fencing_epoch=expected_fencing_epoch,
            )
            dispatch = cur.execute("SELECT * FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
            attempt = cur.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if dispatch is None or attempt is None or dispatch["state"] != "RUNNING":
                if dispatch is not None and dispatch["state"] == "EXIT_REPORTED":
                    return {"dispatch_id": dispatch_id, "attempt_id": attempt_id, "receipt_id": execution_receipt_id, "artifact_manifest_hash": artifact_manifest_hash}
                raise StateConflict("C5 must run fake executor before C6")
            identity = self._identity(dispatch_id)
            self.executor.mark_running(dispatch_id, identity)
            self.executor.mark_exit(dispatch_id, identity)
            self._transition_dispatch(cur, run_id, dispatch_id, "EXIT_REPORTED", "EXIT_REPORTED", {"exit_code": 0})
            self._transition_attempt(cur, run_id, attempt_id, "SUBMITTED", "ATTEMPT_SUBMITTED", result="SUBMITTED")
            cur.execute("UPDATE attempts SET artifact_manifest_hash=?,finished_at=? WHERE attempt_id=?", (artifact_manifest_hash, self.clock.now(), attempt_id))
            cur.execute(
                "INSERT OR IGNORE INTO artifact_manifests(artifact_manifest_hash,attempt_id,artifact_hashes_json,scope_json,created_at) VALUES (?,?,?,?,?)",
                (artifact_manifest_hash, attempt_id, _json(artifact_hashes), _json({"scope": "fake://p0", "attempt_id": attempt_id}), self.clock.now()),
            )
            for ordinal, artifact_hash in enumerate(artifact_hashes, 1):
                cur.execute(
                    "INSERT OR IGNORE INTO artifacts(artifact_id,attempt_id,artifact_manifest_hash,artifact_hash,scope_ref,created_at) VALUES (?,?,?,?,?,?)",
                    (f"artifact-{attempt_id}-{ordinal:03d}", attempt_id, artifact_manifest_hash, artifact_hash, f"fake://p0/{attempt_id}/{ordinal}", self.clock.now()),
                )
            attempt_after = cur.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            state_hash = self.canonical_attempt_state_hash(_row(attempt_after))
            self._insert_receipt(
                cur,
                spec=spec,
                receipt_id=execution_receipt_id,
                receipt_kind="execution",
                state="SEALED",
                run_id=run_id,
                dispatch_id=dispatch_id,
                attempt_id=attempt_id,
                card_id=card_id,
                parent_receipt_id=None,
                artifact_manifest_hash=artifact_manifest_hash,
                artifact_hashes=artifact_hashes,
                result="SUBMITTED",
                next_action={"action": "verify_receipt", "attempt_id": attempt_id},
                validation_result={"result": "SUBMITTED", "validator_id": None},
                validator_id=None,
                validator_version=None,
                canonical_state_hash=state_hash,
                sealed_at=self.clock.now(),
                verified_at=None,
            )
            self._transition_card(cur, run_id, card_id, "SUBMITTED", "CARD_SUBMITTED")
            self._transition_run(cur, run_id, "VERIFYING", "RUN_VERIFYING")
            return {"dispatch_id": dispatch_id, "attempt_id": attempt_id, "receipt_id": execution_receipt_id, "artifact_manifest_hash": artifact_manifest_hash}

        had_marker = self._marker(run_id, "submission") is not None
        self._phase(run_id, "C6", "submission", mutation)
        if had_marker:
            self._rehydrate_identity_under_fence(run_id, dispatch_id)

    def canonical_attempt_state_hash(self, attempt: Mapping[str, Any] | None) -> str:
        if attempt is None:
            raise EvidenceError("attempt missing for canonical state hash")
        return canonical_hash(
            {
                "entity_type": "Attempt",
                "attempt_id": attempt["attempt_id"],
                "card_id": attempt["card_id"],
                "state": attempt["state"],
                "state_version": int(attempt["state_version"]),
                "last_transition_event_id": attempt["last_transition_event_id"],
                "result": attempt["result"],
            }
        )

    def _artifact_manifest_matches(
        self,
        manifest_hash: str | None,
        attempt_id: str | None,
        artifact_hashes: list[str],
    ) -> bool:
        if not manifest_hash or not attempt_id:
            return True
        manifest = self.conn.execute(
            "SELECT * FROM artifact_manifests WHERE artifact_manifest_hash=? AND attempt_id=?",
            (manifest_hash, attempt_id),
        ).fetchone()
        if manifest is None:
            return False
        stored_hashes = sorted(_parse(manifest["artifact_hashes_json"], []))
        scope = _parse(manifest["scope_json"], {})
        if stored_hashes != sorted(artifact_hashes) or scope.get("attempt_id") != attempt_id:
            return False
        artifact_rows = self.conn.execute(
            "SELECT attempt_id,artifact_manifest_hash,artifact_hash,scope_ref FROM artifacts WHERE artifact_manifest_hash=? AND attempt_id=? ORDER BY artifact_id",
            (manifest_hash, attempt_id),
        ).fetchall()
        if len(artifact_rows) != len(stored_hashes):
            return False
        if sorted(str(row["artifact_hash"]) for row in artifact_rows) != stored_hashes:
            return False
        if any(row["attempt_id"] != attempt_id or row["artifact_manifest_hash"] != manifest_hash for row in artifact_rows):
            return False
        for ordinal, row in enumerate(artifact_rows, 1):
            if row["scope_ref"] != f"fake://p0/{attempt_id}/{ordinal}":
                return False
        return canonical_hash(
            {
                "attempt_id": attempt_id,
                "artifact_hashes": stored_hashes,
                "scope": scope.get("scope"),
            }
        ) == manifest_hash

    def reconstruct_receipt_hashes(self, receipt_id: str) -> dict[str, Any]:
        receipt = self.conn.execute("SELECT * FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
        if receipt is None:
            raise EvidenceError(f"receipt missing: {receipt_id}")
        core = _parse(receipt["core_json"], {})
        row_core = {
            "receipt_id": receipt["receipt_id"],
            "receipt_kind": receipt["receipt_kind"],
            "state": receipt["state"],
            "run_id": receipt["run_id"],
            "dispatch_id": receipt["dispatch_id"],
            "attempt_id": receipt["attempt_id"],
            "card_id": receipt["card_id"],
            "parent_receipt_id": receipt["parent_receipt_id"],
            "plan_version": receipt["plan_version"],
            "queue_hash": receipt["queue_hash"],
            "card_hash": receipt["card_hash"],
            "input_snapshot_hash": receipt["input_snapshot_hash"],
            "review_id": receipt["review_id"],
            "policy_hash": receipt["policy_hash"],
            "capability_set_hash": receipt["capability_set_hash"],
            "command_hash": receipt["command_hash"],
            "artifact_manifest_hash": receipt["artifact_manifest_hash"],
            "validator_id": receipt["validator_id"],
            "validator_version": receipt["validator_version"],
            "result": receipt["result"],
            "next_action": _parse(receipt["next_action_json"], {}),
            "artifact_hashes": sorted(_parse(receipt["artifact_hashes_json"], [])),
            "validation_result": _parse(receipt["validation_result_json"], {}),
            "created_at": receipt["created_at"],
            "sealed_at": receipt["sealed_at"],
            "verified_at": receipt["verified_at"],
            "commit_txn_id": receipt["commit_txn_id"],
            "canonical_state_hash": core.get("canonical_state_hash"),
        }
        core_matches_row = canonical_json(row_core) == canonical_json(core)
        attempt_state_matches = True
        if receipt["receipt_kind"] == "validation" and receipt["attempt_id"]:
            attempt = self.conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (receipt["attempt_id"],)).fetchone()
            attempt_state_matches = attempt is not None and self.canonical_attempt_state_hash(_row(attempt)) == core.get("canonical_state_hash")
        artifact_manifest_matches = self._artifact_manifest_matches(
            core.get("artifact_manifest_hash"),
            core.get("attempt_id"),
            list(core.get("artifact_hashes", [])),
        )
        body_hash = canonical_hash(core)
        progress_payload = {
            "card_id": core["card_id"],
            "attempt_id": core["attempt_id"],
            "attempt_no": 1,
            "canonical_state_hash": core["canonical_state_hash"],
            "artifact_hashes": sorted(core["artifact_hashes"]),
            "validation_result": core["validation_result"],
            "receipt_body_hash": body_hash,
            "next_state": core["result"] if core["result"] in {"SUBMITTED", "EVIDENCE_VERIFIED"} else core["state"],
        }
        progress_signature = canonical_hash(progress_payload)
        receipt_hash = canonical_hash({**core, "progress_signature": progress_signature})
        return {
            "receipt_body_hash": body_hash,
            "progress_payload": progress_payload,
            "progress_signature": progress_signature,
            "receipt_hash": receipt_hash,
            "stored": {
                "receipt_body_hash": receipt["receipt_body_hash"],
                "progress_signature": receipt["progress_signature"],
                "receipt_hash": receipt["receipt_hash"],
            },
            "valid": core_matches_row and attempt_state_matches and artifact_manifest_matches and body_hash == receipt["receipt_body_hash"] and progress_signature == receipt["progress_signature"] and receipt_hash == receipt["receipt_hash"],
            "core_matches_row": core_matches_row,
            "attempt_state_matches": attempt_state_matches,
            "artifact_manifest_matches": artifact_manifest_matches,
        }

    def validate_receipt(self, receipt_id: str) -> bool:
        result = self.reconstruct_receipt_hashes(receipt_id)
        if not result["valid"]:
            raise EvidenceError(f"receipt hash mismatch: {receipt_id}")
        return True

    def _receipt_verify(self, spec: Mapping[str, Any]) -> None:
        spec = self._spec_with_defaults(spec)
        run_id, card_id = str(spec["run_id"]), str(spec["card_id"])
        dispatch_id, attempt_id = f"dispatch-attempt-{card_id}-001", f"attempt-{card_id}-001"
        execution_receipt_id = f"receipt-execution-{attempt_id}"
        validation_receipt_id = f"receipt-validation-{attempt_id}"
        lease = self.lease_snapshot(run_id)
        self.assert_fencing(
            run_id,
            owner_id=str(lease["lease_owner_id"]),
            lease_token=str(lease["lease_token"]),
            fencing_epoch=int(lease["fencing_epoch"]),
        )
        expected_owner_id = str(lease["lease_owner_id"])
        expected_lease_token = str(lease["lease_token"])
        expected_fencing_epoch = int(lease["fencing_epoch"])
        self.validate_receipt(execution_receipt_id)

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            self._assert_fencing_cursor(
                cur,
                run_id,
                owner_id=expected_owner_id,
                lease_token=expected_lease_token,
                fencing_epoch=expected_fencing_epoch,
            )
            attempt = cur.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            dispatch = cur.execute("SELECT * FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()
            card = cur.execute("SELECT * FROM cards WHERE card_id=?", (card_id,)).fetchone()
            if attempt is None or dispatch is None or card is None:
                raise StateConflict("C6 must submit before C7")
            existing = cur.execute("SELECT * FROM receipts WHERE receipt_id=?", (validation_receipt_id,)).fetchone()
            if existing is None:
                if attempt["state"] != "SUBMITTED":
                    raise StateConflict(f"unexpected attempt state for C7: {attempt['state']}")
                self._transition_attempt(cur, run_id, attempt_id, "EVIDENCE_VERIFIED", "ATTEMPT_EVIDENCE_VERIFIED", result="EVIDENCE_VERIFIED")
                attempt_after = cur.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
                state_hash = self.canonical_attempt_state_hash(_row(attempt_after))
                manifest = cur.execute("SELECT * FROM artifact_manifests WHERE artifact_manifest_hash=?", (attempt_after["artifact_manifest_hash"],)).fetchone()
                if manifest is None:
                    raise EvidenceError("artifact manifest missing during C7")
                artifact_hashes = _parse(manifest["artifact_hashes_json"], [])
                self._insert_receipt(
                    cur,
                    spec=spec,
                    receipt_id=validation_receipt_id,
                    receipt_kind="validation",
                    state="VERIFIED",
                    run_id=run_id,
                    dispatch_id=dispatch_id,
                    attempt_id=attempt_id,
                    card_id=card_id,
                    parent_receipt_id=execution_receipt_id,
                    artifact_manifest_hash=attempt_after["artifact_manifest_hash"],
                    artifact_hashes=artifact_hashes,
                    result="EVIDENCE_VERIFIED",
                    next_action={"action": "stop_p0", "reason": "review_and_acceptance_disabled"},
                    validation_result={"result": "EVIDENCE_VERIFIED", "validator_id": "w25-deterministic-validator", "validator_version": "1"},
                    validator_id="w25-deterministic-validator",
                    validator_version="1",
                    canonical_state_hash=state_hash,
                    sealed_at=self.clock.now(),
                    verified_at=self.clock.now(),
                )
                cur.execute("UPDATE attempts SET receipt_id=? WHERE attempt_id=?", (validation_receipt_id, attempt_id))
                self._transition_dispatch(cur, run_id, dispatch_id, "COMPLETED", "DISPATCH_COMPLETED")
            else:
                self.validate_receipt(validation_receipt_id)
            return {"attempt_id": attempt_id, "receipt_id": validation_receipt_id, "state": "VERIFIED"}

        self._phase(run_id, "C7", "receipt-verify", mutation)

    def _p0_review_gate(self, spec: Mapping[str, Any]) -> None:
        run_id, attempt_id = str(spec["run_id"]), f"attempt-{spec['card_id']}-001"

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            run = cur.execute("SELECT state FROM runs WHERE run_id=?", (run_id,)).fetchone()
            card = cur.execute("SELECT state FROM cards WHERE card_id=?", (spec["card_id"],)).fetchone()
            attempt = cur.execute("SELECT state FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if run is None or card is None or attempt is None or run[0] != "VERIFYING" or card[0] != "SUBMITTED" or attempt[0] != "EVIDENCE_VERIFIED":
                raise StateConflict("P0 review gate found an unexpected evidence state")
            self._record_event(cur, run_id=run_id, entity_type="Run", entity_id=run_id, event_type="P0_REVIEW_DISABLED", from_state="VERIFYING", to_state="VERIFYING", payload={"p0": True, "evidence": "NOT_REACHED_P0"})
            return {"status": "P0_DISABLED", "evidence": "NOT_REACHED_P0", "review_id": None}

        self._phase(run_id, "C8", "review-decision", mutation, status="SUPPRESSED")

    def _p0_acceptance_gate(self, spec: Mapping[str, Any]) -> None:
        run_id, card_id = str(spec["run_id"]), str(spec["card_id"])
        attempt_id = f"attempt-{card_id}-001"
        receipt_id = f"receipt-validation-{attempt_id}"
        review_id = f"review-{attempt_id}"
        txn_id = f"acceptance-{attempt_id}"

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            card = cur.execute("SELECT state FROM cards WHERE card_id=?", (card_id,)).fetchone()
            attempt = cur.execute("SELECT state FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            run = cur.execute("SELECT state,fencing_epoch FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if card is None or attempt is None or run is None:
                raise StateConflict("P0 acceptance gate requires evidence")
            before_hash = canonical_hash({"card": card[0], "attempt": attempt[0], "run": run[0], "event": run_id})
            cur.execute(
                "INSERT OR IGNORE INTO reviews(review_id,attempt_id,card_id,run_id,review_domain_id,input_manifest_hash,state,decision,retryable,expires_at,heartbeat_at,deadline_policy_hash,criteria_hash,evidence_refs_json,reviewer_identity,reviewer_process_identity,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    review_id,
                    attempt_id,
                    card_id,
                    run_id,
                    "p0-review-disabled",
                    receipt_id,
                    "NOT_REQUESTED",
                    None,
                    0,
                    None,
                    None,
                    None,
                    canonical_hash({"criteria": "p0-no-acceptance"}),
                    _json([receipt_id]),
                    "not-run-in-p0",
                    "not-run-in-p0",
                    self.clock.now(),
                ),
            )
            cur.execute(
                "INSERT OR IGNORE INTO acceptance_txns(acceptance_txn_id,idempotency_key,run_id,card_id,attempt_id,receipt_id,review_id,next_card_intent_id,state,duplicate_outcome,acceptance_enabled,before_card_state,before_attempt_state,before_run_state,after_card_state,after_attempt_state,after_run_state,fencing_epoch,before_state_hash,after_state_hash,commit_marker_hash,last_committed_event_id,created_at,committed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    txn_id,
                    f"acceptance-key:{run_id}:{card_id}",
                    run_id,
                    card_id,
                    attempt_id,
                    receipt_id,
                    review_id,
                    None,
                    "ABORTED",
                    None,
                    0,
                    card[0],
                    attempt[0],
                    run[0],
                    "DONE",
                    "ACCEPTED",
                    "ADVANCING",
                    int(run[1]),
                    before_hash,
                    None,
                    None,
                    None,
                    self.clock.now(),
                    None,
                ),
            )
            self._record_event(cur, run_id=run_id, entity_type="AcceptanceTxn", entity_id=txn_id, event_type="P0_ACCEPTANCE_DISABLED", from_state="PREPARED", to_state="ABORTED", payload={"acceptance_enabled": False, "reason": "P0_DISABLED"})
            return {"status": "P0_DISABLED", "acceptance_enabled": False, "acceptance_txn_id": txn_id, "card_state": card[0], "attempt_state": attempt[0], "run_state": run[0]}

        self._phase(run_id, "C9", "acceptance-gate", mutation, status="SUPPRESSED")

    def _p0_next_card_gate(self, spec: Mapping[str, Any]) -> None:
        run_id, card_id = str(spec["run_id"]), str(spec["card_id"])

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            row = cur.execute("SELECT next_card_intent_id,state FROM cards WHERE card_id=?", (card_id,)).fetchone()
            if row is None or row[0] is not None or cur.execute("SELECT COUNT(*) FROM next_card_intents WHERE run_id=?", (run_id,)).fetchone()[0] != 0:
                raise StateConflict("P0 next-card invariant violated")
            self._record_event(cur, run_id=run_id, entity_type="Run", entity_id=run_id, event_type="P0_NEXT_CARD_DISABLED", from_state="VERIFYING", to_state="VERIFYING", payload={"evidence": "NOT_REACHED_P0", "card_state": row[1]})
            return {"status": "P0_DISABLED", "evidence": "NOT_REACHED_P0", "next_card_intent": None}

        self._phase(run_id, "C10", "next-card-intent", mutation, status="SUPPRESSED")

    def _p0_complete_gate(self, spec: Mapping[str, Any]) -> None:
        run_id = str(spec["run_id"])

        def mutation(cur: sqlite3.Cursor) -> Mapping[str, Any]:
            run = cur.execute("SELECT state FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if run is None or run[0] != "VERIFYING":
                raise StateConflict("P0 completion gate found unexpected run state")
            self._record_event(cur, run_id=run_id, entity_type="Run", entity_id=run_id, event_type="P0_RUN_COMPLETE_DISABLED", from_state="VERIFYING", to_state="VERIFYING", payload={"evidence": "NOT_REACHED_P0", "acceptance_enabled": False})
            return {"status": "P0_DISABLED", "evidence": "NOT_REACHED_P0", "run_state": run[0], "completion_marker": False}

        self._phase(run_id, "C11", "run-complete", mutation, status="SUPPRESSED")

    def run_p0(self, spec: Mapping[str, Any]) -> dict[str, Any]:
        """Run or replay the deterministic P0 single-card path."""

        normalized = self._spec_with_defaults(spec)
        existing = self.conn.execute("SELECT input_spec_json FROM runs WHERE run_id=?", (normalized["run_id"],)).fetchone()
        if existing is not None:
            persisted = _parse(existing[0], {})
            if canonical_json(persisted) != canonical_json(normalized):
                raise StateConflict(f"run idempotency/provenance conflict: {normalized['run_id']}")
        self._ensure_run_and_card(normalized)
        self._dispatch_intent(normalized)
        self._claim_lease(normalized)
        self._spawn_request(normalized)
        self._executor_ack(normalized)
        self._checkpoint(normalized)
        self._submission(normalized)
        self._receipt_verify(normalized)
        self._p0_review_gate(normalized)
        self._p0_acceptance_gate(normalized)
        self._p0_next_card_gate(normalized)
        self._p0_complete_gate(normalized)
        return self.snapshot(str(normalized["run_id"]))

    def recover(self, run_id: str, spec: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Replay the same idempotency keys after a simulated mother crash."""

        if spec is None:
            row = self.conn.execute("SELECT input_spec_json FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise StateConflict("run is absent; recovery needs the original admission spec")
            spec = _parse(row[0])
        else:
            normalized = self._spec_with_defaults(spec)
            if str(normalized["run_id"]) != run_id:
                raise StateConflict("recovery run_id/spec mismatch")
            spec = normalized
        return self.run_p0(spec)

    def snapshot(self, run_id: str) -> dict[str, Any]:
        run = _row(self.conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone())
        if run is None:
            raise StateConflict(f"run missing: {run_id}")
        cards = [_row(row) for row in self.conn.execute("SELECT * FROM cards WHERE run_id=? ORDER BY card_id", (run_id,)).fetchall()]
        attempts = [_row(row) for row in self.conn.execute("SELECT * FROM attempts WHERE run_id=? ORDER BY attempt_no", (run_id,)).fetchall()]
        dispatches = [_row(row) for row in self.conn.execute("SELECT * FROM dispatches WHERE run_id=? ORDER BY dispatch_id", (run_id,)).fetchall()]
        receipts = [_row(row) for row in self.conn.execute("SELECT * FROM receipts WHERE run_id=? ORDER BY receipt_id", (run_id,)).fetchall()]
        reviews = [_row(row) for row in self.conn.execute("SELECT * FROM reviews WHERE run_id=? ORDER BY review_id", (run_id,)).fetchall()]
        acceptance = [_row(row) for row in self.conn.execute("SELECT * FROM acceptance_txns WHERE run_id=? ORDER BY acceptance_txn_id", (run_id,)).fetchall()]
        markers = [_row(row) for row in self.conn.execute("SELECT * FROM commit_markers WHERE run_id=? ORDER BY commit_point", (run_id,)).fetchall()]
        events = [_row(row) for row in self.conn.execute("SELECT * FROM events WHERE run_id=? ORDER BY event_no", (run_id,)).fetchall()]
        for item in cards + attempts + dispatches + receipts + reviews + acceptance + markers + events:
            if item is not None:
                for key in tuple(item):
                    if key.endswith("_json"):
                        item[key[:-5]] = _parse(item[key], None)
        return {
            "run": run,
            "cards": cards,
            "attempts": attempts,
            "dispatches": dispatches,
            "receipts": receipts,
            "reviews": reviews,
            "acceptance_txns": acceptance,
            "commit_markers": markers,
            "events": events,
            "next_card_intents": [_row(row) for row in self.conn.execute("SELECT * FROM next_card_intents WHERE run_id=?", (run_id,)).fetchall()],
            "counts": {
                "runs": self.conn.execute("SELECT COUNT(*) FROM runs WHERE run_id=?", (run_id,)).fetchone()[0],
                "cards": len(cards),
                "attempts": len(attempts),
                "dispatches": len(dispatches),
                "receipts": len(receipts),
                "events": len(events),
            },
        }

    def integrity_check(self) -> str:
        return str(self.conn.execute("PRAGMA integrity_check").fetchone()[0])

    def lease_snapshot(self, run_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT lease_token,lease_owner_id,lease_expires_at,fencing_epoch FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise StateConflict(f"run missing: {run_id}")
        return dict(row)

    def assert_fencing(self, run_id: str, *, owner_id: str, lease_token: str, fencing_epoch: int) -> None:
        row = self.conn.execute("SELECT lease_owner_id,lease_token,lease_expires_at,fencing_epoch FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise FencingError("run missing")
        if row["lease_owner_id"] != owner_id or row["lease_token"] != lease_token or int(row["fencing_epoch"]) != int(fencing_epoch) or int(row["lease_expires_at"] or 0) <= self.clock.epoch():
            raise FencingError("stale or mismatched fencing authority")

    def _assert_fencing_cursor(
        self,
        cur: sqlite3.Cursor,
        run_id: str,
        *,
        owner_id: str,
        lease_token: str,
        fencing_epoch: int,
    ) -> None:
        """Check fencing on the same SQLite snapshot that will be mutated."""

        row = cur.execute(
            "SELECT lease_owner_id,lease_token,lease_expires_at,fencing_epoch FROM runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise FencingError("run missing")
        if (
            row["lease_owner_id"] != owner_id
            or row["lease_token"] != lease_token
            or int(row["fencing_epoch"]) != int(fencing_epoch)
            or int(row["lease_expires_at"] or 0) <= self.clock.epoch()
        ):
            raise FencingError("stale or mismatched fencing authority")

    def expire_lease(self, run_id: str, *, reason: str = "test-expiry") -> None:
        """Test-only clock-independent way to create an expired lease."""

        with self._transaction() as cur:
            run = cur.execute("SELECT state FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if run is None:
                raise StateConflict(f"run missing: {run_id}")
            self._assert_runtime_anchor_cursor(cur, run_id)
            cur.execute("UPDATE runs SET lease_expires_at=?,updated_at=? WHERE run_id=?", (self.clock.epoch() - 1, self.clock.now(), run_id))
            self._record_event(cur, run_id=run_id, entity_type="Run", entity_id=run_id, event_type="LEASE_EXPIRED", from_state=run[0], to_state=run[0], payload={"reason": reason})
            self._set_runtime_anchor(cur, run_id)

    def reclaim_lease(
        self,
        run_id: str,
        *,
        new_owner_id: str = "reclaimer",
        reason: str = "stale",
        force: bool = False,
    ) -> dict[str, Any]:
        with self._transaction() as cur:
            run = cur.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if run is None:
                raise StateConflict(f"run missing: {run_id}")
            self._assert_runtime_anchor_cursor(cur, run_id)
            if not force and int(run["lease_expires_at"] or 0) > self.clock.epoch():
                raise FencingError("cannot reclaim a live lease without force")
            new_epoch = int(run["fencing_epoch"]) + 1
            token = f"lease:{run_id}:epoch:{new_epoch}"
            cur.execute("UPDATE runs SET fencing_epoch=?,lease_token=?,lease_owner_id=?,lease_expires_at=?,last_heartbeat_at=?,updated_at=? WHERE run_id=?", (new_epoch, token, new_owner_id, self.clock.epoch() + 60, self.clock.now(), self.clock.now(), run_id))
            cur.execute(
                "UPDATE dispatches SET fencing_epoch=?,owner_id=?,lease_expires_at=?,heartbeat_at=?,updated_at=? WHERE run_id=? AND state NOT IN ('CANCELLED','EXPIRED','FAILED','BLOCKED','COMPLETED')",
                (new_epoch, new_owner_id, self.clock.epoch() + 60, self.clock.now(), self.clock.now(), run_id),
            )
            self._record_event(cur, run_id=run_id, entity_type="Run", entity_id=run_id, event_type="LEASE_RECLAIMED", from_state=run["state"], to_state=run["state"], payload={"reason": reason, "fencing_epoch": new_epoch, "owner_id": new_owner_id})
            self._set_runtime_anchor(cur, run_id)
        return self.lease_snapshot(run_id)

    def reconcile_dispatch(
        self,
        run_id: str,
        dispatch_id: str,
        identity: FakeProcessIdentity | Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Reconcile a missing/late Ack without ever doing a second spawn.

        ``identity=None`` models an Ack timeout.  A supplied identity is
        adopted only when every dispatch-bound field matches.  A mismatch is
        recorded as uncertain/recovery-required; the controller never kills,
        attaches to, or retries a foreign process.
        """

        dispatch = self.conn.execute("SELECT * FROM dispatches WHERE dispatch_id=? AND run_id=?", (dispatch_id, run_id)).fetchone()
        if dispatch is None:
            raise StateConflict(f"dispatch missing: {dispatch_id}")
        if dispatch["state"] not in {"SPAWN_REQUESTED", "DISPATCH_UNCONFIRMED", "RECONCILING"}:
            raise StateConflict(f"dispatch is not reconcilable from {dispatch['state']}")
        if isinstance(identity, Mapping):
            identity = FakeProcessIdentity(
                pid=int(identity["pid"]),
                starttime=str(identity["starttime"]),
                boot_id=str(identity["boot_id"]),
                pidfd_ref=str(identity["pidfd_ref"]),
                cgroup_ref=str(identity["cgroup_ref"]),
                run_token=str(identity["run_token"]),
                fencing_epoch=int(identity["fencing_epoch"]),
                command_hash=str(identity["command_hash"]),
            )
        with self._transaction() as cur:
            self._assert_runtime_anchor_cursor(cur, run_id)
            dispatch = cur.execute(
                "SELECT * FROM dispatches WHERE dispatch_id=? AND run_id=?",
                (dispatch_id, run_id),
            ).fetchone()
            run = cur.execute(
                "SELECT lease_owner_id,lease_token,lease_expires_at,fencing_epoch FROM runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if dispatch is None or run is None:
                raise StateConflict(f"dispatch/run missing during reconciliation: {dispatch_id}")
            self._assert_fencing_cursor(
                cur,
                run_id,
                owner_id=str(run["lease_owner_id"]),
                lease_token=str(run["lease_token"]),
                fencing_epoch=int(run["fencing_epoch"]),
            )
            expected_identity = self.executor.identity_for(dispatch_id)
            persisted_identity = None
            if dispatch["pid"] is not None:
                persisted_identity = {
                    "pid": int(dispatch["pid"]),
                    "starttime": str(dispatch["process_starttime"]),
                    "boot_id": str(dispatch["boot_id"]),
                    "pidfd_ref": str(dispatch["pidfd_ref"]),
                    "cgroup_ref": str(dispatch["cgroup_ref"]),
                    "run_token": str(dispatch["run_token"]),
                    "fencing_epoch": int(dispatch["fencing_epoch"]),
                    "command_hash": str(dispatch["command_hash"]),
                }
            matches = identity is not None and identity.fencing_epoch == int(run["fencing_epoch"]) and identity.fencing_epoch == int(dispatch["fencing_epoch"]) and (
                (expected_identity is not None and identity.as_dict() == expected_identity.as_dict())
                or (persisted_identity is not None and identity.as_dict() == persisted_identity)
            )
            if matches:
                if dispatch["state"] == "SPAWN_REQUESTED":
                    self._transition_dispatch(cur, run_id, dispatch_id, "EXECUTOR_ACKED", "RECONCILE_EXECUTOR_ACKED", identity.as_dict())
                elif dispatch["state"] == "DISPATCH_UNCONFIRMED":
                    self._transition_dispatch(cur, run_id, dispatch_id, "RECONCILING", "RECONCILE_REOPENED")
                    self._transition_dispatch(cur, run_id, dispatch_id, "EXECUTOR_ACKED", "RECONCILE_EXECUTOR_ACKED", identity.as_dict())
                elif dispatch["state"] == "RECONCILING":
                    self._transition_dispatch(cur, run_id, dispatch_id, "EXECUTOR_ACKED", "RECONCILE_EXECUTOR_ACKED", identity.as_dict())
                cur.execute(
                    "UPDATE dispatches SET pid=?,process_starttime=?,boot_id=?,pidfd_ref=?,cgroup_ref=?,heartbeat_at=?,updated_at=? WHERE dispatch_id=?",
                    (identity.pid, identity.starttime, identity.boot_id, identity.pidfd_ref, identity.cgroup_ref, self.clock.now(), self.clock.now(), dispatch_id),
                )
                attempt_id = dispatch["attempt_id"]
                attempt = cur.execute("SELECT state FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
                if attempt and attempt[0] == "ADMITTED":
                    self._transition_attempt(cur, run_id, attempt_id, "STARTING", "RECONCILE_ATTEMPT_STARTING")
                self._set_runtime_anchor(cur, run_id)
                return {"status": "ADOPTED", "dispatch_id": dispatch_id, "spawn_count": self.executor.spawn_count(dispatch_id)}

            if dispatch["state"] == "SPAWN_REQUESTED":
                self._transition_dispatch(cur, run_id, dispatch_id, "DISPATCH_UNCONFIRMED", "DISPATCH_UNCONFIRMED")
            if self.conn.execute("SELECT state FROM dispatches WHERE dispatch_id=?", (dispatch_id,)).fetchone()[0] == "DISPATCH_UNCONFIRMED":
                self._transition_dispatch(cur, run_id, dispatch_id, "RECONCILING", "DISPATCH_RECONCILING")
            attempt_id = dispatch["attempt_id"]
            attempt = cur.execute("SELECT state FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if attempt and attempt[0] == "ADMITTED":
                self._transition_attempt(cur, run_id, attempt_id, "STARTING", "RECONCILE_ATTEMPT_STARTING")
            attempt = cur.execute("SELECT state FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if attempt and attempt[0] == "STARTING":
                self._transition_attempt(cur, run_id, attempt_id, "UNCERTAIN", "RECONCILE_ATTEMPT_UNCERTAIN")
            run = cur.execute("SELECT state FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if run and run[0] == "DISPATCHING":
                self._transition_run(cur, run_id, "RECOVERY_REQUIRED", "RUN_RECOVERY_REQUIRED", {"reason": "ack_identity_unresolved"})
            self._set_runtime_anchor(cur, run_id)
        return {"status": "RECOVERY_REQUIRED", "dispatch_id": dispatch_id, "spawn_count": self.executor.spawn_count(dispatch_id)}

    def attempt_acceptance(self, run_id: str) -> None:
        row = self.conn.execute("SELECT input_spec_json FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise StateConflict(f"run missing: {run_id}")
        spec = _parse(row[0])
        self._p0_acceptance_gate(spec)
        raise P0Disabled("AcceptanceTxn is disabled in P0")

    def transition_for_test(self, entity_type: str, entity_id: str, to_state: str, run_id: str) -> None:
        """Expose the same fail-closed FSM for negative tests."""
        with self._transaction() as cur:
            self._assert_runtime_anchor_cursor(cur, run_id)
            if entity_type == "Dispatch":
                self._transition_dispatch(cur, run_id, entity_id, to_state, "TEST_TRANSITION")
            elif entity_type == "Attempt":
                self._transition_attempt(cur, run_id, entity_id, to_state, "TEST_TRANSITION")
            elif entity_type == "Card":
                self._transition_card(cur, run_id, entity_id, to_state, "TEST_TRANSITION")
            elif entity_type == "Run":
                self._transition_run(cur, entity_id, to_state, "TEST_TRANSITION")
            else:
                raise ValueError(f"unsupported test entity: {entity_type}")
            self._set_runtime_anchor(cur, run_id)

