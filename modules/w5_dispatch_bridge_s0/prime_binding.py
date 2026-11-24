"""W5-S4 Prime↔HRR binding and read-only control-plane capture.

This module is intentionally an adapter boundary, not a resume executor.  It
binds a freshly evaluated W5-S3 decision to a Prime run/task snapshot and to a
stable, read-only control-plane observation.  A stored binding is never an
authority: callers that need a current answer must provide fresh Prime and
HRR inputs so the complete result is recomputed.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
import json
import re
import sqlite3
from typing import Any, Callable, Mapping

from modules.w4_small_loop_s0 import canonical_hash

from .prime_evidence import (
    EVIDENCE_CODES,
    PrimeEvidenceError,
    build_prime_state_from_evidence_v2,
    build_prime_state_from_capture,
    capture_prime_evidence,
    capture_prime_evidence_v2,
)
from .s3_gate import HrrGateError, evaluate_hrr, verify_hrr_decision


PRIME_BINDING_SCHEMA = "w5-hrr-prime-binding-v1"
PRIME_STATE_SCHEMA = "prime-resume-state-v1"
CONTROL_CAPTURE_SCHEMA = "w5-control-plane-capture-v1"
PRIME_GATE_VALUES = frozenset({"hold", "continue"})
PRIME_STATUS_VALUES = frozenset({"in_progress", "paused", "blocked", "stopped"})
NEXT_ACTION_VALUES = frozenset({"continue", "hold", "stop"})
BINDING_STATUSES = frozenset({"BOUND_READ_ONLY", "HOLD"})
BINDING_DECISIONS = frozenset({"HOLD", "RECONCILE", "RESUME"})

PRIME_STATE_KEYS = frozenset(
    {
        "schema_version",
        "binding_id",
        "prime_run_id",
        "active_task_id",
        "active_task_sha256",
        "status",
        "resume_gate",
        "resume_gate_reason",
        "stop_reason",
        "hold_reason",
        "next_action",
        "resume_packet_sha256",
        "session_sha256",
        "tasks_sha256",
        "queue_sha256",
        "policy_sha256",
        "writer_lease_sha256",
        "w5_identity",
    }
)
W5_IDENTITY_KEYS = frozenset({"run_id", "card_id", "attempt_id", "dispatch_id"})
PRIME_OUTPUT_KEYS = PRIME_STATE_KEYS | {"state_sha256"}
W5_OUTPUT_KEYS = frozenset(
    {
        "identity",
        "state",
        "fencing_epoch",
        "source_attestation_hash",
        "control_snapshot_sha256",
        "live_runtime_sha256",
    }
)
CONTROL_CAPTURE_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "runtime",
        "runtime_sha256",
        "projection_sha256",
        "runtime_anchor",
        "runtime_anchor_history",
        "marker_commitments",
        "clock_before_epoch",
        "clock_after_epoch",
        "integrity_check",
        "read_only",
    }
)
CONTROL_CAPTURE_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "runtime_sha256",
        "projection_sha256",
        "runtime_anchor_sha256",
        "marker_commitments_sha256",
        "clock_before_epoch",
        "clock_after_epoch",
        "integrity_check",
        "read_only",
        "capture_sha256",
    }
)
HRR_OUTPUT_KEYS = frozenset(
    {"input_sha256", "decision_sha256", "decision", "reason"}
)
EXECUTION_KEYS = frozenset({"resume", "reconcile", "mutation", "network"})
BINDING_KEYS = frozenset(
    {
        "schema_version",
        "binding_id",
        "binding_status",
        "reason",
        "decision",
        "resume_allowed",
        "prime",
        "w5",
        "hrr",
        "control_capture",
        "permission",
        "external_action",
        "execution",
    }
)
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_TEXT = 512

BINDING_REASONS = frozenset(
    {
        "BOUND_RESUME",
        "HRR_HOLD",
        "RECONCILE_ACTION_REQUIRED",
        "HRR_NOT_RESUMABLE",
        "INVALID_PRIME_STATE",
        "INVALID_HRR_INPUT",
        "PRIME_IDENTITY_DRIFT",
        "PRIME_GATE_CLOSED",
        "PRIME_GATE_DRIFT",
        "CONTROL_SNAPSHOT_UNSTABLE",
        "CONTROL_SNAPSHOT_INVALID",
        "CONTROL_CAPTURE_DRIFT",
        "DECISION_RECOMPUTE_FAILED",
    }
) | EVIDENCE_CODES
NEXT_ACTION_KEYS = frozenset({"action", "task_id"})

FALSE_EXECUTION = {key: False for key in sorted(EXECUTION_KEYS)}


class PrimeBindingError(ValueError):
    """Prime state, control snapshots or binding evidence are invalid."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PrimeBindingError(f"{label}: object required")
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    keys = set(value)
    if any(not isinstance(key, str) for key in keys):
        raise PrimeBindingError(f"{label}: field names must be strings")
    missing = expected - keys
    extra = keys - expected
    if missing or extra:
        raise PrimeBindingError(
            f"{label}: schema drift; missing={sorted(missing)} extra={sorted(extra)}"
        )


def _text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_TEXT
        or any(ord(char) < 32 for char in value)
    ):
        raise PrimeBindingError(f"{label}: non-empty text required")
    return value


def _sha256(value: Any, label: str) -> str:
    value = _text(value, label)
    if SHA256_HEX.fullmatch(value) is None:
        raise PrimeBindingError(f"{label}: lowercase SHA256 required")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PrimeBindingError(f"{label}: integer >= {minimum} required")
    return value


def _optional_text(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label)


def _empty_allowed_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_TEXT
        or any(ord(char) < 32 for char in value)
    ):
        raise PrimeBindingError(f"{label}: bounded text required")
    return value


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_hash(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _timestamp_epoch(value: Any, label: str) -> int:
    value = _text(value, label)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PrimeBindingError(f"{label}: ISO timestamp required") from exc
    if parsed.tzinfo is None:
        raise PrimeBindingError(f"{label}: timezone required")
    return int(parsed.astimezone(timezone.utc).timestamp())


def _row_dict(row: Any, label: str) -> dict[str, Any]:
    if row is None:
        raise PrimeBindingError(f"{label}: row missing")
    return dict(row)


def _parse_snapshot_rows(rows: list[dict[str, Any]], *, parse_json: bool) -> list[dict[str, Any]]:
    if not parse_json:
        return rows
    for item in rows:
        for key in tuple(item):
            if key.endswith("_json"):
                item[key[:-5]] = json.loads(item[key])
    return rows


def _rows(cur: sqlite3.Cursor, query: str, params: tuple[Any, ...], label: str) -> list[dict[str, Any]]:
    try:
        return [dict(row) for row in cur.execute(query, params).fetchall()]
    except sqlite3.Error as exc:
        raise PrimeBindingError(f"{label}: read failed") from exc


def _runtime_and_projection(cur: sqlite3.Cursor, run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        run_row = cur.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    except sqlite3.Error as exc:
        raise PrimeBindingError("control database: run read failed") from exc
    run = _row_dict(run_row, "control database.run")
    project_id = run.get("project_id")
    runtime = {
        "run": run,
        "cards": _parse_snapshot_rows(
            _rows(cur, "SELECT * FROM cards WHERE run_id=? ORDER BY card_id", (run_id,), "cards"),
            parse_json=True,
        ),
        "attempts": _parse_snapshot_rows(
            _rows(cur, "SELECT * FROM attempts WHERE run_id=? ORDER BY attempt_no", (run_id,), "attempts"),
            parse_json=True,
        ),
        "dispatches": _parse_snapshot_rows(
            _rows(cur, "SELECT * FROM dispatches WHERE run_id=? ORDER BY dispatch_id", (run_id,), "dispatches"),
            parse_json=True,
        ),
        "receipts": _parse_snapshot_rows(
            _rows(cur, "SELECT * FROM receipts WHERE run_id=? ORDER BY receipt_id", (run_id,), "receipts"),
            parse_json=True,
        ),
        "reviews": _parse_snapshot_rows(
            _rows(cur, "SELECT * FROM reviews WHERE run_id=? ORDER BY review_id", (run_id,), "reviews"),
            parse_json=True,
        ),
        "acceptance_txns": _parse_snapshot_rows(
            _rows(cur, "SELECT * FROM acceptance_txns WHERE run_id=? ORDER BY acceptance_txn_id", (run_id,), "acceptance_txns"),
            parse_json=True,
        ),
        "commit_markers": _parse_snapshot_rows(
            _rows(cur, "SELECT * FROM commit_markers WHERE run_id=? ORDER BY commit_point", (run_id,), "commit_markers"),
            parse_json=True,
        ),
        "events": _parse_snapshot_rows(
            _rows(cur, "SELECT * FROM events WHERE run_id=? ORDER BY event_no", (run_id,), "events"),
            parse_json=True,
        ),
        "next_card_intents": _rows(
            cur,
            "SELECT * FROM next_card_intents WHERE run_id=?",
            (run_id,),
            "next_card_intents",
        ),
    }
    runtime["counts"] = {
        "runs": int(cur.execute("SELECT COUNT(*) FROM runs WHERE run_id=?", (run_id,)).fetchone()[0]),
        "cards": len(runtime["cards"]),
        "attempts": len(runtime["attempts"]),
        "dispatches": len(runtime["dispatches"]),
        "receipts": len(runtime["receipts"]),
        "events": len(runtime["events"]),
    }

    projection: dict[str, Any] = {}
    projection_queries = {
        "projects": (
            "SELECT * FROM projects WHERE project_id=(SELECT project_id FROM runs WHERE run_id=?) ORDER BY project_id",
            (run_id,),
        ),
        "runs": ("SELECT * FROM runs WHERE run_id=? ORDER BY run_id", (run_id,)),
        "cards": ("SELECT * FROM cards WHERE run_id=? ORDER BY card_id", (run_id,)),
        "attempts": ("SELECT * FROM attempts WHERE run_id=? ORDER BY attempt_id", (run_id,)),
        "dispatches": ("SELECT * FROM dispatches WHERE run_id=? ORDER BY dispatch_id", (run_id,)),
        "receipts": ("SELECT * FROM receipts WHERE run_id=? ORDER BY receipt_id", (run_id,)),
        "reviews": ("SELECT * FROM reviews WHERE run_id=? ORDER BY review_id", (run_id,)),
        "acceptance_txns": ("SELECT * FROM acceptance_txns WHERE run_id=? ORDER BY acceptance_txn_id", (run_id,)),
        "next_card_intents": ("SELECT * FROM next_card_intents WHERE run_id=? ORDER BY next_card_intent_id", (run_id,)),
    }
    for table, (query, params) in projection_queries.items():
        projection[table] = _rows(cur, query, params, f"projection.{table}")
    if project_id is None:
        raise PrimeBindingError("control database.run.project_id missing")
    return runtime, projection


def _control_epoch(control_plane: Any, label: str) -> int:
    clock = getattr(control_plane, "clock", None)
    epoch = getattr(clock, "epoch", None)
    if not callable(epoch):
        raise PrimeBindingError("control_plane requires a trusted clock.epoch()")
    return _integer(epoch(), label, minimum=0)


def _normalize_control_capture(value: Any) -> dict[str, Any]:
    value = _mapping(value, "control_capture")
    _exact_keys(value, CONTROL_CAPTURE_KEYS, "control_capture")
    if value["schema_version"] != CONTROL_CAPTURE_SCHEMA:
        raise PrimeBindingError("control_capture.schema_version unsupported")
    run_id = _text(value["run_id"], "control_capture.run_id")
    runtime = _mapping(value["runtime"], "control_capture.runtime")
    runtime_hash = _sha256(value["runtime_sha256"], "control_capture.runtime_sha256")
    if canonical_hash(runtime) != runtime_hash:
        raise PrimeBindingError("control_capture.runtime_sha256 mismatch")
    if _mapping(runtime.get("run"), "control_capture.runtime.run").get("run_id") != run_id:
        raise PrimeBindingError("control_capture.run_id does not match runtime")
    projection_hash = _sha256(value["projection_sha256"], "control_capture.projection_sha256")

    anchor = _mapping(value["runtime_anchor"], "control_capture.runtime_anchor")
    _exact_keys(
        anchor,
        frozenset({"run_id", "projection_hash", "last_committed_event_id", "updated_at"}),
        "control_capture.runtime_anchor",
    )
    if anchor["run_id"] != run_id or anchor["projection_hash"] != projection_hash:
        raise PrimeBindingError("control_capture.runtime_anchor mismatch")
    _text(anchor["projection_hash"], "control_capture.runtime_anchor.projection_hash")
    _optional_text(anchor["last_committed_event_id"], "control_capture.runtime_anchor.last_committed_event_id")
    _text(anchor["updated_at"], "control_capture.runtime_anchor.updated_at")

    history_value = value["runtime_anchor_history"]
    if not isinstance(history_value, list) or not history_value:
        raise PrimeBindingError("control_capture.runtime_anchor_history must be non-empty")
    history: list[dict[str, Any]] = []
    for index, item in enumerate(history_value):
        item = _mapping(item, f"control_capture.runtime_anchor_history[{index}]")
        _exact_keys(
            item,
            frozenset({"run_id", "anchor_no", "projection_hash", "last_committed_event_id", "created_at"}),
            f"control_capture.runtime_anchor_history[{index}]",
        )
        if item["run_id"] != run_id:
            raise PrimeBindingError("control_capture.runtime_anchor_history run mismatch")
        _sha256(
            item["projection_hash"],
            f"control_capture.runtime_anchor_history[{index}].projection_hash",
        )
        history.append(
            {
                "run_id": run_id,
                "anchor_no": _integer(item["anchor_no"], f"control_capture.runtime_anchor_history[{index}].anchor_no", minimum=1),
                "projection_hash": item["projection_hash"],
                "last_committed_event_id": _optional_text(item["last_committed_event_id"], f"control_capture.runtime_anchor_history[{index}].last_committed_event_id"),
                "created_at": _text(item["created_at"], f"control_capture.runtime_anchor_history[{index}].created_at"),
            }
        )
    history.sort(key=lambda item: item["anchor_no"])
    if history[-1]["last_committed_event_id"] != anchor["last_committed_event_id"]:
        raise PrimeBindingError("control_capture anchor history tail mismatch")

    marker_value = value["marker_commitments"]
    if not isinstance(marker_value, list):
        raise PrimeBindingError("control_capture.marker_commitments must be a list")
    markers: list[dict[str, Any]] = []
    for index, item in enumerate(marker_value):
        item = _mapping(item, f"control_capture.marker_commitments[{index}]")
        _exact_keys(
            item,
            frozenset({"run_id", "operation_key", "marker_hash", "created_at"}),
            f"control_capture.marker_commitments[{index}]",
        )
        markers.append(
            {
                "run_id": _text(item["run_id"], f"control_capture.marker_commitments[{index}].run_id"),
                "operation_key": _text(item["operation_key"], f"control_capture.marker_commitments[{index}].operation_key"),
                "marker_hash": _sha256(item["marker_hash"], f"control_capture.marker_commitments[{index}].marker_hash"),
                "created_at": _text(item["created_at"], f"control_capture.marker_commitments[{index}].created_at"),
            }
        )
    if any(item["run_id"] != run_id for item in markers):
        raise PrimeBindingError("control_capture.marker_commitments run mismatch")

    before = _integer(value["clock_before_epoch"], "control_capture.clock_before_epoch", minimum=0)
    after = _integer(value["clock_after_epoch"], "control_capture.clock_after_epoch", minimum=0)
    if after < before or after - before > 5:
        raise PrimeBindingError("control_capture clock sample is not fresh")
    if value["integrity_check"] != "ok" or value["read_only"] is not True:
        raise PrimeBindingError("control_capture is not a verified read-only capture")
    normalized = {
        "schema_version": CONTROL_CAPTURE_SCHEMA,
        "run_id": run_id,
        "runtime": copy.deepcopy(dict(runtime)),
        "runtime_sha256": runtime_hash,
        "projection_sha256": projection_hash,
        "runtime_anchor": dict(anchor),
        "runtime_anchor_history": history,
        "marker_commitments": sorted(markers, key=lambda item: item["operation_key"]),
        "clock_before_epoch": before,
        "clock_after_epoch": after,
        "integrity_check": "ok",
        "read_only": True,
    }
    return normalized


def _capture_summary(capture: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalize_control_capture(capture)
    return {
        "schema_version": CONTROL_CAPTURE_SCHEMA,
        "run_id": normalized["run_id"],
        "runtime_sha256": normalized["runtime_sha256"],
        "projection_sha256": normalized["projection_sha256"],
        "runtime_anchor_sha256": canonical_hash(normalized["runtime_anchor"]),
        "marker_commitments_sha256": canonical_hash(normalized["marker_commitments"]),
        "clock_before_epoch": normalized["clock_before_epoch"],
        "clock_after_epoch": normalized["clock_after_epoch"],
        "integrity_check": normalized["integrity_check"],
        "read_only": True,
        "capture_sha256": canonical_hash(normalized),
    }


def _capture_from_sqlite(control_plane: Any, run_id: str) -> dict[str, Any]:
    db_value = getattr(control_plane, "db_path", None)
    if not isinstance(db_value, (str, Path)) or str(db_value) in {"", ":memory:"}:
        raise PrimeBindingError("control_plane requires a file-backed SQLite db_path")
    db_path = Path(db_value)
    if db_path.is_symlink() or not db_path.is_file():
        raise PrimeBindingError("control-plane db_path must be a regular non-symlink file")
    resolved = db_path.resolve(strict=True)
    clock_before = _control_epoch(control_plane, "control_capture.clock_before_epoch")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute("PRAGMA query_only=ON")
        cursor.execute("BEGIN")
        integrity = str(cursor.execute("PRAGMA integrity_check").fetchone()[0])
        runtime, projection = _runtime_and_projection(cursor, run_id)
        anchor = _row_dict(
            cursor.execute(
                "SELECT run_id,projection_hash,last_committed_event_id,updated_at FROM runtime_anchors WHERE run_id=?",
                (run_id,),
            ).fetchone(),
            "control_capture.runtime_anchor",
        )
        history = _rows(
            cursor,
            "SELECT run_id,anchor_no,projection_hash,last_committed_event_id,created_at FROM runtime_anchor_history WHERE run_id=? ORDER BY anchor_no",
            (run_id,),
            "runtime_anchor_history",
        )
        markers = _rows(
            cursor,
            "SELECT run_id,operation_key,marker_hash,created_at FROM marker_commitments WHERE run_id=? ORDER BY operation_key",
            (run_id,),
            "marker_commitments",
        )
        projection_hash = canonical_hash(projection)
        if anchor["projection_hash"] != projection_hash:
            raise PrimeBindingError("control-plane runtime anchor does not match projection")
        if not history or history[-1]["projection_hash"] != projection_hash:
            raise PrimeBindingError("control-plane runtime anchor history does not match projection")
        marker_by_key = {item["operation_key"]: item["marker_hash"] for item in markers}
        for marker in runtime["commit_markers"]:
            if marker_by_key.get(marker["operation_key"]) != marker["marker_hash"]:
                raise PrimeBindingError("control-plane marker commitment drift")
        clock_after = _control_epoch(control_plane, "control_capture.clock_after_epoch")
        raw = {
            "schema_version": CONTROL_CAPTURE_SCHEMA,
            "run_id": run_id,
            "runtime": runtime,
            "runtime_sha256": canonical_hash(runtime),
            "projection_sha256": projection_hash,
            "runtime_anchor": anchor,
            "runtime_anchor_history": history,
            "marker_commitments": markers,
            "clock_before_epoch": clock_before,
            "clock_after_epoch": clock_after,
            "integrity_check": integrity,
            "read_only": True,
        }
    except sqlite3.Error as exc:
        raise PrimeBindingError("read-only control-plane capture failed") from exc
    finally:
        if connection is not None:
            try:
                connection.rollback()
            finally:
                connection.close()
    return _normalize_control_capture(raw)


def capture_consistent_control_snapshot(control_plane: Any, run_id: str) -> dict[str, Any]:
    """Capture the control plane through one read-only SQLite transaction.

    A test or deployment adapter may provide ``capture_read_only_snapshot``;
    its returned object is still validated against the same schema.  The
    normal ControlPlane path uses its file-backed database in ``mode=ro`` and
    never calls a controller mutation method.
    """

    provider = getattr(control_plane, "capture_read_only_snapshot", None)
    if callable(provider):
        return _normalize_control_capture(provider(run_id))
    return _capture_from_sqlite(control_plane, run_id)


def _normalize_w5_identity(value: Any, label: str) -> dict[str, str]:
    value = _mapping(value, label)
    _exact_keys(value, W5_IDENTITY_KEYS, label)
    return {key: _text(value[key], f"{label}.{key}") for key in sorted(W5_IDENTITY_KEYS)}


def _derived_binding_id(prime_run_id: str, active_task_id: str, identity: Mapping[str, str]) -> str:
    return canonical_hash(
        {
            "prime_run_id": prime_run_id,
            "active_task_id": active_task_id,
            "w5_identity": dict(identity),
        }
    )


def _normalize_prime_state(value: Any) -> dict[str, Any]:
    value = _mapping(value, "prime_state")
    _exact_keys(value, PRIME_STATE_KEYS, "prime_state")
    if value["schema_version"] != PRIME_STATE_SCHEMA:
        raise PrimeBindingError("prime_state.schema_version unsupported")
    prime_run_id = _text(value["prime_run_id"], "prime_state.prime_run_id")
    active_task_id = _text(value["active_task_id"], "prime_state.active_task_id")
    w5_identity = _normalize_w5_identity(value["w5_identity"], "prime_state.w5_identity")
    binding_id = _sha256(value["binding_id"], "prime_state.binding_id")
    if binding_id != _derived_binding_id(prime_run_id, active_task_id, w5_identity):
        raise PrimeBindingError("prime_state.binding_id does not match Prime↔W5 identity")
    gate = _text(value["resume_gate"], "prime_state.resume_gate")
    if gate not in PRIME_GATE_VALUES:
        raise PrimeBindingError("prime_state.resume_gate unsupported")
    status = _text(value["status"], "prime_state.status")
    if status not in PRIME_STATUS_VALUES:
        raise PrimeBindingError("prime_state.status unsupported")
    next_action = _mapping(value["next_action"], "prime_state.next_action")
    _exact_keys(next_action, NEXT_ACTION_KEYS, "prime_state.next_action")
    action = _text(next_action["action"], "prime_state.next_action.action")
    task_id = _text(next_action["task_id"], "prime_state.next_action.task_id")
    if action not in NEXT_ACTION_VALUES:
        raise PrimeBindingError("prime_state.next_action.action unsupported")
    if task_id != active_task_id:
        raise PrimeBindingError("prime_state.next_action.task_id mismatch")
    return {
        "schema_version": PRIME_STATE_SCHEMA,
        "binding_id": binding_id,
        "prime_run_id": prime_run_id,
        "active_task_id": active_task_id,
        "active_task_sha256": _sha256(value["active_task_sha256"], "prime_state.active_task_sha256"),
        "status": status,
        "resume_gate": gate,
        "resume_gate_reason": _empty_allowed_text(value["resume_gate_reason"], "prime_state.resume_gate_reason"),
        "stop_reason": _empty_allowed_text(value["stop_reason"], "prime_state.stop_reason"),
        "hold_reason": _empty_allowed_text(value["hold_reason"], "prime_state.hold_reason"),
        "next_action": {"action": action, "task_id": task_id},
        "resume_packet_sha256": _sha256(
            value["resume_packet_sha256"], "prime_state.resume_packet_sha256"
        ),
        "session_sha256": _sha256(value["session_sha256"], "prime_state.session_sha256"),
        "tasks_sha256": _sha256(value["tasks_sha256"], "prime_state.tasks_sha256"),
        "queue_sha256": _sha256(value["queue_sha256"], "prime_state.queue_sha256"),
        "policy_sha256": _sha256(value["policy_sha256"], "prime_state.policy_sha256"),
        "writer_lease_sha256": _sha256(value["writer_lease_sha256"], "prime_state.writer_lease_sha256"),
        "w5_identity": w5_identity,
    }


def _identity_from_runtime(dispatch: Mapping[str, Any], label: str) -> dict[str, Any] | None:
    fields = ("pid", "process_starttime", "boot_id", "pidfd_ref", "cgroup_ref")
    if dispatch.get("pid") is None:
        if any(dispatch.get(field) is not None for field in fields):
            raise PrimeBindingError(f"{label}: partial process identity")
        return None
    return {
        "pid": _integer(dispatch["pid"], f"{label}.pid", minimum=1),
        "process_starttime": _text(dispatch["process_starttime"], f"{label}.process_starttime"),
        "boot_id": _text(dispatch["boot_id"], f"{label}.boot_id"),
        "pidfd_ref": _text(dispatch["pidfd_ref"], f"{label}.pidfd_ref"),
        "cgroup_ref": _text(dispatch["cgroup_ref"], f"{label}.cgroup_ref"),
        "run_token": _text(dispatch["run_token"], f"{label}.run_token"),
        "fencing_epoch": _integer(dispatch["fencing_epoch"], f"{label}.fencing_epoch", minimum=1),
        "command_hash": _text(dispatch["command_hash"], f"{label}.command_hash"),
    }


def control_from_runtime_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Project one ControlPlane snapshot into the strict W5-S3 control input.

    The full snapshot is retained by the caller as ``live_runtime``.  This
    projection is only the small, exact control contract consumed by S3; it
    never writes to the supplied controller.
    """

    runtime = _mapping(snapshot, "control_snapshot")
    for key in ("run", "cards", "attempts", "dispatches", "events"):
        if key not in runtime:
            raise PrimeBindingError(f"control_snapshot.{key}: missing")
    for key in ("cards", "attempts", "dispatches"):
        if not isinstance(runtime[key], list) or len(runtime[key]) != 1:
            raise PrimeBindingError(f"control_snapshot.{key}: exactly one row required")
    if not isinstance(runtime["events"], list):
        raise PrimeBindingError("control_snapshot.events: list required")

    run = _mapping(runtime["run"], "control_snapshot.run")
    card = _mapping(runtime["cards"][0], "control_snapshot.card")
    attempt = _mapping(runtime["attempts"][0], "control_snapshot.attempt")
    dispatch = _mapping(runtime["dispatches"][0], "control_snapshot.dispatch")
    spawn_events = [
        event
        for event in runtime["events"]
        if isinstance(event, Mapping) and event.get("event_type") == "SPAWN_REQUESTED"
    ]
    if len(spawn_events) != 1:
        raise PrimeBindingError("control_snapshot: exactly one SPAWN_REQUESTED event required")
    spawn_event = _mapping(spawn_events[0], "control_snapshot.spawn_event")
    if spawn_event.get("run_id") != run.get("run_id"):
        raise PrimeBindingError("control_snapshot.spawn_event.run_id mismatch")
    spawn_epoch = _timestamp_epoch(
        spawn_event.get("created_at"), "control_snapshot.spawn_event.created_at"
    )

    process_identity = _identity_from_runtime(dispatch, "control_snapshot.dispatch.process_identity")
    control = {
        "run": {
            "run_id": _text(run.get("run_id"), "control.run.run_id"),
            "state": _text(run.get("state"), "control.run.state"),
            "active_dispatch_id": _text(run.get("active_dispatch_id"), "control.run.active_dispatch_id"),
            "queue_hash": _text(run.get("queue_hash"), "control.run.queue_hash"),
            "policy_hash": _text(run.get("policy_hash"), "control.run.policy_hash"),
            "fencing_epoch": _integer(run.get("fencing_epoch"), "control.run.fencing_epoch", minimum=1),
            "lease_token": _text(run.get("lease_token"), "control.run.lease_token"),
        },
        "card": {
            "card_id": _text(card.get("card_id"), "control.card.card_id"),
            "run_id": _text(card.get("run_id"), "control.card.run_id"),
            "state": _text(card.get("state"), "control.card.state"),
            "active_attempt_id": _text(card.get("active_attempt_id"), "control.card.active_attempt_id"),
            "acceptance_txn_id": _optional_text(card.get("acceptance_txn_id"), "control.card.acceptance_txn_id"),
            "next_card_intent_id": _optional_text(card.get("next_card_intent_id"), "control.card.next_card_intent_id"),
            "card_hash": _text(card.get("card_hash"), "control.card.card_hash"),
            "source_queue_hash": _text(card.get("source_queue_hash"), "control.card.source_queue_hash"),
        },
        "attempt": {
            "attempt_id": _text(attempt.get("attempt_id"), "control.attempt.attempt_id"),
            "attempt_no": _integer(attempt.get("attempt_no"), "control.attempt.attempt_no", minimum=1),
            "retry_of": _optional_text(attempt.get("retry_of"), "control.attempt.retry_of"),
            "run_id": _text(attempt.get("run_id"), "control.attempt.run_id"),
            "card_id": _text(attempt.get("card_id"), "control.attempt.card_id"),
            "state": _text(attempt.get("state"), "control.attempt.state"),
            "dispatch_id": _text(attempt.get("dispatch_id"), "control.attempt.dispatch_id"),
            "worker_id": _optional_text(attempt.get("worker_id"), "control.attempt.worker_id"),
            "command_hash": _text(attempt.get("command_hash"), "control.attempt.command_hash"),
            "input_snapshot_hash": _text(attempt.get("input_snapshot_hash"), "control.attempt.input_snapshot_hash"),
            "context_pack_hash": _text(attempt.get("context_pack_hash"), "control.attempt.context_pack_hash"),
            "deadline_policy_hash": _text(attempt.get("deadline_policy_hash"), "control.attempt.deadline_policy_hash"),
        },
        "dispatch": {
            "dispatch_id": _text(dispatch.get("dispatch_id"), "control.dispatch.dispatch_id"),
            "run_id": _text(dispatch.get("run_id"), "control.dispatch.run_id"),
            "attempt_id": _text(dispatch.get("attempt_id"), "control.dispatch.attempt_id"),
            "state": _text(dispatch.get("state"), "control.dispatch.state"),
            "run_token": _text(dispatch.get("run_token"), "control.dispatch.run_token"),
            "owner_id": _text(dispatch.get("owner_id"), "control.dispatch.owner_id"),
            "fencing_epoch": _integer(dispatch.get("fencing_epoch"), "control.dispatch.fencing_epoch", minimum=1),
            "command_hash": _text(dispatch.get("command_hash"), "control.dispatch.command_hash"),
            "ack_deadline_at": _integer(dispatch.get("ack_deadline_at"), "control.dispatch.ack_deadline_at", minimum=1),
            "lease_expires_at": _integer(dispatch.get("lease_expires_at"), "control.dispatch.lease_expires_at", minimum=1),
            "spawn_requested_at_epoch": spawn_epoch,
            "spawn_attempt_no": _integer(dispatch.get("spawn_attempt_no"), "control.dispatch.spawn_attempt_no", minimum=0),
            "max_spawn_attempts": _integer(dispatch.get("max_spawn_attempts"), "control.dispatch.max_spawn_attempts", minimum=1),
            "process_identity": process_identity,
        },
        "lease": {
            "owner_id": _text(run.get("lease_owner_id"), "control.lease.owner_id"),
            "token": _text(run.get("lease_token"), "control.lease.token"),
            "fencing_epoch": _integer(run.get("fencing_epoch"), "control.lease.fencing_epoch", minimum=1),
            "expires_at": _integer(run.get("lease_expires_at"), "control.lease.expires_at", minimum=1),
        },
        "runtime_hash": canonical_hash(runtime),
    }
    return control


def capture_stable_control_snapshot(control_plane: Any, run_id: str) -> dict[str, Any]:
    """Read a stable control snapshot without invoking a mutating method.

    Two snapshots and two integrity checks are required.  This is a bounded
    TOCTOU detector, not a claim of database-level atomicity; an actual caller
    must keep the returned snapshot and the freshly built HRR input together.
    """

    snapshot_reader = getattr(control_plane, "snapshot", None)
    integrity_reader = getattr(control_plane, "integrity_check", None)
    if not callable(snapshot_reader) or not callable(integrity_reader):
        raise PrimeBindingError("control_plane requires snapshot() and integrity_check()")
    if integrity_reader() != "ok":
        raise PrimeBindingError("control-plane integrity check failed before capture")
    first = copy.deepcopy(_mapping(snapshot_reader(run_id), "control_snapshot"))
    if integrity_reader() != "ok":
        raise PrimeBindingError("control-plane integrity check failed during capture")
    second = copy.deepcopy(_mapping(snapshot_reader(run_id), "control_snapshot"))
    if integrity_reader() != "ok":
        raise PrimeBindingError("control-plane integrity check failed after capture")
    if canonical_hash(first) != canonical_hash(second):
        raise PrimeBindingError("control-plane snapshot changed during capture")
    return second


def fresh_hrr_input_from_control_plane(
    control_plane: Any,
    run_id: str,
    *,
    now_epoch: int,
    w5_bundle: Mapping[str, Any],
    w5_authority: Mapping[str, Any],
    w5_observation: Mapping[str, Any],
    candidate_identity: Mapping[str, Any] | None = None,
    candidate_observed_epoch: int | None = None,
    control_capture: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a new W5-S3 input from a coherent read-only ControlPlane capture."""

    now_epoch = _integer(now_epoch, "now_epoch", minimum=0)
    capture = (
        _normalize_control_capture(control_capture)
        if control_capture is not None
        else capture_consistent_control_snapshot(control_plane, run_id)
    )
    if now_epoch != capture["clock_after_epoch"]:
        raise PrimeBindingError("now_epoch is not the trusted control-plane clock sample")
    snapshot = capture["runtime"]
    control = control_from_runtime_snapshot(snapshot)
    if control["run"]["run_id"] != run_id:
        raise PrimeBindingError("control snapshot run_id mismatch")
    if candidate_identity is None and candidate_observed_epoch is not None:
        raise PrimeBindingError("candidate_observed_epoch requires candidate_identity")
    if candidate_identity is not None and candidate_observed_epoch is None:
        raise PrimeBindingError("candidate_identity requires candidate_observed_epoch")
    return {
        "schema_version": "w5-hrr-input-v1",
        "now_epoch": now_epoch,
        "w5_bundle": copy.deepcopy(dict(w5_bundle)),
        "w5_authority": copy.deepcopy(dict(w5_authority)),
        "w5_observation": copy.deepcopy(dict(w5_observation)),
        "live_runtime": snapshot,
        "control": control,
        "candidate_identity": copy.deepcopy(dict(candidate_identity)) if candidate_identity is not None else None,
        "candidate_observed_epoch": candidate_observed_epoch,
    }


def _fallback_hrr_decision(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "w5-hrr-decision-v1",
        "decision": "HOLD",
        "reason": reason,
        "identity": None,
        "state": None,
        "fencing_epoch": None,
        "source_attestation_hash": None,
        "control_snapshot_sha256": None,
        "permission": "read_only",
        "external_action": False,
        "execution": {
            "mutation": False,
            "spawn": False,
            "lease_reclaim": False,
            "acceptance": False,
            "next_card": False,
            "network": False,
        },
    }


def _binding_output(
    *,
    status: str,
    reason: str,
    decision: Mapping[str, Any],
    prime: Mapping[str, Any] | None,
    prime_state_hash: str | None,
    hrr_input_hash: str | None,
    live_runtime_hash: str | None,
    resume_allowed: bool,
    control_capture: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    identity = decision.get("identity")
    state = decision.get("state")
    w5 = {
        "identity": dict(identity) if isinstance(identity, Mapping) else None,
        "state": dict(state) if isinstance(state, Mapping) else None,
        "fencing_epoch": decision.get("fencing_epoch"),
        "source_attestation_hash": decision.get("source_attestation_hash"),
        "control_snapshot_sha256": decision.get("control_snapshot_sha256"),
        "live_runtime_sha256": live_runtime_hash,
    }
    hrr = {
        "input_sha256": hrr_input_hash,
        "decision_sha256": _safe_hash(decision),
        "decision": decision.get("decision"),
        "reason": decision.get("reason"),
    }
    return {
        "schema_version": PRIME_BINDING_SCHEMA,
        "binding_id": prime.get("binding_id") if prime is not None else None,
        "binding_status": status,
        "reason": reason,
        "decision": decision.get("decision", "HOLD"),
        "resume_allowed": bool(resume_allowed),
        "prime": (
            {**dict(prime), "state_sha256": prime_state_hash}
            if prime is not None
            else None
        ),
        "w5": w5,
        "hrr": hrr,
        "control_capture": (
            _capture_summary(control_capture) if control_capture is not None else None
        ),
        "permission": "read_only",
        "external_action": False,
        "execution": dict(FALSE_EXECUTION),
    }


def evaluate_prime_binding(
    prime_state: Mapping[str, Any],
    hrr_input: Mapping[str, Any],
    *,
    control_capture: Mapping[str, Any] | None = None,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Freshly evaluate and bind Prime state to one W5-S3 decision.

    A result without ``control_capture`` is deliberately never ``BOUND``.  A
    caller may use the pure path for diagnostics, but only the coherent
    read-only capture path can establish the S4 binding boundary.
    """

    prime_hash = _safe_hash(prime_state)
    input_hash = _safe_hash(hrr_input)
    try:
        prime = _normalize_prime_state(prime_state)
    except PrimeBindingError:
        prime = None
    capture = None
    try:
        if control_capture is not None:
            capture = _normalize_control_capture(control_capture)
    except PrimeBindingError:
        capture = None

    try:
        decision = evaluate_hrr(hrr_input, source_root=source_root)
        verify_hrr_decision(decision, input_value=hrr_input, source_root=source_root)
    except (HrrGateError, TypeError, ValueError, OSError):
        decision = _fallback_hrr_decision("INVALID_INPUT")

    live_runtime_hash = None
    if isinstance(hrr_input, Mapping):
        live_runtime_hash = _safe_hash(hrr_input.get("live_runtime"))

    if prime is None:
        return _binding_output(
            status="HOLD",
            reason="INVALID_PRIME_STATE",
            decision=decision,
            prime=None,
            prime_state_hash=prime_hash,
            hrr_input_hash=input_hash,
            live_runtime_hash=live_runtime_hash,
            resume_allowed=False,
            control_capture=capture,
        )
    if decision.get("reason") == "INVALID_INPUT":
        return _binding_output(
            status="HOLD",
            reason="INVALID_HRR_INPUT",
            decision=decision,
            prime=prime,
            prime_state_hash=canonical_hash(prime),
            hrr_input_hash=input_hash,
            live_runtime_hash=live_runtime_hash,
            resume_allowed=False,
            control_capture=capture,
        )

    if capture is None:
        return _binding_output(
            status="HOLD",
            reason="CONTROL_SNAPSHOT_INVALID",
            decision=decision,
            prime=prime,
            prime_state_hash=canonical_hash(prime),
            hrr_input_hash=input_hash,
            live_runtime_hash=live_runtime_hash,
            resume_allowed=False,
            control_capture=None,
        )
    if live_runtime_hash != capture["runtime_sha256"]:
        return _binding_output(
            status="HOLD",
            reason="CONTROL_CAPTURE_DRIFT",
            decision=decision,
            prime=prime,
            prime_state_hash=canonical_hash(prime),
            hrr_input_hash=input_hash,
            live_runtime_hash=live_runtime_hash,
            resume_allowed=False,
            control_capture=capture,
        )
    if (
        not isinstance(hrr_input, Mapping)
        or hrr_input.get("now_epoch") != capture["clock_after_epoch"]
    ):
        return _binding_output(
            status="HOLD",
            reason="CONTROL_CAPTURE_DRIFT",
            decision=decision,
            prime=prime,
            prime_state_hash=canonical_hash(prime),
            hrr_input_hash=input_hash,
            live_runtime_hash=live_runtime_hash,
            resume_allowed=False,
            control_capture=capture,
        )

    decision_identity = decision.get("identity")
    if not isinstance(decision_identity, Mapping):
        return _binding_output(
            status="HOLD",
            reason="HRR_NOT_RESUMABLE",
            decision=decision,
            prime=prime,
            prime_state_hash=canonical_hash(prime),
            hrr_input_hash=input_hash,
            live_runtime_hash=live_runtime_hash,
            resume_allowed=False,
            control_capture=capture,
        )
    if dict(decision_identity) != prime["w5_identity"]:
        return _binding_output(
            status="HOLD",
            reason="PRIME_IDENTITY_DRIFT",
            decision=decision,
            prime=prime,
            prime_state_hash=canonical_hash(prime),
            hrr_input_hash=input_hash,
            live_runtime_hash=live_runtime_hash,
            resume_allowed=False,
            control_capture=capture,
        )

    if decision["decision"] == "RESUME":
        if prime["resume_gate"] != "continue":
            return _binding_output(
                status="HOLD",
                reason="PRIME_GATE_CLOSED",
                decision=decision,
                prime=prime,
                prime_state_hash=canonical_hash(prime),
                hrr_input_hash=input_hash,
                live_runtime_hash=live_runtime_hash,
                resume_allowed=False,
                control_capture=capture,
            )
        if (
            prime["status"] != "in_progress"
            or prime["next_action"]["action"] != "continue"
            or prime["next_action"]["task_id"] != prime["active_task_id"]
            or prime["resume_gate_reason"]
            or prime["stop_reason"]
            or prime["hold_reason"]
        ):
            return _binding_output(
                status="HOLD",
                reason="PRIME_GATE_DRIFT",
                decision=decision,
                prime=prime,
                prime_state_hash=canonical_hash(prime),
                hrr_input_hash=input_hash,
                live_runtime_hash=live_runtime_hash,
                resume_allowed=False,
                control_capture=capture,
            )
        return _binding_output(
            status="BOUND_READ_ONLY",
            reason="BOUND_RESUME",
            decision=decision,
            prime=prime,
            prime_state_hash=canonical_hash(prime),
            hrr_input_hash=input_hash,
            live_runtime_hash=live_runtime_hash,
            resume_allowed=True,
            control_capture=capture,
        )

    if prime["resume_gate"] == "continue":
        return _binding_output(
            status="HOLD",
            reason="PRIME_GATE_DRIFT",
            decision=decision,
            prime=prime,
            prime_state_hash=canonical_hash(prime),
            hrr_input_hash=input_hash,
            live_runtime_hash=live_runtime_hash,
            resume_allowed=False,
            control_capture=capture,
        )
    reason = (
        "RECONCILE_ACTION_REQUIRED"
        if decision["decision"] == "RECONCILE"
        else "HRR_HOLD"
    )
    return _binding_output(
        status="BOUND_READ_ONLY",
        reason=reason,
        decision=decision,
        prime=prime,
        prime_state_hash=canonical_hash(prime),
        hrr_input_hash=input_hash,
        live_runtime_hash=live_runtime_hash,
        resume_allowed=False,
        control_capture=capture,
    )


def evaluate_prime_binding_from_control_plane(
    control_plane: Any,
    run_id: str,
    prime_state: Mapping[str, Any],
    *,
    now_epoch: int,
    w5_bundle: Mapping[str, Any],
    w5_authority: Mapping[str, Any],
    w5_observation: Mapping[str, Any],
    candidate_identity: Mapping[str, Any] | None = None,
    candidate_observed_epoch: int | None = None,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Capture the ControlPlane and perform one fresh, actionless binding."""

    try:
        capture = capture_consistent_control_snapshot(control_plane, run_id)
        hrr_input = fresh_hrr_input_from_control_plane(
            control_plane,
            run_id,
            now_epoch=now_epoch,
            w5_bundle=w5_bundle,
            w5_authority=w5_authority,
            w5_observation=w5_observation,
            candidate_identity=candidate_identity,
            candidate_observed_epoch=candidate_observed_epoch,
            control_capture=capture,
        )
    except PrimeBindingError:
        decision = _fallback_hrr_decision("INVALID_INPUT")
        return _binding_output(
            status="HOLD",
            reason="CONTROL_SNAPSHOT_UNSTABLE",
            decision=decision,
            prime=None,
            prime_state_hash=_safe_hash(prime_state),
            hrr_input_hash=None,
            live_runtime_hash=None,
            resume_allowed=False,
        )
    return evaluate_prime_binding(
        prime_state,
        hrr_input,
        control_capture=capture,
        source_root=source_root,
    )


def evaluate_prime_binding_from_prime_evidence(
    control_plane: Any,
    run_id: str,
    prime_root: str | Path,
    run_relative_path: str | Path,
    *,
    now_epoch: int,
    w5_bundle: Mapping[str, Any],
    w5_authority: Mapping[str, Any],
    w5_observation: Mapping[str, Any],
    candidate_identity: Mapping[str, Any] | None = None,
    candidate_observed_epoch: int | None = None,
    resume_packet_relative_path: str | Path | None = None,
    evidence_hook: Callable[[str, str | None], None] | None = None,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Capture real Prime ledgers, build S4 state, then evaluate HRR freshly.

    The filesystem capture is intentionally a separate proof boundary.  A
    missing or ineligible optional sidecar therefore becomes a coded HOLD;
    it is never replaced with a synthetic hash or a guessed task mapping.
    """

    try:
        capture = capture_consistent_control_snapshot(control_plane, run_id)
        hrr_input = fresh_hrr_input_from_control_plane(
            control_plane,
            run_id,
            now_epoch=now_epoch,
            w5_bundle=w5_bundle,
            w5_authority=w5_authority,
            w5_observation=w5_observation,
            candidate_identity=candidate_identity,
            candidate_observed_epoch=candidate_observed_epoch,
            control_capture=capture,
        )
    except PrimeBindingError:
        decision = _fallback_hrr_decision("INVALID_INPUT")
        return _binding_output(
            status="HOLD",
            reason="CONTROL_SNAPSHOT_UNSTABLE",
            decision=decision,
            prime=None,
            prime_state_hash=_safe_hash(None),
            hrr_input_hash=None,
            live_runtime_hash=None,
            resume_allowed=False,
        )

    control = _mapping(hrr_input["control"], "hrr_input.control")
    prime_identity = {
        "run_id": control["run"]["run_id"],
        "card_id": control["card"]["card_id"],
        "attempt_id": control["attempt"]["attempt_id"],
        "dispatch_id": control["dispatch"]["dispatch_id"],
    }
    try:
        evidence = capture_prime_evidence(
            prime_root,
            run_relative_path,
            resume_packet_relative_path=resume_packet_relative_path,
            hook=evidence_hook,
        )
        prime_state = build_prime_state_from_capture(
            evidence,
            w5_identity=prime_identity,
        )
    except PrimeEvidenceError as exc:
        try:
            decision = evaluate_hrr(hrr_input, source_root=source_root)
            verify_hrr_decision(decision, input_value=hrr_input, source_root=source_root)
        except (HrrGateError, TypeError, ValueError, OSError):
            decision = _fallback_hrr_decision("INVALID_INPUT")
        reason = exc.code if exc.code in BINDING_REASONS else "PRIME_EVIDENCE_BINDING_INELIGIBLE"
        return _binding_output(
            status="HOLD",
            reason=reason,
            decision=decision,
            prime=None,
            prime_state_hash=None,
            hrr_input_hash=canonical_hash(hrr_input),
            live_runtime_hash=_safe_hash(hrr_input.get("live_runtime")),
            resume_allowed=False,
            control_capture=capture,
        )

    return evaluate_prime_binding(
        prime_state,
        hrr_input,
        control_capture=capture,
        source_root=source_root,
    )


def evaluate_prime_binding_from_prime_evidence_v2(
    control_plane: Any,
    run_id: str,
    prime_root: str | Path,
    run_relative_path: str | Path,
    *,
    now_epoch: int,
    w5_bundle: Mapping[str, Any],
    w5_authority: Mapping[str, Any],
    w5_observation: Mapping[str, Any],
    candidate_identity: Mapping[str, Any] | None = None,
    candidate_observed_epoch: int | None = None,
    resume_packet_relative_path: str | Path | None = None,
    manifest_hook: Callable[[str, str | None], None] | None = None,
    expected_prime_run_id: str | None = None,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Use the opt-in v2 manifest witness without granting new authority.

    A matched writer manifest is explicitly self-attested.  Even if the
    existing S4 evaluator would report ``resume_allowed=True``, this v2
    adapter downgrades that result to an actionless HOLD until a future,
    externally anchored writer authority exists.
    """

    try:
        capture = capture_consistent_control_snapshot(control_plane, run_id)
        hrr_input = fresh_hrr_input_from_control_plane(
            control_plane,
            run_id,
            now_epoch=now_epoch,
            w5_bundle=w5_bundle,
            w5_authority=w5_authority,
            w5_observation=w5_observation,
            candidate_identity=candidate_identity,
            candidate_observed_epoch=candidate_observed_epoch,
            control_capture=capture,
        )
    except PrimeBindingError:
        decision = _fallback_hrr_decision("INVALID_INPUT")
        return _binding_output(
            status="HOLD",
            reason="CONTROL_SNAPSHOT_UNSTABLE",
            decision=decision,
            prime=None,
            prime_state_hash=_safe_hash(None),
            hrr_input_hash=None,
            live_runtime_hash=None,
            resume_allowed=False,
        )

    control = _mapping(hrr_input["control"], "hrr_input.control")
    prime_identity = {
        "run_id": control["run"]["run_id"],
        "card_id": control["card"]["card_id"],
        "attempt_id": control["attempt"]["attempt_id"],
        "dispatch_id": control["dispatch"]["dispatch_id"],
    }
    try:
        evidence = capture_prime_evidence_v2(
            prime_root,
            run_relative_path,
            resume_packet_relative_path=resume_packet_relative_path,
            manifest_hook=manifest_hook,
        )
        prime_state = build_prime_state_from_evidence_v2(
            evidence,
            w5_identity=prime_identity,
            expected_prime_run_id=expected_prime_run_id,
        )
    except PrimeEvidenceError as exc:
        try:
            decision = evaluate_hrr(hrr_input, source_root=source_root)
            verify_hrr_decision(decision, input_value=hrr_input, source_root=source_root)
        except (HrrGateError, TypeError, ValueError, OSError):
            decision = _fallback_hrr_decision("INVALID_INPUT")
        reason = exc.code if exc.code in BINDING_REASONS else "PRIME_EVIDENCE_BINDING_INELIGIBLE"
        return _binding_output(
            status="HOLD",
            reason=reason,
            decision=decision,
            prime=None,
            prime_state_hash=None,
            hrr_input_hash=canonical_hash(hrr_input),
            live_runtime_hash=_safe_hash(hrr_input.get("live_runtime")),
            resume_allowed=False,
            control_capture=capture,
        )

    result = evaluate_prime_binding(
        prime_state,
        hrr_input,
        control_capture=capture,
        source_root=source_root,
    )
    if result["resume_allowed"]:
        result = dict(result)
        result["binding_status"] = "HOLD"
        result["reason"] = "PRIME_EVIDENCE_WRITER_ATTESTATION_UNTRUSTED"
        result["resume_allowed"] = False
    return result


def _validate_binding(value: Any) -> dict[str, Any]:
    value = _mapping(value, "prime_binding")
    _exact_keys(value, BINDING_KEYS, "prime_binding")
    if value["schema_version"] != PRIME_BINDING_SCHEMA:
        raise PrimeBindingError("prime_binding.schema_version unsupported")
    status = _text(value["binding_status"], "prime_binding.binding_status")
    if status not in BINDING_STATUSES:
        raise PrimeBindingError("prime_binding.binding_status unsupported")
    reason = _text(value["reason"], "prime_binding.reason")
    if reason not in BINDING_REASONS:
        raise PrimeBindingError("prime_binding.reason unsupported")
    decision = _text(value["decision"], "prime_binding.decision")
    if decision not in BINDING_DECISIONS:
        raise PrimeBindingError("prime_binding.decision unsupported")
    if type(value["resume_allowed"]) is not bool:
        raise PrimeBindingError("prime_binding.resume_allowed must be boolean")
    binding_id = value["binding_id"]
    if binding_id is not None:
        _sha256(binding_id, "prime_binding.binding_id")

    prime_value = value["prime"]
    prime = None
    if prime_value is not None:
        prime_value = _mapping(prime_value, "prime_binding.prime")
        _exact_keys(prime_value, PRIME_OUTPUT_KEYS, "prime_binding.prime")
        prime = _normalize_prime_state(
            {key: prime_value[key] for key in PRIME_STATE_KEYS}
        )
        _sha256(prime_value["state_sha256"], "prime_binding.prime.state_sha256")
        if prime_value["state_sha256"] != canonical_hash(prime):
            raise PrimeBindingError("prime_binding.prime.state_sha256 mismatch")

    w5_value = _mapping(value["w5"], "prime_binding.w5")
    _exact_keys(w5_value, W5_OUTPUT_KEYS, "prime_binding.w5")
    identity = w5_value["identity"]
    if identity is not None:
        _normalize_w5_identity(identity, "prime_binding.w5.identity")
    state = w5_value["state"]
    if state is not None:
        state = _mapping(state, "prime_binding.w5.state")
        if set(state) != {"run", "card", "attempt", "dispatch"}:
            raise PrimeBindingError("prime_binding.w5.state schema drift")
        for key in state:
            _text(state[key], f"prime_binding.w5.state.{key}")
    if w5_value["fencing_epoch"] is not None:
        _integer(w5_value["fencing_epoch"], "prime_binding.w5.fencing_epoch", minimum=1)
    for key in ("source_attestation_hash", "control_snapshot_sha256", "live_runtime_sha256"):
        if w5_value[key] is not None:
            _sha256(w5_value[key], f"prime_binding.w5.{key}")

    hrr = _mapping(value["hrr"], "prime_binding.hrr")
    _exact_keys(hrr, HRR_OUTPUT_KEYS, "prime_binding.hrr")
    for key in ("input_sha256", "decision_sha256"):
        if hrr[key] is not None:
            _sha256(hrr[key], f"prime_binding.hrr.{key}")
    if _text(hrr["decision"], "prime_binding.hrr.decision") not in BINDING_DECISIONS:
        raise PrimeBindingError("prime_binding.hrr.decision unsupported")
    _text(hrr["reason"], "prime_binding.hrr.reason")

    capture_value = value["control_capture"]
    capture = None
    if capture_value is not None:
        capture = _mapping(capture_value, "prime_binding.control_capture")
        _exact_keys(capture, CONTROL_CAPTURE_OUTPUT_KEYS, "prime_binding.control_capture")
        if capture["schema_version"] != CONTROL_CAPTURE_SCHEMA:
            raise PrimeBindingError("prime_binding.control_capture.schema_version unsupported")
        _text(capture["run_id"], "prime_binding.control_capture.run_id")
        for key in (
            "runtime_sha256",
            "projection_sha256",
            "runtime_anchor_sha256",
            "marker_commitments_sha256",
            "capture_sha256",
        ):
            _sha256(capture[key], f"prime_binding.control_capture.{key}")
        _integer(capture["clock_before_epoch"], "prime_binding.control_capture.clock_before_epoch", minimum=0)
        _integer(capture["clock_after_epoch"], "prime_binding.control_capture.clock_after_epoch", minimum=0)
        if capture["clock_after_epoch"] < capture["clock_before_epoch"]:
            raise PrimeBindingError("prime_binding.control_capture clock order invalid")
        if capture["integrity_check"] != "ok" or capture["read_only"] is not True:
            raise PrimeBindingError("prime_binding.control_capture is not read-only")

    if value["permission"] != "read_only" or value["external_action"] is not False:
        raise PrimeBindingError("prime_binding is not read-only")
    execution = _mapping(value["execution"], "prime_binding.execution")
    _exact_keys(execution, EXECUTION_KEYS, "prime_binding.execution")
    if any(type(execution[key]) is not bool or execution[key] is not False for key in EXECUTION_KEYS):
        raise PrimeBindingError("prime_binding execution flags must all be false")

    if value["resume_allowed"]:
        if not (
            status == "BOUND_READ_ONLY"
            and reason == "BOUND_RESUME"
            and decision == "RESUME"
            and prime is not None
            and prime["resume_gate"] == "continue"
            and identity is not None
            and binding_id is not None
            and prime is not None
            and binding_id == prime["binding_id"]
        ):
            raise PrimeBindingError("resume_allowed lacks the complete binding boundary")
        if capture is None:
            raise PrimeBindingError("resume_allowed lacks a coherent control capture")
        if hrr["input_sha256"] is None or hrr["decision_sha256"] is None:
            raise PrimeBindingError("resume_allowed lacks HRR hashes")
        if w5_value["source_attestation_hash"] is None or w5_value["control_snapshot_sha256"] is None:
            raise PrimeBindingError("resume_allowed lacks W5 provenance hashes")
    if status == "BOUND_READ_ONLY" and capture is None:
        raise PrimeBindingError("BOUND binding lacks a coherent control capture")
    if status == "BOUND_READ_ONLY" and (prime is None or binding_id != prime["binding_id"]):
        raise PrimeBindingError("BOUND binding lacks the Prime↔W5 binding id")
    if status == "HOLD" and value["resume_allowed"]:
        raise PrimeBindingError("HOLD binding cannot allow resume")
    if hrr["decision"] != decision:
        raise PrimeBindingError("binding decision and HRR decision differ")
    return {
        "schema_version": PRIME_BINDING_SCHEMA,
        "binding_id": binding_id,
        "binding_status": status,
        "reason": reason,
        "decision": decision,
        "resume_allowed": value["resume_allowed"],
        "prime": (
            {**prime, "state_sha256": prime_value["state_sha256"]}
            if prime is not None
            else None
        ),
        "w5": {
            "identity": dict(identity) if isinstance(identity, Mapping) else None,
            "state": dict(state) if isinstance(state, Mapping) else None,
            "fencing_epoch": w5_value["fencing_epoch"],
            "source_attestation_hash": w5_value["source_attestation_hash"],
            "control_snapshot_sha256": w5_value["control_snapshot_sha256"],
            "live_runtime_sha256": w5_value["live_runtime_sha256"],
        },
        "hrr": dict(hrr),
        "control_capture": dict(capture) if capture is not None else None,
        "permission": "read_only",
        "external_action": False,
        "execution": dict(FALSE_EXECUTION),
    }


def verify_prime_binding(
    value: Mapping[str, Any],
    *,
    prime_state: Mapping[str, Any] | None = None,
    hrr_input: Mapping[str, Any] | None = None,
    control_capture: Mapping[str, Any] | None = None,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Verify a binding; fresh inputs are required for authority use.

    Without both fresh inputs this only validates shape and semantics.  It is
    explicitly not a reusable resume token.  With both inputs the complete
    binding is recomputed and must match byte-for-byte after normalization.
    """

    normalized = _validate_binding(value)
    if (prime_state is None) != (hrr_input is None):
        raise PrimeBindingError("prime_state and hrr_input must be supplied together")
    if prime_state is not None and hrr_input is not None:
        expected = evaluate_prime_binding(
            prime_state,
            hrr_input,
            control_capture=control_capture,
            source_root=source_root,
        )
        if expected != normalized:
            raise PrimeBindingError("prime_binding does not match freshly evaluated inputs")
    return normalized


__all__ = [
    "BINDING_STATUSES",
    "CONTROL_CAPTURE_SCHEMA",
    "PRIME_BINDING_SCHEMA",
    "PRIME_GATE_VALUES",
    "PRIME_STATE_SCHEMA",
    "PrimeBindingError",
    "capture_consistent_control_snapshot",
    "capture_stable_control_snapshot",
    "control_from_runtime_snapshot",
    "evaluate_prime_binding",
    "evaluate_prime_binding_from_control_plane",
    "evaluate_prime_binding_from_prime_evidence",
    "evaluate_prime_binding_from_prime_evidence_v2",
    "fresh_hrr_input_from_control_plane",
    "verify_prime_binding",
]
