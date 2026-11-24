"""Test-only S25E boundary and durability harness.

This helper observes isolated fixtures before and after a public S25D action.
It never repairs a fixture and never calls a private Queue-Writer mutation
method.  Threat fields intentionally default to ``NOT_CLAIMED`` unless the
small local observation itself is directly established.
"""

from __future__ import annotations

import hashlib
import json
import fcntl
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping
from urllib.parse import quote

from modules.w4_small_loop_s0 import canonical_hash
from modules.w5_dispatch_bridge_s0.prime_queue_writer import PrimeQueueWriter


HARNESS_SCHEMA = "prime-queue-boundary-harness-v1"
BOUNDARY_CASE_RECORDED = "BOUNDARY_CASE_RECORDED"
CASE_CRASHED = "CASE_CRASHED"
HOLD = "HOLD"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
CLAIMED = "CLAIMED"
NOT_CLAIMED = "NOT_CLAIMED"

_TABLES = (
    "prime_queue_writer_meta",
    "prime_queue_writer_roots",
    "prime_queue_writer_scopes",
    "prime_queue_writer_operations",
    "prime_queue_writer_events",
    "prime_queue_writer_markers",
    "prime_queue_writer_handoff_events",
)
_INDEXES = {
    "idx_prime_queue_writer_events_operation",
    "idx_prime_queue_writer_handoff_events_scope",
}
_TRIGGERS = {
    "prime_queue_writer_markers_immutable_update",
    "prime_queue_writer_markers_immutable_delete",
    "prime_queue_writer_events_immutable_update",
    "prime_queue_writer_events_immutable_delete",
    "prime_queue_writer_handoff_events_immutable_update",
    "prime_queue_writer_handoff_events_immutable_delete",
}


def _identity(path: Path) -> dict[str, int] | None:
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


def _fd_identity(fd: int) -> dict[str, int]:
    info = os.fstat(fd)
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "link_count": int(info.st_nlink),
        "size": int(info.st_size),
        "mode": int(stat.S_IMODE(info.st_mode)),
    }


def _read_fd(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _observe_fd_boundary(
    path: Path,
    *,
    lock: bool,
    mutate_after_open: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Observe one existing path through one FD without creating or writing it."""

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        return {"status": HOLD, "reason": "PATH_MISSING", "path": str(path)}
    except (OSError, ValueError) as exc:
        return {"status": RECOVERY_REQUIRED, "reason": f"PATH_OPEN_FAILED_{type(exc).__name__}", "path": str(path)}

    locked = False
    try:
        fd_before = _fd_identity(fd)
        path_before = _identity(path)
        if path_before != fd_before:
            return {
                "status": RECOVERY_REQUIRED,
                "reason": "PATH_FD_IDENTITY_MISMATCH_BEFORE",
                "fd_before": fd_before,
                "path_before": path_before,
            }
        if lock:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                locked = True
            except (BlockingIOError, OSError) as exc:
                if isinstance(exc, BlockingIOError) or getattr(exc, "errno", None) in {11, 13}:
                    return {"status": HOLD, "reason": "LOCK_UNAVAILABLE", "path": str(path)}
                return {"status": RECOVERY_REQUIRED, "reason": f"LOCK_OBSERVE_FAILED_{type(exc).__name__}"}

        payload_before = None if lock else _read_fd(fd)
        if mutate_after_open is not None:
            mutate_after_open()

        payload = None if lock else _read_fd(fd)
        fd_after = _fd_identity(fd)
        path_after = _identity(path)
        content_stable = lock or (
            hashlib.sha256(payload_before or b"").digest() == hashlib.sha256(payload or b"").digest()
            and len(payload_before or b"") == len(payload or b"")
        )
        stable = fd_before == fd_after == path_before == path_after and content_stable
        result: dict[str, Any] = {
            "status": CLAIMED if stable else RECOVERY_REQUIRED,
            "reason": "FD_PATH_BOUNDARY_STABLE" if stable else "FD_PATH_OR_CONTENT_BOUNDARY_DRIFT",
            "fd_before": fd_before,
            "fd_after": fd_after,
            "path_before": path_before,
            "path_after": path_after,
        }
        if payload is not None:
            result.update(
                {
                    "fd_sha256_before": hashlib.sha256(payload_before or b"").hexdigest(),
                    "fd_sha256": hashlib.sha256(payload).hexdigest(),
                    "fd_size_before": len(payload_before or b""),
                    "fd_size": len(payload),
                }
            )
        return result
    except (OSError, ValueError) as exc:
        return {"status": RECOVERY_REQUIRED, "reason": f"BOUNDARY_READ_FAILED_{type(exc).__name__}"}
    finally:
        if locked:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def observe_read_only_boundary(
    writer: PrimeQueueWriter,
    *,
    mutate_lock_after_open: Callable[[], None] | None = None,
    mutate_queue_after_open: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Observe lock, Queue and SQLite reopen boundaries without mutation authority.

    Mutation callbacks are adversary hooks owned by the test fixture.  They are
    deliberately outside this observer so a detected path change is classified
    rather than repaired.
    """

    control = writer.root / "Plan" / "local-ai" / "control"
    lock_result = _observe_fd_boundary(
        control / "queue.lock",
        lock=True,
        mutate_after_open=mutate_lock_after_open,
    )
    queue_result = _observe_fd_boundary(
        writer.queue_path,
        lock=False,
        mutate_after_open=mutate_queue_after_open,
    )
    reopen_result = reopen_read_only(writer)
    observed_statuses = {lock_result["status"], queue_result["status"], reopen_result["status"]}
    if HOLD in observed_statuses:
        status = HOLD
        reason = "READ_ONLY_BOUNDARY_HOLD"
    elif observed_statuses != {CLAIMED}:
        status = RECOVERY_REQUIRED
        reason = "READ_ONLY_BOUNDARY_DRIFT_OR_REOPEN_FAILURE"
    else:
        status = BOUNDARY_CASE_RECORDED
        reason = "READ_ONLY_BOUNDARY_OBSERVED"
    return {
        "schema_version": HARNESS_SCHEMA,
        "status": status,
        "reason": reason,
        "decision": "OBSERVE_ONLY",
        "lock": lock_result,
        "queue": queue_result,
        "reopen": reopen_result,
        "recovery_authority": False,
        "claim_authority": False,
        "mutation_allowed": False,
        "resume_allowed": False,
        "queue_file_write": False,
        "sqlite_write": False,
        "marker_write": False,
        "cross_store_write": NOT_CLAIMED,
        "foreign_repair_performed": NOT_CLAIMED,
        "boundary_coherence": NOT_CLAIMED,
        "threats": {
            "lock_inode_identity": lock_result["status"],
            "lock_inode_aba": NOT_CLAIMED if lock_result["status"] == CLAIMED else RECOVERY_REQUIRED,
            "queue_path_aba": NOT_CLAIMED if queue_result["status"] == CLAIMED else RECOVERY_REQUIRED,
            "path_toctou": NOT_CLAIMED if queue_result["status"] == CLAIMED else RECOVERY_REQUIRED,
            "sqlite_writer_authority": NOT_CLAIMED,
            "wal_power_loss": NOT_CLAIMED,
            "queue_read_stable": queue_result["status"],
            "wal_reopen": reopen_result["status"],
            "cross_store_atomicity": NOT_CLAIMED,
        },
    }


def _file_digest(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _transaction_projection(control: Path) -> list[dict[str, Any]]:
    projection: list[dict[str, Any]] = []
    for transaction in sorted(control.glob("tx-*")):
        entry: dict[str, Any] = {"path": transaction.name, "identity": _identity(transaction)}
        if transaction.is_symlink() or not transaction.is_dir():
            entry["files"] = None
            projection.append(entry)
            continue
        files: list[dict[str, Any]] = []
        for child in sorted(transaction.iterdir()):
            files.append(
                {
                    "name": child.name,
                    "identity": _identity(child),
                    "sha256": _file_digest(child),
                }
            )
        entry["files"] = files
        projection.append(entry)
    return projection


def _db_projection(writer: PrimeQueueWriter) -> dict[str, Any]:
    rows: dict[str, list[list[Any]]] = {}
    db_path = writer.db_path
    uri = f"file:{quote(str(db_path), safe='/')}?mode=ro"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=1.0)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        for table in _TABLES:
            rows[table] = [list(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()]
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower()
        foreign_key_check = [list(row) for row in connection.execute("PRAGMA foreign_key_check").fetchall()]
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        return {
            "tables_sha256": canonical_hash({"error": type(exc).__name__}),
            "journal_mode": None,
            "synchronous": None,
            "integrity_check": None,
            "foreign_key_check": None,
            "row_counts": {},
        }
    finally:
        if connection is not None:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            connection.close()
    return {
        "tables_sha256": canonical_hash(rows),
        "journal_mode": journal_mode,
        "synchronous": synchronous,
        "integrity_check": integrity,
        "foreign_key_check": foreign_key_check,
        "row_counts": {table: len(rows[table]) for table in _TABLES},
    }


def snapshot_writer_store(writer: PrimeQueueWriter) -> dict[str, Any]:
    """Capture only the local Queue-Writer evidence needed for comparison."""

    control = writer.root / "Plan" / "local-ai" / "control"
    queue = writer.queue_path
    queue_bytes = None
    try:
        if not queue.is_symlink() and queue.is_file():
            queue_bytes = queue.read_bytes()
    except OSError:
        queue_bytes = None
    return {
        "queue_sha256": hashlib.sha256(queue_bytes).hexdigest() if queue_bytes is not None else None,
        "queue_identity": _identity(queue),
        "queue_size": len(queue_bytes) if queue_bytes is not None else None,
        "lock_identity": _identity(control / "queue.lock"),
        "db": _db_projection(writer),
        "transactions": _transaction_projection(control),
    }


def reopen_read_only(writer: PrimeQueueWriter) -> dict[str, Any]:
    """Open the existing SQLite file read-only and run a bounded readback."""

    db_path = writer.db_path
    if db_path.is_symlink() or not db_path.is_file() or db_path.stat().st_nlink != 1:
        return {"status": RECOVERY_REQUIRED, "reason": "REOPEN_DB_PATH_INVALID"}
    uri = f"file:{quote(str(db_path), safe='/')}?mode=ro"
    connection: sqlite3.Connection | None = None
    in_transaction = False
    try:
        connection = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=1.0)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        in_transaction = True
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        indexes = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'"
            ).fetchall()
        }
        triggers = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
        }
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower()
        foreign_key_check = [list(row) for row in connection.execute("PRAGMA foreign_key_check").fetchall()]
        if (
            tables != set(_TABLES)
            or not _INDEXES.issubset(indexes)
            or not _TRIGGERS.issubset(triggers)
            or journal_mode != "wal"
            or synchronous != 2
            or integrity != "ok"
            or foreign_key_check
        ):
            return {
                "status": RECOVERY_REQUIRED,
                "reason": "REOPEN_SCHEMA_DURABILITY_OR_INTEGRITY_DRIFT",
                "claim_scope": "READABILITY_SCHEMA_INTEGRITY_ONLY",
                "tables": sorted(tables),
                "indexes": sorted(indexes),
                "triggers": sorted(triggers),
                "journal_mode": journal_mode,
                "synchronous": synchronous,
                "integrity_check": integrity,
                "foreign_key_check": foreign_key_check,
            }
        return {
            "status": CLAIMED,
            "reason": "READ_ONLY_REOPEN_OBSERVED",
            "claim_scope": "READABILITY_SCHEMA_INTEGRITY_ONLY",
            "journal_mode": journal_mode,
            "synchronous": synchronous,
            "integrity_check": integrity,
            "foreign_key_check": foreign_key_check,
            "tables": sorted(tables),
            "indexes": sorted(indexes),
            "triggers": sorted(triggers),
        }
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        return {"status": RECOVERY_REQUIRED, "reason": f"REOPEN_READ_FAILED_{type(exc).__name__}"}
    finally:
        if connection is not None and in_transaction:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
        if connection is not None:
            connection.close()


def run_boundary_case(
    case_id: str,
    writer: PrimeQueueWriter,
    action: Callable[[], Mapping[str, Any]],
    *,
    reopen: bool = False,
) -> dict[str, Any]:
    """Run one public action and compare local evidence before/after it."""

    before = snapshot_writer_store(writer)
    observed: Mapping[str, Any] | None = None
    exception: str | None = None
    try:
        observed = action()
        status = BOUNDARY_CASE_RECORDED
    except Exception as exc:
        status = CASE_CRASHED
        exception = type(exc).__name__
    after = snapshot_writer_store(writer)
    queue_changed = (
        before["queue_sha256"] != after["queue_sha256"]
        or before["queue_identity"] != after["queue_identity"]
    )
    local_changed = (
        before["db"]["tables_sha256"] != after["db"]["tables_sha256"]
        or before["transactions"] != after["transactions"]
    )
    queue_projection_stable = before["queue_sha256"] == after["queue_sha256"] and before["queue_identity"] == after["queue_identity"]
    reopen_result = reopen_read_only(writer) if reopen else None
    if reopen_result is not None and reopen_result["status"] != CLAIMED:
        status = RECOVERY_REQUIRED
    return {
        "schema_version": HARNESS_SCHEMA,
        "case_id": case_id,
        "status": status,
        "exception": exception,
        "observed_s25d_status": observed.get("status") if observed is not None else None,
        "observed_s25d_reason": observed.get("reason") if observed is not None else None,
        "before": before,
        "after": after,
        "queue_json_write": queue_changed,
        "local_queue_writer_mutation": local_changed,
        "queue_projection_changed": queue_changed,
        "queue_projection_stable": queue_projection_stable,
        "cross_store_write": NOT_CLAIMED,
        "foreign_repair_performed": NOT_CLAIMED,
        "threats": {
            "lock_inode_identity": NOT_CLAIMED,
            "queue_path_aba": NOT_CLAIMED,
            "path_toctou": NOT_CLAIMED,
            "sqlite_writer_authority": NOT_CLAIMED,
            "wal_power_loss": NOT_CLAIMED,
            "queue_read_stable": NOT_CLAIMED if queue_projection_stable else RECOVERY_REQUIRED,
            "wal_reopen": reopen_result["status"] if reopen_result is not None else NOT_CLAIMED,
            "cross_store_atomicity": NOT_CLAIMED,
        },
        "reopen": reopen_result,
    }


def run_killed_child_after_terminal_marker(
    root: Path,
    *,
    scope_id: str,
    handoff_id: str,
    lease_token: str,
    now: int,
    kill_at: str = "after_terminal_marker",
) -> dict[str, Any]:
    """Kill an isolated child at one explicit S25D durability boundary."""

    script = """
import os
import signal
import sys
from modules.w5_dispatch_bridge_s0.prime_queue_writer import PrimeQueueWriter
from modules.w5_dispatch_bridge_s0.recovery_executor import RecoveryExecutor

root, scope_id, handoff_id, lease_token, kill_at, now = sys.argv[1:]

class KillAfterMarker(RecoveryExecutor):
    def _fault(self, point):
        if point == kill_at:
            os.kill(os.getpid(), signal.SIGKILL)
        return super()._fault(point)

writer = PrimeQueueWriter(root, clock=lambda: int(now))
KillAfterMarker(writer).resolve(
    scope_id=scope_id,
    handoff_id=handoff_id,
    lease_token=lease_token,
    now=int(now),
)
"""
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(root),
                scope_id,
                handoff_id,
                lease_token,
                kill_at,
                str(now),
            ],
            cwd=str(Path(__file__).resolve().parents[2]),
            capture_output=True,
            text=True,
            check=False,
            timeout=15.0,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": RECOVERY_REQUIRED,
            "reason": "CHILD_PROCESS_TIMEOUT",
            "returncode": None,
            "signal": None,
            "stderr": str(exc),
        }
    return {
        "status": CASE_CRASHED if completed.returncode == -signal.SIGKILL else RECOVERY_REQUIRED,
        "returncode": completed.returncode,
        "signal": -completed.returncode if completed.returncode < 0 else None,
        "stderr": completed.stderr[-4000:],
    }


__all__ = [
    "BOUNDARY_CASE_RECORDED",
    "CASE_CRASHED",
    "CLAIMED",
    "HARNESS_SCHEMA",
    "HOLD",
    "NOT_CLAIMED",
    "RECOVERY_REQUIRED",
    "reopen_read_only",
    "observe_read_only_boundary",
    "run_boundary_case",
    "run_killed_child_after_terminal_marker",
    "snapshot_writer_store",
]
