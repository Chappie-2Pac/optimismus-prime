"""W5-S23 isolated local Prime-Queue writer.

This adapter is deliberately narrower than the existing MCP write path.  It
owns only ``Plan/local-ai/QUEUE.json`` and a separate local SQLite journal.
Every operation has an explicit queue-local owner/fence/lease, a durable
Prepare record, an idempotency key and a committed marker bound to the
existing task-engine transaction.  It never writes receipts, Prime Ledger,
Control Plane, Knowledge Ledger or any other projection.

The fence is local to this adapter.  It is not silently treated as the
runtime-guard lease and it does not protect legacy callers of ``prime_writes``
that bypass this adapter.
"""

from __future__ import annotations

from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Callable, Iterator, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json

from mcp import prime_writes


QUEUE_WRITER_SCHEMA = "prime-queue-writer-v1"
QUEUE_WRITER_ROLE = "prime_queue_single_store_writer"
QUEUE_WRITER_OPERATION = "QUEUE_TRANSITION"
QUEUE_WRITER_SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "003_prime_queue_writer_v1.sql"
QUEUE_WRITER_SCHEMA_FINGERPRINT = hashlib.sha256(QUEUE_WRITER_SCHEMA_PATH.read_bytes()).hexdigest()
QUEUE_WRITER_COMMANDS = frozenset({"start", "ready", "block", "accept", "release"})
QUEUE_WRITER_STATES = frozenset({"PREPARED", "COMMITTED", "ABORTED", "IN_DOUBT", "RECOVERY_REQUIRED", "QUARANTINED"})
QUEUE_WRITER_CLEAN = "CLEAN"
QUEUE_WRITER_IN_DOUBT = "IN_DOUBT"
QUEUE_WRITER_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
QUEUE_WRITER_QUARANTINED = "QUARANTINED"
QUEUE_WRITER_FAULT_POINTS = frozenset({"after_prepare", "after_queue_commit"})
QUEUE_MUTATION_TRUE = "TRUE"
QUEUE_MUTATION_FALSE = "FALSE"
QUEUE_MUTATION_UNKNOWN = "UNKNOWN"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_CARD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_ACTORS = frozenset({"codex", "local-ai", "shared"})
_TABLES = frozenset(
    {
        "prime_queue_writer_meta",
        "prime_queue_writer_roots",
        "prime_queue_writer_scopes",
        "prime_queue_writer_operations",
        "prime_queue_writer_events",
        "prime_queue_writer_markers",
        "prime_queue_writer_handoff_events",
    }
)
_LEGACY_TABLES = _TABLES - {"prime_queue_writer_handoff_events"}
_REQUIRED_INDEXES = frozenset(
    {
        "idx_prime_queue_writer_events_operation",
        "idx_prime_queue_writer_handoff_events_scope",
    }
)
_REQUIRED_TRIGGERS = frozenset(
    {
        "prime_queue_writer_markers_immutable_update",
        "prime_queue_writer_markers_immutable_delete",
        "prime_queue_writer_events_immutable_update",
        "prime_queue_writer_events_immutable_delete",
        "prime_queue_writer_handoff_events_immutable_update",
        "prime_queue_writer_handoff_events_immutable_delete",
    }
)


class PrimeQueueWriterError(ValueError):
    """Invalid input, stale fence, or detected queue-writer integrity failure."""


class InjectedPrimeQueueWriterCrash(RuntimeError):
    """Deterministic test-only crash at a local queue-writer boundary."""

    def __init__(self, point: str) -> None:
        self.point = point
        super().__init__(point)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise PrimeQueueWriterError(f"{label}_INVALID")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise PrimeQueueWriterError(f"{label}_INVALID")
    return value


def _card_id(value: Any) -> str:
    value = _text(value, "card_id")
    if _CARD_ID.fullmatch(value) is None:
        raise PrimeQueueWriterError("CARD_ID_INVALID")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise PrimeQueueWriterError(f"{label}_INVALID")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PrimeQueueWriterError(f"{label}_INVALID")
    return value


def _copy_json(value: Any, label: str) -> Any:
    try:
        isolated = copy.deepcopy(value)
        canonical_json(isolated)
        return isolated
    except (TypeError, ValueError, copy.Error) as exc:
        raise PrimeQueueWriterError(f"{label}_NOT_CANONICAL") from exc


def _lease_hash(value: str) -> str:
    if len(value) < 16:
        raise PrimeQueueWriterError("LEASE_TOKEN_TOO_SHORT")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class PrimeQueueWriter:
    """One explicitly fenced writer for the local Prime queue only."""

    def __init__(
        self,
        root: str | Path,
        *,
        db_path: str | Path | None = None,
        clock: Callable[[], int] | None = None,
        fault_points: set[str] | frozenset[str] | None = None,
    ) -> None:
        raw_root = Path(root)
        if not raw_root.is_absolute():
            raise PrimeQueueWriterError("ROOT_MUST_BE_ABSOLUTE")
        if raw_root.is_symlink():
            raise PrimeQueueWriterError("ROOT_MUST_NOT_BE_SYMLINK")
        self.root = raw_root.resolve(strict=True)
        if not self.root.is_dir():
            raise PrimeQueueWriterError("ROOT_MUST_BE_DIRECTORY")
        self.queue_path = self.root / "Plan" / "local-ai" / "QUEUE.json"
        self._assert_queue_path()
        control = self.root / "Plan" / "local-ai" / "control"
        self._assert_directory_chain(control, "CONTROL_PATH")
        control.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not control.is_dir():
            raise PrimeQueueWriterError("CONTROL_PATH_MUST_BE_DIRECTORY")
        self.db_path = Path(db_path) if db_path is not None else control / "prime_queue_writer.sqlite3"
        if not self.db_path.is_absolute():
            raise PrimeQueueWriterError("DB_PATH_MUST_BE_ABSOLUTE")
        if self.db_path.parent.resolve(strict=False) != control.resolve(strict=False):
            raise PrimeQueueWriterError("DB_PATH_OUTSIDE_CONTROL_PATH")
        if self.db_path.exists() and self.db_path.is_symlink():
            raise PrimeQueueWriterError("DB_PATH_MUST_NOT_BE_SYMLINK")
        if self.db_path.exists() and self.db_path.stat().st_nlink != 1:
            raise PrimeQueueWriterError("DB_PATH_MUST_NOT_BE_HARDLINK")
        if clock is not None and not callable(clock):
            raise PrimeQueueWriterError("CLOCK_INVALID")
        self.clock = clock or (lambda: int(time.time()))
        self.fault_points = set(fault_points or ())
        if not self.fault_points.issubset(QUEUE_WRITER_FAULT_POINTS):
            raise PrimeQueueWriterError("FAULT_POINT_INVALID")
        preexisting = self.db_path.exists()
        self.conn = sqlite3.connect(str(self.db_path), isolation_level=None, timeout=5.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        try:
            if preexisting:
                journal_mode = str(self.conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
                synchronous = int(self.conn.execute("PRAGMA synchronous").fetchone()[0])
                integrity = str(self.conn.execute("PRAGMA integrity_check").fetchone()[0]).lower()
                if journal_mode != "wal" or synchronous != 2:
                    raise PrimeQueueWriterError("DB_DURABILITY_SETTINGS_INVALID")
                if integrity != "ok":
                    raise PrimeQueueWriterError("DB_INTEGRITY_CHECK_FAILED")
            tables = {row[0] for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'" if self.db_path.exists() else "SELECT 1").fetchall()}
            identity = self._root_binding()
            if tables:
                if tables == _LEGACY_TABLES:
                    # S25B adds its handoff namespace to the same durable
                    # SQLite store.  Migrate only the exact known S24 shape;
                    # every other schema remains fail-closed.
                    self.conn.executescript(QUEUE_WRITER_SCHEMA_PATH.read_text(encoding="utf-8"))
                    self.conn.execute(
                        "UPDATE prime_queue_writer_meta SET value=? WHERE key='schema_fingerprint'",
                        (QUEUE_WRITER_SCHEMA_FINGERPRINT,),
                    )
                    tables = {
                        row[0]
                        for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                    }
                if tables != _TABLES:
                    raise PrimeQueueWriterError("DB_SCHEMA_TABLES_INVALID")
                indexes = {
                    row[0]
                    for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'")
                }
                triggers = {row[0] for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
                if not _REQUIRED_INDEXES.issubset(indexes) or not _REQUIRED_TRIGGERS.issubset(triggers):
                    raise PrimeQueueWriterError("DB_SCHEMA_OBJECTS_INVALID")
                metadata = dict(self.conn.execute("SELECT key,value FROM prime_queue_writer_meta").fetchall())
                expected = {
                    "schema_version": QUEUE_WRITER_SCHEMA,
                    "canonicalization": "json-sortkeys-v1",
                    "root_binding_sha256": identity,
                    "schema_fingerprint": QUEUE_WRITER_SCHEMA_FINGERPRINT,
                }
                if any(metadata.get(key) != value for key, value in expected.items()):
                    raise PrimeQueueWriterError("DB_SCHEMA_IDENTITY_INVALID")
            else:
                if preexisting:
                    raise PrimeQueueWriterError("DB_PREEXISTING_EMPTY")
                self.conn.execute("PRAGMA journal_mode = WAL")
                self.conn.execute("PRAGMA synchronous = FULL")
                self.conn.executescript(QUEUE_WRITER_SCHEMA_PATH.read_text(encoding="utf-8"))
                self.conn.executemany(
                    "INSERT INTO prime_queue_writer_meta(key,value) VALUES (?,?)",
                    [
                        ("schema_version", QUEUE_WRITER_SCHEMA),
                        ("canonicalization", "json-sortkeys-v1"),
                        ("root_binding_sha256", identity),
                        ("schema_fingerprint", QUEUE_WRITER_SCHEMA_FINGERPRINT),
                    ],
                )
                self.conn.execute("PRAGMA journal_mode = WAL")
                self.conn.execute("PRAGMA synchronous = FULL")
        except BaseException:
            self.conn.close()
            raise

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "PrimeQueueWriter":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _now(self) -> int:
        return _integer(self.clock(), "clock")

    def _root_binding(self) -> str:
        return canonical_hash({"schema": QUEUE_WRITER_SCHEMA, "root": str(self.root)})

    def _assert_queue_path(self) -> None:
        self._assert_directory_chain(self.queue_path.parent, "QUEUE_PARENT")
        if self.queue_path.is_symlink() or not self.queue_path.is_file():
            raise PrimeQueueWriterError("QUEUE_PATH_INVALID")

    def _assert_directory_chain(self, path: Path, label: str) -> None:
        try:
            relative = path.relative_to(self.root)
        except ValueError as exc:
            raise PrimeQueueWriterError(f"{label}_OUTSIDE_ROOT") from exc
        cursor = self.root
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise PrimeQueueWriterError(f"{label}_SYMLINK")
            if cursor.exists() and not cursor.is_dir():
                raise PrimeQueueWriterError(f"{label}_MUST_BE_DIRECTORY")

    def _queue_hash(self) -> str:
        self._assert_queue_path()
        return hashlib.sha256(self.queue_path.read_bytes()).hexdigest()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        self.conn.execute("BEGIN IMMEDIATE")
        cursor = self.conn.cursor()
        try:
            yield cursor
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        finally:
            cursor.close()

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Cursor]:
        """Read scope, event chain and operation from one SQLite snapshot."""

        self.conn.execute("BEGIN")
        cursor = self.conn.cursor()
        try:
            yield cursor
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        finally:
            cursor.close()

    def _scope_row(self, cursor: sqlite3.Cursor, scope_id: str) -> sqlite3.Row:
        row = cursor.execute("SELECT * FROM prime_queue_writer_scopes WHERE scope_id=?", (scope_id,)).fetchone()
        if row is None:
            raise PrimeQueueWriterError("SCOPE_NOT_FOUND")
        return row

    def _assert_event_chain(self, cursor: sqlite3.Cursor, scope: Mapping[str, Any]) -> list[sqlite3.Row]:
        events = cursor.execute(
            "SELECT * FROM prime_queue_writer_events WHERE scope_id=? ORDER BY event_seq",
            (scope["scope_id"],),
        ).fetchall()
        if len(events) != int(scope["event_seq"]):
            raise PrimeQueueWriterError("EVENT_CHAIN_LENGTH_DRIFT")
        parent: str | None = None
        for expected_seq, event in enumerate(events, 1):
            if int(event["event_seq"]) != expected_seq or event["parent_event_sha256"] != parent:
                raise PrimeQueueWriterError("EVENT_CHAIN_SEQUENCE_DRIFT")
            payload = json.loads(event["payload_json"])
            expected_hash = canonical_hash(
                {
                    "scope_id": event["scope_id"],
                    "event_seq": expected_seq,
                    "idempotency_key": event["idempotency_key"],
                    "event_type": event["event_type"],
                    "parent_event_sha256": parent,
                    "payload": payload,
                    "fencing_epoch": int(event["fencing_epoch"]),
                    "created_at": int(event["created_at"]),
                }
            )
            if expected_hash != event["event_sha256"]:
                raise PrimeQueueWriterError("EVENT_CHAIN_DIGEST_DRIFT")
            parent = event["event_sha256"]
        return events

    def _assert_handoff_event_chain(
        self,
        cursor: sqlite3.Cursor,
        scope: Mapping[str, Any],
        expected_metadata: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate the separate immutable handoff chain and return its head."""

        events = cursor.execute(
            "SELECT * FROM prime_queue_writer_handoff_events WHERE scope_id=? ORDER BY handoff_seq",
            (scope["scope_id"],),
        ).fetchall()
        parent: str | None = None
        current = dict(expected_metadata)
        for expected_seq, event in enumerate(events, 1):
            if int(event["handoff_seq"]) != expected_seq or event["parent_event_sha256"] != parent:
                raise PrimeQueueWriterError("HANDOFF_EVENT_CHAIN_SEQUENCE_DRIFT")
            if event["event_type"] != "HANDOFF_ACCEPTED_RECOVERY":
                raise PrimeQueueWriterError("HANDOFF_EVENT_TYPE_INVALID")
            try:
                payload = json.loads(event["payload_json"])
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PrimeQueueWriterError("HANDOFF_EVENT_PAYLOAD_INVALID") from exc
            if not isinstance(payload, Mapping):
                raise PrimeQueueWriterError("HANDOFF_EVENT_PAYLOAD_INVALID")
            expected_hash = canonical_hash(
                {
                    "scope_id": event["scope_id"],
                    "handoff_seq": expected_seq,
                    "handoff_id": event["handoff_id"],
                    "event_type": event["event_type"],
                    "parent_event_sha256": parent,
                    "payload": payload,
                    "created_at": int(event["created_at"]),
                }
            )
            if expected_hash != event["event_sha256"]:
                raise PrimeQueueWriterError("HANDOFF_EVENT_DIGEST_DRIFT")
            target = payload.get("target")
            if not isinstance(target, Mapping) or target.get("active_phase") != "RECOVERY":
                raise PrimeQueueWriterError("HANDOFF_EVENT_TARGET_INVALID")
            target_keys = (
                "root_binding_sha256",
                "owner_id",
                "owner_instance_id",
                "owner_epoch",
                "fencing_epoch",
                "lease_token_sha256",
                "lease_expires_at",
            )
            if any(key not in target for key in target_keys):
                raise PrimeQueueWriterError("HANDOFF_EVENT_TARGET_INVALID")
            if target["root_binding_sha256"] != scope["root_binding_sha256"]:
                raise PrimeQueueWriterError("HANDOFF_EVENT_ROOT_DRIFT")
            if (
                event["handoff_id"] != payload.get("handoff_id")
                or event["root_binding_sha256"] != scope["root_binding_sha256"]
                or event["new_owner_id"] != target["owner_id"]
                or event["new_owner_instance_id"] != target["owner_instance_id"]
                or int(event["new_owner_epoch"]) != int(target["owner_epoch"])
                or int(event["new_fencing_epoch"]) != int(target["fencing_epoch"])
                or event["new_lease_token_sha256"] != target["lease_token_sha256"]
                or int(event["new_lease_expires_at"]) != int(target["lease_expires_at"])
            ):
                raise PrimeQueueWriterError("HANDOFF_EVENT_BINDING_DRIFT")
            if int(event["new_fencing_epoch"]) != int(event["old_fencing_epoch"]) + 1:
                raise PrimeQueueWriterError("HANDOFF_EVENT_FENCE_DRIFT")
            if int(event["new_owner_epoch"]) <= int(event["old_owner_epoch"]):
                raise PrimeQueueWriterError("HANDOFF_EVENT_OWNER_EPOCH_DRIFT")
            if {
                "root_binding_sha256": event["root_binding_sha256"],
                "owner_id": event["old_owner_id"],
                "owner_instance_id": event["old_owner_instance_id"],
                "owner_epoch": int(event["old_owner_epoch"]),
                "fencing_epoch": int(event["old_fencing_epoch"]),
                "lease_token_sha256": event["old_lease_token_sha256"],
                "lease_expires_at": int(event["old_lease_expires_at"]),
            } != current:
                raise PrimeQueueWriterError("HANDOFF_EVENT_SOURCE_DRIFT")
            current = {
                "root_binding_sha256": target["root_binding_sha256"],
                "owner_id": target["owner_id"],
                "owner_instance_id": target["owner_instance_id"],
                "owner_epoch": int(target["owner_epoch"]),
                "fencing_epoch": int(target["fencing_epoch"]),
                "lease_token_sha256": target["lease_token_sha256"],
                "lease_expires_at": int(target["lease_expires_at"]),
            }
            parent = event["event_sha256"]
        return current

    def _assert_scope_integrity(self, cursor: sqlite3.Cursor, scope: Mapping[str, Any]) -> None:
        if scope["root_binding_sha256"] != self._root_binding():
            raise PrimeQueueWriterError("SCOPE_ROOT_BINDING_DRIFT")
        events = self._assert_event_chain(cursor, scope)
        if not events or events[0]["event_type"] != "SCOPE_CREATED":
            raise PrimeQueueWriterError("SCOPE_CREATION_EVENT_MISSING")
        created = json.loads(events[0]["payload_json"])
        if not isinstance(created, Mapping):
            raise PrimeQueueWriterError("SCOPE_METADATA_INVALID")
        metadata_keys = (
            "root_binding_sha256",
            "owner_id",
            "owner_instance_id",
            "owner_epoch",
            "fencing_epoch",
            "lease_token_sha256",
            "lease_expires_at",
        )
        if any(key not in created for key in metadata_keys):
            raise PrimeQueueWriterError("SCOPE_METADATA_INVALID")
        expected_metadata = {key: created[key] for key in metadata_keys}
        expected_metadata["owner_epoch"] = int(expected_metadata["owner_epoch"])
        expected_metadata["fencing_epoch"] = int(expected_metadata["fencing_epoch"])
        expected_metadata["lease_expires_at"] = int(expected_metadata["lease_expires_at"])
        if expected_metadata["root_binding_sha256"] != scope["root_binding_sha256"]:
            raise PrimeQueueWriterError("SCOPE_METADATA_DRIFT")
        expected_metadata = self._assert_handoff_event_chain(cursor, scope, expected_metadata)
        expected_status = QUEUE_WRITER_CLEAN
        status_by_event = {
            "QUEUE_PREPARED": QUEUE_WRITER_IN_DOUBT,
            "QUEUE_COMMITTED": QUEUE_WRITER_CLEAN,
            "QUEUE_ABORTED": QUEUE_WRITER_CLEAN,
            "QUEUE_IN_DOUBT": QUEUE_WRITER_IN_DOUBT,
            "QUEUE_RECOVERY_REQUIRED": QUEUE_WRITER_RECOVERY_REQUIRED,
            "QUEUE_QUARANTINED": QUEUE_WRITER_QUARANTINED,
        }
        for event in events[1:]:
            if event["event_type"] not in status_by_event:
                raise PrimeQueueWriterError("EVENT_TYPE_INVALID")
            expected_status = status_by_event[event["event_type"]]
        current_metadata = {
            "root_binding_sha256": scope["root_binding_sha256"],
            "owner_id": scope["owner_id"],
            "owner_instance_id": scope["owner_instance_id"],
            "owner_epoch": int(scope["owner_epoch"]),
            "fencing_epoch": int(scope["fencing_epoch"]),
            "lease_token_sha256": scope["lease_token_sha256"],
            "lease_expires_at": int(scope["lease_expires_at"]),
        }
        if current_metadata != expected_metadata:
            raise PrimeQueueWriterError("SCOPE_METADATA_DRIFT")
        if scope["scope_status"] != expected_status:
            raise PrimeQueueWriterError("SCOPE_STATUS_DRIFT")
        active_operation_id = scope["active_operation_id"]
        active_phase = scope["active_phase"]
        active_states = ("PREPARED", "IN_DOUBT", "RECOVERY_REQUIRED")
        if (active_operation_id is None) != (active_phase == "IDLE"):
            raise PrimeQueueWriterError("ACTIVE_OPERATION_PHASE_DRIFT")
        if active_operation_id is None:
            if scope["scope_status"] not in {QUEUE_WRITER_CLEAN, QUEUE_WRITER_QUARANTINED}:
                raise PrimeQueueWriterError("ACTIVE_OPERATION_MISSING")
            orphan = cursor.execute(
                "SELECT 1 FROM prime_queue_writer_operations WHERE scope_id=? AND state IN (?,?,?) LIMIT 1",
                (scope["scope_id"], *active_states),
            ).fetchone()
            if orphan is not None:
                raise PrimeQueueWriterError("ACTIVE_OPERATION_ORPHANED")
        else:
            active_operations = cursor.execute(
                "SELECT transaction_id,state FROM prime_queue_writer_operations WHERE scope_id=? AND state IN (?,?,?)",
                (scope["scope_id"], *active_states),
            ).fetchall()
            if len(active_operations) != 1 or active_operations[0]["transaction_id"] != active_operation_id:
                raise PrimeQueueWriterError("ACTIVE_OPERATION_MISSING")
        root = cursor.execute(
            "SELECT * FROM prime_queue_writer_roots WHERE root_binding_sha256=?",
            (scope["root_binding_sha256"],),
        ).fetchone()
        if root is None:
            raise PrimeQueueWriterError("ROOT_SCOPE_RECORD_MISSING")
        if (
            root["active_scope_id"] != scope["scope_id"]
            or int(root["active_fencing_epoch"]) != int(scope["fencing_epoch"])
        ):
            raise PrimeQueueWriterError("ROOT_SCOPE_RECORD_DRIFT")

    def _append_event(
        self,
        cursor: sqlite3.Cursor,
        *,
        scope_id: str,
        idempotency_key: str | None,
        event_type: str,
        payload: Mapping[str, Any],
        fencing_epoch: int,
        created_at: int,
    ) -> None:
        scope = self._scope_row(cursor, scope_id)
        event_seq = int(scope["event_seq"]) + 1
        parent = cursor.execute(
            "SELECT event_sha256 FROM prime_queue_writer_events WHERE scope_id=? ORDER BY event_seq DESC LIMIT 1",
            (scope_id,),
        ).fetchone()
        parent_hash = parent[0] if parent else None
        event_payload = _copy_json(dict(payload), "event_payload")
        event_hash = canonical_hash(
            {
                "scope_id": scope_id,
                "event_seq": event_seq,
                "idempotency_key": idempotency_key,
                "event_type": event_type,
                "parent_event_sha256": parent_hash,
                "payload": event_payload,
                "fencing_epoch": fencing_epoch,
                "created_at": created_at,
            }
        )
        cursor.execute(
            "INSERT INTO prime_queue_writer_events(scope_id,event_seq,idempotency_key,event_type,parent_event_sha256,event_sha256,payload_json,fencing_epoch,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (scope_id, event_seq, idempotency_key, event_type, parent_hash, event_hash, canonical_json(event_payload), fencing_epoch, created_at),
        )
        cursor.execute(
            "UPDATE prime_queue_writer_scopes SET event_seq=?,updated_at=? WHERE scope_id=?",
            (event_seq, created_at, scope_id),
        )

    def _validate_owner(self, owner_id: Any, owner_instance_id: Any, owner_epoch: Any, fencing_epoch: Any) -> tuple[str, str, int, int]:
        return (
            _safe_id(owner_id, "owner_id"),
            _safe_id(owner_instance_id, "owner_instance_id"),
            _integer(owner_epoch, "owner_epoch", minimum=1),
            _integer(fencing_epoch, "fencing_epoch", minimum=1),
        )

    def create_scope(
        self,
        *,
        scope_id: str,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        lease_token: str,
        lease_expires_at: int,
    ) -> dict[str, Any]:
        scope_id = _safe_id(scope_id, "scope_id")
        owner_id, owner_instance_id, owner_epoch, fencing_epoch = self._validate_owner(
            owner_id, owner_instance_id, owner_epoch, fencing_epoch
        )
        lease_token = _text(lease_token, "lease_token")
        lease_expires_at = _integer(lease_expires_at, "lease_expires_at")
        now = self._now()
        with self._transaction() as cursor:
            if cursor.execute("SELECT 1 FROM prime_queue_writer_scopes WHERE scope_id=?", (scope_id,)).fetchone():
                raise PrimeQueueWriterError("SCOPE_ALREADY_EXISTS")
            root_binding = self._root_binding()
            if cursor.execute(
                "SELECT 1 FROM prime_queue_writer_roots WHERE root_binding_sha256=?",
                (root_binding,),
            ).fetchone():
                raise PrimeQueueWriterError("ROOT_SCOPE_ALREADY_EXISTS")
            cursor.execute(
                "INSERT INTO prime_queue_writer_roots(root_binding_sha256,active_scope_id,active_fencing_epoch,updated_at) VALUES (?,?,?,?)",
                (root_binding, scope_id, fencing_epoch, now),
            )
            cursor.execute(
                "INSERT INTO prime_queue_writer_scopes(scope_id,root_binding_sha256,owner_id,owner_instance_id,owner_epoch,fencing_epoch,lease_token_sha256,lease_expires_at,scope_status,active_operation_id,active_phase,event_seq,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    scope_id,
                    root_binding,
                    owner_id,
                    owner_instance_id,
                    owner_epoch,
                    fencing_epoch,
                    _lease_hash(lease_token),
                    lease_expires_at,
                    QUEUE_WRITER_CLEAN,
                    None,
                    "IDLE",
                    0,
                    now,
                ),
            )
            self._append_event(
                cursor,
                scope_id=scope_id,
                idempotency_key=None,
                event_type="SCOPE_CREATED",
                payload={
                    "root_binding_sha256": self._root_binding(),
                    "owner_id": owner_id,
                    "owner_instance_id": owner_instance_id,
                    "owner_epoch": owner_epoch,
                    "fencing_epoch": fencing_epoch,
                    "lease_token_sha256": _lease_hash(lease_token),
                    "lease_expires_at": lease_expires_at,
                },
                fencing_epoch=fencing_epoch,
                created_at=now,
            )
        return self.read_scope(scope_id)

    def read_scope(self, scope_id: str) -> dict[str, Any]:
        scope_id = _safe_id(scope_id, "scope_id")
        with self._read_transaction() as cursor:
            scope = self._scope_row(cursor, scope_id)
            self._assert_scope_integrity(cursor, scope)
            return dict(scope)

    def _assert_fence(
        self,
        scope: Mapping[str, Any],
        *,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        lease_token: str,
        now: int,
        allowed_scope_statuses: frozenset[str] = frozenset({QUEUE_WRITER_CLEAN}),
    ) -> None:
        owner_id, owner_instance_id, owner_epoch, fencing_epoch = self._validate_owner(
            owner_id, owner_instance_id, owner_epoch, fencing_epoch
        )
        if scope["scope_status"] not in allowed_scope_statuses:
            raise PrimeQueueWriterError("SCOPE_NOT_CLEAN")
        if (
            scope["owner_id"] != owner_id
            or scope["owner_instance_id"] != owner_instance_id
            or int(scope["owner_epoch"]) != owner_epoch
            or int(scope["fencing_epoch"]) != fencing_epoch
            or scope["lease_token_sha256"] != _lease_hash(_text(lease_token, "lease_token"))
        ):
            raise PrimeQueueWriterError("FENCE_MISMATCH")
        if int(scope["lease_expires_at"]) <= now:
            raise PrimeQueueWriterError("LEASE_EXPIRED")

    def _fault(self, point: str) -> None:
        if point in self.fault_points:
            raise InjectedPrimeQueueWriterCrash(point)

    def _dry_run(self, *, card_id: str, command: str, expected: str, reason: str, result: str | None, cascade: bool, updated_at: str) -> dict[str, Any]:
        try:
            state = prime_writes._state()
            engine = prime_writes._engine()
            return state.transition(
                self.root,
                engine.engine(),
                command,
                card_id,
                expected,
                reason=reason,
                result=result,
                cascade=cascade,
                actor="Plan",
                dry_run=True,
                updated_at=updated_at,
            )
        except Exception as exc:
            raise PrimeQueueWriterError(f"QUEUE_PREFLIGHT_{type(exc).__name__}") from exc

    def _validate_actor_card(self, *, card_id: str, command: str, expected: str, actor: str) -> None:
        try:
            _engine, _current, _queue, by, checked_card_id, _checked_actor = prime_writes._check_card(
                self.root, card_id, expected, actor
            )
            if command == "start" and by[checked_card_id].get("owner") == "shared":
                raise ValueError("shared cards require an explicit actor handoff before start")
        except Exception as exc:
            raise PrimeQueueWriterError(f"QUEUE_ACTOR_AUTHORIZATION_{type(exc).__name__}") from exc

    def _assert_live_fence(
        self,
        *,
        scope_id: str,
        transaction_id: str,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        lease_token: str,
        required_phase: str = "EXECUTING",
    ) -> None:
        now = self._now()
        with self._read_transaction() as cursor:
            scope = self._scope_row(cursor, scope_id)
            self._assert_scope_integrity(cursor, scope)
            self._assert_fence(
                scope,
                owner_id=owner_id,
                owner_instance_id=owner_instance_id,
                owner_epoch=owner_epoch,
                fencing_epoch=fencing_epoch,
                lease_token=lease_token,
                now=now,
                allowed_scope_statuses=frozenset({QUEUE_WRITER_IN_DOUBT, QUEUE_WRITER_RECOVERY_REQUIRED}),
            )
            if scope["active_operation_id"] != transaction_id or scope["active_phase"] != required_phase:
                raise PrimeQueueWriterError("OPERATION_CLAIM_LOST")

    def _operation_intent(
        self,
        *,
        scope_id: str,
        transaction_id: str,
        idempotency_key: str,
        card_id: str,
        command: str,
        actor: str,
        reason: str,
        result: str | None,
        cascade: bool,
        before_queue_sha256: str,
        after_queue_sha256: str,
        fencing_epoch: int,
    ) -> dict[str, Any]:
        return {
            "schema_version": QUEUE_WRITER_SCHEMA,
            "operation": QUEUE_WRITER_OPERATION,
            "scope_id": scope_id,
            "transaction_id": transaction_id,
            "idempotency_key": idempotency_key,
            "card_id": card_id,
            "command": command,
            "actor": actor,
            "reason": reason,
            "result": result,
            "cascade": cascade,
            "before_queue_sha256": before_queue_sha256,
            "after_queue_sha256": after_queue_sha256,
            "fencing_epoch": fencing_epoch,
        }

    def _output(self, row: Mapping[str, Any], *, status: str | None = None, reason: str | None = None, result: Mapping[str, Any] | None = None) -> dict[str, Any]:
        state = str(row["state"])
        actual = status or ({"COMMITTED": "QUEUE_COMMITTED", "ABORTED": "QUEUE_ABORTED"}.get(state, state))
        # A replay reports the historical operation but must not claim that
        # this invocation performed a second queue mutation.
        evidence = row["queue_mutation_evidence"]
        historical_mutation: bool | None = {
            QUEUE_MUTATION_TRUE: True,
            QUEUE_MUTATION_FALSE: False,
            QUEUE_MUTATION_UNKNOWN: None,
        }[evidence]
        queue_mutated: bool | None = False if actual == "REPLAYED" else historical_mutation
        return {
            "schema_version": QUEUE_WRITER_SCHEMA,
            "contract_role": QUEUE_WRITER_ROLE,
            "status": actual,
            "decision": "QUEUE_ONLY_COMMITTED" if actual in {"QUEUE_COMMITTED", "REPLAYED"} else "HOLD",
            "reason": reason or ("QUEUE_OPERATION_REPLAY" if actual == "REPLAYED" else f"QUEUE_WRITER_{state}"),
            "permission": "queue_writer_local" if actual in {"QUEUE_COMMITTED", "REPLAYED"} else "read_only",
            "scope_id": row["scope_id"],
            "transaction_id": row["transaction_id"],
            "idempotency_key": row["idempotency_key"],
            "card_id": row["card_id"],
            "command": row["command"],
            "actor": row["actor"],
            "intent_sha256": row["intent_sha256"],
            "before_queue_sha256": row["expected_queue_sha256"],
            "after_queue_sha256": row["after_queue_sha256"],
            "queue_mutation_performed": queue_mutated,
            "queue_mutation_evidence": evidence,
            "queue_committed": state == "COMMITTED",
            "authoritative_queue_decision": state == "COMMITTED",
            "mutation_allowed": actual in {"QUEUE_COMMITTED", "REPLAYED"},
            "mutation_performed": queue_mutated,
            "external_mutation_performed": queue_mutated,
            "receipt_emitted": False,
            "receipt_committed": False,
            "consume_allowed": False,
            "cross_store_atomicity": "NOT_CLAIMED",
            "recovery_started": False,
            "resume_allowed": False,
            "global_commit": False,
            "result": _copy_json(result, "result") if result is not None else None,
            "execution": {
                "queue": queue_mutated,
                "queue_journal": True,
                "receipt": False,
                "prime_ledger": False,
                "control_plane": False,
                "knowledge_ledger": False,
                "receipt_projection": False,
                "consume": False,
                "network": False,
            },
        }

    def _wait_for_existing_resolution(self, scope_id: str, idempotency_key: str) -> sqlite3.Row:
        """Allow a concurrent identical caller to observe the first commit."""

        deadline = time.monotonic() + 1.0
        row = self._read_operation_row(scope_id, idempotency_key)
        while row["state"] == "PREPARED" and time.monotonic() < deadline:
            time.sleep(0.01)
            row = self._read_operation_row(scope_id, idempotency_key)
        return row

    @staticmethod
    def _request_matches_intent(intent: Mapping[str, Any], request: Mapping[str, Any]) -> bool:
        """Compare the caller's logical request, not a regenerated after hash."""

        return all(intent.get(key) == value for key, value in request.items())

    @staticmethod
    def _hold(
        reason: str,
        *,
        status: str = "HOLD",
        queue_mutation_evidence: str = QUEUE_MUTATION_FALSE,
    ) -> dict[str, Any]:
        if queue_mutation_evidence not in {QUEUE_MUTATION_TRUE, QUEUE_MUTATION_FALSE, QUEUE_MUTATION_UNKNOWN}:
            raise PrimeQueueWriterError("QUEUE_MUTATION_EVIDENCE_INVALID")
        return {
            "schema_version": QUEUE_WRITER_SCHEMA,
            "contract_role": QUEUE_WRITER_ROLE,
            "status": status,
            "decision": "HOLD",
            "reason": reason,
            "permission": "read_only",
            "queue_mutation_performed": (
                True
                if queue_mutation_evidence == QUEUE_MUTATION_TRUE
                else None
                if queue_mutation_evidence == QUEUE_MUTATION_UNKNOWN
                else False
            ),
            "queue_mutation_evidence": queue_mutation_evidence,
            "receipt_emitted": False,
            "receipt_committed": False,
            "consume_allowed": False,
            "cross_store_atomicity": "NOT_CLAIMED",
        }

    def _existing_for_request(
        self,
        *,
        scope_id: str,
        transaction_id: str,
        idempotency_key: str,
        card_id: str,
        command: str,
        actor: str,
        before_queue_sha256: str,
        reason: str,
        result: str | None,
        cascade: bool,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        lease_token: str,
    ) -> dict[str, Any] | None:
        """Return a terminal/recovery result before applying a stale-hash check.

        A lost response must be replayable with the original pre-CAS hash.  The
        fence is still checked, and a reused key with a different logical
        request is rejected rather than being mistaken for a replay.
        """

        now = self._now()
        with self._read_transaction() as cursor:
            scope = self._scope_row(cursor, scope_id)
            self._assert_scope_integrity(cursor, scope)
            rows = cursor.execute(
                "SELECT * FROM prime_queue_writer_operations WHERE scope_id=? AND (idempotency_key=? OR transaction_id=?)",
                (scope_id, idempotency_key, transaction_id),
            ).fetchall()
            if not rows:
                self._assert_fence(
                    scope,
                    owner_id=owner_id,
                    owner_instance_id=owner_instance_id,
                    owner_epoch=owner_epoch,
                    fencing_epoch=fencing_epoch,
                    lease_token=lease_token,
                    now=now,
                )
                return None
            if len({(row["idempotency_key"], row["transaction_id"]) for row in rows}) != 1:
                return self._hold("QUEUE_WRITER_KEY_CONFLICT")
            self._assert_fence(
                scope,
                owner_id=owner_id,
                owner_instance_id=owner_instance_id,
                owner_epoch=owner_epoch,
                fencing_epoch=fencing_epoch,
                lease_token=lease_token,
                now=now,
                allowed_scope_statuses=frozenset(
                    {
                        QUEUE_WRITER_CLEAN,
                        QUEUE_WRITER_IN_DOUBT,
                        QUEUE_WRITER_RECOVERY_REQUIRED,
                    }
                ),
            )
            row = rows[0]
            intent = json.loads(row["operation_json"])
            request = {
                "scope_id": scope_id,
                "transaction_id": transaction_id,
                "idempotency_key": idempotency_key,
                "card_id": card_id,
                "command": command,
                "actor": actor,
                "reason": reason,
                "result": result,
                "cascade": bool(cascade),
                "before_queue_sha256": before_queue_sha256,
            }
            if row["idempotency_key"] != idempotency_key or not self._request_matches_intent(intent, request):
                return self._hold("QUEUE_WRITER_INTENT_CONFLICT")
            if row["state"] == "PREPARED":
                return {
                    "__wait_for_resolution__": True,
                    "scope_id": scope_id,
                    "idempotency_key": idempotency_key,
                }
            if row["state"] == "COMMITTED":
                return self._output(row, status="REPLAYED")
            if row["state"] == "ABORTED":
                return self._output(row)
            return self._output(row, status="RECOVERY_REQUIRED", reason="QUEUE_WRITER_OPERATION_NOT_RESUMABLE")

    def _insert_prepared(self, *, scope_id: str, intent: Mapping[str, Any], owner_id: str, owner_instance_id: str, owner_epoch: int, fencing_epoch: int, lease_token: str, now: int) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        intent_json = canonical_json(intent)
        intent_hash = canonical_hash(intent)
        with self._transaction() as cursor:
            scope = self._scope_row(cursor, scope_id)
            self._assert_scope_integrity(cursor, scope)
            existing = cursor.execute(
                "SELECT * FROM prime_queue_writer_operations WHERE scope_id=? AND (idempotency_key=? OR transaction_id=?)",
                (scope_id, intent["idempotency_key"], intent["transaction_id"]),
            ).fetchall()
            if existing:
                self._assert_fence(
                    scope,
                    owner_id=owner_id,
                    owner_instance_id=owner_instance_id,
                    owner_epoch=owner_epoch,
                    fencing_epoch=fencing_epoch,
                    lease_token=lease_token,
                    now=now,
                    allowed_scope_statuses=frozenset(
                        {
                            QUEUE_WRITER_CLEAN,
                            QUEUE_WRITER_IN_DOUBT,
                            QUEUE_WRITER_RECOVERY_REQUIRED,
                        }
                    ),
                )
                if len({row["idempotency_key"] for row in existing}) != 1:
                    return {"status": "CONFLICT", "reason": "QUEUE_WRITER_KEY_CONFLICT"}, {}
                row = existing[0]
                existing_intent = json.loads(row["operation_json"])
                compatible = self._request_matches_intent(
                    existing_intent,
                    {key: intent[key] for key in ("scope_id", "transaction_id", "idempotency_key", "card_id", "command", "actor", "reason", "result", "cascade", "before_queue_sha256")},
                )
                if row["idempotency_key"] != intent["idempotency_key"] or not compatible:
                    return {"status": "CONFLICT", "reason": "QUEUE_WRITER_INTENT_CONFLICT"}, {}
                if row["state"] == "COMMITTED":
                    return self._output(row, status="REPLAYED"), {}
                if row["state"] == "PREPARED":
                    # Do not wait while holding BEGIN IMMEDIATE: the first
                    # writer needs the journal connection to record COMMITTED.
                    return {
                        "__wait_for_resolution__": True,
                        "scope_id": scope_id,
                        "idempotency_key": intent["idempotency_key"],
                    }, {}
                return self._output(row, status="RECOVERY_REQUIRED", reason="QUEUE_WRITER_OPERATION_NOT_RESUMABLE"), {}
            self._assert_fence(
                scope,
                owner_id=owner_id,
                owner_instance_id=owner_instance_id,
                owner_epoch=owner_epoch,
                fencing_epoch=fencing_epoch,
                lease_token=lease_token,
                now=now,
            )
            cursor.execute(
                "INSERT INTO prime_queue_writer_operations(scope_id,idempotency_key,transaction_id,intent_sha256,card_id,command,actor,expected_queue_sha256,after_queue_sha256,state,queue_mutation_performed,queue_mutation_evidence,operation_json,result_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    scope_id,
                    intent["idempotency_key"],
                    intent["transaction_id"],
                    intent_hash,
                    intent["card_id"],
                    intent["command"],
                    intent["actor"],
                    intent["before_queue_sha256"],
                    intent["after_queue_sha256"],
                    "PREPARED",
                    0,
                    QUEUE_MUTATION_FALSE,
                    intent_json,
                    None,
                    now,
                    now,
                ),
            )
            marker_payload = {"intent_sha256": intent_hash, "state": "PREPARED", "fencing_epoch": fencing_epoch}
            cursor.execute(
                "INSERT INTO prime_queue_writer_markers(scope_id,idempotency_key,marker_kind,marker_hash,payload_json,created_at) VALUES (?,?,?,?,?,?)",
                (scope_id, intent["idempotency_key"], "PREPARED", canonical_hash(marker_payload), canonical_json(marker_payload), now),
            )
            # A prepared queue operation is the one active operation for this
            # local scope.  Block a second mutation until it is resolved.
            cursor.execute(
                "UPDATE prime_queue_writer_scopes SET scope_status=?,active_operation_id=?,active_phase=?,updated_at=? WHERE scope_id=?",
                (QUEUE_WRITER_IN_DOUBT, intent["transaction_id"], "PREPARED", now, scope_id),
            )
            self._append_event(
                cursor,
                scope_id=scope_id,
                idempotency_key=intent["idempotency_key"],
                event_type="QUEUE_PREPARED",
                payload=marker_payload,
                fencing_epoch=fencing_epoch,
                created_at=now,
            )
            return None, {"intent_sha256": intent_hash}

    def _claim_phase(
        self,
        *,
        scope_id: str,
        transaction_id: str,
        phase: str,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        lease_token: str,
        allowed_previous: frozenset[str],
    ) -> None:
        now = self._now()
        with self._transaction() as cursor:
            scope = self._scope_row(cursor, scope_id)
            self._assert_scope_integrity(cursor, scope)
            self._assert_fence(
                scope,
                owner_id=owner_id,
                owner_instance_id=owner_instance_id,
                owner_epoch=owner_epoch,
                fencing_epoch=fencing_epoch,
                lease_token=lease_token,
                now=now,
                allowed_scope_statuses=frozenset(
                    {QUEUE_WRITER_CLEAN, QUEUE_WRITER_IN_DOUBT, QUEUE_WRITER_RECOVERY_REQUIRED}
                ),
            )
            if scope["active_operation_id"] != transaction_id:
                raise PrimeQueueWriterError("OPERATION_CLAIM_LOST")
            if scope["active_phase"] not in allowed_previous:
                raise PrimeQueueWriterError("OPERATION_PHASE_CONFLICT")
            cursor.execute(
                "UPDATE prime_queue_writer_scopes SET active_phase=?,updated_at=? WHERE scope_id=? AND active_operation_id=? AND active_phase=?",
                (phase, now, scope_id, transaction_id, scope["active_phase"]),
            )
            if cursor.rowcount != 1:
                raise PrimeQueueWriterError("OPERATION_CLAIM_LOST")

    def _move_to_recovery_phase(self, *, scope_id: str, transaction_id: str) -> None:
        now = self._now()
        try:
            with self._transaction() as cursor:
                cursor.execute(
                    "UPDATE prime_queue_writer_scopes SET active_phase='RECOVERY',updated_at=? WHERE scope_id=? AND active_operation_id=? AND active_phase IN ('PREPARED','EXECUTING')",
                    (now, scope_id, transaction_id),
                )
        except sqlite3.Error:
            pass

    def _mark_state(
        self,
        *,
        scope_id: str,
        idempotency_key: str,
        state: str,
        reason: str,
        queue_mutation_performed: bool | None,
        queue_mutation_evidence: str | None = None,
        result: Mapping[str, Any] | None = None,
        transaction_id: str | None = None,
        required_active_phase: str | None = None,
        fence: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if state not in QUEUE_WRITER_STATES:
            raise PrimeQueueWriterError("STATE_INVALID")
        now = self._now()
        with self._transaction() as cursor:
            scope = self._scope_row(cursor, scope_id)
            self._assert_scope_integrity(cursor, scope)
            row = cursor.execute(
                "SELECT * FROM prime_queue_writer_operations WHERE scope_id=? AND idempotency_key=?",
                (scope_id, idempotency_key),
            ).fetchone()
            if row is None:
                raise PrimeQueueWriterError("OPERATION_NOT_FOUND")
            if transaction_id is not None and scope["active_operation_id"] != transaction_id:
                raise PrimeQueueWriterError("OPERATION_CLAIM_LOST")
            if required_active_phase is not None and scope["active_phase"] != required_active_phase:
                raise PrimeQueueWriterError("OPERATION_PHASE_CONFLICT")
            if fence is not None:
                self._assert_fence(
                    scope,
                    owner_id=fence["owner_id"],
                    owner_instance_id=fence["owner_instance_id"],
                    owner_epoch=fence["owner_epoch"],
                    fencing_epoch=fence["fencing_epoch"],
                    lease_token=fence["lease_token"],
                    now=now,
                    allowed_scope_statuses=frozenset(
                        {QUEUE_WRITER_CLEAN, QUEUE_WRITER_IN_DOUBT, QUEUE_WRITER_RECOVERY_REQUIRED}
                    ),
                )
            if row["state"] == "COMMITTED" and state != "COMMITTED":
                return self._output(row, status="QUEUE_COMMITTED")
            if state == "QUARANTINED" and row["state"] not in {"PREPARED", "IN_DOUBT", "RECOVERY_REQUIRED"}:
                raise PrimeQueueWriterError("QUARANTINE_STATE_INVALID")
            if row["state"] == state:
                return self._output(row, result=json.loads(row["result_json"]) if row["result_json"] else None)

            current_queue_sha256 = self._queue_hash()
            if state == "COMMITTED":
                if current_queue_sha256 != row["after_queue_sha256"]:
                    state = "IN_DOUBT"
                    reason = "QUEUE_COMMIT_AFTER_DRIFT"
                    queue_mutation_evidence = QUEUE_MUTATION_UNKNOWN
                    queue_mutation_performed = None
                elif not self._matching_committed_transaction(row):
                    state = "IN_DOUBT"
                    reason = "QUEUE_COMMIT_MARKER_UNBOUND"
                    queue_mutation_evidence = QUEUE_MUTATION_UNKNOWN
                    queue_mutation_performed = None
            elif state == "ABORTED":
                if current_queue_sha256 != row["expected_queue_sha256"]:
                    state = "IN_DOUBT"
                    reason = "QUEUE_ABORT_BEFORE_HASH_MISMATCH"
                    queue_mutation_evidence = QUEUE_MUTATION_UNKNOWN
                    queue_mutation_performed = None
                elif not self._matching_aborted_transaction(row):
                    state = "IN_DOUBT"
                    reason = "QUEUE_ABORT_MARKER_UNBOUND"
                    queue_mutation_evidence = QUEUE_MUTATION_UNKNOWN
                    queue_mutation_performed = None
            if queue_mutation_evidence is None:
                queue_mutation_evidence = (
                    QUEUE_MUTATION_TRUE
                    if queue_mutation_performed is True
                    else QUEUE_MUTATION_UNKNOWN
                    if queue_mutation_performed is None
                    else QUEUE_MUTATION_FALSE
                )
            if queue_mutation_evidence not in {
                QUEUE_MUTATION_TRUE,
                QUEUE_MUTATION_FALSE,
                QUEUE_MUTATION_UNKNOWN,
            }:
                raise PrimeQueueWriterError("QUEUE_MUTATION_EVIDENCE_INVALID")
            stored_mutation = int(queue_mutation_evidence == QUEUE_MUTATION_TRUE)
            payload = {
                "intent_sha256": row["intent_sha256"],
                "state": state,
                "reason": reason,
                "queue_sha256": current_queue_sha256,
                "queue_mutation_performed": bool(stored_mutation),
                "queue_mutation_evidence": queue_mutation_evidence,
            }
            if result is not None:
                payload["result"] = _copy_json(result, "result")
            cursor.execute(
                "UPDATE prime_queue_writer_operations SET state=?,queue_mutation_performed=?,queue_mutation_evidence=?,result_json=?,updated_at=? WHERE scope_id=? AND idempotency_key=?",
                (state, stored_mutation, queue_mutation_evidence, canonical_json(payload), now, scope_id, idempotency_key),
            )
            scope_status = {
                "IN_DOUBT": QUEUE_WRITER_IN_DOUBT,
                "RECOVERY_REQUIRED": QUEUE_WRITER_RECOVERY_REQUIRED,
                "QUARANTINED": QUEUE_WRITER_QUARANTINED,
            }.get(state, QUEUE_WRITER_CLEAN)
            if state in {"COMMITTED", "ABORTED", "QUARANTINED"}:
                active_operation_id = None
                active_phase = "IDLE"
            else:
                active_operation_id = row["transaction_id"]
                active_phase = "RECOVERY"
            cursor.execute(
                "UPDATE prime_queue_writer_scopes SET scope_status=?,active_operation_id=?,active_phase=?,updated_at=? WHERE scope_id=?",
                (scope_status, active_operation_id, active_phase, now, scope_id),
            )
            cursor.execute(
                "INSERT INTO prime_queue_writer_markers(scope_id,idempotency_key,marker_kind,marker_hash,payload_json,created_at) VALUES (?,?,?,?,?,?)",
                (scope_id, idempotency_key, state, canonical_hash(payload), canonical_json(payload), now),
            )
            self._append_event(
                cursor,
                scope_id=scope_id,
                idempotency_key=idempotency_key,
                event_type=f"QUEUE_{state}",
                payload=payload,
                fencing_epoch=int(scope["fencing_epoch"]),
                created_at=now,
            )
            row = cursor.execute(
                "SELECT * FROM prime_queue_writer_operations WHERE scope_id=? AND idempotency_key=?",
                (scope_id, idempotency_key),
            ).fetchone()
            return self._output(row, result=payload)

    def execute_transition(
        self,
        *,
        scope_id: str,
        transaction_id: str,
        idempotency_key: str,
        card_id: str,
        command: str,
        actor: str,
        expected_queue_sha256: str,
        lease_token: str,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        reason: str = "",
        result: str | None = None,
        cascade: bool = False,
    ) -> dict[str, Any]:
        prepared = False
        try:
            scope_id = _safe_id(scope_id, "scope_id")
            transaction_id = _safe_id(transaction_id, "transaction_id")
            idempotency_key = _safe_id(idempotency_key, "idempotency_key")
            card_id = _card_id(card_id)
            if command not in QUEUE_WRITER_COMMANDS:
                raise PrimeQueueWriterError("COMMAND_INVALID")
            if actor not in _ACTORS:
                raise PrimeQueueWriterError("ACTOR_INVALID")
            expected_queue_sha256 = _hash64(expected_queue_sha256, "expected_queue_sha256")
            lease_token = _text(lease_token, "lease_token")
            owner_id, owner_instance_id, owner_epoch, fencing_epoch = self._validate_owner(
                owner_id, owner_instance_id, owner_epoch, fencing_epoch
            )
            reason = _text(reason, "reason") if reason else ""
            if result is not None:
                result = _text(result, "result")
            before_queue_sha256 = self._queue_hash()
            existing = self._existing_for_request(
                scope_id=scope_id,
                transaction_id=transaction_id,
                idempotency_key=idempotency_key,
                card_id=card_id,
                command=command,
                actor=actor,
                before_queue_sha256=expected_queue_sha256,
                reason=reason,
                result=result,
                cascade=bool(cascade),
                owner_id=owner_id,
                owner_instance_id=owner_instance_id,
                owner_epoch=owner_epoch,
                fencing_epoch=fencing_epoch,
                lease_token=lease_token,
            )
            if existing is not None:
                if existing.get("__wait_for_resolution__"):
                    row = self._wait_for_existing_resolution(existing["scope_id"], existing["idempotency_key"])
                    if row["state"] == "COMMITTED":
                        return self._output(row, status="REPLAYED")
                    if row["state"] == "ABORTED":
                        return self._output(row)
                    return self._output(row, status="RECOVERY_REQUIRED", reason="QUEUE_WRITER_OPERATION_NOT_RESUMABLE")
                return existing
            if before_queue_sha256 != expected_queue_sha256:
                return {
                    "schema_version": QUEUE_WRITER_SCHEMA,
                    "contract_role": QUEUE_WRITER_ROLE,
                    "status": "HOLD",
                    "decision": "HOLD",
                    "reason": "STALE_QUEUE_HASH",
                    "permission": "read_only",
                    "queue_mutation_performed": False,
                    "queue_mutation_evidence": QUEUE_MUTATION_FALSE,
                    "receipt_emitted": False,
                    "receipt_committed": False,
                    "consume_allowed": False,
                    "cross_store_atomicity": "NOT_CLAIMED",
                }
            self._validate_actor_card(
                card_id=card_id,
                command=command,
                expected=expected_queue_sha256,
                actor=actor,
            )
            # The lease clock is deliberately used as the operation timestamp:
            # same-second retries/concurrent callers preflight the same bytes.
            updated_at = datetime.fromtimestamp(self._now(), timezone.utc).isoformat()
            dry = self._dry_run(
                card_id=card_id,
                command=command,
                expected=expected_queue_sha256,
                reason=reason,
                result=result,
                cascade=bool(cascade),
                updated_at=updated_at,
            )
            after_queue_sha256 = _hash64(dry.get("after_sha256"), "after_queue_sha256")
            intent = self._operation_intent(
                scope_id=scope_id,
                transaction_id=transaction_id,
                idempotency_key=idempotency_key,
                card_id=card_id,
                command=command,
                actor=actor,
                reason=reason,
                result=result,
                cascade=bool(cascade),
                before_queue_sha256=before_queue_sha256,
                after_queue_sha256=after_queue_sha256,
                fencing_epoch=fencing_epoch,
            )
            existing, _metadata = self._insert_prepared(
                scope_id=scope_id,
                intent=intent,
                owner_id=owner_id,
                owner_instance_id=owner_instance_id,
                owner_epoch=owner_epoch,
                fencing_epoch=fencing_epoch,
                lease_token=lease_token,
                now=self._now(),
            )
            if existing is not None:
                if existing.get("__wait_for_resolution__"):
                    row = self._wait_for_existing_resolution(existing["scope_id"], existing["idempotency_key"])
                    if row["state"] == "COMMITTED":
                        return self._output(row, status="REPLAYED")
                    if row["state"] == "ABORTED":
                        return self._output(row)
                    return self._output(row, status="RECOVERY_REQUIRED", reason="QUEUE_WRITER_OPERATION_NOT_RESUMABLE")
                return existing
            prepared = True
            self._claim_phase(
                scope_id=scope_id,
                transaction_id=transaction_id,
                phase="EXECUTING",
                owner_id=owner_id,
                owner_instance_id=owner_instance_id,
                owner_epoch=owner_epoch,
                fencing_epoch=fencing_epoch,
                lease_token=lease_token,
                allowed_previous=frozenset({"PREPARED"}),
            )
            prepared = True
            self._fault("after_prepare")
            state = prime_writes._state()
            engine = prime_writes._engine()
            writer_metadata = {
                "writer_transaction_id": transaction_id,
                "writer_scope_id": scope_id,
                "writer_intent_sha256": canonical_hash(intent),
                "writer_fencing_epoch": fencing_epoch,
            }
            fence = {
                "owner_id": owner_id,
                "owner_instance_id": owner_instance_id,
                "owner_epoch": owner_epoch,
                "fencing_epoch": fencing_epoch,
                "lease_token": lease_token,
            }

            def live_fence_hook(_event: str) -> None:
                self._assert_live_fence(
                    scope_id=scope_id,
                    transaction_id=transaction_id,
                    owner_id=owner_id,
                    owner_instance_id=owner_instance_id,
                    owner_epoch=owner_epoch,
                    fencing_epoch=fencing_epoch,
                    lease_token=lease_token,
                )

            finalized_result: dict[str, Any] | None = None

            def finalize_queue_commit(committed_info: Mapping[str, Any]) -> None:
                nonlocal finalized_result
                current = self._queue_hash()
                if current != after_queue_sha256 or committed_info.get("after_sha256") != after_queue_sha256:
                    finalized_result = self._mark_state(
                        scope_id=scope_id,
                        idempotency_key=idempotency_key,
                        state="IN_DOUBT",
                        reason="QUEUE_AFTER_HASH_MISMATCH",
                        queue_mutation_performed=None,
                        queue_mutation_evidence=QUEUE_MUTATION_UNKNOWN,
                        result=committed_info,
                        transaction_id=transaction_id,
                        required_active_phase="EXECUTING",
                    )
                    return
                self._fault("after_queue_commit")
                finalized_result = self._mark_state(
                    scope_id=scope_id,
                    idempotency_key=idempotency_key,
                    state="COMMITTED",
                    reason="QUEUE_TRANSITION_COMMITTED",
                    queue_mutation_performed=True,
                    result=committed_info,
                    transaction_id=transaction_id,
                    required_active_phase="EXECUTING",
                    fence=fence,
                )

            transition_result = state.transition(
                self.root,
                engine.engine(),
                command,
                card_id,
                expected_queue_sha256,
                reason=reason,
                result=result,
                cascade=bool(cascade),
                actor="Plan",
                dry_run=False,
                hook=live_fence_hook,
                updated_at=updated_at,
                writer_metadata=writer_metadata,
                recover=False,
                commit_hook=finalize_queue_commit,
            )
            if finalized_result is None:
                raise PrimeQueueWriterError("QUEUE_COMMIT_FINALIZER_NOT_CALLED")
            return finalized_result
        except InjectedPrimeQueueWriterCrash:
            if prepared:
                self._move_to_recovery_phase(scope_id=scope_id, transaction_id=transaction_id)
            raise
        except PrimeQueueWriterError as exc:
            if prepared:
                self._move_to_recovery_phase(scope_id=scope_id, transaction_id=transaction_id)
                return self._hold(
                    f"QUEUE_WRITER_RECOVERY_REQUIRED_{exc}",
                    status="RECOVERY_REQUIRED",
                    queue_mutation_evidence=QUEUE_MUTATION_UNKNOWN,
                )
            return {
                "schema_version": QUEUE_WRITER_SCHEMA,
                "contract_role": QUEUE_WRITER_ROLE,
                "status": "HOLD",
                "decision": "HOLD",
                "reason": str(exc),
                "permission": "read_only",
                "queue_mutation_performed": False,
                "queue_mutation_evidence": QUEUE_MUTATION_FALSE,
                "receipt_emitted": False,
                "receipt_committed": False,
                "consume_allowed": False,
                "cross_store_atomicity": "NOT_CLAIMED",
            }
        except Exception as exc:
            if prepared:
                self._move_to_recovery_phase(scope_id=scope_id, transaction_id=transaction_id)
                return self._hold(
                    f"QUEUE_WRITER_UNEXPECTED_{type(exc).__name__}",
                    status="RECOVERY_REQUIRED",
                    queue_mutation_evidence=QUEUE_MUTATION_UNKNOWN,
                )
            return {
                "schema_version": QUEUE_WRITER_SCHEMA,
                "contract_role": QUEUE_WRITER_ROLE,
                "status": "RECOVERY_REQUIRED",
                "decision": "HOLD",
                "reason": f"QUEUE_WRITER_UNEXPECTED_{type(exc).__name__}",
                "permission": "read_only",
                "queue_mutation_performed": False,
                "queue_mutation_evidence": QUEUE_MUTATION_UNKNOWN,
                "receipt_emitted": False,
                "receipt_committed": False,
                "consume_allowed": False,
                "cross_store_atomicity": "NOT_CLAIMED",
            }

    def _read_operation_row(self, scope_id: str, idempotency_key: str) -> sqlite3.Row:
        scope_id = _safe_id(scope_id, "scope_id")
        idempotency_key = _safe_id(idempotency_key, "idempotency_key")
        with self._read_transaction() as cursor:
            scope = self._scope_row(cursor, scope_id)
            self._assert_scope_integrity(cursor, scope)
            row = cursor.execute(
                "SELECT * FROM prime_queue_writer_operations WHERE scope_id=? AND idempotency_key=?",
                (scope_id, idempotency_key),
            ).fetchone()
            if row is None:
                raise PrimeQueueWriterError("OPERATION_NOT_FOUND")
            intent = json.loads(row["operation_json"])
            if canonical_hash(intent) != row["intent_sha256"]:
                raise PrimeQueueWriterError("OPERATION_INTENT_DIGEST_DRIFT")
            markers = cursor.execute(
                "SELECT * FROM prime_queue_writer_markers WHERE scope_id=? AND idempotency_key=? ORDER BY created_at,marker_kind",
                (scope_id, idempotency_key),
            ).fetchall()
            for marker in markers:
                payload = json.loads(marker["payload_json"])
                if canonical_hash(payload) != marker["marker_hash"]:
                    raise PrimeQueueWriterError("MARKER_DIGEST_DRIFT")
            return row

    def read_operation(self, scope_id: str, idempotency_key: str) -> dict[str, Any]:
        try:
            row = self._read_operation_row(scope_id, idempotency_key)
            payload = json.loads(row["result_json"]) if row["result_json"] else None
            return self._output(row, result=payload)
        except PrimeQueueWriterError as exc:
            return {
                "schema_version": QUEUE_WRITER_SCHEMA,
                "contract_role": QUEUE_WRITER_ROLE,
                "status": "RECOVERY_REQUIRED",
                "decision": "HOLD",
                "reason": str(exc),
                "permission": "read_only",
                "queue_mutation_performed": False,
                "receipt_emitted": False,
                "receipt_committed": False,
                "consume_allowed": False,
                "cross_store_atomicity": "NOT_CLAIMED",
            }

    def _accepted_recovery_handoff_exists(self, scope_id: str, idempotency_key: str) -> bool:
        """Keep the legacy recovery entrypoint behind an accepted-handoff gate."""

        with self._read_transaction() as cursor:
            row = cursor.execute(
                "SELECT 1 FROM prime_queue_writer_handoff_events WHERE scope_id=? AND idempotency_key=? LIMIT 1",
                (scope_id, idempotency_key),
            ).fetchone()
            return row is not None

    def recover_operation(
        self,
        *,
        scope_id: str,
        idempotency_key: str,
        lease_token: str,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        pre_claim_check: Callable[[], None] | None = None,
        before_terminal_marker: Callable[[], None] | None = None,
        after_terminal_marker: Callable[[], None] | None = None,
        before_state_mark: Callable[[], None] | None = None,
        after_state_mark: Callable[[], None] | None = None,
        queue_lock_fd: int | None = None,
    ) -> dict[str, Any]:
        """Explicitly resolve one prepared operation without a new queue write."""

        try:
            row = self._read_operation_row(scope_id, idempotency_key)
            if self._accepted_recovery_handoff_exists(scope_id, idempotency_key):
                return self._hold(
                    "S25D_EXECUTOR_REQUIRED",
                    status="RECOVERY_REQUIRED",
                    queue_mutation_evidence=QUEUE_MUTATION_UNKNOWN,
                )
            if row["state"] == "COMMITTED":
                return self._output(row, status="REPLAYED")
            if row["state"] not in {"PREPARED", "IN_DOUBT"}:
                return self._output(row)
            if pre_claim_check is not None:
                pre_claim_check()
            self._claim_phase(
                scope_id=scope_id,
                transaction_id=row["transaction_id"],
                phase="RECOVERY",
                owner_id=owner_id,
                owner_instance_id=owner_instance_id,
                owner_epoch=owner_epoch,
                fencing_epoch=fencing_epoch,
                lease_token=lease_token,
                allowed_previous=frozenset({"PREPARED", "RECOVERY"}),
            )
            fence = {
                "owner_id": owner_id,
                "owner_instance_id": owner_instance_id,
                "owner_epoch": owner_epoch,
                "fencing_epoch": fencing_epoch,
                "lease_token": lease_token,
            }

            def recovery_fence_check() -> None:
                self._assert_live_fence(
                    scope_id=scope_id,
                    transaction_id=row["transaction_id"],
                    owner_id=owner_id,
                    owner_instance_id=owner_instance_id,
                    owner_epoch=owner_epoch,
                    fencing_epoch=fencing_epoch,
                    lease_token=lease_token,
                    required_phase="RECOVERY",
                )

            def terminal_before() -> None:
                recovery_fence_check()
                if before_terminal_marker is not None:
                    before_terminal_marker()

            def terminal_after() -> None:
                if after_terminal_marker is not None:
                    after_terminal_marker()
                recovery_fence_check()

            recovery = self._recover_exact_transaction(
                row,
                before_terminal_marker=terminal_before,
                after_terminal_marker=terminal_after,
                queue_lock_fd=queue_lock_fd,
            )
            if recovery == "ABORTED":
                if before_state_mark is not None:
                    before_state_mark()
                result = self._mark_state(
                    scope_id=scope_id,
                    idempotency_key=idempotency_key,
                    state="ABORTED",
                    reason="QUEUE_RECOVERY_CONFIRMED_BEFORE_ONLY",
                    queue_mutation_performed=False,
                    queue_mutation_evidence=QUEUE_MUTATION_FALSE,
                    transaction_id=row["transaction_id"],
                    required_active_phase="RECOVERY",
                    fence=fence,
                )
                if after_state_mark is not None:
                    after_state_mark()
                return result
            if recovery == "COMMITTED":
                if before_state_mark is not None:
                    before_state_mark()
                result = self._mark_state(
                    scope_id=scope_id,
                    idempotency_key=idempotency_key,
                    state="COMMITTED",
                    reason="QUEUE_RECOVERY_CONFIRMED_COMMITTED",
                    queue_mutation_performed=True,
                    queue_mutation_evidence=QUEUE_MUTATION_TRUE,
                    result={"recovered": True},
                    transaction_id=row["transaction_id"],
                    required_active_phase="RECOVERY",
                    fence=fence,
                )
                if after_state_mark is not None:
                    after_state_mark()
                return result
            if before_state_mark is not None:
                before_state_mark()
            result = self._mark_state(
                scope_id=scope_id,
                idempotency_key=idempotency_key,
                state="RECOVERY_REQUIRED",
                reason="QUEUE_RECOVERY_EXACT_TRANSACTION_UNRESOLVED",
                queue_mutation_performed=None,
                queue_mutation_evidence=QUEUE_MUTATION_UNKNOWN,
                transaction_id=row["transaction_id"],
                required_active_phase="RECOVERY",
                fence=fence,
            )
            if after_state_mark is not None:
                after_state_mark()
            return result
        except InjectedPrimeQueueWriterCrash:
            raise
        except PrimeQueueWriterError as exc:
            return {
                "schema_version": QUEUE_WRITER_SCHEMA,
                "contract_role": QUEUE_WRITER_ROLE,
                "status": "RECOVERY_REQUIRED",
                "decision": "HOLD",
                "reason": str(exc),
                "permission": "read_only",
                "queue_mutation_performed": False,
                "queue_mutation_evidence": QUEUE_MUTATION_UNKNOWN,
                "receipt_emitted": False,
                "receipt_committed": False,
                "consume_allowed": False,
                "cross_store_atomicity": "NOT_CLAIMED",
            }
        except Exception as exc:
            return self._hold(f"QUEUE_RECOVERY_UNEXPECTED_{type(exc).__name__}", status="RECOVERY_REQUIRED")

    def _matching_committed_transaction(self, row: Mapping[str, Any]) -> bool:
        exact, other_open, invalid = self._transaction_details(row)
        if exact is None or other_open or invalid:
            return False
        committed = exact / "COMMITTED"
        aborted = exact / "ABORTED"
        prepared = exact / "PREPARED"
        return committed.is_file() and prepared.is_file() and not aborted.exists()

    def _matching_aborted_transaction(self, row: Mapping[str, Any]) -> bool:
        exact, other_open, invalid = self._transaction_details(row)
        if other_open or invalid:
            return False
        # A crash immediately after the durable SQLite Prepare record can
        # legitimately have no task-engine transaction yet.  The legacy
        # writer is allowed to close that pre-transaction case as an abort;
        # S25D never reaches this branch because its read-only eligibility
        # contract requires an exact transaction manifest first.
        if exact is None:
            return True
        committed = exact / "COMMITTED"
        aborted = exact / "ABORTED"
        prepared = exact / "PREPARED"
        if not aborted.is_file() or not prepared.is_file() or committed.exists():
            return False
        try:
            return aborted.read_bytes() in {
                b"evidence changed before commit\n",
                b"recovered before replacement; no queue write\n",
                b"recovered before replacement; no automatic replay\n",
            }
        except OSError:
            return False

    def _transaction_details(self, row: Mapping[str, Any]) -> tuple[Path | None, bool, bool]:
        """Find only the Queue transaction carrying this writer's binding.

        The legacy queue journal may contain unrelated transactions.  They are
        observed, never recovered by this operation.
        """

        control = self.root / "Plan" / "local-ai" / "control"
        if control.is_symlink() or not control.is_dir():
            return None, False, True
        exact: Path | None = None
        other_open = False
        invalid = False
        for transaction in sorted(control.glob("tx-*")):
            if transaction.is_symlink() or not transaction.is_dir():
                invalid = True
                continue
            manifest_path = transaction / "transaction.json"
            before_path = transaction / "before.json"
            after_path = transaction / "after.json"
            prepared_path = transaction / "PREPARED"
            committed_path = transaction / "COMMITTED"
            aborted_path = transaction / "ABORTED"
            paths = (manifest_path, before_path, after_path, prepared_path, committed_path, aborted_path)
            if any(path.is_symlink() for path in paths):
                # A malformed or symlinked transaction is not equivalent to
                # an absent transaction.  Recovery must stop rather than
                # infer ABORTED from a coincidental Before hash.
                invalid = True
                continue
            if not all(path.is_file() for path in (manifest_path, before_path, after_path, prepared_path)):
                invalid = True
                continue
            if committed_path.exists() and aborted_path.exists():
                invalid = True
                continue
            if committed_path.exists() and not committed_path.is_file():
                invalid = True
                continue
            if aborted_path.exists() and not aborted_path.is_file():
                invalid = True
                continue
            try:
                if prepared_path.read_bytes() != b"prepared\n":
                    invalid = True
                    continue
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if not isinstance(manifest, Mapping):
                    invalid = True
                    continue
                if (
                    hashlib.sha256(before_path.read_bytes()).hexdigest() != manifest.get("before_sha256")
                    or hashlib.sha256(after_path.read_bytes()).hexdigest() != manifest.get("after_sha256")
                ):
                    invalid = True
                    continue
                for marker_path, allowed in (
                    (committed_path, {b"committed\n", b"recovered committed queue\n"}),
                    (aborted_path, {b"evidence changed before commit\n", b"recovered before replacement; no queue write\n", b"recovered before replacement; no automatic replay\n"}),
                ):
                    if marker_path.exists() and marker_path.read_bytes() not in allowed:
                        invalid = True
                        continue
                metadata = manifest.get("writer_metadata")
                looks_like_request = (
                    manifest.get("task_id") == row["card_id"]
                    and manifest.get("operation") == row["command"]
                    and manifest.get("before_sha256") == row["expected_queue_sha256"]
                    and manifest.get("after_sha256") == row["after_queue_sha256"]
                )
                is_exact = (
                    looks_like_request
                    and isinstance(metadata, Mapping)
                    and metadata.get("writer_transaction_id") == row["transaction_id"]
                    and metadata.get("writer_scope_id") == row["scope_id"]
                    and metadata.get("writer_intent_sha256") == row["intent_sha256"]
                    and metadata.get("writer_fencing_epoch") == json.loads(row["operation_json"]).get("fencing_epoch")
                    and hashlib.sha256(before_path.read_bytes()).hexdigest() == row["expected_queue_sha256"]
                    and hashlib.sha256(after_path.read_bytes()).hexdigest() == row["after_queue_sha256"]
                )
                if is_exact:
                    if exact is not None:
                        invalid = True
                    exact = transaction
                elif looks_like_request:
                    # The operation-shaped transaction is ours but its
                    # binding is damaged or foreign; do not downgrade it to
                    # an unrelated completed transaction.
                    invalid = True
                elif not committed_path.exists() and not aborted_path.exists():
                    other_open = True
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                invalid = True
        return exact, other_open, invalid

    def _recover_exact_transaction(
        self,
        row: Mapping[str, Any],
        *,
        before_terminal_marker: Callable[[], None] | None = None,
        after_terminal_marker: Callable[[], None] | None = None,
        queue_lock_fd: int | None = None,
    ) -> str:
        """Resolve only this operation while holding the existing queue lock."""

        state = prime_writes._state()
        if queue_lock_fd is None:
            queue, journal = state.paths(self.root)
            fd = state.lock(journal)
            close_fd = True
        else:
            queue = self.queue_path
            fd = queue_lock_fd
            close_fd = False
        try:
            exact, other_open, invalid = self._transaction_details(row)
            if other_open or invalid:
                return "UNKNOWN"
            live = hashlib.sha256(queue.read_bytes()).hexdigest()
            if exact is None:
                return "ABORTED" if live == row["expected_queue_sha256"] else "UNKNOWN"
            manifest = state.validate_transaction(exact)
            committed = exact / "COMMITTED"
            aborted = exact / "ABORTED"
            prepared = exact / "PREPARED"
            if committed.is_file():
                return "COMMITTED" if live == row["after_queue_sha256"] else "UNKNOWN"
            if aborted.is_file():
                return "ABORTED" if live == row["expected_queue_sha256"] else "UNKNOWN"
            if live == row["after_queue_sha256"]:
                if before_terminal_marker is not None:
                    before_terminal_marker()
                state.durable_new(committed, b"recovered committed queue\n")
                if after_terminal_marker is not None:
                    after_terminal_marker()
                return "COMMITTED"
            if live == row["expected_queue_sha256"]:
                if prepared.is_symlink():
                    return "UNKNOWN"
                if before_terminal_marker is not None:
                    before_terminal_marker()
                state.durable_new(aborted, b"recovered before replacement; no queue write\n")
                if after_terminal_marker is not None:
                    after_terminal_marker()
                return "ABORTED"
            return "UNKNOWN"
        finally:
            if close_fd:
                os.close(fd)

    def quarantine(
        self,
        *,
        scope_id: str,
        idempotency_key: str,
        reason: str,
        lease_token: str,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
    ) -> dict[str, Any]:
        reason = _text(reason, "reason")
        row = self._read_operation_row(scope_id, idempotency_key)
        self._claim_phase(
            scope_id=scope_id,
            transaction_id=row["transaction_id"],
            phase="RECOVERY",
            owner_id=owner_id,
            owner_instance_id=owner_instance_id,
            owner_epoch=owner_epoch,
            fencing_epoch=fencing_epoch,
            lease_token=lease_token,
            allowed_previous=frozenset({"PREPARED", "RECOVERY"}),
        )
        evidence = row["queue_mutation_evidence"]
        performed = {
            QUEUE_MUTATION_TRUE: True,
            QUEUE_MUTATION_FALSE: False,
            QUEUE_MUTATION_UNKNOWN: None,
        }[evidence]
        return self._mark_state(
            scope_id=_safe_id(scope_id, "scope_id"),
            idempotency_key=_safe_id(idempotency_key, "idempotency_key"),
            state="QUARANTINED",
            reason=reason,
            queue_mutation_performed=performed,
            queue_mutation_evidence=evidence,
            transaction_id=row["transaction_id"],
            required_active_phase="RECOVERY",
            fence={
                "owner_id": owner_id,
                "owner_instance_id": owner_instance_id,
                "owner_epoch": owner_epoch,
                "fencing_epoch": fencing_epoch,
                "lease_token": lease_token,
            },
        )


__all__ = [
    "InjectedPrimeQueueWriterCrash",
    "PrimeQueueWriter",
    "PrimeQueueWriterError",
    "QUEUE_WRITER_CLEAN",
    "QUEUE_WRITER_COMMANDS",
    "QUEUE_WRITER_IN_DOUBT",
    "QUEUE_WRITER_QUARANTINED",
    "QUEUE_WRITER_RECOVERY_REQUIRED",
    "QUEUE_WRITER_ROLE",
    "QUEUE_WRITER_SCHEMA",
]
