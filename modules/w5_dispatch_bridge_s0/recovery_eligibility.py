"""W5-S25C read-only recovery eligibility and revalidation.

This module observes one already-open :class:`PrimeQueueWriter` store.  It
does not construct a writer, open a second SQLite connection, claim a phase,
write a marker, resolve a transaction, or start recovery.  A positive result
is only a bounded, cooperative read-only precondition for a later recovery
card; it is never recovery authority.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterator, Mapping

from modules.w4_small_loop_s0 import canonical_hash

from .prime_queue_writer import (
    QUEUE_WRITER_SCHEMA_FINGERPRINT,
    PrimeQueueWriter,
    PrimeQueueWriterError,
)


RECOVERY_ELIGIBILITY_SCHEMA = "prime-queue-recovery-eligibility-v1"
RECOVERY_ELIGIBILITY_ROLE = "prime_queue_recovery_eligibility_read_only"
RECOVERY_ELIGIBLE = "RECOVERY_ELIGIBLE"
RECOVERY_HOLD = "HOLD"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"

_ALLOWED_OPERATION_STATES = frozenset({"PREPARED", "IN_DOUBT"})
_TERMINAL_MARKERS = frozenset({"COMMITTED", "ABORTED"})
_ALLOWED_COMMITTED_BYTES = frozenset({b"committed\n", b"recovered committed queue\n"})
_ALLOWED_ABORTED_BYTES = frozenset(
    {
        b"evidence changed before commit\n",
        b"recovered before replacement; no queue write\n",
        b"recovered before replacement; no automatic replay\n",
    }
)
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
_EXPECTED_COLUMNS: dict[str, tuple[tuple[str, str, int], ...]] = {
    "prime_queue_writer_meta": (("key", "TEXT", 1), ("value", "TEXT", 0)),
    "prime_queue_writer_roots": (
        ("root_binding_sha256", "TEXT", 1),
        ("active_scope_id", "TEXT", 0),
        ("active_fencing_epoch", "INTEGER", 0),
        ("updated_at", "INTEGER", 0),
    ),
    "prime_queue_writer_scopes": (
        ("scope_id", "TEXT", 1),
        ("root_binding_sha256", "TEXT", 0),
        ("owner_id", "TEXT", 0),
        ("owner_instance_id", "TEXT", 0),
        ("owner_epoch", "INTEGER", 0),
        ("fencing_epoch", "INTEGER", 0),
        ("lease_token_sha256", "TEXT", 0),
        ("lease_expires_at", "INTEGER", 0),
        ("scope_status", "TEXT", 0),
        ("active_operation_id", "TEXT", 0),
        ("active_phase", "TEXT", 0),
        ("event_seq", "INTEGER", 0),
        ("updated_at", "INTEGER", 0),
    ),
    "prime_queue_writer_operations": (
        ("scope_id", "TEXT", 1),
        ("idempotency_key", "TEXT", 2),
        ("transaction_id", "TEXT", 0),
        ("intent_sha256", "TEXT", 0),
        ("card_id", "TEXT", 0),
        ("command", "TEXT", 0),
        ("actor", "TEXT", 0),
        ("expected_queue_sha256", "TEXT", 0),
        ("after_queue_sha256", "TEXT", 0),
        ("state", "TEXT", 0),
        ("queue_mutation_performed", "INTEGER", 0),
        ("queue_mutation_evidence", "TEXT", 0),
        ("operation_json", "TEXT", 0),
        ("result_json", "TEXT", 0),
        ("created_at", "INTEGER", 0),
        ("updated_at", "INTEGER", 0),
    ),
    "prime_queue_writer_events": (
        ("scope_id", "TEXT", 1),
        ("event_seq", "INTEGER", 2),
        ("idempotency_key", "TEXT", 0),
        ("event_type", "TEXT", 0),
        ("parent_event_sha256", "TEXT", 0),
        ("event_sha256", "TEXT", 0),
        ("payload_json", "TEXT", 0),
        ("fencing_epoch", "INTEGER", 0),
        ("created_at", "INTEGER", 0),
    ),
    "prime_queue_writer_markers": (
        ("scope_id", "TEXT", 1),
        ("idempotency_key", "TEXT", 2),
        ("marker_kind", "TEXT", 3),
        ("marker_hash", "TEXT", 0),
        ("payload_json", "TEXT", 0),
        ("created_at", "INTEGER", 0),
    ),
    "prime_queue_writer_handoff_events": (
        ("scope_id", "TEXT", 1),
        ("handoff_seq", "INTEGER", 2),
        ("handoff_id", "TEXT", 0),
        ("root_binding_sha256", "TEXT", 0),
        ("transaction_id", "TEXT", 0),
        ("idempotency_key", "TEXT", 0),
        ("observation_sha256", "TEXT", 0),
        ("grant_sha256", "TEXT", 0),
        ("authority_id", "TEXT", 0),
        ("authority_epoch", "INTEGER", 0),
        ("authority_proof_sha256", "TEXT", 0),
        ("old_owner_id", "TEXT", 0),
        ("old_owner_instance_id", "TEXT", 0),
        ("old_owner_epoch", "INTEGER", 0),
        ("old_fencing_epoch", "INTEGER", 0),
        ("old_lease_token_sha256", "TEXT", 0),
        ("old_lease_expires_at", "INTEGER", 0),
        ("new_owner_id", "TEXT", 0),
        ("new_owner_instance_id", "TEXT", 0),
        ("new_owner_epoch", "INTEGER", 0),
        ("new_fencing_epoch", "INTEGER", 0),
        ("new_lease_token_sha256", "TEXT", 0),
        ("new_lease_expires_at", "INTEGER", 0),
        ("handoff_kind", "TEXT", 0),
        ("event_type", "TEXT", 0),
        ("parent_event_sha256", "TEXT", 0),
        ("event_sha256", "TEXT", 0),
        ("payload_json", "TEXT", 0),
        ("created_at", "INTEGER", 0),
    ),
}
_EXPECTED_NOTNULL = {
    "prime_queue_writer_meta": (0, 1),
    "prime_queue_writer_roots": (0, 1, 1, 1),
    "prime_queue_writer_scopes": (0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1),
    "prime_queue_writer_operations": (1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1),
    "prime_queue_writer_events": (1, 1, 0, 1, 0, 1, 1, 1, 1),
    "prime_queue_writer_markers": (1, 1, 1, 1, 1, 1),
    "prime_queue_writer_handoff_events": (1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1),
}
class RecoveryEligibilityError(ValueError):
    """A read-only eligibility input or local observation failed closed."""

    def __init__(self, reason: str, *, status: str = RECOVERY_REQUIRED) -> None:
        self.reason = reason
        self.status = status
        super().__init__(reason)


class _EligibilityFailure(Exception):
    def __init__(self, reason: str, *, status: str = RECOVERY_REQUIRED) -> None:
        self.reason = reason
        self.status = status
        super().__init__(reason)


def _output(
    status: str,
    reason: str,
    *,
    scope_id: str | None = None,
    handoff_id: str | None = None,
    transaction_id: str | None = None,
    idempotency_key: str | None = None,
    handoff_seq: int | None = None,
    handoff_event_sha256: str | None = None,
    grant_sha256: str | None = None,
    observation_sha256: str | None = None,
    queue_hash: str | None = None,
    operation_state: str | None = None,
    transaction_state: str | None = None,
    owner_id: str | None = None,
    owner_instance_id: str | None = None,
    owner_epoch: int | None = None,
    lease_expires_at: int | None = None,
    fencing_epoch: int | None = None,
    gates: Mapping[str, bool] | None = None,
    shared_lock_acquired: bool = False,
) -> dict[str, Any]:
    eligible = status == RECOVERY_ELIGIBLE
    gate_values = {
        "handoff_event_chain": False,
        "root_scope_claim": False,
        "operation_binding": False,
        "marker_binding": False,
        "transaction_binding": False,
        "queue_hash": False,
        "fence": False,
        "lease": False,
        "queue_read_stable": False,
    }
    if gates:
        gate_values.update(gates)
    return {
        "schema_version": RECOVERY_ELIGIBILITY_SCHEMA,
        "contract_role": RECOVERY_ELIGIBILITY_ROLE,
        "status": status,
        "decision": "RECOVERY_ELIGIBILITY_ONLY" if eligible else "HOLD",
        "reason": reason,
        "scope_id": scope_id,
        "handoff_id": handoff_id,
        "handoff_seq": handoff_seq,
        "handoff_event_sha256": handoff_event_sha256,
        "grant_sha256": grant_sha256,
        "observation_sha256": observation_sha256,
        "transaction_id": transaction_id,
        "idempotency_key": idempotency_key,
        "operation_state": operation_state,
        "transaction_state": transaction_state,
        "owner_id": owner_id,
        "owner_instance_id": owner_instance_id,
        "owner_epoch": owner_epoch,
        "queue_sha256": queue_hash,
        "lease_expires_at": lease_expires_at,
        "fencing_epoch": fencing_epoch,
        "read_only": True,
        "snapshot_verified": eligible,
        "handoff_event_verified": gate_values["handoff_event_chain"],
        "root_scope_claim_verified": gate_values["root_scope_claim"],
        "operation_verified": gate_values["operation_binding"],
        "marker_verified": gate_values["marker_binding"],
        "transaction_verified": gate_values["transaction_binding"],
        "queue_hash_verified": gate_values["queue_hash"],
        "fence_verified": gate_values["fence"],
        "lease_verified": gate_values["lease"],
        "queue_read_stable": gate_values["queue_read_stable"],
        "recovery_authority": False,
        "recovery_eligible": eligible,
        "recovery_allowed": False,
        "recovery_execution_allowed": False,
        "recovery_started": False,
        "resume_allowed": False,
        "mutation_allowed": False,
        "mutation_performed": False,
        "queue_mutation_performed": False,
        "marker_write_performed": False,
        "receipt_emitted": False,
        "receipt_committed": False,
        "consume_allowed": False,
        "global_commit": False,
        "cross_store_atomicity": "NOT_CLAIMED",
        "path_toctou": "COOPERATIVE_SHARED_LOCK_ONLY",
        "path_toctou_claimed": False,
        "execution": {
            "queue_lock": shared_lock_acquired,
            "sqlite_read": shared_lock_acquired,
            "queue_file_read": shared_lock_acquired,
            "transaction_file_read": shared_lock_acquired,
            "queue_file_write": False,
            "sqlite_write": False,
            "marker_write": False,
            "recovery": False,
            "executor": False,
            "receipt": False,
            "ledger": False,
            "projection": False,
            "consume": False,
        },
    }


def _fail(reason: str, *, status: str = RECOVERY_REQUIRED) -> None:
    raise _EligibilityFailure(reason, status=status)


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail(f"{label}_INVALID", status=RECOVERY_HOLD)
    return value


def _require_hash(value: Any, label: str) -> str:
    value = _require_text(value, label)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        _fail(f"{label}_INVALID")
    return value


def _require_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        _fail(f"{label}_INVALID", status=RECOVERY_HOLD)
    return value


def _lease_hash(token: str) -> str:
    token = _require_text(token, "lease_token")
    if len(token) < 16:
        _fail("LEASE_TOKEN_TOO_SHORT", status=RECOVERY_HOLD)
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label}_PATH_INVALID")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        _fail(f"{label}_INVALID")
    if not isinstance(value, Mapping):
        _fail(f"{label}_INVALID")
    return value


def _read_bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label}_PATH_INVALID")
    try:
        return path.read_bytes()
    except OSError:
        _fail(f"{label}_READ_FAILED")


class RecoveryEligibilityPreflight:
    """Revalidate one accepted handoff without opening a writer or mutating."""

    def __init__(self, writer: PrimeQueueWriter, *, clock: Any | None = None) -> None:
        if not isinstance(writer, PrimeQueueWriter):
            raise RecoveryEligibilityError("WRITER_INVALID", status=RECOVERY_HOLD)
        if clock is not None and not callable(clock):
            raise RecoveryEligibilityError("CLOCK_INVALID", status=RECOVERY_HOLD)
        self.writer = writer
        self.clock = clock or writer.clock

    def _now(self, value: int | None) -> int:
        if value is None:
            value = self.clock()
        return _require_int(value, "now")

    @contextmanager
    def _shared_queue_lock(self, *, already_held: bool = False) -> Iterator[None]:
        """Take a shared lock only if an existing lock file is present.

        Opening an existing lock read-only without creation is deliberate: an
        eligibility check must not create a lock file or any control artifact.
        """

        if already_held:
            yield
            return
        control = self.writer.root / "Plan" / "local-ai" / "control"
        lock_path = control / "queue.lock"
        if control.is_symlink() or not control.is_dir() or lock_path.is_symlink() or not lock_path.is_file():
            _fail("QUEUE_LOCK_NOT_AVAILABLE", status=RECOVERY_HOLD)
        fd: int | None = None
        try:
            fd = os.open(str(lock_path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            _fail("QUEUE_LOCK_NOT_AVAILABLE", status=RECOVERY_HOLD)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                _fail("QUEUE_WRITER_ACTIVE", status=RECOVERY_HOLD)
            except OSError:
                _fail("QUEUE_LOCK_NOT_AVAILABLE", status=RECOVERY_HOLD)
            yield
        finally:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _queue_hash(self) -> str:
        try:
            self.writer._assert_queue_path()
            return hashlib.sha256(self.writer.queue_path.read_bytes()).hexdigest()
        except (OSError, PrimeQueueWriterError):
            _fail("QUEUE_PATH_OR_HASH_INVALID")

    @staticmethod
    def _assert_schema(cursor: Any) -> None:
        tables = {
            row[0]
            for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        if tables != _TABLES:
            _fail("DB_SCHEMA_TABLES_INVALID")
        for table, expected in _EXPECTED_COLUMNS.items():
            actual_rows = cursor.execute(f"PRAGMA table_info('{table}')").fetchall()
            actual = tuple(
                (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
                for row in actual_rows
            )
            normalized_expected = tuple(
                (name, column_type, not_null, pk)
                for (name, column_type, pk), not_null in zip(expected, _EXPECTED_NOTNULL[table])
            )
            if actual != normalized_expected:
                _fail("DB_SCHEMA_COLUMNS_INVALID")
        indexes = {
            row[0]
            for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'"
            ).fetchall()
        }
        if indexes != _REQUIRED_INDEXES:
            _fail("DB_SCHEMA_INDEXES_INVALID")
        expected_index_columns = {
            "idx_prime_queue_writer_events_operation": ("scope_id", "idempotency_key", "event_seq"),
            "idx_prime_queue_writer_handoff_events_scope": ("scope_id", "handoff_seq"),
        }
        for index, expected_columns in expected_index_columns.items():
            actual_columns = tuple(
                row[2]
                for row in cursor.execute(f"PRAGMA index_info('{index}')").fetchall()
            )
            if actual_columns != expected_columns:
                _fail("DB_SCHEMA_INDEX_DEFINITION_INVALID")
        triggers = {
            row[0]
            for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()
        }
        if triggers != _REQUIRED_TRIGGERS:
            _fail("DB_SCHEMA_TRIGGERS_INVALID")
        trigger_tables = {
            "prime_queue_writer_markers_immutable_update": "BEFOREUPDATEONPRIME_QUEUE_WRITER_MARKERS",
            "prime_queue_writer_markers_immutable_delete": "BEFOREDELETEONPRIME_QUEUE_WRITER_MARKERS",
            "prime_queue_writer_events_immutable_update": "BEFOREUPDATEONPRIME_QUEUE_WRITER_EVENTS",
            "prime_queue_writer_events_immutable_delete": "BEFOREDELETEONPRIME_QUEUE_WRITER_EVENTS",
            "prime_queue_writer_handoff_events_immutable_update": "BEFOREUPDATEONPRIME_QUEUE_WRITER_HANDOFF_EVENTS",
            "prime_queue_writer_handoff_events_immutable_delete": "BEFOREDELETEONPRIME_QUEUE_WRITER_HANDOFF_EVENTS",
        }
        for trigger, marker in trigger_tables.items():
            row = cursor.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (trigger,)).fetchone()
            compact = re.sub(r"\s+", "", str(row[0]).upper()) if row is not None else ""
            if marker not in compact or "RAISE(ABORT" not in compact:
                _fail("DB_SCHEMA_TRIGGER_DEFINITION_INVALID")
        table_sql = {
            row[0]: re.sub(r"\s+", "", str(row[1]).upper())
            for row in cursor.execute("SELECT name,sql FROM sqlite_master WHERE type='table'").fetchall()
        }
        required_sql_markers = {
            "prime_queue_writer_scopes": (
                "CHECK(SCOPE_STATUSIN('CLEAN','IN_DOUBT','RECOVERY_REQUIRED','QUARANTINED'))",
                "CHECK(ACTIVE_PHASEIN('IDLE','PREPARED','EXECUTING','RECOVERY'))",
                "ROOT_BINDING_SHA256TEXTNOTNULLUNIQUE",
            ),
            "prime_queue_writer_operations": (
                "CHECK(STATEIN('PREPARED','COMMITTED','ABORTED','IN_DOUBT','RECOVERY_REQUIRED','QUARANTINED'))",
                "CHECK(QUEUE_MUTATION_PERFORMEDIN(0,1))",
                "CHECK(QUEUE_MUTATION_EVIDENCEIN('TRUE','FALSE','UNKNOWN'))",
                "UNIQUE(SCOPE_ID,TRANSACTION_ID)",
                "REFERENCESPRIME_QUEUE_WRITER_SCOPES(SCOPE_ID)",
            ),
            "prime_queue_writer_events": (
                "UNIQUE(SCOPE_ID,EVENT_SHA256)",
                "REFERENCESPRIME_QUEUE_WRITER_SCOPES(SCOPE_ID)",
            ),
            "prime_queue_writer_markers": (
                "CHECK(MARKER_KINDIN('PREPARED','COMMITTED','ABORTED','IN_DOUBT','RECOVERY_REQUIRED','QUARANTINED'))",
                "FOREIGNKEY(SCOPE_ID,IDEMPOTENCY_KEY)REFERENCESPRIME_QUEUE_WRITER_OPERATIONS(SCOPE_ID,IDEMPOTENCY_KEY)ONDELETECASCADE",
            ),
            "prime_queue_writer_handoff_events": (
                "CHECK(EVENT_TYPE='HANDOFF_ACCEPTED_RECOVERY')",
                "HANDOFF_IDTEXTNOTNULLUNIQUE",
                "REFERENCESPRIME_QUEUE_WRITER_SCOPES(SCOPE_ID)",
                "UNIQUE(SCOPE_ID,IDEMPOTENCY_KEY)",
                "UNIQUE(SCOPE_ID,OLD_FENCING_EPOCH)",
                "UNIQUE(SCOPE_ID,GRANT_SHA256)",
                "UNIQUE(SCOPE_ID,EVENT_SHA256)",
            ),
        }
        for table, markers in required_sql_markers.items():
            sql = table_sql.get(table, "")
            if any(marker not in sql for marker in markers):
                _fail("DB_SCHEMA_CONSTRAINTS_INVALID")
        meta = cursor.execute(
            "SELECT value FROM prime_queue_writer_meta WHERE key='schema_fingerprint'"
        ).fetchone()
        if meta is None or meta[0] != QUEUE_WRITER_SCHEMA_FINGERPRINT:
            _fail("DB_SCHEMA_FINGERPRINT_INVALID")

    @staticmethod
    def _assert_handoff_event_chain(cursor: Any, scope_id: str) -> None:
        """Recompute the immutable S25B handoff chain from its stored rows."""

        rows = cursor.execute(
            "SELECT * FROM prime_queue_writer_handoff_events WHERE scope_id=? ORDER BY handoff_seq",
            (scope_id,),
        ).fetchall()
        if not rows:
            _fail("HANDOFF_EVENT_CHAIN_MISSING")
        parent: str | None = None
        for expected_seq, row in enumerate(rows, start=1):
            if int(row["handoff_seq"]) != expected_seq or row["parent_event_sha256"] != parent:
                _fail("HANDOFF_EVENT_CHAIN_DRIFT")
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                _fail("HANDOFF_EVENT_CHAIN_PAYLOAD_INVALID")
            if not isinstance(payload, Mapping):
                _fail("HANDOFF_EVENT_CHAIN_PAYLOAD_INVALID")
            expected_event = canonical_hash(
                {
                    "scope_id": row["scope_id"],
                    "handoff_seq": expected_seq,
                    "handoff_id": row["handoff_id"],
                    "event_type": row["event_type"],
                    "parent_event_sha256": parent,
                    "payload": payload,
                    "created_at": row["created_at"],
                }
            )
            if row["event_sha256"] != expected_event:
                _fail("HANDOFF_EVENT_CHAIN_DIGEST_DRIFT")
            if (
                row["event_type"] != "HANDOFF_ACCEPTED_RECOVERY"
                or payload.get("handoff_id") != row["handoff_id"]
                or payload.get("transaction_id") != row["transaction_id"]
                or payload.get("idempotency_key") != row["idempotency_key"]
                or payload.get("grant_sha256") != row["grant_sha256"]
                or payload.get("observation_sha256") != row["observation_sha256"]
            ):
                _fail("HANDOFF_EVENT_CHAIN_BINDING_DRIFT")
            parent = str(row["event_sha256"])

    @staticmethod
    def _assert_marker_rows(cursor: Any, row: Mapping[str, Any], operation: Mapping[str, Any]) -> None:
        markers = cursor.execute(
            "SELECT * FROM prime_queue_writer_markers WHERE scope_id=? AND idempotency_key=? ORDER BY created_at,marker_kind",
            (row["scope_id"], row["idempotency_key"]),
        ).fetchall()
        if not markers:
            _fail("OPERATION_MARKER_MISSING")
        kinds: set[str] = set()
        for marker in markers:
            kind = str(marker["marker_kind"])
            if kind in kinds:
                _fail("OPERATION_MARKER_DUPLICATE")
            kinds.add(kind)
            payload = _read_json_from_text(marker["payload_json"], "MARKER_PAYLOAD")
            if canonical_hash(payload) != marker["marker_hash"]:
                _fail("MARKER_DIGEST_DRIFT")
            if payload.get("intent_sha256") != row["intent_sha256"] or payload.get("state") != kind:
                _fail("MARKER_BINDING_DRIFT")
            if "queue_sha256" in payload:
                _require_hash(payload["queue_sha256"], "MARKER_QUEUE_HASH")
                if payload["queue_sha256"] not in {
                    row["expected_queue_sha256"],
                    row["after_queue_sha256"],
                }:
                    _fail("MARKER_QUEUE_HASH_DRIFT")
            if "fencing_epoch" in payload:
                _require_int(payload["fencing_epoch"], "MARKER_FENCING_EPOCH")
                if int(payload["fencing_epoch"]) != int(operation.get("fencing_epoch", -1)):
                    _fail("MARKER_FENCE_DRIFT")
        state = row["state"]
        required = "PREPARED" if state == "PREPARED" else "IN_DOUBT" if state == "IN_DOUBT" else None
        if required is None or required not in kinds:
            _fail("OPERATION_MARKER_STATE_DRIFT")
        if kinds & {"COMMITTED", "ABORTED", "QUARANTINED", "RECOVERY_REQUIRED"} and state in _ALLOWED_OPERATION_STATES:
            _fail("OPERATION_TERMINAL_MARKER_DRIFT")

    def _inspect_transaction(self, row: Mapping[str, Any], live_hash: str, operation: Mapping[str, Any]) -> str:
        try:
            exact, other_open, invalid = self.writer._transaction_details(row)
        except (OSError, PrimeQueueWriterError, TypeError, ValueError):
            _fail("TRANSACTION_DISCOVERY_FAILED")
        if invalid:
            _fail("TRANSACTION_INTEGRITY_DRIFT")
        if other_open:
            _fail("OTHER_OPEN_TRANSACTION", status=RECOVERY_REQUIRED)
        if exact is None:
            _fail("EXACT_TRANSACTION_MISSING")
        tx = Path(exact)
        if tx.is_symlink() or not tx.is_dir():
            _fail("TRANSACTION_PATH_INVALID")
        before_path = tx / "before.json"
        after_path = tx / "after.json"
        manifest_path = tx / "transaction.json"
        prepared_path = tx / "PREPARED"
        committed_path = tx / "COMMITTED"
        aborted_path = tx / "ABORTED"
        paths = (before_path, after_path, manifest_path, prepared_path, committed_path, aborted_path)
        if any(path.is_symlink() for path in paths):
            _fail("TRANSACTION_SYMLINK")
        if not all(path.is_file() for path in (before_path, after_path, manifest_path, prepared_path)):
            _fail("TRANSACTION_FILES_INCOMPLETE")
        if committed_path.exists() and aborted_path.exists():
            _fail("TRANSACTION_TERMINAL_CONFLICT")
        if committed_path.exists() and not committed_path.is_file():
            _fail("COMMITTED_MARKER_INVALID")
        if aborted_path.exists() and not aborted_path.is_file():
            _fail("ABORTED_MARKER_INVALID")
        prepared = _read_bytes(prepared_path, "PREPARED_MARKER")
        if prepared != b"prepared\n":
            _fail("PREPARED_MARKER_INVALID")
        before = _read_bytes(before_path, "TRANSACTION_BEFORE")
        after = _read_bytes(after_path, "TRANSACTION_AFTER")
        before_hash = hashlib.sha256(before).hexdigest()
        after_hash = hashlib.sha256(after).hexdigest()
        manifest = _read_json(manifest_path, "TRANSACTION_MANIFEST")
        if manifest.get("before_sha256") != before_hash or manifest.get("after_sha256") != after_hash:
            _fail("TRANSACTION_FILE_DIGEST_DRIFT")
        if (
            manifest.get("operation") != row["command"]
            or manifest.get("task_id") != row["card_id"]
            or manifest.get("before_sha256") != row["expected_queue_sha256"]
            or manifest.get("after_sha256") != row["after_queue_sha256"]
        ):
            _fail("TRANSACTION_REQUEST_BINDING_DRIFT")
        metadata = manifest.get("writer_metadata")
        if not isinstance(metadata, Mapping):
            _fail("TRANSACTION_WRITER_BINDING_MISSING")
        if (
            metadata.get("writer_transaction_id") != row["transaction_id"]
            or metadata.get("writer_scope_id") != row["scope_id"]
            or metadata.get("writer_intent_sha256") != row["intent_sha256"]
            or metadata.get("writer_fencing_epoch") != operation.get("fencing_epoch")
        ):
            _fail("TRANSACTION_WRITER_BINDING_DRIFT")
        if committed_path.is_file():
            if _read_bytes(committed_path, "COMMITTED_MARKER") not in _ALLOWED_COMMITTED_BYTES:
                _fail("COMMITTED_MARKER_INVALID")
            if live_hash != row["after_queue_sha256"]:
                _fail("COMMITTED_QUEUE_HASH_DRIFT")
            return "COMMITTED"
        if aborted_path.is_file():
            if _read_bytes(aborted_path, "ABORTED_MARKER") not in _ALLOWED_ABORTED_BYTES:
                _fail("ABORTED_MARKER_INVALID")
            if live_hash != row["expected_queue_sha256"]:
                _fail("ABORTED_QUEUE_HASH_DRIFT")
            return "ABORTED"
        if live_hash == row["expected_queue_sha256"]:
            return "BEFORE"
        if live_hash == row["after_queue_sha256"]:
            return "AFTER"
        _fail("QUEUE_HASH_DRIFT")

    def evaluate(
        self,
        *,
        scope_id: str,
        handoff_id: str,
        lease_token: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Revalidate through the public, self-acquiring shared-lock path."""

        return self._evaluate_internal(
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=now,
            queue_lock_held=False,
        )

    def _evaluate_borrowed_lock(
        self,
        *,
        scope_id: str,
        handoff_id: str,
        lease_token: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Internal capability path for a lock held by S25D itself."""

        return self._evaluate_internal(
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=now,
            queue_lock_held=True,
        )

    def _evaluate_internal(
        self,
        *,
        scope_id: str,
        handoff_id: str,
        lease_token: str,
        now: int | None = None,
        queue_lock_held: bool = False,
    ) -> dict[str, Any]:
        """Return only ``RECOVERY_ELIGIBLE``, ``HOLD`` or ``RECOVERY_REQUIRED``."""

        scope_value: str | None = None
        handoff_value: str | None = None
        transaction_value: str | None = None
        idempotency_value: str | None = None
        operation_state: str | None = None
        transaction_state: str | None = None
        handoff_seq: int | None = None
        handoff_event_sha256: str | None = None
        grant_sha256: str | None = None
        observation_sha256: str | None = None
        queue_hash: str | None = None
        owner_id: str | None = None
        owner_instance_id: str | None = None
        owner_epoch: int | None = None
        lease_expires_at: int | None = None
        fencing_epoch: int | None = None
        shared_lock_acquired = False
        try:
            scope_value = _require_text(scope_id, "scope_id")
            handoff_value = _require_text(handoff_id, "handoff_id")
            expected_lease_hash = _lease_hash(lease_token)
            current_time = self._now(now)
            with self._shared_queue_lock(already_held=queue_lock_held):
                shared_lock_acquired = True
                queue_before = self._queue_hash()
                queue_hash = queue_before
                with self.writer._read_transaction() as cursor:
                    self._assert_schema(cursor)
                    scope = self.writer._scope_row(cursor, scope_value)
                    scope_value = str(scope["scope_id"])
                    self.writer._assert_scope_integrity(cursor, scope)
                    self._assert_handoff_event_chain(cursor, scope_value)
                    handoff = cursor.execute(
                        "SELECT * FROM prime_queue_writer_handoff_events WHERE scope_id=? AND handoff_id=?",
                        (scope_value, handoff_value),
                    ).fetchone()
                    if handoff is None:
                        _fail("HANDOFF_EVENT_NOT_FOUND", status=RECOVERY_HOLD)
                    handoff_seq = int(handoff["handoff_seq"])
                    handoff_event_sha256 = str(handoff["event_sha256"])
                    grant_sha256 = str(handoff["grant_sha256"])
                    observation_sha256 = str(handoff["observation_sha256"])
                    latest = cursor.execute(
                        "SELECT handoff_id FROM prime_queue_writer_handoff_events WHERE scope_id=? ORDER BY handoff_seq DESC LIMIT 1",
                        (scope_value,),
                    ).fetchone()
                    if latest is None or latest["handoff_id"] != handoff_value:
                        _fail("HANDOFF_EVENT_NOT_CURRENT", status=RECOVERY_HOLD)
                    try:
                        payload = json.loads(handoff["payload_json"])
                    except (TypeError, ValueError, json.JSONDecodeError):
                        _fail("HANDOFF_EVENT_PAYLOAD_INVALID")
                    if not isinstance(payload, Mapping):
                        _fail("HANDOFF_EVENT_PAYLOAD_INVALID")
                    target = payload.get("target")
                    if (
                        handoff["event_type"] != "HANDOFF_ACCEPTED_RECOVERY"
                        or payload.get("event_type") != "HANDOFF_ACCEPTED_RECOVERY"
                        or not isinstance(target, Mapping)
                        or target.get("active_phase") != "RECOVERY"
                    ):
                        _fail("HANDOFF_TARGET_INVALID")
                    operation_value = _require_text(handoff["transaction_id"], "transaction_id")
                    idempotency_value = _require_text(handoff["idempotency_key"], "idempotency_key")
                    transaction_value = operation_value
                    if (
                        payload.get("handoff_id") != handoff_value
                        or payload.get("transaction_id") != operation_value
                        or payload.get("idempotency_key") != idempotency_value
                        or payload.get("grant_sha256") != handoff["grant_sha256"]
                        or payload.get("observation_sha256") != handoff["observation_sha256"]
                        or payload.get("intent_sha256") is None
                        or handoff["scope_id"] != scope_value
                        or handoff["root_binding_sha256"] != scope["root_binding_sha256"]
                    ):
                        _fail("HANDOFF_EVENT_BINDING_DRIFT")
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
                        _fail("HANDOFF_TARGET_BINDING_MISSING")
                    current_target = {
                        "root_binding_sha256": scope["root_binding_sha256"],
                        "owner_id": scope["owner_id"],
                        "owner_instance_id": scope["owner_instance_id"],
                        "owner_epoch": int(scope["owner_epoch"]),
                        "fencing_epoch": int(scope["fencing_epoch"]),
                        "lease_token_sha256": scope["lease_token_sha256"],
                        "lease_expires_at": int(scope["lease_expires_at"]),
                    }
                    if any(current_target[key] != target[key] for key in target_keys):
                        _fail("HANDOFF_TARGET_SCOPE_DRIFT")
                    fencing_epoch = int(scope["fencing_epoch"])
                    owner_id = str(scope["owner_id"])
                    owner_instance_id = str(scope["owner_instance_id"])
                    owner_epoch = int(scope["owner_epoch"])
                    lease_expires_at = int(scope["lease_expires_at"])
                    if scope["active_phase"] != "RECOVERY" or scope["scope_status"] != "IN_DOUBT":
                        _fail("RECOVERY_PHASE_NOT_PENDING", status=RECOVERY_HOLD)
                    if expected_lease_hash != scope["lease_token_sha256"]:
                        _fail("RECOVERY_LEASE_TOKEN_MISMATCH", status=RECOVERY_HOLD)
                    if lease_expires_at <= current_time:
                        _fail("RECOVERY_LEASE_EXPIRED", status=RECOVERY_HOLD)
                    if int(target["lease_expires_at"]) <= current_time:
                        _fail("HANDOFF_TARGET_LEASE_EXPIRED", status=RECOVERY_HOLD)
                    operation = cursor.execute(
                        "SELECT * FROM prime_queue_writer_operations WHERE scope_id=? AND transaction_id=? AND idempotency_key=?",
                        (scope_value, operation_value, idempotency_value),
                    ).fetchone()
                    if operation is None:
                        _fail("RECOVERY_OPERATION_MISSING")
                    operation_state = str(operation["state"])
                    operation_payload = _read_json_from_text(operation["operation_json"], "OPERATION_INTENT")
                    if canonical_hash(operation_payload) != operation["intent_sha256"]:
                        _fail("OPERATION_INTENT_DIGEST_DRIFT")
                    if (
                        operation_payload.get("scope_id") != scope_value
                        or operation_payload.get("transaction_id") != operation_value
                        or operation_payload.get("idempotency_key") != idempotency_value
                    ):
                        _fail("OPERATION_BINDING_DRIFT")
                    for key, expected in (
                        ("card_id", operation["card_id"]),
                        ("command", operation["command"]),
                        ("actor", operation["actor"]),
                        ("before_queue_sha256", operation["expected_queue_sha256"]),
                        ("after_queue_sha256", operation["after_queue_sha256"]),
                    ):
                        if operation_payload.get(key) != expected:
                            _fail("OPERATION_INTENT_BINDING_DRIFT")
                    if operation_payload.get("fencing_epoch") is None:
                        _fail("OPERATION_FENCE_BINDING_MISSING")
                    if payload.get("intent_sha256") != operation["intent_sha256"]:
                        _fail("HANDOFF_OPERATION_INTENT_DRIFT")
                    if operation_state not in _ALLOWED_OPERATION_STATES:
                        if operation_state in {"RECOVERY_REQUIRED", "QUARANTINED"}:
                            _fail("OPERATION_ALREADY_RECOVERY_REQUIRED")
                        _fail("OPERATION_NOT_RECOVERY_PENDING", status=RECOVERY_HOLD)
                    if target.get("operation_state") != operation_state:
                        _fail("HANDOFF_OPERATION_STATE_DRIFT")
                    if scope["active_operation_id"] != operation_value:
                        _fail("ACTIVE_OPERATION_BINDING_DRIFT")
                    self._assert_marker_rows(cursor, operation, operation_payload)
                    queue_hash = queue_before
                    transaction_state = self._inspect_transaction(operation, queue_before, operation_payload)
                    queue_after = self._queue_hash()
                    if queue_before != queue_after:
                        _fail("QUEUE_CHANGED_DURING_READ")
                    if transaction_state == "COMMITTED" and operation_state not in {"PREPARED", "IN_DOUBT"}:
                        _fail("TRANSACTION_OPERATION_STATE_DRIFT")
                    return _output(
                        RECOVERY_ELIGIBLE,
                        "RECOVERY_EVIDENCE_REVALIDATED_READ_ONLY",
                        scope_id=scope_value,
                        handoff_id=handoff_value,
                        transaction_id=transaction_value,
                        idempotency_key=idempotency_value,
                        handoff_seq=handoff_seq,
                        handoff_event_sha256=handoff_event_sha256,
                        grant_sha256=grant_sha256,
                        observation_sha256=observation_sha256,
                        queue_hash=queue_hash,
                        operation_state=operation_state,
                        transaction_state=transaction_state,
                        owner_id=owner_id,
                        owner_instance_id=owner_instance_id,
                        owner_epoch=owner_epoch,
                        lease_expires_at=lease_expires_at,
                        fencing_epoch=fencing_epoch,
                        gates={
                            "handoff_event_chain": True,
                            "root_scope_claim": True,
                            "operation_binding": True,
                            "marker_binding": True,
                            "transaction_binding": True,
                            "queue_hash": True,
                            "fence": True,
                            "lease": True,
                            "queue_read_stable": True,
                        },
                        shared_lock_acquired=shared_lock_acquired,
                    )
        except _EligibilityFailure as exc:
            return _output(
                exc.status,
                exc.reason,
                scope_id=scope_value,
                handoff_id=handoff_value,
                transaction_id=transaction_value,
                idempotency_key=idempotency_value,
                handoff_seq=handoff_seq,
                handoff_event_sha256=handoff_event_sha256,
                grant_sha256=grant_sha256,
                observation_sha256=observation_sha256,
                queue_hash=queue_hash,
                operation_state=operation_state,
                transaction_state=transaction_state,
                lease_expires_at=lease_expires_at,
                fencing_epoch=fencing_epoch,
                shared_lock_acquired=shared_lock_acquired,
            )
        except (PrimeQueueWriterError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return _output(
                RECOVERY_REQUIRED,
                "RECOVERY_REVALIDATION_FAILED",
                scope_id=scope_value,
                handoff_id=handoff_value,
                transaction_id=transaction_value,
                idempotency_key=idempotency_value,
                handoff_seq=handoff_seq,
                handoff_event_sha256=handoff_event_sha256,
                grant_sha256=grant_sha256,
                observation_sha256=observation_sha256,
                queue_hash=queue_hash,
                operation_state=operation_state,
                transaction_state=transaction_state,
                lease_expires_at=lease_expires_at,
                fencing_epoch=fencing_epoch,
                shared_lock_acquired=shared_lock_acquired,
            )
        except Exception:
            return _output(
                RECOVERY_REQUIRED,
                "RECOVERY_REVALIDATION_FAILED",
                scope_id=scope_value,
                handoff_id=handoff_value,
                transaction_id=transaction_value,
                idempotency_key=idempotency_value,
                handoff_seq=handoff_seq,
                handoff_event_sha256=handoff_event_sha256,
                grant_sha256=grant_sha256,
                observation_sha256=observation_sha256,
                queue_hash=queue_hash,
                operation_state=operation_state,
                transaction_state=transaction_state,
                lease_expires_at=lease_expires_at,
                fencing_epoch=fencing_epoch,
                shared_lock_acquired=shared_lock_acquired,
            )


def _read_json_from_text(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, str):
        _fail(f"{label}_INVALID")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail(f"{label}_INVALID")
    if not isinstance(parsed, Mapping):
        _fail(f"{label}_INVALID")
    return parsed


def evaluate_recovery_eligibility(
    writer: PrimeQueueWriter,
    *,
    scope_id: str,
    handoff_id: str,
    lease_token: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Convenience wrapper around :class:`RecoveryEligibilityPreflight`."""

    return RecoveryEligibilityPreflight(writer).evaluate(
        scope_id=scope_id,
        handoff_id=handoff_id,
        lease_token=lease_token,
        now=now,
    )


__all__ = [
    "RECOVERY_ELIGIBILITY_ROLE",
    "RECOVERY_ELIGIBILITY_SCHEMA",
    "RECOVERY_ELIGIBLE",
    "RECOVERY_HOLD",
    "RECOVERY_REQUIRED",
    "RecoveryEligibilityError",
    "RecoveryEligibilityPreflight",
    "evaluate_recovery_eligibility",
]
