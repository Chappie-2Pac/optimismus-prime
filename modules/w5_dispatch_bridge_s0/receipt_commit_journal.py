"""W5-S21 durable, fenced Receipt-Commit/Prepare journal.

This card owns one new SQLite journal only.  It revalidates S20 immediately
before writing a local ``PREPARED`` record, reserves a Receipt-specific
idempotency key, and records all five expected participants.  It does not
write W2.5 receipts, projections, Prime state, queues, ledgers, consume state
or recovery state in any external store.  ``COMMITTED`` is a reserved future
state, never an assertion made by this module.
"""

from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Callable, Iterator, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json

from .cross_store_snapshot import SNAPSHOT_PARTICIPANT_IDS
from .receipt_intent_witness import verify_receipt_intent_witness
from .replay_owner_store import ReplayOwnerStore


RECEIPT_JOURNAL_SCHEMA = "prime-cross-store-receipt-commit-journal-v1"
RECEIPT_JOURNAL_ROLE = "cross_store_receipt_commit_prepare_journal"
RECEIPT_JOURNAL_OPERATION = "PREPARE_RECEIPT_COMMIT"
JOURNAL_CLEAN = "CLEAN"
JOURNAL_IN_DOUBT = "IN_DOUBT"
JOURNAL_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
JOURNAL_QUARANTINED = "QUARANTINED"
PREPARED = "PREPARED"
PROJECTION_PENDING = "PROJECTION_PENDING"
COMMITTED = "COMMITTED"
OBSERVED_EFFECT_NONE = "NONE"
OBSERVED_EFFECT_OBSERVED = "OBSERVED"
OBSERVED_EFFECT_UNKNOWN = "UNKNOWN"
_JOURNAL_STATUSES = frozenset({JOURNAL_CLEAN, JOURNAL_IN_DOUBT, JOURNAL_RECOVERY_REQUIRED, JOURNAL_QUARANTINED})
_RECEIPT_STATES = frozenset({PREPARED, PROJECTION_PENDING, JOURNAL_IN_DOUBT, JOURNAL_RECOVERY_REQUIRED, JOURNAL_QUARANTINED, COMMITTED})
_OBSERVED_EFFECT_STATES = frozenset({OBSERVED_EFFECT_NONE, OBSERVED_EFFECT_OBSERVED, OBSERVED_EFFECT_UNKNOWN})
_WRITE_ROLES = frozenset({"WRITE", "OBSERVATION"})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_S20_INPUT_KEYS = frozenset(
    {
        "worker_attestations",
        "replay_observation",
        "replay_floor",
        "host_runtime_attestation",
        "s15_input",
        "owner_observation",
        "request",
        "cross_store_snapshot",
        "receipt_intent",
    }
)
_OPAQUE_S20_INPUT_KEYS = frozenset({"s15_input", "owner_observation", "cross_store_snapshot", "receipt_intent"})
_JOURNAL_TABLES = frozenset(
    {
        "receipt_journal_meta",
        "receipt_journal_scopes",
        "receipt_commit_journal",
        "receipt_commit_participants",
        "receipt_commit_events",
        "receipt_commit_markers",
    }
)
_FAULT_POINTS = frozenset({"before_prepare", "after_prepare", "before_commit", "after_commit"})
SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "002_receipt_commit_journal_v1.sql"
SCHEMA_FINGERPRINT = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()


class ReceiptCommitJournalError(ValueError):
    """Invalid journal input or a detected integrity/fence failure."""


class InjectedReceiptJournalCrash(RuntimeError):
    """Deterministic test-only crash at a local journal boundary."""

    def __init__(self, point: str) -> None:
        self.point = point
        super().__init__(point)


def _copy_json(value: Any, label: str) -> Any:
    try:
        isolated = copy.deepcopy(value)
        canonical_json(isolated)
        return isolated
    except (TypeError, ValueError, copy.Error) as exc:
        raise ReceiptCommitJournalError(f"{label} is not canonical JSON") from exc


def _actionless(
    status: str,
    reason: str,
    *,
    transaction_state: str | None = None,
    observed_effect_state: str = OBSERVED_EFFECT_NONE,
    authoritative_prepared: bool = False,
    idempotency_reserved: bool = False,
    journal_mutation_performed: bool = False,
    receipt_key: str | None = None,
    receipt_id: str | None = None,
    receipt_intent_sha256: str | None = None,
    provenance_sha256: str | None = None,
    projection_set_sha256: str | None = None,
    participant_witness_sha256: str | None = None,
    s20_status: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": RECEIPT_JOURNAL_SCHEMA,
        "contract_role": RECEIPT_JOURNAL_ROLE,
        "status": status,
        "decision": "PROJECTION_COMMIT_DEFERRED" if status in {PREPARED, "REPLAYED"} else "HOLD",
        "reason": reason,
        "transaction_state": transaction_state or status,
        "permission": "receipt_journal_prepare" if status in {PREPARED, "REPLAYED"} else "read_only",
        "authoritative_decision": False,
        "authoritative_prepared": authoritative_prepared,
        "idempotency_reserved": idempotency_reserved,
        "receipt_emitted": False,
        "receipt_committed": False,
        "consume_allowed": False,
        "mutation_allowed": False,
        "mutation_performed": False,
        "journal_mutation_performed": journal_mutation_performed,
        "external_mutation_performed": False,
        "recovery_allowed": False,
        "recovery_started": False,
        "resume_allowed": False,
        "external_action": False,
        "observed_effect_state": observed_effect_state,
        "cross_store_atomicity": "NOT_CLAIMED",
        "receipt_key": receipt_key,
        "receipt_id": receipt_id,
        "receipt_intent_sha256": receipt_intent_sha256,
        "provenance_sha256": provenance_sha256,
        "projection_set_sha256": projection_set_sha256,
        "participant_witness_sha256": participant_witness_sha256,
        "s20_status": s20_status,
        "execution": {
            "journal": journal_mutation_performed,
            "receipt": False,
            "projection": False,
            "consume": False,
            "recovery": False,
            "resume": False,
            "network": False,
        },
    }


class ReceiptCommitJournal:
    """One isolated durable journal for the S21 local Prepare boundary."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        scope_id: str,
        owner_root: str | Path | None = None,
        timeout: float = 5.0,
        clock: Callable[[], int] | None = None,
        fault_points: set[str] | frozenset[str] | None = None,
    ) -> None:
        self.scope_id = self._safe_id(scope_id, "scope_id")
        self.db_path = self._validate_db_path(db_path, self.scope_id, owner_root)
        if clock is not None and not callable(clock):
            raise ReceiptCommitJournalError("clock must be callable")
        self.clock = clock or (lambda: int(time.time()))
        self.fault_points = set(fault_points or ())
        if not self.fault_points.issubset(_FAULT_POINTS):
            raise ReceiptCommitJournalError("unknown receipt journal fault point")
        preexisting_database = self.db_path.exists()
        self.conn = sqlite3.connect(str(self.db_path), isolation_level=None, timeout=timeout)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute(f"PRAGMA busy_timeout = {max(1, int(timeout * 1000))}")
        try:
            tables = {
                row[0]
                for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            identity = canonical_hash(
                {
                    "schema_version": RECEIPT_JOURNAL_SCHEMA,
                    "scope_id": self.scope_id,
                    "db_path": str(self.db_path.resolve(strict=False)),
                }
            )
            if tables:
                if tables != _JOURNAL_TABLES:
                    raise ReceiptCommitJournalError("database contains unexpected receipt-journal tables")
                meta = dict(self.conn.execute("SELECT key,value FROM receipt_journal_meta").fetchall())
                expected = {
                    "schema_version": RECEIPT_JOURNAL_SCHEMA,
                    "canonicalization": "json-sortkeys-v1",
                    "scope_id": self.scope_id,
                    "schema_fingerprint": SCHEMA_FINGERPRINT,
                    "store_identity": identity,
                }
                if any(meta.get(key) != value for key, value in expected.items()):
                    raise ReceiptCommitJournalError("receipt-journal schema or identity mismatch")
            else:
                if preexisting_database:
                    raise ReceiptCommitJournalError("pre-existing empty database is not a receipt journal")
                self.conn.execute("PRAGMA journal_mode = WAL")
                self.conn.execute("PRAGMA synchronous = FULL")
                self.conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
                self.conn.executemany(
                    "INSERT INTO receipt_journal_meta(key,value) VALUES (?,?)",
                    [
                        ("schema_version", RECEIPT_JOURNAL_SCHEMA),
                        ("canonicalization", "json-sortkeys-v1"),
                        ("scope_id", self.scope_id),
                        ("schema_fingerprint", SCHEMA_FINGERPRINT),
                        ("store_identity", identity),
                    ],
                )
                self.conn.execute("PRAGMA journal_mode = WAL")
                self.conn.execute("PRAGMA synchronous = FULL")
        except BaseException:
            self.conn.close()
            raise

    @classmethod
    def _validate_db_path(cls, db_path: str | Path, scope_id: str, owner_root: str | Path | None) -> Path:
        path = Path(db_path)
        if not path.is_absolute():
            raise ReceiptCommitJournalError("receipt-journal database path must be absolute")
        if path.name != f"{scope_id}.sqlite3":
            raise ReceiptCommitJournalError("receipt-journal filename must be scope-id.sqlite3")
        if owner_root is None:
            raise ReceiptCommitJournalError("receipt-journal owner root must be explicit")
        root = Path(owner_root)
        if not root.is_absolute():
            raise ReceiptCommitJournalError("receipt-journal owner root must be absolute")
        if root.exists() and root.is_symlink():
            raise ReceiptCommitJournalError("receipt-journal owner root must not be a symlink")
        if path.exists() and path.is_symlink():
            raise ReceiptCommitJournalError("receipt-journal database must not be a symlink")
        if path.parent.resolve(strict=False) != root.resolve(strict=False):
            raise ReceiptCommitJournalError("receipt-journal database is outside owner root")
        cursor = root
        while True:
            if cursor.exists() and cursor.is_symlink():
                raise ReceiptCommitJournalError("receipt-journal parent must not contain symlinks")
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        if not root.exists() or not root.is_dir():
            raise ReceiptCommitJournalError("receipt-journal owner root must be an existing directory")
        return path

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "ReceiptCommitJournal":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        self.conn.execute("BEGIN IMMEDIATE")
        cursor = self.conn.cursor()
        committed = False
        try:
            yield cursor
            self._fault("before_commit")
            self.conn.execute("COMMIT")
            committed = True
        except BaseException:
            if not committed:
                try:
                    self.conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        else:
            self._fault("after_commit")
        finally:
            cursor.close()

    def _fault(self, point: str) -> None:
        if point in self.fault_points:
            self.fault_points.remove(point)
            raise InjectedReceiptJournalCrash(point)

    def _now(self) -> int:
        return self._integer(self.clock(), "journal clock")

    @staticmethod
    def _text(value: Any, label: str) -> str:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ReceiptCommitJournalError(f"{label} must be non-empty text")
        return value

    @classmethod
    def _safe_id(cls, value: Any, label: str) -> str:
        value = cls._text(value, label)
        if _SAFE_ID.fullmatch(value) is None:
            raise ReceiptCommitJournalError(f"{label} is not a safe identifier")
        return value

    @classmethod
    def _hash(cls, value: Any, label: str) -> str:
        value = cls._text(value, label)
        if _HEX64.fullmatch(value) is None:
            raise ReceiptCommitJournalError(f"{label} must be a lowercase SHA-256")
        return value

    @classmethod
    def _integer(cls, value: Any, label: str, *, minimum: int = 0) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ReceiptCommitJournalError(f"{label} must be an integer >= {minimum}")
        return value

    @classmethod
    def _lease_hash(cls, value: Any) -> str:
        value = cls._text(value, "lease_token")
        if len(value) < 16:
            raise ReceiptCommitJournalError("lease_token must contain at least 16 characters")
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _scope_row(cur: sqlite3.Cursor, scope_id: str) -> sqlite3.Row:
        row = cur.execute("SELECT * FROM receipt_journal_scopes WHERE scope_id=?", (scope_id,)).fetchone()
        if row is None:
            raise ReceiptCommitJournalError("receipt-journal scope does not exist")
        return row

    def _assert_event_chain(self, cur: sqlite3.Cursor, scope: sqlite3.Row) -> None:
        events = cur.execute(
            "SELECT * FROM receipt_commit_events WHERE scope_id=? ORDER BY event_seq",
            (self.scope_id,),
        ).fetchall()
        if len(events) != int(scope["event_seq"]):
            raise ReceiptCommitJournalError("receipt-journal event sequence has a gap")
        parent: str | None = None
        for expected_seq, event in enumerate(events, 1):
            if int(event["event_seq"]) != expected_seq or event["parent_event_sha256"] != parent:
                raise ReceiptCommitJournalError("receipt-journal event parent drift")
            payload = json.loads(event["payload_json"])
            core = {
                "schema_version": "prime-cross-store-receipt-commit-event-v1",
                "scope_id": self.scope_id,
                "event_seq": expected_seq,
                "receipt_key": event["receipt_key"],
                "event_type": event["event_type"],
                "parent_event_sha256": parent,
                "payload": payload,
                "fencing_epoch": int(event["fencing_epoch"]),
                "created_at": int(event["created_at"]),
            }
            if canonical_hash(core) != event["event_sha256"]:
                raise ReceiptCommitJournalError("receipt-journal event digest drift")
            parent = event["event_sha256"]

    def _assert_scope_integrity(self, cur: sqlite3.Cursor, scope: sqlite3.Row) -> None:
        if scope["journal_status"] not in _JOURNAL_STATUSES:
            raise ReceiptCommitJournalError("receipt-journal status is invalid")
        self._hash(scope["projection_manifest_sha256"], "projection_manifest_sha256")
        self._hash(scope["projection_set_sha256"], "projection_set_sha256")
        self._assert_event_chain(cur, scope)

    def _append_event(
        self,
        cur: sqlite3.Cursor,
        *,
        receipt_key: str | None,
        event_type: str,
        payload: Mapping[str, Any],
        fencing_epoch: int,
        created_at: int,
    ) -> str:
        scope = self._scope_row(cur, self.scope_id)
        next_seq = int(scope["event_seq"]) + 1
        previous = cur.execute(
            "SELECT event_sha256 FROM receipt_commit_events WHERE scope_id=? ORDER BY event_seq DESC LIMIT 1",
            (self.scope_id,),
        ).fetchone()
        parent = previous[0] if previous is not None else None
        event_core = {
            "schema_version": "prime-cross-store-receipt-commit-event-v1",
            "scope_id": self.scope_id,
            "event_seq": next_seq,
            "receipt_key": receipt_key,
            "event_type": event_type,
            "parent_event_sha256": parent,
            "payload": copy.deepcopy(dict(payload)),
            "fencing_epoch": fencing_epoch,
            "created_at": created_at,
        }
        event_sha256 = canonical_hash(event_core)
        cur.execute(
            "INSERT INTO receipt_commit_events(scope_id,event_seq,receipt_key,event_type,parent_event_sha256,event_sha256,payload_json,fencing_epoch,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                self.scope_id,
                next_seq,
                receipt_key,
                event_type,
                parent,
                event_sha256,
                canonical_json(event_core["payload"]),
                fencing_epoch,
                created_at,
            ),
        )
        cur.execute(
            "UPDATE receipt_journal_scopes SET event_seq=?,updated_at=? WHERE scope_id=?",
            (next_seq, created_at, self.scope_id),
        )
        return event_sha256

    def _validate_owner(self, owner_id: Any, owner_instance_id: Any, owner_epoch: Any, fencing_epoch: Any) -> tuple[str, str, int, int]:
        return (
            self._safe_id(owner_id, "owner_id"),
            self._safe_id(owner_instance_id, "owner_instance_id"),
            self._integer(owner_epoch, "owner_epoch"),
            self._integer(fencing_epoch, "fencing_epoch"),
        )

    def create_scope(
        self,
        *,
        transaction_id: str,
        projection_manifest_sha256: str,
        projection_set_sha256: str,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        lease_token: str,
        lease_expires_at: int,
    ) -> dict[str, Any]:
        transaction_id = self._safe_id(transaction_id, "transaction_id")
        projection_manifest_sha256 = self._hash(projection_manifest_sha256, "projection_manifest_sha256")
        projection_set_sha256 = self._hash(projection_set_sha256, "projection_set_sha256")
        owner_id, owner_instance_id, owner_epoch, fencing_epoch = self._validate_owner(
            owner_id, owner_instance_id, owner_epoch, fencing_epoch
        )
        lease_token_sha256 = self._lease_hash(lease_token)
        lease_expires_at = self._integer(lease_expires_at, "lease_expires_at")
        now = self._now()
        with self._transaction() as cur:
            if cur.execute("SELECT 1 FROM receipt_journal_scopes WHERE scope_id=?", (self.scope_id,)).fetchone() is not None:
                raise ReceiptCommitJournalError("receipt-journal scope already exists")
            cur.execute(
                "INSERT INTO receipt_journal_scopes(scope_id,transaction_id,projection_manifest_sha256,projection_set_sha256,owner_id,owner_instance_id,owner_epoch,fencing_epoch,lease_token_sha256,lease_expires_at,journal_status,event_seq,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    self.scope_id,
                    transaction_id,
                    projection_manifest_sha256,
                    projection_set_sha256,
                    owner_id,
                    owner_instance_id,
                    owner_epoch,
                    fencing_epoch,
                    lease_token_sha256,
                    lease_expires_at,
                    JOURNAL_CLEAN,
                    0,
                    now,
                ),
            )
            self._append_event(
                cur,
                receipt_key=None,
                event_type="SCOPE_CREATED",
                payload={
                    "transaction_id": transaction_id,
                    "projection_manifest_sha256": projection_manifest_sha256,
                    "projection_set_sha256": projection_set_sha256,
                    "owner_id": owner_id,
                    "fencing_epoch": fencing_epoch,
                },
                fencing_epoch=fencing_epoch,
                created_at=now,
            )
        return self.read_scope()

    def read_scope(self) -> dict[str, Any]:
        scope = self.conn.execute("SELECT * FROM receipt_journal_scopes WHERE scope_id=?", (self.scope_id,)).fetchone()
        if scope is None:
            raise ReceiptCommitJournalError("receipt-journal scope does not exist")
        cur = self.conn.cursor()
        try:
            self._assert_scope_integrity(cur, scope)
        finally:
            cur.close()
        return dict(scope)

    def _assert_fence(
        self,
        scope: sqlite3.Row,
        *,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        lease_token: str,
        now: int,
    ) -> None:
        expected_owner_id, expected_instance, expected_owner_epoch, expected_fencing = self._validate_owner(
            owner_id, owner_instance_id, owner_epoch, fencing_epoch
        )
        if scope["journal_status"] != JOURNAL_CLEAN:
            raise ReceiptCommitJournalError("JOURNAL_QUARANTINED")
        if (
            scope["owner_id"] != expected_owner_id
            or scope["owner_instance_id"] != expected_instance
            or int(scope["owner_epoch"]) != expected_owner_epoch
            or int(scope["fencing_epoch"]) != expected_fencing
            or scope["lease_token_sha256"] != self._lease_hash(lease_token)
        ):
            raise ReceiptCommitJournalError("FENCING_EPOCH_MISMATCH")
        if int(scope["lease_expires_at"]) <= now:
            raise ReceiptCommitJournalError("LEASE_EXPIRED")

    @staticmethod
    def _receipt_id(receipt_key: str) -> str:
        return "s21-" + canonical_hash({"schema": RECEIPT_JOURNAL_SCHEMA, "receipt_key": receipt_key})

    def _participant_rows(self, intent: Mapping[str, Any]) -> list[tuple[str, str, str, str]]:
        participants = intent.get("participants")
        if not isinstance(participants, Mapping) or set(participants) != set(SNAPSHOT_PARTICIPANT_IDS):
            raise ReceiptCommitJournalError("PARTICIPANT_SET_INVALID")
        effect_set = intent.get("effect_set")
        if not isinstance(effect_set, list):
            raise ReceiptCommitJournalError("EFFECT_SET_INVALID")
        effect_by_id: dict[str, str] = {}
        for effect in effect_set:
            if not isinstance(effect, Mapping) or not isinstance(effect.get("participant_id"), str):
                raise ReceiptCommitJournalError("EFFECT_SET_INVALID")
            if effect["participant_id"] in effect_by_id:
                raise ReceiptCommitJournalError("EFFECT_SET_DUPLICATE_PARTICIPANT")
            effect_by_id[effect["participant_id"]] = str(effect.get("operation"))
        rows: list[tuple[str, str, str, str]] = []
        for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
            participant = _copy_json(participants[participant_id], f"participant.{participant_id}")
            operation = effect_by_id.get(participant_id)
            if operation is None:
                raise ReceiptCommitJournalError("EFFECT_SET_PARTICIPANT_MISSING")
            role = "OBSERVATION" if operation == "observe" else "WRITE"
            rows.append((participant_id, role, canonical_hash(participant), canonical_json(participant)))
        return rows

    def _build_core(
        self,
        *,
        intent: Mapping[str, Any],
        s20_result: Mapping[str, Any],
        receipt_id: str,
    ) -> dict[str, Any]:
        intent_sha256 = canonical_hash(intent)
        if intent_sha256 != s20_result.get("receipt_intent_sha256"):
            raise ReceiptCommitJournalError("S20_INTENT_DIGEST_INVALID")
        witness = s20_result.get("receipt_intent_witness")
        if not isinstance(witness, Mapping):
            raise ReceiptCommitJournalError("S20_WITNESS_MISSING")
        participants = _copy_json(intent["participants"], "participants")
        if canonical_hash(intent["subject_binding"]) != witness.get("subject_binding_sha256"):
            raise ReceiptCommitJournalError("S20_SUBJECT_WITNESS_INVALID")
        if canonical_hash(intent["effect_set"]) != witness.get("effect_sha256"):
            raise ReceiptCommitJournalError("S20_EFFECT_WITNESS_INVALID")
        if canonical_hash(intent["participants"]) != witness.get("participant_witness_sha256"):
            raise ReceiptCommitJournalError("S20_PARTICIPANT_WITNESS_INVALID")
        return {
            "schema_version": RECEIPT_JOURNAL_SCHEMA,
            "contract_role": RECEIPT_JOURNAL_ROLE,
            "receipt_id": receipt_id,
            "receipt_key": intent["receipt_key"],
            "receipt_kind": "cross_store_provenance_prepare",
            "state": PREPARED,
            "scope_id": self.scope_id,
            "transaction_id": intent["transaction_id"],
            "idempotency_key": intent["idempotency_key"],
            "operation": intent["operation"],
            "receipt_intent_sha256": intent_sha256,
            "provenance_sha256": intent["provenance_sha256"],
            "s18_commit_witness_sha256": intent["s18_commit_witness_sha256"],
            "projection_manifest_sha256": intent["projection_manifest_sha256"],
            "projection_set_sha256": intent["projection_set_sha256"],
            "subject_binding_sha256": witness["subject_binding_sha256"],
            "effect_sha256": witness["effect_sha256"],
            "participant_witness_sha256": witness["participant_witness_sha256"],
            "owner_id": intent["owner_id"],
            "owner_instance_id": intent["owner_instance_id"],
            "owner_epoch": intent["owner_epoch"],
            "fencing_epoch": intent["fencing_epoch"],
            "participants": participants,
            "subject_binding": _copy_json(intent["subject_binding"], "subject_binding"),
            "effect_set": _copy_json(intent["effect_set"], "effect_set"),
            "future_commit_phases": list(intent["future_commit_phases"]),
            "observed_effect_state": OBSERVED_EFFECT_NONE,
            "cross_store_atomicity": "NOT_CLAIMED",
        }

    def _row_result(self, row: sqlite3.Row, *, status: str | None = None, reason: str | None = None) -> dict[str, Any]:
        state = str(row["state"])
        actual_status = status or ("REPLAYED" if state == PREPARED else state)
        result = _actionless(
            actual_status,
            reason or ("PREPARED_INTENT_REPLAY" if actual_status == "REPLAYED" else f"JOURNAL_{state}"),
            transaction_state=state,
            observed_effect_state=str(row["observed_effect_state"]),
            authoritative_prepared=state == PREPARED,
            idempotency_reserved=state == PREPARED,
            receipt_key=str(row["receipt_key"]),
            receipt_id=str(row["receipt_id"]),
            receipt_intent_sha256=str(row["receipt_intent_sha256"]),
            provenance_sha256=str(row["provenance_sha256"]),
            projection_set_sha256=str(row["projection_set_sha256"]),
            participant_witness_sha256=str(row["participant_witness_sha256"]),
        )
        result["receipt_core"] = json.loads(row["receipt_core_json"])
        result["receipt_intent"] = json.loads(row["intent_json"])
        return result

    def _validate_s20_result(self, result: Mapping[str, Any]) -> None:
        if result.get("status") != "RECEIPT_INTENT_REVALIDATED" or result.get("decision") != "RECEIPT_COMMIT_RECHECK_REQUIRED":
            raise ReceiptCommitJournalError("S20_NOT_REVALIDATED")
        if result.get("intent_derived") is not True or result.get("witness_validated") is not True:
            raise ReceiptCommitJournalError("S20_WITNESS_NOT_VALIDATED")
        for key in (
            "authoritative_decision",
            "authoritative_prepared",
            "intent_persisted",
            "receipt_emitted",
            "receipt_committed",
            "mutation_allowed",
            "mutation_performed",
            "idempotency_reserved",
            "consume_allowed",
            "consume_committed",
            "cas_authorized",
            "recovery_started",
            "external_action",
        ):
            if result.get(key) is not False:
                raise ReceiptCommitJournalError(f"S20_UNSAFE_FLAG_{key}")

    def _prepare_transaction(
        self,
        *,
        s20_result: Mapping[str, Any],
        lease_token: str,
    ) -> dict[str, Any]:
        intent = s20_result.get("receipt_intent")
        if not isinstance(intent, Mapping):
            raise ReceiptCommitJournalError("S20_INTENT_MISSING")
        receipt_key = self._safe_id(intent.get("receipt_key"), "receipt_key")
        receipt_id = self._receipt_id(receipt_key)
        transaction_id = self._safe_id(intent.get("transaction_id"), "transaction_id")
        intent_idempotency = self._safe_id(intent.get("idempotency_key"), "idempotency_key")
        now = self._now()
        self._fault("before_prepare")
        with self._transaction() as cur:
            scope = self._scope_row(cur, self.scope_id)
            self._assert_scope_integrity(cur, scope)
            try:
                self._assert_fence(
                    scope,
                    owner_id=intent["owner_id"],
                    owner_instance_id=intent["owner_instance_id"],
                    owner_epoch=intent["owner_epoch"],
                    fencing_epoch=intent["fencing_epoch"],
                    lease_token=lease_token,
                    now=now,
                )
            except ReceiptCommitJournalError as exc:
                if str(exc) in {"JOURNAL_QUARANTINED", "LEASE_EXPIRED"}:
                    return _actionless("RECOVERY_REQUIRED", str(exc), transaction_state=scope["journal_status"])
                return _actionless("HOLD", str(exc))
            if transaction_id != scope["transaction_id"]:
                return _actionless("HOLD", "TRANSACTION_SCOPE_MISMATCH")
            if intent["projection_manifest_sha256"] != scope["projection_manifest_sha256"] or intent["projection_set_sha256"] != scope["projection_set_sha256"]:
                return _actionless("HOLD", "PROJECTION_SCOPE_MISMATCH")

            existing_rows = []
            for query, value in (
                ("SELECT * FROM receipt_commit_journal WHERE scope_id=? AND receipt_key=?", receipt_key),
                ("SELECT * FROM receipt_commit_journal WHERE scope_id=? AND idempotency_key=?", intent_idempotency),
                ("SELECT * FROM receipt_commit_journal WHERE scope_id=? AND transaction_id=?", transaction_id),
            ):
                row = cur.execute(query, (self.scope_id, value)).fetchone()
                if row is not None and all(row["receipt_key"] != item["receipt_key"] for item in existing_rows):
                    existing_rows.append(row)
            if existing_rows:
                if len(existing_rows) != 1:
                    return _actionless("CONFLICT", "JOURNAL_KEY_OR_TRANSACTION_CONFLICT")
                existing = existing_rows[0]
                same = (
                    existing["receipt_key"] == receipt_key
                    and existing["receipt_id"] == receipt_id
                    and existing["transaction_id"] == transaction_id
                    and existing["idempotency_key"] == intent_idempotency
                    and existing["receipt_intent_sha256"] == s20_result.get("receipt_intent_sha256")
                )
                if not same:
                    reason = (
                        "JOURNAL_KEY_OR_TRANSACTION_CONFLICT"
                        if existing["transaction_id"] == transaction_id
                        else "JOURNAL_INTENT_CONFLICT"
                    )
                    return _actionless("CONFLICT", reason)
                if existing["state"] in {PROJECTION_PENDING, COMMITTED}:
                    return _actionless(
                        "RECOVERY_REQUIRED",
                        "JOURNAL_FUTURE_STATE_UNOWNED",
                        transaction_state=existing["state"],
                        observed_effect_state=existing["observed_effect_state"],
                        receipt_key=existing["receipt_key"],
                        receipt_id=existing["receipt_id"],
                        receipt_intent_sha256=existing["receipt_intent_sha256"],
                        provenance_sha256=existing["provenance_sha256"],
                        projection_set_sha256=existing["projection_set_sha256"],
                        participant_witness_sha256=existing["participant_witness_sha256"],
                    )
                return self._row_result(existing)

            core = self._build_core(intent=intent, s20_result=s20_result, receipt_id=receipt_id)
            participant_rows = self._participant_rows(intent)
            participant_witness_sha256 = canonical_hash(intent["participants"])
            if participant_witness_sha256 != s20_result["receipt_intent_witness"]["participant_witness_sha256"]:
                raise ReceiptCommitJournalError("PARTICIPANT_WITNESS_INVALID")
            cur.execute(
                "INSERT INTO receipt_commit_journal(scope_id,receipt_key,receipt_id,transaction_id,idempotency_key,operation,receipt_intent_sha256,provenance_sha256,s18_commit_witness_sha256,projection_manifest_sha256,projection_set_sha256,subject_binding_sha256,effect_sha256,participant_witness_sha256,owner_id,owner_instance_id,owner_epoch,fencing_epoch,state,observed_effect_state,receipt_emitted,receipt_committed,consume_allowed,mutation_performed,intent_json,receipt_core_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    self.scope_id,
                    receipt_key,
                    receipt_id,
                    transaction_id,
                    intent_idempotency,
                    intent["operation"],
                    s20_result["receipt_intent_sha256"],
                    intent["provenance_sha256"],
                    intent["s18_commit_witness_sha256"],
                    intent["projection_manifest_sha256"],
                    intent["projection_set_sha256"],
                    canonical_hash(intent["subject_binding"]),
                    canonical_hash(intent["effect_set"]),
                    participant_witness_sha256,
                    intent["owner_id"],
                    intent["owner_instance_id"],
                    intent["owner_epoch"],
                    intent["fencing_epoch"],
                    PREPARED,
                    OBSERVED_EFFECT_NONE,
                    0,
                    0,
                    0,
                    0,
                    canonical_json(dict(intent)),
                    canonical_json(core),
                    now,
                    now,
                ),
            )
            for participant_id, role, participant_sha256, participant_json in participant_rows:
                cur.execute(
                    "INSERT INTO receipt_commit_participants(scope_id,receipt_key,participant_id,participant_role,participant_sha256,participant_json) VALUES (?,?,?,?,?,?)",
                    (self.scope_id, receipt_key, participant_id, role, participant_sha256, participant_json),
                )
            marker_payload = {
                "receipt_key": receipt_key,
                "receipt_id": receipt_id,
                "receipt_intent_sha256": s20_result["receipt_intent_sha256"],
                "projection_set_sha256": intent["projection_set_sha256"],
                "participant_witness_sha256": participant_witness_sha256,
                "fencing_epoch": intent["fencing_epoch"],
                "state": PREPARED,
            }
            marker_hash = canonical_hash(marker_payload)
            cur.execute(
                "INSERT INTO receipt_commit_markers(scope_id,receipt_key,marker_kind,marker_hash,payload_json,created_at) VALUES (?,?,?,?,?,?)",
                (self.scope_id, receipt_key, PREPARED, marker_hash, canonical_json(marker_payload), now),
            )
            self._append_event(
                cur,
                receipt_key=receipt_key,
                event_type="RECEIPT_PREPARED",
                payload=marker_payload,
                fencing_epoch=int(intent["fencing_epoch"]),
                created_at=now,
            )
            self._fault("after_prepare")
            row = cur.execute(
                "SELECT * FROM receipt_commit_journal WHERE scope_id=? AND receipt_key=?",
                (self.scope_id, receipt_key),
            ).fetchone()
            if row is None:
                raise ReceiptCommitJournalError("receipt-journal prepare disappeared")
            return _actionless(
                PREPARED,
                "RECEIPT_INTENT_DURABLY_PREPARED",
                transaction_state=PREPARED,
                authoritative_prepared=True,
                idempotency_reserved=True,
                journal_mutation_performed=True,
                receipt_key=receipt_key,
                receipt_id=receipt_id,
                receipt_intent_sha256=s20_result["receipt_intent_sha256"],
                provenance_sha256=intent["provenance_sha256"],
                projection_set_sha256=intent["projection_set_sha256"],
                participant_witness_sha256=participant_witness_sha256,
            )

    def prepare_from_s20(
        self,
        owner_store: ReplayOwnerStore,
        *,
        s20_input: Mapping[str, Any],
        lease_token: str,
    ) -> dict[str, Any]:
        """Freshly revalidate S20, then durably prepare only this journal."""

        if not isinstance(s20_input, Mapping) or set(s20_input) != _S20_INPUT_KEYS:
            return _actionless("HOLD", "S21_INPUT_SCHEMA_INVALID")
        try:
            # S15 intentionally contains reader/clock/cohort callback
            # references.  Preserve that explicit callback boundary while
            # isolating every serialised S20 input from the caller.
            copied_input = {
                key: copy.deepcopy(value) if key in _OPAQUE_S20_INPUT_KEYS else _copy_json(value, f"s20_input.{key}")
                for key, value in s20_input.items()
            }
            s20_result = verify_receipt_intent_witness(owner_store, **copied_input)
            if s20_result.get("status") != "RECEIPT_INTENT_REVALIDATED":
                return _actionless(
                    "RECOVERY_REQUIRED" if s20_result.get("status") == "RECOVERY_REQUIRED" else "HOLD",
                    f"S20_{s20_result.get('reason', 'NOT_REVALIDATED')}",
                    s20_status=s20_result.get("status"),
                )
            self._validate_s20_result(s20_result)
            return self._prepare_transaction(s20_result=s20_result, lease_token=lease_token)
        except InjectedReceiptJournalCrash:
            raise
        except ReceiptCommitJournalError as exc:
            reason = str(exc)
            status = (
                "RECOVERY_REQUIRED"
                if reason.startswith("receipt-journal")
                or reason in {"JOURNAL_QUARANTINED", "LEASE_EXPIRED", "S20_NOT_REVALIDATED"}
                else "HOLD"
            )
            return _actionless(status, reason, s20_status="RECEIPT_INTENT_REVALIDATED")
        except (AttributeError, KeyError, TypeError, ValueError, sqlite3.Error):
            return _actionless("HOLD", "S21_SCHEMA_INVALID")

    def _read_row(self, receipt_key: str) -> sqlite3.Row:
        receipt_key = self._safe_id(receipt_key, "receipt_key")
        scope = self.conn.execute("SELECT * FROM receipt_journal_scopes WHERE scope_id=?", (self.scope_id,)).fetchone()
        if scope is None:
            raise ReceiptCommitJournalError("receipt-journal scope does not exist")
        cur = self.conn.cursor()
        try:
            self._assert_scope_integrity(cur, scope)
            row = cur.execute(
                "SELECT * FROM receipt_commit_journal WHERE scope_id=? AND receipt_key=?",
                (self.scope_id, receipt_key),
            ).fetchone()
            if row is None:
                raise ReceiptCommitJournalError("receipt-journal receipt does not exist")
            participants = cur.execute(
                "SELECT * FROM receipt_commit_participants WHERE scope_id=? AND receipt_key=? ORDER BY participant_id",
                (self.scope_id, receipt_key),
            ).fetchall()
            if {item["participant_id"] for item in participants} != set(SNAPSHOT_PARTICIPANT_IDS):
                raise ReceiptCommitJournalError("receipt-journal participant set drift")
            for item in participants:
                if canonical_hash(json.loads(item["participant_json"])) != item["participant_sha256"]:
                    raise ReceiptCommitJournalError("receipt-journal participant digest drift")
            marker = cur.execute(
                "SELECT marker_hash,payload_json FROM receipt_commit_markers WHERE scope_id=? AND receipt_key=? AND marker_kind=?",
                (self.scope_id, receipt_key, PREPARED),
            ).fetchone()
            if marker is None:
                raise ReceiptCommitJournalError("receipt-journal prepare marker missing")
            marker_payload = json.loads(marker["payload_json"])
            if canonical_hash(marker_payload) != marker["marker_hash"]:
                raise ReceiptCommitJournalError("receipt-journal marker digest drift")
            core = json.loads(row["receipt_core_json"])
            intent = json.loads(row["intent_json"])
            if (
                not isinstance(core, Mapping)
                or not isinstance(intent, Mapping)
                or core.get("receipt_key") != row["receipt_key"]
                or core.get("receipt_id") != row["receipt_id"]
                or core.get("receipt_intent_sha256") != row["receipt_intent_sha256"]
                or core.get("provenance_sha256") != row["provenance_sha256"]
                or core.get("projection_set_sha256") != row["projection_set_sha256"]
                or canonical_hash(core.get("participants")) != row["participant_witness_sha256"]
                or canonical_hash(intent) != row["receipt_intent_sha256"]
                or core.get("participants") != intent.get("participants")
                or marker_payload.get("receipt_intent_sha256") != row["receipt_intent_sha256"]
                or marker_payload.get("state") != PREPARED
                or row["state"] in {PROJECTION_PENDING, COMMITTED}
                or any(row[key] != 0 for key in ("receipt_emitted", "receipt_committed", "consume_allowed", "mutation_performed"))
            ):
                raise ReceiptCommitJournalError("receipt-journal core digest drift")
            participant_map = {
                item["participant_id"]: json.loads(item["participant_json"])
                for item in participants
            }
            if participant_map != intent.get("participants"):
                raise ReceiptCommitJournalError("receipt-journal participant content drift")
            return row
        finally:
            cur.close()

    def read_receipt(self, receipt_key: str) -> dict[str, Any]:
        try:
            row = self._read_row(receipt_key)
            if row["state"] == PREPARED:
                return self._row_result(row, status=PREPARED, reason="JOURNAL_PREPARED")
            return self._row_result(row)
        except (ReceiptCommitJournalError, TypeError, ValueError, sqlite3.Error) as exc:
            return _actionless("RECOVERY_REQUIRED", str(exc), observed_effect_state=OBSERVED_EFFECT_UNKNOWN)

    def _mark_state(
        self,
        receipt_key: str,
        *,
        target_state: str,
        observed_effect_state: str,
        reason: str,
    ) -> dict[str, Any]:
        receipt_key = self._safe_id(receipt_key, "receipt_key")
        if target_state not in {JOURNAL_IN_DOUBT, JOURNAL_RECOVERY_REQUIRED}:
            raise ReceiptCommitJournalError("unsupported explicit receipt state")
        if observed_effect_state not in _OBSERVED_EFFECT_STATES or observed_effect_state == OBSERVED_EFFECT_NONE:
            raise ReceiptCommitJournalError("external effect state must be OBSERVED or UNKNOWN")
        now = self._now()
        with self._transaction() as cur:
            scope = self._scope_row(cur, self.scope_id)
            self._assert_scope_integrity(cur, scope)
            row = cur.execute(
                "SELECT * FROM receipt_commit_journal WHERE scope_id=? AND receipt_key=?",
                (self.scope_id, receipt_key),
            ).fetchone()
            if row is None:
                raise ReceiptCommitJournalError("receipt-journal receipt does not exist")
            if scope["journal_status"] != JOURNAL_CLEAN:
                return self._row_result(row)
            if row["state"] in {JOURNAL_IN_DOUBT, JOURNAL_RECOVERY_REQUIRED, JOURNAL_QUARANTINED}:
                return self._row_result(row)
            cur.execute(
                "UPDATE receipt_commit_journal SET state=?,observed_effect_state=?,updated_at=? WHERE scope_id=? AND receipt_key=? AND state IN (?,?)",
                (target_state, observed_effect_state, now, self.scope_id, receipt_key, PREPARED, PROJECTION_PENDING),
            )
            if cur.rowcount != 1:
                raise ReceiptCommitJournalError("receipt-journal state CAS failed")
            cur.execute(
                "UPDATE receipt_journal_scopes SET journal_status=?,updated_at=? WHERE scope_id=?",
                (target_state, now, self.scope_id),
            )
            payload = {
                "receipt_key": receipt_key,
                "state": target_state,
                "observed_effect_state": observed_effect_state,
                "reason": self._text(reason, "reason"),
            }
            marker_hash = canonical_hash(payload)
            cur.execute(
                "INSERT OR IGNORE INTO receipt_commit_markers(scope_id,receipt_key,marker_kind,marker_hash,payload_json,created_at) VALUES (?,?,?,?,?,?)",
                (self.scope_id, receipt_key, target_state, marker_hash, canonical_json(payload), now),
            )
            self._append_event(
                cur,
                receipt_key=receipt_key,
                event_type=f"RECEIPT_{target_state}",
                payload=payload,
                fencing_epoch=int(row["fencing_epoch"]),
                created_at=now,
            )
            updated = cur.execute(
                "SELECT * FROM receipt_commit_journal WHERE scope_id=? AND receipt_key=?",
                (self.scope_id, receipt_key),
            ).fetchone()
            if updated is None:
                raise ReceiptCommitJournalError("receipt-journal state disappeared")
            return self._row_result(updated)

    def mark_in_doubt(self, receipt_key: str, *, reason: str, observed_effect_state: str = OBSERVED_EFFECT_UNKNOWN) -> dict[str, Any]:
        """Explicitly record uncertainty; never called automatically by prepare."""

        return self._mark_state(
            receipt_key,
            target_state=JOURNAL_IN_DOUBT,
            observed_effect_state=observed_effect_state,
            reason=reason,
        )

    def mark_recovery_required(self, receipt_key: str, *, reason: str, observed_effect_state: str = OBSERVED_EFFECT_UNKNOWN) -> dict[str, Any]:
        """Explicitly block a journal after an integrity/effect finding."""

        return self._mark_state(
            receipt_key,
            target_state=JOURNAL_RECOVERY_REQUIRED,
            observed_effect_state=observed_effect_state,
            reason=reason,
        )

    def quarantine(self, receipt_key: str, *, reason: str) -> dict[str, Any]:
        """Explicitly quarantine a prepared/uncertain entry; no repair occurs."""

        receipt_key = self._safe_id(receipt_key, "receipt_key")
        now = self._now()
        with self._transaction() as cur:
            scope = self._scope_row(cur, self.scope_id)
            self._assert_scope_integrity(cur, scope)
            row = cur.execute(
                "SELECT * FROM receipt_commit_journal WHERE scope_id=? AND receipt_key=?",
                (self.scope_id, receipt_key),
            ).fetchone()
            if row is None:
                raise ReceiptCommitJournalError("receipt-journal receipt does not exist")
            if row["state"] == JOURNAL_QUARANTINED:
                return self._row_result(row)
            if row["state"] == COMMITTED:
                raise ReceiptCommitJournalError("committed receipt cannot be quarantined")
            cur.execute(
                "UPDATE receipt_commit_journal SET state=?,observed_effect_state=?,updated_at=? WHERE scope_id=? AND receipt_key=?",
                (JOURNAL_QUARANTINED, OBSERVED_EFFECT_UNKNOWN, now, self.scope_id, receipt_key),
            )
            cur.execute(
                "UPDATE receipt_journal_scopes SET journal_status=?,updated_at=? WHERE scope_id=?",
                (JOURNAL_QUARANTINED, now, self.scope_id),
            )
            payload = {"receipt_key": receipt_key, "state": JOURNAL_QUARANTINED, "reason": self._text(reason, "reason")}
            marker_hash = canonical_hash(payload)
            cur.execute(
                "INSERT OR IGNORE INTO receipt_commit_markers(scope_id,receipt_key,marker_kind,marker_hash,payload_json,created_at) VALUES (?,?,?,?,?,?)",
                (self.scope_id, receipt_key, JOURNAL_QUARANTINED, marker_hash, canonical_json(payload), now),
            )
            self._append_event(
                cur,
                receipt_key=receipt_key,
                event_type="RECEIPT_QUARANTINED",
                payload=payload,
                fencing_epoch=int(row["fencing_epoch"]),
                created_at=now,
            )
            updated = cur.execute(
                "SELECT * FROM receipt_commit_journal WHERE scope_id=? AND receipt_key=?",
                (self.scope_id, receipt_key),
            ).fetchone()
            if updated is None:
                raise ReceiptCommitJournalError("receipt-journal quarantine disappeared")
            return self._row_result(updated)


__all__ = [
    "COMMITTED",
    "InjectedReceiptJournalCrash",
    "JOURNAL_CLEAN",
    "JOURNAL_IN_DOUBT",
    "JOURNAL_QUARANTINED",
    "JOURNAL_RECOVERY_REQUIRED",
    "OBSERVED_EFFECT_NONE",
    "OBSERVED_EFFECT_OBSERVED",
    "OBSERVED_EFFECT_UNKNOWN",
    "PREPARED",
    "PROJECTION_PENDING",
    "RECEIPT_JOURNAL_OPERATION",
    "RECEIPT_JOURNAL_ROLE",
    "RECEIPT_JOURNAL_SCHEMA",
    "ReceiptCommitJournal",
    "ReceiptCommitJournalError",
]
