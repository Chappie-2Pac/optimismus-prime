"""W5-S18 persistent replay-owner CAS store.

This module is the first stateful owner boundary after the read-only S17
preflight.  It owns only its private replay/registry SQLite store.  A single
``BEGIN IMMEDIATE`` transaction atomically checks the caller's owner fence,
state version, head and candidate, then records the idempotency result and
advances the owner state.  It never touches Prime files, queues, receipts,
workers, processes, networks or the W2.5 control plane.

The store deliberately has no automatic recovery path.  A quarantined
``IN_DOUBT``/``RECOVERY_REQUIRED`` scope remains blocked until a later,
separately reviewed recovery contract exists.
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


OWNER_STORE_SCHEMA = "prime-replay-registry-owner-store-v1"
OWNER_HEAD_SCHEMA = "prime-cross-store-replay-owner-head-v1"
OWNER_INTENT_SCHEMA = "prime-replay-registry-owner-intent-v1"
OWNER_EVENT_SCHEMA = "prime-replay-registry-owner-event-v1"
OWNER_TRANSITION_SCHEMA = "prime-replay-registry-owner-transition-v1"
OWNER_OPERATION_RECORD_SCHEMA = "prime-replay-registry-owner-operation-record-v1"
OWNER_OPERATION = "ADVANCE_REPLAY"

JOURNAL_CLEAN = "CLEAN"
JOURNAL_IN_DOUBT = "IN_DOUBT"
JOURNAL_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
_JOURNAL_STATUSES = frozenset({JOURNAL_CLEAN, JOURNAL_IN_DOUBT, JOURNAL_RECOVERY_REQUIRED})

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}\Z")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")

_SCOPE_BINDING_KEYS = frozenset(
    {
        "replay_namespace",
        "registry_id",
        "registry_version",
        "registry_epoch",
        "registry_sha256",
        "profile_set_sha256",
        "source_set_sha256",
        "cohort_binding_sha256",
        "host_id",
        "host_instance_id",
        "worker_epoch",
    }
)
_OWNER_TABLES = frozenset(
    {
        "owner_store_meta",
        "replay_owner_scopes",
        "replay_owner_operations",
        "replay_owner_transitions",
        "replay_owner_events",
    }
)

SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "001_replay_owner_v1.sql"
SCHEMA_FINGERPRINT = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()


class ReplayOwnerStoreError(ValueError):
    """Invalid store input or an integrity violation detected before mutation."""


class ReplayOwnerStore:
    """Durable owner state with fail-closed CAS and idempotency semantics."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        scope_id: str,
        owner_root: str | Path | None = None,
        timeout: float = 5.0,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.scope_id = self._safe_id(scope_id, "scope_id")
        self.db_path = self._validate_db_path(db_path, self.scope_id, owner_root)
        if not callable(clock) and clock is not None:
            raise ReplayOwnerStoreError("clock must be callable")
        preexisting_database = self.db_path.exists()
        self.clock = clock or (lambda: int(time.time()))
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
                    "schema_version": OWNER_STORE_SCHEMA,
                    "scope_id": self.scope_id,
                    "db_path": str(self.db_path.resolve(strict=False)),
                }
            )
            if tables:
                if tables != _OWNER_TABLES:
                    raise ReplayOwnerStoreError("database contains unexpected owner-store tables")
                if "owner_store_meta" not in tables:
                    raise ReplayOwnerStoreError("database is not an owner-store database")
                meta = dict(self.conn.execute("SELECT key,value FROM owner_store_meta").fetchall())
                expected = {
                    "schema_version": OWNER_STORE_SCHEMA,
                    "canonicalization": "json-sortkeys-v1",
                    "scope_id": self.scope_id,
                    "schema_fingerprint": SCHEMA_FINGERPRINT,
                    "store_identity": identity,
                }
                if any(meta.get(key) != value for key, value in expected.items()):
                    raise ReplayOwnerStoreError("owner-store schema or identity mismatch")
            else:
                if preexisting_database:
                    raise ReplayOwnerStoreError("pre-existing empty database is not an owner-store database")
                self.conn.execute("PRAGMA journal_mode = WAL")
                self.conn.execute("PRAGMA synchronous = FULL")
                self.conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
                self.conn.executemany(
                    "INSERT INTO owner_store_meta(key,value) VALUES (?,?)",
                    [
                        ("schema_version", OWNER_STORE_SCHEMA),
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
            raise ReplayOwnerStoreError("owner database path must be absolute")
        if path.name != f"{scope_id}.sqlite3":
            raise ReplayOwnerStoreError("owner database filename must be scope-id.sqlite3")
        if owner_root is None:
            raise ReplayOwnerStoreError("owner root must be explicitly configured")
        root = Path(owner_root)
        if not root.is_absolute():
            raise ReplayOwnerStoreError("owner root must be absolute")
        if root.exists() and root.is_symlink():
            raise ReplayOwnerStoreError("owner root must not be a symlink")
        if path.exists() and path.is_symlink():
            raise ReplayOwnerStoreError("owner database must not be a symlink")
        if path.parent.resolve(strict=False) != root.resolve(strict=False):
            raise ReplayOwnerStoreError("owner database is outside the owner root")
        cursor = root
        while True:
            if cursor.exists() and cursor.is_symlink():
                raise ReplayOwnerStoreError("owner database parent must not contain symlinks")
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        if not root.exists() or not root.is_dir():
            raise ReplayOwnerStoreError("owner root must be an existing directory")
        return path

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "ReplayOwnerStore":
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
            # A crash after COMMIT but before the caller receives the answer
            # must be recovered by the idempotency lookup, never by guessing.
            self._fault("after_commit")
        finally:
            cursor.close()

    def _fault(self, point: str) -> None:
        # Production store has no caller callback surface.  The test harness
        # may subclass this private no-op to inject a deterministic crash.
        del point

    def _now_epoch(self) -> int:
        return self._integer(self.clock(), "owner clock")

    @staticmethod
    def _text(value: Any, label: str) -> str:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ReplayOwnerStoreError(f"{label} must be non-empty text")
        return value

    @classmethod
    def _safe_id(cls, value: Any, label: str) -> str:
        value = cls._text(value, label)
        if _SAFE_ID.fullmatch(value) is None:
            raise ReplayOwnerStoreError(f"{label} is not a safe identifier")
        return value

    @classmethod
    def _idempotency_key(cls, value: Any) -> str:
        value = cls._text(value, "idempotency_key")
        if _IDEMPOTENCY.fullmatch(value) is None:
            raise ReplayOwnerStoreError("idempotency_key is not safe")
        return value

    @classmethod
    def _hash(cls, value: Any, label: str, *, optional: bool = False) -> str | None:
        if value is None and optional:
            return None
        value = cls._text(value, label)
        if _HEX64.fullmatch(value) is None:
            raise ReplayOwnerStoreError(f"{label} must be a lowercase SHA-256")
        return value

    @classmethod
    def _lease_token_hash(cls, value: Any, label: str = "lease_token") -> str:
        value = cls._text(value, label)
        if len(value) < 16:
            raise ReplayOwnerStoreError(f"{label} must contain at least 16 characters")
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ReplayOwnerStoreError(f"{label} must be an integer >= {minimum}")
        return value

    def _owned_scope(self, value: Any) -> str:
        scope_id = self._safe_id(value, "scope_id")
        if scope_id != self.scope_id:
            raise ReplayOwnerStoreError("scope_id is not owned by this store")
        return scope_id

    @classmethod
    def _mapping(cls, value: Any, label: str) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ReplayOwnerStoreError(f"{label} must be a mapping")
        try:
            isolated = copy.deepcopy(dict(value))
            canonical_json(isolated)
        except (TypeError, ValueError, copy.Error) as exc:
            raise ReplayOwnerStoreError(f"{label} is not canonical JSON") from exc
        return isolated

    @classmethod
    def _scope_binding(cls, value: Mapping[str, Any]) -> dict[str, Any]:
        binding = cls._mapping(value, "scope_binding")
        if set(binding) != set(_SCOPE_BINDING_KEYS):
            raise ReplayOwnerStoreError("scope_binding keys are not exact")
        for key in ("replay_namespace", "registry_id", "registry_version", "host_id", "host_instance_id"):
            binding[key] = cls._safe_id(binding[key], f"scope_binding.{key}")
        for key in ("registry_epoch", "worker_epoch"):
            binding[key] = cls._integer(binding[key], f"scope_binding.{key}")
        for key in ("registry_sha256", "profile_set_sha256", "source_set_sha256", "cohort_binding_sha256"):
            binding[key] = cls._hash(binding[key], f"scope_binding.{key}")
        return {key: binding[key] for key in sorted(binding)}

    @classmethod
    def _validate_owner(cls, owner_id: Any, owner_instance_id: Any, owner_epoch: Any, fencing_epoch: Any) -> tuple[str, str, int, int]:
        return (
            cls._safe_id(owner_id, "owner_id"),
            cls._safe_id(owner_instance_id, "owner_instance_id"),
            cls._integer(owner_epoch, "owner_epoch"),
            cls._integer(fencing_epoch, "fencing_epoch"),
        )

    @staticmethod
    def _row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    @classmethod
    def _state_from_row(cls, row: sqlite3.Row | Mapping[str, Any] | None) -> dict[str, Any]:
        if row is None:
            raise ReplayOwnerStoreError("owner scope does not exist")
        state = dict(row)
        try:
            binding = json.loads(state["scope_binding_json"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ReplayOwnerStoreError("owner scope binding is corrupt") from exc
        if not isinstance(binding, dict) or canonical_hash(binding) != state["scope_binding_sha256"]:
            raise ReplayOwnerStoreError("owner scope binding digest mismatch")
        state["scope_binding"] = binding
        del state["scope_binding_json"]
        return state

    @classmethod
    def _operation_index_entry(cls, row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "idempotency_key": row["idempotency_key"],
            "transaction_id": row["transaction_id"],
            "operation": row["operation"],
            "intent_sha256": row["intent_sha256"],
            "state_version_before": row["state_version_before"],
            "state_version_after": row["state_version_after"],
            "sequence_before": row["sequence_before"],
            "sequence_after": row["sequence_after"],
            "head_before_sha256": row["head_before_sha256"],
            "fencing_epoch": row["fencing_epoch"],
        }

    @classmethod
    def _idempotency_index_hash(cls, cur: sqlite3.Cursor, scope_id: str) -> str:
        entries = [
            cls._operation_index_entry(row)
            for row in cur.execute(
                "SELECT idempotency_key,transaction_id,operation,intent_sha256,state_version_before,state_version_after,sequence_before,sequence_after,head_before_sha256,fencing_epoch FROM replay_owner_operations WHERE scope_id=? ORDER BY idempotency_key",
                (scope_id,),
            ).fetchall()
        ]
        return canonical_hash({"entries": entries})

    @classmethod
    def _idempotency_index_hash_with_extra(
        cls, cur: sqlite3.Cursor, scope_id: str, *, entry: Mapping[str, Any]
    ) -> str:
        entries = [
            cls._operation_index_entry(row)
            for row in cur.execute(
                "SELECT idempotency_key,transaction_id,operation,intent_sha256,state_version_before,state_version_after,sequence_before,sequence_after,head_before_sha256,fencing_epoch FROM replay_owner_operations WHERE scope_id=? ORDER BY idempotency_key",
                (scope_id,),
            ).fetchall()
        ]
        entries.append(cls._operation_index_entry(entry))
        entries.sort(key=lambda item: item["idempotency_key"])
        return canonical_hash({"entries": entries})

    @classmethod
    def _assert_index_digest(cls, cur: sqlite3.Cursor, state: Mapping[str, Any]) -> None:
        if state["idempotency_index_sha256"] != cls._idempotency_index_hash(cur, state["scope_id"]):
            raise ReplayOwnerStoreError("owner idempotency index digest mismatch")

    @classmethod
    def _operation_record_core(cls, cur: sqlite3.Cursor, row: Mapping[str, Any]) -> dict[str, Any]:
        transition = cur.execute(
            "SELECT transition_sha256 FROM replay_owner_transitions WHERE scope_id=? AND idempotency_key=?",
            (row["scope_id"], row["idempotency_key"]),
        ).fetchone()
        if transition is None:
            raise ReplayOwnerStoreError("owner operation transition is missing")
        return {
            "schema_version": OWNER_OPERATION_RECORD_SCHEMA,
            "scope_id": row["scope_id"],
            "idempotency_key": row["idempotency_key"],
            "transaction_id": row["transaction_id"],
            "operation": row["operation"],
            "intent_sha256": row["intent_sha256"],
            "state_version_before": row["state_version_before"],
            "state_version_after": row["state_version_after"],
            "sequence_before": row["sequence_before"],
            "sequence_after": row["sequence_after"],
            "head_before_sha256": row["head_before_sha256"],
            "head_after_sha256": row["head_after_sha256"],
            "fencing_epoch": row["fencing_epoch"],
            "result_sha256": row["result_sha256"],
            "idempotency_index_after_sha256": row["idempotency_index_after_sha256"],
            "transition_sha256": transition[0],
        }

    @classmethod
    def _assert_transition_integrity(cls, cur: sqlite3.Cursor, state: Mapping[str, Any]) -> None:
        state_version = int(state["state_version"])
        baseline = int(state["baseline_state_version"])
        if state_version < baseline:
            raise ReplayOwnerStoreError("owner state version precedes baseline")
        expected_head = cls._head_from_state(state)
        if expected_head != state["head_sha256"]:
            raise ReplayOwnerStoreError("owner head does not match canonical state")
        rows = cur.execute(
            "SELECT * FROM replay_owner_transitions WHERE scope_id=? ORDER BY after_state_version",
            (state["scope_id"],),
        ).fetchall()
        if not rows:
            if state_version != baseline:
                raise ReplayOwnerStoreError("owner transition history is incomplete")
            return
        previous_transition_sha256 = None
        expected_after = baseline + 1
        for row in rows:
            if int(row["after_state_version"]) != expected_after:
                raise ReplayOwnerStoreError("owner transition version gap")
            if int(row["before_state_version"]) != expected_after - 1:
                raise ReplayOwnerStoreError("owner transition parent version mismatch")
            if row["parent_transition_sha256"] != previous_transition_sha256:
                raise ReplayOwnerStoreError("owner transition parent digest mismatch")
            core = {
                "schema_version": OWNER_TRANSITION_SCHEMA,
                "scope_id": row["scope_id"],
                "after_state_version": row["after_state_version"],
                "transaction_id": row["transaction_id"],
                "idempotency_key": row["idempotency_key"],
                "parent_head_sha256": row["parent_head_sha256"],
                "new_head_sha256": row["new_head_sha256"],
                "before_state_version": row["before_state_version"],
                "fencing_epoch": row["fencing_epoch"],
                "parent_transition_sha256": row["parent_transition_sha256"],
            }
            if canonical_hash(core) != row["transition_sha256"]:
                raise ReplayOwnerStoreError("owner transition digest mismatch")
            operation = cur.execute(
                "SELECT * FROM replay_owner_operations WHERE scope_id=? AND idempotency_key=?",
                (state["scope_id"], row["idempotency_key"]),
            ).fetchone()
            if operation is None or operation["transaction_id"] != row["transaction_id"] or operation["head_after_sha256"] != row["new_head_sha256"] or int(operation["state_version_after"]) != int(row["after_state_version"]):
                raise ReplayOwnerStoreError("owner transition operation binding mismatch")
            try:
                stored_result = json.loads(operation["result_json"])
            except (TypeError, ValueError) as exc:
                raise ReplayOwnerStoreError("owner operation result is corrupt") from exc
            if not isinstance(stored_result, dict) or canonical_hash(stored_result) != operation["result_sha256"]:
                raise ReplayOwnerStoreError("owner operation result digest mismatch")
            if operation["operation_record_sha256"] != canonical_hash(cls._operation_record_core(cur, operation)):
                raise ReplayOwnerStoreError("owner operation record digest mismatch")
            event = cur.execute(
                "SELECT * FROM replay_owner_events WHERE scope_id=? AND event_type='OWNER_CAS_COMMITTED' AND idempotency_key=? AND state_version=?",
                (state["scope_id"], row["idempotency_key"], row["after_state_version"]),
            ).fetchone()
            if event is None:
                raise ReplayOwnerStoreError("owner transition event is missing")
            try:
                payload = json.loads(event["payload_json"])
            except (TypeError, ValueError) as exc:
                raise ReplayOwnerStoreError("owner transition event is corrupt") from exc
            event_core = {
                "schema_version": OWNER_EVENT_SCHEMA,
                "scope_id": event["scope_id"],
                "event_seq": event["event_seq"],
                "event_type": event["event_type"],
                "idempotency_key": event["idempotency_key"],
                "state_version": event["state_version"],
                "payload": payload,
            }
            if canonical_hash(event_core) != event["event_sha256"]:
                raise ReplayOwnerStoreError("owner transition event digest mismatch")
            if payload.get("transition_sha256") != row["transition_sha256"]:
                raise ReplayOwnerStoreError("owner transition event binding mismatch")
            previous_transition_sha256 = row["transition_sha256"]
            expected_after += 1
        if expected_after - 1 != state_version:
            raise ReplayOwnerStoreError("owner transition history does not reach current state")

    @classmethod
    def _result_base(cls, status: str, decision: str, reason: str, *, mutated: bool = False) -> dict[str, Any]:
        return {
            "schema_version": OWNER_STORE_SCHEMA,
            "status": status,
            "decision": decision,
            "reason": reason,
            "permission": "owner_store_cas" if mutated else "read_only_result",
            "owner_state_advanced": mutated,
            "idempotency_reserved": mutated,
            "cas_authorized": mutated,
            "consume_allowed": False,
            "receipt_emitted": False,
            "recovery_allowed": False,
            "mutation_performed": mutated,
            "external_action": False,
            "execution": {
                "consume": False,
                "receipt": False,
                "recovery": False,
                "process": False,
                "network": False,
            },
        }

    @classmethod
    def _recovery_result(cls, reason: str) -> dict[str, Any]:
        result = cls._result_base("RECOVERY_REQUIRED", "HOLD", reason)
        result["recovery_required"] = True
        return result

    @classmethod
    def _head_core(
        cls,
        *,
        scope_binding: Mapping[str, Any],
        state_version: int,
        sequence: int,
        attestation_set_sha256: str | None,
        nonce_sha256: str | None,
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        idempotency_index_sha256: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": OWNER_HEAD_SCHEMA,
            "owner_id": owner_id,
            "owner_instance_id": owner_instance_id,
            "replay_namespace": scope_binding["replay_namespace"],
            "registry_id": scope_binding["registry_id"],
            "registry_version": scope_binding["registry_version"],
            "registry_epoch": scope_binding["registry_epoch"],
            "registry_sha256": scope_binding["registry_sha256"],
            "profile_set_sha256": scope_binding["profile_set_sha256"],
            "source_set_sha256": scope_binding["source_set_sha256"],
            "cohort_binding_sha256": scope_binding["cohort_binding_sha256"],
            "host_id": scope_binding["host_id"],
            "host_instance_id": scope_binding["host_instance_id"],
            "worker_epoch": scope_binding["worker_epoch"],
            "state_version": state_version,
            "owner_epoch": owner_epoch,
            "fencing_epoch": fencing_epoch,
            "last_sequence": sequence,
            "last_attestation_set_sha256": attestation_set_sha256,
            "last_nonce_sha256": nonce_sha256,
            "idempotency_index_sha256": idempotency_index_sha256,
        }

    @classmethod
    def _head_from_state(cls, state: Mapping[str, Any]) -> str | None:
        if int(state["state_version"]) == 0:
            return None
        return canonical_hash(
            cls._head_core(
                scope_binding=state["scope_binding"],
                state_version=int(state["state_version"]),
                sequence=int(state["sequence"]),
                attestation_set_sha256=state["attestation_set_sha256"],
                nonce_sha256=state["nonce_sha256"],
                owner_id=state["owner_id"],
                owner_instance_id=state["owner_instance_id"],
                owner_epoch=int(state["owner_epoch"]),
                fencing_epoch=int(state["fencing_epoch"]),
                idempotency_index_sha256=state["idempotency_index_sha256"],
            )
        )

    @classmethod
    def _event(
        cls,
        cur: sqlite3.Cursor,
        *,
        scope_id: str,
        event_type: str,
        idempotency_key: str | None,
        state_version: int,
        payload: Mapping[str, Any],
        created_at: int,
    ) -> str:
        row = cur.execute("SELECT event_seq FROM replay_owner_scopes WHERE scope_id=?", (scope_id,)).fetchone()
        if row is None:
            raise ReplayOwnerStoreError("owner scope disappeared during transaction")
        event_seq = int(row[0]) + 1
        core = {
            "schema_version": OWNER_EVENT_SCHEMA,
            "scope_id": scope_id,
            "event_seq": event_seq,
            "event_type": event_type,
            "idempotency_key": idempotency_key,
            "state_version": state_version,
            "payload": cls._mapping(payload, "event payload"),
        }
        event_sha256 = canonical_hash(core)
        cur.execute(
            "INSERT INTO replay_owner_events(scope_id,event_seq,event_type,idempotency_key,state_version,event_sha256,payload_json,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                scope_id,
                event_seq,
                event_type,
                idempotency_key,
                state_version,
                event_sha256,
                canonical_json(core["payload"]),
                created_at,
            ),
        )
        cur.execute("UPDATE replay_owner_scopes SET event_seq=? WHERE scope_id=?", (event_seq, scope_id))
        return event_sha256

    def create_scope(
        self,
        *,
        scope_id: str,
        scope_binding: Mapping[str, Any],
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        lease_token: str,
        lease_expires_at: int,
        initial_state_version: int = 0,
        initial_sequence: int = 0,
        initial_attestation_set_sha256: str | None = None,
        initial_nonce_sha256: str | None = None,
        initial_head_sha256: str | None = None,
        initial_idempotency_index_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Create one isolated owner scope; duplicate creation is rejected."""

        scope_id = self._owned_scope(scope_id)
        binding = self._scope_binding(scope_binding)
        owner_id, owner_instance_id, owner_epoch, fencing_epoch = self._validate_owner(
            owner_id, owner_instance_id, owner_epoch, fencing_epoch
        )
        lease_token_sha256 = self._lease_token_hash(lease_token)
        lease_expires_at = self._integer(lease_expires_at, "lease_expires_at")
        now_epoch = self._now_epoch()
        initial_state_version = self._integer(initial_state_version, "initial_state_version")
        initial_sequence = self._integer(initial_sequence, "initial_sequence")
        initial_attestation_set_sha256 = self._hash(
            initial_attestation_set_sha256, "initial_attestation_set_sha256", optional=True
        )
        initial_nonce_sha256 = self._hash(initial_nonce_sha256, "initial_nonce_sha256", optional=True)
        initial_head_sha256 = self._hash(initial_head_sha256, "initial_head_sha256", optional=True)
        initial_idempotency_index_sha256 = self._hash(
            initial_idempotency_index_sha256, "initial_idempotency_index_sha256", optional=True
        ) or canonical_hash({"entries": []})
        if initial_state_version == 0 and (
            initial_sequence != 0
            or any(value is not None for value in (initial_attestation_set_sha256, initial_nonce_sha256, initial_head_sha256))
            or initial_idempotency_index_sha256 != canonical_hash({"entries": []})
        ):
            raise ReplayOwnerStoreError("zero baseline requires an empty owner head and idempotency index")
        if initial_state_version > 0 and initial_head_sha256 is None:
            raise ReplayOwnerStoreError("non-zero baseline requires a canonical owner head")
        if initial_sequence > 0 and any(value is None for value in (initial_attestation_set_sha256, initial_nonce_sha256)):
            raise ReplayOwnerStoreError("non-zero sequence requires accepted set and nonce")
        expected_initial_head = None
        if initial_state_version > 0:
            expected_initial_head = canonical_hash(
                self._head_core(
                    scope_binding=binding,
                    state_version=initial_state_version,
                    sequence=initial_sequence,
                    attestation_set_sha256=initial_attestation_set_sha256,
                    nonce_sha256=initial_nonce_sha256,
                    owner_id=owner_id,
                    owner_instance_id=owner_instance_id,
                    owner_epoch=owner_epoch,
                    fencing_epoch=fencing_epoch,
                    idempotency_index_sha256=initial_idempotency_index_sha256,
                )
            )
            if initial_head_sha256 != expected_initial_head:
                raise ReplayOwnerStoreError("initial owner head does not match canonical state")
        binding_json = canonical_json(binding)
        binding_sha256 = canonical_hash(binding)
        try:
            with self._transaction() as cur:
                if cur.execute("SELECT 1 FROM replay_owner_scopes WHERE scope_id=?", (scope_id,)).fetchone() is not None:
                    raise ReplayOwnerStoreError("owner scope already exists")
                cur.execute(
                    "INSERT INTO replay_owner_scopes(scope_id,scope_binding_json,scope_binding_sha256,baseline_state_version,state_version,head_sha256,sequence,attestation_set_sha256,nonce_sha256,owner_id,owner_instance_id,owner_epoch,fencing_epoch,lease_token_sha256,lease_expires_at,idempotency_index_sha256,journal_status,event_seq,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        scope_id,
                        binding_json,
                        binding_sha256,
                        initial_state_version,
                        initial_state_version,
                        initial_head_sha256,
                        initial_sequence,
                        initial_attestation_set_sha256,
                        initial_nonce_sha256,
                        owner_id,
                        owner_instance_id,
                        owner_epoch,
                        fencing_epoch,
                        lease_token_sha256,
                        lease_expires_at,
                        initial_idempotency_index_sha256,
                        JOURNAL_CLEAN,
                        0,
                        now_epoch,
                    ),
                )
                self._event(
                    cur,
                    scope_id=scope_id,
                    event_type="OWNER_SCOPE_CREATED",
                    idempotency_key=None,
                    state_version=initial_state_version,
                    payload={"owner_id": owner_id, "fencing_epoch": fencing_epoch},
                    created_at=now_epoch,
                )
        except sqlite3.Error as exc:
            raise ReplayOwnerStoreError("owner scope creation failed") from exc
        return self.read_state(scope_id)

    def read_state(self, scope_id: str) -> dict[str, Any]:
        scope_id = self._owned_scope(scope_id)
        try:
            row = self.conn.execute("SELECT * FROM replay_owner_scopes WHERE scope_id=?", (scope_id,)).fetchone()
        except sqlite3.Error as exc:
            raise ReplayOwnerStoreError("owner state could not be read") from exc
        state = self._state_from_row(row)
        if state["scope_id"] != scope_id or state["journal_status"] not in _JOURNAL_STATUSES:
            raise ReplayOwnerStoreError("owner state is corrupt")
        cursor = self.conn.cursor()
        try:
            self._assert_index_digest(cursor, state)
            self._assert_transition_integrity(cursor, state)
        finally:
            cursor.close()
        return state

    def resolve_operation(self, scope_id: str, idempotency_key: str) -> dict[str, Any]:
        """Resolve a committed owner operation without a lease or a retry write."""

        scope_id = self._owned_scope(scope_id)
        idempotency_key = self._idempotency_key(idempotency_key)
        try:
            state = self.read_state(scope_id)
        except ReplayOwnerStoreError:
            return self._recovery_result("OWNER_STATE_CORRUPT")
        if state["journal_status"] != JOURNAL_CLEAN:
            return self._recovery_result("OWNER_JOURNAL_QUARANTINED")
        row = self.conn.execute(
            "SELECT * FROM replay_owner_operations WHERE scope_id=? AND idempotency_key=?",
            (scope_id, idempotency_key),
        ).fetchone()
        if row is None:
            result = self._result_base("UNRESOLVED", "NOT_FOUND", "IDEMPOTENCY_NOT_FOUND")
            result["idempotency_key"] = idempotency_key
            return result
        cursor = self.conn.cursor()
        try:
            stored = json.loads(row["result_json"])
            operation_record_sha256 = canonical_hash(self._operation_record_core(cursor, row))
        except (TypeError, ValueError, ReplayOwnerStoreError):
            return self._recovery_result("OWNER_OPERATION_RECORD_DRIFT")
        finally:
            cursor.close()
        if not isinstance(stored, dict) or canonical_hash(stored) != row["result_sha256"] or operation_record_sha256 != row["operation_record_sha256"]:
            return self._recovery_result("OWNER_OPERATION_RECORD_DRIFT")
        original_result = dict(stored)
        original_result["idempotency_index_sha256_after"] = row["idempotency_index_after_sha256"]
        original_result["operation_record_sha256"] = row["operation_record_sha256"]
        result = self._result_base("REPLAYED", "IDEMPOTENT_REPLAY", "IDEMPOTENCY_EXACT")
        result.update({"idempotency_key": idempotency_key, "intent_sha256": row["intent_sha256"], "original_result": original_result})
        return result

    def quarantine_scope(self, scope_id: str, *, status: str = JOURNAL_IN_DOUBT) -> dict[str, Any]:
        """Persist a fail-closed quarantine marker; this never performs recovery."""

        scope_id = self._owned_scope(scope_id)
        if status not in {JOURNAL_IN_DOUBT, JOURNAL_RECOVERY_REQUIRED}:
            raise ReplayOwnerStoreError("quarantine status must be IN_DOUBT or RECOVERY_REQUIRED")
        now_epoch = self._now_epoch()
        try:
            with self._transaction() as cur:
                row = cur.execute("SELECT state_version FROM replay_owner_scopes WHERE scope_id=?", (scope_id,)).fetchone()
                if row is None:
                    raise ReplayOwnerStoreError("owner scope does not exist")
                state_version = int(row[0])
                cur.execute(
                    "UPDATE replay_owner_scopes SET state_version=?,journal_status=?,updated_at=? WHERE scope_id=?",
                    (state_version, status, now_epoch, scope_id),
                )
                self._event(
                    cur,
                    scope_id=scope_id,
                    event_type="OWNER_SCOPE_QUARANTINED",
                    idempotency_key=None,
                    state_version=state_version,
                    payload={"journal_status": status},
                    created_at=now_epoch,
                )
        except sqlite3.Error as exc:
            raise ReplayOwnerStoreError("owner quarantine failed") from exc
        return self.read_state(scope_id)

    def reclaim_fence(
        self,
        *,
        scope_id: str,
        expected_owner_id: str,
        expected_fencing_epoch: int,
        expected_lease_token: str,
        new_owner_id: str,
        new_owner_instance_id: str,
        new_owner_epoch: int,
        new_lease_token: str,
        new_lease_expires_at: int,
    ) -> dict[str, Any]:
        """Atomically reclaim an expired fence; no replay state is advanced."""

        scope_id = self._owned_scope(scope_id)
        expected_owner_id = self._safe_id(expected_owner_id, "expected_owner_id")
        expected_fencing_epoch = self._integer(expected_fencing_epoch, "expected_fencing_epoch")
        expected_lease_token_sha256 = self._lease_token_hash(expected_lease_token, "expected_lease_token")
        new_owner_id, new_owner_instance_id, new_owner_epoch, _ = self._validate_owner(
            new_owner_id, new_owner_instance_id, new_owner_epoch, expected_fencing_epoch + 1
        )
        new_lease_token_sha256 = self._lease_token_hash(new_lease_token, "new_lease_token")
        new_lease_expires_at = self._integer(new_lease_expires_at, "new_lease_expires_at")
        now_epoch = self._now_epoch()
        try:
            with self._transaction() as cur:
                row = cur.execute("SELECT * FROM replay_owner_scopes WHERE scope_id=?", (scope_id,)).fetchone()
                try:
                    state = self._state_from_row(row)
                    self._assert_index_digest(cur, state)
                    self._assert_transition_integrity(cur, state)
                except ReplayOwnerStoreError:
                    return self._recovery_result("OWNER_STATE_CORRUPT")
                if state["journal_status"] != JOURNAL_CLEAN:
                    return self._recovery_result("OWNER_JOURNAL_QUARANTINED")
                if (
                    state["owner_id"] != expected_owner_id
                    or state["fencing_epoch"] != expected_fencing_epoch
                    or state["lease_token_sha256"] != expected_lease_token_sha256
                ):
                    return self._result_base("HOLD", "FENCE_REJECTED", "FENCE_EXPECTATION_MISMATCH")
                if int(state["lease_expires_at"]) > now_epoch:
                    return self._result_base("HOLD", "FENCE_REJECTED", "FENCE_NOT_EXPIRED")
                if new_owner_epoch <= int(state["owner_epoch"]):
                    return self._result_base("HOLD", "FENCE_REJECTED", "OWNER_EPOCH_NOT_MONOTONE")
                next_fencing_epoch = expected_fencing_epoch + 1
                cur.execute(
                    "UPDATE replay_owner_scopes SET owner_id=?,owner_instance_id=?,owner_epoch=?,fencing_epoch=?,lease_token_sha256=?,lease_expires_at=?,updated_at=? WHERE scope_id=? AND state_version=? AND fencing_epoch=? AND lease_token_sha256=?",
                    (
                        new_owner_id,
                        new_owner_instance_id,
                        new_owner_epoch,
                        next_fencing_epoch,
                        new_lease_token_sha256,
                        new_lease_expires_at,
                        now_epoch,
                        scope_id,
                        state["state_version"],
                        expected_fencing_epoch,
                        expected_lease_token_sha256,
                    ),
                )
                if cur.rowcount != 1:
                    return self._result_base("HOLD", "FENCE_REJECTED", "FENCE_CAS_MISMATCH")
                self._event(
                    cur,
                    scope_id=scope_id,
                    event_type="OWNER_FENCE_RECLAIMED",
                    idempotency_key=None,
                    state_version=state["state_version"],
                    payload={
                        "previous_owner_id": expected_owner_id,
                        "owner_id": new_owner_id,
                        "fencing_epoch": next_fencing_epoch,
                    },
                    created_at=now_epoch,
                )
                result = self._result_base("OWNER_FENCE_RECLAIMED", "FENCE_ADVANCED", "FENCE_EXPIRED", mutated=True)
                result.update(
                    {
                        "owner_state_advanced": False,
                        "idempotency_reserved": False,
                        "cas_authorized": False,
                        "mutation_performed": True,
                        "permission": "owner_store_fence",
                        "fencing_epoch": next_fencing_epoch,
                        "state_version": state["state_version"],
                    }
                )
                return result
        except sqlite3.Error as exc:
            return self._recovery_result("OWNER_STORE_SQLITE_ERROR")

    def _advance_validated(
        self,
        *,
        scope_id: str,
        scope_binding: Mapping[str, Any],
        owner_id: str,
        owner_instance_id: str,
        owner_epoch: int,
        fencing_epoch: int,
        lease_token: str,
        idempotency_key: str,
        transaction_id: str,
        operation: str,
        intent: Mapping[str, Any],
        expected_state_version: int,
        expected_head_sha256: str | None,
        expected_sequence: int,
        next_sequence: int,
        next_attestation_set_sha256: str,
        next_nonce_sha256: str,
        expected_next_head_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Atomically reserve/advance one replay candidate or fail closed."""

        scope_id = self._owned_scope(scope_id)
        binding = self._scope_binding(scope_binding)
        owner_id, owner_instance_id, owner_epoch, fencing_epoch = self._validate_owner(
            owner_id, owner_instance_id, owner_epoch, fencing_epoch
        )
        lease_token_sha256 = self._lease_token_hash(lease_token)
        idempotency_key = self._idempotency_key(idempotency_key)
        transaction_id = self._safe_id(transaction_id, "transaction_id")
        operation = self._safe_id(operation, "operation")
        if operation != OWNER_OPERATION:
            raise ReplayOwnerStoreError("unsupported owner operation")
        intent = self._mapping(intent, "intent")
        expected_state_version = self._integer(expected_state_version, "expected_state_version")
        expected_head_sha256 = self._hash(expected_head_sha256, "expected_head_sha256", optional=True)
        expected_sequence = self._integer(expected_sequence, "expected_sequence")
        next_sequence = self._integer(next_sequence, "next_sequence")
        next_attestation_set_sha256 = self._hash(next_attestation_set_sha256, "next_attestation_set_sha256")
        next_nonce_sha256 = self._hash(next_nonce_sha256, "next_nonce_sha256")
        expected_next_head_sha256 = self._hash(expected_next_head_sha256, "expected_next_head_sha256", optional=True)
        now_epoch = self._now_epoch()

        intent_material = {
            "schema_version": OWNER_INTENT_SCHEMA,
            "scope_id": scope_id,
            "scope_binding_sha256": canonical_hash(binding),
            "transaction_id": transaction_id,
            "idempotency_key": idempotency_key,
            "operation": operation,
            "intent": intent,
            "expected_state_version": expected_state_version,
            "expected_head_sha256": expected_head_sha256,
            "expected_sequence": expected_sequence,
            "next_sequence": next_sequence,
            "next_attestation_set_sha256": next_attestation_set_sha256,
            "next_nonce_sha256": next_nonce_sha256,
            "expected_next_head_sha256": expected_next_head_sha256,
        }
        intent_sha256 = canonical_hash(intent_material)
        binding_sha256 = canonical_hash(binding)

        try:
            with self._transaction() as cur:
                row = cur.execute("SELECT * FROM replay_owner_scopes WHERE scope_id=?", (scope_id,)).fetchone()
                try:
                    state = self._state_from_row(row)
                except ReplayOwnerStoreError:
                    return self._recovery_result("OWNER_STATE_CORRUPT")
                try:
                    self._assert_index_digest(cur, state)
                    self._assert_transition_integrity(cur, state)
                except ReplayOwnerStoreError:
                    return self._recovery_result("OWNER_INDEX_DRIFT")
                if state["scope_binding_sha256"] != binding_sha256:
                    return self._result_base("HOLD", "REJECTED", "OWNER_SCOPE_MISMATCH")
                if state["journal_status"] != JOURNAL_CLEAN:
                    return self._recovery_result("OWNER_JOURNAL_QUARANTINED")

                existing = cur.execute(
                    "SELECT * FROM replay_owner_operations WHERE scope_id=? AND idempotency_key=?",
                    (scope_id, idempotency_key),
                ).fetchone()
                existing_transaction = cur.execute(
                    "SELECT idempotency_key,intent_sha256 FROM replay_owner_operations WHERE scope_id=? AND transaction_id=?",
                    (scope_id, transaction_id),
                ).fetchone()
                if existing_transaction is not None and existing_transaction["idempotency_key"] != idempotency_key:
                    result = self._result_base("CONFLICT", "HOLD", "TRANSACTION_ID_CONFLICT")
                    result.update({"transaction_id": transaction_id, "existing_idempotency_key": existing_transaction["idempotency_key"]})
                    return result
                if existing is not None:
                    if existing["intent_sha256"] != intent_sha256:
                        result = self._result_base("CONFLICT", "HOLD", "IDEMPOTENCY_INTENT_CONFLICT")
                        result.update({"idempotency_key": idempotency_key, "existing_intent_sha256": existing["intent_sha256"]})
                        return result
                    try:
                        stored = json.loads(existing["result_json"])
                    except (TypeError, ValueError):
                        return self._recovery_result("OWNER_IDEMPOTENCY_RESULT_CORRUPT")
                    if not isinstance(stored, dict) or canonical_hash(stored) != existing["result_sha256"]:
                        return self._recovery_result("OWNER_IDEMPOTENCY_RESULT_DRIFT")
                    try:
                        operation_record_sha256 = canonical_hash(self._operation_record_core(cur, existing))
                    except ReplayOwnerStoreError:
                        return self._recovery_result("OWNER_OPERATION_RECORD_DRIFT")
                    if existing["operation_record_sha256"] != operation_record_sha256:
                        return self._recovery_result("OWNER_OPERATION_RECORD_DRIFT")
                    result = self._result_base("REPLAYED", "IDEMPOTENT_REPLAY", "IDEMPOTENCY_EXACT")
                    original_result = dict(stored)
                    original_result["idempotency_index_sha256_after"] = existing["idempotency_index_after_sha256"]
                    original_result["operation_record_sha256"] = existing["operation_record_sha256"]
                    result.update({"idempotency_key": idempotency_key, "intent_sha256": intent_sha256, "original_result": original_result})
                    return result

                if state["owner_id"] != owner_id or state["owner_instance_id"] != owner_instance_id:
                    return self._result_base("HOLD", "FENCE_REJECTED", "OWNER_IDENTITY_MISMATCH")
                if state["owner_epoch"] != owner_epoch or state["fencing_epoch"] != fencing_epoch:
                    return self._result_base("HOLD", "FENCE_REJECTED", "FENCING_EPOCH_MISMATCH")
                if state["lease_token_sha256"] != lease_token_sha256:
                    return self._result_base("HOLD", "FENCE_REJECTED", "LEASE_TOKEN_MISMATCH")
                if int(state["lease_expires_at"]) <= now_epoch:
                    return self._result_base("HOLD", "FENCE_REJECTED", "FENCE_EXPIRED")
                if state["state_version"] != expected_state_version or state["sequence"] != expected_sequence or state["head_sha256"] != expected_head_sha256:
                    return self._result_base("HOLD", "CAS_REJECTED", "STATE_CAS_MISMATCH")
                if next_sequence != expected_sequence + 1:
                    return self._result_base("HOLD", "CAS_REJECTED", "SEQUENCE_NOT_MONOTONE")

                next_state_version = expected_state_version + 1
                next_index_entry = {
                    "idempotency_key": idempotency_key,
                    "transaction_id": transaction_id,
                    "operation": operation,
                    "intent_sha256": intent_sha256,
                    "state_version_before": expected_state_version,
                    "state_version_after": next_state_version,
                    "sequence_before": expected_sequence,
                    "sequence_after": next_sequence,
                    "head_before_sha256": state["head_sha256"],
                    "fencing_epoch": fencing_epoch,
                }
                next_idempotency_index_sha256 = self._idempotency_index_hash_with_extra(
                    cur, scope_id, entry=next_index_entry
                )
                head_core = self._head_core(
                    scope_binding=state["scope_binding"],
                    state_version=next_state_version,
                    sequence=next_sequence,
                    attestation_set_sha256=next_attestation_set_sha256,
                    nonce_sha256=next_nonce_sha256,
                    owner_id=owner_id,
                    owner_instance_id=owner_instance_id,
                    owner_epoch=owner_epoch,
                    fencing_epoch=fencing_epoch,
                    idempotency_index_sha256=next_idempotency_index_sha256,
                )
                next_head_sha256 = canonical_hash(head_core)
                if expected_next_head_sha256 is not None and expected_next_head_sha256 != next_head_sha256:
                    return self._result_base("HOLD", "CAS_REJECTED", "NEXT_HEAD_MISMATCH")

                previous_transition = cur.execute(
                    "SELECT transition_sha256 FROM replay_owner_transitions WHERE scope_id=? ORDER BY after_state_version DESC LIMIT 1",
                    (scope_id,),
                ).fetchone()
                parent_transition_sha256 = previous_transition[0] if previous_transition is not None else None
                transition_core = {
                    "schema_version": OWNER_TRANSITION_SCHEMA,
                    "scope_id": scope_id,
                    "after_state_version": next_state_version,
                    "transaction_id": transaction_id,
                    "idempotency_key": idempotency_key,
                    "parent_head_sha256": state["head_sha256"],
                    "new_head_sha256": next_head_sha256,
                    "before_state_version": expected_state_version,
                    "fencing_epoch": fencing_epoch,
                    "parent_transition_sha256": parent_transition_sha256,
                }
                transition_sha256 = canonical_hash(transition_core)
                stored_result = self._result_base("OWNER_CAS_COMMITTED", "ADVANCED", "OWNER_STATE_ADVANCED", mutated=True)
                stored_result.update(
                    {
                        "scope_id": scope_id,
                        "idempotency_key": idempotency_key,
                        "transaction_id": transaction_id,
                        "operation": operation,
                        "intent_sha256": intent_sha256,
                        "state_version_before": expected_state_version,
                        "state_version_after": next_state_version,
                        "sequence_before": expected_sequence,
                        "sequence_after": next_sequence,
                        "head_before_sha256": state["head_sha256"],
                        "head_after_sha256": next_head_sha256,
                        "fencing_epoch": fencing_epoch,
                        "transition_sha256": transition_sha256,
                        "parent_transition_sha256": parent_transition_sha256,
                        "committed_at": now_epoch,
                    }
                )
                result_json = canonical_json(stored_result)
                result_sha256 = canonical_hash(stored_result)
                cur.execute(
                    "UPDATE replay_owner_scopes SET state_version=?,head_sha256=?,sequence=?,attestation_set_sha256=?,nonce_sha256=?,idempotency_index_sha256=?,updated_at=? WHERE scope_id=? AND state_version=? AND head_sha256 IS ? AND sequence=? AND fencing_epoch=? AND lease_token_sha256=?",
                    (
                        next_state_version,
                        next_head_sha256,
                        next_sequence,
                        next_attestation_set_sha256,
                        next_nonce_sha256,
                        next_idempotency_index_sha256,
                        now_epoch,
                        scope_id,
                        expected_state_version,
                        state["head_sha256"],
                        expected_sequence,
                        fencing_epoch,
                        lease_token_sha256,
                    ),
                )
                if cur.rowcount != 1:
                    return self._result_base("HOLD", "CAS_REJECTED", "STATE_CAS_LOST")
                cur.execute(
                    "INSERT INTO replay_owner_operations(scope_id,idempotency_key,transaction_id,operation,intent_sha256,state_version_before,state_version_after,sequence_before,sequence_after,head_before_sha256,head_after_sha256,fencing_epoch,result_json,result_sha256,idempotency_index_after_sha256,operation_record_sha256,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        scope_id,
                        idempotency_key,
                        transaction_id,
                        operation,
                        intent_sha256,
                        expected_state_version,
                        next_state_version,
                        expected_sequence,
                        next_sequence,
                        state["head_sha256"],
                        next_head_sha256,
                        fencing_epoch,
                        result_json,
                        result_sha256,
                        next_idempotency_index_sha256,
                        None,
                        now_epoch,
                    ),
                )
                cur.execute(
                    "INSERT INTO replay_owner_transitions(scope_id,after_state_version,transaction_id,idempotency_key,parent_head_sha256,new_head_sha256,before_state_version,fencing_epoch,transition_sha256,parent_transition_sha256,committed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        scope_id,
                        next_state_version,
                        transaction_id,
                        idempotency_key,
                        state["head_sha256"],
                        next_head_sha256,
                        expected_state_version,
                        fencing_epoch,
                        transition_sha256,
                        parent_transition_sha256,
                        now_epoch,
                    ),
                )
                self._event(
                    cur,
                    scope_id=scope_id,
                    event_type="OWNER_CAS_COMMITTED",
                    idempotency_key=idempotency_key,
                    state_version=next_state_version,
                    payload={
                        "transaction_id": transaction_id,
                        "intent_sha256": intent_sha256,
                        "head_after_sha256": next_head_sha256,
                        "fencing_epoch": fencing_epoch,
                        "transition_sha256": transition_sha256,
                    },
                    created_at=now_epoch,
                )
                operation_record = {
                    "schema_version": OWNER_OPERATION_RECORD_SCHEMA,
                    "scope_id": scope_id,
                    "idempotency_key": idempotency_key,
                    "transaction_id": transaction_id,
                    "operation": operation,
                    "intent_sha256": intent_sha256,
                    "state_version_before": expected_state_version,
                    "state_version_after": next_state_version,
                    "sequence_before": expected_sequence,
                    "sequence_after": next_sequence,
                    "head_before_sha256": state["head_sha256"],
                    "head_after_sha256": next_head_sha256,
                    "fencing_epoch": fencing_epoch,
                    "result_sha256": result_sha256,
                    "idempotency_index_after_sha256": next_idempotency_index_sha256,
                    "transition_sha256": transition_sha256,
                }
                operation_record_sha256 = canonical_hash(operation_record)
                cur.execute(
                    "UPDATE replay_owner_operations SET operation_record_sha256=? WHERE scope_id=? AND idempotency_key=?",
                    (operation_record_sha256, scope_id, idempotency_key),
                )
                committed = dict(stored_result)
                committed["idempotency_index_sha256_after"] = next_idempotency_index_sha256
                committed["operation_record_sha256"] = operation_record_sha256
                return committed
        except ReplayOwnerStoreError:
            raise
        except sqlite3.Error:
            return self._recovery_result("OWNER_STORE_SQLITE_ERROR")


__all__ = [
    "JOURNAL_CLEAN",
    "JOURNAL_IN_DOUBT",
    "JOURNAL_RECOVERY_REQUIRED",
    "OWNER_HEAD_SCHEMA",
    "OWNER_INTENT_SCHEMA",
    "OWNER_OPERATION",
    "OWNER_STORE_SCHEMA",
    "ReplayOwnerStore",
    "ReplayOwnerStoreError",
]
