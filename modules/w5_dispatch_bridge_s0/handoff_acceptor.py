"""S25B single-store, authority-backed Handoff acceptance.

The acceptor is deliberately narrower than queue recovery.  It uses the
existing Queue-Writer SQLite connection and the cooperative queue lock to
atomically rotate the local owner/fence claim into ``RECOVERY``.  It does not
touch ``QUEUE.json``, execute recovery, start an executor, or write any other
participant store.

S25A observations and grants remain caller-supplied evidence.  S25B requires
two separately configured and frozen trust roots: one for an approval
attestation and one for a termination/release attestation.  Keys are never
accepted from the grant or either untrusted input envelope.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
import re
import sqlite3
from threading import Lock
from typing import Any, Iterator, Mapping

from modules.w4_small_loop_s0 import canonical_hash, canonical_json
from mcp import prime_writes

from .handoff_preflight import (
    HANDOFF_PREVIEW_ONLY,
    HandoffPreflightError,
    _copy_json,
    _hash64,
    _integer,
    _safe_id,
    evaluate_handoff_preflight,
    _validate_grant,
    _validate_observation,
)
from .prime_queue_writer import PrimeQueueWriter, PrimeQueueWriterError


HANDOFF_ACCEPTOR_SCHEMA = "prime-queue-handoff-acceptor-v1"
HANDOFF_ACCEPTOR_ROLE = "prime_queue_handoff_acceptor_recovery_only"
HANDOFF_AUTHORITY_SCHEMA = "prime-queue-handoff-authority-v1"
HANDOFF_TERMINATION_SCHEMA = "prime-queue-termination-attestation-v1"
HANDOFF_AUTHORITY_PROTOCOL = "hmac-sha256-canonical-json-v1"
HANDOFF_ACCEPTED_RECOVERY = "ACCEPTED_RECOVERY"
HANDOFF_REPLAYED = "REPLAYED"
HANDOFF_HOLD = "HOLD"
HANDOFF_CONFLICT = "CONFLICT"
HANDOFF_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
HANDOFF_FAULT_POINTS = frozenset({"before_commit", "after_commit"})

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HANDOFF_EVENT_TYPE = "HANDOFF_ACCEPTED_RECOVERY"
_HANDOFF_KINDS = frozenset({"COOPERATIVE_RELEASE", "AUTHORIZED_TERMINATION"})
_AUTHORITY_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "authority_id",
        "authority_epoch",
        "decision",
        "handoff_id",
        "grant_sha256",
        "root_binding_sha256",
        "scope_id",
        "transaction_id",
        "old_fencing_epoch",
        "new_fencing_epoch",
        "issued_at",
        "expires_at",
        "nonce",
        "policy_hash",
        "authority_mac",
    }
)
_TERMINATION_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "termination_authority_id",
        "termination_authority_epoch",
        "source_id",
        "source_epoch",
        "handoff_id",
        "grant_sha256",
        "old_owner_id",
        "old_owner_instance_id",
        "old_fencing_epoch",
        "transaction_id",
        "intent_sha256",
        "process_pid",
        "process_start_time",
        "boot_id",
        "run_token_hash",
        "cgroup_identity_hash",
        "outcome",
        "observed_at",
        "expires_at",
        "evidence_sha256",
        "authority_mac",
    }
)

_AUTHORITY_LOCK = Lock()
_TERMINATION_LOCK = Lock()
_TRUSTED_AUTHORITIES: dict[str, bytes] = {}
_TRUSTED_TERMINATION_AUTHORITIES: dict[str, bytes] = {}
_AUTHORITIES_FROZEN = False
_TERMINATION_AUTHORITIES_FROZEN = False


class HandoffAcceptError(ValueError):
    """Fail-closed input, trust, or local CAS error."""

    def __init__(self, reason: str, *, recovery_required: bool = False) -> None:
        self.reason = reason
        self.recovery_required = recovery_required
        super().__init__(reason)


class InjectedHandoffCrash(RuntimeError):
    """Deterministic test-only crash at a single-store commit boundary."""

    def __init__(self, point: str) -> None:
        self.point = point
        super().__init__(point)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise HandoffAcceptError(f"{label}_INVALID")
    return value


def _hash(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise HandoffAcceptError(f"{label}_INVALID")
    return value


def _proof_digest(value: Any) -> str:
    return hashlib.sha256(_text(value, "authority_proof").encode("utf-8")).hexdigest()


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    if set(value) != set(expected):
        raise HandoffAcceptError(f"{label}_KEYS_INVALID")


def _configure_registry(registry: dict[str, bytes], lock: Lock, *, frozen: bool, authority_id: str, key: bytes) -> None:
    authority_id = _safe_id(authority_id, "authority_id")
    if not isinstance(key, bytes) or len(key) < 16:
        raise HandoffAcceptError("AUTHORITY_KEY_INVALID")
    with lock:
        if frozen:
            existing = registry.get(authority_id)
            if existing == key:
                return
            raise HandoffAcceptError("AUTHORITY_TRUST_ROOT_FROZEN")
        existing = registry.get(authority_id)
        if existing is not None and existing != key:
            raise HandoffAcceptError("AUTHORITY_RECONFIGURATION_REJECTED")
        registry[authority_id] = bytes(key)


def configure_trusted_handoff_authority(*, authority_id: str, key: bytes) -> None:
    _configure_registry(
        _TRUSTED_AUTHORITIES,
        _AUTHORITY_LOCK,
        frozen=_AUTHORITIES_FROZEN,
        authority_id=authority_id,
        key=key,
    )


def freeze_trusted_handoff_authorities() -> None:
    global _AUTHORITIES_FROZEN
    with _AUTHORITY_LOCK:
        _AUTHORITIES_FROZEN = True


def configure_trusted_termination_authority(*, authority_id: str, key: bytes) -> None:
    _configure_registry(
        _TRUSTED_TERMINATION_AUTHORITIES,
        _TERMINATION_LOCK,
        frozen=_TERMINATION_AUTHORITIES_FROZEN,
        authority_id=authority_id,
        key=key,
    )


def freeze_trusted_termination_authorities() -> None:
    global _TERMINATION_AUTHORITIES_FROZEN
    with _TERMINATION_LOCK:
        _TERMINATION_AUTHORITIES_FROZEN = True


def _resolve(registry: Mapping[str, bytes], lock: Lock, frozen: bool, authority_id: str, label: str) -> bytes:
    authority_id = _safe_id(authority_id, label)
    with lock:
        if not frozen:
            raise HandoffAcceptError(f"{label.upper()}_TRUST_ROOT_NOT_FROZEN")
        key = registry.get(authority_id)
    if key is None:
        raise HandoffAcceptError(f"{label.upper()}_TRUST_ROOT_UNKNOWN")
    return key


def _authority_core(attestation: Mapping[str, Any]) -> dict[str, Any]:
    return {key: attestation[key] for key in sorted(attestation) if key != "authority_mac"}


def _verify_mac(attestation: Mapping[str, Any], key: bytes) -> None:
    expected = hmac.new(key, canonical_json(_authority_core(attestation)).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(attestation["authority_mac"], expected):
        raise HandoffAcceptError("AUTHORITY_MAC_INVALID")


def _grant_hash(grant: Mapping[str, Any]) -> str:
    return canonical_hash(dict(grant))


def _verify_authority_attestation(
    attestation: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    now: int,
    grant_sha256: str,
) -> dict[str, Any]:
    _exact_keys(attestation, _AUTHORITY_KEYS, "authority_attestation")
    if attestation["schema_version"] != HANDOFF_AUTHORITY_SCHEMA:
        raise HandoffAcceptError("AUTHORITY_SCHEMA_INVALID")
    if attestation["protocol"] != HANDOFF_AUTHORITY_PROTOCOL:
        raise HandoffAcceptError("AUTHORITY_PROTOCOL_INVALID")
    authority_id = _safe_id(attestation["authority_id"], "authority_id")
    _integer(attestation["authority_epoch"], "authority_epoch", minimum=1)
    if attestation["decision"] != "ACCEPT_RECOVERY":
        raise HandoffAcceptError("AUTHORITY_DECISION_INVALID")
    for key in ("handoff_id", "scope_id", "transaction_id", "nonce"):
        _safe_id(attestation[key], key)
    for key in ("grant_sha256", "root_binding_sha256", "policy_hash"):
        _hash(attestation[key], key)
    _integer(attestation["old_fencing_epoch"], "old_fencing_epoch", minimum=1)
    _integer(attestation["new_fencing_epoch"], "new_fencing_epoch", minimum=1)
    _integer(attestation["issued_at"], "issued_at")
    _integer(attestation["expires_at"], "expires_at")
    _hash(attestation["authority_mac"], "authority_mac")
    if attestation["issued_at"] > now or attestation["expires_at"] <= now:
        raise HandoffAcceptError("AUTHORITY_ATTESTATION_EXPIRED")
    if attestation["grant_sha256"] != grant_sha256:
        raise HandoffAcceptError("AUTHORITY_GRANT_DIGEST_MISMATCH")
    if (
        attestation["authority_id"] != grant["authority_id"]
        or attestation["authority_epoch"] != grant["authority_epoch"]
        or attestation["handoff_id"] != grant["handoff_id"]
        or attestation["root_binding_sha256"] != grant["root_binding_sha256"]
        or attestation["scope_id"] != grant["scope_id"]
        or attestation["transaction_id"] != grant["transaction_id"]
        or attestation["old_fencing_epoch"] != grant["old_fencing_epoch"]
        or attestation["new_fencing_epoch"] != grant["new_fencing_epoch"]
    ):
        raise HandoffAcceptError("AUTHORITY_BINDING_MISMATCH")
    key = _resolve(_TRUSTED_AUTHORITIES, _AUTHORITY_LOCK, _AUTHORITIES_FROZEN, authority_id, "authority")
    _verify_mac(attestation, key)
    return dict(attestation)


def _verify_termination_attestation(
    attestation: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    now: int,
    grant_sha256: str,
) -> dict[str, Any]:
    _exact_keys(attestation, _TERMINATION_KEYS, "termination_attestation")
    if attestation["schema_version"] != HANDOFF_TERMINATION_SCHEMA:
        raise HandoffAcceptError("TERMINATION_SCHEMA_INVALID")
    if attestation["protocol"] != HANDOFF_AUTHORITY_PROTOCOL:
        raise HandoffAcceptError("TERMINATION_PROTOCOL_INVALID")
    _safe_id(attestation["termination_authority_id"], "termination_authority_id")
    _integer(attestation["termination_authority_epoch"], "termination_authority_epoch", minimum=1)
    for key in ("source_id", "handoff_id", "transaction_id", "boot_id"):
        _safe_id(attestation[key], key)
    for key in (
        "grant_sha256",
        "intent_sha256",
        "run_token_hash",
        "cgroup_identity_hash",
        "evidence_sha256",
        "authority_mac",
    ):
        _hash(attestation[key], key)
    for key in ("old_fencing_epoch", "source_epoch", "process_pid", "process_start_time", "observed_at", "expires_at"):
        _integer(attestation[key], key, minimum=1)
    if attestation["outcome"] not in {"TERMINATED", "RELEASED"}:
        raise HandoffAcceptError("TERMINATION_OUTCOME_INVALID")
    if attestation["observed_at"] > now or attestation["expires_at"] <= now:
        raise HandoffAcceptError("TERMINATION_ATTESTATION_EXPIRED")
    if (
        attestation["grant_sha256"] != grant_sha256
        or attestation["handoff_id"] != grant["handoff_id"]
        or attestation["transaction_id"] != grant["transaction_id"]
        or attestation["intent_sha256"] != grant["intent_sha256"]
        or attestation["evidence_sha256"] != grant["liveness_evidence_sha256"]
        or attestation["old_owner_id"] != grant["old_owner_id"]
        or attestation["old_owner_instance_id"] != grant["old_owner_instance_id"]
        or attestation["old_fencing_epoch"] != grant["old_fencing_epoch"]
    ):
        raise HandoffAcceptError("TERMINATION_BINDING_MISMATCH")
    key = _resolve(
        _TRUSTED_TERMINATION_AUTHORITIES,
        _TERMINATION_LOCK,
        _TERMINATION_AUTHORITIES_FROZEN,
        attestation["termination_authority_id"],
        "termination_authority",
    )
    _verify_mac(attestation, key)
    return dict(attestation)


def _output(
    status: str,
    reason: str,
    *,
    grant: Mapping[str, Any] | None = None,
    observation: Mapping[str, Any] | None = None,
    authority_verified: bool = False,
    termination_verified: bool = False,
    mutation_performed: bool = False,
    scope_cas_committed: bool = False,
    root_cas_committed: bool = False,
    claim_cas_committed: bool = False,
    event_committed: bool = False,
) -> dict[str, Any]:
    accepted = status == HANDOFF_ACCEPTED_RECOVERY
    replayed = status == HANDOFF_REPLAYED
    grant = grant or {}
    observation = observation or {}
    return {
        "schema_version": HANDOFF_ACCEPTOR_SCHEMA,
        "contract_role": HANDOFF_ACCEPTOR_ROLE,
        "status": status,
        "decision": "HANDOFF_ACCEPTED_RECOVERY" if accepted else ("HANDOFF_REPLAY" if replayed else "HOLD"),
        "reason": reason,
        "handoff_id": grant.get("handoff_id"),
        "grant_sha256": _grant_hash(grant) if grant else None,
        "observation_sha256": observation.get("observation_sha256"),
        "scope_id": grant.get("scope_id"),
        "transaction_id": grant.get("transaction_id"),
        "idempotency_key": grant.get("idempotency_key"),
        "source_phase": grant.get("expected_active_phase"),
        "target_phase": "RECOVERY" if accepted or replayed else None,
        "source_fencing_epoch": grant.get("old_fencing_epoch"),
        "target_fencing_epoch": grant.get("new_fencing_epoch") if accepted or replayed else None,
        "authority_verified": authority_verified,
        "termination_verified": termination_verified,
        "current_sqlite_state_rechecked": scope_cas_committed or replayed,
        "handoff_mutation_performed": mutation_performed,
        "root_cas_committed": root_cas_committed,
        "scope_cas_committed": scope_cas_committed,
        "claim_cas_committed": claim_cas_committed,
        "handoff_event_committed": event_committed,
        "queue_mutation_performed": False,
        "recovery_claim_accepted": accepted or replayed,
        "recovery_executed": False,
        "resume_allowed": False,
        "receipt_emitted": False,
        "receipt_committed": False,
        "consume_allowed": False,
        "global_commit": False,
        "cross_store_atomicity": "NOT_CLAIMED",
        "execution": {
            "queue_lock": scope_cas_committed or replayed,
            "sqlite_scope": scope_cas_committed or replayed,
            "sqlite_root": root_cas_committed,
            "sqlite_claim": claim_cas_committed,
            "handoff_event": event_committed,
            "queue_file": False,
            "recovery": False,
            "executor": False,
            "receipt": False,
            "ledger": False,
            "projection": False,
            "consume": False,
        },
    }


class HandoffAcceptor:
    """Atomically accept one trusted handoff into the local RECOVERY phase."""

    def __init__(
        self,
        writer: PrimeQueueWriter,
        *,
        clock: Any | None = None,
        fault_points: set[str] | frozenset[str] | None = None,
    ) -> None:
        if not isinstance(writer, PrimeQueueWriter):
            raise HandoffAcceptError("WRITER_INVALID")
        if clock is not None and not callable(clock):
            raise HandoffAcceptError("CLOCK_INVALID")
        points = set(fault_points or ())
        if not points.issubset(HANDOFF_FAULT_POINTS):
            raise HandoffAcceptError("FAULT_POINT_INVALID")
        self.writer = writer
        self.clock = clock or writer.clock
        self.fault_points = points

    def _now(self) -> int:
        return _integer(self.clock(), "clock")

    def _fault(self, point: str) -> None:
        if point in self.fault_points:
            raise InjectedHandoffCrash(point)

    @contextmanager
    def _queue_lock(self) -> Iterator[None]:
        state = prime_writes._state()
        _queue, journal = state.paths(self.writer.root)
        fd = state.lock(journal)
        try:
            yield
        finally:
            os.close(fd)

    def _existing_replay(
        self,
        cursor: Any,
        grant: Mapping[str, Any],
        *,
        grant_sha256: str,
        observation_sha256: str,
    ) -> dict[str, Any] | None:
        row = cursor.execute(
            "SELECT * FROM prime_queue_writer_handoff_events WHERE handoff_id=?",
            (grant["handoff_id"],),
        ).fetchone()
        if row is not None:
            if row["grant_sha256"] != grant_sha256 or row["observation_sha256"] != observation_sha256:
                raise HandoffAcceptError("HANDOFF_ID_CONFLICT")
            return _output(
                HANDOFF_REPLAYED,
                "IDENTICAL_HANDOFF_ALREADY_ACCEPTED",
                grant=grant,
                observation={"observation_sha256": observation_sha256},
                authority_verified=True,
                termination_verified=True,
                scope_cas_committed=True,
            )
        row = cursor.execute(
            "SELECT handoff_id FROM prime_queue_writer_handoff_events WHERE scope_id=? AND idempotency_key=?",
            (grant["scope_id"], grant["idempotency_key"]),
        ).fetchone()
        if row is not None:
            raise HandoffAcceptError("HANDOFF_OPERATION_ALREADY_ROTATED")
        row = cursor.execute(
            "SELECT handoff_id FROM prime_queue_writer_handoff_events WHERE scope_id=? AND old_fencing_epoch=?",
            (grant["scope_id"], grant["old_fencing_epoch"]),
        ).fetchone()
        if row is not None:
            raise HandoffAcceptError("HANDOFF_SOURCE_FENCE_ALREADY_ROTATED")
        return None

    @staticmethod
    def _assert_operation_matches(cursor: Any, observation: Mapping[str, Any], grant: Mapping[str, Any]) -> Any:
        scope_data = observation["scope"]
        operation_data = observation["operation"]
        row = cursor.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=? AND transaction_id=?",
            (scope_data["scope_id"], operation_data["transaction_id"]),
        ).fetchone()
        if row is None:
            raise HandoffAcceptError("SOURCE_OPERATION_MISSING", recovery_required=True)
        if (
            row["idempotency_key"] != operation_data["idempotency_key"]
            or row["intent_sha256"] != operation_data["intent_sha256"]
            or row["expected_queue_sha256"] != operation_data["expected_queue_sha256"]
            or row["after_queue_sha256"] != operation_data["after_queue_sha256"]
            or row["state"] != operation_data["state"]
            or row["transaction_id"] != grant["transaction_id"]
        ):
            raise HandoffAcceptError("SOURCE_OPERATION_CAS_DRIFT", recovery_required=True)
        return row

    @staticmethod
    def _assert_scope_matches(cursor: Any, observation: Mapping[str, Any], grant: Mapping[str, Any], writer: PrimeQueueWriter) -> Any:
        scope_data = observation["scope"]
        root_data = observation["root"]
        row = writer._scope_row(cursor, scope_data["scope_id"])
        if (
            row["root_binding_sha256"] != observation["root_binding_sha256"]
            or row["owner_id"] != grant["old_owner_id"]
            or row["owner_instance_id"] != grant["old_owner_instance_id"]
            or int(row["owner_epoch"]) != grant["old_owner_epoch"]
            or int(row["fencing_epoch"]) != grant["old_fencing_epoch"]
            or row["lease_token_sha256"] != grant["old_lease_token_sha256"]
            or int(row["lease_expires_at"]) != grant["old_lease_expires_at"]
            or row["scope_status"] != scope_data["scope_status"]
            or row["active_operation_id"] != grant["transaction_id"]
            or row["active_phase"] != grant["expected_active_phase"]
            or int(row["event_seq"]) != grant["expected_event_seq"]
        ):
            raise HandoffAcceptError("SOURCE_SCOPE_CAS_DRIFT")
        root = cursor.execute(
            "SELECT * FROM prime_queue_writer_roots WHERE root_binding_sha256=?",
            (observation["root_binding_sha256"],),
        ).fetchone()
        if root is None:
            raise HandoffAcceptError("SOURCE_ROOT_MISSING", recovery_required=True)
        if (
            root["active_scope_id"] != root_data["active_scope_id"]
            or root["active_scope_id"] != grant["scope_id"]
            or int(root["active_fencing_epoch"]) != grant["old_fencing_epoch"]
        ):
            raise HandoffAcceptError("SOURCE_ROOT_CAS_DRIFT")
        return row

    def _append_handoff_event(
        self,
        cursor: Any,
        *,
        observation: Mapping[str, Any],
        grant: Mapping[str, Any],
        authority: Mapping[str, Any],
        termination: Mapping[str, Any],
        grant_sha256: str,
        observation_sha256: str,
        now: int,
    ) -> None:
        previous = cursor.execute(
            "SELECT * FROM prime_queue_writer_handoff_events WHERE scope_id=? ORDER BY handoff_seq DESC LIMIT 1",
            (grant["scope_id"],),
        ).fetchone()
        sequence = int(previous["handoff_seq"]) + 1 if previous is not None else 1
        parent = previous["event_sha256"] if previous is not None else None
        source = {
            "root_binding_sha256": grant["root_binding_sha256"],
            "owner_id": grant["old_owner_id"],
            "owner_instance_id": grant["old_owner_instance_id"],
            "owner_epoch": grant["old_owner_epoch"],
            "fencing_epoch": grant["old_fencing_epoch"],
            "lease_token_sha256": grant["old_lease_token_sha256"],
            "lease_expires_at": grant["old_lease_expires_at"],
            "active_phase": grant["expected_active_phase"],
            "operation_state": grant["expected_operation_state"],
        }
        target = {
            "root_binding_sha256": grant["root_binding_sha256"],
            "owner_id": grant["new_owner_id"],
            "owner_instance_id": grant["new_owner_instance_id"],
            "owner_epoch": grant["new_owner_epoch"],
            "fencing_epoch": grant["new_fencing_epoch"],
            "lease_token_sha256": grant["new_lease_token_sha256"],
            "lease_expires_at": grant["new_lease_expires_at"],
            "active_phase": "RECOVERY",
            "operation_state": grant["expected_operation_state"],
            "scope_status": observation["scope"]["scope_status"],
        }
        payload = {
            "handoff_id": grant["handoff_id"],
            "grant_sha256": grant_sha256,
            "observation_sha256": observation_sha256,
            "authority_id": authority["authority_id"],
            "authority_epoch": authority["authority_epoch"],
            "authority_proof_sha256": _proof_digest(grant["authority_proof"]),
            "termination_authority_id": termination["termination_authority_id"],
            "termination_authority_epoch": termination["termination_authority_epoch"],
            "termination_proof_sha256": termination["authority_mac"],
            "event_type": _HANDOFF_EVENT_TYPE,
            "source": source,
            "target": target,
            "transaction_id": grant["transaction_id"],
            "idempotency_key": grant["idempotency_key"],
            "intent_sha256": grant["intent_sha256"],
            "handoff_kind": grant["handoff_kind"],
            "reason": grant["reason"],
        }
        event_hash = canonical_hash(
            {
                "scope_id": grant["scope_id"],
                "handoff_seq": sequence,
                "handoff_id": grant["handoff_id"],
                "event_type": _HANDOFF_EVENT_TYPE,
                "parent_event_sha256": parent,
                "payload": payload,
                "created_at": now,
            }
        )
        cursor.execute(
            """INSERT INTO prime_queue_writer_handoff_events(
                scope_id,handoff_seq,handoff_id,root_binding_sha256,transaction_id,
                idempotency_key,observation_sha256,grant_sha256,authority_id,
                authority_epoch,authority_proof_sha256,old_owner_id,
                old_owner_instance_id,old_owner_epoch,old_fencing_epoch,
                old_lease_token_sha256,old_lease_expires_at,new_owner_id,
                new_owner_instance_id,new_owner_epoch,new_fencing_epoch,
                new_lease_token_sha256,new_lease_expires_at,handoff_kind,
                event_type,parent_event_sha256,event_sha256,payload_json,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                grant["scope_id"],
                sequence,
                grant["handoff_id"],
                grant["root_binding_sha256"],
                grant["transaction_id"],
                grant["idempotency_key"],
                observation_sha256,
                grant_sha256,
                authority["authority_id"],
                authority["authority_epoch"],
                _proof_digest(grant["authority_proof"]),
                grant["old_owner_id"],
                grant["old_owner_instance_id"],
                grant["old_owner_epoch"],
                grant["old_fencing_epoch"],
                grant["old_lease_token_sha256"],
                grant["old_lease_expires_at"],
                grant["new_owner_id"],
                grant["new_owner_instance_id"],
                grant["new_owner_epoch"],
                grant["new_fencing_epoch"],
                grant["new_lease_token_sha256"],
                grant["new_lease_expires_at"],
                grant["handoff_kind"],
                _HANDOFF_EVENT_TYPE,
                parent,
                event_hash,
                canonical_json(payload),
                now,
            ),
        )

    def accept_handoff(
        self,
        *,
        observation: Mapping[str, Any],
        grant: Mapping[str, Any],
        authority_attestation: Mapping[str, Any],
        termination_attestation: Mapping[str, Any],
        new_lease_token: str,
        now: int | None = None,
    ) -> dict[str, Any]:
        try:
            now = self._now() if now is None else _integer(now, "now")
            structural = evaluate_handoff_preflight(
                observation,
                grant,
                new_lease_token=new_lease_token,
                now=now,
            )
            if structural["status"] != HANDOFF_PREVIEW_ONLY:
                return _output(structural["status"], structural["reason"])
            observation_copy = _copy_json(observation, "observation")
            grant_copy = _copy_json(grant, "handoff_grant")
            authority_copy = _copy_json(authority_attestation, "authority_attestation")
            termination_copy = _copy_json(termination_attestation, "termination_attestation")
            if not all(isinstance(value, Mapping) for value in (observation_copy, grant_copy, authority_copy, termination_copy)):
                raise HandoffAcceptError("HANDOFF_INPUT_INVALID", recovery_required=True)
            observation_copy = _validate_observation(observation_copy, now=now)
            _validate_grant(grant_copy, observation_copy, new_lease_token=new_lease_token, now=now)
            grant_sha256 = _grant_hash(grant_copy)
            observation_sha256 = observation_copy["observation_sha256"]
            authority_copy = _verify_authority_attestation(
                authority_copy,
                grant_copy,
                now=now,
                grant_sha256=grant_sha256,
            )
            termination_copy = _verify_termination_attestation(
                termination_copy,
                grant_copy,
                now=now,
                grant_sha256=grant_sha256,
            )
            if grant_copy["handoff_kind"] not in _HANDOFF_KINDS:
                raise HandoffAcceptError("HANDOFF_KIND_NOT_AUTHORIZED")
            if grant_copy["new_lease_expires_at"] <= now:
                raise HandoffAcceptError("NEW_LEASE_EXPIRED")
            with self._queue_lock():
                with self.writer._transaction() as cursor:
                    scope = self.writer._scope_row(cursor, grant_copy["scope_id"])
                    self.writer._assert_scope_integrity(cursor, scope)
                    replay = self._existing_replay(
                        cursor,
                        grant_copy,
                        grant_sha256=grant_sha256,
                        observation_sha256=observation_sha256,
                    )
                    if replay is not None:
                        return replay
                    cas_now = self._now()
                    if (
                        authority_copy["expires_at"] <= cas_now
                        or termination_copy["expires_at"] <= cas_now
                        or grant_copy["new_lease_expires_at"] <= cas_now
                    ):
                        raise HandoffAcceptError("AUTHORITY_OR_NEW_LEASE_EXPIRED")
                    now = cas_now
                    self._assert_scope_matches(cursor, observation_copy, grant_copy, self.writer)
                    self._assert_operation_matches(cursor, observation_copy, grant_copy)
                    latest = cursor.execute(
                        "SELECT MAX(authority_epoch) FROM prime_queue_writer_handoff_events WHERE scope_id=?",
                        (grant_copy["scope_id"],),
                    ).fetchone()[0]
                    if latest is not None and int(grant_copy["authority_epoch"]) <= int(latest):
                        raise HandoffAcceptError("AUTHORITY_EPOCH_STALE")
                    root_update = cursor.execute(
                        """UPDATE prime_queue_writer_roots
                           SET active_fencing_epoch=?, updated_at=?
                           WHERE root_binding_sha256=? AND active_scope_id=?
                             AND active_fencing_epoch=?""",
                        (
                            grant_copy["new_fencing_epoch"],
                            now,
                            grant_copy["root_binding_sha256"],
                            grant_copy["scope_id"],
                            grant_copy["old_fencing_epoch"],
                        ),
                    )
                    if root_update.rowcount != 1:
                        raise HandoffAcceptError("ROOT_CAS_CONFLICT")
                    scope_update = cursor.execute(
                        """UPDATE prime_queue_writer_scopes
                           SET owner_id=?, owner_instance_id=?, owner_epoch=?,
                               fencing_epoch=?, lease_token_sha256=?,
                               lease_expires_at=?, active_phase='RECOVERY',
                               updated_at=?
                           WHERE scope_id=? AND root_binding_sha256=?
                             AND owner_id=? AND owner_instance_id=?
                             AND owner_epoch=? AND fencing_epoch=?
                             AND lease_token_sha256=? AND lease_expires_at=?
                             AND scope_status=? AND active_operation_id=?
                             AND active_phase=? AND event_seq=?""",
                        (
                            grant_copy["new_owner_id"],
                            grant_copy["new_owner_instance_id"],
                            grant_copy["new_owner_epoch"],
                            grant_copy["new_fencing_epoch"],
                            grant_copy["new_lease_token_sha256"],
                            grant_copy["new_lease_expires_at"],
                            now,
                            grant_copy["scope_id"],
                            grant_copy["root_binding_sha256"],
                            grant_copy["old_owner_id"],
                            grant_copy["old_owner_instance_id"],
                            grant_copy["old_owner_epoch"],
                            grant_copy["old_fencing_epoch"],
                            grant_copy["old_lease_token_sha256"],
                            grant_copy["old_lease_expires_at"],
                            observation_copy["scope"]["scope_status"],
                            grant_copy["transaction_id"],
                            grant_copy["expected_active_phase"],
                            grant_copy["expected_event_seq"],
                        ),
                    )
                    if scope_update.rowcount != 1:
                        raise HandoffAcceptError("SCOPE_CAS_CONFLICT")
                    claim_update = cursor.execute(
                        """UPDATE prime_queue_writer_operations
                           SET updated_at=?
                           WHERE scope_id=? AND transaction_id=?
                             AND idempotency_key=? AND intent_sha256=?
                             AND state=?""",
                        (
                            now,
                            grant_copy["scope_id"],
                            grant_copy["transaction_id"],
                            grant_copy["idempotency_key"],
                            grant_copy["intent_sha256"],
                            grant_copy["expected_operation_state"],
                        ),
                    )
                    if claim_update.rowcount != 1:
                        raise HandoffAcceptError("CLAIM_CAS_CONFLICT")
                    self._append_handoff_event(
                        cursor,
                        observation=observation_copy,
                        grant=grant_copy,
                        authority=authority_copy,
                        termination=termination_copy,
                        grant_sha256=grant_sha256,
                        observation_sha256=observation_sha256,
                        now=now,
                    )
                    self._fault("before_commit")
                self._fault("after_commit")
            return _output(
                HANDOFF_ACCEPTED_RECOVERY,
                "HANDOFF_ACCEPTED_IN_RECOVERY_ONLY",
                grant=grant_copy,
                observation=observation_copy,
                authority_verified=True,
                termination_verified=True,
                mutation_performed=True,
                scope_cas_committed=True,
                root_cas_committed=True,
                claim_cas_committed=True,
                event_committed=True,
            )
        except InjectedHandoffCrash:
            raise
        except HandoffPreflightError as exc:
            return _output(HANDOFF_RECOVERY_REQUIRED if exc.recovery_required else HANDOFF_HOLD, exc.reason)
        except HandoffAcceptError as exc:
            status = HANDOFF_RECOVERY_REQUIRED if exc.recovery_required else (
                HANDOFF_CONFLICT
                if any(
                    token in exc.reason
                    for token in (
                        "CONFLICT",
                        "ROTATED",
                        "STALE",
                        "SOURCE_SCOPE_CAS_DRIFT",
                        "SOURCE_ROOT_CAS_DRIFT",
                    )
                )
                else HANDOFF_HOLD
            )
            return _output(status, exc.reason)
        except PrimeQueueWriterError as exc:
            return _output(HANDOFF_RECOVERY_REQUIRED, str(exc))
        except (OSError, sqlite3.Error) as exc:
            return _output(HANDOFF_HOLD, f"HANDOFF_LOCAL_IO_{type(exc).__name__}")
        except Exception as exc:
            return _output(HANDOFF_RECOVERY_REQUIRED, f"HANDOFF_UNEXPECTED_{type(exc).__name__}")


def accept_handoff(**kwargs: Any) -> dict[str, Any]:
    """Convenience wrapper for the explicit S25B acceptor object."""

    writer = kwargs.pop("writer", None)
    if not isinstance(writer, PrimeQueueWriter):
        return _output(HANDOFF_HOLD, "WRITER_INVALID")
    acceptor = HandoffAcceptor(writer)
    return acceptor.accept_handoff(**kwargs)


__all__ = [
    "HANDOFF_ACCEPTED_RECOVERY",
    "HANDOFF_ACCEPTOR_ROLE",
    "HANDOFF_ACCEPTOR_SCHEMA",
    "HANDOFF_AUTHORITY_PROTOCOL",
    "HANDOFF_CONFLICT",
    "HANDOFF_HOLD",
    "HANDOFF_REPLAYED",
    "HANDOFF_RECOVERY_REQUIRED",
    "HANDOFF_TERMINATION_SCHEMA",
    "HandoffAcceptError",
    "HandoffAcceptor",
    "InjectedHandoffCrash",
    "accept_handoff",
    "configure_trusted_handoff_authority",
    "configure_trusted_termination_authority",
    "freeze_trusted_handoff_authorities",
    "freeze_trusted_termination_authorities",
]
