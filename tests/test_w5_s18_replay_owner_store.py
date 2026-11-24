"""Adversarial W5-S18 tests for the persistent replay-owner CAS store."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from modules.w4_small_loop_s0 import canonical_hash  # noqa: E402
from modules.w5_dispatch_bridge_s0.replay_owner_store import (  # noqa: E402
    JOURNAL_IN_DOUBT,
    OWNER_OPERATION,
    ReplayOwnerStore,
    ReplayOwnerStoreError,
)


SCOPE_ID = "replay-scope-s18"
LEASE_TOKEN = "lease-token-s18-initial-012345"
NEW_LEASE_TOKEN = "lease-token-s18-new-0123456789"
SCOPE_BINDING = {
    "replay_namespace": "namespace-s18",
    "registry_id": "registry-s18",
    "registry_version": "registry-v1",
    "registry_epoch": 3,
    "registry_sha256": "0" * 64,
    "profile_set_sha256": "1" * 64,
    "source_set_sha256": "2" * 64,
    "cohort_binding_sha256": "3" * 64,
    "host_id": "host-s18",
    "host_instance_id": "host-instance-s18",
    "worker_epoch": 4,
}


class CrashInjected(RuntimeError):
    pass


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class W5S18ReplayOwnerStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / f"{SCOPE_ID}.sqlite3"
        self.clock = MutableClock(10)
        with self._open() as store:
            store.create_scope(
                scope_id=SCOPE_ID,
                scope_binding=SCOPE_BINDING,
                owner_id="owner-s18",
                owner_instance_id="owner-instance-s18",
                owner_epoch=1,
                fencing_epoch=1,
                lease_token=LEASE_TOKEN,
                lease_expires_at=1000,
            )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _state(self) -> dict:
        with self._open() as store:
            return store.read_state(SCOPE_ID)

    def _open(self, **kwargs: object) -> ReplayOwnerStore:
        return ReplayOwnerStore(self.db_path, scope_id=SCOPE_ID, owner_root=self.temp.name, clock=self.clock, **kwargs)

    def _args(
        self,
        *,
        state: dict | None = None,
        key: str = "idempotency-s18-1",
        transaction_id: str = "transaction-s18-1",
        intent: dict | None = None,
        owner_id: str = "owner-s18",
        owner_instance_id: str = "owner-instance-s18",
        owner_epoch: int = 1,
        fencing_epoch: int = 1,
        lease_token: str = LEASE_TOKEN,
        next_sequence: int | None = None,
    ) -> dict:
        state = state or self._state()
        return {
            "scope_id": SCOPE_ID,
            "scope_binding": copy.deepcopy(SCOPE_BINDING),
            "owner_id": owner_id,
            "owner_instance_id": owner_instance_id,
            "owner_epoch": owner_epoch,
            "fencing_epoch": fencing_epoch,
            "lease_token": lease_token,
            "idempotency_key": key,
            "transaction_id": transaction_id,
            "operation": OWNER_OPERATION,
            "intent": copy.deepcopy(intent or {"effect_digest": "effect-s18-1", "s17_preflight_sha256": "4" * 64}),
            "expected_state_version": state["state_version"],
            "expected_head_sha256": state["head_sha256"],
            "expected_sequence": state["sequence"],
            "next_sequence": state["sequence"] + 1 if next_sequence is None else next_sequence,
            "next_attestation_set_sha256": "5" * 64,
            "next_nonce_sha256": "6" * 64,
        }

    def _advance(self, **overrides: object) -> dict:
        args = self._args(**overrides)
        with self._open() as store:
            return store._advance_validated(**args)

    def test_create_persists_scope_and_initial_empty_index(self) -> None:
        state = self._state()
        self.assertEqual(state["state_version"], 0)
        self.assertEqual(state["sequence"], 0)
        self.assertIsNone(state["head_sha256"])
        self.assertEqual(state["idempotency_index_sha256"], canonical_hash({"entries": []}))
        self.assertEqual(state["journal_status"], "CLEAN")

    def test_first_cas_advances_state_and_writes_one_transition(self) -> None:
        result = self._advance()
        self.assertEqual(result["status"], "OWNER_CAS_COMMITTED")
        self.assertTrue(result["owner_state_advanced"])
        self.assertTrue(result["idempotency_reserved"])
        self.assertTrue(result["cas_authorized"])
        self.assertFalse(result["consume_allowed"])
        state = self._state()
        self.assertEqual(state["state_version"], 1)
        self.assertEqual(state["sequence"], 1)
        self.assertEqual(state["head_sha256"], result["head_after_sha256"])
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM replay_owner_operations").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM replay_owner_transitions").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM replay_owner_events WHERE event_type='OWNER_CAS_COMMITTED'").fetchone()[0], 1)

    def test_restart_replays_exact_idempotency_without_second_transition(self) -> None:
        args = self._args()
        with self._open() as store:
            first = store._advance_validated(**copy.deepcopy(args))
        with self._open() as store:
            retry = store._advance_validated(**copy.deepcopy(args))
        self.assertEqual(retry["status"], "REPLAYED")
        self.assertEqual(retry["original_result"], first)
        self.assertFalse(retry["mutation_performed"])
        with sqlite3.connect(self.db_path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM replay_owner_transitions").fetchone()[0], 1)

    def test_resolve_operation_is_read_only_and_does_not_need_the_lease(self) -> None:
        args = self._args()
        with self._open() as store:
            first = store._advance_validated(**copy.deepcopy(args))
        self.clock.value = 2000
        with self._open() as store:
            resolved = store.resolve_operation(SCOPE_ID, args["idempotency_key"])
            missing = store.resolve_operation(SCOPE_ID, "idempotency-s18-missing")
        self.assertEqual(resolved["status"], "REPLAYED")
        self.assertEqual(resolved["original_result"], first)
        self.assertEqual(missing["status"], "UNRESOLVED")
        self.assertEqual(self._state()["state_version"], 1)

    def test_same_key_different_intent_is_conflict_without_mutation(self) -> None:
        first = self._advance()
        before = self._state()
        result = self._advance(intent={"effect_digest": "different-effect", "s17_preflight_sha256": "4" * 64})
        self.assertEqual(result["status"], "CONFLICT")
        self.assertEqual(result["reason"], "IDEMPOTENCY_INTENT_CONFLICT")
        self.assertEqual(self._state(), before)
        self.assertEqual(result["existing_intent_sha256"], first["intent_sha256"])

    def test_same_key_different_candidate_is_conflict(self) -> None:
        args = self._args()
        with self._open() as store:
            first = store._advance_validated(**copy.deepcopy(args))
        changed = copy.deepcopy(args)
        changed["next_nonce_sha256"] = "7" * 64
        with self._open() as store:
            result = store._advance_validated(**changed)
        self.assertEqual(result["status"], "CONFLICT")
        self.assertEqual(result["existing_intent_sha256"], first["intent_sha256"])
        self.assertEqual(self._state()["state_version"], 1)

    def test_same_key_with_different_expected_parent_is_conflict(self) -> None:
        args = self._args()
        with self._open() as store:
            first = store._advance_validated(**copy.deepcopy(args))
        changed = copy.deepcopy(args)
        changed["expected_state_version"] = 99
        with self._open() as store:
            result = store._advance_validated(**changed)
        self.assertEqual(result["status"], "CONFLICT")
        self.assertEqual(result["reason"], "IDEMPOTENCY_INTENT_CONFLICT")
        self.assertEqual(result["existing_intent_sha256"], first["intent_sha256"])
        self.assertEqual(self._state()["state_version"], 1)

    def test_same_transaction_with_different_key_is_conflict(self) -> None:
        self._advance()
        before = self._state()
        result = self._advance(key="idempotency-" + "s18-other", transaction_id="transaction-" + "s18-1")
        self.assertEqual(result["reason"], "TRANSACTION_ID_CONFLICT")
        self.assertEqual(self._state(), before)

    def test_stale_state_head_and_non_monotone_sequence_are_rejected(self) -> None:
        stale = self._args(key="idempotency-" + "s18-stale", transaction_id="transaction-" + "s18-stale")
        self._advance()
        with self._open() as store:
            result = store._advance_validated(**stale)
        self.assertEqual(result["reason"], "STATE_CAS_MISMATCH")
        self.assertEqual(self._state()["sequence"], 1)

        result = self._advance(key="idempotency-" + "s18-2", transaction_id="transaction-" + "s18-2", next_sequence=1)
        self.assertEqual(result["reason"], "SEQUENCE_NOT_MONOTONE")

    def test_wrong_lease_token_owner_or_epoch_is_fail_closed(self) -> None:
        for overrides, reason in (
            ({"lease_token": "wrong-lease-token-012345"}, "LEASE_TOKEN_MISMATCH"),
            ({"owner_instance_id": "foreign-instance"}, "OWNER_IDENTITY_MISMATCH"),
            ({"fencing_epoch": 99}, "FENCING_EPOCH_MISMATCH"),
        ):
            result = self._advance(key=f"idempotency-{reason}", transaction_id=f"transaction-{reason}", **overrides)
            self.assertEqual(result["reason"], reason)
            self.assertEqual(self._state()["state_version"], 0)

    def test_expired_lease_is_rejected(self) -> None:
        self.clock.value = 1000
        result = self._advance()
        self.assertEqual(result["reason"], "FENCE_EXPIRED")
        self.assertEqual(self._state()["state_version"], 0)

    def test_fence_reclaim_blocks_old_owner_and_allows_new_owner(self) -> None:
        self.clock.value = 1000
        with self._open() as store:
            reclaimed = store.reclaim_fence(
                scope_id=SCOPE_ID,
                expected_owner_id="owner-s18",
                expected_fencing_epoch=1,
                expected_lease_token=LEASE_TOKEN,
                new_owner_id="owner-s18-new",
                new_owner_instance_id="owner-instance-s18-new",
                new_owner_epoch=2,
                new_lease_token=NEW_LEASE_TOKEN,
                new_lease_expires_at=2000,
            )
        self.assertEqual(reclaimed["status"], "OWNER_FENCE_RECLAIMED")
        self.assertEqual(self._state()["state_version"], 0)
        old = self._advance()
        self.assertEqual(old["reason"], "OWNER_IDENTITY_MISMATCH")
        result = self._advance(
            owner_id="owner-s18-new",
            owner_instance_id="owner-instance-s18-new",
            owner_epoch=2,
            fencing_epoch=2,
            lease_token=NEW_LEASE_TOKEN,
            key="idempotency-" + "s18-new",
            transaction_id="transaction-" + "s18-new",
        )
        self.assertEqual(result["status"], "OWNER_CAS_COMMITTED")

    def test_owner_epoch_must_increase_on_fence_reclaim(self) -> None:
        self.clock.value = 1000
        with self._open() as store:
            result = store.reclaim_fence(
                scope_id=SCOPE_ID,
                expected_owner_id="owner-s18",
                expected_fencing_epoch=1,
                expected_lease_token=LEASE_TOKEN,
                new_owner_id="owner-s18-new",
                new_owner_instance_id="owner-instance-s18-new",
                new_owner_epoch=1,
                new_lease_token=NEW_LEASE_TOKEN,
                new_lease_expires_at=2000,
            )
        self.assertEqual(result["reason"], "OWNER_EPOCH_NOT_MONOTONE")
        self.assertEqual(self._state()["fencing_epoch"], 1)

    def test_quarantine_is_persistent_and_never_auto_recovers(self) -> None:
        with self._open() as store:
            state = store.quarantine_scope(SCOPE_ID, status=JOURNAL_IN_DOUBT)
        self.assertEqual(state["journal_status"], JOURNAL_IN_DOUBT)
        result = self._advance()
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(self._state()["journal_status"], JOURNAL_IN_DOUBT)

    def test_corrupt_head_or_index_fails_closed(self) -> None:
        stale = self._args()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE replay_owner_scopes SET head_sha256=? WHERE scope_id=?", ("f" * 64, SCOPE_ID))
        with self.assertRaises(ReplayOwnerStoreError):
            self._state()
        with self._open() as store:
            result = store._advance_validated(**stale)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")

    def test_transition_gap_is_detected_not_repaired(self) -> None:
        self._advance()
        second = self._args(key="idempotency-" + "s18-2", transaction_id="transaction-" + "s18-2")
        with self._open() as store:
            store._advance_validated(**second)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "DELETE FROM replay_owner_transitions WHERE scope_id=? AND after_state_version=1",
                (SCOPE_ID,),
            )
        with self.assertRaises(ReplayOwnerStoreError):
            self._state()
        with self._open() as store:
            result = store.resolve_operation(SCOPE_ID, "idempotency-s18-2")
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")

    def test_database_path_and_scope_identity_are_strict(self) -> None:
        with self.assertRaises(ReplayOwnerStoreError):
            ReplayOwnerStore(Path(self.temp.name) / "other.sqlite3", scope_id=SCOPE_ID, clock=self.clock)
        with self.assertRaises(ReplayOwnerStoreError):
            ReplayOwnerStore(self.db_path, scope_id=SCOPE_ID, clock=self.clock)
        empty_scope = "empty-s18"
        empty_path = Path(self.temp.name) / f"{empty_scope}.sqlite3"
        empty_path.touch()
        with self.assertRaises(ReplayOwnerStoreError):
            ReplayOwnerStore(empty_path, scope_id=empty_scope, owner_root=self.temp.name, clock=self.clock)

    def test_unbound_event_digest_fails_closed(self) -> None:
        self._advance()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE replay_owner_events SET event_sha256=? WHERE scope_id=? AND event_type='OWNER_CAS_COMMITTED'",
                ("e" * 64, SCOPE_ID),
            )
        with self.assertRaises(ReplayOwnerStoreError):
            self._state()

    def test_crash_before_commit_rolls_back(self) -> None:
        def crash(point: str) -> None:
            if point == "before_commit":
                raise CrashInjected(point)

        with self.assertRaises(CrashInjected):
            class FaultStore(ReplayOwnerStore):
                def _fault(self, point: str) -> None:
                    if point == "before_commit":
                        raise CrashInjected(point)

            with FaultStore(self.db_path, scope_id=SCOPE_ID, owner_root=self.temp.name, clock=self.clock) as store:
                store._advance_validated(**self._args())
        self.assertEqual(self._state()["state_version"], 0)
        self.assertEqual(self._advance()["status"], "OWNER_CAS_COMMITTED")

    def test_crash_after_commit_is_resolved_by_replay(self) -> None:
        args = self._args()

        def crash(point: str) -> None:
            if point == "after_commit":
                raise CrashInjected(point)

        with self.assertRaises(CrashInjected):
            class FaultStore(ReplayOwnerStore):
                def _fault(self, point: str) -> None:
                    if point == "after_commit":
                        raise CrashInjected(point)

            with FaultStore(self.db_path, scope_id=SCOPE_ID, owner_root=self.temp.name, clock=self.clock) as store:
                store._advance_validated(**copy.deepcopy(args))
        self.assertEqual(self._state()["state_version"], 1)
        with self._open() as store:
            retry = store._advance_validated(**copy.deepcopy(args))
        self.assertEqual(retry["status"], "REPLAYED")

    def test_concurrent_identical_requests_have_one_commit_and_replays(self) -> None:
        args = self._args()

        def worker() -> dict:
            with self._open(timeout=10) as store:
                return store._advance_validated(**copy.deepcopy(args))

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(lambda _: worker(), range(16)))
        self.assertEqual(sum(result["status"] == "OWNER_CAS_COMMITTED" for result in results), 1)
        self.assertEqual(sum(result["status"] == "REPLAYED" for result in results), 15)
        self.assertEqual(self._state()["state_version"], 1)

    def test_concurrent_different_requests_have_one_cas_winner(self) -> None:
        base = self._args()
        requests = []
        for index in range(16):
            request = copy.deepcopy(base)
            request["idempotency_key"] = f"idempotency-s18-{index}"
            request["transaction_id"] = f"transaction-s18-{index}"
            request["intent"] = {"effect_digest": f"effect-s18-{index}", "s17_preflight_sha256": "4" * 64}
            requests.append(request)

        def worker(request: dict) -> dict:
            with self._open(timeout=10) as store:
                return store._advance_validated(**request)

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(worker, requests))
        self.assertEqual(sum(result["status"] == "OWNER_CAS_COMMITTED" for result in results), 1)
        self.assertEqual(sum(result["reason"] == "STATE_CAS_MISMATCH" for result in results), 15)
        self.assertEqual(self._state()["state_version"], 1)

    def test_module_has_no_process_network_or_prime_mutation_surface(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/replay_owner_store.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket", "urllib", "Popen(", "os.system(", "os.kill(", "prime_transaction_store", "QUEUE.json"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
