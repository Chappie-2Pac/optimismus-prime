"""Adversarial tests for the W5-S23 isolated Prime-Queue writer."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w5_dispatch_bridge_s0.prime_queue_writer import (  # noqa: E402
    InjectedPrimeQueueWriterCrash,
    PrimeQueueWriter,
)
from support.prime_fixture import make_project  # noqa: E402


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class W5S23PrimeQueueWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="w5-s23-queue-writer-")
        self.addCleanup(self.temp.cleanup)
        self.root = make_project(Path(self.temp.name))
        self.queue_path = self.root / "Plan" / "local-ai" / "QUEUE.json"
        queue = json.loads(self.queue_path.read_text(encoding="utf-8"))
        queue["tasks"][0]["owner"] = "codex"
        self.queue_path.write_text(json.dumps(queue), encoding="utf-8")
        self.clock = MutableClock(100)
        self.writer = PrimeQueueWriter(self.root, clock=self.clock)
        self.addCleanup(self.writer.close)
        self.lease = {
            "owner_id": "s23-owner",
            "owner_instance_id": "s23-instance",
            "owner_epoch": 1,
            "fencing_epoch": 1,
            "lease_token": "s23-lease-token-01",
        }
        self.scope_id = "s23-queue-scope"
        self.writer.create_scope(
            scope_id=self.scope_id,
            **self.lease,
            lease_expires_at=1000,
        )

    def _hash(self) -> str:
        return hashlib.sha256(self.queue_path.read_bytes()).hexdigest()

    def _request(self, **changes: object) -> dict[str, object]:
        request: dict[str, object] = {
            "scope_id": self.scope_id,
            "transaction_id": "s23-tx-001",
            "idempotency_key": "s23-idem-001",
            "card_id": "card-1",
            "command": "start",
            "actor": "codex",
            "expected_queue_sha256": self._hash(),
            **self.lease,
        }
        request.update(changes)
        return request

    def test_commit_is_queue_only_and_bound_to_local_journal(self) -> None:
        before = self._hash()
        result = self.writer.execute_transition(**self._request(expected_queue_sha256=before))

        self.assertEqual(result["status"], "QUEUE_COMMITTED")
        self.assertTrue(result["queue_committed"])
        self.assertTrue(result["queue_mutation_performed"])
        self.assertFalse(result["receipt_emitted"])
        self.assertFalse(result["receipt_committed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["global_commit"])
        self.assertEqual(result["cross_store_atomicity"], "NOT_CLAIMED")
        self.assertEqual(json.loads(self.queue_path.read_text())["tasks"][0]["status"], "RUNNING")
        self.assertEqual(self.writer.read_scope(self.scope_id)["event_seq"], 3)
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_operations").fetchone()[0], 1)
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_markers").fetchone()[0], 2)
        self.assertFalse((self.root / "Plan" / "local-ai" / "control" / "mcp-audit.jsonl").exists())
        self.assertFalse((self.root / "Plan" / "local-ai" / "control" / "mcp-receipts").exists())

    def test_stale_hash_and_wrong_fence_hold_before_prepare(self) -> None:
        stale = self.writer.execute_transition(**self._request(expected_queue_sha256="0" * 64))
        self.assertEqual(stale["status"], "HOLD")
        self.assertEqual(stale["reason"], "STALE_QUEUE_HASH")
        self.assertEqual(self.writer.read_scope(self.scope_id)["event_seq"], 1)

        wrong_fence = self.writer.execute_transition(**self._request(lease_token="wrong-lease-token"))
        self.assertEqual(wrong_fence["status"], "HOLD")
        self.assertEqual(wrong_fence["reason"], "FENCE_MISMATCH")
        self.assertEqual(self.writer.read_scope(self.scope_id)["event_seq"], 1)

        self.clock.value = 1001
        expired = self.writer.execute_transition(**self._request())
        self.assertEqual(expired["status"], "HOLD")
        self.assertEqual(expired["reason"], "LEASE_EXPIRED")
        self.assertEqual(self.writer.read_scope(self.scope_id)["event_seq"], 1)

    def test_actor_ownership_and_root_singleton_are_enforced(self) -> None:
        wrong_actor = self.writer.execute_transition(**self._request(actor="local-ai"))
        self.assertEqual(wrong_actor["status"], "HOLD")
        self.assertTrue(wrong_actor["reason"].startswith("QUEUE_ACTOR_AUTHORIZATION_"))
        self.assertEqual(self.writer.read_scope(self.scope_id)["event_seq"], 1)

        with self.assertRaisesRegex(ValueError, "ROOT_SCOPE_ALREADY_EXISTS"):
            self.writer.create_scope(
                scope_id="s23-second-scope",
                **self.lease,
                lease_expires_at=1000,
            )

    def test_lease_expiry_between_prepare_and_replace_fails_closed(self) -> None:
        request = self._request()
        original = self.writer._assert_live_fence

        def expire_before_replace(**kwargs: object) -> None:
            self.clock.value = 1001
            original(**kwargs)

        self.writer._assert_live_fence = expire_before_replace  # type: ignore[method-assign]
        result = self.writer.execute_transition(**request)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(self.writer.read_operation(self.scope_id, request["idempotency_key"])["status"], "PREPARED")
        self.assertEqual(self._hash(), request["expected_queue_sha256"])

    def test_lost_response_replays_with_original_before_hash(self) -> None:
        request = self._request()
        first = self.writer.execute_transition(**request)
        queue_after_first = self.queue_path.read_bytes()
        replay = self.writer.execute_transition(**request)

        self.assertEqual(first["status"], "QUEUE_COMMITTED")
        self.assertEqual(replay["status"], "REPLAYED")
        self.assertFalse(replay["queue_mutation_performed"])
        self.assertEqual(self.queue_path.read_bytes(), queue_after_first)
        self.assertEqual(self.writer.read_scope(self.scope_id)["event_seq"], 3)

    def test_reused_idempotency_or_transaction_key_is_a_conflict(self) -> None:
        request = self._request()
        self.assertEqual(self.writer.execute_transition(**request)["status"], "QUEUE_COMMITTED")

        changed_command = self.writer.execute_transition(**self._request(command="release", reason="different"))
        self.assertEqual(changed_command["status"], "HOLD")
        self.assertEqual(changed_command["reason"], "QUEUE_WRITER_INTENT_CONFLICT")

        changed_idempotency_key = "s23-" + "idem-other"
        changed_key = self.writer.execute_transition(
            **self._request(idempotency_key=changed_idempotency_key, expected_queue_sha256=self._hash())
        )
        self.assertEqual(changed_key["status"], "HOLD")
        self.assertEqual(changed_key["reason"], "QUEUE_WRITER_INTENT_CONFLICT")
        self.assertEqual(self.writer.read_scope(self.scope_id)["event_seq"], 3)

    def test_prepared_scope_blocks_second_mutation_until_explicit_recovery(self) -> None:
        request = self._request()
        self.writer.fault_points.add("after_prepare")
        with self.assertRaises(InjectedPrimeQueueWriterCrash):
            self.writer.execute_transition(**request)
        self.writer.fault_points.clear()

        self.assertEqual(self.writer.read_scope(self.scope_id)["scope_status"], "IN_DOUBT")
        self.assertEqual(self.writer.read_operation(self.scope_id, request["idempotency_key"])["status"], "PREPARED")
        blocked = self.writer.execute_transition(
            **self._request(transaction_id="s23-tx-002", idempotency_key="s23-idem-002")
        )
        self.assertEqual(blocked["status"], "HOLD")
        self.assertEqual(blocked["reason"], "SCOPE_NOT_CLEAN")

        recovered = self.writer.recover_operation(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            **self.lease,
        )
        self.assertEqual(recovered["status"], "QUEUE_ABORTED")
        self.assertEqual(self.writer.read_scope(self.scope_id)["scope_status"], "CLEAN")
        self.assertEqual(self.writer.read_operation(self.scope_id, request["idempotency_key"])["status"], "QUEUE_ABORTED")

    def test_queue_commit_without_local_marker_is_recovered(self) -> None:
        request = self._request()
        self.writer.fault_points.add("after_queue_commit")
        with self.assertRaises(InjectedPrimeQueueWriterCrash):
            self.writer.execute_transition(**request)
        self.writer.fault_points.clear()

        self.assertEqual(self.writer.read_operation(self.scope_id, request["idempotency_key"])["status"], "PREPARED")
        recovered = self.writer.recover_operation(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            **self.lease,
        )
        self.assertEqual(recovered["status"], "QUEUE_COMMITTED")
        self.assertEqual(self.writer.read_scope(self.scope_id)["scope_status"], "CLEAN")
        self.assertEqual(self.writer.execute_transition(**request)["status"], "REPLAYED")

    def test_recovery_rejects_foreign_transaction_binding(self) -> None:
        request = self._request()
        self.writer.fault_points.add("after_queue_commit")
        with self.assertRaises(InjectedPrimeQueueWriterCrash):
            self.writer.execute_transition(**request)
        self.writer.fault_points.clear()
        transaction = next((self.root / "Plan" / "local-ai" / "control").glob("tx-*"))
        manifest_path = transaction / "transaction.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["writer_metadata"]["writer_transaction_id"] = "foreign-transaction"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = self.writer.recover_operation(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            **self.lease,
        )
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(self.writer.read_scope(self.scope_id)["scope_status"], "RECOVERY_REQUIRED")

    def test_recovery_rejects_symlinked_terminal_marker(self) -> None:
        request = self._request()
        self.writer.fault_points.add("after_queue_commit")
        with self.assertRaises(InjectedPrimeQueueWriterCrash):
            self.writer.execute_transition(**request)
        self.writer.fault_points.clear()
        transaction = next((self.root / "Plan" / "local-ai" / "control").glob("tx-*"))
        committed = transaction / "COMMITTED"
        committed.unlink()
        committed.symlink_to("/dev/null")

        result = self.writer.recover_operation(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            **self.lease,
        )
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(self.writer.read_scope(self.scope_id)["scope_status"], "RECOVERY_REQUIRED")

    def test_unknown_queue_drift_requires_recovery_then_quarantine(self) -> None:
        request = self._request()
        self.writer.fault_points.add("after_prepare")
        with self.assertRaises(InjectedPrimeQueueWriterCrash):
            self.writer.execute_transition(**request)
        self.writer.fault_points.clear()
        self.queue_path.write_text("{\"schema\": 1, \"tasks\": []}\n", encoding="utf-8")

        recovery = self.writer.recover_operation(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            **self.lease,
        )
        self.assertEqual(recovery["status"], "RECOVERY_REQUIRED")
        self.assertEqual(self.writer.read_scope(self.scope_id)["scope_status"], "RECOVERY_REQUIRED")

        quarantined = self.writer.quarantine(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            reason="S23 adversarial drift remains unresolved",
            **self.lease,
        )
        self.assertEqual(quarantined["status"], "QUARANTINED")
        self.assertEqual(self.writer.read_scope(self.scope_id)["scope_status"], "QUARANTINED")

    def test_scope_metadata_and_status_drift_fail_closed(self) -> None:
        self.writer.conn.execute(
            "UPDATE prime_queue_writer_scopes SET lease_expires_at=? WHERE scope_id=?",
            (999999, self.scope_id),
        )
        with self.assertRaisesRegex(ValueError, "SCOPE_METADATA_DRIFT"):
            self.writer.read_scope(self.scope_id)

        self.writer.conn.execute(
            "UPDATE prime_queue_writer_scopes SET lease_expires_at=? WHERE scope_id=?",
            (1000, self.scope_id),
        )
        self.writer.conn.execute(
            "UPDATE prime_queue_writer_scopes SET scope_status=? WHERE scope_id=?",
            ("IN_DOUBT", self.scope_id),
        )
        with self.assertRaisesRegex(ValueError, "SCOPE_STATUS_DRIFT"):
            self.writer.read_scope(self.scope_id)

    def test_identical_parallel_requests_have_one_commit_and_one_replay_or_hold(self) -> None:
        request = self._request()

        def worker() -> dict[str, object]:
            writer = PrimeQueueWriter(self.root, clock=self.clock)
            try:
                return writer.execute_transition(**request)
            finally:
                writer.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _item: worker(), range(2)))
        statuses = sorted(result["status"] for result in results)
        self.assertEqual(statuses, ["QUEUE_COMMITTED", "REPLAYED"])
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_operations").fetchone()[0], 1)
        self.assertEqual(self.writer.read_scope(self.scope_id)["event_seq"], 3)

    def test_project_and_database_symlink_paths_fail_closed(self) -> None:
        linked_root = Path(self.temp.name) / "linked-root"
        linked_root.mkdir()
        real_plan = linked_root / "Plan-real"
        (real_plan / "local-ai").mkdir(parents=True)
        (real_plan / "local-ai" / "QUEUE.json").write_text("{\"tasks\": []}\n", encoding="utf-8")
        (linked_root / "Plan").symlink_to(real_plan, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "QUEUE_PARENT_SYMLINK"):
            PrimeQueueWriter(linked_root, clock=self.clock)

        db_path = self.root / "Plan" / "local-ai" / "control" / "prime_queue_writer.sqlite3"
        self.writer.close()
        outside_db = Path(self.temp.name) / "outside.sqlite3"
        outside_db.touch()
        db_path.unlink()
        db_path.symlink_to(outside_db)
        with self.assertRaisesRegex(ValueError, "DB_PATH_MUST_NOT_BE_SYMLINK"):
            PrimeQueueWriter(self.root, clock=self.clock)

    def test_source_does_not_expose_receipt_or_cross_store_write_surface(self) -> None:
        source = (REPO_ROOT / "modules" / "w5_dispatch_bridge_s0" / "prime_queue_writer.py").read_text()
        for forbidden in (
            "prime_writes.record_receipt(",
            "prime_writes.commit_receipt(",
            "prime_writes.write_prime_ledger(",
            "consume_allowed=True",
            "import subprocess",
            "import socket",
            "import urllib",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
