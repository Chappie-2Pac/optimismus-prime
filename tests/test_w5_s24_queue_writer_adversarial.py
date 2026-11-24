"""Adversarial acceptance tests for the W5-S24 queue-writer boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w5_dispatch_bridge_s0.prime_queue_writer import (  # noqa: E402
    InjectedPrimeQueueWriterCrash,
    PrimeQueueWriter,
    PrimeQueueWriterError,
)
from mcp import prime_writes  # noqa: E402
from support.prime_fixture import make_project  # noqa: E402


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class S24Fixture:
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="w5-s24-queue-writer-")
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
            "owner_id": "s24-owner",
            "owner_instance_id": "s24-instance",
            "owner_epoch": 1,
            "fencing_epoch": 1,
            "lease_token": "s24-lease-token-01",
        }
        self.scope_id = "s24-queue-scope"
        self.writer.create_scope(
            scope_id=self.scope_id,
            **self.lease,
            lease_expires_at=1000,
        )

    def queue_hash(self) -> str:
        return hashlib.sha256(self.queue_path.read_bytes()).hexdigest()

    def request(self, **changes: object) -> dict[str, object]:
        request: dict[str, object] = {
            "scope_id": self.scope_id,
            "transaction_id": "s24-tx-001",
            "idempotency_key": "s24-idem-001",
            "card_id": "card-1",
            "command": "start",
            "actor": "codex",
            "expected_queue_sha256": self.queue_hash(),
            **self.lease,
        }
        request.update(changes)
        return request

    def control(self) -> Path:
        return self.root / "Plan" / "local-ai" / "control"

    def crash_after_prepare(self, request: dict[str, object] | None = None) -> dict[str, object]:
        request = request or self.request()
        self.writer.fault_points.add("after_prepare")
        with self.assertRaises(InjectedPrimeQueueWriterCrash):  # type: ignore[attr-defined]
            self.writer.execute_transition(**request)
        self.writer.fault_points.clear()
        return request


class W5S24QueueWriterAdversarialTests(S24Fixture, unittest.TestCase):
    def test_normal_write_does_not_recover_foreign_open_transaction(self) -> None:
        foreign = self.control() / "tx-foreign-open"
        foreign.mkdir(mode=0o700)
        (foreign / "PREPARED").write_bytes(b"prepared\n")
        before = self.queue_hash()

        result = self.writer.execute_transition(**self.request(expected_queue_sha256=before))

        self.assertIn(result["status"], {"HOLD", "RECOVERY_REQUIRED"})
        self.assertFalse((foreign / "COMMITTED").exists())
        self.assertFalse((foreign / "ABORTED").exists())
        self.assertEqual(self.queue_hash(), before)
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_operations").fetchone()[0], 0)
        self.assertEqual(self.writer.read_scope(self.scope_id)["active_phase"], "IDLE")

    def test_recovery_rejects_malformed_transaction_instead_of_aborting(self) -> None:
        request = self.crash_after_prepare()
        transaction = self.control() / "tx-malformed"
        transaction.mkdir(mode=0o700)
        (transaction / "PREPARED").write_bytes(b"prepared\n")
        (transaction / "transaction.json").write_text("{broken", encoding="utf-8")
        (transaction / "before.json").write_bytes(b"before")
        (transaction / "after.json").write_bytes(b"after")

        result = self.writer.recover_operation(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            **self.lease,
        )

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(
            self.writer.read_operation(self.scope_id, request["idempotency_key"])["status"],
            "RECOVERY_REQUIRED",
        )
        self.assertFalse((transaction / "COMMITTED").exists())
        self.assertFalse((transaction / "ABORTED").exists())

    def test_recovery_rejects_symlink_transaction_directory(self) -> None:
        request = self.crash_after_prepare()
        outside = Path(self.temp.name) / "outside-tx"
        outside.mkdir()
        (outside / "PREPARED").write_bytes(b"prepared\n")
        (self.control() / "tx-symlink").symlink_to(outside, target_is_directory=True)

        result = self.writer.recover_operation(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            **self.lease,
        )

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertTrue((self.control() / "tx-symlink").is_symlink())
        self.assertEqual(self.writer.read_scope(self.scope_id)["scope_status"], "RECOVERY_REQUIRED")

    def test_recovery_cannot_take_an_executing_claim(self) -> None:
        request = self.crash_after_prepare()
        self.writer.conn.execute(
            "UPDATE prime_queue_writer_scopes SET active_phase='EXECUTING' WHERE scope_id=?",
            (self.scope_id,),
        )

        result = self.writer.recover_operation(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            **self.lease,
        )

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertIn("OPERATION_PHASE_CONFLICT", result["reason"])
        self.assertEqual(self.writer.read_scope(self.scope_id)["active_phase"], "EXECUTING")

    def test_lease_is_checked_at_the_non_skippable_before_replace_hook(self) -> None:
        request = self.request()
        original = self.writer._assert_live_fence
        calls = 0

        def expire_on_before_replace(**kwargs: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                self.clock.value = 1001
            original(**kwargs)

        self.writer._assert_live_fence = expire_on_before_replace  # type: ignore[method-assign]
        result = self.writer.execute_transition(**request)

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(calls, 2)
        self.assertEqual(self.queue_hash(), request["expected_queue_sha256"])
        self.assertEqual(self.writer.read_operation(self.scope_id, request["idempotency_key"])["status"], "PREPARED")

    def test_lease_expiring_during_temp_write_is_checked_before_replace(self) -> None:
        request = self.request()
        state = prime_writes._state()
        original_state_loader = prime_writes._state
        original_durable_new = state.durable_new

        def expire_after_temp(path: Path, data: bytes) -> None:
            original_durable_new(path, data)
            if Path(path).name.startswith(".QUEUE."):
                self.clock.value = 1001

        prime_writes._state = lambda: state  # type: ignore[method-assign]
        state.durable_new = expire_after_temp  # type: ignore[method-assign]
        try:
            result = self.writer.execute_transition(**request)
        finally:
            state.durable_new = original_durable_new  # type: ignore[method-assign]
            prime_writes._state = original_state_loader  # type: ignore[method-assign]

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(self.queue_hash(), request["expected_queue_sha256"])


    def test_recovery_checks_lease_before_writing_terminal_marker(self) -> None:
        request = self.request()
        self.writer.fault_points.add("after_queue_commit")
        with self.assertRaises(InjectedPrimeQueueWriterCrash):
            self.writer.execute_transition(**request)
        self.writer.fault_points.clear()
        transaction = next(self.control().glob("tx-*"))
        (transaction / "COMMITTED").unlink()
        original = self.writer._assert_live_fence

        def expire_before_marker(**kwargs: object) -> None:
            self.clock.value = 1001
            original(**kwargs)

        self.writer._assert_live_fence = expire_before_marker  # type: ignore[method-assign]
        result = self.writer.recover_operation(
            scope_id=self.scope_id,
            idempotency_key=request["idempotency_key"],
            **self.lease,
        )

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertFalse((transaction / "COMMITTED").exists())
        self.assertEqual(self.writer.read_operation(self.scope_id, request["idempotency_key"])["status"], "PREPARED")

    def test_recovery_revalidates_lease_after_terminal_marker_write(self) -> None:
        request = self.request()
        self.writer.fault_points.add("after_queue_commit")
        with self.assertRaises(InjectedPrimeQueueWriterCrash):
            self.writer.execute_transition(**request)
        self.writer.fault_points.clear()
        transaction = next(self.control().glob("tx-*"))
        (transaction / "COMMITTED").unlink()
        state = prime_writes._state()
        original_state_loader = prime_writes._state
        original_durable_new = state.durable_new

        def expire_after_marker(path: Path, data: bytes) -> None:
            original_durable_new(path, data)
            if Path(path).name == "COMMITTED":
                self.clock.value = 1001

        prime_writes._state = lambda: state  # type: ignore[method-assign]
        state.durable_new = expire_after_marker  # type: ignore[method-assign]
        try:
            result = self.writer.recover_operation(
                scope_id=self.scope_id,
                idempotency_key=request["idempotency_key"],
                **self.lease,
            )
        finally:
            state.durable_new = original_durable_new  # type: ignore[method-assign]
            prime_writes._state = original_state_loader  # type: ignore[method-assign]

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertTrue((transaction / "COMMITTED").is_file())
        self.assertEqual(self.writer.read_operation(self.scope_id, request["idempotency_key"])["status"], "PREPARED")

    def test_prepare_is_recovery_required_when_phase_claim_fails(self) -> None:
        def fail_claim(**_kwargs: object) -> None:
            raise PrimeQueueWriterError("INJECTED_PHASE_CLAIM_FAILURE")

        self.writer._claim_phase = fail_claim  # type: ignore[method-assign]
        request = self.request()
        result = self.writer.execute_transition(**request)

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(self.writer.read_scope(self.scope_id)["active_phase"], "RECOVERY")
        self.assertEqual(self.writer.read_operation(self.scope_id, request["idempotency_key"])["status"], "PREPARED")

    def test_active_operation_fields_are_integrity_bound(self) -> None:
        self.writer.conn.execute(
            "UPDATE prime_queue_writer_scopes SET active_operation_id=?,active_phase='EXECUTING' WHERE scope_id=?",
            ("ghost-operation", self.scope_id),
        )

        with self.assertRaisesRegex(ValueError, "ACTIVE_OPERATION_MISSING"):
            self.writer.read_scope(self.scope_id)

    def test_orphaned_nonterminal_operation_is_integrity_bound(self) -> None:
        request = self.request()
        self.assertEqual(self.writer.execute_transition(**request)["status"], "QUEUE_COMMITTED")
        self.writer.conn.execute(
            "UPDATE prime_queue_writer_operations SET state='PREPARED' WHERE scope_id=? AND idempotency_key=?",
            (self.scope_id, request["idempotency_key"]),
        )

        with self.assertRaisesRegex(ValueError, "ACTIVE_OPERATION_ORPHANED"):
            self.writer.read_scope(self.scope_id)

    def test_malformed_terminal_transaction_blocks_s23_preflight(self) -> None:
        foreign = self.control() / "tx-foreign-terminal"
        foreign.mkdir(mode=0o700)
        before = b"foreign-before\n"
        after = b"foreign-after\n"
        (foreign / "before.json").write_bytes(before)
        (foreign / "after.json").write_bytes(after)
        (foreign / "transaction.json").write_text(
            json.dumps(
                {
                    "before_sha256": hashlib.sha256(before).hexdigest(),
                    "after_sha256": hashlib.sha256(after).hexdigest(),
                }
            ),
            encoding="utf-8",
        )
        (foreign / "PREPARED").write_bytes(b"prepared\n")
        (foreign / "COMMITTED").write_bytes(b"forged marker\n")
        before_queue = self.queue_hash()

        result = self.writer.execute_transition(**self.request(expected_queue_sha256=before_queue))

        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(self.queue_hash(), before_queue)
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_operations").fetchone()[0], 0)

    def test_existing_database_requires_full_wal_durability(self) -> None:
        db_path = self.writer.db_path
        self.writer.close()
        connection = sqlite3.connect(str(db_path), isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
        finally:
            connection.close()

        with self.assertRaisesRegex(ValueError, "DB_DURABILITY_SETTINGS_INVALID"):
            PrimeQueueWriter(self.root, clock=self.clock)

    def test_existing_database_requires_schema_triggers(self) -> None:
        db_path = self.writer.db_path
        self.writer.close()
        connection = sqlite3.connect(str(db_path), isolation_level=None)
        try:
            connection.execute("DROP TRIGGER prime_queue_writer_markers_immutable_delete")
        finally:
            connection.close()

        with self.assertRaisesRegex(ValueError, "DB_SCHEMA_OBJECTS_INVALID"):
            PrimeQueueWriter(self.root, clock=self.clock)


if __name__ == "__main__":
    unittest.main()
