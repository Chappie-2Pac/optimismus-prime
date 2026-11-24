"""Adversarial tests for the bounded W5-S25D recovery executor."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import test_w5_s25b_handoff_acceptor as s25b  # noqa: E402
import test_w5_s25c_recovery_eligibility as s25c  # noqa: E402
from modules.w5_dispatch_bridge_s0.recovery_executor import (  # noqa: E402
    InjectedRecoveryExecutorCrash,
    RECOVERY_ABORTED,
    RECOVERY_COMMITTED,
    RECOVERY_HOLD,
    RECOVERY_REPLAYED,
    RECOVERY_REQUIRED,
    RecoveryExecutor,
)


class AdvancingClock:
    def __init__(self, *values: int) -> None:
        self.values = list(values)

    def __call__(self) -> int:
        return self.values.pop(0) if len(self.values) > 1 else self.values[0]


class W5S25DRecoveryExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        s25b.W5S25BHandoffAcceptorTests.setUpClass()

    def _base(self, *, unresolved: bool = True) -> s25b.W5S25BHandoffAcceptorTests:
        helper = s25c.W5S25CRecoveryEligibilityTests()
        base = helper._build_transaction_base(unresolved=unresolved)
        self.addCleanup(base.doCleanups)
        accepted = base.accept()
        self.assertEqual(accepted["status"], "ACCEPTED_RECOVERY")
        return base

    @staticmethod
    def _resolve(base: s25b.W5S25BHandoffAcceptorTests, **kwargs: object) -> dict[str, object]:
        return RecoveryExecutor(base.writer, **kwargs).resolve(
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )

    def test_before_evidence_aborts_without_queue_file_write(self) -> None:
        base = self._base(unresolved=True)
        before = base.queue_path.read_bytes()

        result = self._resolve(base)

        self.assertEqual(result["status"], RECOVERY_ABORTED)
        self.assertEqual(result["transaction_state"], "BEFORE")
        self.assertFalse(result["queue_file_mutation_performed"])
        self.assertEqual(result["queue_mutation_evidence"], "FALSE")
        self.assertTrue(result["transaction_marker_written"])
        self.assertTrue(result["sqlite_state_written"])
        self.assertEqual(base.queue_path.read_bytes(), before)
        self.assertEqual(base.writer.read_scope(base.scope_id)["active_phase"], "IDLE")
        self.assertEqual(base.writer.read_operation(base.scope_id, "s25b-idem")["status"], "QUEUE_ABORTED")

    def test_after_evidence_commits_only_the_existing_queue_transaction(self) -> None:
        base = self._base(unresolved=False)
        after = base.queue_path.read_bytes()

        result = self._resolve(base)

        self.assertEqual(result["status"], RECOVERY_COMMITTED)
        self.assertEqual(result["transaction_state"], "AFTER")
        self.assertFalse(result["queue_file_mutation_performed"])
        self.assertEqual(result["queue_mutation_evidence"], "TRUE")
        self.assertEqual(base.queue_path.read_bytes(), after)
        self.assertEqual(base.writer.read_operation(base.scope_id, "s25b-idem")["status"], "QUEUE_COMMITTED")

    def test_after_commit_response_loss_is_read_only_replayed(self) -> None:
        base = self._base(unresolved=False)

        with self.assertRaises(InjectedRecoveryExecutorCrash) as raised:
            self._resolve(base, fault_points={"after_state_mark"})

        self.assertEqual(raised.exception.point, "after_state_mark")
        replay = self._resolve(base)

        self.assertEqual(replay["status"], RECOVERY_REPLAYED)
        self.assertEqual(replay["queue_mutation_evidence"], "TRUE")
        self.assertFalse(replay["sqlite_state_written"])

    def test_crash_before_claim_is_retryable_and_does_not_claim_scope(self) -> None:
        base = self._base(unresolved=True)

        with self.assertRaises(InjectedRecoveryExecutorCrash) as raised:
            self._resolve(base, fault_points={"before_claim"})

        self.assertEqual(raised.exception.point, "before_claim")
        self.assertEqual(base.writer.read_scope(base.scope_id)["active_phase"], "RECOVERY")
        self.assertEqual(base.writer.read_operation(base.scope_id, "s25b-idem")["status"], "PREPARED")
        self.assertEqual(self._resolve(base)["status"], RECOVERY_ABORTED)

    def test_crash_after_terminal_marker_replays_marker_then_marks_state(self) -> None:
        base = self._base(unresolved=True)

        with self.assertRaises(InjectedRecoveryExecutorCrash) as raised:
            self._resolve(base, fault_points={"after_terminal_marker"})

        self.assertEqual(raised.exception.point, "after_terminal_marker")
        row = base.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=?",
            (base.scope_id,),
        ).fetchone()
        exact, other_open, invalid = base.writer._transaction_details(row)
        self.assertIsNotNone(exact)
        self.assertFalse(other_open)
        self.assertFalse(invalid)
        self.assertTrue((Path(exact) / "ABORTED").is_file())
        self.assertEqual(row["state"], "PREPARED")

        result = self._resolve(base)

        self.assertEqual(result["status"], RECOVERY_ABORTED)
        self.assertEqual(base.writer.read_scope(base.scope_id)["active_phase"], "IDLE")

    def test_crash_after_claim_is_retryable_without_terminal_marker(self) -> None:
        base = self._base(unresolved=True)

        with self.assertRaises(InjectedRecoveryExecutorCrash) as raised:
            self._resolve(base, fault_points={"after_claim"})

        self.assertEqual(raised.exception.point, "after_claim")
        row = base.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=?",
            (base.scope_id,),
        ).fetchone()
        exact, other_open, invalid = base.writer._transaction_details(row)
        self.assertIsNotNone(exact)
        self.assertFalse(other_open)
        self.assertFalse(invalid)
        self.assertFalse((Path(exact) / "ABORTED").exists())
        self.assertEqual(self._resolve(base)["status"], RECOVERY_ABORTED)

    def test_crash_before_terminal_marker_leaves_no_terminal_marker(self) -> None:
        base = self._base(unresolved=True)

        with self.assertRaises(InjectedRecoveryExecutorCrash) as raised:
            self._resolve(base, fault_points={"before_terminal_marker"})

        self.assertEqual(raised.exception.point, "before_terminal_marker")
        row = base.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=?",
            (base.scope_id,),
        ).fetchone()
        exact, other_open, invalid = base.writer._transaction_details(row)
        self.assertIsNotNone(exact)
        self.assertFalse(other_open)
        self.assertFalse(invalid)
        self.assertFalse((Path(exact) / "ABORTED").exists())
        self.assertEqual(self._resolve(base)["status"], RECOVERY_ABORTED)

    def test_crash_before_state_mark_leaves_terminal_evidence_but_open_operation(self) -> None:
        base = self._base(unresolved=True)

        with self.assertRaises(InjectedRecoveryExecutorCrash) as raised:
            self._resolve(base, fault_points={"before_state_mark"})

        self.assertEqual(raised.exception.point, "before_state_mark")
        row = base.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=?",
            (base.scope_id,),
        ).fetchone()
        exact, other_open, invalid = base.writer._transaction_details(row)
        self.assertIsNotNone(exact)
        self.assertFalse(other_open)
        self.assertFalse(invalid)
        self.assertTrue((Path(exact) / "ABORTED").is_file())
        self.assertEqual(row["state"], "PREPARED")
        self.assertEqual(self._resolve(base)["status"], RECOVERY_ABORTED)

    def test_explicit_initial_time_does_not_freeze_later_lease_revalidation(self) -> None:
        base = self._base(unresolved=True)
        clock = AdvancingClock(200, 200, 200, 1000)
        base.writer.clock = clock

        result = RecoveryExecutor(base.writer, clock=clock).resolve(
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=200,
        )

        self.assertEqual(result["status"], RECOVERY_HOLD)
        self.assertEqual(result["reason"], "RECOVERY_LEASE_EXPIRED")
        row = base.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=?",
            (base.scope_id,),
        ).fetchone()
        exact, other_open, invalid = base.writer._transaction_details(row)
        self.assertIsNotNone(exact)
        self.assertFalse(other_open)
        self.assertFalse(invalid)
        self.assertTrue((Path(exact) / "ABORTED").is_file())
        self.assertEqual(row["state"], "PREPARED")

    def test_nonterminal_state_mark_readback_is_not_reported_as_success(self) -> None:
        base = self._base(unresolved=True)
        original_mark_state = base.writer._mark_state

        def downgrade_state(**kwargs: object) -> dict[str, object]:
            changed = dict(kwargs)
            changed["state"] = "IN_DOUBT"
            changed["queue_mutation_performed"] = None
            changed["queue_mutation_evidence"] = "UNKNOWN"
            changed["result"] = {"injected": True}
            return original_mark_state(**changed)

        with patch.object(base.writer, "_mark_state", side_effect=downgrade_state):
            result = self._resolve(base)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "RECOVERY_STATE_MARK_NOT_TERMINAL")
        self.assertEqual(base.writer.read_operation(base.scope_id, "s25b-idem")["status"], "IN_DOUBT")

    def test_crash_after_state_mark_is_a_read_only_replay(self) -> None:
        base = self._base(unresolved=True)

        with self.assertRaises(InjectedRecoveryExecutorCrash) as raised:
            self._resolve(base, fault_points={"after_state_mark"})

        self.assertEqual(raised.exception.point, "after_state_mark")
        replay = self._resolve(base)

        self.assertEqual(replay["status"], RECOVERY_REPLAYED)
        self.assertTrue(replay["replayed"])
        self.assertFalse(replay["sqlite_state_written"])
        self.assertFalse(replay["queue_file_mutation_performed"])

    def test_lease_or_queue_drift_holds_without_mutation(self) -> None:
        base = self._base(unresolved=True)
        before = base.writer.read_scope(base.scope_id), base.writer.read_operation(base.scope_id, "s25b-idem")
        wrong = RecoveryExecutor(base.writer).resolve(
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token="wrong-lease-token-012345",
            now=base.clock.value,
        )
        self.assertEqual(wrong["status"], RECOVERY_HOLD)
        self.assertEqual(wrong["reason"], "RECOVERY_LEASE_TOKEN_MISMATCH")
        self.assertEqual(base.writer.read_scope(base.scope_id), before[0])
        self.assertEqual(base.writer.read_operation(base.scope_id, "s25b-idem"), before[1])

        base.queue_path.write_bytes(b"foreign queue bytes")
        drift = self._resolve(base)
        self.assertEqual(drift["status"], RECOVERY_REQUIRED)
        self.assertEqual(drift["reason"], "QUEUE_HASH_DRIFT")
        self.assertEqual(base.writer.read_scope(base.scope_id)["active_phase"], "RECOVERY")

    def test_legacy_recovery_cannot_bypass_an_accepted_handoff(self) -> None:
        base = self._base(unresolved=True)
        before_scope = base.writer.read_scope(base.scope_id)
        before_operation = base.writer.read_operation(base.scope_id, "s25b-idem")

        result = base.writer.recover_operation(
            scope_id=base.scope_id,
            idempotency_key="s25b-idem",
            owner_id="new-owner",
            owner_instance_id="new-instance",
            owner_epoch=5,
            fencing_epoch=10,
            lease_token=base.new_lease,
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "S25D_EXECUTOR_REQUIRED")
        self.assertEqual(base.writer.read_scope(base.scope_id), before_scope)
        self.assertEqual(base.writer.read_operation(base.scope_id, "s25b-idem"), before_operation)

    def test_active_writer_lock_is_hold_and_missing_lock_is_not_created(self) -> None:
        base = self._base(unresolved=True)
        lock_path = base.writer.root / "Plan" / "local-ai" / "control" / "queue.lock"
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held = self._resolve(base)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertEqual(held["status"], RECOVERY_HOLD)
        self.assertEqual(held["reason"], "QUEUE_WRITER_ACTIVE")

        lock_path.unlink()
        missing = self._resolve(base)
        self.assertEqual(missing["status"], RECOVERY_HOLD)
        self.assertEqual(missing["reason"], "QUEUE_LOCK_NOT_AVAILABLE")
        self.assertFalse(lock_path.exists())

    def test_schema_drift_is_recovery_required_before_claim(self) -> None:
        base = self._base(unresolved=True)
        base.writer.conn.execute("DROP TRIGGER prime_queue_writer_handoff_events_immutable_update")

        result = self._resolve(base)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "DB_SCHEMA_TRIGGERS_INVALID")
        self.assertEqual(base.writer.read_scope(base.scope_id)["active_phase"], "RECOVERY")

    def test_source_surface_has_no_second_writer_or_cross_store_entrypoint(self) -> None:
        source = (REPO_ROOT / "modules" / "w5_dispatch_bridge_s0" / "recovery_executor.py").read_text()
        for forbidden in (
            "recover_operation(",
            "execute_transition(",
            "sqlite3.connect",
            "prime_writes.",
            "os.replace",
            "O_CREAT",
            "durable_new",
            "write_bytes",
            "write_text",
            "unlink",
            "EXECUTING",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
