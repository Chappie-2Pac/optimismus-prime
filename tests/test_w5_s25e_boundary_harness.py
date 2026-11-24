"""W5-S25E test-only boundary, reopen and process-abort harness cases."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
import sqlite3
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import test_w5_s25b_handoff_acceptor as s25b  # noqa: E402
import test_w5_s25c_recovery_eligibility as s25c  # noqa: E402
from modules.w5_dispatch_bridge_s0.recovery_executor import (  # noqa: E402
    RECOVERY_ABORTED,
    RECOVERY_REPLAYED,
    RecoveryExecutor,
)
from modules.w5_dispatch_bridge_s0.prime_queue_writer import PrimeQueueWriter  # noqa: E402
from support.w5_s25e_harness import (  # noqa: E402
    BOUNDARY_CASE_RECORDED,
    CASE_CRASHED,
    CLAIMED,
    HOLD,
    NOT_CLAIMED,
    RECOVERY_REQUIRED,
    observe_read_only_boundary,
    reopen_read_only,
    run_boundary_case,
    run_killed_child_after_terminal_marker,
    snapshot_writer_store,
)


class W5S25EBoundaryHarnessTests(unittest.TestCase):
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
    def _resolve(base: s25b.W5S25BHandoffAcceptorTests) -> dict[str, object]:
        return RecoveryExecutor(base.writer).resolve(
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )

    def test_public_s25d_case_is_projected_without_queue_json_write(self) -> None:
        base = self._base(unresolved=True)

        result = run_boundary_case(
            "before-recovery",
            base.writer,
            lambda: self._resolve(base),
            reopen=True,
        )

        self.assertEqual(result["status"], BOUNDARY_CASE_RECORDED)
        self.assertEqual(result["observed_s25d_status"], "RECOVERY_ABORTED")
        self.assertFalse(result["queue_json_write"])
        self.assertTrue(result["local_queue_writer_mutation"])
        self.assertEqual(result["cross_store_write"], NOT_CLAIMED)
        self.assertEqual(result["threats"]["queue_path_aba"], NOT_CLAIMED)
        self.assertEqual(result["threats"]["path_toctou"], NOT_CLAIMED)
        self.assertEqual(result["threats"]["wal_reopen"], CLAIMED)

    def test_read_only_observer_claims_only_current_fd_path_stability(self) -> None:
        base = self._base(unresolved=True)
        before = snapshot_writer_store(base.writer)

        observed = observe_read_only_boundary(base.writer)

        self.assertEqual(observed["status"], BOUNDARY_CASE_RECORDED)
        self.assertEqual(observed["decision"], "OBSERVE_ONLY")
        self.assertEqual(observed["threats"]["lock_inode_identity"], CLAIMED)
        self.assertEqual(observed["threats"]["queue_read_stable"], CLAIMED)
        self.assertEqual(observed["threats"]["queue_path_aba"], NOT_CLAIMED)
        self.assertEqual(observed["threats"]["lock_inode_aba"], NOT_CLAIMED)
        self.assertFalse(observed["recovery_authority"])
        self.assertFalse(observed["mutation_allowed"])
        self.assertEqual(before, snapshot_writer_store(base.writer))

    def test_read_only_observer_detects_lock_inode_aba_without_repair(self) -> None:
        base = self._base(unresolved=True)
        lock_path = base.writer.root / "Plan" / "local-ai" / "control" / "queue.lock"

        def replace_lock_path() -> None:
            replacement = lock_path.with_name("queue.lock.replacement")
            replacement.touch()
            os.replace(replacement, lock_path)

        observed = observe_read_only_boundary(
            base.writer,
            mutate_lock_after_open=replace_lock_path,
        )

        self.assertEqual(observed["status"], RECOVERY_REQUIRED)
        self.assertEqual(observed["lock"]["reason"], "FD_PATH_OR_CONTENT_BOUNDARY_DRIFT")
        self.assertEqual(observed["threats"]["lock_inode_identity"], RECOVERY_REQUIRED)
        self.assertEqual(observed["foreign_repair_performed"], NOT_CLAIMED)

    def test_read_only_observer_detects_queue_a_to_b_to_a_inode_drift(self) -> None:
        base = self._base(unresolved=True)
        queue_path = base.writer.queue_path
        original = queue_path.read_bytes()

        def replace_queue_a_b_a() -> None:
            middle = queue_path.with_name("QUEUE.json.middle")
            final = queue_path.with_name("QUEUE.json.final")
            middle.write_bytes(original + b"\n")
            os.replace(middle, queue_path)
            final.write_bytes(original)
            os.replace(final, queue_path)

        observed = observe_read_only_boundary(
            base.writer,
            mutate_queue_after_open=replace_queue_a_b_a,
        )

        self.assertEqual(observed["status"], RECOVERY_REQUIRED)
        self.assertEqual(observed["queue"]["reason"], "FD_PATH_OR_CONTENT_BOUNDARY_DRIFT")
        self.assertEqual(observed["threats"]["queue_path_aba"], RECOVERY_REQUIRED)
        self.assertEqual(observed["threats"]["queue_read_stable"], RECOVERY_REQUIRED)
        self.assertFalse(observed["queue_file_write"])

    def test_read_only_observer_detects_same_inode_queue_content_drift(self) -> None:
        base = self._base(unresolved=True)
        queue_path = base.writer.queue_path
        original = queue_path.read_bytes()

        def rewrite_same_inode() -> None:
            queue_path.write_bytes(original + b"same-inode-drift")

        observed = observe_read_only_boundary(
            base.writer,
            mutate_queue_after_open=rewrite_same_inode,
        )

        self.assertEqual(observed["status"], RECOVERY_REQUIRED)
        self.assertEqual(observed["queue"]["reason"], "FD_PATH_OR_CONTENT_BOUNDARY_DRIFT")
        self.assertEqual(observed["threats"]["queue_path_aba"], RECOVERY_REQUIRED)
        self.assertNotEqual(
            observed["queue"]["fd_sha256_before"],
            observed["queue"]["fd_sha256"],
        )

    def test_read_only_observer_detects_queue_a_to_b_unknown_hash(self) -> None:
        base = self._base(unresolved=True)
        queue_path = base.writer.queue_path
        original = queue_path.read_bytes()

        def replace_queue_path() -> None:
            replacement = queue_path.with_name("QUEUE.json.unknown")
            replacement.write_bytes(original + b"unknown-boundary")
            os.replace(replacement, queue_path)

        observed = observe_read_only_boundary(
            base.writer,
            mutate_queue_after_open=replace_queue_path,
        )

        self.assertEqual(observed["status"], RECOVERY_REQUIRED)
        self.assertEqual(observed["queue"]["reason"], "FD_PATH_OR_CONTENT_BOUNDARY_DRIFT")
        self.assertEqual(observed["threats"]["queue_path_aba"], RECOVERY_REQUIRED)

    def test_read_only_observer_detects_lock_symlink_without_following(self) -> None:
        base = self._base(unresolved=True)
        lock_path = base.writer.root / "Plan" / "local-ai" / "control" / "queue.lock"

        def replace_lock_with_symlink() -> None:
            lock_path.unlink()
            os.symlink("queue.lock.target", lock_path)

        observed = observe_read_only_boundary(
            base.writer,
            mutate_lock_after_open=replace_lock_with_symlink,
        )

        self.assertEqual(observed["status"], RECOVERY_REQUIRED)
        self.assertEqual(observed["threats"]["lock_inode_identity"], RECOVERY_REQUIRED)

    def test_read_only_reopen_rejects_trigger_schema_drift(self) -> None:
        base = self._base(unresolved=True)
        base.writer.close()
        connection = sqlite3.connect(str(base.writer.db_path), isolation_level=None)
        try:
            connection.execute("DROP TRIGGER prime_queue_writer_events_immutable_update")
        finally:
            connection.close()

        reopened = reopen_read_only(base.writer)
        self.assertEqual(reopened["status"], RECOVERY_REQUIRED)
        self.assertEqual(reopened["reason"], "REOPEN_SCHEMA_DURABILITY_OR_INTEGRITY_DRIFT")

    def test_sigkill_after_terminal_marker_reopens_to_pending_then_retries(self) -> None:
        base = self._base(unresolved=True)
        root = base.root
        scope_id = base.scope_id
        handoff_id = base.grant["handoff_id"]
        lease_token = base.new_lease
        base.writer.close()

        killed = run_killed_child_after_terminal_marker(
            root,
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=200,
        )
        self.assertEqual(killed["status"], CASE_CRASHED)
        self.assertEqual(killed["signal"], 9)

        reopened = PrimeQueueWriter(root, clock=base.clock)
        self.addCleanup(reopened.close)
        row = reopened.conn.execute(
            "SELECT state FROM prime_queue_writer_operations WHERE scope_id=?",
            (scope_id,),
        ).fetchone()
        self.assertEqual(row["state"], "PREPARED")
        retry = RecoveryExecutor(reopened).resolve(
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=200,
        )
        self.assertEqual(retry["status"], RECOVERY_ABORTED)
        self.assertEqual(reopen_read_only(reopened)["status"], CLAIMED)

    def test_sigkill_before_terminal_marker_reopens_pending_without_marker(self) -> None:
        base = self._base(unresolved=True)
        root = base.root
        scope_id = base.scope_id
        handoff_id = base.grant["handoff_id"]
        lease_token = base.new_lease
        base.writer.close()

        killed = run_killed_child_after_terminal_marker(
            root,
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=200,
            kill_at="before_terminal_marker",
        )
        self.assertEqual(killed["status"], CASE_CRASHED)
        self.assertEqual(killed["signal"], 9)

        reopened = PrimeQueueWriter(root, clock=base.clock)
        self.addCleanup(reopened.close)
        row = reopened.conn.execute(
            "SELECT state FROM prime_queue_writer_operations WHERE scope_id=?",
            (scope_id,),
        ).fetchone()
        self.assertEqual(row["state"], "PREPARED")
        retry = RecoveryExecutor(reopened).resolve(
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=200,
        )
        self.assertEqual(retry["status"], RECOVERY_ABORTED)

    def test_sigkill_after_state_mark_reopens_as_read_only_replay(self) -> None:
        base = self._base(unresolved=False)
        root = base.root
        scope_id = base.scope_id
        handoff_id = base.grant["handoff_id"]
        lease_token = base.new_lease
        base.writer.close()

        killed = run_killed_child_after_terminal_marker(
            root,
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=200,
            kill_at="after_state_mark",
        )
        self.assertEqual(killed["status"], CASE_CRASHED)
        self.assertEqual(killed["signal"], 9)

        reopened = PrimeQueueWriter(root, clock=base.clock)
        self.addCleanup(reopened.close)
        replay = RecoveryExecutor(reopened).resolve(
            scope_id=scope_id,
            handoff_id=handoff_id,
            lease_token=lease_token,
            now=200,
        )
        self.assertEqual(replay["status"], RECOVERY_REPLAYED)
        self.assertFalse(replay["sqlite_state_written"])
        self.assertEqual(reopen_read_only(reopened)["status"], CLAIMED)

    def test_missing_or_active_lock_is_hold_and_never_created(self) -> None:
        base = self._base(unresolved=True)
        lock_path = base.writer.root / "Plan" / "local-ai" / "control" / "queue.lock"
        lock_path.unlink()

        missing = run_boundary_case(
            "missing-lock",
            base.writer,
            lambda: self._resolve(base),
        )

        self.assertEqual(missing["observed_s25d_status"], HOLD)
        self.assertFalse(lock_path.exists())

        lock_path.touch()
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            active = run_boundary_case(
                "active-lock",
                base.writer,
                lambda: self._resolve(base),
            )
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertEqual(active["observed_s25d_status"], HOLD)

    def test_uncooperative_sqlite_state_drift_is_not_repaired(self) -> None:
        base = self._base(unresolved=True)
        connection = sqlite3.connect(str(base.writer.db_path), isolation_level=None)
        try:
            connection.execute(
                "UPDATE prime_queue_writer_operations SET state='COMMITTED' WHERE scope_id=?",
                (base.scope_id,),
            )
        finally:
            connection.close()

        before = snapshot_writer_store(base.writer)
        result = run_boundary_case(
            "foreign-sqlite-state-drift",
            base.writer,
            lambda: self._resolve(base),
        )
        after = snapshot_writer_store(base.writer)

        self.assertEqual(result["observed_s25d_status"], RECOVERY_REQUIRED)
        self.assertEqual(before["queue_sha256"], after["queue_sha256"])
        self.assertEqual(result["threats"]["sqlite_writer_authority"], NOT_CLAIMED)
        self.assertEqual(result["foreign_repair_performed"], NOT_CLAIMED)

    def test_read_only_reopen_rejects_durability_drift(self) -> None:
        base = self._base(unresolved=True)
        base.writer.close()
        connection = sqlite3.connect(str(base.writer.db_path), isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
        finally:
            connection.close()

        self.assertEqual(reopen_read_only(base.writer)["status"], RECOVERY_REQUIRED)

    def test_harness_surface_has_only_readback_and_public_s25d_entrypoints(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25e_harness.py").read_text()
        for forbidden in (
            "recover_operation(",
            "execute_transition(",
            "_claim_phase(",
            "_mark_state(",
            "_recover_exact_transaction(",
            "os.replace",
            "durable_new",
            "prime_writes.",
            "receipt_commit",
            "cross_store_atomicity = True",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("mode=ro", source)


if __name__ == "__main__":
    unittest.main()
