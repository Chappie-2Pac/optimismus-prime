"""W5-S25G read-only quarantine/Foreign-Writer decision tests."""

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
from modules.w5_dispatch_bridge_s0.recovery_eligibility import (  # noqa: E402
    RECOVERY_ELIGIBLE,
    evaluate_recovery_eligibility,
)
from support.w5_s25e_harness import (  # noqa: E402
    CLAIMED,
    HOLD,
    NOT_CLAIMED,
    RECOVERY_REQUIRED,
    reopen_read_only,
    snapshot_writer_store,
)
from support.w5_s25g_quarantine_harness import (  # noqa: E402
    QUARANTINE_NOT_REQUIRED,
    QUARANTINE_REQUIRED,
    classify_quarantine_boundary,
    observe_quarantine_boundary,
    path_identity,
)


class W5S25GQuarantineObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        s25b.W5S25BHandoffAcceptorTests.setUpClass()

    def _base(self) -> s25b.W5S25BHandoffAcceptorTests:
        helper = s25c.W5S25CRecoveryEligibilityTests()
        base = helper._build_transaction_base(unresolved=True)
        self.addCleanup(base.doCleanups)
        self.assertEqual(base.accept()["status"], "ACCEPTED_RECOVERY")
        return base

    @staticmethod
    def _observe_after_fixture_mutation(base: s25b.W5S25BHandoffAcceptorTests, mutate: object) -> dict[str, object]:
        before = snapshot_writer_store(base.writer)
        db_before = path_identity(base.writer.db_path)
        eligibility = evaluate_recovery_eligibility(
            base.writer,
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )
        assert callable(mutate)
        mutate()
        after = snapshot_writer_store(base.writer)
        db_after = path_identity(base.writer.db_path)
        return classify_quarantine_boundary(
            before=before,
            after=after,
            db_before=db_before,
            db_after=db_after,
            eligibility=eligibility,
            reopen=reopen_read_only(base.writer),
        )

    def test_coherent_local_evidence_is_narrowly_claimed_without_authority(self) -> None:
        base = self._base()

        result = observe_quarantine_boundary(
            base.writer,
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )

        self.assertEqual(result["status"], CLAIMED)
        self.assertEqual(result["decision"], QUARANTINE_NOT_REQUIRED)
        self.assertEqual(result["evidence_status"], RECOVERY_ELIGIBLE)
        self.assertEqual(result["reopen"]["status"], CLAIMED)
        self.assertEqual(result["claim_scope"], "LOCAL_READ_ONLY_BOUNDARY_EVIDENCE")
        self.assertFalse(result["recovery_authority"])
        self.assertFalse(result["quarantine_authority"])
        self.assertFalse(result["mutation_allowed"])
        self.assertEqual(result["foreign_writer_authority"], NOT_CLAIMED)

    def test_missing_or_active_lock_is_hold_and_never_created(self) -> None:
        base = self._base()
        lock_path = base.writer.root / "Plan" / "local-ai" / "control" / "queue.lock"
        lock_path.unlink()

        missing = observe_quarantine_boundary(
            base.writer,
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )
        self.assertEqual(missing["status"], HOLD)
        self.assertFalse(lock_path.exists())

        lock_path.touch()
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            active = observe_quarantine_boundary(
                base.writer,
                scope_id=base.scope_id,
                handoff_id=base.grant["handoff_id"],
                lease_token=base.new_lease,
                now=base.clock.value,
            )
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertEqual(active["status"], HOLD)

    def test_foreign_state_drift_after_eligibility_requires_quarantine(self) -> None:
        base = self._base()

        def foreign_state_write() -> None:
            connection = sqlite3.connect(str(base.writer.db_path), isolation_level=None)
            try:
                connection.execute(
                    "UPDATE prime_queue_writer_operations SET state='COMMITTED' WHERE scope_id=?",
                    (base.scope_id,),
                )
            finally:
                connection.close()

        result = self._observe_after_fixture_mutation(base, foreign_state_write)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], QUARANTINE_REQUIRED)
        self.assertIn("DB_PROJECTION_DRIFT", result["drift"])
        self.assertFalse(result["automatic_repair_performed"])
        self.assertEqual(result["foreign_writer_authority"], NOT_CLAIMED)

    def test_queue_path_drift_after_eligibility_requires_quarantine(self) -> None:
        base = self._base()
        queue_path = base.writer.queue_path
        original = queue_path.read_bytes()

        def foreign_queue_replace() -> None:
            replacement = queue_path.with_name("QUEUE.json.quarantine")
            replacement.write_bytes(original + b"foreign-queue-drift")
            os.replace(replacement, queue_path)

        result = self._observe_after_fixture_mutation(base, foreign_queue_replace)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], QUARANTINE_REQUIRED)
        self.assertIn("QUEUE_IDENTITY_DRIFT", result["drift"])
        self.assertEqual(result["queue_path_aba"], NOT_CLAIMED)

    def test_handoff_chain_or_schema_drift_requires_quarantine(self) -> None:
        base = self._base()
        base.writer.close()
        connection = sqlite3.connect(str(base.writer.db_path), isolation_level=None)
        try:
            connection.execute("DROP TRIGGER prime_queue_writer_handoff_events_immutable_update")
            connection.execute(
                "UPDATE prime_queue_writer_handoff_events SET event_sha256=? WHERE handoff_id=?",
                ("0" * 64, base.grant["handoff_id"]),
            )
        finally:
            connection.close()

        result = observe_quarantine_boundary(
            base.writer,
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], QUARANTINE_REQUIRED)
        self.assertFalse(result["mutation_allowed"])

    def test_quarantine_support_surface_has_no_repair_or_cross_store_api(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25g_quarantine_harness.py").read_text()
        for forbidden in (
            "sqlite3.connect(",
            "O_CREAT",
            "O_WRONLY",
            "O_RDWR",
            "LOCK_EX",
            "write_bytes",
            "write_text",
            "unlink(",
            "replace(",
            "mkdir(",
            "quarantine(",
            "recover_operation(",
            "execute_recovery(",
            "execute_transition(",
            "_claim_phase(",
            "_mark_state(",
            "_recover_exact_transaction(",
            "prime_writes",
            "durable_new(",
            "commit(",
            "prime_receipt",
            "prime_ledger",
            "cross_store_atomicity = True",
            "subprocess",
            "signal.",
            "sleep(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("evaluate_recovery_eligibility", source)
        self.assertIn("mode=ro", (REPO_ROOT / "tests" / "support" / "w5_s25e_harness.py").read_text())

    def test_incomplete_positive_mapping_fails_closed(self) -> None:
        result = classify_quarantine_boundary(
            before={"queue_sha256": "same"},
            after={"queue_sha256": "same"},
            db_before={},
            db_after={},
            eligibility={"status": RECOVERY_ELIGIBLE},
            reopen={"status": CLAIMED},
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], QUARANTINE_REQUIRED)
        self.assertEqual(result["reason"], "INCOMPLETE_POSITIVE_EVIDENCE")
        self.assertTrue(result["evidence_gaps"])
        self.assertFalse(result["quarantine_written"])
        self.assertFalse(result["mutation_allowed"])


if __name__ == "__main__":
    unittest.main()
