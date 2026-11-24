"""W5-S25F deterministic return-ambiguity/interleaving tests."""

from __future__ import annotations

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
    RECOVERY_REQUIRED,
    RecoveryExecutor,
)
from modules.w5_dispatch_bridge_s0.prime_queue_writer import PrimeQueueWriter  # noqa: E402
from support.w5_s25e_harness import CLAIMED, NOT_CLAIMED, reopen_read_only, snapshot_writer_store  # noqa: E402
from support.w5_s25f_fault_harness import (  # noqa: E402
    FOREIGN_SQLITE_DRIFT,
    REOPEN_INCONCLUSIVE,
    RETURN_AMBIGUOUS,
    capture_reopen_snapshot,
    classify_reopen_snapshot,
    run_foreign_writer_interleave,
    run_marker_return_ambiguity,
    run_sqlite_commit_return_ambiguity,
)


class W5S25FFaultHarnessTests(unittest.TestCase):
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

    def test_marker_return_ambiguity_is_required_and_not_retried_implicitly(self) -> None:
        base = self._base(unresolved=True)

        result = run_marker_return_ambiguity(
            base.writer,
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], RETURN_AMBIGUOUS)
        self.assertEqual(result["durability_claim"], NOT_CLAIMED)
        self.assertFalse(result["automatic_repair_performed"])
        retry = RecoveryExecutor(base.writer).resolve(
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )
        self.assertEqual(retry["status"], RECOVERY_ABORTED)
        self.assertEqual(reopen_read_only(base.writer)["status"], CLAIMED)

    def test_sqlite_commit_return_ambiguity_reopens_as_read_only_replay(self) -> None:
        base = self._base(unresolved=False)

        result = run_sqlite_commit_return_ambiguity(
            base.writer,
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], RETURN_AMBIGUOUS)
        self.assertEqual(result["durability_claim"], NOT_CLAIMED)
        replay = RecoveryExecutor(base.writer).resolve(
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )
        self.assertEqual(replay["status"], RECOVERY_REPLAYED)
        self.assertEqual(reopen_read_only(base.writer)["status"], CLAIMED)

    def test_foreign_writer_after_revalidation_is_required_without_repair(self) -> None:
        base = self._base(unresolved=True)

        result = run_foreign_writer_interleave(
            base.writer,
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            idempotency_key="s25b-idem",
            now=base.clock.value,
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], FOREIGN_SQLITE_DRIFT)
        self.assertEqual(result["foreign_writer_authority"], NOT_CLAIMED)
        self.assertFalse(result["automatic_repair_performed"])
        self.assertEqual(base.writer.read_operation(base.scope_id, "s25b-idem")["status"], RECOVERY_REQUIRED)

    def test_reopen_snapshot_is_not_a_durability_causality_claim(self) -> None:
        base = self._base(unresolved=True)

        result = capture_reopen_snapshot(base.writer)

        self.assertEqual(result["status"], NOT_CLAIMED)
        self.assertEqual(result["reason"], REOPEN_INCONCLUSIVE)
        self.assertEqual(result["durability_claim"], NOT_CLAIMED)
        self.assertEqual(result["reopen"]["status"], CLAIMED)

    def test_reopen_projection_drift_is_required(self) -> None:
        base = self._base(unresolved=True)
        before = snapshot_writer_store(base.writer)
        connection = sqlite3.connect(str(base.writer.db_path), isolation_level=None)
        try:
            connection.execute(
                "UPDATE prime_queue_writer_operations SET state='COMMITTED' WHERE scope_id=?",
                (base.scope_id,),
            )
        finally:
            connection.close()
        after = snapshot_writer_store(base.writer)

        result = classify_reopen_snapshot(before, after, reopen_read_only(base.writer))

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "REOPEN_SNAPSHOT_DRIFT")
        self.assertEqual(result["reopen_causality"], NOT_CLAIMED)

    def test_fault_support_is_test_only_and_does_not_offer_cross_store_api(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25f_fault_harness.py").read_text()
        self.assertIn("prime-queue-durability-fault-harness-v1", source)
        self.assertIn("mode=ro", (REPO_ROOT / "tests" / "support" / "w5_s25e_harness.py").read_text())
        for forbidden in (
            "prime_receipt",
            "prime_ledger",
            "cross_store_atomicity = True",
            "os.replace",
            "O_CREAT",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
