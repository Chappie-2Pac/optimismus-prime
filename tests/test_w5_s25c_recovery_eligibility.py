"""Adversarial tests for the read-only W5-S25C recovery preflight."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import test_w5_s25b_handoff_acceptor as s25b  # noqa: E402
from modules.w5_dispatch_bridge_s0.recovery_eligibility import (  # noqa: E402
    RECOVERY_ELIGIBLE,
    RECOVERY_HOLD,
    RECOVERY_REQUIRED,
    RecoveryEligibilityPreflight,
    evaluate_recovery_eligibility,
)
from modules.w5_dispatch_bridge_s0.handoff_acceptor import InjectedHandoffCrash  # noqa: E402


class W5S25CRecoveryEligibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        s25b.W5S25BHandoffAcceptorTests.setUpClass()

    def setUp(self) -> None:
        base = self._build_transaction_base()
        self.base = base
        self.addCleanup(base.doCleanups)
        self.writer = base.writer
        self.queue_path = base.queue_path
        accepted = base.accept()
        self.assertEqual(accepted["status"], "ACCEPTED_RECOVERY")

    def _build_transaction_base(self, *, unresolved: bool = True) -> s25b.W5S25BHandoffAcceptorTests:
        base = s25b.W5S25BHandoffAcceptorTests()
        base.temp = tempfile.TemporaryDirectory(prefix="w5-s25c-recovery-")
        base.addCleanup(base.temp.cleanup)
        base.root = s25b.make_project(Path(base.temp.name))
        base.queue_path = base.root / "Plan" / "local-ai" / "QUEUE.json"
        queue = json.loads(base.queue_path.read_text(encoding="utf-8"))
        queue["tasks"][0]["owner"] = "codex"
        base.queue_path.write_text(json.dumps(queue), encoding="utf-8")
        base.clock = s25b.MutableClock(200)
        base.writer = s25b.PrimeQueueWriter(base.root, clock=base.clock)
        base.addCleanup(base.writer.close)
        base.old_lease = "s25b-old-lease-token-012345"
        base.new_lease = "s25b-new-lease-token-012345"
        base.scope_id = "s25b-scope"
        base.lease = {
            "owner_id": "old-owner",
            "owner_instance_id": "old-instance",
            "owner_epoch": 4,
            "fencing_epoch": 9,
            "lease_token": base.old_lease,
        }
        base.writer.create_scope(scope_id=base.scope_id, **base.lease, lease_expires_at=1000)
        request = {
            "scope_id": base.scope_id,
            "transaction_id": "s25b-tx",
            "idempotency_key": "s25b-idem",
            "card_id": "card-1",
            "command": "start",
            "actor": "codex",
            "expected_queue_sha256": hashlib.sha256(base.queue_path.read_bytes()).hexdigest(),
            **base.lease,
        }
        base.writer.fault_points.add("after_queue_commit")
        with self.assertRaises(s25b.InjectedPrimeQueueWriterCrash):
            base.writer.execute_transition(**request)
        base.writer.fault_points.clear()
        row = base.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=?",
            (base.scope_id,),
        ).fetchone()
        exact, other_open, invalid = base.writer._transaction_details(row)
        self.assertIsNotNone(exact)
        self.assertFalse(other_open)
        self.assertFalse(invalid)
        exact = Path(exact)
        if unresolved:
            # Turn the crash-after-queue-commit fixture into an unresolved,
            # exact before-state fixture without changing production code.
            base.queue_path.write_bytes((exact / "before.json").read_bytes())
            (exact / "COMMITTED").unlink()
        base.observation, base.grant = base._handoff_inputs()
        base.authority, base.termination = base._attestations()
        return base

    def _evaluate(self, **changes: object) -> dict[str, object]:
        values: dict[str, object] = {
            "scope_id": self.base.scope_id,
            "handoff_id": self.base.grant["handoff_id"],
            "lease_token": self.base.new_lease,
            "now": self.base.clock.value,
        }
        values.update(changes)
        return evaluate_recovery_eligibility(self.writer, **values)

    def _snapshot(self) -> tuple[object, ...]:
        scope = self.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_scopes WHERE scope_id=?",
            (self.base.scope_id,),
        ).fetchone()
        operation = self.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=?",
            (self.base.scope_id,),
        ).fetchone()
        counts = tuple(
            self.writer.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "prime_queue_writer_events",
                "prime_queue_writer_handoff_events",
                "prime_queue_writer_markers",
            )
        )
        return (tuple(scope), tuple(operation), counts, self.queue_path.read_bytes())

    def _exact_transaction(self) -> Path:
        row = self.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=?",
            (self.base.scope_id,),
        ).fetchone()
        exact, other_open, invalid = self.writer._transaction_details(row)
        self.assertFalse(other_open)
        self.assertFalse(invalid)
        self.assertIsNotNone(exact)
        return Path(exact)

    def test_stable_before_state_is_eligible_but_never_authorized(self) -> None:
        before = self._snapshot()

        result = self._evaluate()

        self.assertEqual(result["status"], RECOVERY_ELIGIBLE)
        self.assertEqual(result["transaction_state"], "BEFORE")
        self.assertTrue(result["handoff_event_verified"])
        self.assertTrue(result["root_scope_claim_verified"])
        self.assertTrue(result["operation_verified"])
        self.assertTrue(result["marker_verified"])
        self.assertTrue(result["transaction_verified"])
        self.assertTrue(result["queue_hash_verified"])
        self.assertTrue(result["fence_verified"])
        self.assertTrue(result["lease_verified"])
        self.assertTrue(result["read_only"])
        self.assertFalse(result["recovery_authority"])
        self.assertFalse(result["recovery_execution_allowed"])
        self.assertFalse(result["recovery_started"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["queue_mutation_performed"])
        self.assertEqual(result["cross_store_atomicity"], "NOT_CLAIMED")
        self.assertEqual(self._snapshot(), before)

    def test_after_state_is_also_eligible_for_later_recovery_revalidation(self) -> None:
        transaction = self._exact_transaction()
        self.queue_path.write_bytes((transaction / "after.json").read_bytes())

        result = self._evaluate()

        self.assertEqual(result["status"], RECOVERY_ELIGIBLE)
        self.assertEqual(result["transaction_state"], "AFTER")
        self.assertFalse(result["mutation_performed"])

    def test_response_loss_after_handoff_commit_is_read_as_persistent_evidence(self) -> None:
        # The fixture accepted once in setUp; re-create the scenario in a
        # fresh base so the after-commit fault is the first acceptance.
        base = self._build_transaction_base(unresolved=False)
        self.addCleanup(base.doCleanups)
        with self.assertRaises(InjectedHandoffCrash):
            base.acceptor(fault_points={"after_commit"}).accept_handoff(
                observation=base.observation,
                grant=base.grant,
                authority_attestation=base.authority,
                termination_attestation=base.termination,
                new_lease_token=base.new_lease,
                now=base.clock.value,
            )

        result = evaluate_recovery_eligibility(
            base.writer,
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )

        self.assertEqual(result["status"], RECOVERY_ELIGIBLE)
        self.assertEqual(result["transaction_state"], "COMMITTED")
        self.assertEqual(base.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_handoff_events").fetchone()[0], 1)

    def test_expired_or_wrong_lease_is_hold_without_mutation(self) -> None:
        before = self._snapshot()

        expired = self._evaluate(now=1000)
        wrong = self._evaluate(lease_token="a-different-lease-token-012345")

        self.assertEqual(expired["status"], RECOVERY_HOLD)
        self.assertEqual(expired["reason"], "RECOVERY_LEASE_EXPIRED")
        self.assertEqual(wrong["status"], RECOVERY_HOLD)
        self.assertEqual(wrong["reason"], "RECOVERY_LEASE_TOKEN_MISMATCH")
        self.assertEqual(self._snapshot(), before)

    def test_missing_or_stale_handoff_is_hold(self) -> None:
        missing = self._evaluate(handoff_id="not-the-current-handoff")

        self.assertEqual(missing["status"], RECOVERY_HOLD)
        self.assertEqual(missing["reason"], "HANDOFF_EVENT_NOT_FOUND")

    def test_foreign_queue_hash_is_recovery_required(self) -> None:
        before = self._snapshot()
        self.queue_path.write_bytes(b"foreign queue bytes")

        result = self._evaluate()

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "QUEUE_HASH_DRIFT")
        self.assertFalse(result["mutation_performed"])
        after = self._snapshot()
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[1], before[1])
        self.assertEqual(after[2], before[2])

    def test_transaction_file_digest_drift_is_recovery_required(self) -> None:
        transaction = self._exact_transaction()
        before_path = transaction / "before.json"
        before_path.write_bytes(before_path.read_bytes() + b"tampered")

        result = self._evaluate()

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertIn(result["reason"], {"TRANSACTION_INTEGRITY_DRIFT", "TRANSACTION_FILE_DIGEST_DRIFT"})

    def test_missing_lock_does_not_create_a_lock_file(self) -> None:
        lock_path = self.writer.root / "Plan" / "local-ai" / "control" / "queue.lock"
        lock_path.unlink()

        result = self._evaluate()

        self.assertEqual(result["status"], RECOVERY_HOLD)
        self.assertEqual(result["reason"], "QUEUE_LOCK_NOT_AVAILABLE")
        self.assertFalse(lock_path.exists())

    def test_schema_trigger_drift_is_recovery_required(self) -> None:
        self.writer.conn.execute("DROP TRIGGER prime_queue_writer_handoff_events_immutable_update")

        result = self._evaluate()

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "DB_SCHEMA_TRIGGERS_INVALID")

    def test_recovery_required_operation_is_not_eligible(self) -> None:
        self.writer.conn.execute(
            "UPDATE prime_queue_writer_operations SET state='RECOVERY_REQUIRED' WHERE scope_id=?",
            (self.base.scope_id,),
        )

        result = self._evaluate()

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "OPERATION_ALREADY_RECOVERY_REQUIRED")

    def test_source_surface_has_no_mutation_or_recovery_entrypoint(self) -> None:
        source = (REPO_ROOT / "modules" / "w5_dispatch_bridge_s0" / "recovery_eligibility.py").read_text()
        for forbidden in (
            "recover_operation(",
            "_claim_phase(",
            "_mark_state(",
            "_insert_prepared(",
            "_append_event(",
            "_recover_exact_transaction(",
            "quarantine(",
            "durable_new",
            "os.replace",
            "write_bytes",
            "write_text",
            "unlink",
            "sqlite3.connect",
            "prime_writes.",
            "O_CREAT",
            "BEGIN IMMEDIATE",
            "executescript",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
