"""Adversarial tests for the W5-S21 local Receipt-Commit/Prepare journal."""

from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w5_dispatch_bridge_s0.receipt_commit_journal import (  # noqa: E402
    InjectedReceiptJournalCrash,
    JOURNAL_IN_DOUBT,
    JOURNAL_QUARANTINED,
    OBSERVED_EFFECT_UNKNOWN,
    PREPARED,
    ReceiptCommitJournal,
)
from test_w5_s20_receipt_intent_witness import (  # noqa: E402
    W5S20ReceiptIntentWitnessTests,
)
from modules.w4_small_loop_s0 import canonical_json  # noqa: E402


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class W5S21ReceiptCommitJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        base = W5S20ReceiptIntentWitnessTests()
        base.setUp()
        self.base = base
        self.addCleanup(base.doCleanups)
        self.clock = MutableClock(100)
        self.temp = tempfile.TemporaryDirectory(prefix="w5-s21-journal-")
        self.addCleanup(self.temp.cleanup)
        self.scope_id = "s21-receipt-scope"
        self.db_path = Path(self.temp.name) / f"{self.scope_id}.sqlite3"
        intent = self.base.intent
        self.lease_token = self.base.base.lease_token
        self.journal = self._open()
        self.addCleanup(self.journal.close)
        self.journal.create_scope(
            transaction_id=intent["transaction_id"],
            projection_manifest_sha256=intent["projection_manifest_sha256"],
            projection_set_sha256=intent["projection_set_sha256"],
            owner_id=intent["owner_id"],
            owner_instance_id=intent["owner_instance_id"],
            owner_epoch=intent["owner_epoch"],
            fencing_epoch=intent["fencing_epoch"],
            lease_token=self.lease_token,
            lease_expires_at=1000,
        )
        self.s20_input = self._s20_input()

    def _open(self, **kwargs: object) -> ReceiptCommitJournal:
        return ReceiptCommitJournal(
            self.db_path,
            scope_id=self.scope_id,
            owner_root=self.temp.name,
            clock=self.clock,
            **kwargs,
        )

    def _s20_input(self, *, intent: dict | None = None) -> dict:
        return {
            "worker_attestations": copy.deepcopy(self.base.base.bundle["worker_attestations"]),
            "replay_observation": copy.deepcopy(self.base.base.bundle["replay_observation"]),
            "replay_floor": copy.deepcopy(self.base.base.bundle["replay_floor"]),
            "host_runtime_attestation": copy.deepcopy(self.base.base.bundle["host_runtime_attestation"]),
            "s15_input": copy.deepcopy(self.base.base.s15_input),
            "owner_observation": copy.deepcopy(self.base.base.owner),
            "request": copy.deepcopy(self.base.base.request),
            "cross_store_snapshot": copy.deepcopy(self.base.base.snapshot),
            "receipt_intent": copy.deepcopy(intent if intent is not None else self.base.intent),
        }

    def _prepare(self, *, journal: ReceiptCommitJournal | None = None, s20_input: dict | None = None, lease_token: str | None = None) -> dict:
        target = journal or self.journal
        with self.base.base._open() as owner_store:
            return target.prepare_from_s20(
                owner_store,
                s20_input=copy.deepcopy(s20_input or self.s20_input),
                lease_token=lease_token or self.lease_token,
            )

    def test_prepare_is_local_and_fenced(self) -> None:
        result = self._prepare()
        self.assertEqual(result["status"], PREPARED)
        self.assertEqual(result["transaction_state"], PREPARED)
        self.assertTrue(result["authoritative_prepared"])
        self.assertTrue(result["idempotency_reserved"])
        self.assertTrue(result["journal_mutation_performed"])
        self.assertFalse(result["receipt_emitted"])
        self.assertFalse(result["receipt_committed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["mutation_performed"])
        self.assertFalse(result["external_mutation_performed"])
        self.assertEqual(result["observed_effect_state"], "NONE")
        self.assertEqual(result["cross_store_atomicity"], "NOT_CLAIMED")
        self.assertEqual(self.journal.read_scope()["event_seq"], 2)
        stored = self.journal.read_receipt(result["receipt_key"])
        self.assertEqual(stored["status"], PREPARED)
        self.assertEqual(stored["receipt_intent_sha256"], result["receipt_intent_sha256"])
        self.assertEqual(
            self.journal.conn.execute("SELECT COUNT(*) FROM receipt_commit_participants").fetchone()[0],
            5,
        )

    def test_identical_retry_is_replayed_without_second_event(self) -> None:
        first = self._prepare()
        second = self._prepare()
        self.assertEqual(second["status"], "REPLAYED")
        self.assertEqual(second["receipt_id"], first["receipt_id"])
        self.assertFalse(second["journal_mutation_performed"])
        self.assertEqual(self.journal.read_scope()["event_seq"], 2)
        self.assertEqual(self.journal.conn.execute("SELECT COUNT(*) FROM receipt_commit_journal").fetchone()[0], 1)

    def test_parallel_identical_prepare_has_one_local_winner(self) -> None:
        def worker() -> dict:
            journal = self._open()
            try:
                return self._prepare(journal=journal)
            finally:
                journal.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _item: worker(), range(2)))
        self.assertEqual(sorted(result["status"] for result in results), ["PREPARED", "REPLAYED"])
        self.assertEqual(self.journal.conn.execute("SELECT COUNT(*) FROM receipt_commit_journal").fetchone()[0], 1)
        self.assertEqual(self.journal.read_scope()["event_seq"], 2)

    def test_same_transaction_with_new_receipt_key_is_conflict(self) -> None:
        self._prepare()
        changed = copy.deepcopy(self.base.intent)
        changed["receipt_key"] = "receipt-intent-s21-other"
        result = self._prepare(s20_input=self._s20_input(intent=changed))
        self.assertEqual(result["status"], "CONFLICT")
        self.assertEqual(result["reason"], "JOURNAL_KEY_OR_TRANSACTION_CONFLICT")
        self.assertEqual(self.journal.read_scope()["event_seq"], 2)

    def test_s20_drift_does_not_touch_journal(self) -> None:
        bundle = copy.deepcopy(self.s20_input["worker_attestations"])
        bundle["control_plane"]["authority_mac"] = "0" * 64
        result = self._prepare(s20_input={**self.s20_input, "worker_attestations": bundle})
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(result["reason"].startswith("S20_"))
        self.assertEqual(self.journal.read_scope()["event_seq"], 1)
        self.assertEqual(self.journal.conn.execute("SELECT COUNT(*) FROM receipt_commit_journal").fetchone()[0], 0)

    def test_wrong_fence_and_expired_lease_fail_before_prepare(self) -> None:
        result = self._prepare(lease_token="wrong-lease-token-0123456789")
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "FENCING_EPOCH_MISMATCH")
        self.assertEqual(self.journal.read_scope()["event_seq"], 1)

        self.clock.value = 1001
        result = self._prepare()
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "LEASE_EXPIRED")
        self.assertEqual(self.journal.read_scope()["event_seq"], 1)

    def test_crash_before_commit_rolls_back_prepare(self) -> None:
        self.journal.fault_points.add("before_commit")
        with self.assertRaises(InjectedReceiptJournalCrash):
            self._prepare()
        self.assertEqual(self.journal.read_scope()["event_seq"], 1)
        self.assertEqual(self.journal.conn.execute("SELECT COUNT(*) FROM receipt_commit_journal").fetchone()[0], 0)

        result = self._prepare()
        self.assertEqual(result["status"], PREPARED)

    def test_crash_after_commit_replays_without_duplicate_prepare(self) -> None:
        self.journal.fault_points.add("after_commit")
        with self.assertRaises(InjectedReceiptJournalCrash):
            self._prepare()
        reopened = self._open()
        try:
            result = self._prepare(journal=reopened)
            self.assertEqual(result["status"], "REPLAYED")
            self.assertEqual(reopened.read_scope()["event_seq"], 2)
            self.assertEqual(reopened.conn.execute("SELECT COUNT(*) FROM receipt_commit_journal").fetchone()[0], 1)
        finally:
            reopened.close()

    def test_explicit_in_doubt_and_quarantine_never_resume(self) -> None:
        prepared = self._prepare()
        uncertain = self.journal.mark_in_doubt(
            prepared["receipt_key"],
            reason="external projection outcome not observable",
        )
        self.assertEqual(uncertain["status"], JOURNAL_IN_DOUBT)
        self.assertEqual(uncertain["observed_effect_state"], OBSERVED_EFFECT_UNKNOWN)
        self.assertFalse(uncertain["recovery_started"])
        retry = self._prepare()
        self.assertEqual(retry["status"], "RECOVERY_REQUIRED")
        self.assertEqual(retry["reason"], "JOURNAL_QUARANTINED")

        quarantined = self.journal.quarantine(prepared["receipt_key"], reason="operator quarantine")
        self.assertEqual(quarantined["status"], JOURNAL_QUARANTINED)
        self.assertFalse(quarantined["resume_allowed"])
        self.assertFalse(quarantined["consume_allowed"])

    def test_explicit_recovery_required_is_terminal_until_quarantine(self) -> None:
        prepared = self._prepare()
        recovery = self.journal.mark_recovery_required(
            prepared["receipt_key"],
            reason="participant writer evidence missing",
        )
        self.assertEqual(recovery["status"], "RECOVERY_REQUIRED")
        self.assertEqual(recovery["observed_effect_state"], OBSERVED_EFFECT_UNKNOWN)
        retry = self._prepare()
        self.assertEqual(retry["status"], "RECOVERY_REQUIRED")
        self.assertEqual(retry["reason"], "JOURNAL_QUARANTINED")

    def test_serialized_s20_opaque_inputs_are_supported(self) -> None:
        serialized = self._s20_input()
        serialized["owner_observation"] = canonical_json(serialized["owner_observation"])
        serialized["cross_store_snapshot"] = canonical_json(serialized["cross_store_snapshot"])
        serialized["receipt_intent"] = canonical_json(serialized["receipt_intent"])
        result = self._prepare(s20_input=serialized)
        self.assertEqual(result["status"], PREPARED)

    def test_corrupt_participant_and_future_state_fail_closed(self) -> None:
        prepared = self._prepare()
        self.journal.conn.execute(
            "UPDATE receipt_commit_participants SET participant_json=? WHERE receipt_key=? AND participant_id='control_plane'",
            (json.dumps({"tampered": True}), prepared["receipt_key"]),
        )
        corrupted = self.journal.read_receipt(prepared["receipt_key"])
        self.assertEqual(corrupted["status"], "RECOVERY_REQUIRED")

        self.journal.conn.execute(
            "UPDATE receipt_commit_participants SET participant_json=? WHERE receipt_key=? AND participant_id='control_plane'",
            (canonical_json(self.base.intent["participants"]["control_plane"]), prepared["receipt_key"]),
        )
        self.journal.conn.execute(
            "UPDATE receipt_commit_journal SET state='COMMITTED' WHERE receipt_key=?",
            (prepared["receipt_key"],),
        )
        future = self.journal.read_receipt(prepared["receipt_key"])
        self.assertEqual(future["status"], "RECOVERY_REQUIRED")

    def test_participant_roles_distinguish_observation_from_write(self) -> None:
        prepared = self._prepare()
        self.assertEqual(prepared["status"], PREPARED)
        roles = dict(
            self.journal.conn.execute(
                "SELECT participant_id,participant_role FROM receipt_commit_participants"
            ).fetchall()
        )
        self.assertEqual(roles["knowledge_ledger"], "OBSERVATION")
        self.assertEqual(
            {participant_id for participant_id, role in roles.items() if role == "WRITE"},
            {"control_plane", "prime_ledger", "prime_queue", "receipt_projection"},
        )

    def test_input_mapping_isolated(self) -> None:
        supplied = copy.deepcopy(self.s20_input)
        original_intent = copy.deepcopy(supplied["receipt_intent"])
        original_snapshot = copy.deepcopy(supplied["cross_store_snapshot"])
        original_request = copy.deepcopy(supplied["request"])
        self._prepare(s20_input=supplied)
        self.assertEqual(supplied["receipt_intent"], original_intent)
        self.assertEqual(supplied["cross_store_snapshot"], original_snapshot)
        self.assertEqual(supplied["request"], original_request)

    def test_store_path_and_schema_guards(self) -> None:
        with self.assertRaises(ValueError):
            ReceiptCommitJournal(
                Path(self.temp.name) / "wrong.sqlite3",
                scope_id=self.scope_id,
                owner_root=self.temp.name,
                clock=self.clock,
            )
        with sqlite3.connect(self.db_path) as connection:
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(
            tables,
            {
                "receipt_journal_meta",
                "receipt_journal_scopes",
                "receipt_commit_journal",
                "receipt_commit_participants",
                "receipt_commit_events",
                "receipt_commit_markers",
            },
        )

    def test_s21_source_has_no_external_or_projection_write_surface(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/receipt_commit_journal.py").read_text()
        for forbidden in (
            "import subprocess",
            "import socket",
            "import urllib",
            "os.system",
            "os.kill",
            "ControlPlane",
            "w25_compat",
            "_advance_validated",
            '"receipt_emitted": True',
            '"consume_allowed": True',
            '"receipt_committed": True',
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
