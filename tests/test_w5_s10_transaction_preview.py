"""Adversarial W5-S10 read-only participant/coordinator preview tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash, canonical_json  # noqa: E402
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    JOURNAL_SCHEMA,
    build_prime_transaction_preview,
    evaluate_prime_transaction_preview,
    verify_prime_transaction_preview,
)
import test_w5_s9_transaction_prepare as _s9_tests  # noqa: E402


class W5S10TransactionPreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _s9_tests.W5S9TransactionPrepareTests.setUpClass()

    def setUp(self) -> None:
        self.s9 = _s9_tests.W5S9TransactionPrepareTests("test_valid_prepare_is_deterministic_and_explicitly_non_authoritative")
        self.s9.setUp()

    def tearDown(self) -> None:
        self.s9.tearDown()

    def participants(self, plan: dict) -> dict:
        expected = plan["expected"]
        safety = {
            "read_only": True,
            "lock_held": False,
            "reservation": False,
            "mutation_performed": False,
            "write_authority": False,
            "atomicity_claimed": False,
        }

        def journal(participant_id: str) -> dict:
            return {
                "schema_version": JOURNAL_SCHEMA,
                "journal_kind": {
                    "prime_queue": "prime_queue_journal",
                    "prime_ledger": "prime_ledger_journal",
                    "control_plane": "control_plane_transaction_state",
                    "receipt_projection": "receipt_marker_projection",
                }[participant_id],
                "status": "CLEAN",
                "journal_sha256": canonical_hash({"participant_id": participant_id, "status": "CLEAN", "open": []}),
                "open_transaction_ids": [],
                "recovery_required": False,
            }

        return {
            "prime_queue": {
                "schema_version": "prime-transaction-participant-observation-v1",
                "participant_id": "prime_queue",
                "status": "OBSERVED_READ_ONLY",
                "before": {"queue_sha256": expected["prime_queue_sha256"]},
                "journal": journal("prime_queue"),
                "safety": copy.deepcopy(safety),
            },
            "prime_ledger": {
                "schema_version": "prime-transaction-participant-observation-v1",
                "participant_id": "prime_ledger",
                "status": "OBSERVED_READ_ONLY",
                "before": {
                    key: expected[key]
                    for key in (
                        "prime_head_sha256",
                        "prime_anchor_sha256",
                        "prime_snapshot_sha256",
                        "prime_root_binding_sha256",
                        "prime_active_task_id",
                        "prime_run_relative_path",
                        "prime_queue_sha256",
                        "prime_policy_sha256",
                        "prime_active_card_sha256",
                        "prime_resume_packet_sha256",
                        "prime_writer_lease_sha256",
                        "prime_previous_head_sha256",
                    )
                },
                "journal": journal("prime_ledger"),
                "safety": copy.deepcopy(safety),
            },
            "control_plane": {
                "schema_version": "prime-transaction-participant-observation-v1",
                "participant_id": "control_plane",
                "status": "OBSERVED_READ_ONLY",
                "before": {
                    "runtime_sha256": expected["w5_runtime_sha256"],
                    "projection_sha256": expected["w5_projection_sha256"],
                    "capture_sha256": expected["w5_capture_sha256"],
                    "runtime_anchor_sha256": expected["control_runtime_anchor_sha256"],
                    "history_tail_sha256": expected["control_history_tail_sha256"],
                    "marker_commitments_sha256": expected["control_marker_commitments_sha256"],
                    "queue_hash": expected["w5_queue_hash"],
                    "policy_hash": expected["w5_policy_hash"],
                    "card_hash": expected["w5_card_hash"],
                    "lease_claim_sha256": expected["w5_lease_claim_sha256"],
                    "lease_owner_id": expected["w5_lease_owner_id"],
                    "lease_expires_at": expected["w5_lease_expires_at"],
                    "fencing_epoch": expected["w5_fencing_epoch"],
                    "last_committed_event_id": expected["control_last_committed_event_id"],
                    "clock_after_epoch": expected["control_clock_after_epoch"],
                    "run_state": expected["run_state"],
                    "card_state": expected["card_state"],
                    "card_state_version": expected["card_state_version"],
                    "attempt_state": expected["attempt_state"],
                    "attempt_state_version": expected["attempt_state_version"],
                    "dispatch_state": expected["dispatch_state"],
                    "dispatch_row_version": expected["dispatch_row_version"],
                },
                "journal": journal("control_plane"),
                "safety": copy.deepcopy(safety),
            },
            "receipt_projection": {
                "schema_version": "prime-transaction-participant-observation-v1",
                "participant_id": "receipt_projection",
                "status": "OBSERVED_READ_ONLY",
                "before": {
                    "receipts_sha256": expected["w5_receipts_sha256"],
                    "commit_markers_sha256": expected["w5_commit_markers_sha256"],
                    "history_tail_sha256": expected["control_history_tail_sha256"],
                    "marker_commitments_sha256": expected["control_marker_commitments_sha256"],
                    "last_committed_event_id": expected["control_last_committed_event_id"],
                },
                "journal": journal("receipt_projection"),
                "safety": copy.deepcopy(safety),
            },
        }

    def build(self, participants: dict | None = None) -> tuple[dict, dict]:
        plan = self.s9.build_plan()
        participants = self.participants(plan) if participants is None else participants
        preview = build_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            participants=participants,
            s8_kwargs=self.s9.s8_kwargs(),
        )
        return plan, preview

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["external_action"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_valid_preview_is_deterministic_and_deferred(self) -> None:
        plan, preview = self.build()
        first = verify_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            preview,
            participants=self.participants(plan),
            s8_kwargs=self.s9.s8_kwargs(),
        )
        second = verify_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            canonical_json(plan),
            canonical_json(preview),
            participants=self.participants(plan),
            s8_kwargs=self.s9.s8_kwargs(),
        )
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "PARTICIPANT_PREVIEW_ONLY_READ_ONLY")
        self.assertEqual(first["coordinator_state"], "PREPARED")
        self.assertEqual(first["required_next_state"], "COMMIT_RECHECK_REQUIRED")
        self.assertTrue(first["atomic_commit_required"])
        self.assertFalse(first["effect_defined"])
        self.assertFalse(first["authoritative_prepared"])
        self.assertFalse(first["idempotency_reserved"])
        self.assertFalse(first["lock_held"])
        self.assertEqual(first["cross_store_atomicity"], "not_claimed")
        self.assertEqual(first["subject"], plan["subject"])
        self.assertEqual(first["participant_observations_sha256"], canonical_hash(self.participants(plan)))
        self.assert_actionless(first)

    def test_missing_participant_is_hold(self) -> None:
        plan = self.s9.build_plan()
        participants = self.participants(plan)
        del participants["prime_ledger"]
        result = evaluate_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            None,
            participants=participants,
            s8_kwargs=self.s9.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PREVIEW_PARTICIPANT_SET_INVALID")
        self.assert_actionless(result)

    def test_open_journal_is_recovery_required_without_auto_repair(self) -> None:
        plan = self.s9.build_plan()
        participants = self.participants(plan)
        participants["prime_queue"]["journal"]["status"] = "OPEN"
        participants["prime_queue"]["journal"]["open_transaction_ids"] = ["tx-open-001"]
        result = evaluate_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            None,
            participants=participants,
            s8_kwargs=self.s9.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PREVIEW_RECOVERY_REQUIRED")
        self.assert_actionless(result)

    def test_participant_before_drift_and_unsafe_safety_are_hold(self) -> None:
        plan = self.s9.build_plan()
        participants = self.participants(plan)
        participants["control_plane"]["before"]["card_state_version"] += 1
        result = evaluate_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            None,
            participants=participants,
            s8_kwargs=self.s9.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PREVIEW_PRECONDITION_MISMATCH")
        self.assert_actionless(result)

        participants = self.participants(plan)
        participants["prime_queue"]["safety"]["reservation"] = True
        result = evaluate_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            None,
            participants=participants,
            s8_kwargs=self.s9.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PREVIEW_UNSAFE_EXECUTION_REQUEST")
        self.assert_actionless(result)

    def test_lease_fence_receipt_and_each_participant_are_bound(self) -> None:
        plan = self.s9.build_plan()
        cases = (
            ("prime_queue", "before", "queue_sha256"),
            ("prime_ledger", "before", "prime_head_sha256"),
            ("control_plane", "before", "fencing_epoch"),
            ("receipt_projection", "before", "receipts_sha256"),
        )
        for participant_id, section, key in cases:
            with self.subTest(participant_id=participant_id, key=key):
                participants = self.participants(plan)
                value = participants[participant_id][section][key]
                participants[participant_id][section][key] = value + 1 if isinstance(value, int) else "f" * 64
                result = evaluate_prime_transaction_preview(
                    self.s9.capture,
                    self.s9.anchor,
                    self.s9.control_capture,
                    self.s9.head,
                    plan,
                    None,
                    participants=participants,
                    s8_kwargs=self.s9.s8_kwargs(),
                )
                self.assertEqual(result["reason"], "PRIME_TX_PREVIEW_PRECONDITION_MISMATCH")
                self.assert_actionless(result)

    def test_noncanonical_or_unobservable_journal_is_hold_without_recovery_call(self) -> None:
        plan = self.s9.build_plan()
        participants = self.participants(plan)
        participants["prime_ledger"]["journal"]["open_transaction_ids"] = ["tx-2", "tx-1"]
        result = evaluate_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            None,
            participants=participants,
            s8_kwargs=self.s9.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PREVIEW_JOURNAL_UNOBSERVABLE")
        self.assert_actionless(result)

    def test_duplicate_preview_and_stale_s9_are_hold(self) -> None:
        plan, preview = self.build()
        duplicate = '{"schema_version":"prime-transaction-participant-preview-verification-v1","schema_version":"forged"}'
        result = evaluate_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            duplicate,
            participants=self.participants(plan),
            s8_kwargs=self.s9.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PREVIEW_JSON_DUPLICATE_KEY")
        self.assert_actionless(result)

        stale = self.s9.s8_kwargs()
        stale["expected_current_head"] = None
        result = evaluate_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            preview,
            participants=self.participants(plan),
            s8_kwargs=stale,
        )
        self.assertEqual(result["reason"], "PRIME_TX_PREVIEW_S9_NOT_SATISFIED")
        self.assertEqual(result["cause_code"], "PRIME_TX_S8_NOT_SATISFIED")
        self.assert_actionless(result)

    def test_preview_drift_and_inputs_remain_unchanged(self) -> None:
        plan, preview = self.build()
        drift = copy.deepcopy(preview)
        drift["prepare_digest"] = "f" * 64
        result = evaluate_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            drift,
            participants=self.participants(plan),
            s8_kwargs=self.s9.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PREVIEW_PLAN_MISMATCH")
        self.assert_actionless(result)

        before_capture = copy.deepcopy(self.s9.capture)
        before_control = copy.deepcopy(self.s9.control_capture)
        before_participants = self.participants(plan)
        before_snapshot = self.s9.data["cp"].snapshot(self.s9.data["control"]["run"]["run_id"])
        verify_prime_transaction_preview(
            self.s9.capture,
            self.s9.anchor,
            self.s9.control_capture,
            self.s9.head,
            plan,
            preview,
            participants=before_participants,
            s8_kwargs=self.s9.s8_kwargs(),
        )
        self.assertEqual(self.s9.capture, before_capture)
        self.assertEqual(self.s9.control_capture, before_control)
        self.assertEqual(self.s9.data["cp"].snapshot(self.s9.data["control"]["run"]["run_id"]), before_snapshot)
        self.assertEqual(self.s9.data["cp"].integrity_check(), "ok")


if __name__ == "__main__":
    unittest.main()
