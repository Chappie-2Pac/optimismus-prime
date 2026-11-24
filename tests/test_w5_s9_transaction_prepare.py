"""Adversarial W5-S9 read-only Consume/CAS preparation tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash, canonical_json  # noqa: E402
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    build_prime_consume_plan,
    capture_consistent_control_snapshot,
    capture_prime_evidence_v2,
    configure_trusted_prime_anchor,
    configure_trusted_prime_head,
    evaluate_prime_consume_plan,
    freeze_trusted_prime_anchors,
    freeze_trusted_prime_heads,
    verify_prime_consume_plan,
)
import modules.w5_dispatch_bridge_s0.prime_transaction as prime_transaction  # noqa: E402
from test_w5_s3_hold_reconcile_resume import _verified_fixture  # noqa: E402
from test_w5_s6_writer_manifest import _ManifestFixture  # noqa: E402
from test_w5_s8_external_head import (  # noqa: E402
    ANCHOR_AUTHORITY_ID,
    ANCHOR_KEY,
    ANCHOR_KEY_ID,
    HEAD_AUTHORITY_ID,
    HEAD_KEY,
    HEAD_KEY_ID,
    _seal_anchor,
    _seal_head,
)


class W5S9TransactionPrepareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configure_trusted_prime_anchor(
            authority_id=ANCHOR_AUTHORITY_ID,
            key_id=ANCHOR_KEY_ID,
            key=ANCHOR_KEY,
        )
        freeze_trusted_prime_anchors()
        configure_trusted_prime_head(
            authority_id=HEAD_AUTHORITY_ID,
            key_id=HEAD_KEY_ID,
            key=HEAD_KEY,
        )
        freeze_trusted_prime_heads()

    def setUp(self) -> None:
        self.fixture = _ManifestFixture()
        self.helper, bundle, authority, data = _verified_fixture()
        self.data = data
        card_id = data["control"]["card"]["card_id"]
        session_path = self.fixture.run / "session_state.json"
        session = json.loads(session_path.read_text(encoding="utf-8"))
        session["active_task_id"] = card_id
        self.fixture.write_json(session_path, session)
        self.fixture.write_json(
            self.fixture.run / "tasks.json",
            {"tasks": [{"task_id": card_id, "status": "in_progress"}]},
        )
        queue = json.loads((self.fixture.card_root / "QUEUE.json").read_text(encoding="utf-8"))
        queue["tasks"][0]["id"] = card_id
        self.fixture.write_json(self.fixture.card_root / "QUEUE.json", queue)
        packet = json.loads((self.fixture.packet_dir / "resume_packet.json").read_text(encoding="utf-8"))
        packet["source"]["session_state_sha256"] = hashlib.sha256(session_path.read_bytes()).hexdigest()
        packet["source"]["tasks_sha256"] = hashlib.sha256((self.fixture.run / "tasks.json").read_bytes()).hexdigest()
        packet["state"]["active_task_id"] = card_id
        packet["next"]["task_id"] = card_id
        self.fixture.write_json(self.fixture.packet_dir / "resume_packet.json", packet)
        self.fixture.install_manifest(generation_id="gen-000007", generation=7)
        self.capture = capture_prime_evidence_v2(
            self.fixture.root,
            f"runtime/runs/{self.fixture.run_id}",
        )
        self.control_capture = capture_consistent_control_snapshot(
            data["cp"],
            data["control"]["run"]["run_id"],
        )
        self.anchor = _seal_anchor(self.capture)
        self.head = _seal_head(self.capture, self.control_capture, self.anchor)
        self.expected_identity = {
            "run_id": data["control"]["run"]["run_id"],
            "card_id": data["control"]["card"]["card_id"],
            "attempt_id": data["control"]["attempt"]["attempt_id"],
            "dispatch_id": data["control"]["dispatch"]["dispatch_id"],
        }

    def tearDown(self) -> None:
        self.fixture.close()
        self.helper.doCleanups()

    def s8_kwargs(self) -> dict:
        return {
            "last_accepted_generation": 6,
            "last_accepted_head_sequence": 41,
            "last_accepted_head_sha256": "a" * 64,
            "expected_current_head": {
                "head_sequence": 42,
                "head_sha256": canonical_hash(self.head),
            },
            "expected_prime_run_id": self.fixture.run_id,
            "expected_w5_identity": self.expected_identity,
        }

    def build_plan(self) -> dict:
        return build_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            idempotency_key="consume:test:001",
            s8_kwargs=self.s8_kwargs(),
        )

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["external_action"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_valid_prepare_is_deterministic_and_explicitly_non_authoritative(self) -> None:
        plan = self.build_plan()
        self.assertEqual(plan["safety"], {
            "requires_commit_recheck": True,
            "requires_queue_journal_recheck": True,
            "queue_journal_observed": False,
            "reservation": False,
            "lock_held": False,
            "mutation_performed": False,
            "cross_store_atomicity": "not_claimed",
        })
        first = verify_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            plan,
            s8_kwargs=self.s8_kwargs(),
        )
        second = verify_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            canonical_json(plan),
            s8_kwargs=self.s8_kwargs(),
        )
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "PREPARE_ONLY_READ_ONLY")
        self.assertEqual(first["transaction_authority"], "DEFERRED_TO_ATOMIC_CONSUMER")
        self.assertTrue(first["atomic_commit_required"])
        self.assertTrue(first["requires_commit_recheck"])
        self.assertTrue(first["requires_queue_journal_recheck"])
        self.assertFalse(first["queue_journal_observed"])
        self.assertFalse(first["reservation"])
        self.assertFalse(first["lock_held"])
        self.assertFalse(first["mutation_performed"])
        self.assertEqual(first["cross_store_atomicity"], "not_claimed")
        self.assert_actionless(first)

    def test_unsafe_s8_flags_are_not_promoted_to_s9(self) -> None:
        plan = self.build_plan()
        unsafe_s8 = {
            "status": "PRECONDITION_SATISFIED_READ_ONLY",
            "permission": "read_only",
            "trusted": False,
            "current_head": True,
            "replay_protected": True,
            "generation_bound": True,
            "queue_bound": True,
            "fencing_bound": True,
            "lease_live": True,
            "external_action": False,
            "resume_allowed": False,
            "consume_allowed": False,
            "cas_authorized": False,
            "execution": {"resume": False, "reconcile": False, "mutation": False, "network": False},
        }
        actual = prime_transaction.verify_prime_writer_head
        with patch.object(prime_transaction, "verify_prime_writer_head", return_value=unsafe_s8):
            result = evaluate_prime_consume_plan(
                self.capture,
                self.anchor,
                self.control_capture,
                self.head,
                plan,
                s8_kwargs=self.s8_kwargs(),
            )
        self.assertEqual(result["reason"], "PRIME_TX_S8_NOT_SATISFIED")
        self.assert_actionless(result)
        self.assertIs(prime_transaction.verify_prime_writer_head, actual)

    def test_s8_and_derivation_use_isolated_observations(self) -> None:
        original_capture = copy.deepcopy(self.capture)
        real_verify = prime_transaction.verify_prime_writer_head

        def mutate_after_verification(capture, anchor, control_capture, head, **kwargs):
            result = real_verify(capture, anchor, control_capture, head, **kwargs)
            capture["files"]["policy"]["sha256"] = "f" * 64
            return result

        with patch.object(prime_transaction, "verify_prime_writer_head", side_effect=mutate_after_verification):
            plan = self.build_plan()
        self.assertEqual(self.capture, original_capture)
        self.assertEqual(plan["contract_role"], "precondition_bundle_only")

    def test_stale_s8_current_head_is_hold(self) -> None:
        args = self.s8_kwargs()
        args["expected_current_head"] = None
        result = evaluate_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            self.build_plan(),
            s8_kwargs=args,
        )
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "PRIME_TX_S8_NOT_SATISFIED")
        self.assert_actionless(result)

    def test_subject_and_version_drift_are_rejected(self) -> None:
        plan = self.build_plan()
        subject_drift = copy.deepcopy(plan)
        subject_drift["subject"]["card_id"] = "foreign-card"
        result = evaluate_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            subject_drift,
            s8_kwargs=self.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_SUBJECT_MISMATCH")
        self.assert_actionless(result)

        version_drift = copy.deepcopy(plan)
        version_drift["expected"]["card_state_version"] += 1
        result = evaluate_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            version_drift,
            s8_kwargs=self.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PRECONDITION_MISMATCH")
        self.assert_actionless(result)

    def test_dispatch_and_receipt_observation_drift_is_rejected(self) -> None:
        plan = self.build_plan()
        drift = copy.deepcopy(plan)
        drift["expected"]["w5_receipts_sha256"] = "f" * 64
        result = evaluate_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            drift,
            s8_kwargs=self.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PRECONDITION_MISMATCH")
        self.assert_actionless(result)

    def test_duplicate_json_and_unsafe_safety_fail_closed(self) -> None:
        plan = self.build_plan()
        duplicate = '{"schema_version":"prime-consume-preconditions-v1","schema_version":"forged"}'
        result = evaluate_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            duplicate,
            s8_kwargs=self.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_PLAN_JSON_DUPLICATE_KEY")
        self.assert_actionless(result)

        unsafe = copy.deepcopy(plan)
        unsafe["safety"]["mutation_performed"] = True
        result = evaluate_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            unsafe,
            s8_kwargs=self.s8_kwargs(),
        )
        self.assertEqual(result["reason"], "PRIME_TX_UNSAFE_EXECUTION_REQUEST")
        self.assert_actionless(result)

    def test_prepare_does_not_mutate_evidence_files_or_control_plane(self) -> None:
        plan = self.build_plan()
        before_files = {
            path.relative_to(self.fixture.root).as_posix(): path.read_bytes()
            for path in self.fixture.root.rglob("*")
            if path.is_file()
        }
        before_capture = copy.deepcopy(self.capture)
        before_control_capture = copy.deepcopy(self.control_capture)
        before_head = copy.deepcopy(self.head)
        before_snapshot = self.data["cp"].snapshot(self.data["control"]["run"]["run_id"])
        result = verify_prime_consume_plan(
            self.capture,
            self.anchor,
            self.control_capture,
            self.head,
            plan,
            s8_kwargs=self.s8_kwargs(),
        )
        after_files = {
            path.relative_to(self.fixture.root).as_posix(): path.read_bytes()
            for path in self.fixture.root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(result["status"], "PREPARE_ONLY_READ_ONLY")
        self.assertEqual(before_files, after_files)
        self.assertEqual(self.capture, before_capture)
        self.assertEqual(self.control_capture, before_control_capture)
        self.assertEqual(self.head, before_head)
        self.assertEqual(
            self.data["cp"].snapshot(self.data["control"]["run"]["run_id"]),
            before_snapshot,
        )
        self.assertEqual(self.data["cp"].integrity_check(), "ok")


if __name__ == "__main__":
    unittest.main()
