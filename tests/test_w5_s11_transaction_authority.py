"""Adversarial tests for the read-only W5-S11 authority step."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from modules.w4_small_loop_s0 import canonical_hash, canonical_json  # noqa: E402
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    classify_authoritative_recovery,
    evaluate_authoritative_transaction_contract,
    verify_authoritative_transaction_contract,
)
from modules.w5_dispatch_bridge_s0.prime_transaction_authority import PrimeTransactionAuthorityError  # noqa: E402


class W5S11TransactionAuthorityTests(unittest.TestCase):
    def expected(self, participant_id: str, *, after: bool = False) -> dict:
        suffix = "after" if after else "before"
        return {
            "state_sha256": canonical_hash({"participant": participant_id, "state": suffix}),
            "journal_sha256": canonical_hash({"participant": participant_id, "journal": suffix}),
            "version": 2 if after else 1,
            "generation": 2 if after else 1,
            "parent_hash": None if not after else canonical_hash({"participant": participant_id, "state": "before"}),
        }

    def contract(self, *, effect_mode: str = "PRIME_PROJECTION") -> dict:
        participant_ids = ("control_plane", "knowledge_ledger", "prime_ledger", "prime_queue", "receipt_projection")
        before = {participant_id: self.expected(participant_id) for participant_id in participant_ids}
        after = {participant_id: self.expected(participant_id, after=True) for participant_id in participant_ids}
        effects = [
            {
                "participant_id": "prime_queue",
                "target_id": "queue",
                "operation": "replace",
                "mode": "PRIME_PROJECTION",
                "before_sha256": before["prime_queue"]["state_sha256"],
                "after_sha256": after["prime_queue"]["state_sha256"],
                "before_version": 1,
                "after_version": 2,
            },
            {
                "participant_id": "control_plane",
                "target_id": "runtime",
                "operation": "cas",
                "mode": "PRIME_PROJECTION",
                "before_sha256": before["control_plane"]["state_sha256"],
                "after_sha256": after["control_plane"]["state_sha256"],
                "before_version": 1,
                "after_version": 2,
            },
        ]
        effects = sorted(effects, key=lambda item: (item["participant_id"], item["target_id"], item["operation"]))
        contract = {
            "schema_version": "prime-authoritative-coordinator-v2",
            "contract_role": "authoritative_transaction_contract_read_only",
            "transaction_id": "tx-s11-001",
            "idempotency_key": "idem-s11-001",
            "operation": "project_queue",
            "effect_mode": effect_mode,
            "subject": {
                "project_id": "project-001",
                "goal_id": "goal-001",
                "run_id": "run-001",
                "plan_id": "plan-001",
                "plan_version": "plan-v1",
                "task_id": "task-001",
                "card_id": "card-001",
                "attempt_id": "attempt-001",
                "dispatch_id": "dispatch-001",
                "receipt_id_or_null": None,
                "review_id_or_null": None,
            },
            "subject_binding": {
                "goal_version": 1,
                "goal_hash": "1" * 64,
                "non_goals_hash": "2" * 64,
                "scope_gate_id": "scope-001",
                "project_profile_hash": "3" * 64,
                "path_policy_hash": "4" * 64,
                "source_manifest_hash": "5" * 64,
                "task_hash": "6" * 64,
                "plan_hash": "7" * 64,
                "card_hash": "8" * 64,
                "source_queue_hash": "9" * 64,
                "input_snapshot_id": "input-001",
                "input_snapshot_hash": "a" * 64,
                "context_pack_id": "pack-001",
                "pack_version": 1,
                "base_snapshot_id": "base-001",
                "context_pack_hash": "b" * 64,
            },
            "provenance": {
                "repository_id": "optimismus-prime",
                "repository_commit_hash": "0" * 64,
                "repository_tree_hash": "1" * 64,
                "dirty_tree_manifest_hash": "2" * 64,
                "test_manifest_hash": "3" * 64,
                "evidence_hash": "4" * 64,
                "evidence_set_hash": "5" * 64,
                "knowledge_ledger_head_hash": "6" * 64,
                "provenance_manifest_hash": "7" * 64,
                "derivation_trace_hash": "8" * 64,
                "source_refs": ["evidence-001"],
                "source_refs_hash": None,
                "provenance_status": {
                    "structural_provenance_verified": True,
                    "content_supported": True,
                    "temporal_valid": True,
                    "derivation_traced": True,
                },
                "provenance_digest": None,
            },
            "context_gate": {
                "context_pack_id": "pack-001",
                "pack_version": 1,
                "base_snapshot_id": "base-001",
                "compression_version": "compression-v1",
                "loss_ledger_hash": "0" * 64,
                "context_pack_hash": "b" * 64,
                "critical_context_recall": 10000,
                "task_loss": False,
                "decision_loss": False,
                "blocker_loss": False,
                "provenance_loss": False,
                "contradiction_rate": 0,
                "reconstruction_test_id": "reconstruct-001",
                "context_gate_digest": None,
            },
            "continuity_gate": {
                "run_budget_hash": "1" * 64,
                "budget_counters": {"retry": 0, "error": 0, "replan": 0},
                "deadline_policy_hash": "2" * 64,
                "deadline_at": 4000,
                "heartbeat_deadline_at": 3000,
                "last_heartbeat_at": 2000,
                "checkpoint_id_or_null": None,
                "checkpoint_hash": "3" * 64,
                "resume_point_id_or_null": None,
                "last_committed_event_id": "event-000",
                "progress_signature": "4" * 64,
                "progress_signature_count": 0,
                "no_progress_window": 3,
                "retry_budget": 3,
                "error_budget": 3,
                "replan_budget": 1,
                "projection_pending_deadline": 3500,
                "continuity_digest": None,
            },
            "review_binding": {
                "enabled": False,
                "review_domain_id_or_null": None,
                "reviewer_identity_or_null": None,
                "reviewer_process_identity_or_null": None,
                "criteria_hash_or_null": None,
                "review_input_manifest_hash_or_null": None,
                "review_decision_hash_or_null": None,
                "scheduler_snapshot_hash_or_null": None,
                "candidate_set_hash_or_null": None,
                "selection_policy_hash_or_null": None,
                "dependency_snapshot_hash_or_null": None,
                "wave_sequence_no": 0,
                "previous_acceptance_transaction_id_or_null": None,
            },
            "subagent_admission": {
                "enabled": False,
                "parent_run_id": "run-001",
                "parent_attempt_id": "attempt-001",
                "child_count": 0,
                "max_children": 0,
                "max_depth": 0,
                "parallelism": False,
                "role": "NONE",
                "worker_interface_version": "NONE",
                "child_run_id_or_null": None,
                "child_attempt_id_or_null": None,
                "child_dispatch_id_or_null": None,
                "child_input_snapshot_hash_or_null": None,
                "child_context_pack_hash_or_null": None,
                "capability_set_hash_or_null": None,
                "path_policy_hash_or_null": None,
                "resource_budget_hash_or_null": None,
                "merge_policy_hash_or_null": None,
                "failure_isolation_policy": "NONE",
                "expected_utility": 0,
                "estimated_cost": 0,
            },
            "precondition_plan_sha256": "7" * 64,
            "participant_observations_sha256": "b" * 64,
            "effect_set": effects,
            "effect_digest": canonical_hash(effects),
            "expected_before": before,
            "expected_after": after,
            "lease": {
                "owner_id": "owner-001",
                "token_sha256": "c" * 64,
                "expires_at": 1767225660,
                "fencing_epoch": 3,
            },
            "required_rechecks": {
                "atomic_commit": True,
                "participant": True,
                "queue_journal": True,
                "lease": True,
                "fencing": True,
                "receipts": True,
            },
            "acceptance_enabled": False,
            "next_card_intent_id_or_null": None,
            "safety": {
                "read_only": True,
                "lock_held": False,
                "reservation": False,
                "mutation_performed": False,
                "authoritative_commit": False,
            },
        }
        contract["provenance"]["source_refs_hash"] = canonical_hash(sorted(contract["provenance"]["source_refs"]))
        contract["provenance"]["provenance_digest"] = canonical_hash({key: value for key, value in contract["provenance"].items() if key != "provenance_digest"})
        contract["context_gate"]["context_gate_digest"] = canonical_hash({key: value for key, value in contract["context_gate"].items() if key != "context_gate_digest"})
        contract["continuity_gate"]["continuity_digest"] = canonical_hash({key: value for key, value in contract["continuity_gate"].items() if key != "continuity_digest"})
        return contract

    def recovery(self, *, participant_state: str, journal_state: str, marker_state: str, observed_epoch: int = 3) -> dict:
        participant_ids = ("control_plane", "knowledge_ledger", "prime_ledger", "prime_queue", "receipt_projection")
        expected_before = {key: self.expected(key) for key in participant_ids}
        expected_after = {key: self.expected(key, after=True) for key in participant_ids}
        observed_participants = expected_before if participant_state == "BEFORE" else expected_after
        return {
            "schema_version": "prime-authoritative-recovery-v1",
            "transaction_id": "tx-s11-001",
            "expected_contract_digest": "1" * 64,
            "observed_contract_digest": "1" * 64,
            "expected_subject_binding_digest": "2" * 64,
            "observed_subject_binding_digest": "2" * 64,
            "expected_precondition_plan_sha256": "3" * 64,
            "observed_precondition_plan_sha256": "3" * 64,
            "expected_participant_observations_sha256": canonical_hash(observed_participants),
            "observed_participant_observations_sha256": canonical_hash(observed_participants),
            "expected_effect_digest": "d" * 64,
            "observed_effect_digest": "d" * 64,
            "expected_before": expected_before,
            "expected_after": expected_after,
            "observed_participants": observed_participants,
            "expected_marker_commitment_sha256": "5" * 64,
            "observed_marker_commitment_sha256": "5" * 64,
            "observed_state": "COMMITTING",
            "participant_states": {key: participant_state for key in participant_ids},
            "journal_states": {key: journal_state for key in participant_ids},
            "marker_states": {key: marker_state for key in ("coordinator", "prime_queue", "prime_ledger", "knowledge_ledger", "receipt")},
            "expected_fencing_epoch": 3,
            "observed_fencing_epoch": observed_epoch,
            "lease_valid": True,
        }

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["external_action"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_valid_contract_is_deterministic_and_not_authoritative(self) -> None:
        contract = self.contract()
        first = verify_authoritative_transaction_contract(contract)
        second = verify_authoritative_transaction_contract(canonical_json(contract))
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "CONTRACT_VALIDATED_READ_ONLY")
        self.assertEqual(first["transaction_state"], "PREPARED")
        self.assertFalse(first["authoritative_prepared"])
        self.assertFalse(first["idempotency_reserved"])
        self.assertEqual(first["effect_mode"], "PRIME_PROJECTION")
        self.assert_actionless(first)

    def test_prime_consume_and_p0_acceptance_are_hard_holds(self) -> None:
        result = evaluate_authoritative_transaction_contract(self.contract(effect_mode="PRIME_CONSUME"))
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_PRIME_CONSUME_UNIMPLEMENTED")
        self.assert_actionless(result)

        contract = self.contract()
        contract["acceptance_enabled"] = True
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_P0_DISABLED")
        self.assert_actionless(result)

    def test_effect_digest_safety_and_duplicate_json_fail_closed(self) -> None:
        contract = self.contract()
        before = copy.deepcopy(contract)
        contract["effect_digest"] = "e" * 64
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_EFFECT_DIGEST_MISMATCH")
        self.assert_actionless(result)
        self.assertEqual(contract["expected_before"], before["expected_before"])

        duplicate = '{"schema_version":"prime-authoritative-coordinator-v2","schema_version":"forged"}'
        result = evaluate_authoritative_transaction_contract(duplicate)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_JSON_DUPLICATE_KEY")
        self.assert_actionless(result)

        contract = self.contract()
        contract["safety"]["lock_held"] = True
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_UNSAFE_REQUEST")
        self.assert_actionless(result)

    def test_participant_and_effect_shape_are_exact(self) -> None:
        contract = self.contract()
        del contract["expected_after"]["prime_ledger"]
        with self.assertRaises(PrimeTransactionAuthorityError) as caught:
            verify_authoritative_transaction_contract(contract)
        self.assertEqual(caught.exception.code, "PRIME_TX_AUTHORITY_PARTICIPANT_MISMATCH")

        contract = self.contract()
        contract["effect_set"][1] = copy.deepcopy(contract["effect_set"][0])
        contract["effect_digest"] = canonical_hash(sorted(contract["effect_set"], key=lambda item: (item["participant_id"], item["target_id"], item["operation"])))
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_EFFECT_UNDEFINED")
        self.assert_actionless(result)

        contract = self.contract()
        contract["effect_set"][0]["participant_id"] = "knowledge_ledger"
        contract["effect_digest"] = canonical_hash(sorted(contract["effect_set"], key=lambda item: (item["participant_id"], item["target_id"], item["operation"])))
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_EFFECT_SCOPE_INVALID")
        self.assert_actionless(result)

    def test_context_continuity_review_subagent_and_generic_schema_gates_hold(self) -> None:
        contract = self.contract()
        contract["context_gate"]["task_loss"] = True
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_CONTEXT_GATE_INVALID")
        self.assert_actionless(result)

        contract = self.contract()
        contract["context_gate"]["context_gate_digest"] = "f" * 64
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_CONTEXT_GATE_INVALID")
        self.assert_actionless(result)

        contract = self.contract()
        contract["provenance"]["provenance_digest"] = "f" * 64
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_PROVENANCE_INVALID")
        self.assert_actionless(result)

        contract = self.contract()
        contract["continuity_gate"]["progress_signature_count"] = 3
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_CONTINUITY_INVALID")
        self.assert_actionless(result)

        contract = self.contract()
        contract["continuity_gate"]["budget_counters"]["retry"] = 4
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_CONTINUITY_INVALID")
        self.assert_actionless(result)

        contract = self.contract()
        contract["operation"] = "accept_reviewed_card"
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_REVIEW_INVALID")
        self.assert_actionless(result)

        contract = self.contract()
        contract["subagent_admission"]["enabled"] = True
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_P2_DISABLED")
        self.assert_actionless(result)

        contract = self.contract()
        contract["subagent_admission"]["max_children"] = 1
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_P2_DISABLED")
        self.assert_actionless(result)

        contract = self.contract()
        contract["provenance"]["source_refs"] = []
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_PROVENANCE_INVALID")
        self.assert_actionless(result)

        contract = self.contract()
        contract["precondition_plan_sha256"] = "a" * 64
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_SUBJECT_BINDING_INVALID")
        self.assert_actionless(result)

        contract = self.contract()
        del contract["subject_binding"]
        result = evaluate_authoritative_transaction_contract(contract)
        self.assertEqual(result["reason"], "PRIME_TX_AUTHORITY_SCHEMA_INVALID")
        self.assert_actionless(result)

    def test_recovery_all_before_and_all_after_are_deterministic(self) -> None:
        aborted = classify_authoritative_recovery(self.recovery(participant_state="BEFORE", journal_state="CLEAN_BEFORE", marker_state="ABSENT"))
        self.assertEqual(aborted["status"], "ABORTED_SAFE")
        self.assertEqual(aborted["transaction_state"], "ABORTED")
        self.assertFalse(aborted["mutation_allowed"])

        committed = classify_authoritative_recovery(self.recovery(participant_state="AFTER", journal_state="CLEAN_AFTER", marker_state="VALID"))
        self.assertEqual(committed["status"], "COMMITTED_PROVEN")
        self.assertEqual(committed["transaction_state"], "COMMITTED")
        self.assertFalse(committed["authoritative_decision"])
        self.assertTrue(committed["commit_evidence_sufficient_read_only"])
        self.assertFalse(committed["mutation_allowed"])

        unbound = self.recovery(participant_state="AFTER", journal_state="CLEAN_AFTER", marker_state="VALID")
        unbound["observed_contract_digest"] = "e" * 64
        result = classify_authoritative_recovery(unbound)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertFalse(result["binding_verified"])

    def test_mixed_drift_open_journal_and_fence_loss_require_recovery(self) -> None:
        mixed = self.recovery(participant_state="AFTER", journal_state="OPEN", marker_state="VALID")
        mixed["participant_states"]["prime_queue"] = "DRIFT"
        result = classify_authoritative_recovery(mixed)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["transaction_state"], "IN_DOUBT")

        uncertain = self.recovery(participant_state="AFTER", journal_state="CLEAN_AFTER", marker_state="VALID")
        uncertain["observed_state"] = "IN_DOUBT"
        result = classify_authoritative_recovery(uncertain)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["transaction_state"], "IN_DOUBT")

        contradictory = self.recovery(participant_state="AFTER", journal_state="CLEAN_AFTER", marker_state="VALID")
        contradictory["observed_state"] = "PREPARED"
        result = classify_authoritative_recovery(contradictory)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["transaction_state"], "IN_DOUBT")
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["consume_allowed"])

        stale = self.recovery(participant_state="AFTER", journal_state="CLEAN_AFTER", marker_state="VALID", observed_epoch=4)
        result = classify_authoritative_recovery(stale)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["transaction_state"], "IN_DOUBT")

    def test_recovery_duplicate_json_and_input_isolation(self) -> None:
        observation = self.recovery(participant_state="BEFORE", journal_state="CLEAN_BEFORE", marker_state="ABSENT")
        snapshot = copy.deepcopy(observation)
        result = classify_authoritative_recovery(observation)
        self.assertEqual(result["status"], "ABORTED_SAFE")
        self.assertEqual(observation, snapshot)

        duplicate = '{"schema_version":"prime-authoritative-recovery-v1","schema_version":"forged"}'
        with self.assertRaises(PrimeTransactionAuthorityError) as caught:
            classify_authoritative_recovery(duplicate)
        self.assertEqual(caught.exception.code, "PRIME_TX_AUTHORITY_RECOVERY_CONFLICT")


if __name__ == "__main__":
    unittest.main()
