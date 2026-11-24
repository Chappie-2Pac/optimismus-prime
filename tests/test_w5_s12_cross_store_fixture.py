"""Adversarial tests for the pure W5-S12 Cross-Store fixture harness."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from modules.w4_small_loop_s0 import canonical_hash  # noqa: E402
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    CROSS_STORE_PARTICIPANT_IDS,
    HOOK_IDS,
    build_cross_store_fixture,
    build_cross_store_hook_trace,
    classify_cross_store_fixture,
    evaluate_cross_store_fixture,
    inject_cross_store_fault,
)


class W5S12CrossStoreFixtureTests(unittest.TestCase):
    def projection(self, participant_id: str, *, after: bool) -> dict:
        phase = "after" if after else "before"
        version = 2 if after else 1
        generation = 2 if after else 1
        state = {"participant": participant_id, "phase": phase}
        journal = {"participant": participant_id, "journal": phase}
        before_state_hash = canonical_hash({"participant": participant_id, "phase": "before"})
        return {
            "state": state,
            "journal": journal,
            "state_sha256": canonical_hash(state),
            "journal_sha256": canonical_hash(journal),
            "version": version,
            "generation": generation,
            "generation_id": canonical_hash({"participant": participant_id, "generation": generation}),
            "parent_hash": before_state_hash if after else None,
        }

    def fixture(self, *, observed: str = "after", hook_count: int = len(HOOK_IDS)) -> dict:
        participants = {}
        for participant_id in sorted(CROSS_STORE_PARTICIPANT_IDS):
            before = self.projection(participant_id, after=False)
            after = self.projection(participant_id, after=True)
            participants[participant_id] = {
                "expected_before": before,
                "expected_after": after,
                "observed": copy.deepcopy(after if observed == "after" else before),
            }
        transaction_id = "tx-s12-001"
        hooks = build_cross_store_hook_trace(transaction_id=transaction_id, fencing_epoch=3)
        subject_binding = {
            "project_id": "project-001",
            "goal_id": "goal-001",
            "task_id": "task-001",
            "plan_id": "plan-001",
            "card_id": "card-001",
            "attempt_id": "attempt-001",
            "dispatch_id": "dispatch-001",
        }
        contract_subject = {
            **subject_binding,
            "run_id": "run-001",
        }
        contract = {
            "schema_version": "prime-authoritative-coordinator-v2",
            "contract_role": "authoritative_transaction_contract_read_only",
            "transaction_id": transaction_id,
            "idempotency_key": "idem-s12-001",
            "operation": "project_queue",
            "effect_mode": "PRIME_PROJECTION",
            "subject": contract_subject,
            "subject_binding": subject_binding,
            "provenance": {
                "source_refs": ["evidence-s12-001"],
                "provenance_status": {
                    "structural_provenance_verified": True,
                    "content_supported": True,
                    "temporal_valid": True,
                    "derivation_traced": True,
                },
            },
            "context_gate": {
                "task_loss": False,
                "decision_loss": False,
                "blocker_loss": False,
                "provenance_loss": False,
                "contradiction_rate": 0,
            },
            "subagent_admission": {
                "enabled": False,
                "child_count": 0,
                "parallelism": False,
                "max_depth": 0,
            },
            "acceptance_enabled": False,
            "safety": {
                "read_only": True,
                "lock_held": False,
                "reservation": False,
                "mutation_performed": False,
                "authoritative_commit": False,
            },
        }
        return build_cross_store_fixture(
            transaction_id=transaction_id,
            fencing_epoch=3,
            participants=participants,
            hook_trace=hooks[:hook_count],
            contract_material=contract,
            subject_binding_material=subject_binding,
        )

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["authoritative_decision"])
        self.assertFalse(result["external_action"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_full_after_is_deterministic_and_not_authoritative(self) -> None:
        fixture = self.fixture()
        first = classify_cross_store_fixture(fixture)
        second = classify_cross_store_fixture(json.loads(json.dumps(fixture, sort_keys=True)))
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "COMMITTED")
        self.assertTrue(first["commit_evidence_sufficient_read_only"])
        self.assert_actionless(first)

    def test_prepared_all_before_is_only_prepared(self) -> None:
        result = classify_cross_store_fixture(self.fixture(observed="before", hook_count=4))
        self.assertEqual(result["status"], "PREPARED")
        self.assertFalse(result.get("commit_evidence_sufficient_read_only", False))
        self.assert_actionless(result)

    def test_fault_prefixes_are_deterministic_and_split_commit_is_pending(self) -> None:
        full = self.fixture()
        prepared = inject_cross_store_fault(full, "T0.before_prepare")
        self.assertEqual(classify_cross_store_fixture(prepared)["status"], "PREPARED")
        split = inject_cross_store_fault(full, "T3.sqlite_after_commit")
        split_result = classify_cross_store_fixture(split)
        self.assertEqual(split_result["status"], "IN_DOUBT")
        self.assertEqual(split_result["reason"], "PROJECTION_PENDING")
        self.assertEqual(split_result, classify_cross_store_fixture(inject_cross_store_fault(full, "T3.sqlite_after_commit")))

    def test_marker_and_content_binding_reject_self_consistent_forgery(self) -> None:
        fixture = self.fixture()
        fixture["expected_contract_digest"] = fixture["observed_contract_digest"] = canonical_hash({"forged": True})
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertFalse(result["bindings_verified"] if "bindings_verified" in result else True)
        self.assert_actionless(result)

        fixture = self.fixture()
        fixture["participants"]["prime_queue"]["observed"]["state"]["phase"] = "forged"
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["reason"], {"PRIME_FIXTURE_HOOK_INVALID", "PRIME_FIXTURE_BINDING_CONFLICT"})
        self.assert_actionless(result)

    def test_effect_set_is_complete_and_cannot_hide_unlisted_after_state(self) -> None:
        fixture = self.fixture()
        del fixture["bindings"]["effect_set"][-1]
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["reason"], {"PRIME_FIXTURE_EFFECT_INVALID", "PRIME_FIXTURE_BINDING_CONFLICT"})
        self.assert_actionless(result)

    def test_fence_lease_and_aba_fail_closed(self) -> None:
        fixture = self.fixture()
        fixture["observed_fencing_epoch"] = 4
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assert_actionless(result)

        fixture = self.fixture()
        fixture["lease"]["observed_at"] = fixture["lease"]["expires_at"]
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertFalse(result["lease_valid"])
        self.assert_actionless(result)

        fixture = self.fixture()
        fixture["hook_trace"][5]["after_states"]["prime_ledger"] = "BEFORE"
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["reason"], {"PRIME_FIXTURE_HOOK_INVALID", "PRIME_FIXTURE_BINDING_CONFLICT"})
        self.assert_actionless(result)

        fixture = self.fixture()
        fixture["lease"]["token_sha256"] = canonical_hash({"forged": True})
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "PRIME_FIXTURE_BINDING_CONFLICT")
        self.assert_actionless(result)

    def test_s11_mode_and_hook_phase_are_hard_gates(self) -> None:
        fixture = self.fixture()
        fixture["bindings"]["contract"]["effect_mode"] = "PRIME_CONSUME"
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "PRIME_FIXTURE_BINDING_CONFLICT")
        self.assert_actionless(result)

        fixture = self.fixture()
        fixture["bindings"]["contract"]["external_action"] = True
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "PRIME_FIXTURE_UNSAFE_REQUEST")
        self.assert_actionless(result)

        fixture = self.fixture(observed="before", hook_count=4)
        self.assertEqual(fixture["bindings"]["marker"]["status"], "PENDING")
        fixture["bindings"]["marker"]["status"] = "COMMITTED"
        marker_digest = canonical_hash(fixture["bindings"]["marker"])
        fixture["expected_marker_commitment_sha256"] = marker_digest
        fixture["observed_marker_commitment_sha256"] = marker_digest
        result = evaluate_cross_store_fixture(fixture)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertFalse(result["marker_phase_verified"])
        self.assert_actionless(result)

        with self.assertRaises(ValueError):
            build_cross_store_hook_trace(
                transaction_id="tx-s12-001",
                fencing_epoch=3,
                state_after_by_hook={
                    "T1.coordinator_prepared": {
                        participant_id: "AFTER" for participant_id in sorted(CROSS_STORE_PARTICIPANT_IDS)
                    }
                },
            )

    def test_duplicate_json_input_and_input_isolation(self) -> None:
        duplicate = '{"schema_version":"one","schema_version":"two"}'
        result = evaluate_cross_store_fixture(duplicate)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "PRIME_FIXTURE_JSON_DUPLICATE_KEY")
        self.assert_actionless(result)

        fixture = self.fixture()
        original = copy.deepcopy(fixture)
        result = classify_cross_store_fixture(fixture)
        fixture["participants"]["control_plane"]["observed"]["state"]["phase"] = "mutated-after-call"
        self.assertEqual(result["status"], "COMMITTED")
        self.assertEqual(original["participants"]["control_plane"]["observed"]["state"]["phase"], "after")

    def test_fault_matrix_covers_every_hook_without_commit_authority(self) -> None:
        full = self.fixture()
        for hook_id in HOOK_IDS:
            with self.subTest(hook_id=hook_id):
                result = evaluate_cross_store_fixture(inject_cross_store_fault(full, hook_id))
                self.assertIn(result["status"], {"PREPARED", "IN_DOUBT", "COMMITTED"})
                self.assert_actionless(result)


if __name__ == "__main__":
    unittest.main()
