"""Adversarial tests for the W5-S20 read-only receipt-intent boundary."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w5_dispatch_bridge_s0 import receipt_intent_witness as s20  # noqa: E402
from modules.w5_dispatch_bridge_s0.cross_store_snapshot import (  # noqa: E402
    evaluate_cross_store_snapshot,
)
from test_w5_s19_cross_store_receipt_provenance import (  # noqa: E402
    W5S19ReceiptProvenanceTests,
)


class W5S20ReceiptIntentWitnessTests(unittest.TestCase):
    def setUp(self) -> None:
        base = W5S19ReceiptProvenanceTests()
        base.setUp()
        self.base = base
        self.addCleanup(base.tearDown)
        self.s19 = base._evaluate()
        self.evaluated = evaluate_cross_store_snapshot(base.snapshot)
        self.intent = self._build_intent()

    def _build_intent(self) -> dict:
        core = self.s19["provenance_core"]
        s16 = core["s16"]
        s17 = core["s17"]
        s18 = core["s18"]
        projection = core["projection"]
        owner_witness = s18["owner_commit_witness"]
        return {
            "schema_version": s20.RECEIPT_INTENT_WITNESS_SCHEMA,
            "contract_role": s20.RECEIPT_INTENT_WITNESS_ROLE,
            "receipt_key": "receipt-intent-s20-001",
            "receipt_kind": s20.RECEIPT_INTENT_KIND,
            "receipt_state": s20.RECEIPT_INTENT_STATE,
            "transaction_id": core["transaction_id"],
            "idempotency_key": core["idempotency_key"],
            "operation": core["operation"],
            "provenance_sha256": self.s19["provenance_sha256"],
            "s15_authorization_sha256": s16["s15_authorization_sha256"],
            "worker_authorization_sha256": s16["worker_authorization_sha256"],
            "s16_replay_observation_sha256": s16["s16_replay_observation_sha256"],
            "s16_replay_floor_sha256": s16["s16_replay_floor_sha256"],
            "s17_preflight_sha256": s17["preflight_sha256"],
            "s17_owner_observation_sha256": s17["owner_observation_sha256"],
            "s18_result_sha256": s18["result_sha256"],
            "s18_transition_sha256": s18["transition_sha256"],
            "s18_operation_record_sha256": s18["operation_record_sha256"],
            "s18_idempotency_index_sha256_after": s18["idempotency_index_sha256_after"],
            "s18_commit_witness_sha256": s18["owner_commit_witness_sha256"],
            "s18_head_before_sha256": s18["head_before_sha256"],
            "s18_head_after_sha256": s18["head_after_sha256"],
            "s18_state_version_before": s18["state_version_before"],
            "s18_state_version_after": s18["state_version_after"],
            "owner_id": owner_witness["revalidation_state"]["owner_id"],
            "owner_instance_id": owner_witness["revalidation_state"]["owner_instance_id"],
            "owner_epoch": owner_witness["revalidation_state"]["owner_epoch"],
            "fencing_epoch": s18["fencing_epoch"],
            "projection_manifest_sha256": projection["projection_manifest_sha256"],
            "projection_set_sha256": projection["projection_set_sha256"],
            "subject_binding": self.evaluated["fixture"]["bindings"]["subject_binding"],
            "effect_set": self.evaluated["fixture"]["bindings"]["effect_set"],
            "participants": self.evaluated["fixture"]["participants"],
            "future_commit_phases": list(s20.FUTURE_COMMIT_PHASES),
            "safety": {
                "read_only": True,
                "intent_persisted": False,
                "receipt_emitted": False,
                "receipt_committed": False,
                "consume_allowed": False,
                "consume_committed": False,
                "mutation_performed": False,
                "recovery_started": False,
                "external_action": False,
            },
        }

    def _evaluate(self, **overrides: object) -> dict:
        values = {
            "worker_attestations": copy.deepcopy(self.base.bundle["worker_attestations"]),
            "replay_observation": copy.deepcopy(self.base.bundle["replay_observation"]),
            "replay_floor": copy.deepcopy(self.base.bundle["replay_floor"]),
            "host_runtime_attestation": copy.deepcopy(self.base.bundle["host_runtime_attestation"]),
            "s15_input": copy.deepcopy(self.base.s15_input),
            "owner_observation": copy.deepcopy(self.base.owner),
            "request": copy.deepcopy(self.base.request),
            "cross_store_snapshot": copy.deepcopy(self.base.snapshot),
            "receipt_intent": copy.deepcopy(self.intent),
        }
        values.update(overrides)
        with self.base._open() as store:
            return s20.verify_receipt_intent_witness(store, **values)

    def _assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        for key in (
            "authoritative_decision",
            "authoritative_prepared",
            "intent_persisted",
            "receipt_emitted",
            "receipt_committed",
            "mutation_allowed",
            "mutation_window_open",
            "mutation_performed",
            "idempotency_reserved",
            "consume_allowed",
            "consume_committed",
            "cas_authorized",
            "recovery_allowed",
            "recovery_started",
            "resume_allowed",
            "external_action",
        ):
            self.assertFalse(result[key], key)
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_valid_intent_is_revalidated_but_not_committed(self) -> None:
        before = self.base._evaluate()
        result = self._evaluate()
        after = self.base._evaluate()
        self.assertEqual(result["status"], "RECEIPT_INTENT_REVALIDATED")
        self.assertEqual(result["decision"], "RECEIPT_COMMIT_RECHECK_REQUIRED")
        self.assertTrue(result["intent_derived"])
        self.assertTrue(result["witness_validated"])
        self.assertTrue(result["future_commit_requires_fresh_revalidation"])
        self.assertEqual(result["receipt_intent"]["receipt_key"], "receipt-intent-s20-001")
        self.assertEqual(result["receipt_intent_witness"]["provenance_sha256"], self.s19["provenance_sha256"])
        self.assertEqual(result["receipt_intent_witness"]["future_commit_phases"], list(s20.FUTURE_COMMIT_PHASES))
        self.assertEqual(before["provenance_sha256"], after["provenance_sha256"])
        self._assert_actionless(result)

    def test_s19_signature_drift_stays_hold(self) -> None:
        bundle = copy.deepcopy(self.base.bundle["worker_attestations"])
        bundle["control_plane"]["authority_mac"] = "0" * 64
        result = self._evaluate(worker_attestations=bundle)
        self.assertEqual(result["status"], "HOLD")
        self.assertTrue(result["reason"].startswith("S19_"))
        self._assert_actionless(result)

    def test_receipt_key_cannot_reuse_s19_idempotency_key(self) -> None:
        intent = copy.deepcopy(self.intent)
        intent["receipt_key"] = self.s19["provenance_core"]["idempotency_key"]
        result = self._evaluate(receipt_intent=intent)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "RECEIPT_KEYSPACE_COLLISION")
        self._assert_actionless(result)

    def test_subject_binding_and_effect_drift_are_rejected(self) -> None:
        for field in ("subject_binding", "effect_set"):
            intent = copy.deepcopy(self.intent)
            if isinstance(intent[field], dict):
                intent[field]["tampered"] = True
            else:
                intent[field].append({"tampered": True})
            result = self._evaluate(receipt_intent=intent)
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["reason"], "INTENT_SUBJECT_OR_EFFECT_DRIFT")
            self._assert_actionless(result)

    def test_participant_drift_requires_recovery(self) -> None:
        intent = copy.deepcopy(self.intent)
        intent["participants"]["control_plane"]["expected_before"]["version"] += 1
        result = self._evaluate(receipt_intent=intent)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "INTENT_PARTICIPANT_DRIFT")
        self._assert_actionless(result)

    def test_future_phase_and_safety_escalation_are_rejected(self) -> None:
        intent = copy.deepcopy(self.intent)
        intent["future_commit_phases"] = ["PREPARED", "COMMITTED"]
        result = self._evaluate(receipt_intent=intent)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "INTENT_COMMIT_PHASES_INVALID")
        self._assert_actionless(result)

        intent = copy.deepcopy(self.intent)
        intent["safety"]["receipt_emitted"] = True
        result = self._evaluate(receipt_intent=intent)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "INTENT_SAFETY_UNSAFE")
        self._assert_actionless(result)

    def test_duplicate_json_key_is_rejected(self) -> None:
        encoded = json.dumps(self.intent, separators=(",", ":"))[:-1]
        encoded += ',"receipt_key":"duplicate-receipt-key"}'
        result = self._evaluate(receipt_intent=encoded)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "INTENT_JSON_DUPLICATE_KEY")
        self._assert_actionless(result)

    def test_projection_toctou_is_recovery_required(self) -> None:
        snapshot = copy.deepcopy(self.base.snapshot)
        snapshot["observations"]["prime_queue"]["sample_b"]["projection"]["observed"]["phase"] = "tampered"
        result = self._evaluate(cross_store_snapshot=snapshot)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertTrue(result["reason"].startswith("S19_"))
        self._assert_actionless(result)

    def test_input_mapping_isolated(self) -> None:
        intent = copy.deepcopy(self.intent)
        original = copy.deepcopy(intent)
        result = self._evaluate(receipt_intent=intent)
        self.assertEqual(result["status"], "RECEIPT_INTENT_REVALIDATED")
        self.assertEqual(intent, original)

    def test_s20_source_has_no_mutation_or_external_io_surface(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/receipt_intent_witness.py").read_text()
        for forbidden in (
            "import sqlite3",
            "import subprocess",
            "import socket",
            "import urllib",
            "os.system",
            "os.kill",
            "_advance_validated",
            "quarantine_scope",
            '"receipt_emitted": True',
            '"consume_allowed": True',
            '"mutation_performed": True',
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
