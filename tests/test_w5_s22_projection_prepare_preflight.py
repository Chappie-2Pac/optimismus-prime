"""Adversarial tests for the W5-S22 read-only Projection-Prepare preflight."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash  # noqa: E402
from modules.w5_dispatch_bridge_s0.projection_prepare_preflight import (  # noqa: E402
    PROJECTION_PREPARE_ELIGIBLE,
    evaluate_projection_prepare_preflight,
)
from modules.w5_dispatch_bridge_s0.receipt_commit_journal import ReceiptCommitJournal  # noqa: E402
from test_w5_s20_receipt_intent_witness import W5S20ReceiptIntentWitnessTests  # noqa: E402


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class W5S22ProjectionPreparePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        base = W5S20ReceiptIntentWitnessTests()
        base.setUp()
        self.base = base
        self.addCleanup(base.doCleanups)
        self.clock = MutableClock(100)
        self.temp = tempfile.TemporaryDirectory(prefix="w5-s22-preflight-")
        self.addCleanup(self.temp.cleanup)
        self.scope_id = "s22-projection-scope"
        self.db_path = Path(self.temp.name) / f"{self.scope_id}.sqlite3"
        self.lease_token = self.base.base.lease_token
        self.journal = ReceiptCommitJournal(
            self.db_path,
            scope_id=self.scope_id,
            owner_root=self.temp.name,
            clock=self.clock,
        )
        self.addCleanup(self.journal.close)
        intent = self.base.intent
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
        self.s20_input = {
            "worker_attestations": copy.deepcopy(self.base.base.bundle["worker_attestations"]),
            "replay_observation": copy.deepcopy(self.base.base.bundle["replay_observation"]),
            "replay_floor": copy.deepcopy(self.base.base.bundle["replay_floor"]),
            "host_runtime_attestation": copy.deepcopy(self.base.base.bundle["host_runtime_attestation"]),
            "s15_input": copy.deepcopy(self.base.base.s15_input),
            "owner_observation": copy.deepcopy(self.base.base.owner),
            "request": copy.deepcopy(self.base.base.request),
            "cross_store_snapshot": copy.deepcopy(self.base.base.snapshot),
            "receipt_intent": copy.deepcopy(self.base.intent),
        }
        with self.base.base._open() as owner_store:
            self.prepared = self.journal.prepare_from_s20(
                owner_store,
                s20_input=copy.deepcopy(self.s20_input),
                lease_token=self.lease_token,
            )
        self.scope = self.journal.read_scope()
        self.attestations = self._build_attestations()

    def _build_attestations(self) -> dict[str, dict]:
        intent = self.base.intent
        attestations: dict[str, dict] = {}
        for participant_id in sorted(intent["participants"]):
            participant = intent["participants"][participant_id]
            role = "OBSERVATION" if participant_id == "knowledge_ledger" else "WRITE"
            cursor = canonical_hash({"participant": participant_id, "cursor": "before-001"})
            attestations[participant_id] = {
                "participant_id": participant_id,
                "role": role,
                "source_identity": {
                    "adapter_id": f"adapter-{participant_id}",
                    "adapter_instance_id": f"instance-{participant_id}",
                    "store_id": f"store-{participant_id}",
                    "root_binding_sha256": "a" * 64,
                    "schema_version": f"{participant_id}-source-v1",
                },
                "writer_identity": None
                if role == "OBSERVATION"
                else {
                    "writer_id": f"writer-{participant_id}",
                    "writer_instance_id": f"writer-instance-{participant_id}",
                    "writer_epoch": 1,
                    "write_capability": True,
                    "local_atomicity": "BEFORE_CAS_AFTER_MARKER",
                    "writer_schema": f"{participant_id}-writer-v1",
                    "target_id": participant_id,
                },
                "observations": [
                    self._observation(participant_id, participant["expected_before"], cursor, 1),
                    self._observation(participant_id, participant["expected_before"], cursor, 2),
                ],
                "before_state_cas": {
                    "protocol": "before-state-cas-v1",
                    "target_id": participant_id,
                    "transaction_id": intent["transaction_id"],
                    "receipt_key": intent["receipt_key"],
                    "idempotency_key": intent["idempotency_key"],
                    "intent_sha256": canonical_hash(intent),
                    "expected_before": copy.deepcopy(participant["expected_before"]),
                    "expected_before_sha256": canonical_hash(participant["expected_before"]),
                    "expected_after": copy.deepcopy(participant["expected_after"]),
                    "expected_after_sha256": canonical_hash(participant["expected_after"]),
                    "fencing_epoch": self.scope["fencing_epoch"],
                    "source_cursor_sha256": cursor,
                },
            }
        return attestations

    def _observation(self, participant_id: str, before: dict, cursor: str, sequence: int) -> dict:
        return {
            "observation_id": f"observation-{participant_id}-{sequence}",
            "observer_id": f"reader-{participant_id}-{sequence}",
            "observer_instance_id": f"reader-instance-{participant_id}-{sequence}",
            "sequence": sequence,
            "observed_at": 90 + sequence,
            "lease": {
                "owner_id": self.scope["owner_id"],
                "owner_instance_id": self.scope["owner_instance_id"],
                "owner_epoch": self.scope["owner_epoch"],
                "fencing_epoch": self.scope["fencing_epoch"],
                "token_sha256": self.scope["lease_token_sha256"],
                "expires_at": self.scope["lease_expires_at"],
            },
            "before": copy.deepcopy(before),
            "source_cursor_sha256": cursor,
        }

    def _evaluate(self, *, attestations: dict | None = None, now: int = 100) -> dict:
        return evaluate_projection_prepare_preflight(
            self.journal,
            receipt_key=self.prepared["receipt_key"],
            participant_attestations=copy.deepcopy(attestations or self.attestations),
            now=now,
        )

    def test_complete_preflight_is_eligible_but_actionless(self) -> None:
        result = self._evaluate()
        self.assertEqual(result["status"], PROJECTION_PREPARE_ELIGIBLE)
        self.assertEqual(result["transaction_state"], "PREPARED")
        self.assertTrue(result["projection_prepare_eligible"])
        self.assertTrue(result["s21_prepared"])
        self.assertFalse(result["authoritative_decision"])
        self.assertFalse(result["projection_pending_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["mutation_performed"])
        self.assertFalse(result["external_mutation_performed"])
        self.assertFalse(result["receipt_committed"])
        self.assertFalse(result["consume_allowed"])
        self.assertEqual(result["cross_store_atomicity"], "NOT_CLAIMED")
        self.assertEqual(result["writer_participant_ids"], ["control_plane", "prime_ledger", "prime_queue", "receipt_projection"])
        self.assertEqual(result["observation_participant_ids"], ["knowledge_ledger"])

    def test_preflight_only_reads_s21_and_does_not_add_journal_events(self) -> None:
        before_seq = self.journal.read_scope()["event_seq"]
        result = self._evaluate()
        self.assertEqual(result["status"], PROJECTION_PREPARE_ELIGIBLE)
        self.assertEqual(self.journal.read_scope()["event_seq"], before_seq)
        self.assertEqual(self.journal.conn.execute("SELECT COUNT(*) FROM receipt_commit_journal").fetchone()[0], 1)

    def test_missing_participant_fails_closed_without_pending(self) -> None:
        invalid = copy.deepcopy(self.attestations)
        del invalid["prime_queue"]
        result = self._evaluate(attestations=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "PARTICIPANT_ATTESTATION_SET_INVALID")
        self.assertNotEqual(result["transaction_state"], "PROJECTION_PENDING")

    def test_knowledge_ledger_cannot_be_promoted_to_writer(self) -> None:
        invalid = copy.deepcopy(self.attestations)
        invalid["knowledge_ledger"]["writer_identity"] = copy.deepcopy(invalid["control_plane"]["writer_identity"])
        result = self._evaluate(attestations=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "KNOWLEDGE_LEDGER_WRITER_FORBIDDEN")

    def test_writer_capability_and_local_atomicity_are_required(self) -> None:
        invalid = copy.deepcopy(self.attestations)
        invalid["prime_queue"]["writer_identity"]["write_capability"] = False
        result = self._evaluate(attestations=invalid)
        self.assertEqual(result["reason"], "prime_queue_WRITER_CAPABILITY_INVALID")

        invalid = copy.deepcopy(self.attestations)
        invalid["prime_ledger"]["writer_identity"]["local_atomicity"] = "WRITE_ONLY"
        result = self._evaluate(attestations=invalid)
        self.assertEqual(result["reason"], "prime_ledger_WRITER_CAPABILITY_INVALID")

    def test_double_observation_and_independent_reader_identity_are_required(self) -> None:
        invalid = copy.deepcopy(self.attestations)
        invalid["control_plane"]["observations"].pop()
        self.assertEqual(self._evaluate(attestations=invalid)["reason"], "control_plane_DOUBLE_OBSERVATION_REQUIRED")

        invalid = copy.deepcopy(self.attestations)
        invalid["control_plane"]["observations"][1]["observer_instance_id"] = invalid["control_plane"]["observations"][0]["observer_instance_id"]
        self.assertEqual(self._evaluate(attestations=invalid)["reason"], "control_plane_OBSERVERS_NOT_INDEPENDENT")

    def test_before_state_drift_and_aba_fields_fail_closed(self) -> None:
        invalid = copy.deepcopy(self.attestations)
        invalid["prime_ledger"]["observations"][1]["before"]["version"] += 1
        result = self._evaluate(attestations=invalid)
        self.assertEqual(result["reason"], "prime_ledger_BEFORE_STATE_MISMATCH")

        invalid = copy.deepcopy(self.attestations)
        invalid["prime_ledger"]["before_state_cas"]["expected_after"]["generation"] = 1
        invalid["prime_ledger"]["before_state_cas"]["expected_after_sha256"] = canonical_hash(
            invalid["prime_ledger"]["before_state_cas"]["expected_after"]
        )
        result = self._evaluate(attestations=invalid)
        self.assertEqual(result["reason"], "prime_ledger_BEFORE_CAS_EXPECTED_AFTER_SHA256_MISMATCH")

    def test_fence_and_lease_drift_fail_before_any_writer(self) -> None:
        invalid = copy.deepcopy(self.attestations)
        invalid["control_plane"]["observations"][0]["lease"]["fencing_epoch"] -= 1
        result = self._evaluate(attestations=invalid)
        self.assertEqual(result["reason"], "control_plane_LEASE_FENCING_EPOCH_MISMATCH")

        self.assertEqual(self._evaluate(now=1000)["reason"], "S21_LEASE_EXPIRED")

    def test_source_cursor_and_cas_binding_are_required(self) -> None:
        invalid = copy.deepcopy(self.attestations)
        invalid["receipt_projection"]["observations"][1]["source_cursor_sha256"] = "b" * 64
        result = self._evaluate(attestations=invalid)
        self.assertEqual(result["reason"], "receipt_projection_SOURCE_CURSOR_DRIFT")

        invalid = copy.deepcopy(self.attestations)
        invalid["control_plane"]["before_state_cas"]["intent_sha256"] = "c" * 64
        result = self._evaluate(attestations=invalid)
        self.assertEqual(result["reason"], "control_plane_BEFORE_CAS_INTENT_SHA256_MISMATCH")

    def test_writer_target_and_observation_sequence_are_bound(self) -> None:
        invalid = copy.deepcopy(self.attestations)
        invalid["prime_queue"]["writer_identity"]["target_id"] = "prime_ledger"
        self.assertEqual(self._evaluate(attestations=invalid)["reason"], "prime_queue_WRITER_TARGET_MISMATCH")

        invalid = copy.deepcopy(self.attestations)
        invalid["receipt_projection"]["observations"][1]["sequence"] = 1
        self.assertEqual(self._evaluate(attestations=invalid)["reason"], "receipt_projection_OBSERVATION_SEQUENCE_NOT_MONOTONIC")

    def test_s21_integrity_drift_becomes_recovery_required(self) -> None:
        self.journal.conn.execute(
            "UPDATE receipt_commit_journal SET receipt_core_json=? WHERE receipt_key=?",
            (json.dumps({"tampered": True}), self.prepared["receipt_key"]),
        )
        result = self._evaluate()
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "S21_READBACK_UNAVAILABLE")

    def test_input_isolation_and_deterministic_digest(self) -> None:
        supplied = copy.deepcopy(self.attestations)
        original = copy.deepcopy(supplied)
        first = self._evaluate(attestations=supplied)
        self.assertEqual(supplied, original)
        second = self._evaluate(attestations=supplied)
        self.assertEqual(first["preflight_digest"], second["preflight_digest"])
        self.assertEqual(first["participant_attestations_sha256"], second["participant_attestations_sha256"])

    def test_no_pending_or_commit_state_is_emitted(self) -> None:
        result = self._evaluate()
        self.assertEqual(result["status"], PROJECTION_PREPARE_ELIGIBLE)
        self.assertEqual(result["projection_pending_state"], "PROJECTION_PENDING_DEFERRED")
        self.assertEqual(result["projection_commit_state"], "COMMITTED_DEFERRED")
        self.assertNotEqual(result["transaction_state"], "PROJECTION_PENDING")
        self.assertNotEqual(result["transaction_state"], "COMMITTED")

    def test_source_has_no_external_writer_surface(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/projection_prepare_preflight.py").read_text()
        for forbidden in (
            "import subprocess",
            "import socket",
            "import urllib",
            "os.system",
            "os.kill",
            "open(",
            "os.replace",
            "INSERT INTO",
            "UPDATE ",
            "commit_receipt",
            "consume_allowed = True",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
