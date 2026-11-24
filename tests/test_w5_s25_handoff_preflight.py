"""Read-only S25 handoff/fence-rotation preflight tests."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from modules.w4_small_loop_s0 import canonical_hash  # noqa: E402
from modules.w5_dispatch_bridge_s0.handoff_preflight import (  # noqa: E402
    HANDOFF_HOLD,
    HANDOFF_PREVIEW_ONLY,
    HANDOFF_RECOVERY_REQUIRED,
    build_handoff_observation,
    evaluate_handoff_preflight,
)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class W5S25HandoffPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root_binding = digest(b"s25-root")
        self.before = digest(b"queue-before")
        self.after = digest(b"queue-after")
        self.intent = digest(b"intent")
        self.manifest = digest(b"manifest")
        self.old_lease = "s25-old-lease-token-012345"
        self.new_lease = "s25-new-lease-token-012345"
        self.scope = {
            "scope_id": "s25-scope",
            "root_binding_sha256": self.root_binding,
            "owner_id": "old-owner",
            "owner_instance_id": "old-instance",
            "owner_epoch": 4,
            "fencing_epoch": 9,
            "lease_token_sha256": digest(self.old_lease.encode()),
            "lease_expires_at": 100,
            "scope_status": "IN_DOUBT",
            "active_operation_id": "s25-tx",
            "active_phase": "EXECUTING",
            "event_seq": 1,
        }
        self.operation = {
            "transaction_id": "s25-tx",
            "idempotency_key": "s25-idem",
            "intent_sha256": self.intent,
            "state": "PREPARED",
            "expected_queue_sha256": self.before,
            "after_queue_sha256": self.after,
        }
        self.transaction = {
            "status": "EXACT",
            "manifest_sha256": self.manifest,
            "before_sha256": self.before,
            "after_sha256": self.after,
            "queue_sha256": self.after,
            "terminal_marker": "ABSENT",
        }
        self.observation = build_handoff_observation(
            observation_id="s25-observation",
            observed_at=120,
            root={
                "root_binding_sha256": self.root_binding,
                "active_scope_id": "s25-scope",
                "active_fencing_epoch": 9,
            },
            scope=self.scope,
            operation=self.operation,
            transaction=self.transaction,
        )
        new_lease_hash = digest(self.new_lease.encode())
        self.grant = {
            "schema_version": "prime-queue-handoff-grant-v1",
            "handoff_id": "s25-handoff",
            "authority_id": "runtime-authority",
            "authority_epoch": 3,
            "authority_proof": "signed-or-bound-authority-proof",
            "root_binding_sha256": self.root_binding,
            "scope_id": "s25-scope",
            "transaction_id": "s25-tx",
            "idempotency_key": "s25-idem",
            "intent_sha256": self.intent,
            "expected_active_phase": "EXECUTING",
            "expected_operation_state": "PREPARED",
            "expected_event_seq": 1,
            "old_owner_id": "old-owner",
            "old_owner_instance_id": "old-instance",
            "old_owner_epoch": 4,
            "old_fencing_epoch": 9,
            "old_lease_token_sha256": digest(self.old_lease.encode()),
            "old_lease_expires_at": 100,
            "new_owner_id": "new-owner",
            "new_owner_instance_id": "new-instance",
            "new_owner_epoch": 5,
            "new_fencing_epoch": 10,
            "new_lease_token_sha256": new_lease_hash,
            "new_lease_expires_at": 1000,
            "handoff_kind": "AUTHORIZED_TERMINATION",
            "liveness_evidence_sha256": digest(b"liveness-proof"),
            "reason": "replace stale executor through trusted handoff",
            "issued_at": 120,
        }

    def evaluate(self, observation=None, grant=None, *, token=None, now=150) -> dict[str, object]:
        return evaluate_handoff_preflight(
            observation or self.observation,
            grant or self.grant,
            new_lease_token=token or self.new_lease,
            now=now,
        )

    def test_structurally_valid_grant_is_only_a_preview(self) -> None:
        observation_before = copy.deepcopy(self.observation)
        grant_before = copy.deepcopy(self.grant)

        result = self.evaluate()

        self.assertEqual(result["status"], HANDOFF_PREVIEW_ONLY)
        self.assertTrue(result["handoff_preview_eligible"])
        self.assertFalse(result["authority_verified"])
        self.assertFalse(result["handoff_allowed"])
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["queue_mutation_performed"])
        self.assertEqual(result["cross_store_atomicity"], "NOT_CLAIMED")
        self.assertEqual(self.observation, observation_before)
        self.assertEqual(self.grant, grant_before)

    def test_same_input_has_same_candidate_digest(self) -> None:
        first = self.evaluate()
        second = self.evaluate()

        self.assertEqual(first["candidate_sha256"], second["candidate_sha256"])
        self.assertEqual(first["observation_sha256"], second["observation_sha256"])

    def test_missing_authority_proof_is_hold_even_with_expired_source_lease(self) -> None:
        missing_proof = copy.deepcopy(self.grant)
        missing_proof["authority_proof"] = ""

        result = self.evaluate(grant=missing_proof)

        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertFalse(result["handoff_allowed"])

    def test_recovery_required_operation_is_not_previewable(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["operation"]["state"] = "RECOVERY_REQUIRED"
        observation["observation_sha256"] = canonical_hash(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )

        result = self.evaluate(observation=observation)

        self.assertEqual(result["status"], HANDOFF_RECOVERY_REQUIRED)
        self.assertFalse(result["handoff_preview_eligible"])

    def test_stale_source_fence_is_hold(self) -> None:
        stale = copy.deepcopy(self.grant)
        stale["old_fencing_epoch"] = 8

        result = self.evaluate(grant=stale)

        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertIn("HANDOFF_SOURCE_FENCE_STALE", result["reason"])

    def test_new_fence_and_owner_epochs_must_advance(self) -> None:
        non_monotonic = copy.deepcopy(self.grant)
        non_monotonic["new_fencing_epoch"] = 9
        non_monotonic["new_owner_epoch"] = 4

        result = self.evaluate(grant=non_monotonic)

        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertIn("HANDOFF_FENCING_EPOCH_NOT_MONOTONIC", result["reason"])

    def test_new_lease_must_match_grant_and_be_live(self) -> None:
        result = self.evaluate(token="wrong-s25-new-lease-token")
        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertIn("HANDOFF_NEW_LEASE_MISMATCH", result["reason"])

        expired = copy.deepcopy(self.grant)
        expired["new_lease_expires_at"] = 150
        result = self.evaluate(grant=expired)
        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertIn("HANDOFF_NEW_LEASE_EXPIRED", result["reason"])

    def test_old_lease_expiry_is_bound_against_aba_renewal(self) -> None:
        changed = copy.deepcopy(self.grant)
        changed["old_lease_expires_at"] = 101

        result = self.evaluate(grant=changed)

        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertIn("HANDOFF_SOURCE_FENCE_STALE", result["reason"])

    def test_scope_recovery_required_is_not_automatically_rotated(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["scope"]["scope_status"] = "RECOVERY_REQUIRED"
        observation["observation_sha256"] = canonical_hash(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )

        result = self.evaluate(observation=observation)

        self.assertEqual(result["status"], HANDOFF_RECOVERY_REQUIRED)
        self.assertFalse(result["handoff_allowed"])

    def test_malformed_or_foreign_transaction_requires_recovery(self) -> None:
        for status in ("MALFORMED", "FOREIGN", "UNKNOWN"):
            observation = copy.deepcopy(self.observation)
            observation["transaction"]["status"] = status
            observation["observation_sha256"] = canonical_hash(
                {key: value for key, value in observation.items() if key != "observation_sha256"}
            )

            result = self.evaluate(observation=observation)

            self.assertEqual(result["status"], HANDOFF_RECOVERY_REQUIRED)

    def test_transaction_before_after_and_live_hash_are_bound(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["transaction"]["after_sha256"] = digest(b"different-after")
        observation["observation_sha256"] = canonical_hash(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )

        result = self.evaluate(observation=observation)

        self.assertEqual(result["status"], HANDOFF_RECOVERY_REQUIRED)
        self.assertIn("TRANSACTION_INTENT_BINDING_DRIFT", result["reason"])

    def test_observation_digest_and_root_drift_fail_closed(self) -> None:
        tampered = copy.deepcopy(self.observation)
        tampered["root"]["active_fencing_epoch"] = 10
        result = self.evaluate(observation=tampered)
        self.assertEqual(result["status"], HANDOFF_RECOVERY_REQUIRED)

        digest_drift = copy.deepcopy(self.observation)
        digest_drift["observation_id"] = "different-observation"
        result = self.evaluate(observation=digest_drift)
        self.assertEqual(result["status"], HANDOFF_RECOVERY_REQUIRED)

    def test_grant_intent_and_active_phase_are_bound(self) -> None:
        changed = copy.deepcopy(self.grant)
        changed["intent_sha256"] = digest(b"different-intent")
        result = self.evaluate(grant=changed)
        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertIn("HANDOFF_INTENT_BINDING_MISMATCH", result["reason"])

        changed = copy.deepcopy(self.grant)
        changed["expected_active_phase"] = "RECOVERY"
        result = self.evaluate(grant=changed)
        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertIn("HANDOFF_ACTIVE_STATE_DRIFT", result["reason"])

    def test_future_observation_or_grant_is_hold(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["observed_at"] = 151
        observation["observation_sha256"] = canonical_hash(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )
        self.assertEqual(self.evaluate(observation=observation)["status"], HANDOFF_HOLD)

        grant = copy.deepcopy(self.grant)
        grant["issued_at"] = 151
        self.assertEqual(self.evaluate(grant=grant)["status"], HANDOFF_HOLD)

    def test_malformed_unhashable_inputs_fail_closed(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["operation"]["state"] = []
        observation["observation_sha256"] = canonical_hash(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )
        self.assertEqual(self.evaluate(observation=observation)["status"], HANDOFF_RECOVERY_REQUIRED)

        grant = copy.deepcopy(self.grant)
        grant["expected_operation_state"] = []
        result = self.evaluate(grant=grant)
        self.assertEqual(result["status"], HANDOFF_HOLD)

        self.assertEqual(self.evaluate(now=None)["status"], HANDOFF_HOLD)  # type: ignore[arg-type]

    def test_unknown_scope_status_is_recovery_required(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["scope"]["scope_status"] = "NOT_A_SCOPE_STATUS"
        observation["observation_sha256"] = canonical_hash(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )

        result = self.evaluate(observation=observation)

        self.assertEqual(result["status"], HANDOFF_RECOVERY_REQUIRED)

    def test_terminal_marker_and_queue_hash_must_agree(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["transaction"]["terminal_marker"] = "COMMITTED"
        observation["transaction"]["queue_sha256"] = self.before
        observation["observation_sha256"] = canonical_hash(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )

        result = self.evaluate(observation=observation)

        self.assertEqual(result["status"], HANDOFF_RECOVERY_REQUIRED)
        self.assertIn("COMMITTED_MARKER_HASH_CONFLICT", result["reason"])

    def test_digest_is_only_a_self_consistent_claim_not_authority(self) -> None:
        observation = copy.deepcopy(self.observation)
        observation["db_integrity"] = "OK"
        observation["schema_objects_valid"] = True
        observation["observation_sha256"] = canonical_hash(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )

        result = self.evaluate(observation=observation)

        self.assertEqual(result["status"], HANDOFF_PREVIEW_ONLY)
        self.assertFalse(result["observation_verified"])
        self.assertEqual(result["source_attestation"], "SELF_CONSISTENT_CLAIM_ONLY")

    def test_source_surface_is_read_only(self) -> None:
        source = (REPO_ROOT / "modules" / "w5_dispatch_bridge_s0" / "handoff_preflight.py").read_text()
        for forbidden in (
            "sqlite3.connect",
            "prime_writes.",
            "os.replace",
            "durable_new",
            "subprocess",
            "socket",
            "urllib",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
