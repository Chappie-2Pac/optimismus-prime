"""W5-S25I tests for the design-only Authority-/Fence-/CAS boundary."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from support.w5_s25i_authority_boundary import (  # noqa: E402
    CAS_NOT_ATTEMPTED,
    DESIGN_ONLY,
    FENCE_NOT_ISSUED,
    HOLD,
    MANUAL_REVIEW,
    NOT_CLAIMED,
    RECOVERY_REQUIRED,
    evaluate_authority_proposal,
)


class W5S25IAuthorityBoundaryTests(unittest.TestCase):
    @staticmethod
    def _proposal() -> dict[str, object]:
        return {
            "authority_id": "authority-1",
            "authority_key_id": "key-1",
            "authority_sequence": 7,
            "grant_id": "grant-1",
            "action": "PERSIST_QUARANTINE",
            "root_binding": "root-sha",
            "store_instance_id": "store-1",
            "authority_store_id": "authority-store-1",
            "scope_id": "scope-1",
            "transaction_id": "tx-1",
            "idempotency_key": "idem-1",
            "observation_digest": "obs-sha",
            "observation_id": "observation-1",
            "expected_subject_generation": {
                "db_identity": "db-1",
                "queue_identity": "queue-1",
                "event_head": "event-1",
                "handoff_head": "handoff-1",
                "fencing_epoch": 4,
            },
            "expected_event_head": "event-1",
            "expected_handoff_head": "handoff-1",
            "expected_subject_fence": {
                "owner_epoch": 3,
                "fencing_epoch": 4,
                "lease_token_sha256": "lease-sha",
            },
            "lease_id": "lease-1",
            "not_before": 100,
            "expires_at": 200,
            "allowed_transition": {
                "from": ["PREPARED", "IN_DOUBT", "RECOVERY_REQUIRED"],
                "to": "QUARANTINED",
            },
        }

    def test_complete_proposal_is_design_only_and_never_authorized(self) -> None:
        result = evaluate_authority_proposal(self._proposal(), now=150)

        self.assertEqual(result["status"], NOT_CLAIMED)
        self.assertEqual(result["decision"], DESIGN_ONLY)
        self.assertTrue(result["proposal_complete"])
        self.assertEqual(result["authority_claim"], NOT_CLAIMED)
        self.assertEqual(result["cas_claim"], CAS_NOT_ATTEMPTED)
        self.assertEqual(result["fence_observation"], FENCE_NOT_ISSUED)
        self.assertFalse(result["write_authorized"])
        self.assertFalse(result["cas_attempted"])
        self.assertFalse(result["fence_issued"])
        self.assertFalse(result["quarantine_persisted"])

    def test_missing_field_fails_closed(self) -> None:
        proposal = self._proposal()
        proposal.pop("observation_digest")

        result = evaluate_authority_proposal(proposal, now=150)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], MANUAL_REVIEW)
        self.assertIn("MISSING_OBSERVATION_DIGEST", result["audit_gaps"])
        self.assertFalse(result["write_authorized"])

    def test_expired_or_not_yet_current_lease_is_hold(self) -> None:
        expired = evaluate_authority_proposal(self._proposal(), now=200)
        future = evaluate_authority_proposal(self._proposal(), now=99)

        self.assertEqual(expired["status"], HOLD)
        self.assertEqual(future["status"], HOLD)
        self.assertEqual(expired["decision"], HOLD)
        self.assertFalse(expired["write_authorized"])

    def test_same_store_authority_is_not_independent(self) -> None:
        proposal = self._proposal()
        proposal["authority_store_id"] = proposal["store_instance_id"]

        result = evaluate_authority_proposal(proposal, now=150)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "AUTHORITY_NOT_INDEPENDENT")
        self.assertIn("SAME_AUTHORITY_STORE", result["audit_gaps"])

    def test_unverified_signature_claim_is_rejected(self) -> None:
        proposal = self._proposal()
        proposal["signature_valid"] = True

        result = evaluate_authority_proposal(proposal, now=150)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "SIGNATURE_UNVERIFIED")
        self.assertEqual(result["authority_claim"], NOT_CLAIMED)

    def test_aba_or_foreign_drift_is_manual_review(self) -> None:
        for flag in ("aba_detected", "generation_reused", "foreign_writer_observed", "reopen_gap"):
            proposal = self._proposal()
            proposal[flag] = True
            result = evaluate_authority_proposal(proposal, now=150)
            self.assertEqual(result["status"], RECOVERY_REQUIRED)
            self.assertEqual(result["decision"], MANUAL_REVIEW)
            self.assertFalse(result["write_authorized"])

    def test_invalid_transition_is_not_narrowed_implicitly(self) -> None:
        proposal = self._proposal()
        proposal["allowed_transition"] = {"from": ["*"], "to": "*"}

        result = evaluate_authority_proposal(proposal, now=150)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "TRANSITION_NOT_NARROW")

    def test_invalid_authority_sequence_fails_closed(self) -> None:
        proposal = self._proposal()
        proposal["authority_sequence"] = "not-an-integer"

        result = evaluate_authority_proposal(proposal, now=150)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "AUTHORITY_SEQUENCE_INVALID")

    def test_authority_boundary_support_surface_has_no_mutation_api(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25i_authority_boundary.py").read_text()
        for forbidden in (
            "sqlite3",
            "os.open(",
            "O_CREAT",
            "O_WRONLY",
            "O_RDWR",
            "LOCK_EX",
            "write_bytes",
            "write_text",
            "unlink(",
            "replace(",
            "rename(",
            "mkdir(",
            "commit(",
            "durable_new(",
            "quarantine(",
            "recover_operation(",
            "execute_recovery(",
            "PrimeQueueWriter",
            "RecoveryExecutor",
            "subprocess",
            "signal.",
            "sleep(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("evaluate_authority_proposal", source)


if __name__ == "__main__":
    unittest.main()
