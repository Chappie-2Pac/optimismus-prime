"""W5-S25H tests for the read-only S25G consumer/audit gate."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import test_w5_s25b_handoff_acceptor as s25b  # noqa: E402
import test_w5_s25c_recovery_eligibility as s25c  # noqa: E402
from support.w5_s25e_harness import CLAIMED, HOLD, NOT_CLAIMED, RECOVERY_REQUIRED  # noqa: E402
from support.w5_s25g_quarantine_harness import observe_quarantine_boundary  # noqa: E402
from support.w5_s25h_observation_audit import (  # noqa: E402
    CAS_NOT_ATTEMPTED,
    MANUAL_QUARANTINE_REVIEW,
    PERSISTENCE_NOT_AUTHORIZED,
    READBACK_ONLY,
    audit_quarantine_observation,
)


class W5S25HObservationAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        s25b.W5S25BHandoffAcceptorTests.setUpClass()

    def _base(self) -> s25b.W5S25BHandoffAcceptorTests:
        helper = s25c.W5S25CRecoveryEligibilityTests()
        base = helper._build_transaction_base(unresolved=True)
        self.addCleanup(base.doCleanups)
        self.assertEqual(base.accept()["status"], "ACCEPTED_RECOVERY")
        return base

    def _valid_observation(self) -> tuple[s25b.W5S25BHandoffAcceptorTests, dict[str, object]]:
        base = self._base()
        observation = observe_quarantine_boundary(
            base.writer,
            scope_id=base.scope_id,
            handoff_id=base.grant["handoff_id"],
            lease_token=base.new_lease,
            now=base.clock.value,
        )
        return base, observation

    def test_valid_observation_is_local_readback_only(self) -> None:
        base, observation = self._valid_observation()

        result = audit_quarantine_observation(
            observation,
            expected_scope_id=base.scope_id,
            expected_handoff_id=base.grant["handoff_id"],
        )

        self.assertEqual(result["status"], CLAIMED)
        self.assertEqual(result["decision"], PERSISTENCE_NOT_AUTHORIZED)
        self.assertEqual(result["local_evidence"], CLAIMED)
        self.assertEqual(result["persistence_claim"], READBACK_ONLY)
        self.assertEqual(result["authority_claim"], NOT_CLAIMED)
        self.assertEqual(result["cas_claim"], CAS_NOT_ATTEMPTED)
        self.assertFalse(result["persistence_allowed"])
        self.assertFalse(result["cas_allowed"])
        self.assertFalse(result["fence_issue_allowed"])
        self.assertFalse(result["quarantine_written"])

    def test_hold_is_preserved_without_authority(self) -> None:
        result = audit_quarantine_observation(
            {"status": HOLD, "reason": "LOCK_UNAVAILABLE"},
            expected_scope_id="scope",
            expected_handoff_id="handoff",
        )

        self.assertEqual(result["status"], HOLD)
        self.assertEqual(result["decision"], HOLD)
        self.assertEqual(result["local_evidence"], NOT_CLAIMED)
        self.assertFalse(result["persistence_allowed"])

    def test_quarantine_required_becomes_manual_review(self) -> None:
        result = audit_quarantine_observation(
            {"status": RECOVERY_REQUIRED, "reason": "BOUNDARY_DRIFT"},
            expected_scope_id="scope",
            expected_handoff_id="handoff",
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], MANUAL_QUARANTINE_REVIEW)
        self.assertFalse(result["recovery_authority"])
        self.assertFalse(result["quarantine_written"])

    def test_claimed_without_complete_evidence_is_rejected(self) -> None:
        result = audit_quarantine_observation(
            {"status": CLAIMED},
            expected_scope_id="scope",
            expected_handoff_id="handoff",
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], MANUAL_QUARANTINE_REVIEW)
        self.assertIn("S25G_SCHEMA_UNVERIFIED", result["audit_gaps"])
        self.assertFalse(result["persistence_allowed"])

    def test_scope_binding_mismatch_is_rejected(self) -> None:
        base, observation = self._valid_observation()
        altered = deepcopy(observation)
        altered["eligibility"]["scope_id"] = "other-scope"

        result = audit_quarantine_observation(
            altered,
            expected_scope_id=base.scope_id,
            expected_handoff_id=base.grant["handoff_id"],
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertIn("S25C_SCOPE_BINDING_MISMATCH", result["audit_gaps"])

    def test_unexpected_quarantine_write_claim_is_rejected(self) -> None:
        base, observation = self._valid_observation()
        altered = deepcopy(observation)
        altered["quarantine_written"] = True

        result = audit_quarantine_observation(
            altered,
            expected_scope_id=base.scope_id,
            expected_handoff_id=base.grant["handoff_id"],
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "UNEXPECTED_QUARANTINE_WRITE_CLAIM")
        self.assertFalse(result["quarantine_written"])

    def test_existing_quarantined_state_is_not_consumable(self) -> None:
        base, observation = self._valid_observation()
        altered = deepcopy(observation)
        altered["eligibility"]["operation_state"] = "QUARANTINED"

        result = audit_quarantine_observation(
            altered,
            expected_scope_id=base.scope_id,
            expected_handoff_id=base.grant["handoff_id"],
        )

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertIn("QUARANTINE_STATE_PRESENT", result["audit_gaps"])

    def test_audit_support_surface_has_no_write_or_recovery_api(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25h_observation_audit.py").read_text()
        for forbidden in (
            "sqlite3.connect(",
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
            "recover_operation(",
            "execute_recovery(",
            "quarantine(",
            "prime_writes",
            "RecoveryExecutor",
            "subprocess",
            "signal.",
            "sleep(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("audit_quarantine_observation", source)


if __name__ == "__main__":
    unittest.main()
