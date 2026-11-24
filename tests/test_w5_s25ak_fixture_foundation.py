"""Independent literal foundation cases for the S25AK lifecycle relation."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ak_workflow_transition as s25ak  # noqa: E402


class W5S25AKFixtureFoundationTests(unittest.TestCase):
    def test_literal_valid_transitions_and_noops(self) -> None:
        cases = (
            ("created", "start", "VALID_TRANSITION", "running"),
            ("created", "cancel", "VALID_TRANSITION", "cancelled"),
            ("running", "pause", "VALID_TRANSITION", "paused"),
            ("running", "complete", "VALID_TRANSITION", "completed"),
            ("paused", "resume", "VALID_TRANSITION", "running"),
            ("completed", "cancel", "IDEMPOTENT_NOOP", "completed"),
            ("cancelled", "cancel", "IDEMPOTENT_NOOP", "cancelled"),
            ("failed", "fail", "VALID_TRANSITION", "failed"),
        )
        for state, operation, classification, next_state in cases:
            with self.subTest(state=state, operation=operation):
                result = s25ak.evaluate_workflow_transition_case(state, operation)
                self.assertEqual(result["classification"], classification)
                self.assertEqual(result["next_state"], next_state)
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["decision"], "PROPOSAL_ONLY")

    def test_literal_fail_is_admitted_from_each_known_state(self) -> None:
        for state, expected in (
            ("created", "failed"),
            ("running", "failed"),
            ("paused", "failed"),
            ("completed", "failed"),
            ("failed", "failed"),
            ("cancelled", "failed"),
        ):
            with self.subTest(state=state):
                result = s25ak.evaluate_workflow_transition_case(state, "fail")
                self.assertEqual(result["classification"], "VALID_TRANSITION")
                self.assertEqual(result["next_state"], expected)

    def test_literal_known_invalid_combinations_are_blocked(self) -> None:
        for state, operation in (
            ("created", "pause"),
            ("running", "resume"),
            ("paused", "complete"),
            ("completed", "start"),
            ("failed", "complete"),
            ("cancelled", "resume"),
        ):
            with self.subTest(state=state, operation=operation):
                result = s25ak.evaluate_workflow_transition_case(state, operation)
                self.assertEqual(result["classification"], "INVALID_TRANSITION")
                self.assertEqual(result["next_state"], "")
                self.assertEqual(result["status"], "TEST_BLOCKED")
                self.assertEqual(result["decision"], "HOLD")

    def test_literal_result_has_no_authority_or_production_claim(self) -> None:
        result = s25ak.evaluate_workflow_transition_case("created", "start")
        self.assertEqual(result["schema_version"], "s25ak.workflow-transition.v1")
        self.assertEqual(result["reason"], "valid_transition")
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")


if __name__ == "__main__":
    unittest.main()
