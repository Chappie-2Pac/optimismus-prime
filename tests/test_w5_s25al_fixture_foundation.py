"""Independent literal foundation cases for the S25AL relation."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25al_memory_layer_first_match as s25al  # noqa: E402


class W5S25ALFixtureFoundationTests(unittest.TestCase):
    def test_literal_truth_table(self) -> None:
        cases = (
            (False, False, False, "none"),
            (False, False, True, "ltm"),
            (False, True, False, "mtm"),
            (False, True, True, "mtm"),
            (True, False, False, "stm"),
            (True, False, True, "stm"),
            (True, True, False, "stm"),
            (True, True, True, "stm"),
        )
        for stm_present, mtm_present, ltm_present, expected_layer in cases:
            with self.subTest(
                stm_present=stm_present,
                mtm_present=mtm_present,
                ltm_present=ltm_present,
            ):
                result = s25al.evaluate_memory_layer_first_match_case(
                    {
                        "stm_present": stm_present,
                        "mtm_present": mtm_present,
                        "ltm_present": ltm_present,
                    }
                )
                self.assertEqual(result["classification"], "MEMORY_LAYER_FIRST_MATCH_CLOSED")
                self.assertEqual(result["selected_layer"], expected_layer)
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["decision"], "PROPOSAL_ONLY")
                self.assertEqual(result["reason"], "first_match_resolved")

    def test_literal_result_shape_and_safety_literals(self) -> None:
        result = s25al.evaluate_memory_layer_first_match_case(
            {"stm_present": False, "mtm_present": False, "ltm_present": False}
        )
        self.assertEqual(
            tuple(result),
            (
                "schema_version",
                "classification",
                "status",
                "decision",
                "reason",
                "selected_layer",
                "production_status",
                "authority_claim",
            ),
        )
        self.assertEqual(result["schema_version"], "s25al.memory-layer-first-match.v1")
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def test_literal_unknown_structure_is_blocked(self) -> None:
        result = s25al.evaluate_memory_layer_first_match_case(
            {"stm_present": True, "mtm_present": False}
        )
        self.assertEqual(result["classification"], "INPUT_INVALID")
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], "input_invalid")
        self.assertEqual(result["selected_layer"], "")


if __name__ == "__main__":
    unittest.main()
