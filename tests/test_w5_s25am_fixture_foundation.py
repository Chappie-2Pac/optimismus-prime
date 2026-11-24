"""Independent literal foundation cases for S25AM."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25am_local_plan_shape as s25am  # noqa: E402


class W5S25AMFixtureFoundationTests(unittest.TestCase):
    def test_literal_complete_plan_has_exact_success_result(self) -> None:
        result = s25am.evaluate_local_plan_shape_case(
            {
                "goal": "build",
                "files": ["src/main.py"],
                "steps": ["implement"],
                "tests": ["unit"],
                "risks": ["regression"],
                "open_questions": ["none"],
            }
        )
        self.assertIs(type(result), dict)
        self.assertEqual(
            result,
            {
                "valid": True,
                "fields": [
                    "goal",
                    "files",
                    "steps",
                    "tests",
                    "risks",
                    "open_questions",
                ],
            },
        )
        self.assertIs(type(result["valid"]), bool)
        self.assertIs(type(result["fields"]), list)

    def test_literal_missing_field_keeps_public_error(self) -> None:
        with self.assertRaisesRegex(ValueError, r"^Plan unvollständig: risks$"):
            s25am.evaluate_local_plan_shape_case(
                {
                    "goal": "build",
                    "files": ["src/main.py"],
                    "steps": ["implement"],
                    "tests": ["unit"],
                    "open_questions": ["none"],
                }
            )

    def test_literal_extra_key_is_ignored(self) -> None:
        plan = {
            "goal": "build",
            "files": ["src/main.py"],
            "steps": ["implement"],
            "tests": ["unit"],
            "risks": ["regression"],
            "open_questions": ["none"],
            "future_metadata": {"owner": "local"},
        }
        result = s25am.evaluate_local_plan_shape_case(plan)
        self.assertTrue(result["valid"])
        self.assertNotIn("future_metadata", result)


if __name__ == "__main__":
    unittest.main()
