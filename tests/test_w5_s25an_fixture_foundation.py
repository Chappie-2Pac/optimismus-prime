"""Independent literal foundation cases for S25AN."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25an_local_review_normalization as s25an  # noqa: E402


class W5S25ANFixtureFoundationTests(unittest.TestCase):
    def test_literal_pass_default_has_exact_result(self) -> None:
        result = s25an.evaluate_local_review_normalization_case(
            {"status": "pass"}
        )
        self.assertIs(type(result), dict)
        self.assertEqual(
            result,
            {"status": "pass", "findings": [], "summary": ""},
        )
        self.assertEqual(tuple(result), ("status", "findings", "summary"))
        self.assertIs(type(result["status"]), str)
        self.assertIs(type(result["findings"]), list)
        self.assertIs(type(result["summary"]), str)

    def test_literal_blocked_with_empty_findings_is_valid(self) -> None:
        review = {"status": "blocked", "findings": []}
        result = s25an.evaluate_local_review_normalization_case(
            review
        )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["findings"], [])
        self.assertIsNot(result["findings"], review["findings"])
        result["findings"].append({"path": "output", "reason": "only"})
        self.assertEqual(review["findings"], [])

    def test_literal_fail_reduces_one_finding(self) -> None:
        result = s25an.evaluate_local_review_normalization_case(
            {
                "status": "fail",
                "findings": [
                    {
                        "path": "tests/test_a.py",
                        "reason": "missing assertion",
                        "extra": "ignored",
                    }
                ],
            }
        )
        self.assertEqual(
            result,
            {
                "status": "fail",
                "findings": [
                    {"path": "tests/test_a.py", "reason": "missing assertion"}
                ],
                "summary": "",
            },
        )

    def test_literal_fail_without_finding_keeps_public_error(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"^fail benötigt mindestens einen konkreten Befund$",
        ):
            s25an.evaluate_local_review_normalization_case({"status": "fail"})


if __name__ == "__main__":
    unittest.main()
