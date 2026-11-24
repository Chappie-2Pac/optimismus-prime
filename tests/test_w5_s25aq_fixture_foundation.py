"""Literal foundation cases for S25AQ."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25aq_chappie_language_list as s25aq  # noqa: E402


class W5S25AQFixtureFoundationTests(unittest.TestCase):
    def _assert_exact_list(self, result: object, expected: list[str]) -> None:
        self.assertIs(type(result), list)
        self.assertEqual(result, expected)
        for item in result:
            self.assertIs(type(item), str)

    def test_literal_string_path_splits_trims_and_lowers(self) -> None:
        result = s25aq.evaluate_chappie_language_list(" DE, en ,DE,, ")
        self._assert_exact_list(result, ["de", "en"])

    def test_literal_list_path_does_not_split_elements(self) -> None:
        value = [" EN ", "de,en", "en"]
        result = s25aq.evaluate_chappie_language_list(value)
        self._assert_exact_list(result, ["en", "de,en"])
        self.assertEqual(value, [" EN ", "de,en", "en"])
        self.assertIsNot(result, value)

    def test_literal_empty_inputs_use_exact_fallback(self) -> None:
        for value in ("", [""]):
            with self.subTest(value=repr(value)):
                result = s25aq.evaluate_chappie_language_list(value)
                self._assert_exact_list(result, ["de", "en"])

    def test_fallback_result_is_fresh(self) -> None:
        first = s25aq.evaluate_chappie_language_list("")
        second = s25aq.evaluate_chappie_language_list("")
        self.assertEqual(first, ["de", "en"])
        self.assertEqual(second, ["de", "en"])
        self.assertIsNot(first, second)


if __name__ == "__main__":
    unittest.main()
