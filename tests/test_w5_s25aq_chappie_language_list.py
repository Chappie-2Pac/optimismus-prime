"""Adversarial tests for the S25AQ language-list oracle."""

from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPORT_PATH = (
    REPO_ROOT
    / "tests"
    / "support"
    / "w5_s25aq_chappie_language_list.py"
)
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25aq_chappie_language_list as s25aq  # noqa: E402


class W5S25AQChappieLanguageListTests(unittest.TestCase):
    def _assert_exact_list(self, result: object, expected: list[str]) -> None:
        self.assertIs(type(result), list)
        self.assertEqual(result, expected)
        for item in result:
            self.assertIs(type(item), str)

    def test_string_and_list_paths_have_different_split_semantics(self) -> None:
        string_result = s25aq.evaluate_chappie_language_list("de,en")
        list_result = s25aq.evaluate_chappie_language_list(["de,en"])
        self._assert_exact_list(string_result, ["de", "en"])
        self._assert_exact_list(list_result, ["de,en"])

    def test_trim_lower_empty_filter_and_first_seen_deduplication(self) -> None:
        value = [" DE ", "de", "", " ", "EN", "en", "de-DE", "de-de"]
        before = list(value)
        result = s25aq.evaluate_chappie_language_list(value)
        self._assert_exact_list(result, ["de", "en", "de-de"])
        self.assertEqual(value, before)

    def test_empty_values_fallback_after_filtering(self) -> None:
        for value in (", ,", ["", " ", "\t"]):
            with self.subTest(value=repr(value)):
                result = s25aq.evaluate_chappie_language_list(value)
                self._assert_exact_list(result, ["de", "en"])

    def test_lower_is_not_casefold_or_nfkc_and_codes_are_not_validated(self) -> None:
        value = [
            "ß",
            "ｅ",
            "xx",
            "de-DE",
            "eng",
            "ger",
            "deu",
            "fra",
            "fre",
        ]
        result = s25aq.evaluate_chappie_language_list(value)
        self._assert_exact_list(
            result,
            [
                "ß",
                "ｅ",
                "xx",
                "de-de",
                "eng",
                "ger",
                "deu",
                "fra",
                "fre",
            ],
        )

    def test_nonempty_result_is_fresh_and_input_is_not_aliased(self) -> None:
        cases = ((["de", "en"], ["de", "en"]), ("de,en", ["de", "en"]))
        for value, expected in cases:
            with self.subTest(value=repr(value)):
                before = list(value) if type(value) is list else value
                first = s25aq.evaluate_chappie_language_list(value)
                second = s25aq.evaluate_chappie_language_list(value)
                self._assert_exact_list(first, expected)
                self._assert_exact_list(second, expected)
                self.assertIsNot(first, second)
                if type(value) is list:
                    self.assertIsNot(first, value)
                first.append("output-only")
                first[0] = "mutated"
                first.clear()
                self.assertEqual(value, before)
                self.assertEqual(second, expected)

    def test_fallback_output_mutation_does_not_create_cross_call_state(self) -> None:
        input_list = []
        first = s25aq.evaluate_chappie_language_list(input_list)
        self.assertIsNot(first, input_list)
        first.append("tampered")
        first.clear()
        second = s25aq.evaluate_chappie_language_list(input_list)
        self._assert_exact_list(second, ["de", "en"])
        self.assertEqual(input_list, [])
        self.assertIsNot(first, second)

    def test_repeated_calls_are_deterministic(self) -> None:
        cases = (
            (" DE,en,DE ", ["de", "en"]),
            (["en", "de", "en"], ["en", "de"]),
            ("xx", ["xx"]),
            ([], ["de", "en"]),
        )
        for value, expected in cases:
            with self.subTest(value=repr(value)):
                for _ in range(6):
                    self._assert_exact_list(
                        s25aq.evaluate_chappie_language_list(value),
                        expected,
                    )

    def test_support_has_no_imports_or_forbidden_effects(self) -> None:
        source = SUPPORT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        self.assertEqual(imports, [])
        for forbidden in (
            "settings_store",
            "os.environ",
            "open(",
            "Path",
            "json",
            "subprocess",
            "socket",
            "time",
            "importlib",
            "__import__",
            "eval(",
            "exec(",
            "getenv",
        ):
            self.assertNotIn(forbidden, source)

        allowed_names = {"type", "str"}
        allowed_attributes = {"split", "strip", "lower", "append"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertIn(node.func.id, allowed_names)
            else:
                self.assertIsInstance(node.func, ast.Attribute)
                self.assertIn(node.func.attr, allowed_attributes)

    def test_support_control_flow_has_no_alias_or_mapping_branch(self) -> None:
        tree = ast.parse(SUPPORT_PATH.read_text(encoding="utf-8"))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
        self.assertEqual(
            [function.name for function in functions],
            ["evaluate_chappie_language_list"],
        )
        function = functions[0]
        module_assignments = [
            node
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        ]
        self.assertEqual(module_assignments, [])
        self.assertEqual(
            [node for node in ast.walk(function) if isinstance(node, ast.Dict)],
            [],
        )
        self.assertEqual(
            [node for node in ast.walk(function) if isinstance(node, ast.Set)],
            [],
        )
        self.assertEqual(
            [node for node in ast.walk(function) if isinstance(node, ast.Match)],
            [],
        )
        self.assertEqual(
            len([node for node in ast.walk(function) if isinstance(node, ast.If)]),
            4,
        )

        compares = [node for node in ast.walk(function) if isinstance(node, ast.Compare)]
        self.assertEqual(len(compares), 3)
        signatures = []
        for compare in compares:
            self.assertEqual(len(compare.ops), 1)
            self.assertEqual(len(compare.comparators), 1)
            if (
                isinstance(compare.left, ast.Call)
                and isinstance(compare.left.func, ast.Name)
                and compare.left.func.id == "type"
                and isinstance(compare.comparators[0], ast.Name)
                and isinstance(compare.ops[0], ast.Is)
            ):
                signatures.append(("type", compare.comparators[0].id))
            elif (
                isinstance(compare.left, ast.Name)
                and compare.left.id == "code"
                and isinstance(compare.comparators[0], ast.Name)
                and compare.comparators[0].id == "deduped"
                and isinstance(compare.ops[0], ast.NotIn)
            ):
                signatures.append(("dedup",))
            else:
                self.fail(f"unexpected comparison: {ast.dump(compare)}")
        self.assertEqual(set(signatures), {("type", "list"), ("type", "str"), ("dedup",)})


if __name__ == "__main__":
    unittest.main()
