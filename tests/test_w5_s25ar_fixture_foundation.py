"""Literal foundation and structural tests for S25AR."""

from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPORT_PATH = REPO_ROOT / "tests" / "support" / "w5_s25ar_chappie_help_detail.py"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ar_chappie_help_detail as s25ar  # noqa: E402


EXPECTED_INDEX = (
    ("A", "analyze", ("analysis", "analyse")),
    ("B", "workflow", ("wf", "workflows")),
    ("C", "pipeline", ("llm-pipeline", "data")),
    ("Y", "pipeline-builder", ("pipeline_builder", "pipebuilder")),
    ("W", "workflow-builder", ("workflow_builder", "wf-builder")),
    ("O", "connectors", ("connector", "connectors")),
    ("U", "hub", ("hub-server", "hub-client", "hub-pair")),
    ("D", "memory", ("mem",)),
    ("E", "artifacts", ("artifact", "outputs")),
    ("F", "assistant", ("wizard", "guide")),
    ("R", "harvest", ("harvest_wizard", "harvest-wizard", "ernte")),
    ("G", "builder", ("assistant-builder", "spec")),
    ("H", "settings", ("prefs", "config")),
    ("I", "mistral", ("copilot", "llm")),
    ("J", "docs", ("readme", "documentation")),
    ("K", "boost", ("booster", "augment")),
    ("L", "llm", ("front", "llm_front", "chat")),
    ("M", "mistral", ("copilot", "assist")),
    ("N", "kb-refresh", ("kb", "kb_refresh", "knowledge", "knowledge-base")),
    ("P", "preset", ("profile", "mode")),
    ("T", "todo", ("to-do", "todo-list")),
    ("U", "training-eval", ("training_eval", "train-eval")),
)


class W5S25ARFixtureFoundationTests(unittest.TestCase):
    def test_literal_catalog_has_exact_order_and_aliases(self) -> None:
        self.assertIs(type(s25ar._HELP_TOPICS), tuple)
        self.assertEqual(len(s25ar._HELP_TOPICS), 22)
        actual = tuple((record[0], record[1], record[2]) for record in s25ar._HELP_TOPICS)
        self.assertEqual(actual, EXPECTED_INDEX)
        for record in s25ar._HELP_TOPICS:
            self.assertIs(type(record), tuple)
            self.assertEqual(len(record), 5)
            self.assertIs(type(record[0]), str)
            self.assertIs(type(record[1]), str)
            self.assertIs(type(record[2]), tuple)
            self.assertIs(type(record[3]), str)
            self.assertIs(type(record[4]), str)

    def test_support_is_import_free_and_effect_free(self) -> None:
        source = SUPPORT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertEqual(
            [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))],
            [],
        )
        self.assertNotIn("help_content", source)
        self.assertNotIn("settings_store", source)
        self.assertEqual(
            [node for node in ast.walk(tree) if isinstance(node, (ast.Global, ast.Nonlocal))],
            [],
        )
        self.assertEqual(
            [node for node in ast.walk(tree) if isinstance(node, (ast.AugAssign, ast.NamedExpr))],
            [],
        )
        self.assertEqual(
            [node for node in ast.walk(tree) if isinstance(node, ast.Subscript)],
            [],
        )
        self.assertEqual(
            [node for node in ast.walk(tree) if isinstance(node, (ast.Dict, ast.Set))],
            [],
        )
        self.assertEqual(
            [
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp))
            ],
            [],
        )
        module_assignments = [
            node
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        ]
        self.assertEqual(len(module_assignments), 1)
        assignment = module_assignments[0]
        self.assertIsInstance(assignment, ast.Assign)
        self.assertEqual(len(assignment.targets), 1)
        self.assertIsInstance(assignment.targets[0], ast.Name)
        self.assertEqual(assignment.targets[0].id, "_HELP_TOPICS")
        self.assertIsInstance(assignment.value, ast.Tuple)

    def test_support_calls_are_limited_to_normalization_methods(self) -> None:
        tree = ast.parse(SUPPORT_PATH.read_text(encoding="utf-8"))
        allowed_attributes = {"strip", "lower", "startswith"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertEqual(node.func.id, "_normalize_language")
            else:
                self.assertIsInstance(node.func, ast.Attribute)
                self.assertIn(node.func.attr, allowed_attributes)

    def test_support_has_one_ordered_topic_loop_and_ordered_alias_loop(self) -> None:
        tree = ast.parse(SUPPORT_PATH.read_text(encoding="utf-8"))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
        self.assertEqual(
            [function.name for function in functions],
            ["_normalize_language", "evaluate_chappie_help_detail"],
        )
        normalize = functions[0]
        normalize_body = [
            node
            for node in normalize.body
            if not (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            )
        ]
        self.assertEqual(
            [type(node) for node in normalize_body],
            [ast.Assign, ast.If, ast.If, ast.Return],
        )
        lowered_assignment = normalize_body[0]
        self.assertIsInstance(lowered_assignment, ast.Assign)
        self.assertEqual(lowered_assignment.targets[0].id, "lowered")
        lowered_call = lowered_assignment.value
        self.assertIsInstance(lowered_call, ast.Call)
        self.assertIsInstance(lowered_call.func, ast.Attribute)
        self.assertEqual(lowered_call.func.attr, "lower")
        strip_call = lowered_call.func.value
        self.assertIsInstance(strip_call, ast.Call)
        self.assertIsInstance(strip_call.func, ast.Attribute)
        self.assertEqual(strip_call.func.attr, "strip")
        self.assertIsInstance(strip_call.func.value, ast.Name)
        self.assertEqual(strip_call.func.value.id, "value")
        language_prefixes = ("de", "en")
        for node, prefix in zip(normalize_body[1:3], language_prefixes):
            self.assertIsInstance(node, ast.If)
            self.assertIsInstance(node.test, ast.Call)
            self.assertIsInstance(node.test.func, ast.Attribute)
            self.assertEqual(node.test.func.attr, "startswith")
            self.assertIsInstance(node.test.func.value, ast.Name)
            self.assertEqual(node.test.func.value.id, "lowered")
            self.assertEqual(node.test.args[0].value, prefix)
        self.assertIsInstance(normalize_body[3], ast.Return)
        self.assertEqual(normalize_body[3].value.value, "en")

        function = functions[1]
        function_body = [
            node
            for node in function.body
            if not (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            )
        ]
        self.assertEqual(
            [type(node) for node in function_body],
            [ast.Assign, ast.Assign, ast.If, ast.For, ast.Return],
        )
        self.assertEqual(function_body[0].targets[0].id, "lang")
        self.assertIsInstance(function_body[0].value, ast.Call)
        self.assertIsInstance(function_body[0].value.func, ast.Name)
        self.assertEqual(function_body[0].value.func.id, "_normalize_language")
        self.assertEqual(function_body[1].targets[0].id, "normalized")
        normalized_call = function_body[1].value
        self.assertIsInstance(normalized_call, ast.Call)
        self.assertIsInstance(normalized_call.func, ast.Attribute)
        self.assertEqual(normalized_call.func.attr, "lower")
        self.assertIsInstance(normalized_call.func.value, ast.Call)
        self.assertEqual(normalized_call.func.value.func.attr, "strip")

        topic_loops = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.For)
            and isinstance(node.iter, ast.Name)
            and node.iter.id == "_HELP_TOPICS"
        ]
        self.assertEqual(len(topic_loops), 1)
        topic_loop = topic_loops[0]
        top_level_branches = [
            node for node in topic_loop.body if isinstance(node, (ast.If, ast.For))
        ]
        self.assertEqual(
            [type(node) for node in top_level_branches],
            [ast.If, ast.If, ast.For],
        )
        self.assertIsInstance(top_level_branches[0].test, ast.Compare)
        self._assert_normalized_lower_compare(
            top_level_branches[0].test, "letter"
        )
        self.assertIsInstance(top_level_branches[1].test, ast.Compare)
        self._assert_normalized_lower_compare(
            top_level_branches[1].test, "command"
        )
        alias_loop = top_level_branches[2]
        self.assertIsInstance(alias_loop, ast.For)
        self.assertIsInstance(alias_loop.iter, ast.Name)
        self.assertEqual(alias_loop.iter.id, "aliases")
        alias_ifs = [node for node in alias_loop.body if isinstance(node, ast.If)]
        self.assertEqual(len(alias_ifs), 1)
        self.assertIsInstance(alias_ifs[0].test, ast.Compare)
        self._assert_normalized_lower_compare(alias_ifs[0].test, "alias")
        payload_returns = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Return) and isinstance(node.value, ast.IfExp)
        ]
        self.assertEqual(len(payload_returns), 3)
        for node in payload_returns:
            self.assertIsInstance(node.value.test, ast.Compare)
            self.assertIsInstance(node.value.test.left, ast.Name)
            self.assertEqual(node.value.test.left.id, "lang")
            self.assertIsInstance(node.value.test.ops[0], ast.Eq)
            self.assertEqual(node.value.test.comparators[0].value, "de")
            self.assertEqual(node.value.body.id, "de_detail")
            self.assertEqual(node.value.orelse.id, "en_detail")
        for forbidden_name in ("sorted", "set", "dict", "casefold", "normalize"):
            self.assertNotIn(forbidden_name, {node.id for node in ast.walk(function) if isinstance(node, ast.Name)})

    def _assert_normalized_lower_compare(
        self, compare: ast.Compare, source_name: str
    ) -> None:
        self.assertEqual(len(compare.ops), 1)
        self.assertIsInstance(compare.ops[0], ast.Eq)
        self.assertIsInstance(compare.left, ast.Name)
        self.assertEqual(compare.left.id, "normalized")
        self.assertIsInstance(compare.comparators[0], ast.Call)
        self.assertIsInstance(compare.comparators[0].func, ast.Attribute)
        self.assertEqual(compare.comparators[0].func.attr, "lower")
        self.assertIsInstance(compare.comparators[0].func.value, ast.Name)
        self.assertEqual(compare.comparators[0].func.value.id, source_name)


if __name__ == "__main__":
    unittest.main()

