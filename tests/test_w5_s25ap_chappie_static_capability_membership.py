"""Adversarial tests for the S25AP static capability oracle."""

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
    / "w5_s25ap_chappie_static_capability_membership.py"
)
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ap_chappie_static_capability_membership as s25ap  # noqa: E402


ALLOWED = {
    "analyze",
    "compare",
    "document",
    "suggest",
    "evaluate",
    "structure",
    "clarify",
}
FORBIDDEN = {
    "self_modify",
    "set_goals",
    "self_preservation",
    "autonomous_action",
    "replicate",
    "override_constraints",
}


class W5S25APStaticCapabilityMembershipTests(unittest.TestCase):
    def _evaluate(self, capability: str) -> bool:
        self.assertIs(type(capability), str)
        result = s25ap.evaluate_chappie_static_capability_membership(capability)
        self.assertIs(type(result), bool)
        return result

    def test_literal_partition_is_complete_and_disjoint(self) -> None:
        self.assertEqual(len(ALLOWED), 7)
        self.assertEqual(len(FORBIDDEN), 6)
        self.assertTrue(ALLOWED.isdisjoint(FORBIDDEN))
        for capability in ALLOWED | FORBIDDEN:
            self.assertIs(type(capability), str)

    def test_every_allowed_literal_is_true(self) -> None:
        for capability in sorted(ALLOWED):
            with self.subTest(capability=capability):
                self.assertIs(self._evaluate(capability), True)

    def test_every_forbidden_literal_is_false(self) -> None:
        for capability in sorted(FORBIDDEN):
            with self.subTest(capability=capability):
                self.assertIs(self._evaluate(capability), False)

    def test_unknown_and_near_miss_values_are_default_deny(self) -> None:
        unknown = (
            "unknown_capability",
            "Analyze",
            "ANALYZE",
            " analyze",
            "analyze ",
            "self_modify ",
            "override_constraint",
            "clarify\n",
        )
        for capability in unknown:
            with self.subTest(capability=repr(capability)):
                self.assertIs(self._evaluate(capability), False)

    def test_no_alias_or_unicode_normalization_is_applied(self) -> None:
        values = (
            "documenting",
            "evaluate_",
            "self-preservation",
            "Ｓtructure",
            "suggestion",
        )
        for capability in values:
            with self.subTest(capability=repr(capability)):
                self.assertIs(self._evaluate(capability), False)

    def test_repeated_calls_are_deterministic_and_stateless(self) -> None:
        sequence = ("analyze", "self_modify", "not-known", "clarify")
        expected = (True, False, False, True)
        for _ in range(8):
            for capability, expected_result in zip(sequence, expected):
                with self.subTest(capability=capability):
                    self.assertIs(self._evaluate(capability), expected_result)

    def test_support_has_no_production_imports_or_effectful_calls(self) -> None:
        source = SUPPORT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        self.assertEqual(imports, [])
        self.assertNotIn("chappie_core", source)
        self.assertNotIn("config", source)
        self.assertNotIn("ConstraintKernel", source)
        self.assertNotIn("enforce_constraints", source)
        self.assertNotIn("require_external_decision", source)
        self.assertNotIn("open(", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("socket", source)
        self.assertNotIn("time", source)
        self.assertNotIn("json", source)
        self.assertNotIn("__import__", source)
        self.assertNotIn("import_module", source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self.fail(f"support must be call-free, found {ast.dump(node)}")

    def test_support_keeps_literal_sets_local_and_has_one_public_function(self) -> None:
        tree = ast.parse(SUPPORT_PATH.read_text(encoding="utf-8"))
        functions = [
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.assertEqual(
            [function.name for function in functions],
            ["evaluate_chappie_static_capability_membership"],
        )
        module_assignments = [
            node
            for node in tree.body
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        ]
        self.assertEqual(module_assignments, [])
        function = functions[0]
        local_sets = {}
        for node in ast.walk(function):
            if not isinstance(node, ast.Assign):
                continue
            self.assertEqual(len(node.targets), 1)
            target = node.targets[0]
            self.assertIsInstance(target, ast.Name)
            self.assertIsInstance(node.value, ast.Set)
            values = []
            for element in node.value.elts:
                self.assertIsInstance(element, ast.Constant)
                self.assertIs(type(element.value), str)
                values.append(element.value)
            local_sets[target.id] = values
        self.assertEqual(set(local_sets), {"forbidden", "allowed"})
        self.assertEqual(set(local_sets["forbidden"]), FORBIDDEN)
        self.assertEqual(set(local_sets["allowed"]), ALLOWED)
        self.assertEqual(len(local_sets["forbidden"]), len(FORBIDDEN))
        self.assertEqual(len(local_sets["allowed"]), len(ALLOWED))
        self.assertTrue(
            set(local_sets["forbidden"]).isdisjoint(local_sets["allowed"])
        )

    def test_support_control_flow_is_exact_membership_only(self) -> None:
        tree = ast.parse(SUPPORT_PATH.read_text(encoding="utf-8"))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
        )
        if_nodes = [node for node in ast.walk(function) if isinstance(node, ast.If)]
        self.assertEqual(len(if_nodes), 2)
        for node, expected_set, expected_result in zip(
            if_nodes,
            ("forbidden", "allowed"),
            (False, True),
        ):
            self.assertIsInstance(node.test, ast.Compare)
            self.assertIsInstance(node.test.left, ast.Name)
            self.assertEqual(node.test.left.id, "capability")
            self.assertEqual(len(node.test.ops), 1)
            self.assertIsInstance(node.test.ops[0], ast.In)
            self.assertEqual(len(node.test.comparators), 1)
            self.assertIsInstance(node.test.comparators[0], ast.Name)
            self.assertEqual(node.test.comparators[0].id, expected_set)
            self.assertEqual(node.orelse, [])
            self.assertEqual(len(node.body), 1)
            self.assertIsInstance(node.body[0], ast.Return)
            self.assertIsInstance(node.body[0].value, ast.Constant)
            self.assertIs(node.body[0].value.value, expected_result)

        returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
        self.assertEqual(len(returns), 3)
        self.assertEqual(
            [node.value.value for node in returns].count(False),
            2,
        )
        self.assertEqual(
            [node.value.value for node in returns].count(True),
            1,
        )
        self.assertIsInstance(function.body[-1], ast.Return)
        self.assertIsInstance(function.body[-1].value, ast.Constant)
        self.assertIs(function.body[-1].value.value, False)
        comparisons = [
            node for node in ast.walk(function) if isinstance(node, ast.Compare)
        ]
        self.assertEqual(len(comparisons), 2)


if __name__ == "__main__":
    unittest.main()
