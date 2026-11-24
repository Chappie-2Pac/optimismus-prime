"""Adversarial tests for the S25AM local plan-shape oracle."""

from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPORT_PATH = REPO_ROOT / "tests" / "support" / "w5_s25am_local_plan_shape.py"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25am_local_plan_shape as s25am  # noqa: E402


EXPECTED_FIELDS = (
    "goal",
    "files",
    "steps",
    "tests",
    "risks",
    "open_questions",
)


def complete_plan() -> dict[str, object]:
    return {
        "goal": "build",
        "files": ["src/main.py"],
        "steps": ["implement"],
        "tests": ["unit"],
        "risks": ["regression"],
        "open_questions": ["none"],
    }


class W5S25AMLocalPlanShapeTests(unittest.TestCase):
    def _assert_success(self, result: object) -> None:
        self.assertIs(type(result), dict)
        self.assertEqual(tuple(result), ("valid", "fields"))
        self.assertEqual(
            result,
            {"valid": True, "fields": list(EXPECTED_FIELDS)},
        )
        self.assertIs(type(result["valid"]), bool)
        self.assertIs(type(result["fields"]), list)
        self.assertTrue(all(type(field) is str for field in result["fields"]))

    def test_all_missing_and_falsy_fields_keep_order_and_message(self) -> None:
        falsy_values = (None, False, 0, "", [], {})
        for field in EXPECTED_FIELDS:
            for value in falsy_values:
                with self.subTest(field=field, value=repr(value)):
                    plan = complete_plan()
                    plan[field] = value
                    before = deepcopy(plan)
                    with self.assertRaisesRegex(
                        ValueError,
                        rf"^Plan unvollständig: {field}$",
                    ):
                        s25am.evaluate_local_plan_shape_case(plan)
                    self.assertEqual(plan, before)

        plan = complete_plan()
        plan["goal"] = ""
        plan["files"] = []
        with self.assertRaisesRegex(ValueError, r"^Plan unvollständig: goal, files$"):
            s25am.evaluate_local_plan_shape_case(plan)

    def test_list_gate_checks_all_three_fields_and_keeps_precedence(self) -> None:
        truthy_non_lists = ("not-a-list", {"item": 1}, True, 1)
        for field in ("files", "steps", "tests"):
            for value in truthy_non_lists:
                with self.subTest(field=field, value=repr(value)):
                    plan = complete_plan()
                    plan[field] = value
                    with self.assertRaisesRegex(
                        ValueError,
                        r"^files, steps und tests müssen Listen sein$",
                    ):
                        s25am.evaluate_local_plan_shape_case(plan)

        for missing_field, invalid_field in (
            ("files", "steps"),
            ("steps", "tests"),
            ("tests", "steps"),
        ):
            with self.subTest(missing_field=missing_field, invalid_field=invalid_field):
                plan = complete_plan()
                plan[missing_field] = []
                plan[invalid_field] = "not-a-list"
                with self.assertRaisesRegex(
                    ValueError,
                    rf"^Plan unvollständig: {missing_field}$",
                ):
                    s25am.evaluate_local_plan_shape_case(plan)

    def test_path_rules_are_lexical_and_do_not_require_filesystem(self) -> None:
        for item in ("/absolute/file.py", "../outside.py", "src/../outside.py"):
            with self.subTest(item=item):
                plan = complete_plan()
                plan["files"] = [item]
                with self.assertRaisesRegex(
                    ValueError,
                    r"^Plan enthält einen unzulässigen Dateipfad$",
                ):
                    s25am.evaluate_local_plan_shape_case(plan)

        for item in ("src/main.py", "./src/main.py", "src/nested/file.py"):
            with self.subTest(item=item):
                plan = complete_plan()
                plan["files"] = [item]
                self._assert_success(
                    s25am.evaluate_local_plan_shape_case(plan)
                )

    def test_path_error_and_any_short_circuit_precedence_are_preserved(self) -> None:
        plan = complete_plan()
        plan["files"] = [None, "/absolute/file.py"]
        with self.assertRaises(TypeError):
            s25am.evaluate_local_plan_shape_case(plan)

        plan = complete_plan()
        plan["files"] = ["/absolute/file.py", None]
        with self.assertRaisesRegex(
            ValueError,
            r"^Plan enthält einen unzulässigen Dateipfad$",
        ):
            s25am.evaluate_local_plan_shape_case(plan)

        plan = complete_plan()
        plan["files"] = ["relative/file.py", None]
        with self.assertRaises(TypeError):
            s25am.evaluate_local_plan_shape_case(plan)

    def test_extra_keys_orders_and_input_are_unchanged(self) -> None:
        plan = {
            "open_questions": ["none"],
            "future": {"flag": True},
            "tests": ["unit"],
            "risks": ["regression"],
            "steps": ["implement"],
            "files": ["src/main.py"],
            "goal": "build",
        }
        before = deepcopy(plan)
        before_keys = tuple(plan)
        before_ids = {key: id(value) for key, value in plan.items()}
        result = s25am.evaluate_local_plan_shape_case(plan)
        self._assert_success(result)
        self.assertEqual(plan, before)
        self.assertEqual(tuple(plan), before_keys)
        self.assertEqual(
            {key: id(value) for key, value in plan.items()},
            before_ids,
        )
        self.assertNotIn("future", result)

    def test_repeat_and_output_mutation_do_not_create_state(self) -> None:
        first = s25am.evaluate_local_plan_shape_case(complete_plan())
        first["fields"].append("tampered")
        second = s25am.evaluate_local_plan_shape_case(complete_plan())
        self._assert_success(second)

    def test_support_has_only_stdlib_pathlib_import_and_no_production_import(self) -> None:
        source = SUPPORT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        self.assertEqual(imports, ["__future__", "pathlib"])
        for forbidden in (
            "ki-workflow",
            "validate_plan",
            "prime_plans",
            "subprocess",
            "socket",
            "os.system",
            "open(",
            "read_text",
            "write_text",
        ):
            self.assertNotIn(forbidden, source)
        allowed_names = {"Path", "isinstance", "ValueError", "any", "list"}
        allowed_attributes = {"get", "is_absolute", "join"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertIn(node.func.id, allowed_names)
            else:
                self.assertIsInstance(node.func, ast.Attribute)
                self.assertIn(node.func.attr, allowed_attributes)


if __name__ == "__main__":
    unittest.main()
