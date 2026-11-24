"""Adversarial tests for the pure S25AL memory-layer relation."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import sys
import subprocess
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPORT_PATH = REPO_ROOT / "tests" / "support" / "w5_s25al_memory_layer_first_match.py"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25al_memory_layer_first_match as s25al  # noqa: E402


EXPECTED_KEYS = (
    "schema_version",
    "classification",
    "status",
    "decision",
    "reason",
    "selected_layer",
    "production_status",
    "authority_claim",
)

EXPECTED_MATRIX = {
    (False, False, False): "none",
    (False, False, True): "ltm",
    (False, True, False): "mtm",
    (False, True, True): "mtm",
    (True, False, False): "stm",
    (True, False, True): "stm",
    (True, True, False): "stm",
    (True, True, True): "stm",
}


class ExplosiveDict(dict):
    def __len__(self):
        raise AssertionError("dict subclass method must not run")

    def __iter__(self):
        raise AssertionError("dict subclass method must not run")

    def __getitem__(self, key):
        raise AssertionError("dict subclass method must not run")


class ExplosiveKey:
    armed = False

    def __hash__(self):
        if type(self).armed:
            raise AssertionError("custom key hash must not run")
        return hash("stm_present")

    def __eq__(self, other):
        if type(self).armed:
            raise AssertionError("custom key equality must not run")
        return False


class ExplosiveString(str):
    armed = False

    def __hash__(self):
        if type(self).armed:
            raise AssertionError("str-subclass hash must not run")
        return super().__hash__()

    def __eq__(self, other):
        if type(self).armed:
            raise AssertionError("str-subclass equality must not run")
        return super().__eq__(other)


class ExplosiveValue:
    def __bool__(self):
        raise AssertionError("invalid value must not be coerced to bool")


class W5S25ALMemoryLayerFirstMatchTests(unittest.TestCase):
    def _assert_output_shape(self, result: object) -> None:
        self.assertIs(type(result), dict)
        self.assertEqual(tuple(result), EXPECTED_KEYS)
        self.assertEqual(len(result), 8)
        for key, value in result.items():
            self.assertIs(type(key), str)
            self.assertIs(type(value), str)

    def _assert_invalid_result(self, result: object) -> None:
        self._assert_output_shape(result)
        self.assertEqual(
            result,
            {
                "schema_version": "s25al.memory-layer-first-match.v1",
                "classification": "INPUT_INVALID",
                "status": "TEST_BLOCKED",
                "decision": "HOLD",
                "reason": "input_invalid",
                "selected_layer": "",
                "production_status": "PRODUCTION_NOT_AUTHORIZED",
                "authority_claim": "NOT_CLAIMED",
            },
        )

    def _assert_valid_result(self, result: object, selected_layer: str) -> None:
        self._assert_output_shape(result)
        self.assertEqual(
            result,
            {
                "schema_version": "s25al.memory-layer-first-match.v1",
                "classification": "MEMORY_LAYER_FIRST_MATCH_CLOSED",
                "status": "PASS",
                "decision": "PROPOSAL_ONLY",
                "reason": "first_match_resolved",
                "selected_layer": selected_layer,
                "production_status": "PRODUCTION_NOT_AUTHORIZED",
                "authority_claim": "NOT_CLAIMED",
            },
        )

    def test_complete_literal_matrix_is_independent_and_deterministic(self) -> None:
        for bits, expected_layer in EXPECTED_MATRIX.items():
            case = {
                "stm_present": bits[0],
                "mtm_present": bits[1],
                "ltm_present": bits[2],
            }
            before = tuple(case.items())
            first = s25al.evaluate_memory_layer_first_match_case(case)
            second = s25al.evaluate_memory_layer_first_match_case(case)
            self._assert_output_shape(first)
            self.assertEqual(first, second)
            self.assertEqual(tuple(case.items()), before)
            self.assertEqual(first["schema_version"], "s25al.memory-layer-first-match.v1")
            self.assertEqual(first["classification"], "MEMORY_LAYER_FIRST_MATCH_CLOSED")
            self.assertEqual(first["selected_layer"], expected_layer)
            self.assertEqual(first["status"], "PASS")
            self.assertEqual(first["decision"], "PROPOSAL_ONLY")
            self.assertEqual(first["reason"], "first_match_resolved")
            self.assertEqual(first["production_status"], "PRODUCTION_NOT_AUTHORIZED")
            self.assertEqual(first["authority_claim"], "NOT_CLAIMED")

    def test_key_order_permutations_do_not_change_result(self) -> None:
        for order in (
            (0, 1, 2),
            (0, 2, 1),
            (1, 0, 2),
            (1, 2, 0),
            (2, 0, 1),
            (2, 1, 0),
        ):
            for bits, expected_layer in EXPECTED_MATRIX.items():
                entries = (
                    ("stm_present", bits[0]),
                    ("mtm_present", bits[1]),
                    ("ltm_present", bits[2]),
                )
                case = dict(entries[index] for index in order)
                with self.subTest(order=order, bits=bits):
                    result = s25al.evaluate_memory_layer_first_match_case(case)
                    self._assert_valid_result(result, expected_layer)

    def test_invalid_container_and_structure_are_blocked(self) -> None:
        cases = (
            None,
            [],
            (),
            {"stm_present": True},
            {"stm_present": True, "mtm_present": False, "ltm_present": False, "extra": False},
            {"stm_present": True, "mtm_present": False, "unknown": False},
            ExplosiveDict(
                stm_present=True,
                mtm_present=False,
                ltm_present=False,
            ),
        )
        for case in cases:
            with self.subTest(case_type=type(case).__name__):
                before = (
                    tuple((id(key), id(value)) for key, value in dict.items(case))
                    if isinstance(case, dict)
                    else None
                )
                result = s25al.evaluate_memory_layer_first_match_case(case)
                self._assert_invalid_result(result)
                if before is not None:
                    after = tuple((id(key), id(value)) for key, value in dict.items(case))
                    self.assertEqual(after, before)

    def test_invalid_values_are_never_coerced(self) -> None:
        for field in ("stm_present", "mtm_present", "ltm_present"):
            for invalid in (None, 0, 1, "true", ExplosiveValue()):
                with self.subTest(field=field, value_type=type(invalid).__name__):
                    case = {
                        "stm_present": False,
                        "mtm_present": False,
                        "ltm_present": False,
                    }
                    case[field] = invalid
                    before = tuple(case.items())
                    result = s25al.evaluate_memory_layer_first_match_case(case)
                    self._assert_invalid_result(result)
                    self.assertEqual(tuple(case.items()), before)

    def test_custom_keys_are_rejected_before_foreign_methods(self) -> None:
        ExplosiveKey.armed = False
        case = {ExplosiveKey(): True, "mtm_present": False, "ltm_present": False}
        before = tuple((id(key), id(value)) for key, value in dict.items(case))
        ExplosiveKey.armed = True
        try:
            result = s25al.evaluate_memory_layer_first_match_case(case)
        finally:
            ExplosiveKey.armed = False
        self._assert_invalid_result(result)
        self.assertEqual(
            tuple((id(key), id(value)) for key, value in dict.items(case)),
            before,
        )

    def test_string_subclass_keys_are_rejected_before_foreign_methods(self) -> None:
        ExplosiveString.armed = False
        case = {
            ExplosiveString("stm_present"): True,
            "mtm_present": False,
            "ltm_present": False,
        }
        before = tuple((id(key), id(value)) for key, value in dict.items(case))
        ExplosiveString.armed = True
        try:
            result = s25al.evaluate_memory_layer_first_match_case(case)
        finally:
            ExplosiveString.armed = False
        self._assert_invalid_result(result)
        self.assertEqual(
            tuple((id(key), id(value)) for key, value in dict.items(case)),
            before,
        )

    def test_output_mutation_does_not_create_cross_call_state(self) -> None:
        first = s25al.evaluate_memory_layer_first_match_case(
            {"stm_present": True, "mtm_present": False, "ltm_present": False}
        )
        first["selected_layer"] = "tampered"
        second = s25al.evaluate_memory_layer_first_match_case(
            {"stm_present": True, "mtm_present": False, "ltm_present": False}
        )
        self.assertEqual(second["selected_layer"], "stm")

    def test_large_dict_is_rejected_before_iteration(self) -> None:
        case = {f"extra_{index}": False for index in range(10_000)}
        case.update(
            {
                "stm_present": True,
                "mtm_present": False,
                "ltm_present": False,
            }
        )
        before = tuple(case.items())
        result = s25al.evaluate_memory_layer_first_match_case(case)
        self._assert_invalid_result(result)
        self.assertEqual(tuple(case.items()), before)

    def test_interleaved_calls_have_no_cross_call_state(self) -> None:
        first = s25al.evaluate_memory_layer_first_match_case(
            {"stm_present": False, "mtm_present": True, "ltm_present": True}
        )
        invalid = s25al.evaluate_memory_layer_first_match_case(
            {"stm_present": True, "mtm_present": False}
        )
        third = s25al.evaluate_memory_layer_first_match_case(
            {"stm_present": False, "mtm_present": False, "ltm_present": True}
        )
        self._assert_valid_result(first, "mtm")
        self._assert_invalid_result(invalid)
        self._assert_valid_result(third, "ltm")

    def test_support_source_has_no_external_or_effectful_import_surface(self) -> None:
        source = SUPPORT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        self.assertEqual(imports, ["__future__"])
        forbidden = (
            "chappie_git",
            "MemoryManager",
            "MemoryRecord",
            "read_record",
            "subprocess",
            "socket",
            "pathlib",
            "random",
            "time",
            "os.environ",
        )
        for token in forbidden:
            self.assertNotIn(token, source)

        allowed_call_names = {"type", "len", "_result"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            self.assertIsInstance(node.func, ast.Name)
            self.assertIn(node.func.id, allowed_call_names)

    def test_fresh_import_does_not_load_project_or_third_party_modules(self) -> None:
        probe = (
            "import sys\n"
            "before = set(sys.modules)\n"
            "import support.w5_s25al_memory_layer_first_match\n"
            "after = set(sys.modules)\n"
            "print('\\n'.join(sorted(after - before)))\n"
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPO_ROOT / "tests")
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            cwd=REPO_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        )
        loaded = set(filter(None, completed.stdout.splitlines()))
        self.assertTrue(
            loaded <= {
                "__future__",
                "support",
                "support.w5_s25al_memory_layer_first_match",
            },
            loaded,
        )


if __name__ == "__main__":
    unittest.main()
