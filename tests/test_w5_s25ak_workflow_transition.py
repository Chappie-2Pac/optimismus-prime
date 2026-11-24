"""Adversarial tests for the independent S25AK lifecycle matrix."""

from __future__ import annotations

import builtins
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ak_workflow_transition as s25ak  # noqa: E402


EXPECTED_KEYS = {
    "schema_version",
    "classification",
    "status",
    "decision",
    "reason",
    "next_state",
    "production_status",
    "authority_claim",
}
EXPECTED_KEY_ORDER = (
    "schema_version",
    "classification",
    "status",
    "decision",
    "reason",
    "next_state",
    "production_status",
    "authority_claim",
)
MAX_STRING_BYTES = 64

EXPECTED_MATRIX = {
    "created": {
        "start": ("VALID_TRANSITION", "running"),
        "pause": ("INVALID_TRANSITION", ""),
        "resume": ("INVALID_TRANSITION", ""),
        "cancel": ("VALID_TRANSITION", "cancelled"),
        "fail": ("VALID_TRANSITION", "failed"),
        "complete": ("INVALID_TRANSITION", ""),
    },
    "running": {
        "start": ("INVALID_TRANSITION", ""),
        "pause": ("VALID_TRANSITION", "paused"),
        "resume": ("INVALID_TRANSITION", ""),
        "cancel": ("VALID_TRANSITION", "cancelled"),
        "fail": ("VALID_TRANSITION", "failed"),
        "complete": ("VALID_TRANSITION", "completed"),
    },
    "paused": {
        "start": ("INVALID_TRANSITION", ""),
        "pause": ("INVALID_TRANSITION", ""),
        "resume": ("VALID_TRANSITION", "running"),
        "cancel": ("VALID_TRANSITION", "cancelled"),
        "fail": ("VALID_TRANSITION", "failed"),
        "complete": ("INVALID_TRANSITION", ""),
    },
    "completed": {
        "start": ("INVALID_TRANSITION", ""),
        "pause": ("INVALID_TRANSITION", ""),
        "resume": ("INVALID_TRANSITION", ""),
        "cancel": ("IDEMPOTENT_NOOP", "completed"),
        "fail": ("VALID_TRANSITION", "failed"),
        "complete": ("INVALID_TRANSITION", ""),
    },
    "failed": {
        "start": ("INVALID_TRANSITION", ""),
        "pause": ("INVALID_TRANSITION", ""),
        "resume": ("INVALID_TRANSITION", ""),
        "cancel": ("VALID_TRANSITION", "cancelled"),
        "fail": ("VALID_TRANSITION", "failed"),
        "complete": ("INVALID_TRANSITION", ""),
    },
    "cancelled": {
        "start": ("INVALID_TRANSITION", ""),
        "pause": ("INVALID_TRANSITION", ""),
        "resume": ("INVALID_TRANSITION", ""),
        "cancel": ("IDEMPOTENT_NOOP", "cancelled"),
        "fail": ("VALID_TRANSITION", "failed"),
        "complete": ("INVALID_TRANSITION", ""),
    },
}


class _TrackingString(str):
    calls = 0

    def __iter__(self):
        type(self).calls += 1
        return super().__iter__()

    def encode(self, *args, **kwargs):
        type(self).calls += 1
        return super().encode(*args, **kwargs)


class _ExplosiveObject:
    calls = 0

    def __str__(self):
        type(self).calls += 1
        raise AssertionError("__str__ executed")

    def __eq__(self, other):
        type(self).calls += 1
        raise AssertionError("__eq__ executed")

    def __iter__(self):
        type(self).calls += 1
        raise AssertionError("__iter__ executed")


class W5S25AKWorkflowTransitionTests(unittest.TestCase):
    @staticmethod
    def _evaluate(state: object, operation: object) -> dict[str, str]:
        return s25ak.evaluate_workflow_transition_case(state, operation)

    def assert_shape(self, result: dict[str, str]) -> None:
        self.assertEqual(set(result), EXPECTED_KEYS)
        self.assertEqual(tuple(result), EXPECTED_KEY_ORDER)
        self.assertEqual(result["schema_version"], "s25ak.workflow-transition.v1")
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")
        for value in result.values():
            self.assertIs(type(value), str)

    def test_complete_literal_matrix_and_next_states(self) -> None:
        self.assertEqual(len(EXPECTED_MATRIX), 6)
        self.assertTrue(all(len(operations) == 6 for operations in EXPECTED_MATRIX.values()))
        for state, operations in EXPECTED_MATRIX.items():
            for operation, (classification, next_state) in operations.items():
                with self.subTest(state=state, operation=operation):
                    result = self._evaluate(state, operation)
                    self.assert_shape(result)
                    self.assertEqual(result["classification"], classification)
                    self.assertEqual(result["next_state"], next_state)
                    if classification in {"VALID_TRANSITION", "IDEMPOTENT_NOOP"}:
                        self.assertEqual(result["status"], "PASS")
                        self.assertEqual(result["decision"], "PROPOSAL_ONLY")
                    else:
                        self.assertEqual(result["status"], "TEST_BLOCKED")
                        self.assertEqual(result["decision"], "HOLD")
                    self.assertEqual(result["reason"], classification.lower())

    def test_unknown_strings_are_semantic_until_the_byte_boundary(self) -> None:
        ascii_exact = "x" * MAX_STRING_BYTES
        unicode_exact = "é" * 32
        three_byte_exact = ("€" * 21) + "x"
        four_byte_exact = "🙂" * 16
        self.assertEqual(len(ascii_exact.encode("utf-8")), MAX_STRING_BYTES)
        self.assertEqual(len(unicode_exact.encode("utf-8")), MAX_STRING_BYTES)
        self.assertEqual(len(three_byte_exact.encode("utf-8")), MAX_STRING_BYTES)
        self.assertEqual(len(four_byte_exact.encode("utf-8")), MAX_STRING_BYTES)
        for position in ("state", "operation"):
            for unknown in (ascii_exact, unicode_exact, three_byte_exact, four_byte_exact):
                with self.subTest(position=position, unknown=unknown[:5]):
                    state, operation = (unknown, "start") if position == "state" else ("created", unknown)
                    result = self._evaluate(state, operation)
                    self.assert_shape(result)
                    self.assertEqual(result["classification"], "INVALID_TRANSITION")
                    self.assertEqual(result["next_state"], "")

        for position in ("state", "operation"):
            for oversized in (ascii_exact + "x", unicode_exact + "x", three_byte_exact + "x", four_byte_exact + "x"):
                with self.subTest(position=position, oversized=oversized[:5]):
                    state, operation = (oversized, "start") if position == "state" else ("created", oversized)
                    result = self._evaluate(state, operation)
                    self.assert_shape(result)
                    self.assertEqual(result["classification"], "INPUT_INVALID")
                    self.assertEqual(result["reason"], "input_invalid")

    def test_surrogates_and_wrong_types_are_input_invalid(self) -> None:
        cases = (
            ("created", "\ud800"),
            ("\udfff", "start"),
            (None, "start"),
            ("created", None),
            (True, "start"),
            ("created", 1),
            ([], "start"),
            ("created", b"start"),
            (object(), object()),
        )
        for state, operation in cases:
            with self.subTest(state=state, operation=operation):
                result = self._evaluate(state, operation)
                self.assert_shape(result)
                self.assertEqual(result["classification"], "INPUT_INVALID")
                self.assertEqual(result["status"], "TEST_BLOCKED")
                self.assertEqual(result["decision"], "HOLD")
                self.assertEqual(result["next_state"], "")

    def test_custom_strings_are_rejected_without_method_execution(self) -> None:
        _TrackingString.calls = 0
        state = _TrackingString("created")
        operation = _TrackingString("start")
        result = self._evaluate(state, operation)
        self.assert_shape(result)
        self.assertEqual(result["classification"], "INPUT_INVALID")
        self.assertEqual(_TrackingString.calls, 0)

        _ExplosiveObject.calls = 0
        explosive = _ExplosiveObject()
        result = self._evaluate(explosive, explosive)
        self.assert_shape(result)
        self.assertEqual(result["classification"], "INPUT_INVALID")
        self.assertEqual(_ExplosiveObject.calls, 0)

    def test_result_mapping_is_deterministic_and_stateless(self) -> None:
        cases = (
            ("created", "start"),
            ("completed", "cancel"),
            ("running", "start"),
            ("created", "unknown"),
            ("created", "x" * (MAX_STRING_BYTES + 1)),
        )
        for state, operation in cases:
            with self.subTest(state=state, operation=operation):
                first = self._evaluate(state, operation)
                second = self._evaluate(state, operation)
                self.assertEqual(first, second)
                self.assert_shape(first)

    def test_no_chappie_import_or_external_effect_surface(self) -> None:
        modules_before = set(sys.modules)
        with patch("builtins.open", side_effect=AssertionError("open called")), patch.object(
            builtins, "__import__", side_effect=AssertionError("import called")
        ):
            result = self._evaluate("running", "pause")
        self.assert_shape(result)
        self.assertEqual(result["classification"], "VALID_TRANSITION")
        self.assertEqual(set(sys.modules), modules_before)

        source = Path(s25ak.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "chappie_git",
            "workflow_base",
            "WorkflowState",
            "importlib",
            "socket",
            "subprocess",
            "open(",
            "encode(",
        ):
            self.assertNotIn(forbidden, source)

    def test_import_time_execution_is_stdlib_only_and_bounded(self) -> None:
        source = Path(s25ak.__file__).read_text(encoding="utf-8")
        imported: list[str] = []
        allowed = {"__future__", "typing"}
        real_import = builtins.__import__

        def guarded_import(name: str, *args: object, **kwargs: object) -> object:
            imported.append(name)
            if name.split(".", 1)[0] not in allowed:
                raise AssertionError(f"unexpected import: {name}")
            return real_import(name, *args, **kwargs)

        namespace = {
            "__name__": "s25ak_import_probe",
            "__file__": str(s25ak.__file__),
        }
        with patch("builtins.open", side_effect=AssertionError("open called at import time")), patch.object(
            builtins, "__import__", side_effect=guarded_import
        ):
            exec(compile(source, str(s25ak.__file__), "exec"), namespace)
        self.assertTrue(set(imported).issubset(allowed))


if __name__ == "__main__":
    unittest.main()
