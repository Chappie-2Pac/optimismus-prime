"""Adversarial tests for the pure W5-S25AG dual-renderer relation."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ag_dual_renderer_projection as s25ag  # noqa: E402
import test_w5_s25ag_fixture_foundation as fixtures  # noqa: E402


EXPECTED_RESULT_KEYS = set(s25ag.RESULT_KEYS)
_UNSET = object()


class _ExplodingDict(dict):
    def __iter__(self):  # pragma: no cover - execution is the failure
        raise AssertionError("custom mapping was executed")


class _ExplodingString(str):
    def __str__(self):  # pragma: no cover - execution is the failure
        raise AssertionError("custom string was executed")


class W5S25AGDualRendererProjectionTests(unittest.TestCase):
    @staticmethod
    def _case(name: str = "ascii") -> tuple[dict[str, str], str]:
        return fixtures.build_positive_s25ag_case(name)

    @staticmethod
    def _evaluate(
        record: dict[str, str],
        golden: str,
        *,
        transformers: str | object = _UNSET,
        unsloth: str | object = _UNSET,
    ) -> dict[str, object]:
        if transformers is _UNSET:
            transformers = golden
        if unsloth is _UNSET:
            unsloth = golden
        return s25ag.evaluate_dual_renderer_case(
            record,
            transformers_projection=transformers,
            unsloth_projection=unsloth,
        )

    def assert_actionless(self, result: dict[str, object]) -> None:
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["decision"], "PROPOSAL_ONLY")
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def assert_blocked(self, result: dict[str, object], classification: str) -> None:
        self.assertEqual(result["classification"], classification)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def test_positive_requires_both_exact_projections_and_is_actionless(self) -> None:
        record, golden = self._case()
        result = self._evaluate(record, golden)
        self.assertEqual(result["classification"], "DUAL_RENDER_CLOSED")
        self.assertTrue(result["transformers_match"])
        self.assertTrue(result["unsloth_match"])
        self.assertTrue(result["projections_equal"])
        self.assert_actionless(result)

    def test_json_bytes_and_json_string_are_strict_but_key_order_invariant(self) -> None:
        record, golden = self._case("unicode_crlf")
        raw = json.dumps(record, ensure_ascii=False, indent=2)
        reordered = json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        first = s25ag.evaluate_dual_renderer_case(
            raw,
            transformers_projection=golden,
            unsloth_projection=golden,
        )
        second = s25ag.evaluate_dual_renderer_case(
            reordered.encode("utf-8"),
            transformers_projection=golden,
            unsloth_projection=golden,
        )
        self.assertEqual(first, second)
        self.assertEqual(first["classification"], "DUAL_RENDER_CLOSED")

    def test_result_keys_are_exact_on_positive_and_all_major_failure_paths(self) -> None:
        record, golden = self._case()
        cases = [
            self._evaluate(record, golden),
            self._evaluate(record, golden, transformers=golden + "x"),
            self._evaluate(record, golden, transformers=golden, unsloth=golden + "x"),
            s25ag.evaluate_dual_renderer_case(b"not-json", transformers_projection=golden, unsloth_projection=golden),
            s25ag.evaluate_dual_renderer_case(record, transformers_projection=None, unsloth_projection=golden),
        ]
        for result in cases:
            self.assertEqual(set(result), EXPECTED_RESULT_KEYS)
            self.assertEqual(result["schema_version"], "s25ag.dual-render.v1")

    def test_case_is_not_mutated_and_evaluation_is_deterministic(self) -> None:
        record, golden = self._case("marker_content")
        before = deepcopy(record)
        first = self._evaluate(record, golden)
        second = self._evaluate(record, golden)
        self.assertEqual(record, before)
        self.assertEqual(first, second)

    def test_missing_extra_and_duplicate_keys_are_input_invalid(self) -> None:
        record, golden = self._case()
        missing = dict(record)
        del missing["input"]
        extra = dict(record)
        extra["unexpected"] = "x"
        duplicate = (
            '{"format":"s25ag.dual-render.v1",'
            '"instruction":"Explain the concept.","input":"A useful source concept.",'
            '"input":"forged","output":""}'
        )
        for case in (missing, extra, duplicate):
            with self.subTest(case=case):
                self.assert_blocked(
                    s25ag.evaluate_dual_renderer_case(
                        case,
                        transformers_projection=golden,
                        unsloth_projection=golden,
                    )
                    if isinstance(case, dict)
                    else s25ag.evaluate_dual_renderer_case(
                        case,
                        transformers_projection=golden,
                        unsloth_projection=golden,
                    ),
                    "INPUT_INVALID",
                )

    def test_record_types_format_output_and_boundary_whitespace_are_fail_closed(self) -> None:
        _, golden = self._case()
        mutations = []
        for key, value in (("format", 3), ("instruction", ["x"]), ("input", None), ("output", False)):
            case, _ = self._case()
            case[key] = value  # type: ignore[assignment]
            mutations.append(case)
        for key, value in (
            ("format", "wrong"),
            ("instruction", ""),
            ("instruction", " leading"),
            ("instruction", "trailing "),
            ("instruction", "\n"),
            ("input", " leading"),
            ("input", "trailing\n"),
            ("output", " answer"),
            ("output", "answer\n"),
        ):
            case, _ = self._case()
            case[key] = value
            mutations.append(case)
        for case in mutations:
            with self.subTest(case=case):
                self.assert_blocked(self._evaluate(case, golden), "INPUT_INVALID")

    def test_strict_utf8_bom_surrogate_and_json_constant_are_rejected(self) -> None:
        record, golden = self._case()
        valid_json = json.dumps(record, ensure_ascii=False).encode("utf-8")
        malformed = [
            b"\xff",
            b"\xef\xbb\xbf" + valid_json,
            json.dumps({**record, "instruction": "\ud800"}).encode("utf-8"),
            b'{"format":"s25ag.dual-render.v1","instruction":NaN,"input":"","output":""}',
        ]
        for case in malformed:
            with self.subTest(case=case):
                self.assert_blocked(
                    s25ag.evaluate_dual_renderer_case(
                        case,
                        transformers_projection=golden,
                        unsloth_projection=golden,
                    ),
                    "INPUT_INVALID",
                )

    def test_input_and_projection_budgets_are_separate_and_fail_closed(self) -> None:
        record, golden = self._case()
        oversized_json = b"{" + b"x" * s25ag.MAX_INPUT_BYTES + b"}"
        oversized_field = dict(record)
        oversized_field["instruction"] = "x" * (s25ag.MAX_RECORD_STRING_BYTES + 1)
        self.assert_blocked(
            s25ag.evaluate_dual_renderer_case(
                oversized_json,
                transformers_projection=golden,
                unsloth_projection=golden,
            ),
            "BUDGET_EXCEEDED",
        )
        self.assert_blocked(self._evaluate(oversized_field, golden), "BUDGET_EXCEEDED")
        oversized_projection = "x" * (s25ag.MAX_PROJECTION_BYTES + 1)
        self.assert_blocked(
            self._evaluate(record, golden, transformers=oversized_projection),
            "BUDGET_EXCEEDED",
        )

    def test_projection_error_priority_is_argument_order_independent(self) -> None:
        record, golden = self._case()
        oversized_projection = "x" * (s25ag.MAX_PROJECTION_BYTES + 1)
        for transformers, unsloth in (
            (None, oversized_projection),
            (oversized_projection, None),
        ):
            with self.subTest(first=type(transformers).__name__, second=type(unsloth).__name__):
                self.assert_blocked(
                    self._evaluate(record, golden, transformers=transformers, unsloth=unsloth),
                    "BUDGET_EXCEEDED",
                )

    def test_invalid_empty_or_surrogate_renderer_outputs_do_not_become_drift(self) -> None:
        record, golden = self._case()
        for projection in (None, "", "\ud800"):
            with self.subTest(projection=repr(projection)):
                self.assert_blocked(
                    self._evaluate(record, golden, transformers=projection),
                    "RENDERER_OUTPUT_INVALID",
                )

    def test_backend_divergence_is_not_hidden_by_one_correct_projection(self) -> None:
        record, golden = self._case()
        result = self._evaluate(record, golden, unsloth=golden + " forged")
        self.assert_blocked(result, "BACKEND_DIVERGENCE")
        self.assertTrue(result["transformers_match"])
        self.assertFalse(result["unsloth_match"])
        self.assertFalse(result["projections_equal"])

    def test_common_truncation_or_field_loss_is_not_positive(self) -> None:
        record, golden = self._case()
        truncated = golden[: golden.index("A useful")]
        result = self._evaluate(record, golden, transformers=truncated, unsloth=truncated)
        self.assert_blocked(result, "FIELD_LOSS")
        self.assertTrue(result["projections_equal"])

    def test_output_loss_change_and_whitespace_unicode_drift_are_field_aware(self) -> None:
        record, golden = self._case("with_output")
        output_start = golden.index("An exact answer.")
        output_prefix = golden[:output_start]
        missing = output_prefix
        changed = output_prefix + "A different answer."
        whitespace = output_prefix + "An\texact answer."
        for drifted, classification in (
            (missing, "FIELD_LOSS"),
            (changed, "FIELD_DRIFT"),
            (whitespace, "WHITESPACE_DRIFT"),
        ):
            with self.subTest(classification=classification):
                self.assert_blocked(
                    self._evaluate(record, golden, transformers=drifted, unsloth=drifted),
                    classification,
                )

        unicode_record = {
            "format": "s25ag.dual-render.v1",
            "instruction": "Keep this.",
            "input": "Question.",
            "output": "é",
        }
        unicode_golden = "<s>[INST]\nKeep this.\n\nQuestion.\n[/INST]é"
        unicode_drift = "<s>[INST]\nKeep this.\n\nQuestion.\n[/INST]e\u0301"
        self.assert_blocked(
            self._evaluate(unicode_record, unicode_golden, transformers=unicode_drift, unsloth=unicode_drift),
            "UNICODE_DRIFT",
        )

    def test_equal_instruction_and_input_values_do_not_hide_input_loss(self) -> None:
        record = {
            "format": "s25ag.dual-render.v1",
            "instruction": "same",
            "input": "same",
            "output": "",
        }
        golden = "<s>[INST]\nsame\n\nsame\n[/INST]"
        input_removed = "<s>[INST]\nsame\n[/INST]"
        self.assert_blocked(
            self._evaluate(record, golden, transformers=input_removed, unsloth=input_removed),
            "FIELD_LOSS",
        )

    def test_common_whitespace_drift_is_detected_exactly(self) -> None:
        record, golden = self._case()
        drifted = golden.replace("\n[/INST]", "\r\n[/INST]", 1)
        self.assert_blocked(
            self._evaluate(record, golden, transformers=drifted, unsloth=drifted),
            "WHITESPACE_DRIFT",
        )

    def test_common_unicode_drift_is_detected_without_normalizing_the_contract(self) -> None:
        record = {
            "format": "s25ag.dual-render.v1",
            "instruction": "é",
            "input": "é",
            "output": "",
        }
        golden = "<s>[INST]\né\n\né\n[/INST]"
        drifted = "<s>[INST]\ne\u0301\n\né\n[/INST]"
        result = self._evaluate(record, golden, transformers=drifted, unsloth=drifted)
        self.assert_blocked(result, "UNICODE_DRIFT")

    def test_common_field_reorder_and_wrapper_mutations_are_template_drift(self) -> None:
        record, golden = self._case()
        swapped = "<s>[INST]\nA useful source concept.\n\nExplain the concept.\n[/INST]"
        wrapped = "<s>" + golden
        for drifted in (swapped, wrapped):
            with self.subTest(drifted=drifted):
                self.assert_blocked(
                    self._evaluate(record, golden, transformers=drifted, unsloth=drifted),
                    "TEMPLATE_DRIFT",
                )

    def test_common_unclassified_drift_remains_shared_render_drift(self) -> None:
        record, golden = self._case()
        drifted = "both backends agree on an unrelated projection"
        self.assert_blocked(
            self._evaluate(record, golden, transformers=drifted, unsloth=drifted),
            "SHARED_RENDER_DRIFT",
        )

    def test_nested_values_arrays_and_custom_mappings_are_never_executed(self) -> None:
        record, golden = self._case()
        nested = dict(record)
        nested["input"] = {"nested": "value"}  # type: ignore[assignment]
        array = dict(record)
        array["input"] = ["value"]  # type: ignore[assignment]
        for case in (nested, array, _ExplodingDict(record)):
            with self.subTest(case=type(case).__name__):
                self.assert_blocked(self._evaluate(case, golden), "INPUT_INVALID")

    def test_custom_string_subclasses_are_not_accepted_or_executed(self) -> None:
        record, golden = self._case()
        custom_record = dict(record)
        custom_record["instruction"] = _ExplodingString(record["instruction"])
        result = self._evaluate(custom_record, golden)
        self.assert_blocked(result, "INPUT_INVALID")
        result = self._evaluate(record, golden, transformers=_ExplodingString(golden))
        self.assert_blocked(result, "RENDERER_OUTPUT_INVALID")

    def test_boundary_is_actionless_under_patched_file_network_and_process_calls(self) -> None:
        record, golden = self._case()
        with patch("builtins.open", side_effect=AssertionError("open called")), patch(
            "socket.socket", side_effect=AssertionError("socket called")
        ), patch("subprocess.Popen", side_effect=AssertionError("process called")):
            result = self._evaluate(record, golden)
        self.assertEqual(result["classification"], "DUAL_RENDER_CLOSED")

    def test_unknown_json_constant_and_recursive_parser_failure_never_escape(self) -> None:
        record, golden = self._case()
        recursive_like = "[" * 10000 + "0" + "]" * 10000
        for raw in (
            b'{"format":"s25ag.dual-render.v1","instruction":Infinity,"input":"","output":""}',
            recursive_like,
        ):
            with self.subTest(raw_type=type(raw).__name__):
                result = s25ag.evaluate_dual_renderer_case(
                    raw,
                    transformers_projection=golden,
                    unsloth_projection=golden,
                )
                self.assertIn(result["classification"], {"INPUT_INVALID", "BUDGET_EXCEEDED"})


if __name__ == "__main__":
    unittest.main()

