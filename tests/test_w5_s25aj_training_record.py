"""Adversarial tests for the pure W5-S25AJ training-record relation."""

from __future__ import annotations

from copy import deepcopy
import builtins
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25aj_training_record as s25aj  # noqa: E402
import test_w5_s25aj_fixture_foundation as fixtures  # noqa: E402


EXPECTED_RESULT_KEYS = {
    "schema_version",
    "classification",
    "status",
    "decision",
    "reason",
    "production_status",
    "authority_claim",
}
EXPECTED_RESULT_KEY_ORDER = (
    "schema_version",
    "classification",
    "status",
    "decision",
    "reason",
    "production_status",
    "authority_claim",
)
EXPECTED_REASONS = {
    "BUDGET_EXCEEDED": "budget_exceeded",
    "INPUT_INVALID": "input_invalid",
    "TRAINING_MODE_INVALID": "training_mode_invalid",
    "OUTPUT_INVALID": "output_invalid",
    "INSTRUCTION_INVALID": "instruction_invalid",
    "INPUT_TEXT_INVALID": "input_text_invalid",
}
TEST_MAX_INPUT_BYTES = 64 * 1024
TEST_MAX_JSON_DEPTH = 8
TEST_MAX_CONTAINER_ITEMS = 256
TEST_MAX_CONTAINERS = 1024
TEST_MAX_NODES = 4096
TEST_MAX_STRING_BYTES = 16 * 1024
TEST_MAX_TOTAL_STRING_BYTES = 64 * 1024


def _count_string_bytes(value: object) -> int:
    if type(value) is dict:
        return sum(_count_string_bytes(key) + _count_string_bytes(item) for key, item in value.items())
    if type(value) is list:
        return sum(_count_string_bytes(item) for item in value)
    if type(value) is str:
        return len(value.encode("utf-8"))
    return 0


def _base_case() -> dict[str, object]:
    return fixtures.build_positive_s25aj_case("ascii")


def _case_with_exact_string_budget(total: int) -> dict[str, object]:
    case = _base_case()
    for index in range(4):
        case[f"extra_{index}"] = ""
    fixed = _count_string_bytes(case)
    remaining = total - fixed
    for index in range(4):
        length = min(TEST_MAX_STRING_BYTES, remaining)
        case[f"extra_{index}"] = "x" * length
        remaining -= length
    if remaining != 0 or _count_string_bytes(case) != total:
        raise AssertionError("cannot construct exact string boundary")
    return case


class _TrackingDict(dict):
    calls = 0

    def __iter__(self):
        type(self).calls += 1
        return super().__iter__()

    def items(self):
        type(self).calls += 1
        return super().items()


class _TrackingList(list):
    calls = 0

    def __iter__(self):
        type(self).calls += 1
        return super().__iter__()


class _TrackingString(str):
    calls = 0

    def __str__(self):
        type(self).calls += 1
        return super().__str__()

    def encode(self, *args, **kwargs):
        type(self).calls += 1
        return super().encode(*args, **kwargs)


class _TrackingBytes(bytes):
    calls = 0

    def __len__(self):
        type(self).calls += 1
        return super().__len__()


class W5S25AJTrainingRecordTests(unittest.TestCase):
    @staticmethod
    def _evaluate(record: object) -> dict[str, str]:
        return s25aj.evaluate_training_record_case(record)  # type: ignore[arg-type]

    def assert_result_shape(self, result: dict[str, str]) -> None:
        self.assertEqual(set(result), EXPECTED_RESULT_KEYS)
        self.assertEqual(tuple(result), EXPECTED_RESULT_KEY_ORDER)
        self.assertEqual(result["schema_version"], "s25aj.training-record.v1")
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")
        for value in result.values():
            self.assertIs(type(value), str)

    def assert_positive(self, result: dict[str, str]) -> None:
        self.assert_result_shape(result)
        self.assertEqual(result["classification"], "TRAINING_RECORD_CLOSED")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["decision"], "PROPOSAL_ONLY")
        self.assertEqual(result["reason"], "training_record_closed")

    def assert_blocked(self, result: dict[str, str], classification: str) -> None:
        self.assert_result_shape(result)
        self.assertEqual(result["classification"], classification)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], EXPECTED_REASONS[classification])

    def test_result_shape_json_forms_and_determinism(self) -> None:
        case = _base_case()
        raw = json.dumps(case, ensure_ascii=False, indent=2)
        reordered = json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        first = self._evaluate(case)
        self.assert_positive(first)
        self.assertEqual(first, self._evaluate(raw))
        self.assertEqual(first, self._evaluate(reordered.encode("utf-8")))
        self.assertEqual(first, self._evaluate(case))

    def test_semantic_error_priority_is_exact_and_disjoint(self) -> None:
        wrong_mode = _base_case()
        wrong_mode["training_mode"] = "chat"
        self.assert_blocked(self._evaluate(wrong_mode), "TRAINING_MODE_INVALID")

        nonempty_output = _base_case()
        nonempty_output["output"] = "answer"
        self.assert_blocked(self._evaluate(nonempty_output), "OUTPUT_INVALID")

        whitespace_output = _base_case()
        whitespace_output["output"] = " \t\n"
        self.assert_blocked(self._evaluate(whitespace_output), "OUTPUT_INVALID")

        empty_instruction = _base_case()
        empty_instruction["instruction"] = " \t\n"
        self.assert_blocked(self._evaluate(empty_instruction), "INSTRUCTION_INVALID")

        empty_input = _base_case()
        empty_input["input"] = "\r\n\u2003"
        self.assert_blocked(self._evaluate(empty_input), "INPUT_TEXT_INVALID")

    def test_missing_and_wrong_required_fields_are_outer_input_errors(self) -> None:
        case = _base_case()
        for missing in ("training_mode", "instruction", "input", "output"):
            mutation = deepcopy(case)
            del mutation[missing]
            with self.subTest(missing=missing):
                self.assert_blocked(self._evaluate(mutation), "INPUT_INVALID")

        for key, value in (
            ("training_mode", False),
            ("instruction", 1),
            ("input", None),
            ("output", []),
        ):
            mutation = deepcopy(case)
            mutation[key] = value
            with self.subTest(key=key):
                self.assert_blocked(self._evaluate(mutation), "INPUT_INVALID")

        self.assert_blocked(self._evaluate([]), "INPUT_INVALID")
        non_string_key = _base_case()
        non_string_key[1] = 0
        self.assert_blocked(self._evaluate(non_string_key), "INPUT_INVALID")

    def test_valid_extra_metadata_is_allowed_and_ignored(self) -> None:
        case = _base_case()
        case.update({"id": "unit-1", "source_path": "opaque.md", "quality_status": "changed"})
        changed = deepcopy(case)
        changed["id"] = "unit-2"
        changed["source_path"] = "other.md"
        changed["quality_status"] = {"reviewed": False}
        self.assert_positive(self._evaluate(case))
        self.assertEqual(self._evaluate(case), self._evaluate(changed))

    def test_strict_json_rejects_duplicate_bom_utf8_surrogate_and_nonfinite_float(self) -> None:
        valid = json.dumps(_base_case(), ensure_ascii=False).encode("utf-8")
        malformed = [
            b'{"training_mode":"self_supervised_continuation","training_mode":"x",'
            b'"instruction":"i","input":"x","output":""}',
            b"\xef\xbb\xbf" + valid,
            b"\xff",
            b'{"training_mode":"self_supervised_continuation","instruction":"\\ud800",'
            b'"input":"x","output":""}',
            b'{"training_mode":"self_supervised_continuation","instruction":"i",'
            b'"input":"x","output":"","meta":NaN}',
            b'{"training_mode":"self_supervised_continuation","instruction":"i",'
            b'"input":"x","output":"","meta":Infinity}',
        ]
        for raw in malformed:
            with self.subTest(raw=raw[:35]):
                self.assert_blocked(self._evaluate(raw), "INPUT_INVALID")

        duplicate_with_oversized_value = (
            b'{"training_mode":"self_supervised_continuation","instruction":"i",'
            b'"input":"x","output":"","meta":"short","meta":"'
            + (b"x" * (TEST_MAX_STRING_BYTES + 1))
            + b'"}'
        )
        self.assert_blocked(self._evaluate(duplicate_with_oversized_value), "INPUT_INVALID")

    def test_exact_raw_string_depth_and_utf8_boundaries(self) -> None:
        base = json.dumps(_base_case(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        exact_raw = base + (b" " * (TEST_MAX_INPUT_BYTES - len(base)))
        self.assertEqual(len(exact_raw), TEST_MAX_INPUT_BYTES)
        self.assert_positive(self._evaluate(exact_raw))
        self.assert_blocked(self._evaluate(exact_raw + b" "), "BUDGET_EXCEEDED")

        exact_text = base.decode("utf-8") + (" " * (TEST_MAX_INPUT_BYTES - len(base)))
        self.assertEqual(len(exact_text.encode("utf-8")), TEST_MAX_INPUT_BYTES)
        self.assert_positive(self._evaluate(exact_text))
        self.assert_blocked(self._evaluate(exact_text + " "), "BUDGET_EXCEEDED")

        unicode_base = json.dumps(
            fixtures.build_positive_s25aj_case("unicode_whitespace"),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        unicode_size = len(unicode_base.encode("utf-8"))
        unicode_text = unicode_base + (" " * (TEST_MAX_INPUT_BYTES - unicode_size))
        self.assertEqual(len(unicode_text.encode("utf-8")), TEST_MAX_INPUT_BYTES)
        self.assert_positive(self._evaluate(unicode_text))
        self.assert_blocked(self._evaluate(unicode_text + " "), "BUDGET_EXCEEDED")

        unicode_exact = _base_case()
        unicode_exact["instruction"] = "é" * 8192
        self.assertEqual(len(unicode_exact["instruction"].encode("utf-8")), TEST_MAX_STRING_BYTES)
        self.assert_positive(self._evaluate(unicode_exact))
        unicode_over = deepcopy(unicode_exact)
        unicode_over["instruction"] += "x"
        self.assert_blocked(self._evaluate(unicode_over), "BUDGET_EXCEEDED")

        depth_eight = _base_case()
        nested: object = []
        for _ in range(6):
            nested = [nested]
        depth_eight["padding"] = nested
        self.assert_positive(self._evaluate(depth_eight))
        depth_nine = deepcopy(depth_eight)
        depth_nine["padding"] = [nested]
        self.assert_blocked(self._evaluate(depth_nine), "BUDGET_EXCEEDED")

    def test_independent_multibyte_total_and_individual_string_boundaries(self) -> None:
        case = fixtures.build_positive_s25aj_case("unicode_whitespace")
        extra_keys = ("meta_a", "meta_b", "meta_c", "meta_d")
        fixed = (
            len("training_mode".encode("utf-8"))
            + len("self_supervised_continuation".encode("utf-8"))
            + len("instruction".encode("utf-8"))
            + len("  Prüfe Unicode é und Marker🙂  ".encode("utf-8"))
            + len("input".encode("utf-8"))
            + len("\r\nEin gebundener Kontext.\u2003".encode("utf-8"))
            + len("output".encode("utf-8"))
            + sum(len(key.encode("utf-8")) for key in extra_keys)
        )
        self.assertEqual(fixed, 151)
        extras = (
            "x" + ("é" * 8191),
            "é" * 8192,
            "é" * 8192,
            "é" * 8117,
        )
        case.update(dict(zip(extra_keys, extras)))
        expected_total = fixed + sum(len(value.encode("utf-8")) for value in extras)
        self.assertEqual(expected_total, TEST_MAX_TOTAL_STRING_BYTES)
        self.assert_positive(self._evaluate(case))

        over = deepcopy(case)
        over["meta_d"] += "x"
        self.assert_blocked(self._evaluate(over), "BUDGET_EXCEEDED")

        individual = _base_case()
        individual["opaque"] = "x" * TEST_MAX_STRING_BYTES
        self.assert_positive(self._evaluate(individual))
        individual["opaque"] += "x"
        self.assert_blocked(self._evaluate(individual), "BUDGET_EXCEEDED")

    def test_exact_total_string_container_and_node_boundaries(self) -> None:
        exact_total = _case_with_exact_string_budget(TEST_MAX_TOTAL_STRING_BYTES)
        self.assertEqual(_count_string_bytes(exact_total), TEST_MAX_TOTAL_STRING_BYTES)
        self.assert_positive(self._evaluate(exact_total))
        over_total = deepcopy(exact_total)
        over_total["extra_3"] += "x"
        self.assert_blocked(self._evaluate(over_total), "BUDGET_EXCEEDED")

        within_container = _base_case()
        within_container["padding"] = [0] * TEST_MAX_CONTAINER_ITEMS
        self.assert_positive(self._evaluate(within_container))
        over_container = deepcopy(within_container)
        over_container["padding"].append(0)
        self.assert_blocked(self._evaluate(over_container), "BUDGET_EXCEEDED")

        within_dict = _base_case()
        within_dict["padding"] = {f"k{index}": 0 for index in range(TEST_MAX_CONTAINER_ITEMS)}
        self.assert_positive(self._evaluate(within_dict))
        over_dict = deepcopy(within_dict)
        over_dict["padding"]["k256"] = 0
        self.assert_blocked(self._evaluate(over_dict), "BUDGET_EXCEEDED")

        exact_nodes = _base_case()
        for index in range(16):
            exact_nodes[f"extra_{index}"] = [0] * (256 if index < 15 else 215)
        self.assert_positive(self._evaluate(exact_nodes))
        over_nodes = deepcopy(exact_nodes)
        over_nodes["extra_15"].append(0)
        self.assert_blocked(self._evaluate(over_nodes), "BUDGET_EXCEEDED")

    def test_budget_precedes_input_invalid_regardless_of_mapping_order(self) -> None:
        for invalid_first in (True, False):
            case = _base_case()
            if invalid_first:
                case["invalid"] = object()
                case["oversized"] = "x" * (TEST_MAX_STRING_BYTES + 1)
            else:
                case["oversized"] = "x" * (TEST_MAX_STRING_BYTES + 1)
                case["invalid"] = object()
            with self.subTest(invalid_first=invalid_first):
                self.assert_blocked(self._evaluate(case), "BUDGET_EXCEEDED")

    def test_exact_container_count_and_opaque_primitive_values(self) -> None:
        children = []
        for index in range(255):
            nested_count = 5 if index == 0 else 3
            children.append([[] for _ in range(nested_count)])
        exact = _base_case()
        exact["padding"] = children
        self.assert_positive(self._evaluate(exact))
        over = deepcopy(exact)
        over["padding"].append([])
        self.assert_blocked(self._evaluate(over), "BUDGET_EXCEEDED")

        primitives = _base_case()
        primitives["metadata"] = {"flag": True, "missing": None, "negative_zero": -0.0, "count": 0}
        self.assert_positive(self._evaluate(primitives))

    def test_cycles_and_alias_containers_are_input_invalid(self) -> None:
        cyclic = _base_case()
        cyclic["metadata"] = []
        cyclic["metadata"].append(cyclic["metadata"])
        self.assert_blocked(self._evaluate(cyclic), "INPUT_INVALID")

        shared = []
        aliased = _base_case()
        aliased["first"] = shared
        aliased["second"] = shared
        self.assert_blocked(self._evaluate(aliased), "INPUT_INVALID")

        shared_dict = {}
        aliased_dict = _base_case()
        aliased_dict["first"] = shared_dict
        aliased_dict["second"] = shared_dict
        self.assert_blocked(self._evaluate(aliased_dict), "INPUT_INVALID")

    def test_case_and_custom_objects_are_not_mutated_or_executed(self) -> None:
        case = _base_case()
        before = deepcopy(case)
        self.assert_positive(self._evaluate(case))
        self.assertEqual(case, before)

        _TrackingDict.calls = 0
        _TrackingList.calls = 0
        _TrackingString.calls = 0
        _TrackingBytes.calls = 0
        custom_dict = _TrackingDict(case)
        custom_list = _TrackingList([1])
        custom_string = _TrackingString(json.dumps(case))
        custom_bytes = _TrackingBytes(json.dumps(case).encode("utf-8"))
        for value in (custom_dict, custom_list, custom_string, custom_bytes):
            with self.subTest(value=type(value).__name__):
                self.assert_blocked(self._evaluate(value), "INPUT_INVALID")
        self.assertEqual(_TrackingDict.calls, 0)
        self.assertEqual(_TrackingList.calls, 0)
        self.assertEqual(_TrackingString.calls, 0)
        self.assertEqual(_TrackingBytes.calls, 0)

        nested_custom = _base_case()
        _TrackingString.calls = 0
        nested_custom["instruction"] = _TrackingString("valid")
        self.assert_blocked(self._evaluate(nested_custom), "INPUT_INVALID")
        self.assertEqual(_TrackingString.calls, 0)

        for custom in (_TrackingList([0]), _TrackingDict({"opaque": 0})):
            with self.subTest(nested_type=type(custom).__name__):
                nested_custom = _base_case()
                nested_custom["metadata"] = custom
                _TrackingList.calls = 0
                _TrackingDict.calls = 0
                self.assert_blocked(self._evaluate(nested_custom), "INPUT_INVALID")
                self.assertEqual(_TrackingList.calls, 0)
                self.assertEqual(_TrackingDict.calls, 0)

    def test_lexical_parser_states_and_json_rejection_paths(self) -> None:
        escaped = _base_case()
        escaped["instruction"] = 'literal {"quoted": "\\\\\\"[]{}"}'
        self.assert_positive(self._evaluate(json.dumps(escaped, ensure_ascii=False)))

        malformed = [
            b'{"training_mode":"self_supervised_continuation","instruction":"\\q",'
            b'"input":"x","output":""}',
            b'{"training_mode":"self_supervised_continuation","instruction":"i",'
            b'"input":"x","output":""}]',
            b'{"training_mode":"self_supervised_continuation","instruction":"i",'
            b'"input":"x","output":""}{}',
            b'{"training_mode":"self_supervised_continuation","instruction":"i",'
            b'"input":"x","output":""',
            b'{"training_mode":"self_supervised_continuation","instruction":"i",'
            b'"input":"x","output":"}',
        ]
        for raw in malformed:
            with self.subTest(raw=raw):
                self.assert_blocked(self._evaluate(raw), "INPUT_INVALID")

    def test_relation_has_no_chappie_formatter_or_external_effect(self) -> None:
        case = _base_case()
        modules_before = set(sys.modules)
        with patch("builtins.open", side_effect=AssertionError("open called")), patch(
            "os.open", side_effect=AssertionError("os.open called")
        ), patch("os.system", side_effect=AssertionError("os.system called")), patch(
            "socket.socket", side_effect=AssertionError("socket called")
        ), patch("socket.create_connection", side_effect=AssertionError("connection called")), patch(
            "subprocess.Popen", side_effect=AssertionError("process called")
        ), patch("subprocess.run", side_effect=AssertionError("run called")), patch(
            "subprocess.call", side_effect=AssertionError("call called")
        ), patch("time.time", side_effect=AssertionError("clock called")), patch(
            "time.monotonic", side_effect=AssertionError("monotonic called")
        ), patch.object(builtins, "__import__", side_effect=AssertionError("import called")):
            result = self._evaluate(case)
        self.assert_positive(result)
        self.assertEqual(set(sys.modules), modules_before)

        source = Path(s25aj.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "validate_training_contract",
            "train_transformers",
            "train_unsloth",
            "importlib",
            "socket",
            "subprocess",
            "open(",
            "encode(",
        ):
            self.assertNotIn(forbidden, source)

    def test_import_time_execution_is_bounded_and_stdlib_only(self) -> None:
        source = Path(s25aj.__file__).read_text(encoding="utf-8")
        imported: list[str] = []
        allowed = {"__future__", "json", "math", "typing"}
        real_import = builtins.__import__

        def guarded_import(name: str, *args: object, **kwargs: object) -> object:
            imported.append(name)
            if name.split(".", 1)[0] not in allowed:
                raise AssertionError(f"unexpected import: {name}")
            return real_import(name, *args, **kwargs)

        namespace = {
            "__name__": "s25aj_import_probe",
            "__file__": str(s25aj.__file__),
        }
        with patch("builtins.open", side_effect=AssertionError("open called at import time")), patch.object(
            builtins, "__import__", side_effect=guarded_import
        ):
            exec(compile(source, str(s25aj.__file__), "exec"), namespace)
        self.assertTrue(set(imported).issubset(allowed))


if __name__ == "__main__":
    unittest.main()

