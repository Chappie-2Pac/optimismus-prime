"""Adversarial tests for the pure W5-S25AI knowledge-order relation."""

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

import support.w5_s25ai_knowledge_order as s25ai  # noqa: E402
import test_w5_s25ai_fixture_foundation as fixtures  # noqa: E402


EXPECTED_RESULT_KEYS = {
    "schema_version",
    "canonicalization",
    "classification",
    "status",
    "decision",
    "reason",
    "expected_hit_count",
    "observed_hit_count",
    "top_k",
    "production_status",
    "authority_claim",
}
EXPECTED_RESULT_KEY_ORDER = (
    "schema_version",
    "canonicalization",
    "classification",
    "status",
    "decision",
    "reason",
    "expected_hit_count",
    "observed_hit_count",
    "top_k",
    "production_status",
    "authority_claim",
)
EXPECTED_REASONS = {
    "BUDGET_EXCEEDED": "budget_exceeded",
    "INPUT_INVALID": "input_invalid",
    "QUERY_EMPTY": "query_empty",
    "ENTRY_INVALID": "entry_invalid",
    "OBSERVATION_INVALID": "observation_invalid",
    "HIT_SET_DRIFT": "hit_set_drift",
    "SCORE_DRIFT": "score_drift",
    "ORDER_DRIFT": "order_drift",
}
TEST_MAX_INPUT_BYTES = 64 * 1024
TEST_MAX_JSON_DEPTH = 8
TEST_MAX_NODES = 4096
TEST_MAX_ENTRIES = 128
TEST_MAX_TAGS = 32
TEST_MAX_HITS = 3
TEST_MAX_STRING_BYTES = 16 * 1024
TEST_MAX_SCORE = 27315
TEST_MAX_TOTAL_STRING_BYTES = 64 * 1024


def _count_string_bytes(value: object) -> int:
    if type(value) is dict:
        return sum(_count_string_bytes(key) + _count_string_bytes(item) for key, item in value.items())
    if type(value) is list:
        return sum(_count_string_bytes(item) for item in value)
    if type(value) is str:
        return len(value.encode("utf-8"))
    return 0


def _case_with_exact_total_string_bytes(total: int) -> dict[str, object]:
    case: dict[str, object] = {
        "query": "memory",
        "entries": [
            {"id": f"e{index}", "title": "Archive", "tags": [], "selected_text": ""}
            for index in range(4)
        ],
    }
    fixed = _count_string_bytes(case)
    remaining = total - fixed
    lengths = []
    for _ in range(3):
        length = min(TEST_MAX_STRING_BYTES, remaining)
        lengths.append(length)
        remaining -= length
    lengths.append(remaining)
    if remaining < 0 or remaining > TEST_MAX_STRING_BYTES:
        raise AssertionError("fixture cannot fit the per-string boundary")
    for entry, length in zip(case["entries"], lengths):
        entry["selected_text"] = "x" * length
    if _count_string_bytes(case) != total:
        raise AssertionError("fixture did not reach the requested string boundary")
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


class W5S25AIKnowledgeOrderTests(unittest.TestCase):
    @staticmethod
    def _case(name: str = "content_cap") -> tuple[dict[str, object], list[dict[str, object]]]:
        return fixtures.build_positive_s25ai_case(name)

    @staticmethod
    def _evaluate(
        case: object,
        observed_hits: object,
    ) -> dict[str, object]:
        return s25ai.evaluate_knowledge_order_case(  # type: ignore[arg-type]
            case,  # type: ignore[arg-type]
            observed_hits=observed_hits,  # type: ignore[arg-type]
        )

    def assert_result_shape(self, result: dict[str, object]) -> None:
        self.assertEqual(set(result), EXPECTED_RESULT_KEYS)
        self.assertEqual(tuple(result), EXPECTED_RESULT_KEY_ORDER)
        self.assertEqual(result["schema_version"], "s25ai.knowledge-order.v1")
        self.assertEqual(result["canonicalization"], "NFKC_CASEFOLD_WORD_STOPWORD_V1")
        self.assertEqual(result["top_k"], 3)
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")
        self.assertIs(type(result["top_k"]), int)
        self.assertIs(type(result["expected_hit_count"]), int)
        self.assertIs(type(result["observed_hit_count"]), int)

    def assert_positive(self, result: dict[str, object]) -> None:
        self.assert_result_shape(result)
        self.assertEqual(result["classification"], "KNOWLEDGE_ORDER_CLOSED")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["decision"], "PROPOSAL_ONLY")
        self.assertEqual(result["reason"], "knowledge_order_closed")

    def assert_blocked(self, result: dict[str, object], classification: str) -> None:
        self.assert_result_shape(result)
        self.assertEqual(result["classification"], classification)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], EXPECTED_REASONS[classification])
        self.assertEqual(result["expected_hit_count"], 0)
        self.assertEqual(result["observed_hit_count"], 0)

    def test_result_shape_and_json_forms_are_stable(self) -> None:
        case, expected = self._case("emoji_crlf")
        raw = json.dumps(case, ensure_ascii=False, indent=2)
        reordered = json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        first = self._evaluate(case, expected)
        second = self._evaluate(raw, expected)
        third = self._evaluate(reordered.encode("utf-8"), expected)
        self.assert_positive(first)
        self.assertEqual(first, second)
        self.assertEqual(first, third)

    def test_case_and_observation_are_not_mutated_and_are_deterministic(self) -> None:
        case, expected = self._case("top_three")
        before_case = deepcopy(case)
        before_observed = deepcopy(expected)
        first = self._evaluate(case, expected)
        second = self._evaluate(case, expected)
        self.assertEqual(case, before_case)
        self.assertEqual(expected, before_observed)
        self.assertEqual(first, second)
        self.assert_positive(first)

    def test_exact_ranking_errors_are_partitioned(self) -> None:
        case, expected = self._case("content_cap")
        wrong_score = self._evaluate(case, [{"id": "cap", "score": 14}])
        self.assert_blocked(wrong_score, "SCORE_DRIFT")

        tie_case, tie_expected = self._case("tie_break")
        reversed_order = list(reversed(tie_expected))
        self.assert_blocked(self._evaluate(tie_case, reversed_order), "ORDER_DRIFT")

        top_case, top_expected = self._case("top_three")
        forged_set = [*top_expected[:2], {"id": "delta", "score": 5}]
        self.assert_blocked(self._evaluate(top_case, forged_set), "HIT_SET_DRIFT")

        score_and_order = [{"id": "zeta", "score": 4}, {"id": "alpha", "score": 5}]
        self.assert_blocked(self._evaluate(tie_case, score_and_order), "SCORE_DRIFT")

    def test_error_priority_is_explicit_across_entry_and_observation_layers(self) -> None:
        case, _ = self._case()
        empty_entries = {"query": "memory", "entries": []}
        self.assert_blocked(
            self._evaluate(empty_entries, [{"id": "unknown", "score": 1}]),
            "ENTRY_INVALID",
        )

        invalid_entry = deepcopy(case)
        invalid_entry["entries"][0]["id"] = "bad/id"
        self.assert_blocked(
            self._evaluate(invalid_entry, [{"id": "unknown", "score": 1}]),
            "ENTRY_INVALID",
        )

    def test_content_only_match_is_not_a_candidate_but_known_id_is_set_drift(self) -> None:
        case, _ = self._case("emoji_crlf")
        case["entries"].append(
            {
                "id": "content-only",
                "title": "Archive",
                "tags": [],
                "selected_text": "memory",
            }
        )
        result = self._evaluate(case, [{"id": "content-only", "score": 1}])
        self.assert_blocked(result, "HIT_SET_DRIFT")

    def test_unknown_duplicate_and_malformed_observations_fail_closed(self) -> None:
        case, expected = self._case()
        mutations = [
            ([{"id": "unknown", "score": 15}], "OBSERVATION_INVALID"),
            ([{"id": "cap", "score": 15}, {"id": "cap", "score": 15}], "OBSERVATION_INVALID"),
            ([{"id": "cap", "score": 15, "extra": 1}], "OBSERVATION_INVALID"),
            ([{"id": "cap"}], "OBSERVATION_INVALID"),
            ([{"id": "cap", "score": -1}], "OBSERVATION_INVALID"),
            ([{"id": "cap", "score": TEST_MAX_SCORE + 1}], "OBSERVATION_INVALID"),
            ([{"id": "cap", "score": True}], "INPUT_INVALID"),
        ]
        for observed, classification in mutations:
            with self.subTest(observed=observed):
                self.assert_blocked(self._evaluate(case, observed), classification)
        self.assert_blocked(self._evaluate(case, expected * 4), "BUDGET_EXCEEDED")

    def test_empty_query_and_priority_against_structure_and_entry_semantics(self) -> None:
        case, _ = self._case()
        case["query"] = "der für FUER"
        self.assert_blocked(self._evaluate(case, []), "QUERY_EMPTY")

        invalid_entry = deepcopy(case)
        invalid_entry["query"] = "der"
        invalid_entry["entries"][0]["id"] = "bad/id"
        self.assert_blocked(self._evaluate(invalid_entry, []), "QUERY_EMPTY")

        invalid_structure = deepcopy(case)
        invalid_structure["query"] = "der"
        invalid_structure["entries"][0]["tags"] = "not-a-list"
        self.assert_blocked(self._evaluate(invalid_structure, []), "INPUT_INVALID")

    def test_entry_schema_and_semantic_boundaries_are_disjoint(self) -> None:
        case, expected = self._case()
        missing = deepcopy(case)
        del missing["entries"][0]["title"]
        self.assert_blocked(self._evaluate(missing, expected), "INPUT_INVALID")

        duplicate_id = deepcopy(case)
        duplicate_id["entries"].append(deepcopy(duplicate_id["entries"][0]))
        self.assert_blocked(self._evaluate(duplicate_id, expected), "ENTRY_INVALID")

        control_title = deepcopy(case)
        control_title["entries"][0]["title"] = "Memory\x1f"
        self.assert_blocked(self._evaluate(control_title, expected), "ENTRY_INVALID")

        title_121 = deepcopy(case)
        title_121["entries"][0]["title"] = "a" * 121
        self.assert_blocked(self._evaluate(title_121, expected), "ENTRY_INVALID")

        tags_33 = deepcopy(case)
        tags_33["entries"][0]["tags"] = ["x"] * 33
        self.assert_blocked(self._evaluate(tags_33, expected), "ENTRY_INVALID")

        invalid_id = deepcopy(case)
        invalid_id["entries"][0]["id"] = "bad/id"
        self.assert_blocked(self._evaluate(invalid_id, expected), "ENTRY_INVALID")

    def test_string_and_container_budgets_are_fail_closed(self) -> None:
        case, expected = self._case()
        oversized_text = deepcopy(case)
        oversized_text["entries"][0]["selected_text"] = "x" * (TEST_MAX_STRING_BYTES + 1)
        self.assert_blocked(self._evaluate(oversized_text, expected), "BUDGET_EXCEEDED")

        many_strings = {
            "query": "memory",
            "entries": [
                {
                    "id": f"e{index}",
                    "title": "Archive",
                    "tags": [],
                    "selected_text": "x" * TEST_MAX_STRING_BYTES,
                }
                for index in range(4)
            ],
        }
        self.assert_blocked(self._evaluate(many_strings, []), "BUDGET_EXCEEDED")

        too_many_entries = {
            "query": "memory",
            "entries": [
                {"id": f"e{index}", "title": "Archive", "tags": [], "selected_text": ""}
                for index in range(TEST_MAX_ENTRIES + 1)
            ],
        }
        self.assert_blocked(self._evaluate(too_many_entries, []), "BUDGET_EXCEEDED")

        oversized_raw = b"x" * (TEST_MAX_INPUT_BYTES + 1)
        self.assert_blocked(self._evaluate(oversized_raw, []), "BUDGET_EXCEEDED")
        self.assert_blocked(
            self._evaluate(oversized_raw, [{"id": "cap", "score": 15}] * 4),
            "BUDGET_EXCEEDED",
        )

    def test_exact_raw_string_total_and_direct_object_boundaries(self) -> None:
        simple_case = {
            "query": "memory",
            "entries": [
                {"id": "cap", "title": "Memory", "tags": ["memory"], "selected_text": ""}
            ],
        }
        exact_query = deepcopy(simple_case)
        exact_query["query"] = "memory" + (" " * (TEST_MAX_STRING_BYTES - len("memory")))
        self.assertEqual(len(exact_query["query"].encode("utf-8")), TEST_MAX_STRING_BYTES)
        self.assert_positive(self._evaluate(exact_query, [{"id": "cap", "score": 5}]))

        over_query = deepcopy(exact_query)
        over_query["query"] += " "
        self.assert_blocked(self._evaluate(over_query, []), "BUDGET_EXCEEDED")

        exact_text = deepcopy(simple_case)
        exact_text["entries"][0]["selected_text"] = "x" * TEST_MAX_STRING_BYTES
        self.assert_positive(self._evaluate(exact_text, [{"id": "cap", "score": 5}]))

        exact_total = _case_with_exact_total_string_bytes(TEST_MAX_TOTAL_STRING_BYTES)
        self.assertEqual(_count_string_bytes(exact_total), TEST_MAX_TOTAL_STRING_BYTES)
        serialized_size = len(json.dumps(exact_total, separators=(",", ":")).encode("utf-8"))
        self.assertGreater(serialized_size, TEST_MAX_INPUT_BYTES)
        self.assert_positive(self._evaluate(exact_total, []))

        over_total = deepcopy(exact_total)
        over_total["entries"][-1]["selected_text"] += "x"
        self.assert_blocked(self._evaluate(over_total, []), "BUDGET_EXCEEDED")

        raw_base = json.dumps(simple_case, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        raw_exact = raw_base + (b" " * (TEST_MAX_INPUT_BYTES - len(raw_base)))
        self.assertEqual(len(raw_exact), TEST_MAX_INPUT_BYTES)
        self.assert_positive(self._evaluate(raw_exact, [{"id": "cap", "score": 5}]))
        self.assert_blocked(self._evaluate(raw_exact + b" ", []), "BUDGET_EXCEEDED")

        unicode_exact = deepcopy(simple_case)
        unicode_exact["entries"][0]["selected_text"] = "é" * 8192
        self.assertEqual(len(unicode_exact["entries"][0]["selected_text"].encode("utf-8")), TEST_MAX_STRING_BYTES)
        self.assert_positive(self._evaluate(unicode_exact, [{"id": "cap", "score": 5}]))
        unicode_over = deepcopy(unicode_exact)
        unicode_over["entries"][0]["selected_text"] += "x"
        self.assert_blocked(self._evaluate(unicode_over, []), "BUDGET_EXCEEDED")

        combined_case = {
            "query": "memory",
            "entries": [
                {"id": "cap", "title": "Memory", "tags": ["memory"], "selected_text": ""},
                *[
                    {"id": f"filler{index}", "title": "Archive", "tags": [], "selected_text": ""}
                    for index in range(3)
                ],
            ],
        }
        combined_target = TEST_MAX_TOTAL_STRING_BYTES - _count_string_bytes(
            [{"id": "cap", "score": 5}]
        )
        remaining = combined_target - _count_string_bytes(combined_case)
        for entry in combined_case["entries"]:
            length = min(TEST_MAX_STRING_BYTES, remaining)
            entry["selected_text"] = "x" * length
            remaining -= length
        self.assertEqual(remaining, 0)
        self.assertEqual(
            _count_string_bytes(combined_case) + _count_string_bytes([{"id": "cap", "score": 5}]),
            TEST_MAX_TOTAL_STRING_BYTES,
        )
        self.assert_positive(self._evaluate(combined_case, [{"id": "cap", "score": 5}]))
        combined_over = deepcopy(combined_case)
        combined_over["entries"][-1]["selected_text"] += "x"
        self.assert_blocked(self._evaluate(combined_over, [{"id": "cap", "score": 5}]), "BUDGET_EXCEEDED")

    def test_exact_entry_tag_title_score_and_observation_boundaries(self) -> None:
        case = {
            "query": "memory",
            "entries": [
                {"id": "cap", "title": "Archive", "tags": ["memory"], "selected_text": ""}
            ],
        }
        title_120 = deepcopy(case)
        title_120["entries"][0]["title"] = "a" * 120
        title_120["entries"][0]["tags"] = ["memory"]
        self.assert_positive(self._evaluate(title_120, [{"id": "cap", "score": 5}]))

        tag_64 = deepcopy(case)
        tag_64["entries"][0]["tags"] = ["memory", "x" * 64]
        self.assert_positive(self._evaluate(tag_64, [{"id": "cap", "score": 5}]))

        tags_32 = deepcopy(case)
        tags_32["entries"][0]["tags"] = ["memory"] + ["x"] * 31
        self.assertEqual(len(tags_32["entries"][0]["tags"]), TEST_MAX_TAGS)
        self.assert_positive(self._evaluate(tags_32, [{"id": "cap", "score": 5}]))

        tag_65 = deepcopy(case)
        tag_65["entries"][0]["tags"] = ["memory", "x" * 65]
        self.assert_blocked(self._evaluate(tag_65, [{"id": "cap", "score": 5}]), "ENTRY_INVALID")

        max_score = self._evaluate(case, [{"id": "cap", "score": TEST_MAX_SCORE}])
        self.assert_blocked(max_score, "SCORE_DRIFT")
        over_score = self._evaluate(case, [{"id": "cap", "score": TEST_MAX_SCORE + 1}])
        self.assert_blocked(over_score, "OBSERVATION_INVALID")

        three_case, three_expected = self._case("top_three")
        self.assertEqual(len(three_expected), 3)
        self.assert_positive(self._evaluate(three_case, three_expected))

    def test_exact_node_and_entry_boundaries(self) -> None:
        entries = []
        for index in range(TEST_MAX_ENTRIES):
            tag_count = 21 if index == 0 else (22 if index < 5 else 23)
            entries.append(
                {
                    "id": f"e{index}",
                    "title": "Archive",
                    "tags": ["t"] * tag_count,
                    "selected_text": "",
                }
            )
        exact_nodes = {"query": "memory", "entries": entries}
        self.assert_positive(self._evaluate(exact_nodes, []))

        over_nodes = deepcopy(exact_nodes)
        over_nodes["entries"][0]["tags"].append("extra")
        self.assert_blocked(self._evaluate(over_nodes, []), "BUDGET_EXCEEDED")

        empty_entries = {"query": "memory", "entries": []}
        self.assert_blocked(self._evaluate(empty_entries, []), "ENTRY_INVALID")

        depth_eight: object = 0
        for _ in range(TEST_MAX_JSON_DEPTH):
            depth_eight = [depth_eight]
        self.assert_blocked(self._evaluate(json.dumps(depth_eight), []), "INPUT_INVALID")

    def test_generic_container_boundary_is_distinct_from_root_schema(self) -> None:
        within = {"query": "memory", "entries": [], "padding": [0] * 256}
        self.assert_blocked(self._evaluate(within, []), "INPUT_INVALID")
        over = {"query": "memory", "entries": [], "padding": [0] * 257}
        self.assert_blocked(self._evaluate(over, []), "BUDGET_EXCEEDED")

    def test_depth_cycle_alias_and_node_limits_are_bounded(self) -> None:
        nested: object = 0
        for _ in range(TEST_MAX_JSON_DEPTH + 1):
            nested = [nested]
        self.assert_blocked(self._evaluate(json.dumps(nested), []), "BUDGET_EXCEEDED")

        cyclic = {"query": "memory", "entries": []}
        cyclic["entries"].append(cyclic)
        self.assert_blocked(self._evaluate(cyclic, []), "INPUT_INVALID")

        shared_tags: list[str] = []
        aliased = {
            "query": "memory",
            "entries": [
                {"id": "a", "title": "Archive", "tags": shared_tags, "selected_text": ""},
                {"id": "b", "title": "Archive", "tags": shared_tags, "selected_text": ""},
            ],
        }
        self.assert_blocked(self._evaluate(aliased, []), "INPUT_INVALID")

        node_heavy = {
            "query": "memory",
            "entries": [
                {
                    "id": f"e{index}",
                    "title": "Archive",
                    "tags": [f"tag{tag}" for tag in range(TEST_MAX_TAGS)],
                    "selected_text": "",
                }
                for index in range(TEST_MAX_ENTRIES)
            ],
        }
        self.assert_blocked(self._evaluate(node_heavy, []), "BUDGET_EXCEEDED")

    def test_strict_json_rejects_duplicate_keys_bom_utf8_surrogates_and_numbers(self) -> None:
        case, _ = self._case()
        valid = json.dumps(case, ensure_ascii=False).encode("utf-8")
        malformed: list[bytes] = [
            b'{"query":"memory","query":"forged","entries":[]}',
            b"\xef\xbb\xbf" + valid,
            b"\xff",
            b'{"query":"\\ud800","entries":[]}',
            b'{"query":1.0,"entries":[]}',
            b'{"query":true,"entries":[]}',
            b'{"query":null,"entries":[]}',
        ]
        for raw in malformed:
            with self.subTest(raw=raw[:30]):
                self.assert_blocked(self._evaluate(raw, []), "INPUT_INVALID")

    def test_custom_objects_are_rejected_without_executing_overrides(self) -> None:
        case, expected = self._case()
        _TrackingDict.calls = 0
        _TrackingList.calls = 0
        _TrackingString.calls = 0
        _TrackingBytes.calls = 0
        custom_case = _TrackingDict(case)
        custom_observed = _TrackingList(expected)
        custom_string_case = _TrackingString(json.dumps(case))
        custom_bytes_case = _TrackingBytes(json.dumps(case).encode("utf-8"))
        self.assert_blocked(self._evaluate(custom_case, expected), "INPUT_INVALID")
        self.assert_blocked(self._evaluate(case, custom_observed), "INPUT_INVALID")
        self.assert_blocked(self._evaluate(custom_string_case, expected), "INPUT_INVALID")
        self.assert_blocked(self._evaluate(custom_bytes_case, expected), "INPUT_INVALID")
        self.assertEqual(_TrackingDict.calls, 0)
        self.assertEqual(_TrackingList.calls, 0)
        self.assertEqual(_TrackingString.calls, 0)
        self.assertEqual(_TrackingBytes.calls, 0)

        mutated = deepcopy(case)
        _TrackingString.calls = 0
        mutated["entries"][0]["title"] = _TrackingString("Memory")
        self.assert_blocked(self._evaluate(mutated, expected), "INPUT_INVALID")
        self.assertEqual(_TrackingString.calls, 0)

        custom_hit = _TrackingDict(expected[0])
        _TrackingDict.calls = 0
        self.assert_blocked(self._evaluate(case, [custom_hit]), "INPUT_INVALID")
        self.assertEqual(_TrackingDict.calls, 0)

    def test_relation_has_no_io_or_production_knowledge_dependency(self) -> None:
        case, expected = self._case("emoji_crlf")
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
            result = self._evaluate(case, expected)
        self.assert_positive(result)
        self.assertEqual(set(sys.modules), modules_before)

        source = Path(s25ai.__file__).read_text(encoding="utf-8")
        self.assertNotIn("knowledge.py", source)
        self.assertNotIn("local-mother-session", source)
        self.assertNotIn("from modules", source)


if __name__ == "__main__":
    unittest.main()

