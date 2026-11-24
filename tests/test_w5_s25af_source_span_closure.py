"""Adversarial tests for the pure W5-S25AF source-span relation."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import sys
import unittest
from collections import UserDict
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25af_source_span_closure as s25af  # noqa: E402
import test_w5_s25af_fixture_foundation as fixtures  # noqa: E402


EXPECTED_RESULT_KEYS = {
    "schema_version",
    "observation_mode",
    "classification",
    "status",
    "decision",
    "reason",
    "closure_scope",
    "source_id",
    "source_sha256",
    "chunk_total",
    "coverage_start",
    "coverage_end",
    "max_overlap_chars",
    "intervals",
    "closure_digest",
    "production_status",
    "authority_claim",
}


class W5S25AFSourceSpanClosureTests(unittest.TestCase):
    @staticmethod
    def _canonical_json(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def _digest(cls, value: object) -> str:
        return hashlib.sha256(cls._canonical_json(value)).hexdigest()

    @classmethod
    def _source_hash(cls, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def _closure_digest(cls, case: dict[str, object]) -> str:
        expected = case["expected"]
        source = case["source"]
        chunks = case["chunks"]
        assert isinstance(expected, dict)
        assert isinstance(source, dict)
        assert isinstance(chunks, list)
        return cls._digest(
            {
                "schema": "w5.s25af.source-span-closure-witness.v1",
                "closure_scope": "SOURCE_SPAN_CONTENT_CLOSURE_ONLY",
                "source_id": source["source_id"],
                "source_sha256": source["source_sha256"],
                "coverage_start": expected["coverage_start"],
                "coverage_end": expected["coverage_end"],
                "max_overlap_chars": expected["max_overlap_chars"],
                "chunks": [
                    {
                        "chunk_index": chunk["chunk_index"],
                        "chunk_total": chunk["chunk_total"],
                        "char_start": chunk["char_start"],
                        "char_end": chunk["char_end"],
                        "text": chunk["text"],
                    }
                    for chunk in chunks
                ],
            }
        )

    @classmethod
    def _reseal_input(cls, case: dict[str, object]) -> None:
        case["input_digest"] = cls._digest({key: value for key, value in case.items() if key != "input_digest"})

    @classmethod
    def _source_text(cls, case: dict[str, object]) -> str:
        source = case["source"]
        assert isinstance(source, dict)
        return source["source_text"]  # type: ignore[return-value]

    @classmethod
    def _refresh_chunk_text(cls, case: dict[str, object], index: int) -> None:
        source_text = cls._source_text(case)
        chunks = case["chunks"]
        assert isinstance(chunks, list)
        chunk = chunks[index]
        assert isinstance(chunk, dict)
        chunk["text"] = source_text[chunk["char_start"] : chunk["char_end"]]

    def _case(self, variant: str = "no_overlap") -> dict[str, object]:
        return fixtures.build_positive_s25af_case(variant)

    def assert_actionless(self, result: dict[str, object]) -> None:
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def assert_non_authoritative(self, result: dict[str, object]) -> None:
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def test_positive_no_overlap_is_closed_and_actionless(self) -> None:
        result = s25af.evaluate_source_span_closure(self._case("no_overlap"))
        self.assertEqual(result["classification"], "SOURCE_SPAN_CLOSED")
        self.assertEqual(result["intervals"][0]["overlap_from_previous"], 0)  # type: ignore[index]
        self.assert_actionless(result)

    def test_positive_overlap_at_explicit_limit_and_three_chunk_chain(self) -> None:
        for variant in ("overlap_limit", "three_chunks"):
            with self.subTest(variant=variant):
                result = s25af.evaluate_source_span_closure(self._case(variant))
                self.assertEqual(result["classification"], "SOURCE_SPAN_CLOSED")
                self.assert_actionless(result)

    def test_result_keys_are_exact_and_stable_on_positive_and_failure_paths(self) -> None:
        positive = s25af.evaluate_source_span_closure(self._case())
        invalid_case = self._case()
        invalid_case["expected"]["closure_digest"] = "0" * 64  # type: ignore[index]
        self._reseal_input(invalid_case)
        invalid = s25af.evaluate_source_span_closure(invalid_case)
        raw_invalid = s25af.evaluate_source_span_closure(b"not-json")
        for result in (positive, invalid, raw_invalid):
            self.assertEqual(set(result), EXPECTED_RESULT_KEYS)
            self.assert_non_authoritative(result)

    def test_case_is_not_mutated_and_repeated_evaluation_is_deterministic(self) -> None:
        case = self._case("three_chunks")
        before = deepcopy(case)
        first = s25af.evaluate_source_span_closure(case)
        second = s25af.evaluate_source_span_closure(case)
        self.assertEqual(case, before)
        self.assertEqual(first, second)

    def test_json_key_order_and_whitespace_do_not_change_result(self) -> None:
        case = self._case("overlap_limit")
        raw = json.dumps(case, ensure_ascii=False, indent=2)
        reordered = json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertEqual(
            s25af.evaluate_source_span_closure(raw),
            s25af.evaluate_source_span_closure(reordered.encode("utf-8")),
        )

    def test_initial_middle_and_terminal_gaps_are_blocked(self) -> None:
        leading = self._case("three_chunks")
        leading_chunks = leading["chunks"]
        assert isinstance(leading_chunks, list)
        leading_chunks[0]["char_start"] = 1
        self._refresh_chunk_text(leading, 0)
        self._reseal_input(leading)

        middle = self._case("three_chunks")
        middle_chunks = middle["chunks"]
        assert isinstance(middle_chunks, list)
        previous_end = middle_chunks[0]["char_end"]
        middle_chunks[1]["char_start"] = previous_end + 1
        self._refresh_chunk_text(middle, 1)
        self._reseal_input(middle)

        terminal = self._case("three_chunks")
        terminal_chunks = terminal["chunks"]
        assert isinstance(terminal_chunks, list)
        terminal_chunks[-1]["char_end"] -= 1
        self._refresh_chunk_text(terminal, len(terminal_chunks) - 1)
        self._reseal_input(terminal)

        for case in (leading, middle, terminal):
            self.assertEqual(
                s25af.evaluate_source_span_closure(case)["classification"],
                "SOURCE_SPAN_GAP",
            )

    def test_overlap_above_limit_and_nested_or_backwards_intervals_are_blocked(self) -> None:
        too_much = self._case("no_overlap")
        chunks = too_much["chunks"]
        assert isinstance(chunks, list)
        chunks[1]["char_start"] = chunks[0]["char_end"] - 1
        self._refresh_chunk_text(too_much, 1)
        self._reseal_input(too_much)

        nested = self._case("three_chunks")
        nested_chunks = nested["chunks"]
        assert isinstance(nested_chunks, list)
        nested_chunks[1]["char_start"] = nested_chunks[0]["char_start"]
        self._refresh_chunk_text(nested, 1)
        self._reseal_input(nested)

        decreasing_end = self._case("three_chunks")
        decreasing_chunks = decreasing_end["chunks"]
        assert isinstance(decreasing_chunks, list)
        decreasing_chunks[1]["char_end"] = decreasing_chunks[0]["char_end"] - 1
        self._refresh_chunk_text(decreasing_end, 1)
        self._reseal_input(decreasing_end)

        for case in (too_much, nested, decreasing_end):
            self.assertEqual(
                s25af.evaluate_source_span_closure(case)["classification"],
                "SOURCE_SPAN_OVERLAP_INVALID",
            )

    def test_exact_slice_text_is_rechecked(self) -> None:
        case = self._case()
        chunks = case["chunks"]
        assert isinstance(chunks, list)
        chunks[0]["text"] += " forged"
        self._reseal_input(case)
        result = s25af.evaluate_source_span_closure(case)
        self.assertEqual(result["classification"], "SOURCE_SPAN_TEXT_MISMATCH")
        self.assert_non_authoritative(result)

        repeated_text = self._case("three_chunks")
        repeated_chunks = repeated_text["chunks"]
        assert isinstance(repeated_chunks, list)
        repeated_chunks[1]["text"] = repeated_chunks[0]["text"]
        self._reseal_input(repeated_text)
        self.assertEqual(
            s25af.evaluate_source_span_closure(repeated_text)["classification"],
            "SOURCE_SPAN_TEXT_MISMATCH",
        )

    def test_source_and_chunk_hash_bindings_are_not_status_claims(self) -> None:
        source_drift = self._case()
        source = source_drift["source"]
        expected = source_drift["expected"]
        chunks = source_drift["chunks"]
        assert isinstance(source, dict) and isinstance(expected, dict) and isinstance(chunks, list)
        source["source_sha256"] = "f" * 64
        expected["source_sha256"] = "f" * 64
        for chunk in chunks:
            chunk["source_sha256"] = "f" * 64
        self._reseal_input(source_drift)
        self.assertEqual(
            s25af.evaluate_source_span_closure(source_drift)["classification"],
            "SOURCE_SPAN_HASH_MISMATCH",
        )

        chunk_drift = self._case()
        chunk_drift_chunks = chunk_drift["chunks"]
        assert isinstance(chunk_drift_chunks, list)
        chunk_drift_chunks[0]["source_sha256"] = "e" * 64
        self._reseal_input(chunk_drift)
        self.assertEqual(
            s25af.evaluate_source_span_closure(chunk_drift)["classification"],
            "SOURCE_SPAN_HASH_MISMATCH",
        )

    def test_index_order_and_chunk_total_drift_are_blocked(self) -> None:
        duplicate = self._case("three_chunks")
        duplicate_chunks = duplicate["chunks"]
        assert isinstance(duplicate_chunks, list)
        duplicate_chunks[1]["chunk_index"] = 1
        self._reseal_input(duplicate)

        reordered = self._case("three_chunks")
        reordered_chunks = reordered["chunks"]
        assert isinstance(reordered_chunks, list)
        reordered_chunks.reverse()
        self._reseal_input(reordered)

        total = self._case()
        total_chunks = total["chunks"]
        assert isinstance(total_chunks, list)
        total_chunks[0]["chunk_total"] = 9
        self._reseal_input(total)

        for case in (duplicate, reordered, total):
            self.assertEqual(
                s25af.evaluate_source_span_closure(case)["classification"],
                "SOURCE_SPAN_INDEX_INVALID",
            )

    def test_expected_binding_and_closure_digest_resealing_do_not_forge_positive(self) -> None:
        binding = self._case()
        expected = binding["expected"]
        assert isinstance(expected, dict)
        expected["source_id"] = "other-source"
        self._reseal_input(binding)
        binding_result = s25af.evaluate_source_span_closure(binding)
        self.assertEqual(binding_result["classification"], "INPUT_INVALID")

        closure = self._case()
        closure_expected = closure["expected"]
        assert isinstance(closure_expected, dict)
        closure_expected["closure_digest"] = "0" * 64
        self._reseal_input(closure)
        closure_result = s25af.evaluate_source_span_closure(closure)
        self.assertEqual(closure_result["classification"], "INPUT_INVALID")
        self.assertNotEqual(closure_result["classification"], "SOURCE_SPAN_CLOSED")

    def test_outer_input_digest_gate_precedes_inner_fault_classification(self) -> None:
        stale_gap = self._case("three_chunks")
        stale_gap_chunks = stale_gap["chunks"]
        assert isinstance(stale_gap_chunks, list)
        stale_gap_chunks[1]["char_start"] = stale_gap_chunks[0]["char_end"] + 1
        self._refresh_chunk_text(stale_gap, 1)

        stale_hash = self._case()
        stale_hash_source = stale_hash["source"]
        assert isinstance(stale_hash_source, dict)
        stale_hash_source["source_sha256"] = "f" * 64

        stale_index = self._case()
        stale_index_chunks = stale_index["chunks"]
        assert isinstance(stale_index_chunks, list)
        stale_index_chunks[0]["chunk_index"] = 2

        for case in (stale_gap, stale_hash, stale_index):
            result = s25af.evaluate_source_span_closure(case)
            self.assertEqual(result["classification"], "INPUT_INVALID")
            self.assertEqual(result["reason"], "CASE_DIGEST_DRIFT")

    def test_unicode_codepoint_offsets_are_not_byte_offsets(self) -> None:
        case = self._case()
        source_text = self._source_text(case)
        chunks = case["chunks"]
        assert isinstance(chunks, list)
        chunks[0]["char_end"] = len(source_text.encode("utf-8"))
        self._reseal_input(case)
        self.assertEqual(
            s25af.evaluate_source_span_closure(case)["classification"],
            "SOURCE_SPAN_INDEX_INVALID",
        )

    def test_empty_source_and_unsafe_source_id_fail_closed(self) -> None:
        empty = self._case()
        source = empty["source"]
        expected = empty["expected"]
        assert isinstance(source, dict) and isinstance(expected, dict)
        empty_hash = self._source_hash("")
        source["source_text"] = ""
        source["source_sha256"] = empty_hash
        expected["source_sha256"] = empty_hash
        expected["chunk_total"] = 0
        expected["coverage_end"] = 0
        expected["closure_digest"] = self._closure_digest(empty)
        empty["chunks"] = []
        self._reseal_input(empty)
        self.assertEqual(s25af.evaluate_source_span_closure(empty)["classification"], "INPUT_INVALID")

        unsafe = self._case()
        unsafe_source = unsafe["source"]
        assert isinstance(unsafe_source, dict)
        unsafe_source["source_id"] = "../unsafe"
        self._reseal_input(unsafe)
        self.assertEqual(s25af.evaluate_source_span_closure(unsafe)["classification"], "INPUT_INVALID")

    def test_parser_rejects_duplicate_keys_invalid_utf8_nan_and_non_builtin_mapping(self) -> None:
        case = self._case()
        raw = json.dumps(case, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        duplicate = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '"}'
        self.assertEqual(s25af.evaluate_source_span_closure(duplicate)["classification"], "INPUT_INVALID")
        self.assertEqual(s25af.evaluate_source_span_closure(b"\xff")["classification"], "INPUT_INVALID")
        self.assertEqual(s25af.evaluate_source_span_closure(b"{\"input_digest\":NaN}")["classification"], "INPUT_INVALID")
        self.assertEqual(
            s25af.evaluate_source_span_closure(UserDict(case))["classification"],
            "INPUT_INVALID",
        )

    def test_bool_float_recursive_and_over_budget_values_are_invalid(self) -> None:
        boolean = self._case()
        boolean_chunks = boolean["chunks"]
        assert isinstance(boolean_chunks, list)
        boolean_chunks[0]["chunk_index"] = True
        self._reseal_input(boolean)
        self.assertEqual(s25af.evaluate_source_span_closure(boolean)["classification"], "SOURCE_SPAN_INDEX_INVALID")

        floating = self._case()
        floating_chunks = floating["chunks"]
        assert isinstance(floating_chunks, list)
        floating_chunks[0]["char_start"] = 0.0
        self._reseal_input(floating)
        self.assertEqual(s25af.evaluate_source_span_closure(floating)["classification"], "INPUT_INVALID")

        recursive = self._case()
        recursive_source = recursive["source"]
        assert isinstance(recursive_source, dict)
        recursive_source["loop"] = recursive
        self.assertEqual(s25af.evaluate_source_span_closure(recursive)["classification"], "INPUT_INVALID")

        oversized = self._case()
        oversized_source = oversized["source"]
        assert isinstance(oversized_source, dict)
        oversized_source["source_text"] = "x" * (65_536 + 1)
        self.assertEqual(s25af.evaluate_source_span_closure(oversized)["classification"], "INPUT_INVALID")

    def test_no_file_or_network_discovery_is_needed(self) -> None:
        case = self._case("overlap_limit")
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch(
            "socket.socket", side_effect=AssertionError("network is forbidden")
        ):
            result = s25af.evaluate_source_span_closure(case)
        self.assertEqual(result["classification"], "SOURCE_SPAN_CLOSED")

    def test_support_surface_is_stdlib_only_and_non_operational(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25af_source_span_closure.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "validate_source_spans",
            "semantic_chunker",
            "clean_source",
            "subprocess",
            "socket",
            "open(",
            "Path(",
            "time.",
            "AD_TETRAHEDRAL",
            "evaluate_triangle_topology",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
