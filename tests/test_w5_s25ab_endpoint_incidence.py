"""Adversarial tests for the pure S25AB endpoint-incidence relation."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25aa_pairwise_identity as s25aa  # noqa: E402
import support.w5_s25ab_endpoint_incidence as s25ab  # noqa: E402
import test_w5_s25ab_fixture_foundation as fixtures  # noqa: E402


IDENTITY_FIELDS = tuple(s25aa.IDENTITY_FIELDS)
MATRIX_FIELDS = tuple(s25ab.MATRIX_FIELDS)


class W5S25ABEndpointIncidenceTests(unittest.TestCase):
    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _edge(cls, output: dict[str, object]) -> dict[str, dict[str, str]]:
        return {
            "left_endpoint": deepcopy(output["left_identity"]),
            "right_endpoint": deepcopy(output["right_identity"]),
        }

    @classmethod
    def _matrix(
        cls, left_edge: dict[str, object], right_edge: dict[str, object]
    ) -> dict[str, bool]:
        return {
            "left_left": left_edge["left_endpoint"] == right_edge["left_endpoint"],
            "left_right": left_edge["left_endpoint"] == right_edge["right_endpoint"],
            "right_left": left_edge["right_endpoint"] == right_edge["left_endpoint"],
            "right_right": left_edge["right_endpoint"] == right_edge["right_endpoint"],
        }

    @classmethod
    def _endpoint_digest(
        cls,
        left_edge: dict[str, object],
        right_edge: dict[str, object],
        matrix: dict[str, bool],
        relation: str,
    ) -> str:
        return cls._digest(
            {
                "schema": "s25ab.endpoint-incidence-witness.v1",
                "incidence_scope": "S25AA_EDGE_ENDPOINT_INCIDENCE_ONLY",
                "left_edge": left_edge,
                "right_edge": right_edge,
                "match_matrix": matrix,
                "relation": relation,
            }
        )

    @classmethod
    def _relation(cls, matrix: dict[str, bool]) -> str:
        values = tuple(matrix[field] for field in MATRIX_FIELDS)
        if values == (True, False, False, True):
            return s25ab.AA_EDGE_SAME
        if values == (False, True, True, False):
            return s25ab.AA_EDGE_REVERSED
        if sum(values) == 1:
            return s25ab.AA_ONE_ENDPOINT_SHARED
        if sum(values) == 0:
            return s25ab.AA_ENDPOINTS_DISJOINT
        raise AssertionError(f"unexpected test matrix: {matrix}")

    @classmethod
    def _case(
        cls,
        left_pair: tuple[str, str],
        right_pair: tuple[str, str],
        *,
        left_case: dict[str, object] | None = None,
        right_case: dict[str, object] | None = None,
    ) -> dict[str, object]:
        left_case = deepcopy(left_case if left_case is not None else fixtures.build_positive_s25aa_case(*left_pair))
        right_case = deepcopy(right_case if right_case is not None else fixtures.build_positive_s25aa_case(*right_pair))
        left_output = s25aa.evaluate_pairwise_identity(left_case)
        right_output = s25aa.evaluate_pairwise_identity(right_case)
        left_edge = cls._edge(left_output)
        right_edge = cls._edge(right_output)
        matrix = cls._matrix(left_edge, right_edge)
        relation = cls._relation(matrix)
        endpoint_digest = cls._endpoint_digest(left_edge, right_edge, matrix, relation)
        case: dict[str, object] = {
            "schema_version": s25ab.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25ab.CANONICALIZATION,
            "expected": {
                "left_aa_case_digest": s25aa.input_digest(left_case),
                "right_aa_case_digest": s25aa.input_digest(right_case),
                "left_aa_result_digest": cls._digest(left_output),
                "right_aa_result_digest": cls._digest(right_output),
                "endpoint_relation_digest": endpoint_digest,
            },
            "left_case": left_case,
            "left_output": left_output,
            "right_case": right_case,
            "right_output": right_output,
            "endpoint_witness": {
                "left_edge": left_edge,
                "right_edge": right_edge,
                "match_matrix": matrix,
                "relation": relation,
            },
            "input_digest": "",
        }
        case["input_digest"] = s25ab.input_digest(case)
        return case

    @staticmethod
    def _reseal(case: dict[str, object]) -> None:
        case["input_digest"] = s25ab.input_digest(case)

    def test_all_four_shared_endpoint_positions_are_positive(self) -> None:
        cases = (
            (("alpha", "beta"), ("alpha", "gamma"), "left_left"),
            (("alpha", "beta"), ("gamma", "alpha"), "left_right"),
            (("beta", "alpha"), ("alpha", "gamma"), "right_left"),
            (("beta", "alpha"), ("gamma", "alpha"), "right_right"),
        )
        for left_pair, right_pair, shared_position in cases:
            with self.subTest(shared_position=shared_position):
                result = s25ab.evaluate_endpoint_incidence(self._case(left_pair, right_pair))

                self.assertEqual(result["classification"], s25ab.AA_ONE_ENDPOINT_SHARED)
                self.assertEqual(result["status"], "PROPOSAL_ONLY")
                self.assertEqual(result["decision"], "DESIGN_ONLY")
                self.assertEqual(sum(result["match_matrix"].values()), 1)
                self.assertTrue(result["match_matrix"][shared_position])
                self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
                self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def test_fourth_fixture_enables_a_genuine_disjoint_relation(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))

        result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.AA_ENDPOINTS_DISJOINT)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["match_matrix"], {field: False for field in MATRIX_FIELDS})

    def test_same_edge_is_not_new_information(self) -> None:
        result = s25ab.evaluate_endpoint_incidence(self._case(("alpha", "beta"), ("alpha", "beta")))

        self.assertEqual(result["classification"], s25ab.AA_EDGE_SAME)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], "AA_EDGE_IDENTICAL_NOT_NEW")
        self.assertEqual(result["match_matrix"], {"left_left": True, "left_right": False, "right_left": False, "right_right": True})

    def test_reverse_edge_is_not_new_information(self) -> None:
        result = s25ab.evaluate_endpoint_incidence(self._case(("alpha", "beta"), ("beta", "alpha")))

        self.assertEqual(result["classification"], s25ab.AA_EDGE_REVERSED)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], "AA_EDGE_REVERSED_NOT_NEW")

    def test_non_positive_aa_never_becomes_endpoint_incidence(self) -> None:
        non_positive = fixtures.build_positive_s25aa_case("alpha", "alpha")
        positive = fixtures.build_positive_s25aa_case("beta", "gamma")
        case = self._case(
            ("alpha", "beta"),
            ("beta", "gamma"),
            left_case=non_positive,
            right_case=positive,
        )

        result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.S25AA_NOT_POSITIVE)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")

    def test_both_aa_sides_are_attempted_when_left_side_fails(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        right_output = deepcopy(case["right_output"])

        with patch.object(s25ab, "evaluate_pairwise_identity", side_effect=[RuntimeError("left"), right_output]) as mocked:
            result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(mocked.call_args_list[0].args[0], case["left_case"])
        self.assertEqual(mocked.call_args_list[1].args[0], case["right_case"])
        self.assertEqual(result["classification"], s25ab.S25AA_REJECTED)
        self.assertEqual(result["status"], "TEST_BLOCKED")

    def test_both_aa_sides_are_attempted_and_left_failure_wins_when_both_fail(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))

        with patch.object(
            s25ab, "evaluate_pairwise_identity", side_effect=[RuntimeError("left"), RuntimeError("right")]
        ) as mocked:
            result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(result["classification"], s25ab.S25AA_REJECTED)
        self.assertEqual(result["reason"], "S25AA_RESULT_UNREADABLE")

    def test_forged_positive_aa_relation_is_rejected_at_the_public_boundary(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        forged_left_output = deepcopy(case["left_output"])
        forged_left_output["left_identity"]["y_result_digest"] = "c" * 64
        case["left_output"] = forged_left_output
        case["expected"]["left_aa_result_digest"] = self._digest(forged_left_output)
        self._reseal(case)

        with patch.object(
            s25ab,
            "evaluate_pairwise_identity",
            side_effect=[forged_left_output, case["right_output"]],
        ):
            result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.S25AA_REJECTED)
        self.assertEqual(result["reason"], "S25AA_RESULT_INVALID")

    def test_same_z_case_with_downstream_identity_drift_is_fail_closed(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        forged_right_output = deepcopy(case["right_output"])
        forged_right_output["left_identity"] = deepcopy(case["left_output"]["left_identity"])
        forged_right_output["left_identity"]["y_result_digest"] = "d" * 64
        forged_right_output["equal_fields"] = {
            field: forged_right_output["left_identity"][field] == forged_right_output["right_identity"][field]
            for field in IDENTITY_FIELDS
        }
        forged_right_output["pair_digest"] = s25aa.pair_digest(
            forged_right_output["left_identity"],
            forged_right_output["right_identity"],
            forged_right_output["equal_fields"],
            s25aa.PAIR_SEPARATED,
        )
        case["right_output"] = forged_right_output
        case["expected"]["right_aa_result_digest"] = self._digest(forged_right_output)
        self._reseal(case)

        with patch.object(
            s25ab,
            "evaluate_pairwise_identity",
            side_effect=[case["left_output"], forged_right_output],
        ):
            result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.AA_ENDPOINT_WITNESS_MISMATCH)
        self.assertEqual(result["reason"], "ENDPOINT_IDENTITY_CONFLICT")

    def test_supplied_aa_output_mismatch_is_rejected(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        case["left_output"]["reason"] = "FORGED"
        self._reseal(case)

        result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.S25AA_REJECTED)
        self.assertEqual(result["reason"], "S25AA_RESULT_MISMATCH")

    def test_nested_aa_case_digest_drift_is_rejected(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        case["left_case"]["input_digest"] = "f" * 64
        self._reseal(case)

        result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.S25AA_REJECTED)
        self.assertEqual(result["reason"], "S25AA_CASE_DIGEST_DRIFT")

    def test_expected_binding_drift_cannot_authorize_incidence(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        case["expected"]["left_aa_result_digest"] = "a" * 64
        self._reseal(case)

        result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.AA_ENDPOINT_WITNESS_MISMATCH)
        self.assertEqual(result["reason"], "EXPECTED_AA_BINDING_MISMATCH")

    def test_matrix_witness_drift_is_blocked(self) -> None:
        case = self._case(("alpha", "beta"), ("alpha", "gamma"))
        case["endpoint_witness"]["match_matrix"]["left_left"] = False
        self._reseal(case)

        result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.AA_ENDPOINT_WITNESS_MISMATCH)
        self.assertEqual(result["reason"], "ENDPOINT_WITNESS_MISMATCH")
        self.assertTrue(result["match_matrix"]["left_left"])

    def test_relation_digest_drift_is_blocked(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        case["expected"]["endpoint_relation_digest"] = "b" * 64
        self._reseal(case)

        result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.AA_ENDPOINT_WITNESS_MISMATCH)
        self.assertEqual(result["reason"], "ENDPOINT_RELATION_DIGEST_MISMATCH")

    def test_missing_extra_and_unknown_witness_fields_are_invalid(self) -> None:
        for mutation in ("missing", "extra", "unknown"):
            with self.subTest(mutation=mutation):
                case = self._case(("alpha", "beta"), ("gamma", "delta"))
                if mutation == "missing":
                    case["endpoint_witness"].pop("relation")
                elif mutation == "extra":
                    case["endpoint_witness"]["extra"] = True
                else:
                    case["endpoint_witness"]["relation"] = "UNKNOWN"
                self._reseal(case)

                result = s25ab.evaluate_endpoint_incidence(case)

                self.assertEqual(result["classification"], s25ab.INPUT_INVALID)

    def test_impossible_matrix_is_fail_closed(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        case["endpoint_witness"]["match_matrix"] = {
            "left_left": True,
            "left_right": True,
            "right_left": False,
            "right_right": False,
        }
        self._reseal(case)

        result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.AA_ENDPOINT_WITNESS_MISMATCH)
        self.assertEqual(result["reason"], "ENDPOINT_WITNESS_MISMATCH")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        raw = json.dumps(case, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        raw = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '","input_digest":"' + ("1" * 64) + '"}'

        result = s25ab.evaluate_endpoint_incidence(raw)

        self.assertEqual(result["classification"], s25ab.INPUT_INVALID)

    def test_raw_parser_rejects_nested_duplicates_utf8_nan_bytes_depth_nodes_and_integer_overflow(self) -> None:
        nested_duplicate = b'{"outer":{"key":1,"key":2}}'
        deep = b"[" * 66 + b"0" + b"]" * 66
        many_nodes = b"[" + b",".join(b"0" for _ in range(50001)) + b"]"
        raw_inputs = (
            nested_duplicate,
            b"\xff",
            b'{"value":NaN}',
            b"x" * (2 * 1024 * 1024 + 1),
            deep,
            many_nodes,
            b'{"value":9223372036854775808}',
        )

        for raw in raw_inputs:
            with self.subTest(raw_prefix=raw[:16]):
                result = s25ab.evaluate_endpoint_incidence(raw)
                self.assertEqual(result["classification"], s25ab.INPUT_INVALID)

    def test_unsafe_scalar_path_uri_float_and_bool_values_are_blocked(self) -> None:
        mutations = {
            "float": lambda case: case["endpoint_witness"]["match_matrix"].__setitem__("left_left", 1.0),
            "path": lambda case: case["endpoint_witness"].__setitem__("relation", "/tmp/relation"),
            "uri": lambda case: case["endpoint_witness"].__setitem__("relation", "https://example.invalid/relation"),
            "bool_digest": lambda case: case["expected"].__setitem__("left_aa_case_digest", True),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = self._case(("alpha", "beta"), ("gamma", "delta"))
                mutate(case)
                if label != "float":
                    self._reseal(case)

                result = s25ab.evaluate_endpoint_incidence(case)

                self.assertEqual(result["classification"], s25ab.INPUT_INVALID)

    def test_recursive_mapping_and_budget_limits_are_blocked(self) -> None:
        recursive = self._case(("alpha", "beta"), ("gamma", "delta"))
        loop: dict[str, object] = {}
        loop["self"] = loop
        recursive["endpoint_witness"] = loop
        result_recursive = s25ab.evaluate_endpoint_incidence(recursive)

        oversized = self._case(("alpha", "beta"), ("gamma", "delta"))
        oversized["endpoint_witness"]["left_edge"]["left_endpoint"]["z_case_digest"] = "x" * 4097
        result_oversized = s25ab.evaluate_endpoint_incidence(oversized)

        self.assertEqual(result_recursive["classification"], s25ab.INPUT_INVALID)
        self.assertEqual(result_oversized["classification"], s25ab.INPUT_INVALID)

    def test_input_is_unchanged_and_repeated_calls_have_no_hidden_state(self) -> None:
        case = self._case(("alpha", "beta"), ("alpha", "gamma"))
        before = deepcopy(case)

        first = s25ab.evaluate_endpoint_incidence(case)
        second = s25ab.evaluate_endpoint_incidence(deepcopy(case))
        third = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(case, before)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_no_file_or_network_discovery_is_needed(self) -> None:
        case = self._case(("alpha", "beta"), ("gamma", "delta"))
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch(
            "socket.socket", side_effect=AssertionError("network is forbidden")
        ):
            result = s25ab.evaluate_endpoint_incidence(case)

        self.assertEqual(result["classification"], s25ab.AA_ENDPOINTS_DISJOINT)

    def test_public_boundary_and_no_temporal_or_production_implementation(self) -> None:
        source = Path(s25ab.__file__).read_text(encoding="utf-8")

        self.assertIn("w5_s25aa_pairwise_identity", source)
        for forbidden in (
            "w5_s25z",
            "w5_s25y",
            "w5_s25x",
            "w5_s25w",
            "w5_s25v",
            "test_w5_s25",
            "socket",
            "datetime",
            "random",
            "time",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("open(", source)
        self.assertNotIn("def write", source)
        self.assertNotIn("def commit", source)
        self.assertNotIn("def persist", source)

    def test_all_result_paths_have_exact_public_keys(self) -> None:
        cases = (
            self._case(("alpha", "beta"), ("alpha", "gamma")),
            self._case(("alpha", "beta"), ("gamma", "delta")),
            self._case(("alpha", "beta"), ("alpha", "beta")),
            self._case(("alpha", "beta"), ("beta", "alpha")),
        )
        for case in cases:
            with self.subTest(case=case["endpoint_witness"]["relation"]):
                result = s25ab.evaluate_endpoint_incidence(case)
                self.assertEqual(set(result), set(s25ab.RESULT_KEYS))


def build_complete_s25ab_case() -> dict[str, object]:
    """Public test-only fixture boundary for downstream W5 cards."""

    return W5S25ABEndpointIncidenceTests._case(("alpha", "beta"), ("alpha", "gamma"))


if __name__ == "__main__":
    unittest.main()

