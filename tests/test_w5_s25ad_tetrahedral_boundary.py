"""Adversarial tests for the pure S25AD signed tetrahedral boundary relation."""

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

import support.w5_s25ac_triangle_topology as s25ac  # noqa: E402
import support.w5_s25ad_tetrahedral_boundary as s25ad  # noqa: E402
import support.w5_s25ab_endpoint_incidence as s25ab  # noqa: E402
import test_w5_s25ac_fixture_foundation as ac_fixtures  # noqa: E402
import test_w5_s25ac_triangle_topology as ac_tests  # noqa: E402
import test_w5_s25ad_fixture_foundation as fixtures  # noqa: E402


BASE_CYCLES = (
    ("B", "C", "D"),
    ("A", "D", "C"),
    ("A", "B", "D"),
    ("A", "C", "B"),
)
BASE_SIGNS = (1, -1, 1, -1)
FACE_IDS = (
    "FACE_123_POSITIVE",
    "FACE_023_NEGATIVE",
    "FACE_013_POSITIVE",
    "FACE_012_NEGATIVE",
)


class W5S25ADTetrahedralBoundaryTests(unittest.TestCase):
    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _edge_key(cls, edge: dict[str, object]) -> bytes:
        return json.dumps(edge, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    @classmethod
    def _deepcopy_edge(cls, edge: dict[str, object]) -> dict[str, object]:
        return {
            "left_endpoint": deepcopy(edge["left_endpoint"]),
            "right_endpoint": deepcopy(edge["right_endpoint"]),
        }

    @classmethod
    def _ac_case_from_cycle(cls, cycle: tuple[str, str, str]) -> dict[str, object]:
        pairs = tuple((cycle[index], cycle[(index + 1) % 3]) for index in range(3))
        return ac_tests.W5S25ACTriangleTopologyTests._case_from_pairs(pairs)

    @classmethod
    def _make_face(
        cls, catalog: list[dict[str, object]], opposite_index: int
    ) -> dict[str, object]:
        cycle = (1, 2, 3) if opposite_index == 0 else (
            (0, 2, 3) if opposite_index == 1 else ((0, 1, 3) if opposite_index == 2 else (0, 1, 2))
        )
        ordered_edges = [
            {
                "from_edge": cls._deepcopy_edge(catalog[source]),
                "to_edge": cls._deepcopy_edge(catalog[target]),
            }
            for source, target in zip(cycle, cycle[1:] + cycle[:1])
        ]
        return {"opposite_index": opposite_index, "ordered_edges": ordered_edges, "orientation": BASE_SIGNS[opposite_index]}

    @classmethod
    def _golden_boundary_witness(
        cls,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]], list[int], str]:
        ab_cases = {
            "A_B": ac_fixtures.build_positive_s25ab_case("A", "B"),
            "A_C": ac_fixtures.build_positive_s25ab_case("A", "C"),
            "A_D": ac_fixtures.build_positive_s25ab_case("A", "D"),
        }
        ab_outputs = {key: s25ab.evaluate_endpoint_incidence(case) for key, case in ab_cases.items()}
        raw_vertices = {
            "A": ab_outputs["A_B"]["left_edge"],
            "B": ab_outputs["A_B"]["right_edge"],
            "C": ab_outputs["A_C"]["right_edge"],
            "D": ab_outputs["A_D"]["right_edge"],
        }
        catalog = sorted((cls._deepcopy_edge(edge) for edge in raw_vertices.values()), key=cls._edge_key)
        ordered_faces = [cls._make_face(catalog, opposite_index) for opposite_index in range(4)]
        pattern = list(BASE_SIGNS)
        digest = cls._digest(
            {
                "schema": "s25ad.signed-tetrahedral-boundary-witness.v1",
                "boundary_scope": "S25AC_SIGNED_TETRAHEDRAL_BOUNDARY_ONLY",
                "ordered_faces": ordered_faces,
                "vertex_catalog": catalog,
                "orientation_pattern": pattern,
                "relation": s25ad.AD_TETRAHEDRAL_BOUNDARY_CLOSED,
            }
        )
        return ordered_faces, catalog, pattern, digest

    @classmethod
    def _case_from_face_cases(
        cls, cases: list[dict[str, object]], *, expected_positive: bool = True
    ) -> dict[str, object]:
        outputs = [s25ac.evaluate_triangle_topology(case) for case in cases]
        if expected_positive:
            ordered_faces, catalog, pattern, boundary_digest = cls._golden_boundary_witness()
            relation = s25ad.AD_TETRAHEDRAL_BOUNDARY_CLOSED
        else:
            ordered_faces, catalog, pattern = [], [], []
            relation = s25ad.AD_NOT_TETRAHEDRAL
            boundary_digest = "0" * 64
        case: dict[str, object] = {
            "schema_version": s25ad.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25ad.CANONICALIZATION,
            "expected": {
                "first_ac_case_digest": s25ac.input_digest(cases[0]),
                "second_ac_case_digest": s25ac.input_digest(cases[1]),
                "third_ac_case_digest": s25ac.input_digest(cases[2]),
                "fourth_ac_case_digest": s25ac.input_digest(cases[3]),
                "first_ac_result_digest": cls._digest(outputs[0]),
                "second_ac_result_digest": cls._digest(outputs[1]),
                "third_ac_result_digest": cls._digest(outputs[2]),
                "fourth_ac_result_digest": cls._digest(outputs[3]),
                "boundary_digest": boundary_digest,
            },
            "first_ac_case": cases[0],
            "first_ac_output": outputs[0],
            "second_ac_case": cases[1],
            "second_ac_output": outputs[1],
            "third_ac_case": cases[2],
            "third_ac_output": outputs[2],
            "fourth_ac_case": cases[3],
            "fourth_ac_output": outputs[3],
            "boundary_witness": {
                "ordered_faces": ordered_faces,
                "vertex_catalog": catalog,
                "orientation_pattern": pattern,
                "relation": relation,
            },
            "input_digest": "",
        }
        case["input_digest"] = s25ad.input_digest(case)
        return case

    @classmethod
    def setUpClass(cls) -> None:
        cls.tetra_case = cls._case_from_face_cases(
            [fixtures.build_positive_s25ac_face_case(face_id) for face_id in FACE_IDS]
        )
        cls.tetra_outputs = [
            deepcopy(cls.tetra_case["first_ac_output"]),
            deepcopy(cls.tetra_case["second_ac_output"]),
            deepcopy(cls.tetra_case["third_ac_output"]),
            deepcopy(cls.tetra_case["fourth_ac_output"]),
        ]

    def _patched_result(
        self, case: dict[str, object], outputs: list[dict[str, object]] | None = None
    ) -> dict[str, object]:
        with patch.object(
            s25ad, "evaluate_triangle_topology", side_effect=deepcopy(outputs or self.tetra_outputs)
        ):
            return s25ad.evaluate_tetrahedral_boundary(case)

    def test_genuine_tetrahedral_boundary_is_positive(self) -> None:
        result = s25ad.evaluate_tetrahedral_boundary(deepcopy(self.tetra_case))

        self.assertEqual(result["classification"], s25ad.AD_TETRAHEDRAL_BOUNDARY_CLOSED)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")
        self.assertEqual(result["orientation_pattern"], [1, -1, 1, -1])
        self.assertEqual(len(result["ordered_faces"]), 4)
        self.assertEqual(len(result["vertex_catalog"]), 4)

    def test_global_orientation_reversal_is_accepted(self) -> None:
        reversed_cases = [
            self._ac_case_from_cycle((cycle[0], cycle[2], cycle[1])) for cycle in BASE_CYCLES
        ]
        case = self._case_from_face_cases(reversed_cases)
        outputs = [case["first_ac_output"], case["second_ac_output"], case["third_ac_output"], case["fourth_ac_output"]]
        result = self._patched_result(case, outputs)

        self.assertEqual(result["classification"], s25ad.AD_TETRAHEDRAL_BOUNDARY_CLOSED)
        self.assertEqual(result["boundary_digest"], self.tetra_case["expected"]["boundary_digest"])

    def test_nontrivial_vertex_label_permutation_preserves_canonical_boundary(self) -> None:
        permutation = {"A": "C", "B": "A", "C": "D", "D": "B"}
        permuted_cases = [
            self._ac_case_from_cycle(tuple(permutation[label] for label in cycle))
            for cycle in BASE_CYCLES
        ]
        case = self._case_from_face_cases(permuted_cases)
        outputs = [case["first_ac_output"], case["second_ac_output"], case["third_ac_output"], case["fourth_ac_output"]]
        result = self._patched_result(case, outputs)

        self.assertEqual(result["classification"], s25ad.AD_TETRAHEDRAL_BOUNDARY_CLOSED)
        self.assertEqual(result["boundary_digest"], self.tetra_case["expected"]["boundary_digest"])
        self.assertEqual(result["ordered_faces"], s25ad.evaluate_tetrahedral_boundary(self.tetra_case)["ordered_faces"])

    def test_single_face_reversal_breaks_boundary_cancellation(self) -> None:
        cases = [fixtures.build_positive_s25ac_face_case(face_id) for face_id in FACE_IDS]
        cases[0] = self._ac_case_from_cycle(("B", "D", "C"))
        case = self._case_from_face_cases(cases, expected_positive=False)
        outputs = [case["first_ac_output"], case["second_ac_output"], case["third_ac_output"], case["fourth_ac_output"]]
        result = self._patched_result(case, outputs)

        self.assertEqual(result["classification"], s25ad.AD_NOT_TETRAHEDRAL)
        self.assertEqual(result["decision"], "HOLD")

    def test_duplicate_face_and_missing_face_are_not_closed(self) -> None:
        cases = [fixtures.build_positive_s25ac_face_case(face_id) for face_id in FACE_IDS]
        cases[3] = deepcopy(cases[0])
        case = self._case_from_face_cases(cases, expected_positive=False)
        outputs = [case["first_ac_output"], case["second_ac_output"], case["third_ac_output"], case["fourth_ac_output"]]
        result = self._patched_result(case, outputs)

        self.assertEqual(result["classification"], s25ad.AD_NOT_TETRAHEDRAL)
        self.assertEqual(result["status"], "TEST_BLOCKED")

    def test_nonpositive_ac_side_cannot_be_lifted_to_ad(self) -> None:
        nonpositive = ac_tests.W5S25ACTriangleTopologyTests._case_from_pairs(
            (("A", "B"), ("A", "C"), ("A", "D"))
        )
        nonpositive_output = s25ac.evaluate_triangle_topology(nonpositive)
        self.assertEqual(nonpositive_output["classification"], s25ac.AC_NOT_TRIANGLE)
        cases = [nonpositive] + [fixtures.build_positive_s25ac_face_case(face_id) for face_id in FACE_IDS[1:]]
        case = self._case_from_face_cases(cases, expected_positive=False)
        case["first_ac_output"] = nonpositive_output
        case["expected"]["first_ac_result_digest"] = self._digest(nonpositive_output)
        case["input_digest"] = s25ad.input_digest(case)

        result = s25ad.evaluate_tetrahedral_boundary(case)

        self.assertEqual(result["classification"], s25ad.AC_NOT_POSITIVE)
        self.assertEqual(result["decision"], "HOLD")

    def test_all_four_sides_are_attempted_and_first_failure_wins(self) -> None:
        with patch.object(
            s25ad,
            "evaluate_triangle_topology",
            side_effect=[RuntimeError("first"), self.tetra_outputs[1], self.tetra_outputs[2], self.tetra_outputs[3]],
        ) as mocked:
            result = s25ad.evaluate_tetrahedral_boundary(deepcopy(self.tetra_case))

        self.assertEqual(mocked.call_count, 4)
        self.assertEqual(result["classification"], s25ad.AC_REJECTED)
        self.assertEqual(result["reason"], "S25AC_RESULT_UNREADABLE")

    def test_supplied_ac_output_mismatch_is_rejected(self) -> None:
        case = deepcopy(self.tetra_case)
        case["first_ac_output"]["reason"] = "FORGED"
        case["input_digest"] = s25ad.input_digest(case)

        result = self._patched_result(case)

        self.assertEqual(result["classification"], s25ad.AC_REJECTED)
        self.assertEqual(result["reason"], "S25AC_RESULT_MISMATCH")

    def test_same_face_case_digest_drift_is_rejected(self) -> None:
        case = deepcopy(self.tetra_case)
        case["first_ac_case"]["input_digest"] = "f" * 64
        case["input_digest"] = s25ad.input_digest(case)

        result = self._patched_result(case)

        self.assertEqual(result["classification"], s25ad.AC_REJECTED)
        self.assertEqual(result["reason"], "S25AC_CASE_DIGEST_DRIFT")

    def test_forged_ac_triangle_digest_is_rejected(self) -> None:
        case = deepcopy(self.tetra_case)
        forged = deepcopy(case["first_ac_output"])
        forged["triangle_digest"] = "c" * 64
        case["first_ac_output"] = forged
        case["expected"]["first_ac_result_digest"] = self._digest(forged)
        case["input_digest"] = s25ad.input_digest(case)

        result = self._patched_result(case, [forged, *self.tetra_outputs[1:]])

        self.assertEqual(result["classification"], s25ad.AC_REJECTED)
        self.assertEqual(result["reason"], "S25AC_RESULT_INVALID")

    def test_boundary_witness_and_digest_drift_are_blocked(self) -> None:
        for mutation in ("witness", "digest"):
            with self.subTest(mutation=mutation):
                case = deepcopy(self.tetra_case)
                if mutation == "witness":
                    case["boundary_witness"]["ordered_faces"][0]["orientation"] = -1
                else:
                    case["expected"]["boundary_digest"] = "a" * 64
                case["input_digest"] = s25ad.input_digest(case)

                result = self._patched_result(case)

                self.assertEqual(result["classification"], s25ad.AD_REJECTED)
                self.assertIn(result["reason"], {"BOUNDARY_WITNESS_MISMATCH", "BOUNDARY_DIGEST_MISMATCH"})

    def test_full_opaque_vertex_equality_is_required(self) -> None:
        case = deepcopy(self.tetra_case)
        forged = deepcopy(case["first_ac_output"])
        forged["ordered_edges"][0]["from_edge"]["left_endpoint"]["y_result_digest"] = "d" * 64
        case["first_ac_output"] = forged
        case["expected"]["first_ac_result_digest"] = self._digest(forged)
        case["input_digest"] = s25ad.input_digest(case)

        result = self._patched_result(case, [forged, *self.tetra_outputs[1:]])

        self.assertEqual(result["classification"], s25ad.AC_REJECTED)
        self.assertEqual(result["reason"], "S25AC_RESULT_INVALID")

    def test_duplicate_json_keys_and_unsafe_parser_values_are_rejected(self) -> None:
        duplicate = b'{"schema_version":"x","schema_version":"y"}'
        self.assertEqual(s25ad.evaluate_tetrahedral_boundary(duplicate)["classification"], s25ad.INPUT_INVALID)

        case = deepcopy(self.tetra_case)
        case["boundary_witness"]["relation"] = "https://example.invalid/relation"
        case["input_digest"] = s25ad.input_digest(case)
        self.assertEqual(s25ad.evaluate_tetrahedral_boundary(case)["classification"], s25ad.INPUT_INVALID)

    def test_raw_parser_rejects_utf8_nan_depth_nodes_size_and_integer_overflow(self) -> None:
        deep = b"[" * 66 + b"0" + b"]" * 66
        many_nodes = b"[" + b",".join(b"0" for _ in range(300001)) + b"]"
        raw_inputs = (
            b"\xff",
            b'{"value":NaN}',
            deep,
            many_nodes,
            b"x" * (16 * 1024 * 1024 + 1),
            b'{"value":9223372036854775808}',
        )
        for raw in raw_inputs:
            with self.subTest(raw_prefix=raw[:16]):
                self.assertEqual(s25ad.evaluate_tetrahedral_boundary(raw)["classification"], s25ad.INPUT_INVALID)

    def test_recursive_input_and_input_immutability(self) -> None:
        recursive = deepcopy(self.tetra_case)
        loop: dict[str, object] = {}
        loop["self"] = loop
        recursive["boundary_witness"] = loop
        self.assertEqual(s25ad.evaluate_tetrahedral_boundary(recursive)["classification"], s25ad.INPUT_INVALID)

        case = deepcopy(self.tetra_case)
        before = deepcopy(case)
        first = self._patched_result(case)
        second = self._patched_result(deepcopy(case))
        third = self._patched_result(case)
        self.assertEqual(case, before)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_no_file_or_network_discovery_is_needed(self) -> None:
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch(
            "socket.socket", side_effect=AssertionError("network is forbidden")
        ):
            result = self._patched_result(deepcopy(self.tetra_case))
        self.assertEqual(result["classification"], s25ad.AD_TETRAHEDRAL_BOUNDARY_CLOSED)

    def test_public_boundary_is_test_only_and_non_geometric(self) -> None:
        source = Path(s25ad.__file__).read_text(encoding="utf-8")

        self.assertIn("w5_s25ac_triangle_topology", source)
        for forbidden in (
            "w5_s25ab",
            "w5_s25aa",
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
            "geometry",
            "physical",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("open(", source)
        self.assertNotIn("def write", source)
        self.assertNotIn("def commit", source)
        self.assertNotIn("def persist", source)

    def test_all_result_paths_have_exact_public_keys(self) -> None:
        invalid_case = self._case_from_face_cases(
            [fixtures.build_positive_s25ac_face_case(face_id) for face_id in FACE_IDS],
            expected_positive=False,
        )
        for case in (deepcopy(self.tetra_case), invalid_case):
            result = self._patched_result(
                case,
                [case["first_ac_output"], case["second_ac_output"], case["third_ac_output"], case["fourth_ac_output"]],
            )
            self.assertEqual(set(result), set(s25ad.RESULT_KEYS))


if __name__ == "__main__":
    unittest.main()
