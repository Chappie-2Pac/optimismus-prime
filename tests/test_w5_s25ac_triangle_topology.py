"""Adversarial tests for the pure S25AC directed triangle relation."""

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

import support.w5_s25ab_endpoint_incidence as s25ab  # noqa: E402
import support.w5_s25ac_triangle_topology as s25ac  # noqa: E402
import test_w5_s25ab_endpoint_incidence as s25ab_tests  # noqa: E402
import test_w5_s25ab_fixture_foundation as s25ab_fixtures  # noqa: E402
import test_w5_s25ac_fixture_foundation as fixtures  # noqa: E402


IDENTITY_FIELDS = tuple(s25ac.IDENTITY_FIELDS)


class W5S25ACTriangleTopologyTests(unittest.TestCase):
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
    def _strict_equal(cls, left: object, right: object) -> bool:
        if type(left) is not type(right):
            return False
        if isinstance(left, dict):
            return set(left) == set(right) and all(cls._strict_equal(left[key], right[key]) for key in left)
        if isinstance(left, list):
            return len(left) == len(right) and all(
                cls._strict_equal(item, other) for item, other in zip(left, right)
            )
        return left == right

    @classmethod
    def _deepcopy_edge(cls, edge: dict[str, object]) -> dict[str, object]:
        return {
            "left_endpoint": deepcopy(edge["left_endpoint"]),
            "right_endpoint": deepcopy(edge["right_endpoint"]),
        }

    @classmethod
    def _directed_edge(cls, output: dict[str, object]) -> dict[str, object]:
        return {
            "from_edge": cls._deepcopy_edge(output["left_edge"]),
            "to_edge": cls._deepcopy_edge(output["right_edge"]),
        }

    @classmethod
    def _unique_vertices(cls, directed_edges: list[dict[str, object]]) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for directed in directed_edges:
            for edge_name in ("from_edge", "to_edge"):
                edge = directed[edge_name]
                if not any(cls._strict_equal(edge, existing) for existing in result):
                    result.append(cls._deepcopy_edge(edge))
        return result

    @classmethod
    def _topology_oracle(
        cls, outputs: list[dict[str, object]]
    ) -> tuple[str, list[dict[str, object]], list[dict[str, object]], str]:
        observed = [cls._directed_edge(output) for output in outputs]
        vertex_by_id: dict[int, dict[str, object]] = {}
        id_by_key: dict[bytes, int] = {}
        pairs: list[tuple[int, int]] = []

        def vertex_id(edge: dict[str, object]) -> int:
            key = cls._edge_key(edge)
            if key not in id_by_key:
                identifier = len(id_by_key)
                id_by_key[key] = identifier
                vertex_by_id[identifier] = cls._deepcopy_edge(edge)
            return id_by_key[key]

        for directed in observed:
            pairs.append((vertex_id(directed["from_edge"]), vertex_id(directed["to_edge"])))

        catalog_ids = sorted(vertex_by_id, key=lambda identifier: cls._edge_key(vertex_by_id[identifier]))
        catalog = [vertex_by_id[identifier] for identifier in catalog_ids]
        if any(source == target for source, target in pairs):
            relation = s25ac.AC_REJECTED
            return relation, observed, catalog, cls._topology_digest(observed, catalog, relation)
        if len(set(pairs)) != len(pairs) or any((target, source) in pairs for source, target in pairs):
            relation = s25ac.AC_REJECTED
            return relation, observed, catalog, cls._topology_digest(observed, catalog, relation)
        if len(vertex_by_id) != 3:
            relation = s25ac.AC_NOT_TRIANGLE
            return relation, observed, catalog, cls._topology_digest(observed, catalog, relation)

        sources = [source for source, _target in pairs]
        targets = [target for _source, target in pairs]
        if len(set(sources)) != 3 or len(set(targets)) != 3 or set(sources) != set(targets):
            relation = s25ac.AC_NOT_TRIANGLE
            return relation, observed, catalog, cls._topology_digest(observed, catalog, relation)

        next_by_source = dict(pairs)
        current = catalog_ids[0]
        ordered: list[dict[str, object]] = []
        for _ in range(3):
            target = next_by_source[current]
            ordered.append(
                {"from_edge": cls._deepcopy_edge(vertex_by_id[current]), "to_edge": cls._deepcopy_edge(vertex_by_id[target])}
            )
            current = target
        if current != catalog_ids[0]:
            relation = s25ac.AC_NOT_TRIANGLE
            return relation, observed, catalog, cls._topology_digest(observed, catalog, relation)
        relation = s25ac.AC_TRIANGLE_CLOSED
        return relation, ordered, catalog, cls._topology_digest(ordered, catalog, relation)

    @classmethod
    def _topology_digest(
        cls, ordered_edges: list[dict[str, object]], vertex_catalog: list[dict[str, object]], relation: str
    ) -> str:
        return cls._digest(
            {
                "schema": "s25ac.ordered-aa-edge-triangle-witness.v1",
                "topology_scope": "S25AB_ORDERED_AA_EDGE_TRIANGLE_CLOSURE_ONLY",
                "ordered_edges": deepcopy(ordered_edges),
                "vertex_catalog": deepcopy(vertex_catalog),
                "relation": relation,
            }
        )

    @classmethod
    def _case_from_pairs(cls, pairs: tuple[tuple[str, str], tuple[str, str], tuple[str, str]]) -> dict[str, object]:
        cases = [fixtures.build_positive_s25ab_case(*pair) for pair in pairs]
        outputs = [s25ab.evaluate_endpoint_incidence(case) for case in cases]
        relation, ordered_edges, vertex_catalog, triangle_digest = cls._topology_oracle(outputs)
        case: dict[str, object] = {
            "schema_version": s25ac.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25ac.CANONICALIZATION,
            "expected": {
                "first_ab_case_digest": s25ab.input_digest(cases[0]),
                "second_ab_case_digest": s25ab.input_digest(cases[1]),
                "third_ab_case_digest": s25ab.input_digest(cases[2]),
                "first_ab_result_digest": cls._digest(outputs[0]),
                "second_ab_result_digest": cls._digest(outputs[1]),
                "third_ab_result_digest": cls._digest(outputs[2]),
                "triangle_digest": triangle_digest,
            },
            "first_ab_case": cases[0],
            "first_ab_output": outputs[0],
            "second_ab_case": cases[1],
            "second_ab_output": outputs[1],
            "third_ab_case": cases[2],
            "third_ab_output": outputs[2],
            "topology_witness": {
                "ordered_edges": ordered_edges,
                "vertex_catalog": vertex_catalog,
                "relation": relation,
            },
            "input_digest": "",
        }
        case["input_digest"] = s25ac.input_digest(case)
        return case

    @classmethod
    def setUpClass(cls) -> None:
        cls.triangle_pairs = (("A", "B"), ("B", "C"), ("C", "A"))
        cls.triangle_case = cls._case_from_pairs(cls.triangle_pairs)
        cls.triangle_outputs = [
            deepcopy(cls.triangle_case["first_ab_output"]),
            deepcopy(cls.triangle_case["second_ab_output"]),
            deepcopy(cls.triangle_case["third_ab_output"]),
        ]

    def _patched_result(self, case: dict[str, object], outputs: list[dict[str, object]] | None = None) -> dict[str, object]:
        side_outputs = outputs or self.triangle_outputs
        with patch.object(s25ac, "evaluate_endpoint_incidence", side_effect=deepcopy(side_outputs)):
            return s25ac.evaluate_triangle_topology(case)

    def test_genuine_triangle_is_positive_and_proposal_only(self) -> None:
        result = s25ac.evaluate_triangle_topology(deepcopy(self.triangle_case))

        self.assertEqual(result["classification"], s25ac.AC_TRIANGLE_CLOSED)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["reason"], "AC_ORDERED_AA_EDGE_TRIANGLE_CLOSED")
        self.assertEqual(len(result["ordered_edges"]), 3)
        self.assertEqual(len(result["vertex_catalog"]), 3)
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def test_cyclic_rotation_is_same_closed_relation(self) -> None:
        rotated = self._case_from_pairs((("B", "C"), ("C", "A"), ("A", "B")))
        result = s25ac.evaluate_triangle_topology(rotated)

        self.assertEqual(result["classification"], s25ac.AC_TRIANGLE_CLOSED)
        self.assertEqual(result["triangle_digest"], self.triangle_case["expected"]["triangle_digest"])
        self.assertEqual(result["ordered_edges"], self.triangle_case["topology_witness"]["ordered_edges"])

    def test_star_and_chain_are_not_triangles(self) -> None:
        controls = {
            "star": (("A", "B"), ("A", "C"), ("A", "D")),
            "chain": (("A", "B"), ("B", "C"), ("C", "E")),
            "partial_reverse": (("A", "B"), ("C", "B"), ("C", "A")),
        }
        for label, pairs in controls.items():
            with self.subTest(topology=label):
                case = self._case_from_pairs(pairs)
                outputs = [case["first_ab_output"], case["second_ab_output"], case["third_ab_output"]]
                result = self._patched_result(case, outputs)
                self.assertEqual(result["classification"], s25ac.AC_NOT_TRIANGLE)
                self.assertEqual(result["status"], "TEST_BLOCKED")
                self.assertEqual(result["decision"], "HOLD")

    def test_duplicate_pair_and_reverse_pair_are_rejected(self) -> None:
        controls = {
            "duplicate": (("A", "B"), ("A", "B"), ("B", "C")),
            "reverse": (("A", "B"), ("B", "A"), ("B", "C")),
        }
        for label, pairs in controls.items():
            with self.subTest(topology=label):
                case = self._case_from_pairs(pairs)
                outputs = [case["first_ab_output"], case["second_ab_output"], case["third_ab_output"]]
                result = self._patched_result(case, outputs)
                self.assertEqual(result["classification"], s25ac.AC_REJECTED)
                self.assertEqual(result["reason"], "AC_TOPOLOGY_REJECTED")
                self.assertEqual(result["decision"], "HOLD")

    def test_self_loop_cannot_pass_the_positive_ab_gate(self) -> None:
        case = deepcopy(self.triangle_case)
        forged = deepcopy(case["first_ab_output"])
        forged["right_edge"] = deepcopy(forged["left_edge"])
        forged["match_matrix"] = {
            "left_left": True,
            "left_right": False,
            "right_left": False,
            "right_right": True,
        }
        case["first_ab_output"] = forged
        case["expected"]["first_ab_result_digest"] = self._digest(forged)
        case["input_digest"] = s25ac.input_digest(case)

        result = self._patched_result(case, [forged, self.triangle_outputs[1], self.triangle_outputs[2]])

        self.assertEqual(result["classification"], s25ac.S25AB_REJECTED)
        self.assertEqual(result["reason"], "S25AB_RESULT_INVALID")

    def test_nonpositive_ab_side_cannot_be_lifted_to_ac(self) -> None:
        same_aa = fixtures.build_positive_s25aa_edge_case("A")
        nonpositive_ab = s25ab_tests.W5S25ABEndpointIncidenceTests._case(
            ("alpha", "beta"),
            ("alpha", "beta"),
            left_case=same_aa,
            right_case=same_aa,
        )
        case = deepcopy(self.triangle_case)
        case["first_ab_case"] = nonpositive_ab
        case["first_ab_output"] = s25ab.evaluate_endpoint_incidence(nonpositive_ab)
        case["expected"]["first_ab_case_digest"] = s25ab.input_digest(nonpositive_ab)
        case["expected"]["first_ab_result_digest"] = self._digest(case["first_ab_output"])
        case["input_digest"] = s25ac.input_digest(case)

        result = s25ac.evaluate_triangle_topology(case)

        self.assertEqual(result["classification"], s25ac.S25AB_NOT_POSITIVE)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")

    def test_valid_ab_disjoint_relation_is_outside_the_ac_triangle_contract(self) -> None:
        left_aa = fixtures.build_positive_s25aa_edge_case("A")
        right_aa = s25ab_fixtures.build_positive_s25aa_case("gamma", "delta")
        disjoint_ab = s25ab_tests.W5S25ABEndpointIncidenceTests._case(
            ("alpha", "beta"),
            ("gamma", "delta"),
            left_case=left_aa,
            right_case=right_aa,
        )
        disjoint_output = s25ab.evaluate_endpoint_incidence(disjoint_ab)
        self.assertEqual(disjoint_output["classification"], s25ab.AA_ENDPOINTS_DISJOINT)

        case = deepcopy(self.triangle_case)
        case["first_ab_case"] = disjoint_ab
        case["first_ab_output"] = disjoint_output
        case["expected"]["first_ab_case_digest"] = s25ab.input_digest(disjoint_ab)
        case["expected"]["first_ab_result_digest"] = self._digest(disjoint_output)
        case["input_digest"] = s25ac.input_digest(case)

        result = self._patched_result(
            case,
            [disjoint_output, self.triangle_outputs[1], self.triangle_outputs[2]],
        )

        self.assertEqual(result["classification"], s25ac.S25AB_NOT_POSITIVE)
        self.assertEqual(result["reason"], s25ac.S25AB_NOT_POSITIVE)

    def test_rejected_ab_side_is_not_misclassified_as_nonpositive(self) -> None:
        rejected_ab = fixtures.build_positive_s25ab_case("A", "B")
        rejected_ab["endpoint_witness"]["relation"] = s25ab.AA_EDGE_SAME
        rejected_ab["input_digest"] = s25ab.input_digest(rejected_ab)
        rejected_output = s25ab.evaluate_endpoint_incidence(rejected_ab)
        self.assertEqual(rejected_output["classification"], s25ab.AA_ENDPOINT_WITNESS_MISMATCH)

        case = deepcopy(self.triangle_case)
        case["first_ab_case"] = rejected_ab
        case["first_ab_output"] = rejected_output
        case["expected"]["first_ab_case_digest"] = s25ab.input_digest(rejected_ab)
        case["expected"]["first_ab_result_digest"] = self._digest(rejected_output)
        case["input_digest"] = s25ac.input_digest(case)

        result = s25ac.evaluate_triangle_topology(case)

        self.assertEqual(result["classification"], s25ac.S25AB_REJECTED)
        self.assertEqual(result["reason"], s25ac.S25AB_REJECTED)

    def test_all_three_sides_are_attempted_and_first_failure_wins(self) -> None:
        outputs = self.triangle_outputs
        with patch.object(
            s25ac,
            "evaluate_endpoint_incidence",
            side_effect=[RuntimeError("first"), outputs[1], outputs[2]],
        ) as mocked:
            result = s25ac.evaluate_triangle_topology(deepcopy(self.triangle_case))

        self.assertEqual(mocked.call_count, 3)
        self.assertEqual(result["classification"], s25ac.S25AB_REJECTED)
        self.assertEqual(result["reason"], "S25AB_RESULT_UNREADABLE")

    def test_supplied_ab_output_mismatch_is_rejected(self) -> None:
        case = deepcopy(self.triangle_case)
        case["first_ab_output"]["reason"] = "FORGED"
        case["input_digest"] = s25ac.input_digest(case)

        result = self._patched_result(case)

        self.assertEqual(result["classification"], s25ac.S25AB_REJECTED)
        self.assertEqual(result["reason"], "S25AB_RESULT_MISMATCH")

    def test_ab_case_digest_binding_mismatch_is_rejected(self) -> None:
        case = deepcopy(self.triangle_case)
        case["first_ab_case"]["input_digest"] = "f" * 64
        case["input_digest"] = s25ac.input_digest(case)

        result = self._patched_result(case)

        self.assertEqual(result["classification"], s25ac.S25AB_REJECTED)
        self.assertEqual(result["reason"], "S25AB_CASE_DIGEST_DRIFT")

    def test_ab_result_witness_is_revalidated_on_public_boundary(self) -> None:
        case = deepcopy(self.triangle_case)
        forged_output = deepcopy(case["first_ab_output"])
        forged_output["match_matrix"]["left_left"] = not forged_output["match_matrix"]["left_left"]
        case["first_ab_output"] = forged_output
        case["expected"]["first_ab_result_digest"] = self._digest(forged_output)
        case["input_digest"] = s25ac.input_digest(case)

        result = self._patched_result(case, [forged_output, self.triangle_outputs[1], self.triangle_outputs[2]])

        self.assertEqual(result["classification"], s25ac.S25AB_REJECTED)
        self.assertEqual(result["reason"], "S25AB_RESULT_INVALID")

    def test_topology_witness_and_digest_drift_are_blocked(self) -> None:
        for mutation in ("witness", "digest"):
            with self.subTest(mutation=mutation):
                case = deepcopy(self.triangle_case)
                if mutation == "witness":
                    case["topology_witness"]["relation"] = s25ac.AC_NOT_TRIANGLE
                else:
                    case["expected"]["triangle_digest"] = "a" * 64
                case["input_digest"] = s25ac.input_digest(case)

                result = self._patched_result(case)

                self.assertEqual(result["classification"], s25ac.AC_REJECTED)
                self.assertIn(result["reason"], {"TOPOLOGY_WITNESS_MISMATCH", "TRIANGLE_DIGEST_MISMATCH"})

    def test_endpoint_equality_is_full_and_not_z_digest_only(self) -> None:
        case = deepcopy(self.triangle_case)
        forged = deepcopy(case["first_ab_output"])
        forged["left_edge"]["left_endpoint"]["y_result_digest"] = "c" * 64
        forged["match_matrix"] = {
            "left_left": True,
            "left_right": False,
            "right_left": False,
            "right_right": False,
        }
        case["first_ab_output"] = forged
        case["expected"]["first_ab_result_digest"] = self._digest(forged)
        case["input_digest"] = s25ac.input_digest(case)

        result = self._patched_result(case, [forged, self.triangle_outputs[1], self.triangle_outputs[2]])

        self.assertEqual(result["classification"], s25ac.S25AB_REJECTED)
        self.assertEqual(result["reason"], "S25AB_RESULT_INVALID")

    def test_forged_ab_endpoint_digest_is_rejected(self) -> None:
        case = deepcopy(self.triangle_case)
        forged = deepcopy(case["first_ab_output"])
        forged["endpoint_relation_digest"] = "c" * 64
        case["first_ab_output"] = forged
        case["expected"]["first_ab_result_digest"] = self._digest(forged)
        case["input_digest"] = s25ac.input_digest(case)

        result = self._patched_result(case, [forged, self.triangle_outputs[1], self.triangle_outputs[2]])

        self.assertEqual(result["classification"], s25ac.S25AB_REJECTED)
        self.assertEqual(result["reason"], "S25AB_RESULT_INVALID")

    def test_duplicate_json_keys_and_unsafe_parser_values_are_rejected(self) -> None:
        raw_duplicate = b'{\"schema_version\":\"x\",\"schema_version\":\"y\"}'
        self.assertEqual(s25ac.evaluate_triangle_topology(raw_duplicate)["classification"], s25ac.INPUT_INVALID)

        case = deepcopy(self.triangle_case)
        case["topology_witness"]["relation"] = "https://example.invalid/relation"
        case["input_digest"] = s25ac.input_digest(case)
        self.assertEqual(s25ac.evaluate_triangle_topology(case)["classification"], s25ac.INPUT_INVALID)

    def test_raw_parser_rejects_utf8_nan_depth_nodes_size_and_integer_overflow(self) -> None:
        deep = b"[" * 66 + b"0" + b"]" * 66
        many_nodes = b"[" + b",".join(b"0" for _ in range(150001)) + b"]"
        raw_inputs = (
            b"\xff",
            b"{\"value\":NaN}",
            deep,
            many_nodes,
            b"x" * (8 * 1024 * 1024 + 1),
            b"{\"value\":9223372036854775808}",
        )
        for raw in raw_inputs:
            with self.subTest(raw_prefix=raw[:16]):
                self.assertEqual(s25ac.evaluate_triangle_topology(raw)["classification"], s25ac.INPUT_INVALID)

    def test_recursive_input_budget_and_input_immutability(self) -> None:
        recursive = deepcopy(self.triangle_case)
        loop: dict[str, object] = {}
        loop["self"] = loop
        recursive["topology_witness"] = loop
        self.assertEqual(s25ac.evaluate_triangle_topology(recursive)["classification"], s25ac.INPUT_INVALID)

        case = deepcopy(self.triangle_case)
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
            result = self._patched_result(deepcopy(self.triangle_case))
        self.assertEqual(result["classification"], s25ac.AC_TRIANGLE_CLOSED)

    def test_public_boundary_is_test_only_and_non_temporal(self) -> None:
        source = Path(s25ac.__file__).read_text(encoding="utf-8")

        self.assertIn("w5_s25ab_endpoint_incidence", source)
        for forbidden in (
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
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("open(", source)
        self.assertNotIn("def write", source)
        self.assertNotIn("def commit", source)
        self.assertNotIn("def persist", source)

    def test_all_result_paths_have_exact_public_keys(self) -> None:
        controls = (
            deepcopy(self.triangle_case),
            self._case_from_pairs((("A", "B"), ("A", "C"), ("A", "D"))),
            self._case_from_pairs((("A", "B"), ("A", "B"), ("B", "C"))),
        )
        for case in controls:
            result = self._patched_result(
                case,
                [case["first_ab_output"], case["second_ab_output"], case["third_ab_output"]],
            )
            self.assertEqual(set(result), set(s25ac.RESULT_KEYS))


if __name__ == "__main__":
    unittest.main()
