"""Unpatched positive fixture corpus for the next S25AA boundary card.

This module is test-only infrastructure.  It does not add an AB relation; it
only exposes several independently re-evaluable positive Z cases so a later
relation can be tested without manufacturing evaluator outputs.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25t_receipt_provenance as s25t  # noqa: E402
import support.w5_s25u_provenance_monotonicity as s25u  # noqa: E402
import support.w5_s25v_projection_set_completeness as s25v  # noqa: E402
import support.w5_s25w_projection_delta as s25w  # noqa: E402
import support.w5_s25x_delta_claim_containment as s25x  # noqa: E402
import support.w5_s25y_claim_evidence_closure as s25y  # noqa: E402
import support.w5_s25z_coverage_verdict_partition as s25z  # noqa: E402
import test_w5_s25aa_pairwise_identity as s25aa_tests  # noqa: E402
import test_w5_s25t_receipt_provenance as s25t_tests  # noqa: E402
import test_w5_s25u_provenance_monotonicity as s25u_tests  # noqa: E402
import test_w5_s25v_projection_set_completeness as s25v_tests  # noqa: E402
import test_w5_s25w_projection_delta as s25w_tests  # noqa: E402
import test_w5_s25x_delta_claim_containment as s25x_tests  # noqa: E402
import test_w5_s25y_claim_evidence_closure as s25y_tests  # noqa: E402
import test_w5_s25z_coverage_verdict_partition as s25z_tests  # noqa: E402


_VARIANTS = {
    "alpha": ("observer-alpha", "s25r-receipt-bundle"),
    "beta": ("observer-beta", "s25r-receipt-bundle-beta"),
    "gamma": ("observer-gamma", "s25r-receipt-bundle-gamma"),
    "delta": ("observer-delta", "s25r-receipt-bundle-delta"),
    "epsilon": ("observer-epsilon", "s25r-receipt-bundle-epsilon"),
}


def _digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(raw).hexdigest()


def _build_t_variant_case(variant_id: str) -> dict[str, object]:
    try:
        observer_id, comparison_group = _VARIANTS[variant_id]
    except KeyError as exc:
        raise ValueError(f"unknown fixture variant: {variant_id!r}") from exc

    case = deepcopy(s25t_tests.build_complete_s25t_case())
    case["expected"]["observer_id"] = observer_id
    case["expected"]["comparison_group"] = comparison_group

    sources_by_id: dict[str, dict[str, object]] = {}
    for source in case["sources"]["sources"]:
        source["observer_id"] = observer_id
        source["comparison_group"] = comparison_group
        source["source_digest"] = s25t_tests.W5S25TReceiptProvenanceTests._source_digest(source)
        sources_by_id[source["source_id"]] = source
    case["sources"]["source_digests"] = [source["source_digest"] for source in case["sources"]["sources"]]
    case["sources"]["set_digest"] = s25t_tests.W5S25TReceiptProvenanceTests._source_set_digest(case["sources"])

    cells_by_source: dict[str, dict[str, object]] = {}
    for cell in case["window"]["expected_cells"]:
        cell["observer_id"] = observer_id
        cell["cell_digest"] = s25t_tests.W5S25TReceiptProvenanceTests._cell_digest(cell)
        cells_by_source[cell["source_id"]] = cell
    case["window"]["observer_id"] = observer_id
    case["window"]["comparison_group"] = comparison_group
    case["window"]["window_id"] = s25t_tests.W5S25TReceiptProvenanceTests._window_id(case["window"])
    case["window"]["window_digest"] = s25t_tests.W5S25TReceiptProvenanceTests._window_digest(case["window"])

    for observation in case["observations"]:
        observation["observer_id"] = observer_id
        observation["comparison_group"] = comparison_group
        observation["source_digest"] = sources_by_id[observation["source_id"]]["source_digest"]
        observation["cell_digest"] = cells_by_source[observation["source_id"]]["cell_digest"]
        observation["observation_digest"] = s25t_tests.W5S25TReceiptProvenanceTests._observation_digest(observation)

    case["expected"]["source_set_digest"] = case["sources"]["set_digest"]
    case["expected"]["window_digest"] = case["window"]["window_digest"]
    case["expected"]["observation_set_digest"] = s25t_tests.W5S25TReceiptProvenanceTests._observation_set_digest(
        case["observations"]
    )
    case["input_digest"] = s25t.input_digest(case)
    return case


def _build_w_case(v_case: dict[str, object]) -> dict[str, object]:
    v_output = s25v.evaluate_projection_set_completeness(v_case)
    case: dict[str, object] = {
        "schema_version": s25w.HARNESS_SCHEMA,
        "observation_mode": "TEST_ONLY",
        "canonicalization": s25w.CANONICALIZATION,
        "expected": {
            "s25v_case_digest": s25v.input_digest(v_case),
            "s25v_result_digest": _digest(v_output),
            "transition_kind": v_output["transition_kind"],
            "before_projection_set_digest": v_output["before_projection_set_digest"],
            "after_projection_set_digest": v_output["after_projection_set_digest"],
            "before_projection_order_digest": v_output["before_projection_order_digest"],
            "after_projection_order_digest": v_output["after_projection_order_digest"],
            "required_member_count": len(s25v.ALLOWED_MEMBER_IDS),
        },
        "s25v_case": v_case,
        "s25v_output": v_output,
        "input_digest": "",
    }
    case["input_digest"] = s25w.input_digest(case)
    return case


def _build_x_case(w_case: dict[str, object]) -> dict[str, object]:
    w_output = s25w.evaluate_projection_delta(w_case)
    w_case_digest = s25w.input_digest(w_case)
    w_result_digest = _digest(w_output)
    claim = s25x_tests.W5S25XDeltaClaimContainmentTests._claim_from_output(
        w_output,
        s25w_case_digest=w_case_digest,
        s25w_result_digest=w_result_digest,
    )
    case: dict[str, object] = {
        "schema_version": s25x.HARNESS_SCHEMA,
        "observation_mode": "TEST_ONLY",
        "canonicalization": s25x.CANONICALIZATION,
        "expected": {
            "s25w_case_digest": w_case_digest,
            "s25w_result_digest": w_result_digest,
            "claim_digest": _digest(claim),
            "required_member_count": len(s25w.ALLOWED_MEMBER_IDS),
        },
        "s25w_case": w_case,
        "s25w_output": w_output,
        "claim": claim,
        "input_digest": "",
    }
    case["input_digest"] = s25x.input_digest(case)
    return case


def build_positive_s25z_variant_case(variant_id: str) -> dict[str, object]:
    """Build one independently re-evaluable positive Z case without patches."""

    t_case = _build_t_variant_case(variant_id)
    u_case = s25u_tests.build_s25u_case_from_s25t_cases(t_case, deepcopy(t_case), "NO_CHANGE")
    v_case = s25v_tests.W5S25VProjectionSetCompletenessTests._case(u_case)
    w_case = _build_w_case(v_case)
    x_case = _build_x_case(w_case)
    y_case = s25y_tests.W5S25YClaimEvidenceClosureTests._case_from_x(
        x_case, s25x.evaluate_delta_claim_containment(x_case)
    )
    return s25z_tests.W5S25ZCoverageVerdictPartitionTests._case_from_y(
        y_case, s25y.evaluate_claim_evidence_closure(y_case)
    )


def build_positive_s25aa_case(left_variant_id: str, right_variant_id: str) -> dict[str, object]:
    """Build a positive AA pair from two real, unpatched positive Z variants."""

    return s25aa_tests.W5S25AAPairwiseIdentityTests._case(
        left_case=build_positive_s25z_variant_case(left_variant_id),
        right_case=build_positive_s25z_variant_case(right_variant_id),
    )


class W5S25ABFixtureFoundationTests(unittest.TestCase):
    def test_three_distinct_variants_are_positive_without_patch(self) -> None:
        cases = {variant_id: build_positive_s25z_variant_case(variant_id) for variant_id in _VARIANTS}
        outputs = {variant_id: s25z.evaluate_coverage_verdict_partition(case) for variant_id, case in cases.items()}

        self.assertEqual({output["classification"] for output in outputs.values()}, {s25z.VERDICT_COMPLETE})
        self.assertEqual(len({case["input_digest"] for case in cases.values()}), len(cases))
        self.assertEqual(len({output["y_case_digest"] for output in outputs.values()}), len(cases))
        self.assertTrue(all(output["status"] == "PROPOSAL_ONLY" for output in outputs.values()))
        self.assertTrue(all(output["decision"] == "DESIGN_ONLY" for output in outputs.values()))

    def test_positive_aa_pair_binds_two_real_z_variants(self) -> None:
        case = build_positive_s25aa_case("alpha", "beta")
        result = s25aa_tests.s25aa.evaluate_pairwise_identity(case)

        self.assertEqual(result["classification"], "PAIR_SEPARATED")
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertNotEqual(result["left_identity"], result["right_identity"])

    def test_same_variant_remains_non_separated_and_repeated_calls_are_stable(self) -> None:
        case = build_positive_s25aa_case("gamma", "gamma")
        before = deepcopy(case)

        first = s25aa_tests.s25aa.evaluate_pairwise_identity(case)
        second = s25aa_tests.s25aa.evaluate_pairwise_identity(deepcopy(case))

        self.assertEqual(first["classification"], "PAIR_NOT_SEPARATED")
        self.assertEqual(first, second)
        self.assertEqual(case, before)

    def test_fixture_builder_does_not_use_io_or_network(self) -> None:
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch(
            "socket.socket", side_effect=AssertionError("network is forbidden")
        ):
            case = build_positive_s25z_variant_case("beta")
            result = s25z.evaluate_coverage_verdict_partition(case)

        self.assertEqual(result["classification"], s25z.VERDICT_COMPLETE)

    def test_unknown_variant_is_rejected_before_construction(self) -> None:
        with self.assertRaises(ValueError):
            build_positive_s25z_variant_case("zeta")


if __name__ == "__main__":
    unittest.main()

