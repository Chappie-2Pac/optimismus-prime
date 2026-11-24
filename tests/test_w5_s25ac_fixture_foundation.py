"""Unpatched positive AA/AB fixtures for the S25AC boundary card.

This module adds no AC relation.  It only exposes a small, independently
re-evaluable corpus of genuine positive S25AA edge cases and positive S25AB
pairings so the AC tests do not manufacture evaluator outputs.
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ab_endpoint_incidence as s25ab  # noqa: E402
import support.w5_s25aa_pairwise_identity as s25aa  # noqa: E402
import test_w5_s25ab_endpoint_incidence as s25ab_tests  # noqa: E402
import test_w5_s25ab_fixture_foundation as s25ab_fixtures  # noqa: E402


# Each identifier names one complete ordered AA edge.  The pairs were chosen
# so several independently positive AB incidences can be composed without
# changing any production or lower-layer fixture.
_EDGE_VARIANTS = {
    "A": ("alpha", "beta"),
    "B": ("alpha", "gamma"),
    "C": ("alpha", "delta"),
    "D": ("alpha", "epsilon"),
    "E": ("beta", "delta"),
}


@lru_cache(maxsize=None)
def _cached_aa_case(edge_id: str) -> dict[str, object]:
    try:
        left_variant, right_variant = _EDGE_VARIANTS[edge_id]
    except KeyError as exc:
        raise ValueError(f"unknown AA edge fixture: {edge_id!r}") from exc
    return s25ab_fixtures.build_positive_s25aa_case(left_variant, right_variant)


def build_positive_s25aa_edge_case(edge_id: str) -> dict[str, object]:
    """Return a fresh copy of one real positive AA edge case."""

    return deepcopy(_cached_aa_case(edge_id))


@lru_cache(maxsize=None)
def _cached_ab_case(left_edge_id: str, right_edge_id: str) -> dict[str, object]:
    left_case = _cached_aa_case(left_edge_id)
    right_case = _cached_aa_case(right_edge_id)
    case = s25ab_tests.W5S25ABEndpointIncidenceTests._case(
        ("alpha", "beta"),
        ("alpha", "gamma"),
        left_case=left_case,
        right_case=right_case,
    )
    output = s25ab.evaluate_endpoint_incidence(case)
    if output["classification"] != s25ab.AA_ONE_ENDPOINT_SHARED:
        raise AssertionError(f"fixture pairing is not positive: {left_edge_id}->{right_edge_id}")
    return case


def build_positive_s25ab_case(left_edge_id: str, right_edge_id: str) -> dict[str, object]:
    """Return a fresh positive AB case whose directed pair is edge_id→edge_id."""

    if left_edge_id not in _EDGE_VARIANTS or right_edge_id not in _EDGE_VARIANTS:
        raise ValueError(f"unknown AB edge fixture: {left_edge_id!r}->{right_edge_id!r}")
    return deepcopy(_cached_ab_case(left_edge_id, right_edge_id))


class W5S25ACFixtureFoundationTests(unittest.TestCase):
    def test_five_real_aa_edges_are_positive_and_distinct(self) -> None:
        cases = {edge_id: build_positive_s25aa_edge_case(edge_id) for edge_id in _EDGE_VARIANTS}
        outputs = {edge_id: s25aa.evaluate_pairwise_identity(case) for edge_id, case in cases.items()}

        self.assertEqual({output["classification"] for output in outputs.values()}, {"PAIR_SEPARATED"})
        self.assertEqual(len({output["left_identity"]["z_case_digest"] for output in outputs.values()}), 2)
        self.assertEqual(len({case["input_digest"] for case in cases.values()}), 5)
        self.assertTrue(all(output["status"] == "PROPOSAL_ONLY" for output in outputs.values()))

    def test_positive_ab_pairings_are_re_evaluable_without_patch(self) -> None:
        pairs = (("A", "B"), ("B", "C"), ("C", "A"), ("A", "D"), ("C", "E"))
        cases = {pair: build_positive_s25ab_case(*pair) for pair in pairs}
        outputs = {pair: s25ab.evaluate_endpoint_incidence(case) for pair, case in cases.items()}

        self.assertEqual({output["classification"] for output in outputs.values()}, {s25ab.AA_ONE_ENDPOINT_SHARED})
        self.assertEqual(len({case["input_digest"] for case in cases.values()}), len(pairs))
        self.assertTrue(all(output["decision"] == "DESIGN_ONLY" for output in outputs.values()))

    def test_unknown_fixture_ids_fail_before_construction(self) -> None:
        with self.assertRaises(ValueError):
            build_positive_s25aa_edge_case("F")
        with self.assertRaises(ValueError):
            build_positive_s25ab_case("A", "F")


if __name__ == "__main__":
    unittest.main()
