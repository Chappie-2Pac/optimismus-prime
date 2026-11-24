"""Unpatched positive AC face fixtures for the S25AD boundary card."""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ac_triangle_topology as s25ac  # noqa: E402
import test_w5_s25ac_triangle_topology as s25ac_tests  # noqa: E402


_FACE_PAIRS = {
    "FACE_123_POSITIVE": (("B", "C"), ("C", "D"), ("D", "B")),
    "FACE_023_NEGATIVE": (("A", "D"), ("D", "C"), ("C", "A")),
    "FACE_013_POSITIVE": (("A", "B"), ("B", "D"), ("D", "A")),
    "FACE_012_NEGATIVE": (("A", "C"), ("C", "B"), ("B", "A")),
}


@lru_cache(maxsize=None)
def _cached_face_case(face_id: str) -> dict[str, object]:
    try:
        pairs = _FACE_PAIRS[face_id]
    except KeyError as exc:
        raise ValueError(f"unknown AC face fixture: {face_id!r}") from exc
    return s25ac_tests.W5S25ACTriangleTopologyTests._case_from_pairs(pairs)


def build_positive_s25ac_face_case(face_id: str) -> dict[str, object]:
    """Return a fresh complete AC face case built from real positive AB pairs."""

    return deepcopy(_cached_face_case(face_id))


class W5S25ADFixtureFoundationTests(unittest.TestCase):
    def test_four_oriented_ac_faces_are_positive_without_patch(self) -> None:
        cases = {face_id: build_positive_s25ac_face_case(face_id) for face_id in _FACE_PAIRS}
        outputs = {face_id: s25ac.evaluate_triangle_topology(case) for face_id, case in cases.items()}

        self.assertEqual({output["classification"] for output in outputs.values()}, {s25ac.AC_TRIANGLE_CLOSED})
        self.assertEqual(len({case["input_digest"] for case in cases.values()}), 4)
        self.assertEqual(len({output["triangle_digest"] for output in outputs.values()}), 4)
        self.assertTrue(all(output["status"] == "PROPOSAL_ONLY" for output in outputs.values()))

    def test_each_face_contains_three_real_positive_ab_observations(self) -> None:
        cases = {face_id: build_positive_s25ac_face_case(face_id) for face_id in _FACE_PAIRS}
        for face_id, case in cases.items():
            with self.subTest(face=face_id):
                self.assertEqual(
                    {
                        case["first_ab_output"]["classification"],
                        case["second_ab_output"]["classification"],
                        case["third_ab_output"]["classification"],
                    },
                    {"AA_ONE_ENDPOINT_SHARED"},
                )

    def test_unknown_face_fixture_is_rejected_before_construction(self) -> None:
        with self.assertRaises(ValueError):
            build_positive_s25ac_face_case("FACE_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
