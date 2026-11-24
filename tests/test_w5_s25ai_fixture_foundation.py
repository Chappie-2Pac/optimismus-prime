"""Independent literal fixtures for the W5-S25AI knowledge-order relation."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ai_knowledge_order as s25ai  # noqa: E402


_FIXTURES: dict[str, tuple[dict[str, object], list[dict[str, object]]]] = {
    "content_cap": (
        {
            "query": "memory control plane archive bounded context record signal learning durable provenance witness",
            "entries": [
                {
                    "id": "cap",
                    "title": "Memory",
                    "tags": ["memory"],
                    "selected_text": "memory control plane archive bounded context record signal learning durable provenance witness",
                }
            ],
        },
        [{"id": "cap", "score": 15}],
    ),
    "nfkc_casefold": (
        {
            "query": "ＣＯＮＴＲＯＬ Straße",
            "entries": [
                {
                    "id": "unicode",
                    "title": "control STRASSE",
                    "tags": ["control"],
                    "selected_text": "control strasse",
                }
            ],
        },
        [{"id": "unicode", "score": 12}],
    ),
    "tie_break": (
        {
            "query": "alpha beta",
            "entries": [
                {"id": "zeta", "title": "Alpha", "tags": [], "selected_text": ""},
                {"id": "alpha", "title": "Beta", "tags": [], "selected_text": ""},
            ],
        },
        [{"id": "alpha", "score": 5}, {"id": "zeta", "score": 5}],
    ),
    "top_three": (
        {
            "query": "alpha",
            "entries": [
                {"id": "delta", "title": "Alpha", "tags": [], "selected_text": ""},
                {"id": "charlie", "title": "Alpha", "tags": [], "selected_text": ""},
                {"id": "bravo", "title": "Alpha", "tags": [], "selected_text": ""},
                {"id": "alpha", "title": "Alpha", "tags": [], "selected_text": ""},
            ],
        },
        [
            {"id": "alpha", "score": 5},
            {"id": "bravo", "score": 5},
            {"id": "charlie", "score": 5},
        ],
    ),
    "emoji_crlf": (
        {
            "query": "memory",
            "entries": [
                {
                    "id": "marker",
                    "title": "Memory",
                    "tags": ["memory"],
                    "selected_text": "marker🙂\r\nmemory",
                }
            ],
        },
        [{"id": "marker", "score": 6}],
    ),
}


def build_positive_s25ai_case(name: str = "content_cap") -> tuple[dict[str, object], list[dict[str, object]]]:
    try:
        case, expected = _FIXTURES[name]
    except KeyError as exc:
        raise ValueError(f"unknown S25AI fixture: {name!r}") from exc
    return deepcopy(case), deepcopy(expected)


class W5S25AIFixtureFoundationTests(unittest.TestCase):
    def test_literal_positive_variants_are_closed_and_actionless(self) -> None:
        for name in _FIXTURES:
            with self.subTest(name=name):
                case, expected = build_positive_s25ai_case(name)
                result = s25ai.evaluate_knowledge_order_case(case, observed_hits=expected)
                self.assertEqual(result["classification"], "KNOWLEDGE_ORDER_CLOSED")
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["decision"], "PROPOSAL_ONLY")
                self.assertEqual(result["expected_hit_count"], len(expected))
                self.assertEqual(result["observed_hit_count"], len(expected))
                self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
                self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def test_literal_golden_scores_are_not_derived_from_support_oracle(self) -> None:
        case, expected = build_positive_s25ai_case("content_cap")
        self.assertEqual(expected, [{"id": "cap", "score": 15}])
        self.assertEqual(
            s25ai.evaluate_knowledge_order_case(case, observed_hits=expected)["classification"],
            "KNOWLEDGE_ORDER_CLOSED",
        )

    def test_zero_expected_hits_are_a_closed_empty_projection(self) -> None:
        case = {
            "query": "memory",
            "entries": [
                {
                    "id": "content-only",
                    "title": "Archive",
                    "tags": [],
                    "selected_text": "memory appears only in content",
                }
            ],
        }
        result = s25ai.evaluate_knowledge_order_case(case, observed_hits=[])
        self.assertEqual(result["classification"], "KNOWLEDGE_ORDER_CLOSED")
        self.assertEqual(result["expected_hit_count"], 0)
        self.assertEqual(result["observed_hit_count"], 0)

    def test_unknown_fixture_is_rejected_before_evaluation(self) -> None:
        with self.assertRaises(ValueError):
            build_positive_s25ai_case("unknown")


if __name__ == "__main__":
    unittest.main()

