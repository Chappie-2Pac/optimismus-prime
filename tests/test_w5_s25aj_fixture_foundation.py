"""Independent literal fixtures for the W5-S25AJ training-record contract."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25aj_training_record as s25aj  # noqa: E402


_FIXTURES: dict[str, dict[str, object]] = {
    "ascii": {
        "training_mode": "self_supervised_continuation",
        "instruction": "Explain the bounded contract.",
        "input": "Use the literal training fields.",
        "output": "",
    },
    "unicode_whitespace": {
        "training_mode": "self_supervised_continuation",
        "instruction": "  Prüfe Unicode é und Marker🙂  ",
        "input": "\r\nEin gebundener Kontext.\u2003",
        "output": "",
    },
    "opaque_metadata": {
        "id": "unit-α",
        "source_path": "knowledge/opaque.md",
        "quality_status": "reviewed",
        "repair_flags": ["segmented", False, None, -0.0],
        "training_mode": "self_supervised_continuation",
        "instruction": "Keep metadata opaque.",
        "input": "The four fields are the contract.",
        "output": "",
    },
}


def build_positive_s25aj_case(name: str = "ascii") -> dict[str, object]:
    try:
        return deepcopy(_FIXTURES[name])
    except KeyError as exc:
        raise ValueError(f"unknown S25AJ fixture: {name!r}") from exc


class W5S25AJFixtureFoundationTests(unittest.TestCase):
    def test_literal_positive_variants_are_closed_and_actionless(self) -> None:
        for name in _FIXTURES:
            with self.subTest(name=name):
                result = s25aj.evaluate_training_record_case(build_positive_s25aj_case(name))
                self.assertEqual(result["classification"], "TRAINING_RECORD_CLOSED")
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["decision"], "PROPOSAL_ONLY")
                self.assertEqual(result["reason"], "training_record_closed")
                self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
                self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def test_literal_training_fields_are_not_derived_from_support_or_chappie(self) -> None:
        case = build_positive_s25aj_case("ascii")
        self.assertEqual(case["training_mode"], "self_supervised_continuation")
        self.assertEqual(case["instruction"], "Explain the bounded contract.")
        self.assertEqual(case["input"], "Use the literal training fields.")
        self.assertEqual(case["output"], "")
        result = s25aj.evaluate_training_record_case(case)
        self.assertEqual(result["classification"], "TRAINING_RECORD_CLOSED")

    def test_bounded_metadata_is_opaque_and_key_order_does_not_matter(self) -> None:
        case = build_positive_s25aj_case("opaque_metadata")
        mutated = deepcopy(case)
        mutated["id"] = "changed-id"
        mutated["source_path"] = "different/source.txt"
        mutated["quality_status"] = "unknown"
        self.assertEqual(
            s25aj.evaluate_training_record_case(case),
            s25aj.evaluate_training_record_case(mutated),
        )
        raw = json.dumps(case, ensure_ascii=False)
        reordered = json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertEqual(
            s25aj.evaluate_training_record_case(raw),
            s25aj.evaluate_training_record_case(reordered.encode("utf-8")),
        )

    def test_unknown_fixture_is_rejected_before_evaluation(self) -> None:
        with self.assertRaises(ValueError):
            build_positive_s25aj_case("unknown")


if __name__ == "__main__":
    unittest.main()

