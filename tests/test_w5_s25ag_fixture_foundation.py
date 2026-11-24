"""Independent literal fixtures for the W5-S25AG renderer boundary."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ag_dual_renderer_projection as s25ag  # noqa: E402


_FIXTURES: dict[str, tuple[dict[str, str], str]] = {
    "ascii": (
        {
            "format": "s25ag.dual-render.v1",
            "instruction": "Explain the concept.",
            "input": "A useful source concept.",
            "output": "",
        },
        "<s>[INST]\nExplain the concept.\n\nA useful source concept.\n[/INST]",
    ),
    "empty_input": (
        {
            "format": "s25ag.dual-render.v1",
            "instruction": "Continue.",
            "input": "",
            "output": "",
        },
        "<s>[INST]\nContinue.\n[/INST]",
    ),
    "with_output": (
        {
            "format": "s25ag.dual-render.v1",
            "instruction": "Answer exactly.",
            "input": "A bounded question.",
            "output": "An exact answer.",
        },
        "<s>[INST]\nAnswer exactly.\n\nA bounded question.\n[/INST]An exact answer.",
    ),
    "unicode_crlf": (
        {
            "format": "s25ag.dual-render.v1",
            "instruction": "Mark e\u0301 and β🙂.",
            "input": "Line one\r\nLine two\tΩ.",
            "output": "",
        },
        "<s>[INST]\nMark e\u0301 and β🙂.\n\nLine one\r\nLine two\tΩ.\n[/INST]",
    ),
    "marker_content": (
        {
            "format": "s25ag.dual-render.v1",
            "instruction": "Keep [INST] and [/INST] as data.",
            "input": "Do not interpret <s> as a wrapper.",
            "output": "",
        },
        "<s>[INST]\nKeep [INST] and [/INST] as data.\n\nDo not interpret <s> as a wrapper.\n[/INST]",
    ),
}


def build_positive_s25ag_case(name: str = "ascii") -> tuple[dict[str, str], str]:
    try:
        record, golden = _FIXTURES[name]
    except KeyError as exc:
        raise ValueError(f"unknown S25AG fixture: {name!r}") from exc
    return deepcopy(record), golden


class W5S25AGFixtureFoundationTests(unittest.TestCase):
    def test_literal_positive_variants_are_closed_and_actionless(self) -> None:
        outputs = {}
        for name in _FIXTURES:
            record, golden = build_positive_s25ag_case(name)
            outputs[name] = s25ag.evaluate_dual_renderer_case(
                record,
                transformers_projection=golden,
                unsloth_projection=golden,
            )
        self.assertEqual({result["classification"] for result in outputs.values()}, {"DUAL_RENDER_CLOSED"})
        self.assertEqual({result["status"] for result in outputs.values()}, {"PASS"})
        self.assertEqual({result["decision"] for result in outputs.values()}, {"PROPOSAL_ONLY"})
        for result in outputs.values():
            self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
            self.assertEqual(result["authority_claim"], "NOT_CLAIMED")

    def test_literal_golden_strings_are_not_derived_from_support_oracle(self) -> None:
        record, golden = build_positive_s25ag_case("unicode_crlf")
        self.assertEqual(
            golden,
            "<s>[INST]\nMark e\u0301 and β🙂.\n\nLine one\r\nLine two\tΩ.\n[/INST]",
        )
        result = s25ag.evaluate_dual_renderer_case(
            record,
            transformers_projection=golden,
            unsloth_projection=golden,
        )
        self.assertEqual(result["classification"], "DUAL_RENDER_CLOSED")

    def test_fixture_preserves_optional_empty_input_and_marker_content(self) -> None:
        empty_record, empty_golden = build_positive_s25ag_case("empty_input")
        marker_record, marker_golden = build_positive_s25ag_case("marker_content")
        self.assertNotIn("\n\n", empty_golden)
        self.assertIn("[INST]", marker_record["instruction"])
        self.assertIn("<s>", marker_record["input"])
        for record, golden in ((empty_record, empty_golden), (marker_record, marker_golden)):
            with self.subTest(record=record):
                self.assertEqual(
                    s25ag.evaluate_dual_renderer_case(
                        record,
                        transformers_projection=golden,
                        unsloth_projection=golden,
                    )["classification"],
                    "DUAL_RENDER_CLOSED",
                )

    def test_unknown_fixture_is_rejected_before_evaluation(self) -> None:
        with self.assertRaises(ValueError):
            build_positive_s25ag_case("unknown")


if __name__ == "__main__":
    unittest.main()

