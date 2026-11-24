"""Literal foundation cases for S25AP."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25ap_chappie_static_capability_membership as s25ap  # noqa: E402


ALLOWED = (
    "analyze",
    "compare",
    "document",
    "suggest",
    "evaluate",
    "structure",
    "clarify",
)
FORBIDDEN = (
    "self_modify",
    "set_goals",
    "self_preservation",
    "autonomous_action",
    "replicate",
    "override_constraints",
)


class W5S25APFixtureFoundationTests(unittest.TestCase):
    def test_literal_allowed_capability_is_exact_bool_true(self) -> None:
        for capability in ALLOWED:
            with self.subTest(capability=capability):
                result = s25ap.evaluate_chappie_static_capability_membership(
                    capability
                )
                self.assertIs(type(result), bool)
                self.assertIs(result, True)

    def test_literal_forbidden_capability_is_exact_bool_false(self) -> None:
        for capability in FORBIDDEN:
            with self.subTest(capability=capability):
                result = s25ap.evaluate_chappie_static_capability_membership(
                    capability
                )
                self.assertIs(type(result), bool)
                self.assertIs(result, False)

    def test_unknown_capability_is_default_deny(self) -> None:
        for capability in ("unknown_capability", "analyze ", " Analyze", ""):
            with self.subTest(capability=repr(capability)):
                result = s25ap.evaluate_chappie_static_capability_membership(
                    capability
                )
                self.assertIs(type(result), bool)
                self.assertIs(result, False)


if __name__ == "__main__":
    unittest.main()
