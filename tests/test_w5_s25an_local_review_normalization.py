"""Adversarial tests for the S25AN local review-normalization oracle."""

from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPORT_PATH = (
    REPO_ROOT
    / "tests"
    / "support"
    / "w5_s25an_local_review_normalization.py"
)
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import support.w5_s25an_local_review_normalization as s25an  # noqa: E402


def valid_finding(path="src/a.py", reason="broken") -> dict[str, object]:
    return {"path": path, "reason": reason}


def identity_snapshot(value: object) -> object:
    if type(value) is dict:
        return (
            "dict",
            id(value),
            tuple(
                (key, identity_snapshot(nested_value))
                for key, nested_value in value.items()
            ),
        )
    if type(value) is list:
        return (
            "list",
            id(value),
            tuple(identity_snapshot(nested_value) for nested_value in value),
        )
    return ("scalar", id(value), type(value), value)


class W5S25ANLocalReviewNormalizationTests(unittest.TestCase):
    def _assert_unchanged(
        self,
        review: dict[str, object],
        before: dict[str, object],
        before_identity: object,
    ) -> None:
        self.assertEqual(review, before)
        self.assertEqual(identity_snapshot(review), before_identity)

    def _assert_success(
        self,
        result: object,
        status: str,
        findings: list[object],
        summary: object,
    ) -> None:
        self.assertIs(type(result), dict)
        self.assertEqual(tuple(result), ("status", "findings", "summary"))
        self.assertEqual(
            result,
            {"status": status, "findings": findings, "summary": summary},
        )
        self.assertIs(type(result["status"]), str)
        self.assertIs(type(result["findings"]), list)
        self.assertIs(type(result["summary"]), type(summary))
        for finding in result["findings"]:
            self.assertIs(type(finding), dict)
            self.assertEqual(tuple(finding), ("path", "reason"))

    def test_all_statuses_and_findings_defaults(self) -> None:
        for status in ("pass", "blocked"):
            with self.subTest(status=status):
                result = s25an.evaluate_local_review_normalization_case(
                    {"status": status}
                )
                self._assert_success(result, status, [], "")

        result = s25an.evaluate_local_review_normalization_case(
            {"status": "fail", "findings": [valid_finding()]}
        )
        self._assert_success(
            result,
            "fail",
            [{"path": "src/a.py", "reason": "broken"}],
            "",
        )

        result = s25an.evaluate_local_review_normalization_case(
            {"status": "blocked", "findings": [valid_finding()]}
        )
        self._assert_success(
            result,
            "blocked",
            [{"path": "src/a.py", "reason": "broken"}],
            "",
        )

    def test_invalid_hashable_statuses_keep_exact_error(self) -> None:
        for status in (None, False, 0, "", "unknown", 1):
            with self.subTest(status=repr(status)):
                review = {
                    "status": status,
                    "findings": [{"path": "a", "reason": "b"}],
                }
                before = deepcopy(review)
                before_identity = identity_snapshot(review)
                with self.assertRaisesRegex(
                    ValueError,
                    r"^Reviewstatus muss pass, fail oder blocked sein$",
                ):
                    s25an.evaluate_local_review_normalization_case(review)
                self._assert_unchanged(review, before, before_identity)

    def test_unhashable_status_keeps_native_type_error_precedence(self) -> None:
        for status in ([], {}):
            with self.subTest(status_type=type(status).__name__):
                review = {"status": status, "findings": "bad"}
                before = deepcopy(review)
                before_identity = identity_snapshot(review)
                with self.assertRaises(TypeError):
                    s25an.evaluate_local_review_normalization_case(review)
                self._assert_unchanged(review, before, before_identity)

    def test_findings_gate_accepts_only_lists(self) -> None:
        for status in ("pass", "fail", "blocked"):
            for findings in (None, False, 0, "", {}, "bad"):
                with self.subTest(status=status, findings=repr(findings)):
                    review = {"status": status, "findings": findings}
                    before = deepcopy(review)
                    before_identity = identity_snapshot(review)
                    with self.assertRaisesRegex(
                        ValueError,
                        r"^findings muss eine Liste sein$",
                    ):
                        s25an.evaluate_local_review_normalization_case(review)
                    self._assert_unchanged(review, before, before_identity)

    def test_malformed_findings_keep_exact_error(self) -> None:
        malformed = (
            None,
            False,
            0,
            "",
            [],
            {},
            "finding",
            1,
            True,
            ["truthy"],
            {"path": "src/a.py"},
            {"reason": "broken"},
        )
        for status in ("pass", "blocked", "fail"):
            for finding in malformed:
                with self.subTest(status=status, finding=repr(finding)):
                    review = {"status": status, "findings": [finding]}
                    before = deepcopy(review)
                    before_identity = identity_snapshot(review)
                    with self.assertRaisesRegex(
                        ValueError,
                        r"^Jeder Reviewbefund braucht path und reason$",
                    ):
                        s25an.evaluate_local_review_normalization_case(review)
                    self._assert_unchanged(review, before, before_identity)

        valid = valid_finding()
        for status in ("pass", "blocked", "fail"):
            for findings in ([valid, {}], [{}, valid]):
                with self.subTest(status=status, findings=repr(findings)):
                    review = {"status": status, "findings": findings}
                    before = deepcopy(review)
                    before_identity = identity_snapshot(review)
                    with self.assertRaisesRegex(
                        ValueError,
                        r"^Jeder Reviewbefund braucht path und reason$",
                    ):
                        s25an.evaluate_local_review_normalization_case(review)
                    self._assert_unchanged(review, before, before_identity)

    def test_all_json_falsy_path_and_reason_values_are_rejected(self) -> None:
        falsy = (None, False, 0, "", [], {})
        for field in ("path", "reason"):
            for value in falsy:
                with self.subTest(field=field, value=repr(value)):
                    finding = valid_finding()
                    finding[field] = value
                    review = {"status": "pass", "findings": [finding]}
                    before = deepcopy(review)
                    before_identity = identity_snapshot(review)
                    with self.assertRaisesRegex(
                        ValueError,
                        r"^Jeder Reviewbefund braucht path und reason$",
                    ):
                        s25an.evaluate_local_review_normalization_case(review)
                    self._assert_unchanged(review, before, before_identity)

    def test_findings_are_ordered_reduced_and_values_are_not_copied(self) -> None:
        path_value = {"path": "object"}
        reason_value = ["reason"]
        findings = [
            {
                "path": path_value,
                "reason": reason_value,
                "ignored": True,
            },
            valid_finding("second.py", "second"),
        ]
        review = {"status": "pass", "findings": findings}
        result = s25an.evaluate_local_review_normalization_case(review)
        self._assert_success(
            result,
            "pass",
            [
                {"path": path_value, "reason": reason_value},
                {"path": "second.py", "reason": "second"},
            ],
            "",
        )
        self.assertIs(result["findings"][0]["path"], path_value)
        self.assertIs(result["findings"][0]["reason"], reason_value)
        self.assertNotIn("ignored", result["findings"][0])

        truthy_values = (1, 2.5, True, "truthy", [1], {"object": True})
        for path_value in truthy_values:
            for reason_value in truthy_values:
                with self.subTest(
                    path_type=type(path_value).__name__,
                    reason_type=type(reason_value).__name__,
                ):
                    result = s25an.evaluate_local_review_normalization_case(
                        {
                            "status": "pass",
                            "findings": [
                                {"path": path_value, "reason": reason_value}
                            ],
                        }
                    )
                    self._assert_success(
                        result,
                        "pass",
                        [{"path": path_value, "reason": reason_value}],
                        "",
                    )
                    self.assertIs(
                        type(result["findings"][0]["path"]), type(path_value)
                    )
                    self.assertIs(
                        type(result["findings"][0]["reason"]),
                        type(reason_value),
                    )
                    if type(path_value) in (list, dict):
                        self.assertIs(
                            result["findings"][0]["path"], path_value
                        )
                    if type(reason_value) in (list, dict):
                        self.assertIs(
                            result["findings"][0]["reason"], reason_value
                        )

    def test_summary_defaults_and_passes_through_any_json_value(self) -> None:
        for status in ("pass", "blocked", "fail"):
            for summary in (None, False, 0, True, 1, 2.5, [], {}, "summary"):
                with self.subTest(status=status, summary=repr(summary)):
                    findings = [valid_finding()] if status == "fail" else []
                    review = {
                        "status": status,
                        "findings": findings,
                        "summary": summary,
                    }
                    before = deepcopy(review)
                    before_identity = identity_snapshot(review)
                    result = s25an.evaluate_local_review_normalization_case(
                        review
                    )
                    self._assert_success(result, status, findings, summary)
                    self._assert_unchanged(review, before, before_identity)
                    if isinstance(summary, (list, dict)):
                        self.assertIs(result["summary"], summary)

    def test_exception_precedence_is_exact(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            r"^Reviewstatus muss pass, fail oder blocked sein$",
        ):
            s25an.evaluate_local_review_normalization_case(
                {"status": "unknown", "findings": "bad"}
            )

        with self.assertRaisesRegex(
            ValueError,
            r"^Jeder Reviewbefund braucht path und reason$",
        ):
            s25an.evaluate_local_review_normalization_case(
                {"status": "fail", "findings": [{}]}
            )

        with self.assertRaisesRegex(
            ValueError,
            r"^fail benötigt mindestens einen konkreten Befund$",
        ):
            s25an.evaluate_local_review_normalization_case(
                {"status": "fail", "findings": []}
            )

    def test_error_paths_preserve_input_identity(self) -> None:
        cases = (
            (
                {"status": "unknown", "findings": "bad"},
                ValueError,
                r"^Reviewstatus muss pass, fail oder blocked sein$",
            ),
            (
                {"status": [], "findings": "bad"},
                TypeError,
                None,
            ),
            (
                {"status": "pass", "findings": {}},
                ValueError,
                r"^findings muss eine Liste sein$",
            ),
            (
                {"status": "fail", "findings": []},
                ValueError,
                r"^fail benötigt mindestens einen konkreten Befund$",
            ),
            (
                {"status": "fail", "findings": [{}]},
                ValueError,
                r"^Jeder Reviewbefund braucht path und reason$",
            ),
            (
                {
                    "status": "pass",
                    "findings": [{"path": "", "reason": "x"}],
                },
                ValueError,
                r"^Jeder Reviewbefund braucht path und reason$",
            ),
        )
        for review, error_type, error_regex in cases:
            with self.subTest(review=repr(review)):
                before = deepcopy(review)
                before_identity = identity_snapshot(review)
                if error_regex is None:
                    with self.assertRaises(error_type):
                        s25an.evaluate_local_review_normalization_case(review)
                else:
                    with self.assertRaisesRegex(error_type, error_regex):
                        s25an.evaluate_local_review_normalization_case(review)
                self._assert_unchanged(review, before, before_identity)

    def test_extra_keys_input_order_and_nonmutation_are_preserved(self) -> None:
        finding = {"reason": "broken", "path": "src/a.py", "extra": 1}
        review = {
            "summary": ["summary"],
            "extra_root": {"ignored": True},
            "findings": [finding],
            "status": "pass",
        }
        before = deepcopy(review)
        before_identity = identity_snapshot(review)
        result = s25an.evaluate_local_review_normalization_case(review)
        self._assert_success(
            result,
            "pass",
            [{"path": "src/a.py", "reason": "broken"}],
            review["summary"],
        )
        self._assert_unchanged(review, before, before_identity)
        self.assertIs(result["summary"], review["summary"])

    def test_output_mutation_does_not_create_cross_call_state(self) -> None:
        review_without_findings = {"status": "pass"}
        first = s25an.evaluate_local_review_normalization_case(
            review_without_findings
        )
        first_before_mutation = deepcopy(first)
        first["findings"].append({"path": "tampered", "reason": "tampered"})
        second = s25an.evaluate_local_review_normalization_case(
            review_without_findings
        )
        self.assertIsNot(first, second)
        self.assertIsNot(first["findings"], second["findings"])
        self.assertEqual(
            first,
            {
                **first_before_mutation,
                "findings": [
                    {"path": "tampered", "reason": "tampered"}
                ],
            },
        )
        self._assert_success(second, "pass", [], "")

        path_value = {"path": "object"}
        reason_value = ["reason"]
        summary_value = {"summary": True}
        review = {
            "status": "pass",
            "findings": [{"path": path_value, "reason": reason_value}],
            "summary": summary_value,
        }
        input_findings = review["findings"]
        input_finding = input_findings[0]
        first = s25an.evaluate_local_review_normalization_case(review)
        self.assertIsNot(first["findings"], input_findings)
        self.assertIsNot(first["findings"][0], input_finding)
        first["findings"][0]["extra"] = "output-only"
        first["findings"].append({"path": "output", "reason": "output"})
        first["summary"] = "replaced"
        second = s25an.evaluate_local_review_normalization_case(review)
        self.assertIsNot(first, second)
        self.assertIsNot(first["findings"], second["findings"])
        self._assert_success(
            second,
            "pass",
            [{"path": path_value, "reason": reason_value}],
            summary_value,
        )
        self.assertIs(second["findings"][0]["path"], path_value)
        self.assertIs(second["findings"][0]["reason"], reason_value)
        self.assertIs(second["summary"], summary_value)

    def test_mutable_findings_are_fresh_for_every_status(self) -> None:
        for status in ("pass", "blocked", "fail"):
            with self.subTest(status=status):
                path_value = {"path": status}
                reason_value = [status]
                input_finding = {
                    "path": path_value,
                    "reason": reason_value,
                    "ignored": True,
                }
                input_findings = [input_finding]
                summary_value = {"status": status}
                review = {
                    "status": status,
                    "findings": input_findings,
                    "summary": summary_value,
                }

                first = s25an.evaluate_local_review_normalization_case(review)
                self.assertIsNot(first["findings"], input_findings)
                self.assertIsNot(first["findings"][0], input_finding)
                self.assertIs(first["findings"][0]["path"], path_value)
                self.assertIs(first["findings"][0]["reason"], reason_value)
                self.assertIs(first["summary"], summary_value)

                first["findings"][0]["output_only"] = True
                first["findings"].append(
                    {"path": "output", "reason": "output"}
                )
                second = s25an.evaluate_local_review_normalization_case(review)
                self.assertIsNot(first, second)
                self.assertIsNot(first["findings"], second["findings"])
                self.assertIsNot(second["findings"][0], input_finding)
                self._assert_success(
                    second,
                    status,
                    [{"path": path_value, "reason": reason_value}],
                    summary_value,
                )
                self.assertNotIn("output_only", second["findings"][0])
                self.assertIs(second["summary"], summary_value)

    def test_support_import_surface_is_stdlib_only_and_effect_free(self) -> None:
        source = SUPPORT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        self.assertEqual(imports, ["__future__"])
        for forbidden in (
            "ki-workflow",
            "normalize_review",
            "subprocess",
            "socket",
            "pathlib",
            "open(",
            "read_text",
            "write_text",
        ):
            self.assertNotIn(forbidden, source)
        allowed_names = {"ValueError", "isinstance"}
        allowed_attributes = {"get", "append"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                self.assertIn(node.func.id, allowed_names)
            else:
                self.assertIsInstance(node.func, ast.Attribute)
                self.assertIn(node.func.attr, allowed_attributes)


if __name__ == "__main__":
    unittest.main()
