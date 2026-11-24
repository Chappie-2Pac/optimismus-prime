"""Adversarial tests for the pure S25Z coverage-verdict partition."""

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

import support.w5_s25y_claim_evidence_closure as s25y  # noqa: E402
import support.w5_s25z_coverage_verdict_partition as s25z  # noqa: E402
import support.w5_s25x_delta_claim_containment as s25x  # noqa: E402
import test_w5_s25x_delta_claim_containment as s25x_tests  # noqa: E402
import test_w5_s25y_claim_evidence_closure as s25y_tests  # noqa: E402


ATOM_ORDER = (
    "X_CASE_BINDING",
    "X_RESULT_BINDING",
    "CLAIM_SCOPE",
    "TRANSITION",
    "MEMBER_DELTA",
    "MEMBER_PROVENANCE",
    "AUTHORITY_BOUNDARY",
)


class W5S25ZCoverageVerdictPartitionTests(unittest.TestCase):
    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _verdict(cls, output: dict[str, object]) -> dict[str, object]:
        covered = set(output["covered_atom_ids"])
        uncovered = set(output["uncovered_atom_ids"])
        return {
            "coverage_digest": output["coverage_digest"],
            "classification": output["classification"],
            "covered_atom_ids": deepcopy(output["covered_atom_ids"]),
            "uncovered_atom_ids": deepcopy(output["uncovered_atom_ids"]),
            "required_atom_count": output["required_atom_count"],
            "partition": [
                {
                    "atom_id": atom_id,
                    "state": "COVERED" if atom_id in covered else "UNCOVERED" if atom_id in uncovered else "UNOBSERVED",
                }
                for atom_id in ATOM_ORDER
            ],
        }

    @classmethod
    def _verdict_oracle(cls, y_result_digest: str, verdict: dict[str, object]) -> str:
        return cls._digest(
            {
                "schema": "s25z.coverage-verdict.v1",
                "verdict_scope": "S25Y_COVERAGE_VERDICT_PARTITION_ONLY",
                "y_result_digest": y_result_digest,
                "verdict": verdict,
            }
        )

    @classmethod
    def _case_from_y(cls, y_case: dict[str, object], y_output: dict[str, object]) -> dict[str, object]:
        y_case_digest = s25y.input_digest(y_case)
        y_result_digest = cls._digest(y_output)
        verdict = cls._verdict(y_output)
        case: dict[str, object] = {
            "schema_version": s25z.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25z.CANONICALIZATION,
            "expected": {
                "y_case_digest": y_case_digest,
                "y_result_digest": y_result_digest,
                "verdict_digest": cls._verdict_oracle(y_result_digest, verdict),
                "required_atom_count": len(s25z.ATOM_IDS),
            },
            "s25y_case": y_case,
            "s25y_output": y_output,
            "verdict": verdict,
            "input_digest": "",
        }
        case["input_digest"] = s25z.input_digest(case)
        return case

    @classmethod
    def _case(cls) -> dict[str, object]:
        y_case = deepcopy(s25y_tests.build_complete_s25y_case())
        y_output = s25y.evaluate_claim_evidence_closure(y_case)
        return cls._case_from_y(y_case, y_output)

    @classmethod
    def _synthetic_next_case(cls) -> dict[str, object]:
        """Build the isolated public boundary fixture used for A/B/A checks."""

        x_case = deepcopy(s25x_tests.build_synthetic_next_s25x_case(["WINDOW_DIGEST"]))
        with patch.object(s25x, "evaluate_projection_delta", return_value=x_case["s25w_output"]):
            x_output = s25x.evaluate_delta_claim_containment(x_case)
        x_case_digest = s25x.input_digest(x_case)
        x_result_digest = cls._digest(x_output)
        atoms = s25y.build_claim_atoms(x_case_digest, x_result_digest, x_output)
        y_case: dict[str, object] = {
            "schema_version": s25y.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25y.CANONICALIZATION,
            "expected": {
                "x_case_digest": x_case_digest,
                "x_result_digest": x_result_digest,
                "claim_digest": x_output["claim_digest"],
                "coverage_digest": s25y.coverage_digest(x_case_digest, x_result_digest, atoms),
                "required_atom_count": len(s25y.ATOM_IDS),
                "required_member_count": len(s25x.ALLOWED_MEMBER_IDS),
            },
            "s25x_case": x_case,
            "s25x_output": x_output,
            "claim_atoms": atoms,
            "input_digest": "",
        }
        y_case["input_digest"] = s25y.input_digest(y_case)
        with patch.object(s25y, "evaluate_delta_claim_containment", return_value=x_output):
            y_output = s25y.evaluate_claim_evidence_closure(y_case)
        return cls._case_from_y(y_case, y_output)

    @staticmethod
    def _reseal(case: dict[str, object]) -> None:
        case["input_digest"] = s25z.input_digest(case)

    @classmethod
    def _sync_y_output(cls, case: dict[str, object], output: dict[str, object]) -> None:
        case["s25y_output"] = output
        case["verdict"] = cls._verdict(output)
        case["expected"]["y_case_digest"] = s25y.input_digest(case["s25y_case"])
        case["expected"]["y_result_digest"] = cls._digest(output)
        case["expected"]["verdict_digest"] = cls._verdict_oracle(
            case["expected"]["y_result_digest"], case["verdict"]
        )
        cls._reseal(case)

    def test_positive_verdict_partition_is_complete_and_non_authoritative(self) -> None:
        case = self._case()
        before = deepcopy(case)

        result = s25z.evaluate_coverage_verdict_partition(case)

        self.assertEqual(result["classification"], s25z.VERDICT_COMPLETE)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["verdict_scope"], s25z.VERDICT_SCOPE)
        self.assertEqual(result["y_coverage_scope"], s25y.COVERAGE_SCOPE)
        self.assertEqual(result["y_claim_scope"], "S25W_MEMBER_DELTA_ONLY")
        self.assertEqual(result["covered_atom_ids"], list(ATOM_ORDER))
        self.assertEqual(result["uncovered_atom_ids"], [])
        self.assertEqual(result["required_atom_count"], len(ATOM_ORDER))
        self.assertEqual(result["partition"], [{"atom_id": atom_id, "state": "COVERED"} for atom_id in ATOM_ORDER])
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")
        self.assertTrue(all(result[field] is False for field in s25z.Y_FLAG_KEYS))
        self.assertEqual(set(result), set(s25z.RESULT_KEYS))
        self.assertEqual(case, before)

    def test_repeated_calls_and_two_independent_cases_have_no_cross_call_state(self) -> None:
        first = self._case()
        second = self._case()
        first_before = deepcopy(first)
        second_before = deepcopy(second)

        first_result = s25z.evaluate_coverage_verdict_partition(first)
        second_result = s25z.evaluate_coverage_verdict_partition(second)
        first_again = s25z.evaluate_coverage_verdict_partition(first)

        self.assertEqual(first, first_before)
        self.assertEqual(second, second_before)
        self.assertEqual(first_result, second_result)
        self.assertEqual(first_result, first_again)

    def test_verdict_digest_has_an_independent_canonical_oracle(self) -> None:
        case = self._case()
        verdict = case["verdict"]
        y_result_digest = case["expected"]["y_result_digest"]

        self.assertEqual(s25z.verdict_digest(y_result_digest, verdict), self._verdict_oracle(y_result_digest, verdict))
        self.assertEqual(case["expected"]["verdict_digest"], self._verdict_oracle(y_result_digest, verdict))

    def test_atom_order_is_a_fixed_independent_relation(self) -> None:
        self.assertEqual(tuple(s25z.ATOM_IDS), ATOM_ORDER)
        self.assertEqual(len(set(ATOM_ORDER)), len(ATOM_ORDER))

    def test_y_flag_contract_is_explicit_and_complete(self) -> None:
        core = {
            "schema_version",
            "observation_mode",
            "classification",
            "status",
            "decision",
            "reason",
            "coverage_scope",
            "claim_scope",
            "covered_atom_ids",
            "uncovered_atom_ids",
            "required_atom_count",
            "x_case_digest",
            "x_result_digest",
            "claim_digest",
            "coverage_digest",
            "production_status",
            "authority_claim",
        }
        self.assertEqual(set(s25z.Y_FLAG_KEYS) | core, set(s25y.RESULT_KEYS))

    def test_missing_extra_duplicate_unknown_and_ordered_verdict_atoms_fail_closed(self) -> None:
        mutations = {
            "missing": lambda ids: ids.pop(),
            "extra": lambda ids: ids.append("UNKNOWN"),
            "duplicate": lambda ids: ids.__setitem__(1, ids[0]),
            "unknown": lambda ids: ids.__setitem__(0, "UNKNOWN"),
            "order": lambda ids: ids.reverse(),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = self._case()
                mutate(case["verdict"]["covered_atom_ids"])
                self._reseal(case)

                result = s25z.evaluate_coverage_verdict_partition(case)

                self.assertEqual(result["classification"], s25z.VERDICT_INCOMPLETE)
                self.assertIn(result["reason"], {"VERDICT_PARTITION_MISMATCH", "VERDICT_ATOM_UNKNOWN", "VERDICT_ATOM_DUPLICATE", "VERDICT_ATOM_ORDER_DRIFT", "VERDICT_PARTITION_REWIRE"})
                self.assertEqual(result["status"], "TEST_BLOCKED")
                self.assertEqual(result["decision"], "HOLD")

    def test_partition_rows_missing_extra_duplicate_unknown_order_and_rewire_fail_closed(self) -> None:
        mutations = {
            "missing": lambda rows: rows.pop(),
            "extra": lambda rows: rows.append(deepcopy(rows[-1])),
            "duplicate": lambda rows: rows.__setitem__(1, deepcopy(rows[0])),
            "unknown": lambda rows: rows.__setitem__(0, {**rows[0], "atom_id": "UNKNOWN"}),
            "order": lambda rows: rows.reverse(),
            "rewire": lambda rows: rows.__setitem__(0, {**rows[0], "state": "UNCOVERED"}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = self._case()
                mutate(case["verdict"]["partition"])
                self._reseal(case)

                result = s25z.evaluate_coverage_verdict_partition(case)

                self.assertEqual(result["classification"], s25z.VERDICT_INCOMPLETE)
                self.assertIn(
                    result["reason"],
                    {
                        "VERDICT_PARTITION_SCHEMA_INVALID",
                        "VERDICT_PARTITION_ATOM_UNKNOWN",
                        "VERDICT_PARTITION_ATOM_DUPLICATE",
                        "VERDICT_PARTITION_ORDER_DRIFT",
                        "VERDICT_PARTITION_REWIRE",
                    },
                )

    def test_verdict_missing_extra_keys_and_invalid_shapes_are_input_or_partition_invalid(self) -> None:
        case = self._case()
        case["verdict"].pop("coverage_digest")
        self._reseal(case)
        missing = s25z.evaluate_coverage_verdict_partition(case)

        case = self._case()
        case["verdict"]["extra"] = "not allowed"
        self._reseal(case)
        extra = s25z.evaluate_coverage_verdict_partition(case)

        self.assertEqual(missing["classification"], s25z.VERDICT_INCOMPLETE)
        self.assertEqual(missing["reason"], "VERDICT_SCHEMA_INVALID")
        self.assertEqual(extra["classification"], s25z.VERDICT_INCOMPLETE)
        self.assertEqual(extra["reason"], "VERDICT_SCHEMA_INVALID")

    def test_verdict_coverage_and_partition_drift_cannot_be_hidden_by_outer_resealing(self) -> None:
        for field, value in (("coverage_digest", "f" * 64), ("classification", "FORGED"), ("required_atom_count", 0)):
            with self.subTest(field=field):
                case = self._case()
                case["verdict"][field] = value
                self._reseal(case)

                result = s25z.evaluate_coverage_verdict_partition(case)

                self.assertEqual(result["classification"], s25z.VERDICT_INCOMPLETE)
                self.assertIn(result["reason"], {"VERDICT_PARTITION_MISMATCH", "VERDICT_CLASSIFICATION_INVALID", "VERDICT_ATOM_COUNT_INVALID"})

    def test_expected_case_result_and_verdict_digests_are_bound(self) -> None:
        for field in ("y_case_digest", "y_result_digest", "verdict_digest"):
            with self.subTest(field=field):
                case = self._case()
                case["expected"][field] = "e" * 64
                self._reseal(case)

                result = s25z.evaluate_coverage_verdict_partition(case)

                self.assertEqual(result["classification"], s25z.VERDICT_INCOMPLETE)
                self.assertEqual(result["reason"], "EXPECTED_BINDING_MISMATCH" if field != "verdict_digest" else "VERDICT_DIGEST_MISMATCH")

    def test_forged_y_output_is_rejected_even_after_outer_resealing(self) -> None:
        case = self._case()
        case["s25y_output"]["reason"] = "FORGED"
        self._reseal(case)

        result = s25z.evaluate_coverage_verdict_partition(case)

        self.assertEqual(result["classification"], s25z.S25Y_REJECTED)
        self.assertEqual(result["reason"], "S25Y_RESULT_MISMATCH")

    def test_y_status_decision_and_authority_drift_are_not_promoted(self) -> None:
        for field, value in (("status", "TEST_BLOCKED"), ("decision", "HOLD"), ("production_status", "PRODUCTION_AUTHORIZED"), ("authority_claim", "CLAIMED")):
            with self.subTest(field=field):
                case = self._case()
                output = deepcopy(case["s25y_output"])
                output[field] = value
                self._sync_y_output(case, output)
                with patch.object(s25z, "evaluate_claim_evidence_closure", return_value=output):
                    result = s25z.evaluate_coverage_verdict_partition(case)

                self.assertEqual(result["classification"], s25z.S25Y_REJECTED)
                self.assertEqual(result["reason"], "S25Y_RESULT_INVALID")

    def test_positive_y_scope_digest_and_reason_forgery_is_rejected(self) -> None:
        mutations = {
            "claim_scope": "FORGED_SCOPE",
            "x_case_digest": "f" * 63,
            "x_result_digest": "e" * 63,
            "claim_digest": "d" * 63,
            "reason": "FORGED_REASON",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                case = self._case()
                output = deepcopy(case["s25y_output"])
                output[field] = value
                self._sync_y_output(case, output)
                with patch.object(s25z, "evaluate_claim_evidence_closure", return_value=output):
                    result = s25z.evaluate_coverage_verdict_partition(case)

                self.assertEqual(result["classification"], s25z.S25Y_REJECTED)
                self.assertEqual(result["reason"], "S25Y_RESULT_INVALID")

    def test_non_complete_y_verdict_never_becomes_positive(self) -> None:
        case = self._case()
        output = deepcopy(case["s25y_output"])
        output.update(
            {
                "classification": "COVERAGE_INCOMPLETE",
                "status": "TEST_BLOCKED",
                "decision": "HOLD",
                "reason": "ATOM_SET_INCOMPLETE",
                "covered_atom_ids": [],
                "uncovered_atom_ids": list(s25y.ATOM_IDS),
            }
        )
        self._sync_y_output(case, output)
        with patch.object(s25z, "evaluate_claim_evidence_closure", return_value=output):
            result = s25z.evaluate_coverage_verdict_partition(case)

        self.assertEqual(result["classification"], s25z.S25Y_NOT_COMPLETE)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")

    def test_y_exception_and_case_digest_drift_are_rejected(self) -> None:
        case = self._case()
        with patch.object(s25z, "evaluate_claim_evidence_closure", side_effect=RuntimeError("boom")):
            exception_result = s25z.evaluate_coverage_verdict_partition(case)
        self.assertEqual(exception_result["classification"], s25z.S25Y_REJECTED)
        self.assertEqual(exception_result["reason"], "S25Y_RESULT_UNREADABLE")

        case = self._case()
        case["s25y_case"]["extra"] = "drift"
        self._reseal(case)
        drift_result = s25z.evaluate_coverage_verdict_partition(case)
        self.assertEqual(drift_result["classification"], s25z.S25Y_REJECTED)
        self.assertEqual(drift_result["reason"], "S25Y_CASE_DIGEST_DRIFT")

    def test_all_result_paths_have_the_exact_public_output_keys(self) -> None:
        positive = s25z.evaluate_coverage_verdict_partition(self._case())
        invalid_case = self._case()
        invalid_case.pop("verdict")
        invalid = s25z.evaluate_coverage_verdict_partition(invalid_case)
        forged_case = self._case()
        forged_case["s25y_output"]["reason"] = "FORGED"
        self._reseal(forged_case)
        forged = s25z.evaluate_coverage_verdict_partition(forged_case)

        for result in (positive, invalid, forged):
            with self.subTest(classification=result["classification"]):
                self.assertEqual(set(result), set(s25z.RESULT_KEYS))

    def test_a_b_a_uses_an_isolated_synthetic_next_boundary_case(self) -> None:
        first = self._case()
        second = self._synthetic_next_case()

        first_before = deepcopy(first)
        first_result = s25z.evaluate_coverage_verdict_partition(first)
        with patch.object(s25z, "evaluate_claim_evidence_closure", return_value=second["s25y_output"]):
            second_result = s25z.evaluate_coverage_verdict_partition(second)
        first_again = s25z.evaluate_coverage_verdict_partition(first)

        self.assertEqual(first, first_before)
        self.assertEqual(first_result, first_again)
        self.assertEqual(second_result["classification"], s25z.VERDICT_COMPLETE)
        self.assertNotEqual(first_result["y_case_digest"], second_result["y_case_digest"])

    def test_missing_and_extra_envelope_keys_are_input_invalid(self) -> None:
        case = self._case()
        case.pop("verdict")
        self.assertEqual(s25z.evaluate_coverage_verdict_partition(case)["classification"], s25z.INPUT_INVALID)

        case = self._case()
        case["extra"] = "not allowed"
        self._reseal(case)
        self.assertEqual(s25z.evaluate_coverage_verdict_partition(case)["classification"], s25z.INPUT_INVALID)

    def test_duplicate_json_keys_are_input_invalid(self) -> None:
        case = self._case()
        raw = json.dumps(case, sort_keys=True, separators=(",", ":"))
        raw = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '","input_digest":"' + ("1" * 64) + '"}'

        result = s25z.evaluate_coverage_verdict_partition(raw)

        self.assertEqual(result["classification"], s25z.INPUT_INVALID)

    def test_parser_rejects_invalid_utf8_constants_and_oversized_bytes(self) -> None:
        self.assertEqual(s25z.evaluate_coverage_verdict_partition(b"\xff")["classification"], s25z.INPUT_INVALID)
        self.assertEqual(s25z.evaluate_coverage_verdict_partition(b"{\"x\":NaN}")["classification"], s25z.INPUT_INVALID)
        self.assertEqual(
            s25z.evaluate_coverage_verdict_partition(b"{" + b" " * (2 * 1024 * 1024 + 1) + b"}")["classification"],
            s25z.INPUT_INVALID,
        )

    def test_bool_float_and_unsafe_values_are_input_invalid(self) -> None:
        case = self._case()
        case["expected"]["required_atom_count"] = True
        self._reseal(case)
        bool_result = s25z.evaluate_coverage_verdict_partition(case)

        case = self._case()
        case["verdict"]["required_atom_count"] = 1.5
        float_result = s25z.evaluate_coverage_verdict_partition(case)

        self.assertEqual(bool_result["classification"], s25z.INPUT_INVALID)
        self.assertEqual(float_result["classification"], s25z.INPUT_INVALID)

        for value in ("/tmp/secret", "~/secret", "https://example.invalid", "\\\\server\\share"):
            with self.subTest(value=value):
                case = self._case()
                case["verdict"]["classification"] = value
                self._reseal(case)
                self.assertEqual(s25z.evaluate_coverage_verdict_partition(case)["classification"], s25z.INPUT_INVALID)

    def test_recursive_and_over_budget_inputs_are_invalid(self) -> None:
        case = self._case()
        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        case["s25y_case"]["recursive"] = recursive
        self.assertEqual(s25z.evaluate_coverage_verdict_partition(case)["classification"], s25z.INPUT_INVALID)

        case = self._case()
        padding: object = "leaf"
        for _ in range(7):
            padding = [padding] * 4
        case["s25y_case"]["padding"] = padding
        self.assertEqual(s25z.evaluate_coverage_verdict_partition(case)["classification"], s25z.INPUT_INVALID)

        case = self._case()
        case["verdict"]["covered_atom_ids"] = ["X_CASE_BINDING"] * 2049
        self.assertEqual(s25z.evaluate_coverage_verdict_partition(case)["classification"], s25z.INPUT_INVALID)

        case = self._case()
        deep: object = "leaf"
        for _ in range(66):
            deep = [deep]
        case["s25y_case"]["padding"] = deep
        self.assertEqual(s25z.evaluate_coverage_verdict_partition(case)["classification"], s25z.INPUT_INVALID)

    def test_bytes_input_and_no_file_or_network_discovery_are_supported(self) -> None:
        case = self._case()
        raw = json.dumps(case, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch("socket.socket", side_effect=AssertionError("network is forbidden")):
            result = s25z.evaluate_coverage_verdict_partition(raw)

        self.assertEqual(result["classification"], s25z.VERDICT_COMPLETE)

    def test_json_key_order_does_not_change_verdict(self) -> None:
        case = self._case()
        raw = json.dumps(case, ensure_ascii=False, sort_keys=False, separators=(",", ":"))
        reordered = json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

        self.assertEqual(
            s25z.evaluate_coverage_verdict_partition(raw), s25z.evaluate_coverage_verdict_partition(reordered)
        )

    def test_only_public_s25y_boundary_is_imported(self) -> None:
        source = Path(s25z.__file__).read_text(encoding="utf-8")

        self.assertIn("w5_s25y_claim_evidence_closure", source)
        self.assertNotIn("w5_s25x", source)
        self.assertNotIn("w5_s25v", source)
        self.assertNotIn("w5_s25w", source)
        self.assertNotIn("test_w5_s25", source)


def build_complete_s25z_case() -> dict[str, object]:
    """Public test-only fixture boundary for downstream W5 cards."""

    return W5S25ZCoverageVerdictPartitionTests._case()


def build_synthetic_next_s25z_case() -> dict[str, object]:
    """Public test-only fixture for an independently different valid Z case."""

    return W5S25ZCoverageVerdictPartitionTests._synthetic_next_case()


if __name__ == "__main__":
    unittest.main()
