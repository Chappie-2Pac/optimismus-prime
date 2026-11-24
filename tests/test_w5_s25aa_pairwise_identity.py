"""Adversarial tests for the pure S25AA pairwise identity relation."""

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

import support.w5_s25aa_pairwise_identity as s25aa  # noqa: E402
import support.w5_s25z_coverage_verdict_partition as s25z  # noqa: E402
import test_w5_s25z_coverage_verdict_partition as s25z_tests  # noqa: E402


IDENTITY_ORACLE_FIELDS = (
    "z_case_digest",
    "y_case_digest",
    "y_result_digest",
    "verdict_digest",
)
Z_FLAG_ORACLE_FIELDS = (
    "capability_issued",
    "cas_attempted",
    "commit_authorized",
    "fence_issued",
    "floor_advanced",
    "mutation_allowed",
    "persistence_performed",
    "receipt_committed",
    "receipt_emitted",
    "resume_allowed",
    "write_authorized",
)


class W5S25AAPairwiseIdentityTests(unittest.TestCase):
    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _identity(cls, case: dict[str, object], output: dict[str, object]) -> dict[str, str]:
        return {
            "z_case_digest": s25z.input_digest(case),
            "y_case_digest": output["y_case_digest"],
            "y_result_digest": output["y_result_digest"],
            "verdict_digest": output["verdict_digest"],
        }

    @classmethod
    def _relation_oracle(
        cls, left: dict[str, str], right: dict[str, str]
    ) -> tuple[str, dict[str, bool]]:
        equal_fields = {field: left[field] == right[field] for field in IDENTITY_ORACLE_FIELDS}
        if left["z_case_digest"] != right["z_case_digest"]:
            return "PAIR_SEPARATED", equal_fields
        if all(equal_fields.values()):
            return "PAIR_NOT_SEPARATED", equal_fields
        return "PAIR_IDENTITY_INCONSISTENT", equal_fields

    @classmethod
    def _pair_digest_oracle(
        cls,
        left: dict[str, str],
        right: dict[str, str],
        equal_fields: dict[str, bool],
        relation: str,
    ) -> str:
        return cls._digest(
            {
                "schema": "s25aa.pairwise-identity.v1",
                "pair_scope": "S25Z_PAIRWISE_IDENTITY_SEPARATION_ONLY",
                "left_identity": left,
                "right_identity": right,
                "equal_fields": equal_fields,
                "relation": relation,
            }
        )

    @classmethod
    def _case(
        cls,
        left_case: dict[str, object] | None = None,
        right_case: dict[str, object] | None = None,
        left_output: dict[str, object] | None = None,
        right_output: dict[str, object] | None = None,
    ) -> dict[str, object]:
        left_case = deepcopy(left_case if left_case is not None else s25z_tests.build_complete_s25z_case())
        right_case = deepcopy(right_case if right_case is not None else s25z_tests.build_complete_s25z_case())
        left_output = deepcopy(left_output if left_output is not None else s25z.evaluate_coverage_verdict_partition(left_case))
        right_output = deepcopy(right_output if right_output is not None else s25z.evaluate_coverage_verdict_partition(right_case))
        left_identity = cls._identity(left_case, left_output)
        right_identity = cls._identity(right_case, right_output)
        relation, equal_fields = cls._relation_oracle(left_identity, right_identity)
        witness = {
            "left_identity": left_identity,
            "right_identity": right_identity,
            "equal_fields": equal_fields,
            "relation": relation,
        }
        case: dict[str, object] = {
            "schema_version": s25aa.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25aa.CANONICALIZATION,
            "expected": {
                "left_z_case_digest": left_identity["z_case_digest"],
                "right_z_case_digest": right_identity["z_case_digest"],
                "left_result_digest": cls._digest(left_output),
                "right_result_digest": cls._digest(right_output),
                "pair_digest": cls._pair_digest_oracle(left_identity, right_identity, equal_fields, relation),
            },
            "left_case": left_case,
            "left_output": left_output,
            "right_case": right_case,
            "right_output": right_output,
            "pair_witness": witness,
            "input_digest": "",
        }
        case["input_digest"] = s25aa.input_digest(case)
        return case

    @staticmethod
    def _reseal(case: dict[str, object]) -> None:
        case["input_digest"] = s25aa.input_digest(case)

    @staticmethod
    def _synthetic_z_boundary() -> tuple[dict[str, object], dict[str, object]]:
        """Return the existing isolated NEXT fixture and its public-Z result."""

        case = s25z_tests.build_synthetic_next_s25z_case()
        with patch.object(s25z, "evaluate_claim_evidence_closure", return_value=case["s25y_output"]):
            output = s25z.evaluate_coverage_verdict_partition(case)
        return case, output

    @staticmethod
    def _negative_z_boundary() -> tuple[dict[str, object], dict[str, object]]:
        """Return a genuinely negative public-Z case without patching Z."""

        case = s25z_tests.build_complete_s25z_case()
        case["verdict"].pop("partition")
        case["input_digest"] = s25z.input_digest(case)
        return case, s25z.evaluate_coverage_verdict_partition(case)

    @staticmethod
    def _evaluate(
        case: dict[str, object],
        boundary_outputs: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        if boundary_outputs is None:
            return s25aa.evaluate_pairwise_identity(case)
        with patch.object(s25aa, "evaluate_coverage_verdict_partition", side_effect=boundary_outputs):
            return s25aa.evaluate_pairwise_identity(case)

    def test_same_case_is_not_reported_as_separated(self) -> None:
        case = self._case()
        before = deepcopy(case)

        result = s25aa.evaluate_pairwise_identity(case)

        self.assertEqual(result["classification"], s25aa.PAIR_NOT_SEPARATED)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], "PAIR_IDENTICAL_NOT_SEPARATED")
        self.assertEqual(result["equal_fields"], {field: True for field in IDENTITY_ORACLE_FIELDS})
        self.assertEqual(result["pair_digest"], case["expected"]["pair_digest"])
        self.assertEqual(result["left_identity"], case["pair_witness"]["left_identity"])
        self.assertEqual(result["right_identity"], case["pair_witness"]["right_identity"])
        self.assertEqual(case, before)

    def test_different_valid_z_cases_are_separated_without_authority(self) -> None:
        second, second_output = self._synthetic_z_boundary()
        case = self._case(right_case=second, right_output=second_output)
        left_output = case["left_output"]

        result = self._evaluate(case, [left_output, second_output])

        self.assertEqual(result["classification"], s25aa.PAIR_SEPARATED)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["reason"], "PAIR_IDENTITY_SEPARATED")
        self.assertNotEqual(result["left_identity"]["z_case_digest"], result["right_identity"]["z_case_digest"])
        self.assertEqual(result["left_identity"], case["pair_witness"]["left_identity"])
        self.assertEqual(result["right_identity"], case["pair_witness"]["right_identity"])
        self.assertEqual(result["pair_digest"], case["expected"]["pair_digest"])
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")
        self.assertTrue(all(result[field] is False for field in Z_FLAG_ORACLE_FIELDS))

    def test_pair_digest_and_relation_have_an_independent_ordered_oracle(self) -> None:
        second, second_output = self._synthetic_z_boundary()
        case = self._case(right_case=second, right_output=second_output)
        left = case["pair_witness"]["left_identity"]
        right = case["pair_witness"]["right_identity"]
        relation, equal_fields = self._relation_oracle(left, right)

        result = self._evaluate(case, [case["left_output"], second_output])

        self.assertEqual(result["classification"], relation)
        self.assertEqual(result["equal_fields"], equal_fields)
        self.assertEqual(result["pair_digest"], self._pair_digest_oracle(left, right, equal_fields, relation))
        reversed_case = self._case(
            left_case=second,
            left_output=second_output,
            right_case=s25z_tests.build_complete_s25z_case(),
        )
        reversed_result = self._evaluate(reversed_case, [second_output, reversed_case["right_output"]])
        self.assertNotEqual(result["pair_digest"], reversed_result["pair_digest"])
        self.assertEqual(reversed_result["left_identity"], right)
        self.assertEqual(reversed_result["right_identity"], left)

    def test_a_b_a_is_deterministic_and_has_no_cross_call_state(self) -> None:
        first = self._case()
        synthetic_case, synthetic_output = self._synthetic_z_boundary()
        second = self._case(right_case=synthetic_case, right_output=synthetic_output)
        first_before = deepcopy(first)
        second_before = deepcopy(second)

        first_result = s25aa.evaluate_pairwise_identity(first)
        second_result = self._evaluate(second, [second["left_output"], synthetic_output])
        first_again = s25aa.evaluate_pairwise_identity(first)

        self.assertEqual(first_result["classification"], s25aa.PAIR_NOT_SEPARATED)
        self.assertEqual(second_result["classification"], s25aa.PAIR_SEPARATED)
        self.assertEqual(first_result, first_again)
        self.assertEqual(first, first_before)
        self.assertEqual(second, second_before)

    def test_same_z_case_with_different_downstream_identity_is_inconsistent_not_positive(self) -> None:
        left_case = s25z_tests.build_complete_s25z_case()
        left_output = s25z.evaluate_coverage_verdict_partition(left_case)
        right_output = deepcopy(left_output)
        right_output["y_result_digest"] = "f" * 64
        case = self._case(
            left_case=left_case,
            right_case=deepcopy(left_case),
            left_output=left_output,
            right_output=right_output,
        )

        with patch.object(s25aa, "evaluate_coverage_verdict_partition", side_effect=[left_output, right_output]):
            result = s25aa.evaluate_pairwise_identity(case)

        self.assertEqual(result["classification"], s25aa.PAIR_IDENTITY_INCONSISTENT)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], "PAIR_IDENTITY_DRIFT")
        self.assertTrue(result["equal_fields"]["z_case_digest"])
        self.assertFalse(result["equal_fields"]["y_result_digest"])

    def test_each_downstream_identity_field_has_the_same_drift_relation_on_either_side(self) -> None:
        base_case = s25z_tests.build_complete_s25z_case()
        base_output = s25z.evaluate_coverage_verdict_partition(base_case)

        for field in ("y_case_digest", "y_result_digest", "verdict_digest"):
            for side in ("left", "right"):
                with self.subTest(field=field, side=side):
                    altered = deepcopy(base_output)
                    altered[field] = "a" * 64 if base_output[field] != "a" * 64 else "b" * 64
                    if side == "left":
                        case = self._case(left_output=altered, right_output=base_output)
                        outputs = [altered, base_output]
                    else:
                        case = self._case(left_output=base_output, right_output=altered)
                        outputs = [base_output, altered]
                    result = self._evaluate(case, outputs)
                    self.assertEqual(result["classification"], s25aa.PAIR_IDENTITY_INCONSISTENT)
                    self.assertFalse(result["equal_fields"][field])

    def test_different_z_cases_are_separated_even_when_downstream_fields_match(self) -> None:
        second, second_output = self._synthetic_z_boundary()
        left_case = s25z_tests.build_complete_s25z_case()
        left_output = s25z.evaluate_coverage_verdict_partition(left_case)
        aligned = deepcopy(second_output)
        for field in ("y_case_digest", "y_result_digest", "verdict_digest"):
            aligned[field] = left_output[field]
        case = self._case(
            left_case=left_case,
            left_output=left_output,
            right_case=second,
            right_output=aligned,
        )

        result = self._evaluate(case, [left_output, aligned])

        self.assertEqual(result["classification"], s25aa.PAIR_SEPARATED)
        self.assertFalse(result["equal_fields"]["z_case_digest"])
        self.assertTrue(all(result["equal_fields"][field] for field in IDENTITY_ORACLE_FIELDS[1:]))

    def test_nonpositive_z_side_can_never_become_a_positive_pair(self) -> None:
        negative_case, negative = self._negative_z_boundary()
        positive_case = s25z_tests.build_complete_s25z_case()
        positive = s25z.evaluate_coverage_verdict_partition(positive_case)

        for left_case, right_case, left_output, right_output in (
            (negative_case, positive_case, negative, positive),
            (positive_case, negative_case, positive, negative),
        ):
            with self.subTest(left=left_output["classification"], right=right_output["classification"]):
                case = self._case(
                    left_case=left_case,
                    right_case=right_case,
                    left_output=left_output,
                    right_output=right_output,
                )
                result = s25aa.evaluate_pairwise_identity(case)
                self.assertEqual(result["classification"], s25aa.S25Z_NOT_COMPLETE)
                self.assertEqual(result["status"], "TEST_BLOCKED")
                self.assertNotEqual(result["classification"], s25aa.PAIR_SEPARATED)

    def test_each_side_is_re_evaluated_and_supplied_output_must_match(self) -> None:
        case = self._case()
        forged = deepcopy(case["left_output"])
        forged["reason"] = "FORGED"
        case["left_output"] = forged
        self._reseal(case)

        result = s25aa.evaluate_pairwise_identity(case)

        self.assertEqual(result["classification"], s25aa.S25Z_REJECTED)
        self.assertEqual(result["reason"], "S25Z_RESULT_MISMATCH")

    def test_semantically_rewired_positive_z_partition_is_not_accepted(self) -> None:
        case = self._case()
        forged = deepcopy(case["left_output"])
        forged["covered_atom_ids"] = list(reversed(forged["covered_atom_ids"]))
        case["left_output"] = forged
        self._reseal(case)

        with patch.object(s25aa, "evaluate_coverage_verdict_partition", side_effect=[forged, case["right_output"]]):
            result = s25aa.evaluate_pairwise_identity(case)

        self.assertEqual(result["classification"], s25aa.S25Z_REJECTED)
        self.assertEqual(result["reason"], "S25Z_RESULT_INVALID")

    def test_semantically_rewired_negative_z_partition_is_not_accepted_as_a_valid_boundary(self) -> None:
        _, negative = self._negative_z_boundary()
        negative["uncovered_atom_ids"] = ["UNKNOWN_ATOM"]
        case = self._case(left_case=s25z_tests.build_complete_s25z_case(), left_output=negative)

        with patch.object(s25aa, "evaluate_coverage_verdict_partition", side_effect=[negative, case["right_output"]]):
            result = s25aa.evaluate_pairwise_identity(case)

        self.assertEqual(result["classification"], s25aa.S25Z_REJECTED)
        self.assertEqual(result["reason"], "S25Z_RESULT_INVALID")

    def test_z_exception_is_fail_closed(self) -> None:
        case = self._case()
        with patch.object(s25aa, "evaluate_coverage_verdict_partition", side_effect=RuntimeError("boom")):
            result = s25aa.evaluate_pairwise_identity(case)

        self.assertEqual(result["classification"], s25aa.S25Z_REJECTED)
        self.assertEqual(result["reason"], "S25Z_RESULT_UNREADABLE")

    def test_both_sides_are_attempted_even_when_the_left_side_fails(self) -> None:
        case = self._case()
        with patch.object(
            s25aa,
            "evaluate_coverage_verdict_partition",
            side_effect=[RuntimeError("left boom"), case["right_output"]],
        ) as evaluator:
            result = s25aa.evaluate_pairwise_identity(case)

        self.assertEqual(evaluator.call_count, 2)
        self.assertEqual(result["classification"], s25aa.S25Z_REJECTED)
        self.assertEqual(result["reason"], "S25Z_RESULT_UNREADABLE")

    def test_both_calls_receive_the_expected_positional_cases(self) -> None:
        case = self._case()
        seen: list[str] = []

        def evaluator(argument: dict[str, object]) -> dict[str, object]:
            seen.append(s25z.input_digest(argument))
            return case["left_output"] if len(seen) == 1 else case["right_output"]

        with patch.object(s25aa, "evaluate_coverage_verdict_partition", side_effect=evaluator) as mocked:
            result = s25aa.evaluate_pairwise_identity(case)

        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(
            seen,
            [
                case["pair_witness"]["left_identity"]["z_case_digest"],
                case["pair_witness"]["right_identity"]["z_case_digest"],
            ],
        )
        self.assertEqual(result["classification"], s25aa.PAIR_NOT_SEPARATED)

    def test_all_result_paths_have_exact_public_output_keys(self) -> None:
        complete = s25aa.evaluate_pairwise_identity(self._case())
        synthetic_case, synthetic_output = self._synthetic_z_boundary()
        separated_case = self._case(right_case=synthetic_case, right_output=synthetic_output)
        separated = self._evaluate(separated_case, [separated_case["left_output"], synthetic_output])
        invalid_case = self._case()
        invalid_case.pop("pair_witness")
        invalid = s25aa.evaluate_pairwise_identity(invalid_case)

        for result in (complete, separated, invalid):
            with self.subTest(classification=result["classification"]):
                self.assertEqual(set(result), set(s25aa.RESULT_KEYS))

    def test_witness_missing_extra_unknown_duplicate_and_relation_drift_are_blocked(self) -> None:
        mutations = ("missing", "extra", "unknown", "relation")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                case = self._case()
                if mutation == "missing":
                    case["pair_witness"].pop("relation")
                elif mutation == "extra":
                    case["pair_witness"]["extra"] = "drift"
                elif mutation == "unknown":
                    case["pair_witness"]["equal_fields"]["unknown"] = True
                else:
                    case["pair_witness"]["relation"] = s25aa.PAIR_SEPARATED
                self._reseal(case)
                result = s25aa.evaluate_pairwise_identity(case)
                self.assertEqual(result["classification"], s25aa.INPUT_INVALID if mutation != "relation" else s25aa.PAIR_IDENTITY_INCONSISTENT)

    def test_identity_and_equal_field_order_or_type_drift_is_fail_closed(self) -> None:
        case = self._case()
        case["pair_witness"]["left_identity"]["z_case_digest"] = True
        self._reseal(case)
        self.assertEqual(s25aa.evaluate_pairwise_identity(case)["classification"], s25aa.INPUT_INVALID)

        case = self._case()
        case["pair_witness"]["equal_fields"]["z_case_digest"] = 1
        self._reseal(case)
        self.assertEqual(s25aa.evaluate_pairwise_identity(case)["classification"], s25aa.INPUT_INVALID)

    def test_expected_digest_and_witness_digest_drift_are_blocked(self) -> None:
        for field in (
            "left_z_case_digest",
            "right_z_case_digest",
            "left_result_digest",
            "right_result_digest",
            "pair_digest",
        ):
            with self.subTest(field=field):
                case = self._case()
                case["expected"][field] = "e" * 64
                self._reseal(case)
                result = s25aa.evaluate_pairwise_identity(case)
                self.assertEqual(result["classification"], s25aa.PAIR_IDENTITY_INCONSISTENT)

    def test_nested_case_drift_and_unknown_output_profile_are_rejected(self) -> None:
        case = self._case()
        case["left_case"]["extra"] = "drift"
        self._reseal(case)
        self.assertEqual(s25aa.evaluate_pairwise_identity(case)["classification"], s25aa.S25Z_REJECTED)

        case = self._case()
        forged = deepcopy(case["left_output"])
        forged["classification"] = "UNKNOWN"
        case["left_output"] = forged
        self._reseal(case)
        with patch.object(s25aa, "evaluate_coverage_verdict_partition", return_value=forged):
            result = s25aa.evaluate_pairwise_identity(case)
        self.assertEqual(result["classification"], s25aa.S25Z_REJECTED)
        self.assertEqual(result["reason"], "S25Z_RESULT_INVALID")

    def test_missing_and_extra_envelope_keys_are_input_invalid(self) -> None:
        case = self._case()
        case.pop("left_output")
        self.assertEqual(s25aa.evaluate_pairwise_identity(case)["classification"], s25aa.INPUT_INVALID)

        case = self._case()
        case["extra"] = "not allowed"
        self._reseal(case)
        self.assertEqual(s25aa.evaluate_pairwise_identity(case)["classification"], s25aa.INPUT_INVALID)

    def test_duplicate_json_keys_are_input_invalid(self) -> None:
        case = self._case()
        raw = json.dumps(case, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        raw = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '","input_digest":"' + ("1" * 64) + '"}'

        result = s25aa.evaluate_pairwise_identity(raw)

        self.assertEqual(result["classification"], s25aa.INPUT_INVALID)

    def test_invalid_utf8_nan_oversize_and_unsafe_values_are_input_invalid(self) -> None:
        self.assertEqual(s25aa.evaluate_pairwise_identity(b"\xff")["classification"], s25aa.INPUT_INVALID)
        self.assertEqual(s25aa.evaluate_pairwise_identity(b"{\"x\":NaN}")["classification"], s25aa.INPUT_INVALID)
        self.assertEqual(s25aa.evaluate_pairwise_identity(b"x" * (2 * 1024 * 1024 + 1))["classification"], s25aa.INPUT_INVALID)

        case = self._case()
        case["left_output"]["reason"] = "/tmp/secret"
        self._reseal(case)
        self.assertEqual(s25aa.evaluate_pairwise_identity(case)["classification"], s25aa.INPUT_INVALID)

    def test_recursive_and_over_budget_inputs_are_invalid(self) -> None:
        case = self._case()
        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        case["left_case"]["recursive"] = recursive
        self.assertEqual(s25aa.evaluate_pairwise_identity(case)["classification"], s25aa.INPUT_INVALID)

        case = self._case()
        padding: object = "leaf"
        for _ in range(7):
            padding = [padding] * 4
        case["right_case"]["padding"] = padding
        self.assertEqual(s25aa.evaluate_pairwise_identity(case)["classification"], s25aa.INPUT_INVALID)

    def test_bytes_input_and_no_file_or_network_discovery_are_supported(self) -> None:
        synthetic_case, synthetic_output = self._synthetic_z_boundary()
        case = self._case(right_case=synthetic_case, right_output=synthetic_output)
        raw = json.dumps(case, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch.object(
            socket, "socket", side_effect=AssertionError("network is forbidden")
        ):
            with patch.object(s25aa, "evaluate_coverage_verdict_partition", side_effect=[case["left_output"], synthetic_output]):
                result = s25aa.evaluate_pairwise_identity(raw)

        self.assertEqual(result["classification"], s25aa.PAIR_SEPARATED)

    def test_json_key_order_does_not_change_result(self) -> None:
        case = self._case()
        raw = json.dumps(case, ensure_ascii=False, sort_keys=False, separators=(",", ":"))
        reordered = json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

        self.assertEqual(s25aa.evaluate_pairwise_identity(raw), s25aa.evaluate_pairwise_identity(reordered))

    def test_public_s25z_boundary_only_and_no_stateful_or_temporal_implementation(self) -> None:
        source = Path(s25aa.__file__).read_text(encoding="utf-8")

        self.assertIn("w5_s25z_coverage_verdict_partition", source)
        for forbidden in ("w5_s25y", "w5_s25x", "w5_s25w", "w5_s25v", "test_w5_s25", "time", "random", "socket"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("datetime", source)

    def test_input_digest_changes_for_any_authenticated_field_but_omits_only_its_own_field(self) -> None:
        case = self._case()
        original = s25aa.input_digest(case)
        without_self = deepcopy(case)
        without_self["input_digest"] = "f" * 64
        self.assertEqual(s25aa.input_digest(without_self), original)

        case["expected"]["pair_digest"] = "a" * 64
        self.assertNotEqual(s25aa.input_digest(case), original)


def build_complete_s25aa_case() -> dict[str, object]:
    """Public test-only fixture boundary for downstream W5 cards."""

    return W5S25AAPairwiseIdentityTests._case()


if __name__ == "__main__":
    unittest.main()
