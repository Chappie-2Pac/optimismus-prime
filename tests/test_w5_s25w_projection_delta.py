"""Adversarial tests for the pure S25W projection-delta witness."""

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

import support.w5_s25v_projection_set_completeness as s25v  # noqa: E402
import support.w5_s25w_projection_delta as s25w  # noqa: E402
import test_w5_s25v_projection_set_completeness as s25v_tests  # noqa: E402


class W5S25WProjectionDeltaTests(unittest.TestCase):
    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _case(cls) -> dict[str, object]:
        s25v_case = deepcopy(s25v_tests.build_complete_s25v_case())
        s25v_output = s25v.evaluate_projection_set_completeness(s25v_case)
        case: dict[str, object] = {
            "schema_version": s25w.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25w.CANONICALIZATION,
            "expected": {
                "s25v_case_digest": s25v.input_digest(s25v_case),
                "s25v_result_digest": cls._digest(s25v_output),
                "transition_kind": s25v_output["transition_kind"],
                "before_projection_set_digest": s25v_output["before_projection_set_digest"],
                "after_projection_set_digest": s25v_output["after_projection_set_digest"],
                "before_projection_order_digest": s25v_output["before_projection_order_digest"],
                "after_projection_order_digest": s25v_output["after_projection_order_digest"],
                "required_member_count": len(s25v.ALLOWED_MEMBER_IDS),
            },
            "s25v_case": s25v_case,
            "s25v_output": s25v_output,
            "input_digest": "",
        }
        case["input_digest"] = s25w.input_digest(case)
        return case

    @classmethod
    def _reseal_member_witness(cls, witness: dict[str, object]) -> None:
        for member in witness["members"]:
            member["member_digest"] = cls._digest(
                {key: member[key] for key in ("member_id", "observation_state", "value_digest", "context_digest")}
            )
        digests = [member["member_digest"] for member in witness["members"]]
        witness["projection_set_digest"] = cls._digest(
            {"schema": "s25v.projection-set.v1", "member_digests": sorted(digests)}
        )
        witness["projection_order_digest"] = cls._digest(
            {"schema": "s25v.projection-set.v1", "member_digests": digests}
        )

    @classmethod
    def _sync_case(cls, case: dict[str, object], *, output: dict[str, object] | None = None) -> None:
        s25v_case = case["s25v_case"]
        if output is None:
            output = s25v.evaluate_projection_set_completeness(s25v_case)
        case["s25v_output"] = output
        expected = case["expected"]
        transition_kind = output.get("transition_kind", "NO_CHANGE")
        if transition_kind not in {"NO_CHANGE", "NEXT_SEQUENCE", "EVIDENCE_DEGRADED"}:
            transition_kind = "NO_CHANGE"
        expected.update(
            {
                "s25v_case_digest": s25v.input_digest(s25v_case),
                "s25v_result_digest": cls._digest(output),
                "transition_kind": transition_kind,
                "before_projection_set_digest": output.get("before_projection_set_digest", "0" * 64),
                "after_projection_set_digest": output.get("after_projection_set_digest", "0" * 64),
                "before_projection_order_digest": output.get("before_projection_order_digest", "0" * 64),
                "after_projection_order_digest": output.get("after_projection_order_digest", "0" * 64),
            }
        )
        case["input_digest"] = s25w.input_digest(case)

    @classmethod
    def _synthetic_next_case(cls, member_id: str | None) -> dict[str, object]:
        # The current public fixture catalog exposes only a genuine NO_CHANGE
        # S25V case. This helper exercises W's fixed allowlist at the public
        # boundary; it is deliberately not an end-to-end NEXT_SEQUENCE proof.
        case = cls._case()
        if member_id is not None:
            member = next(item for item in case["s25v_case"]["after_witness"]["members"] if item["member_id"] == member_id)
            member["value_digest"] = "a" * 64 if member["value_digest"] != "a" * 64 else "b" * 64
            cls._reseal_member_witness(case["s25v_case"]["after_witness"])
        case["s25v_case"]["input_digest"] = s25v.input_digest(case["s25v_case"])
        output = deepcopy(case["s25v_output"])
        output["transition_kind"] = "NEXT_SEQUENCE"
        output["before_projection_set_digest"] = case["s25v_case"]["before_witness"]["projection_set_digest"]
        output["after_projection_set_digest"] = case["s25v_case"]["after_witness"]["projection_set_digest"]
        output["before_projection_order_digest"] = case["s25v_case"]["before_witness"]["projection_order_digest"]
        output["after_projection_order_digest"] = case["s25v_case"]["after_witness"]["projection_order_digest"]
        cls._sync_case(case, output=output)
        return case

    @classmethod
    def _valid_nonpositive_output(cls, case: dict[str, object], classification: str) -> dict[str, object]:
        output = deepcopy(case["s25v_output"])
        output.update(
            {
                "classification": classification,
                "status": "RECOVERY_REQUIRED",
                "decision": "MANUAL_REVIEW",
                "reason": "TEST_ONLY_REVIEW",
                "transition_kind": "UNKNOWN",
                "completeness_status": "NOT_CLAIMED",
                "before_member_count": 0,
                "after_member_count": 0,
                "before_projection_set_digest": "0" * 64,
                "after_projection_set_digest": "0" * 64,
                "before_projection_order_digest": "0" * 64,
                "after_projection_order_digest": "0" * 64,
            }
        )
        return output

    def test_complete_no_change_delta_is_read_only(self) -> None:
        case = self._case()

        result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.PROJECTION_DELTA_NO_CHANGE)
        self.assertEqual(result["reason"], "NO_MEMBER_DELTA")
        self.assertEqual(result["changed_member_ids"], [])
        self.assertEqual(result["unchanged_member_ids"], list(s25v.ALLOWED_MEMBER_IDS))
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["floor_advanced"])

    def test_input_is_unchanged_and_calls_have_no_hidden_state(self) -> None:
        case = self._case()
        before = deepcopy(case)

        first = s25w.evaluate_projection_delta(case)
        second = s25w.evaluate_projection_delta(deepcopy(case))
        third = s25w.evaluate_projection_delta(case)

        self.assertEqual(case, before)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_delta_digest_and_fixed_allowed_list_are_deterministic(self) -> None:
        case = self._case()
        result = s25w.evaluate_projection_delta(case)

        expected_delta = self._digest(
            {
                "schema": "s25w.projection-delta.v1",
                "transition_kind": "NO_CHANGE",
                "members": [
                    {
                        "member_id": member_id,
                        "before_member_digest": case["s25v_case"]["before_witness"]["members"][index]["member_digest"],
                        "after_member_digest": case["s25v_case"]["after_witness"]["members"][index]["member_digest"],
                        "changed": False,
                    }
                    for index, member_id in enumerate(s25v.ALLOWED_MEMBER_IDS)
                ],
            }
        )

        self.assertEqual(result["delta_digest"], expected_delta)
        self.assertEqual(result["allowed_changed_member_ids"], [])

    def test_synthetic_next_sequence_accepts_only_allowed_member_delta(self) -> None:
        """Contract-only allowlist branch; real NEXT evidence remains upstream-owned."""
        case = self._synthetic_next_case("WINDOW_DIGEST")
        with patch.object(s25w, "evaluate_projection_set_completeness", return_value=case["s25v_output"]):
            result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.PROJECTION_DELTA_NEXT_SEQUENCE)
        self.assertEqual(result["reason"], "ALLOWED_SUCCESSOR_DELTA")
        self.assertEqual(result["changed_member_ids"], ["WINDOW_DIGEST"])
        self.assertEqual(result["allowed_changed_member_ids"], list(s25w.NEXT_SEQUENCE_ALLOWED_MEMBER_IDS))

    def test_each_next_sequence_allowlist_member_is_accepted_by_the_contract(self) -> None:
        for member_id in s25w.NEXT_SEQUENCE_ALLOWED_MEMBER_IDS:
            with self.subTest(member_id=member_id):
                case = self._synthetic_next_case(member_id)
                with patch.object(s25w, "evaluate_projection_set_completeness", return_value=case["s25v_output"]):
                    result = s25w.evaluate_projection_delta(case)
                self.assertEqual(result["classification"], s25w.PROJECTION_DELTA_NEXT_SEQUENCE)
                self.assertEqual(result["changed_member_ids"], [member_id])

    def test_identity_quality_and_security_deltas_are_never_allowed(self) -> None:
        for member_id in ("IDENTITY", "QUALITY", "SECURITY"):
            with self.subTest(member_id=member_id):
                case = self._synthetic_next_case(member_id)
                with patch.object(s25w, "evaluate_projection_set_completeness", return_value=case["s25v_output"]):
                    result = s25w.evaluate_projection_delta(case)
                self.assertEqual(result["classification"], s25w.PROJECTION_DELTA_CONFLICT)
                self.assertEqual(result["reason"], "FORBIDDEN_MEMBER_DELTA")

    def test_synthetic_next_sequence_rejects_identity_delta(self) -> None:
        case = self._synthetic_next_case("IDENTITY")
        with patch.object(s25w, "evaluate_projection_set_completeness", return_value=case["s25v_output"]):
            result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.PROJECTION_DELTA_CONFLICT)
        self.assertEqual(result["reason"], "FORBIDDEN_MEMBER_DELTA")
        self.assertEqual(result["changed_member_ids"], ["IDENTITY"])

    def test_next_sequence_without_a_member_delta_is_rejected(self) -> None:
        case = self._synthetic_next_case(None)
        with patch.object(s25w, "evaluate_projection_set_completeness", return_value=case["s25v_output"]):
            result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.PROJECTION_DELTA_CONFLICT)
        self.assertEqual(result["reason"], "NEXT_SEQUENCE_WITHOUT_DELTA")

    def test_s25v_partial_is_never_promoted(self) -> None:
        case = self._case()
        case["s25v_case"]["before_witness"]["members"].pop()
        case["s25v_case"]["input_digest"] = s25v.input_digest(case["s25v_case"])
        self._sync_case(case)

        result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.PROJECTION_DELTA_PARTIAL)
        self.assertEqual(result["reason"], "S25V_NOT_COMPLETE")
        self.assertEqual(result["status"], "TEST_BLOCKED")

    def test_s25v_output_forgery_is_rejected_even_after_outer_reseal(self) -> None:
        case = self._case()
        case["s25v_output"]["reason"] = "FORGED"
        case["input_digest"] = s25w.input_digest(case)

        result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.S25V_REJECTED)
        self.assertEqual(result["reason"], "S25V_RESULT_MISMATCH")

    def test_s25v_projection_digest_binding_cannot_be_resealed(self) -> None:
        case = self._case()
        forged = deepcopy(case["s25v_output"])
        forged["before_projection_set_digest"] = "f" * 64
        self._sync_case(case, output=forged)
        with patch.object(s25w, "evaluate_projection_set_completeness", return_value=forged):
            result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.S25V_REJECTED)
        self.assertEqual(result["reason"], "S25V_RESULT_SEMANTIC_MISMATCH")

    def test_s25v_case_digest_reseal_does_not_hide_case_schema_drift(self) -> None:
        case = self._case()
        case["s25v_case"]["unexpected"] = "drift"
        case["s25v_case"]["input_digest"] = s25v.input_digest(case["s25v_case"])
        self._sync_case(case)

        result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.S25V_REJECTED)
        self.assertEqual(result["reason"], "S25V_RESULT_INVALID")

    def test_invalid_member_digest_is_rejected_before_delta_claim(self) -> None:
        case = self._case()
        case["s25v_case"]["before_witness"]["members"][0]["member_digest"] = "f" * 64
        case["s25v_case"]["input_digest"] = s25v.input_digest(case["s25v_case"])
        with patch.object(s25w, "evaluate_projection_set_completeness", return_value=case["s25v_output"]):
            self._sync_case(case, output=case["s25v_output"])
            with patch.object(s25w, "evaluate_projection_set_completeness", return_value=case["s25v_output"]):
                result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.S25V_REJECTED)
        self.assertEqual(result["reason"], "S25V_MEMBER_WITNESS_INVALID")

    def test_expected_binding_drift_is_conflict(self) -> None:
        case = self._case()
        case["expected"]["after_projection_set_digest"] = "e" * 64
        case["input_digest"] = s25w.input_digest(case)

        result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.PROJECTION_DELTA_CONFLICT)
        self.assertEqual(result["reason"], "EXPECTED_BINDING_MISMATCH")

    def test_s25v_positive_safety_forgery_is_rejected(self) -> None:
        case = self._case()
        forged = deepcopy(case["s25v_output"])
        forged["mutation_allowed"] = True
        case["s25v_output"] = forged
        case["expected"]["s25v_result_digest"] = self._digest(forged)
        case["input_digest"] = s25w.input_digest(case)
        with patch.object(s25w, "evaluate_projection_set_completeness", return_value=forged):
            result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.S25V_REJECTED)
        self.assertEqual(result["reason"], "S25V_RESULT_INVALID")

    def test_malformed_stale_and_future_s25v_classes_are_rejected(self) -> None:
        for classification, expected_classification, expected_reason in (
            (s25v.PROJECTION_STALE, s25w.PROJECTION_STALE, "S25V_STALE"),
            (s25v.PROJECTION_OUT_OF_WINDOW, s25w.PROJECTION_OUT_OF_WINDOW, "S25V_OUT_OF_WINDOW"),
        ):
            with self.subTest(classification=classification):
                case = self._case()
                output = {"classification": classification}
                self._sync_case(case, output=output)
                with patch.object(s25w, "evaluate_projection_set_completeness", return_value=output):
                    result = s25w.evaluate_projection_delta(case)
                self.assertEqual(result["classification"], s25w.S25V_REJECTED)
                self.assertEqual(result["reason"], "S25V_RESULT_INVALID")

    def test_schema_valid_stale_and_future_s25v_classes_remain_nonpositive(self) -> None:
        for classification, expected_classification, expected_reason in (
            (s25v.PROJECTION_STALE, s25w.PROJECTION_STALE, "S25V_STALE"),
            (s25v.PROJECTION_OUT_OF_WINDOW, s25w.PROJECTION_OUT_OF_WINDOW, "S25V_OUT_OF_WINDOW"),
        ):
            with self.subTest(classification=classification):
                case = self._case()
                output = self._valid_nonpositive_output(case, classification)
                self._sync_case(case, output=output)
                with patch.object(s25w, "evaluate_projection_set_completeness", return_value=output):
                    result = s25w.evaluate_projection_delta(case)
                self.assertEqual(result["classification"], expected_classification)
                self.assertEqual(result["reason"], expected_reason)

    def test_public_s25v_exception_is_fail_closed(self) -> None:
        case = self._case()
        with patch.object(s25w, "evaluate_projection_set_completeness", side_effect=RuntimeError("boom")):
            result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.S25V_REJECTED)
        self.assertEqual(result["reason"], "S25V_RESULT_UNREADABLE")

    def test_a_b_a_calls_do_not_share_case_state(self) -> None:
        first_case = self._case()
        second_case = self._case()
        second_case["s25v_case"]["before_witness"]["context"]["observer_id"] = "observer-beta"
        second_case["s25v_case"]["input_digest"] = s25v.input_digest(second_case["s25v_case"])
        self._sync_case(second_case)

        first_before = deepcopy(first_case)
        first_result = s25w.evaluate_projection_delta(first_case)
        second_result = s25w.evaluate_projection_delta(second_case)
        first_again = s25w.evaluate_projection_delta(first_case)

        self.assertEqual(first_case, first_before)
        self.assertEqual(first_result, first_again)
        self.assertNotEqual(first_result["s25v_case_digest"], second_result["s25v_case_digest"])

    def test_node_budget_rejects_unbounded_padding(self) -> None:
        case = self._case()
        case["s25v_case"]["padding"] = list(range(10001))

        result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.INPUT_INVALID)

    def test_missing_and_extra_envelope_keys_are_invalid(self) -> None:
        case = self._case()
        case.pop("s25v_output")
        self.assertEqual(s25w.evaluate_projection_delta(case)["classification"], s25w.INPUT_INVALID)

        case = self._case()
        case["extra"] = "not allowed"
        self.assertEqual(s25w.evaluate_projection_delta(case)["classification"], s25w.INPUT_INVALID)

    def test_expected_extra_key_is_invalid(self) -> None:
        case = self._case()
        case["expected"]["extra"] = "not allowed"
        case["input_digest"] = s25w.input_digest(case)

        result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.INPUT_INVALID)
        self.assertEqual(result["reason"], "EXPECTED_SCHEMA_NOT_EXACT")

    def test_duplicate_json_keys_are_invalid(self) -> None:
        case = self._case()
        raw = json.dumps(case, sort_keys=True, separators=(",", ":"))
        raw = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '","input_digest":"' + ("1" * 64) + '"}'

        result = s25w.evaluate_projection_delta(raw)

        self.assertEqual(result["classification"], s25w.INPUT_INVALID)

    def test_bool_and_float_expected_counters_are_invalid(self) -> None:
        case = self._case()
        case["expected"]["required_member_count"] = True
        case["input_digest"] = s25w.input_digest(case)
        result_bool = s25w.evaluate_projection_delta(case)

        case = self._case()
        case["expected"]["required_member_count"] = 1.5
        case["input_digest"] = "0" * 64
        result_float = s25w.evaluate_projection_delta(case)

        self.assertEqual(result_bool["classification"], s25w.INPUT_INVALID)
        self.assertEqual(result_float["classification"], s25w.INPUT_INVALID)

    def test_unsafe_uri_and_path_values_are_invalid(self) -> None:
        for value in ("/tmp/secret", "~/secret", "https://example.invalid", "\\\\server\\share"):
            with self.subTest(value=value):
                case = self._case()
                case["s25v_case"]["unsafe"] = value
                case["s25v_case"]["input_digest"] = s25v.input_digest(case["s25v_case"])
                case["input_digest"] = s25w.input_digest(case)
                result = s25w.evaluate_projection_delta(case)
                self.assertEqual(result["classification"], s25w.INPUT_INVALID)

    def test_recursive_input_is_invalid_without_recursion_error(self) -> None:
        case = self._case()
        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        case["s25v_case"]["recursive"] = recursive

        result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.INPUT_INVALID)

    def test_no_file_or_network_discovery_is_needed(self) -> None:
        case = self._case()
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch("socket.socket", side_effect=AssertionError("network is forbidden")):
            result = s25w.evaluate_projection_delta(case)

        self.assertEqual(result["classification"], s25w.PROJECTION_DELTA_NO_CHANGE)

    def test_only_public_s25v_boundary_is_imported(self) -> None:
        source = Path(s25w.__file__).read_text(encoding="utf-8")

        self.assertNotIn("test_w5_s25v", source)
        self.assertNotIn("_case(", source)
        self.assertNotIn("_witness(", source)


def build_complete_s25w_case() -> dict[str, object]:
    """Public test-only fixture boundary for downstream W5 cards."""

    return W5S25WProjectionDeltaTests._case()


if __name__ == "__main__":
    unittest.main()
