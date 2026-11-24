"""Adversarial tests for the pure S25V projection-set completeness gate."""

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

import support.w5_s25r_receipt_reconciliation as s25r  # noqa: E402
import support.w5_s25t_receipt_provenance as s25t  # noqa: E402
import support.w5_s25u_provenance_monotonicity as s25u  # noqa: E402
import support.w5_s25v_projection_set_completeness as s25v  # noqa: E402
import test_w5_s25t_receipt_provenance as s25t_tests  # noqa: E402
import test_w5_s25u_provenance_monotonicity as s25u_tests  # noqa: E402


class W5S25VProjectionSetCompletenessTests(unittest.TestCase):
    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _projection(cls, case: dict[str, object], result: dict[str, object]) -> dict[str, object]:
        expected = case["expected"]
        projection: dict[str, object] = {
            "schema": "s25u.s25t-projection.v1",
            "s25t_case_digest": s25t.input_digest(case),
            "s25t_result_digest": cls._digest(result),
            "s25r_case_digest": expected["s25r_case_digest"],
            "s25r_result_digest": expected["s25r_result_digest"],
            "s25r_projection_digest": expected["s25r_projection_digest"],
            "source_set_digest": expected["source_set_digest"],
            "window_digest": expected["window_digest"],
            "observation_set_digest": expected["observation_set_digest"],
            "classification": result["classification"],
            "status": result["status"],
            "decision": result["decision"],
            "reason": result["reason"],
            "provenance_status": result["provenance_status"],
            "coverage_status": result["coverage_status"],
            "freshness_status": result["freshness_status"],
            "comparison_status": result["comparison_status"],
            "source_count": result["source_count"],
            "observation_count": result["observation_count"],
            "witness_only": result["witness_only"],
            "source_witnessed": result["source_witnessed"],
            "s25r_classification": result["s25r_classification"],
            "s25r_status": result["s25r_status"],
            "s25r_reconciliation_status": result["s25r_reconciliation_status"],
            "production_status": result["production_status"],
            "authority_claim": result["authority_claim"],
            **{field: result[field] for field in s25v.FALSE_FLAGS},
            "subject_digest": expected["subject_digest"],
            "scope_digest": expected["scope_digest"],
            "baseline_digest": expected["baseline_digest"],
            "epoch": expected["epoch"],
            "previous_sequence": expected["previous_sequence"],
            "current_sequence": expected["current_sequence"],
            "observation_id": expected["observation_id"],
            "idempotency_key": expected["idempotency_key"],
            "observer_id": expected["observer_id"],
            "comparison_group": expected["comparison_group"],
        }
        projection["projection_digest"] = cls._digest(projection)
        return projection

    @classmethod
    def _witness(cls, case: dict[str, object]) -> dict[str, object]:
        t_result = s25t.evaluate_receipt_provenance(case)
        r_result = s25r.evaluate_receipt_reconciliation(case["s25r_case"])
        projection = cls._projection(case, t_result)
        context = {key: projection[key] for key in s25v.CONTEXT_KEYS}
        context_digest = cls._digest(context)
        members: list[dict[str, object]] = []
        for member_id, fields in s25v.MEMBER_FIELDS:
            member: dict[str, object] = {
                "member_id": member_id,
                "observation_state": "PRESENT",
                "value_digest": cls._digest({field: projection[field] for field in fields}),
                "context_digest": context_digest,
                "member_digest": "",
            }
            member["member_digest"] = cls._digest({key: member[key] for key in ("member_id", "observation_state", "value_digest", "context_digest")})
            members.append(member)
        member_digests = [member["member_digest"] for member in members]
        return {
            "s25t_output": t_result,
            "s25r_output": r_result,
            "context": context,
            "members": members,
            "projection_set_digest": cls._digest({"schema": "s25v.projection-set.v1", "member_digests": sorted(member_digests)}),
            "projection_order_digest": cls._digest({"schema": "s25v.projection-set.v1", "member_digests": member_digests}),
        }

    @classmethod
    def _case(cls, u_case: dict[str, object] | None = None) -> dict[str, object]:
        u_case = deepcopy(u_case) if u_case is not None else s25u_tests.build_complete_s25u_case()
        u_result = s25u.evaluate_provenance_monotonicity(u_case)
        before_case = u_case["before_case"]
        after_case = u_case["after_case"]
        before_witness = cls._witness(before_case)
        after_witness = cls._witness(after_case)
        before_projection = u_case["before_projection"]
        after_projection = u_case["after_projection"]
        expected: dict[str, object] = {
            "s25u_case_digest": s25u.input_digest(u_case),
            "s25u_result_digest": cls._digest(u_result),
            "before_s25t_case_digest": before_projection["s25t_case_digest"],
            "after_s25t_case_digest": after_projection["s25t_case_digest"],
            "before_s25t_result_digest": before_projection["s25t_result_digest"],
            "after_s25t_result_digest": after_projection["s25t_result_digest"],
            "before_s25r_case_digest": before_projection["s25r_case_digest"],
            "after_s25r_case_digest": after_projection["s25r_case_digest"],
            "before_s25r_result_digest": before_projection["s25r_result_digest"],
            "after_s25r_result_digest": after_projection["s25r_result_digest"],
            "before_s25r_projection_digest": before_projection["s25r_projection_digest"],
            "after_s25r_projection_digest": after_projection["s25r_projection_digest"],
            "before_context_digest": cls._digest(before_witness["context"]),
            "after_context_digest": cls._digest(after_witness["context"]),
            "before_projection_set_digest": before_witness["projection_set_digest"],
            "after_projection_set_digest": after_witness["projection_set_digest"],
            "before_projection_order_digest": before_witness["projection_order_digest"],
            "after_projection_order_digest": after_witness["projection_order_digest"],
            "subject_digest": before_projection["subject_digest"],
            "scope_digest": before_projection["scope_digest"],
            "baseline_digest": before_projection["baseline_digest"],
            "observer_id": before_projection["observer_id"],
            "comparison_group": before_projection["comparison_group"],
            "epoch": before_projection["epoch"],
            "before_sequence": before_projection["current_sequence"],
            "after_sequence": after_projection["current_sequence"],
            "transition_kind": u_result["transition_kind"],
            "required_member_count": len(s25v.ALLOWED_MEMBER_IDS),
        }
        case: dict[str, object] = {
            "schema_version": s25v.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25v.CANONICALIZATION,
            "expected": expected,
            "s25u_case": u_case,
            "s25u_output": u_result,
            "allowed_member_ids": list(s25v.ALLOWED_MEMBER_IDS),
            "before_witness": before_witness,
            "after_witness": after_witness,
            "input_digest": "",
        }
        case["input_digest"] = s25v.input_digest(case)
        return case

    @staticmethod
    def _reseal(case: dict[str, object]) -> None:
        case["input_digest"] = s25v.input_digest(case)

    @staticmethod
    def _reseal_u(case: dict[str, object]) -> None:
        case["input_digest"] = s25u.input_digest(case)

    @staticmethod
    def _reseal_members(witness: dict[str, object]) -> None:
        members = witness["members"]
        for member in members:
            member["member_digest"] = W5S25VProjectionSetCompletenessTests._digest(
                {key: member[key] for key in ("member_id", "observation_state", "value_digest", "context_digest")}
            )
        digests = [member["member_digest"] for member in members]
        witness["projection_set_digest"] = W5S25VProjectionSetCompletenessTests._digest(
            {"schema": "s25v.projection-set.v1", "member_digests": sorted(digests)}
        )
        witness["projection_order_digest"] = W5S25VProjectionSetCompletenessTests._digest(
            {"schema": "s25v.projection-set.v1", "member_digests": digests}
        )

    def test_complete_set_is_only_a_read_only_witness(self) -> None:
        case = self._case()
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_SET_COMPLETE)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["reason"], "COMPLETE_PROJECTION_SET")
        self.assertEqual(result["before_member_count"], len(s25v.ALLOWED_MEMBER_IDS))
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["floor_advanced"])

    def test_input_is_unchanged_and_repeated_calls_have_no_hidden_state(self) -> None:
        case = self._case()
        before = deepcopy(case)
        first = s25v.evaluate_projection_set_completeness(case)
        second = s25v.evaluate_projection_set_completeness(deepcopy(case))
        third = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(case, before)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_missing_member_is_partial(self) -> None:
        case = self._case()
        case["before_witness"]["members"].pop()
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_PARTIAL)
        self.assertEqual(result["reason"], "MEMBER_MISSING")

    def test_extra_member_is_rejected(self) -> None:
        case = self._case()
        case["before_witness"]["members"].append({"member_id": "EXTRA"})
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "MEMBER_EXTRA")

    def test_duplicate_member_is_rejected_before_normalization(self) -> None:
        case = self._case()
        members = case["before_witness"]["members"]
        members[1]["member_id"] = members[0]["member_id"]
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "MEMBER_DUPLICATE")

    def test_unknown_member_is_rejected(self) -> None:
        case = self._case()
        case["before_witness"]["members"][0]["member_id"] = "UNKNOWN"
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "MEMBER_UNKNOWN")

    def test_order_drift_is_rejected_even_when_set_is_complete(self) -> None:
        case = self._case()
        case["before_witness"]["members"] = list(reversed(case["before_witness"]["members"]))
        self._reseal_members(case["before_witness"])
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "MEMBER_ORDER_DRIFT")

    def test_member_value_resealing_cannot_hide_drift(self) -> None:
        case = self._case()
        case["before_witness"]["members"][0]["value_digest"] = "f" * 64
        self._reseal_members(case["before_witness"])
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "MEMBER_VALUE_MISMATCH")

    def test_set_digest_resealing_cannot_hide_drift(self) -> None:
        case = self._case()
        case["before_witness"]["projection_set_digest"] = "e" * 64
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "PROJECTION_SET_DIGEST_MISMATCH")

    def test_context_drift_is_conflict(self) -> None:
        case = self._case()
        case["before_witness"]["context"]["scope_digest"] = "f" * 64
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_CONFLICT)
        self.assertEqual(result["reason"], "WITNESS_CONTEXT_DRIFT")

    def test_s25u_output_resealing_cannot_authorize_forgery(self) -> None:
        case = self._case()
        case["s25u_output"]["reason"] = "FORGED"
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.S25U_REJECTED)
        self.assertEqual(result["reason"], "S25U_RESULT_MISMATCH")

    def test_semantically_forged_s25u_summary_is_rejected(self) -> None:
        case = self._case()
        forged = deepcopy(case["s25u_output"])
        forged["before_status"] = "FORGED"
        case["s25u_output"] = forged
        self._reseal(case)
        with patch.object(s25v, "evaluate_provenance_monotonicity", return_value=forged):
            result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.S25U_REJECTED)
        self.assertEqual(result["reason"], "S25U_RESULT_SEMANTIC_MISMATCH")

    def test_invalid_nested_s25u_case_is_rejected(self) -> None:
        case = self._case()
        case["s25u_case"]["before_case"]["input_digest"] = "0" * 64
        self._reseal_u(case["s25u_case"])
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.S25U_REJECTED)

    def test_invalid_nested_s25t_case_is_rejected(self) -> None:
        case = self._case()
        case["s25u_case"]["before_case"]["input_digest"] = "0" * 64
        self._reseal_u(case["s25u_case"])
        self._reseal(case)
        with patch.object(s25v, "evaluate_provenance_monotonicity", return_value=case["s25u_output"]):
            result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.S25T_REJECTED)

    def test_invalid_nested_s25r_case_is_rejected_exactly(self) -> None:
        case = self._case()
        case["s25u_case"]["before_case"]["s25r_case"]["input_digest"] = "0" * 64
        self._reseal_u(case["s25u_case"])
        self._reseal(case)
        with patch.object(s25v, "evaluate_provenance_monotonicity", return_value=case["s25u_output"]), patch.object(
            s25v, "evaluate_receipt_provenance", return_value=case["before_witness"]["s25t_output"]
        ):
            result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.S25R_REJECTED)

    def test_forged_s25r_q_metadata_is_rejected(self) -> None:
        case = self._case()
        forged_r = deepcopy(case["before_witness"]["s25r_output"])
        forged_r["s25q_classification"] = "INPUT_INVALID"
        with patch.object(s25v, "evaluate_receipt_reconciliation", return_value=forged_r):
            result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.S25R_REJECTED)

    def test_partial_s25t_evidence_cannot_be_complete(self) -> None:
        partial = s25t_tests.build_complete_s25t_case()
        observation = partial["observations"][0]
        observation.update(
            {
                "observation_state": "ABSENT",
                "comparison_status": "NOT_COMPARABLE",
                "freshness_status": "UNKNOWN",
                "coverage_status": "PARTIAL",
                "receipt_digest": None,
            }
        )
        s25t_tests.reseal_s25t_observation(partial, 0)
        u_case = s25u_tests.build_s25u_case_from_s25t_cases(partial, deepcopy(partial), "NO_CHANGE")
        case = self._case(u_case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_PARTIAL)
        self.assertEqual(result["reason"], "S25T_NOT_COMPLETE")

    def test_stale_and_future_s25t_evidence_keep_precise_review_classes(self) -> None:
        for state, freshness, expected_class, expected_reason in (
            ("STALE", "STALE", s25v.PROJECTION_STALE, "S25T_STALE"),
            ("FUTURE", "FUTURE", s25v.PROJECTION_OUT_OF_WINDOW, "S25T_OUT_OF_WINDOW"),
        ):
            with self.subTest(state=state):
                nested = s25t_tests.build_complete_s25t_case()
                observation = nested["observations"][0]
                observation.update(
                    {
                        "observation_state": state,
                        "comparison_status": "NOT_COMPARABLE",
                        "freshness_status": freshness,
                        "coverage_status": "PARTIAL",
                        "receipt_digest": None,
                    }
                )
                s25t_tests.reseal_s25t_observation(nested, 0)
                u_case = s25u_tests.build_s25u_case_from_s25t_cases(nested, deepcopy(nested), "NO_CHANGE")
                result = s25v.evaluate_projection_set_completeness(self._case(u_case))
                self.assertEqual(result["classification"], expected_class)
                self.assertEqual(result["reason"], expected_reason)

    def test_next_sequence_contract_accepts_only_contiguous_public_state(self) -> None:
        case = self._case()
        u_case = case["s25u_case"]
        before_case = u_case["before_case"]
        after_case = u_case["after_case"]
        before_t = case["before_witness"]["s25t_output"]
        before_r = case["before_witness"]["s25r_output"]
        after_t = deepcopy(before_t)
        after_r = deepcopy(before_r)
        next_sequence = before_case["expected"]["current_sequence"] + 1
        after_case["expected"]["previous_sequence"] = before_case["expected"]["current_sequence"]
        after_case["expected"]["current_sequence"] = next_sequence
        after_projection = self._projection(after_case, after_t)
        u_case["after_projection"] = after_projection
        u_case["expected"]["after_sequence"] = next_sequence
        u_case["expected"]["after_projection_digest"] = after_projection["projection_digest"]
        u_case["expected"]["after_case_digest"] = s25t.input_digest(after_case)
        u_case["expected"]["after_result_digest"] = self._digest(after_t)
        u_case["input_digest"] = s25u.input_digest(u_case)
        forged_u = deepcopy(case["s25u_output"])
        forged_u.update(
            {
                "transition_kind": "NEXT_SEQUENCE",
                "reason": "MONOTONIC_NEXT_SEQUENCE",
                "before_sequence": before_case["expected"]["current_sequence"],
                "after_sequence": next_sequence,
            }
        )
        with patch.object(s25t, "evaluate_receipt_provenance", side_effect=[before_t, after_t]), patch.object(
            s25r, "evaluate_receipt_reconciliation", side_effect=[before_r, after_r]
        ):
            case["after_witness"] = self._witness(after_case)
        case["s25u_output"] = forged_u
        expected = case["expected"]
        expected.update(
            {
                "s25u_case_digest": s25u.input_digest(u_case),
                "s25u_result_digest": self._digest(forged_u),
                "after_s25t_case_digest": after_projection["s25t_case_digest"],
                "after_s25t_result_digest": after_projection["s25t_result_digest"],
                "after_s25r_case_digest": after_projection["s25r_case_digest"],
                "after_s25r_result_digest": after_projection["s25r_result_digest"],
                "after_s25r_projection_digest": after_projection["s25r_projection_digest"],
                "after_context_digest": self._digest(case["after_witness"]["context"]),
                "after_projection_set_digest": case["after_witness"]["projection_set_digest"],
                "after_projection_order_digest": case["after_witness"]["projection_order_digest"],
                "after_sequence": next_sequence,
                "transition_kind": "NEXT_SEQUENCE",
            }
        )
        self._reseal(case)
        with patch.object(s25v, "evaluate_provenance_monotonicity", return_value=forged_u), patch.object(
            s25v, "evaluate_receipt_provenance", side_effect=[before_t, after_t]
        ), patch.object(s25v, "evaluate_receipt_reconciliation", side_effect=[before_r, after_r]):
            result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_SET_COMPLETE)
        self.assertEqual(result["transition_kind"], "NEXT_SEQUENCE")

    def test_expected_identity_drift_is_not_authorized_by_resealing(self) -> None:
        case = self._case()
        case["expected"]["scope_digest"] = "e" * 64
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_CONFLICT)
        self.assertEqual(result["reason"], "EXPECTED_IDENTITY_DRIFT")

    def test_allowed_member_echo_cannot_extend_contract(self) -> None:
        case = self._case()
        case["allowed_member_ids"].append("EXTRA")
        self._reseal(case)
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "ALLOWED_MEMBER_IDS_MISMATCH")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        case = self._case()
        raw = json.dumps(case, sort_keys=True, separators=(",", ":"))
        raw = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '","input_digest":"' + ("1" * 64) + '"}'
        result = s25v.evaluate_projection_set_completeness(raw)
        self.assertEqual(result["classification"], s25v.INPUT_INVALID)

    def test_bool_and_float_values_are_rejected(self) -> None:
        case = self._case()
        case["expected"]["epoch"] = True
        self._reseal(case)
        result_bool = s25v.evaluate_projection_set_completeness(case)
        case = self._case()
        case["before_witness"]["context"]["epoch"] = 1.5
        case["input_digest"] = "0" * 64
        result_float = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result_bool["classification"], s25v.PROJECTION_REJECTED)
        self.assertEqual(result_float["classification"], s25v.INPUT_INVALID)

    def test_unsafe_uri_and_path_are_not_admissible(self) -> None:
        for unsafe in ("/tmp/projection", "https://example.invalid/projection", "file:///tmp/projection", r"\\server\share\projection"):
            with self.subTest(unsafe=unsafe):
                case = self._case()
                case["expected"]["observer_id"] = unsafe
                self._reseal(case)
                result = s25v.evaluate_projection_set_completeness(case)
                self.assertEqual(result["classification"], s25v.INPUT_INVALID)

    def test_recursive_input_is_rejected_without_recursion_error(self) -> None:
        case = self._case()
        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        case["before_witness"]["context"] = recursive
        result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.INPUT_INVALID)

    def test_no_file_or_network_discovery_is_needed(self) -> None:
        case = self._case()
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch("socket.socket", side_effect=AssertionError("network is forbidden")):
            result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.PROJECTION_SET_COMPLETE)

    def test_public_s25t_exception_is_rejected_fail_closed(self) -> None:
        case = self._case()
        with patch.object(s25v, "evaluate_receipt_provenance", side_effect=RuntimeError("synthetic failure")):
            result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.S25T_REJECTED)

    def test_public_s25r_exception_is_rejected_fail_closed(self) -> None:
        case = self._case()
        with patch.object(s25v, "evaluate_receipt_reconciliation", side_effect=RuntimeError("synthetic failure")):
            result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.S25R_REJECTED)

    def test_public_s25u_exception_is_rejected_fail_closed(self) -> None:
        case = self._case()
        with patch.object(s25v, "evaluate_provenance_monotonicity", side_effect=RuntimeError("synthetic failure")):
            result = s25v.evaluate_projection_set_completeness(case)
        self.assertEqual(result["classification"], s25v.S25U_REJECTED)


if __name__ == "__main__":
    unittest.main()


def build_complete_s25v_case() -> dict[str, object]:
    """Public test-only fixture boundary for downstream W5 cards."""

    return W5S25VProjectionSetCompletenessTests._case()
