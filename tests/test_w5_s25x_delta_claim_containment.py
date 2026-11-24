"""Adversarial tests for the pure S25X delta-claim containment witness."""

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
import support.w5_s25x_delta_claim_containment as s25x  # noqa: E402
import test_w5_s25w_projection_delta as s25w_tests  # noqa: E402


class W5S25XDeltaClaimContainmentTests(unittest.TestCase):
    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _claim_from_output(
        cls, output: dict[str, object], *, s25w_case_digest: str, s25w_result_digest: str
    ) -> dict[str, object]:
        fields = (
            "classification",
            "transition_kind",
            "changed_member_ids",
            "unchanged_member_ids",
            "allowed_changed_member_ids",
            "changed_member_count",
            "before_projection_set_digest",
            "after_projection_set_digest",
            "before_projection_order_digest",
            "after_projection_order_digest",
            "delta_digest",
            "production_status",
            "authority_claim",
        )
        return {
            "claim_scope": s25x.CLAIM_SCOPE,
            "s25w_case_digest": s25w_case_digest,
            "s25w_result_digest": s25w_result_digest,
            **{field: output[field] for field in fields},
            **{field: output[field] for field in s25w.FALSE_FLAGS},
        }

    @classmethod
    def _case(cls) -> dict[str, object]:
        s25w_case = deepcopy(s25w_tests.build_complete_s25w_case())
        s25w_output = s25w.evaluate_projection_delta(s25w_case)
        s25w_case_digest = s25w.input_digest(s25w_case)
        s25w_result_digest = cls._digest(s25w_output)
        claim = cls._claim_from_output(
            s25w_output,
            s25w_case_digest=s25w_case_digest,
            s25w_result_digest=s25w_result_digest,
        )
        case: dict[str, object] = {
            "schema_version": s25x.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25x.CANONICALIZATION,
            "expected": {
                "s25w_case_digest": s25w_case_digest,
                "s25w_result_digest": s25w_result_digest,
                "claim_digest": cls._digest(claim),
                "required_member_count": len(s25w.ALLOWED_MEMBER_IDS),
            },
            "s25w_case": s25w_case,
            "s25w_output": s25w_output,
            "claim": claim,
            "input_digest": "",
        }
        case["input_digest"] = s25x.input_digest(case)
        return case

    @classmethod
    def _reseal_witness(cls, witness: dict[str, object]) -> None:
        for member in witness["members"]:
            member["member_digest"] = s25w.member_digest(member)
        digests = [member["member_digest"] for member in witness["members"]]
        witness["projection_set_digest"] = cls._digest(
            {"schema": s25w.PROJECTION_SET_SCHEMA, "member_digests": sorted(digests)}
        )
        witness["projection_order_digest"] = cls._digest(
            {"schema": s25w.PROJECTION_SET_SCHEMA, "member_digests": digests}
        )

    @classmethod
    def _synthetic_next_case(cls, member_ids: list[str]) -> dict[str, object]:
        """Exercise W's public NEXT_SEQUENCE shape without claiming E2E upstream evidence."""
        s25w_case = deepcopy(s25w_tests.build_complete_s25w_case())
        after_witness = s25w_case["s25v_case"]["after_witness"]
        for member_id in member_ids:
            member = next(item for item in after_witness["members"] if item["member_id"] == member_id)
            member["value_digest"] = "a" * 64 if member["value_digest"] != "a" * 64 else "b" * 64
        cls._reseal_witness(after_witness)
        s25w_case["s25v_case"]["input_digest"] = s25v.input_digest(s25w_case["s25v_case"])
        s25w_case["input_digest"] = s25w.input_digest(s25w_case)

        base_output = s25w.evaluate_projection_delta(s25w_tests.build_complete_s25w_case())
        output = deepcopy(base_output)
        before_members = s25w_case["s25v_case"]["before_witness"]["members"]
        after_members = s25w_case["s25v_case"]["after_witness"]["members"]
        before = {member["member_id"]: member["member_digest"] for member in before_members}
        after = {member["member_id"]: member["member_digest"] for member in after_members}
        changed = [member_id for member_id in s25w.ALLOWED_MEMBER_IDS if before[member_id] != after[member_id]]
        unchanged = [member_id for member_id in s25w.ALLOWED_MEMBER_IDS if member_id not in changed]
        output.update(
            {
                "classification": s25w.PROJECTION_DELTA_NEXT_SEQUENCE,
                "reason": "ALLOWED_SUCCESSOR_DELTA",
                "transition_kind": "NEXT_SEQUENCE",
                "changed_member_ids": changed,
                "unchanged_member_ids": unchanged,
                "allowed_changed_member_ids": list(s25w.NEXT_SEQUENCE_ALLOWED_MEMBER_IDS),
                "changed_member_count": len(changed),
                "before_projection_set_digest": s25w_case["s25v_case"]["before_witness"]["projection_set_digest"],
                "after_projection_set_digest": s25w_case["s25v_case"]["after_witness"]["projection_set_digest"],
                "before_projection_order_digest": s25w_case["s25v_case"]["before_witness"]["projection_order_digest"],
                "after_projection_order_digest": s25w_case["s25v_case"]["after_witness"]["projection_order_digest"],
                "delta_digest": cls._digest(
                    {
                        "schema": s25w.DELTA_SCHEMA,
                        "transition_kind": "NEXT_SEQUENCE",
                        "members": [
                            {
                                "member_id": member_id,
                                "before_member_digest": before[member_id],
                                "after_member_digest": after[member_id],
                                "changed": before[member_id] != after[member_id],
                            }
                            for member_id in s25w.ALLOWED_MEMBER_IDS
                        ],
                    }
                ),
                "s25v_case_digest": s25v.input_digest(s25w_case["s25v_case"]),
            }
        )
        s25w_case_digest = s25w.input_digest(s25w_case)
        s25w_result_digest = cls._digest(output)
        claim = cls._claim_from_output(
            output,
            s25w_case_digest=s25w_case_digest,
            s25w_result_digest=s25w_result_digest,
        )
        case: dict[str, object] = {
            "schema_version": s25x.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25x.CANONICALIZATION,
            "expected": {
                "s25w_case_digest": s25w_case_digest,
                "s25w_result_digest": s25w_result_digest,
                "claim_digest": cls._digest(claim),
                "required_member_count": len(s25w.ALLOWED_MEMBER_IDS),
            },
            "s25w_case": s25w_case,
            "s25w_output": output,
            "claim": claim,
            "input_digest": "",
        }
        case["input_digest"] = s25x.input_digest(case)
        return case

    @staticmethod
    def _reseal(case: dict[str, object]) -> None:
        case["input_digest"] = s25x.input_digest(case)

    @staticmethod
    def _reseal_nested_w_case(case: dict[str, object]) -> None:
        case["s25w_case"]["input_digest"] = s25w.input_digest(case["s25w_case"])
        case["expected"]["s25w_case_digest"] = s25w.input_digest(case["s25w_case"])
        case["claim"]["s25w_case_digest"] = case["expected"]["s25w_case_digest"]
        case["expected"]["claim_digest"] = W5S25XDeltaClaimContainmentTests._digest(case["claim"])
        case["input_digest"] = s25x.input_digest(case)

    def test_positive_claim_is_contained_to_member_delta_and_read_only(self) -> None:
        case = self._case()

        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.DELTA_CLAIM_CONTAINED)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["claim_scope"], s25x.CLAIM_SCOPE)
        self.assertEqual(result["transition_kind"], "NO_CHANGE")
        self.assertEqual(result["changed_member_ids"], [])
        self.assertEqual(result["unchanged_member_ids"], list(s25w.ALLOWED_MEMBER_IDS))
        self.assertEqual(result["changed_member_count"], 0)
        self.assertEqual(len(result["member_provenance"]), len(s25w.ALLOWED_MEMBER_IDS))
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")
        self.assertTrue(all(result[field] is False for field in s25w.FALSE_FLAGS))
        for item in result["member_provenance"]:
            self.assertEqual(
                set(item),
                {
                    "member_id",
                    "before_member_digest",
                    "after_member_digest",
                    "before_value_digest",
                    "after_value_digest",
                    "before_context_digest",
                    "after_context_digest",
                    "changed",
                },
            )
            self.assertFalse(item["changed"])

    def test_input_is_unchanged_and_repeated_calls_have_no_hidden_state(self) -> None:
        case = self._case()
        before = deepcopy(case)

        first = s25x.evaluate_delta_claim_containment(case)
        second = s25x.evaluate_delta_claim_containment(deepcopy(case))
        third = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(case, before)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_next_sequence_allowed_members_are_contained_at_public_boundary(self) -> None:
        for member_id in s25w.NEXT_SEQUENCE_ALLOWED_MEMBER_IDS:
            with self.subTest(member_id=member_id):
                case = self._synthetic_next_case([member_id])
                with patch.object(s25x, "evaluate_projection_delta", return_value=case["s25w_output"]):
                    result = s25x.evaluate_delta_claim_containment(case)

                self.assertEqual(result["classification"], s25x.DELTA_CLAIM_CONTAINED)
                self.assertEqual(result["transition_kind"], "NEXT_SEQUENCE")
                self.assertEqual(result["changed_member_ids"], [member_id])
                self.assertEqual(result["changed_member_count"], 1)

    def test_next_sequence_without_delta_or_with_forbidden_delta_is_rejected(self) -> None:
        for member_ids in ([], ["IDENTITY"], ["WINDOW_DIGEST", "IDENTITY"]):
            with self.subTest(member_ids=member_ids):
                case = self._synthetic_next_case(member_ids)
                with patch.object(s25x, "evaluate_projection_delta", return_value=case["s25w_output"]):
                    result = s25x.evaluate_delta_claim_containment(case)

                self.assertEqual(result["classification"], s25x.S25W_REJECTED)
                self.assertEqual(result["reason"], "S25W_DELTA_SEMANTIC_MISMATCH")

    def test_a_b_a_calls_do_not_share_case_state(self) -> None:
        first_case = self._case()
        second_case = self._synthetic_next_case(["WINDOW_DIGEST"])

        first_before = deepcopy(first_case)
        first_result = s25x.evaluate_delta_claim_containment(first_case)
        with patch.object(s25x, "evaluate_projection_delta", return_value=second_case["s25w_output"]):
            second_result = s25x.evaluate_delta_claim_containment(second_case)
        first_again = s25x.evaluate_delta_claim_containment(first_case)

        self.assertEqual(first_case, first_before)
        self.assertEqual(first_result, first_again)
        self.assertEqual(second_result["classification"], s25x.DELTA_CLAIM_CONTAINED)
        self.assertNotEqual(first_result["s25w_case_digest"], second_result["s25w_case_digest"])

    def test_claim_scope_is_fixed_and_unsupported_scope_is_not_promoted(self) -> None:
        case = self._case()
        case["claim"]["claim_scope"] = "SUCCESSOR_CONTINUITY"
        self._reseal(case)

        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.CLAIM_SCOPE_UNSUPPORTED)
        self.assertEqual(result["reason"], "CLAIM_SCOPE_UNSUPPORTED")
        self.assertEqual(result["claim_scope"], s25x.UNSUPPORTED_SCOPE)
        self.assertEqual(result["status"], "TEST_BLOCKED")

    def test_claim_field_drift_is_not_hidden_by_claim_and_outer_resealing(self) -> None:
        case = self._case()
        case["claim"]["changed_member_ids"] = ["WINDOW_DIGEST"]
        case["claim"]["changed_member_count"] = 1
        case["expected"]["claim_digest"] = self._digest(case["claim"])
        self._reseal(case)

        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.CLAIM_NOT_CONTAINED)
        self.assertEqual(result["reason"], "CLAIM_NOT_BOUND")

    def test_transition_and_delta_digest_claims_cannot_be_invented(self) -> None:
        for field, value in (("transition_kind", "NEXT_SEQUENCE"), ("delta_digest", "f" * 64)):
            with self.subTest(field=field):
                case = self._case()
                case["claim"][field] = value
                case["expected"]["claim_digest"] = self._digest(case["claim"])
                self._reseal(case)

                result = s25x.evaluate_delta_claim_containment(case)

                self.assertEqual(result["classification"], s25x.CLAIM_NOT_CONTAINED)
                self.assertEqual(result["reason"], "CLAIM_NOT_BOUND")

    def test_false_authority_flags_cannot_be_raised_by_downstream_claim(self) -> None:
        for field in s25w.FALSE_FLAGS:
            with self.subTest(field=field):
                case = self._case()
                case["claim"][field] = True
                case["expected"]["claim_digest"] = self._digest(case["claim"])
                self._reseal(case)

                result = s25x.evaluate_delta_claim_containment(case)

                self.assertEqual(result["classification"], s25x.CLAIM_NOT_CONTAINED)
                self.assertEqual(result["reason"], "CLAIM_NOT_BOUND")

    def test_claim_scalar_types_are_strictly_bound(self) -> None:
        for field, value in (("changed_member_count", True), ("write_authorized", 0)):
            with self.subTest(field=field):
                case = self._case()
                case["claim"][field] = value
                case["expected"]["claim_digest"] = self._digest(case["claim"])
                self._reseal(case)

                result = s25x.evaluate_delta_claim_containment(case)

                self.assertEqual(result["classification"], s25x.CLAIM_NOT_CONTAINED)
                self.assertEqual(result["reason"], "CLAIM_NOT_BOUND")

    def test_public_schema_constants_match_the_emitted_contract(self) -> None:
        case = self._case()
        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(set(s25x.RESULT_KEYS), set(result))
        self.assertEqual(set(s25x.CLAIM_KEYS), set(case["claim"]))
        self.assertEqual(
            set(s25x.PROVENANCE_KEYS),
            set(result["member_provenance"][0]),
        )

    def test_claim_digest_drift_is_not_authorized_by_outer_resealing(self) -> None:
        case = self._case()
        case["expected"]["claim_digest"] = "f" * 64
        self._reseal(case)

        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.CLAIM_NOT_CONTAINED)
        self.assertEqual(result["reason"], "CLAIM_DIGEST_MISMATCH")

    def test_expected_upstream_binding_drift_is_not_authorized_by_resealing(self) -> None:
        for field in ("s25w_case_digest", "s25w_result_digest"):
            with self.subTest(field=field):
                case = self._case()
                case["expected"][field] = "e" * 64
                self._reseal(case)

                result = s25x.evaluate_delta_claim_containment(case)

                self.assertEqual(result["classification"], s25x.CLAIM_NOT_CONTAINED)
                self.assertEqual(result["reason"], "EXPECTED_BINDING_MISMATCH")

    def test_forged_s25w_output_is_rejected_even_after_outer_resealing(self) -> None:
        case = self._case()
        case["s25w_output"]["reason"] = "FORGED"
        self._reseal(case)

        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.S25W_REJECTED)
        self.assertEqual(result["reason"], "S25W_RESULT_MISMATCH")

    def test_s25w_output_binding_is_strict_about_bool_and_integer_types(self) -> None:
        case = self._case()
        case["s25w_output"]["changed_member_count"] = True
        self._reseal(case)

        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.S25W_REJECTED)
        self.assertEqual(result["reason"], "S25W_RESULT_MISMATCH")

    def test_malformed_s25w_output_cannot_be_promoted(self) -> None:
        case = self._case()
        case["s25w_output"] = {"classification": s25w.PROJECTION_DELTA_NO_CHANGE}
        case["expected"]["s25w_result_digest"] = self._digest(case["s25w_output"])
        self._reseal(case)
        with patch.object(s25x, "evaluate_projection_delta", return_value=case["s25w_output"]):
            result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.CLAIM_NOT_CONTAINED)
        self.assertEqual(result["reason"], "S25W_NOT_POSITIVE")

    def test_s25w_delta_fields_are_revalidated_against_nested_members(self) -> None:
        case = self._case()
        forged = deepcopy(case["s25w_output"])
        forged["allowed_changed_member_ids"] = ["WINDOW_DIGEST"]
        forged["before_projection_set_digest"] = "f" * 64
        forged["delta_digest"] = "e" * 64
        case["s25w_output"] = forged
        case["expected"]["s25w_result_digest"] = self._digest(forged)
        case["claim"] = self._claim_from_output(
            forged,
            s25w_case_digest=case["expected"]["s25w_case_digest"],
            s25w_result_digest=case["expected"]["s25w_result_digest"],
        )
        case["expected"]["claim_digest"] = self._digest(case["claim"])
        self._reseal(case)
        with patch.object(s25x, "evaluate_projection_delta", return_value=forged):
            result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.S25W_REJECTED)
        self.assertEqual(result["reason"], "S25W_DELTA_SEMANTIC_MISMATCH")

    def test_public_s25w_exception_is_fail_closed(self) -> None:
        case = self._case()
        with patch.object(s25x, "evaluate_projection_delta", side_effect=RuntimeError("boom")):
            result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.S25W_REJECTED)
        self.assertEqual(result["reason"], "S25W_RESULT_UNREADABLE")

    def test_nested_s25w_case_digest_drift_is_rejected(self) -> None:
        case = self._case()
        case["s25w_case"]["unexpected"] = "drift"
        self._reseal(case)

        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.S25W_REJECTED)
        self.assertEqual(result["reason"], "S25W_CASE_DIGEST_DRIFT")

    def test_member_provenance_rejects_digest_tampering_after_upstream_result_reseal(self) -> None:
        case = self._case()
        member = case["s25w_case"]["s25v_case"]["before_witness"]["members"][0]
        member["value_digest"] = "a" * 64
        self._reseal_nested_w_case(case)
        original_output = deepcopy(case["s25w_output"])
        with patch.object(s25x, "evaluate_projection_delta", return_value=original_output):
            result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.S25W_REJECTED)
        self.assertEqual(result["reason"], "S25V_MEMBER_WITNESS_INVALID")

    def test_nested_witness_profile_context_and_projection_digests_are_revalidated(self) -> None:
        mutations = {
            "observation_state": lambda witness: witness["members"][0].__setitem__("observation_state", "ABSENT"),
            "context_digest": lambda witness: witness["members"][0].__setitem__("context_digest", "a" * 64),
            "projection_set_digest": lambda witness: witness.__setitem__("projection_set_digest", "f" * 64),
            "projection_order_digest": lambda witness: witness.__setitem__("projection_order_digest", "e" * 64),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = self._case()
                witness = case["s25w_case"]["s25v_case"]["before_witness"]
                mutate(witness)
                if label in {"observation_state", "context_digest"}:
                    for member in witness["members"]:
                        member["member_digest"] = s25w.member_digest(member)
                    digests = [member["member_digest"] for member in witness["members"]]
                    witness["projection_set_digest"] = self._digest(
                        {"schema": s25w.PROJECTION_SET_SCHEMA, "member_digests": sorted(digests)}
                    )
                    witness["projection_order_digest"] = self._digest(
                        {"schema": s25w.PROJECTION_SET_SCHEMA, "member_digests": digests}
                    )
                self._reseal_nested_w_case(case)
                original_output = deepcopy(case["s25w_output"])
                with patch.object(s25x, "evaluate_projection_delta", return_value=original_output):
                    result = s25x.evaluate_delta_claim_containment(case)

                self.assertEqual(result["classification"], s25x.S25W_REJECTED)
                self.assertEqual(result["reason"], "S25V_MEMBER_WITNESS_INVALID")

    def test_member_provenance_rejects_missing_extra_duplicate_and_unknown_members(self) -> None:
        mutations = {
            "missing": lambda members: members.pop(),
            "extra": lambda members: members.append(deepcopy(members[0])),
            "duplicate": lambda members: members.__setitem__(1, deepcopy(members[0])),
            "unknown": lambda members: members[0].__setitem__("member_id", "UNKNOWN"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = self._case()
                members = case["s25w_case"]["s25v_case"]["before_witness"]["members"]
                mutate(members)
                self._reseal_nested_w_case(case)
                original_output = deepcopy(case["s25w_output"])
                with patch.object(s25x, "evaluate_projection_delta", return_value=original_output):
                    result = s25x.evaluate_delta_claim_containment(case)

                self.assertEqual(result["classification"], s25x.S25W_REJECTED)
                self.assertEqual(result["reason"], "S25V_MEMBER_WITNESS_INVALID")

    def test_missing_and_extra_claim_keys_are_input_invalid(self) -> None:
        case = self._case()
        case["claim"].pop("delta_digest")
        self._reseal(case)
        self.assertEqual(s25x.evaluate_delta_claim_containment(case)["classification"], s25x.INPUT_INVALID)

        case = self._case()
        case["claim"]["extra"] = "not allowed"
        self._reseal(case)
        self.assertEqual(s25x.evaluate_delta_claim_containment(case)["classification"], s25x.INPUT_INVALID)

    def test_missing_and_extra_envelope_keys_are_input_invalid(self) -> None:
        case = self._case()
        case.pop("claim")
        self.assertEqual(s25x.evaluate_delta_claim_containment(case)["classification"], s25x.INPUT_INVALID)

        case = self._case()
        case["extra"] = "not allowed"
        self._reseal(case)
        self.assertEqual(s25x.evaluate_delta_claim_containment(case)["classification"], s25x.INPUT_INVALID)

    def test_expected_schema_and_counter_types_are_fail_closed(self) -> None:
        case = self._case()
        case["expected"]["required_member_count"] = True
        self._reseal(case)
        result_bool = s25x.evaluate_delta_claim_containment(case)

        case = self._case()
        case["expected"]["required_member_count"] = 1.5
        result_float = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result_bool["classification"], s25x.INPUT_INVALID)
        self.assertEqual(result_bool["reason"], "EXPECTED_MEMBER_COUNT_INVALID")
        self.assertEqual(result_float["classification"], s25x.INPUT_INVALID)
        self.assertEqual(result_float["reason"], "CASE_UNREADABLE_OR_TOO_DEEP")

    def test_duplicate_json_keys_are_input_invalid(self) -> None:
        case = self._case()
        raw = json.dumps(case, sort_keys=True, separators=(",", ":"))
        raw = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '","input_digest":"' + ("1" * 64) + '"}'

        result = s25x.evaluate_delta_claim_containment(raw)

        self.assertEqual(result["classification"], s25x.INPUT_INVALID)

    def test_unsafe_uri_and_path_values_are_not_admissible(self) -> None:
        for value in ("/tmp/secret", "~/secret", "https://example.invalid", "\\\\server\\share"):
            with self.subTest(value=value):
                case = self._case()
                case["claim"]["authority_claim"] = value
                self._reseal(case)
                result = s25x.evaluate_delta_claim_containment(case)
                self.assertEqual(result["classification"], s25x.INPUT_INVALID)

    def test_recursive_input_is_invalid_without_recursion_error(self) -> None:
        case = self._case()
        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        case["s25w_case"]["recursive"] = recursive

        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.INPUT_INVALID)

    def test_node_budget_rejects_unbounded_padding(self) -> None:
        case = self._case()
        padding: object = "leaf"
        for _ in range(7):
            padding = [padding] * 4
        case["s25w_case"]["padding"] = padding

        result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.INPUT_INVALID)

    def test_no_file_or_network_discovery_is_needed(self) -> None:
        case = self._case()
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch("socket.socket", side_effect=AssertionError("network is forbidden")):
            result = s25x.evaluate_delta_claim_containment(case)

        self.assertEqual(result["classification"], s25x.DELTA_CLAIM_CONTAINED)

    def test_only_public_s25w_boundary_is_imported(self) -> None:
        source = Path(s25x.__file__).read_text(encoding="utf-8")

        self.assertNotIn("w5_s25v", source)
        self.assertNotIn("test_w5_s25", source)
        self.assertIn("w5_s25w_projection_delta", source)


def build_complete_s25x_case() -> dict[str, object]:
    """Public test-only fixture boundary for downstream W5 cards."""

    return W5S25XDeltaClaimContainmentTests._case()


def build_synthetic_next_s25x_case(member_ids: list[str]) -> dict[str, object]:
    """Public boundary fixture for isolated, non-E2E NEXT contract tests."""

    return W5S25XDeltaClaimContainmentTests._synthetic_next_case(member_ids)


if __name__ == "__main__":
    unittest.main()
