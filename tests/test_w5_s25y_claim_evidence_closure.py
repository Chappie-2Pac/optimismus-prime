"""Adversarial tests for the pure S25Y claim-evidence closure."""

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

import support.w5_s25x_delta_claim_containment as s25x  # noqa: E402
import support.w5_s25y_claim_evidence_closure as s25y  # noqa: E402
import test_w5_s25x_delta_claim_containment as s25x_tests  # noqa: E402


class W5S25YClaimEvidenceClosureTests(unittest.TestCase):
    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _case(cls) -> dict[str, object]:
        x_case = deepcopy(s25x_tests.build_complete_s25x_case())
        x_output = s25x.evaluate_delta_claim_containment(x_case)
        x_case_digest = s25x.input_digest(x_case)
        x_result_digest = cls._digest(x_output)
        atoms = s25y.build_claim_atoms(x_case_digest, x_result_digest, x_output)
        case: dict[str, object] = {
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
        case["input_digest"] = s25y.input_digest(case)
        return case

    @classmethod
    def _case_from_x(cls, x_case: dict[str, object], x_output: dict[str, object]) -> dict[str, object]:
        x_case_digest = s25x.input_digest(x_case)
        x_result_digest = cls._digest(x_output)
        atoms = s25y.build_claim_atoms(x_case_digest, x_result_digest, x_output)
        case: dict[str, object] = {
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
        case["input_digest"] = s25y.input_digest(case)
        return case

    @staticmethod
    def _reseal(case: dict[str, object]) -> None:
        case["input_digest"] = s25y.input_digest(case)

    @classmethod
    def _sync_output(cls, case: dict[str, object], output: dict[str, object]) -> None:
        x_case_digest = s25x.input_digest(case["s25x_case"])
        x_result_digest = cls._digest(output)
        atoms = s25y.build_claim_atoms(x_case_digest, x_result_digest, output)
        case["s25x_output"] = output
        case["claim_atoms"] = atoms
        case["expected"]["x_case_digest"] = x_case_digest
        case["expected"]["x_result_digest"] = x_result_digest
        case["expected"]["claim_digest"] = output.get("claim_digest", "0" * 64)
        case["expected"]["coverage_digest"] = s25y.coverage_digest(x_case_digest, x_result_digest, atoms)
        cls._reseal(case)

    def test_positive_coverage_closure_is_read_only_and_complete(self) -> None:
        case = self._case()

        result = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result["classification"], s25y.COVERAGE_COMPLETE)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["coverage_scope"], s25y.COVERAGE_SCOPE)
        self.assertEqual(result["claim_scope"], s25x.CLAIM_SCOPE)
        self.assertEqual(result["covered_atom_ids"], list(s25y.ATOM_IDS))
        self.assertEqual(result["uncovered_atom_ids"], [])
        self.assertEqual(result["required_atom_count"], len(s25y.ATOM_IDS))
        self.assertEqual(result["production_status"], "PRODUCTION_NOT_AUTHORIZED")
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")
        self.assertTrue(all(result[field] is False for field in s25x.FALSE_FLAGS))
        self.assertEqual(set(s25y.RESULT_KEYS), set(result))

    def test_input_is_unchanged_and_repeated_calls_have_no_hidden_state(self) -> None:
        case = self._case()
        before = deepcopy(case)

        first = s25y.evaluate_claim_evidence_closure(case)
        second = s25y.evaluate_claim_evidence_closure(deepcopy(case))
        third = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(case, before)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_a_b_a_uses_two_distinct_valid_boundary_cases_without_state_leak(self) -> None:
        first_case = self._case()
        second_x_case = s25x_tests.build_synthetic_next_s25x_case(["WINDOW_DIGEST"])
        with patch.object(s25x, "evaluate_projection_delta", return_value=second_x_case["s25w_output"]):
            second_x_output = s25x.evaluate_delta_claim_containment(second_x_case)
        second_case = self._case_from_x(second_x_case, second_x_output)
        first_before = deepcopy(first_case)

        first_result = s25y.evaluate_claim_evidence_closure(first_case)
        with patch.object(s25y, "evaluate_delta_claim_containment", return_value=second_case["s25x_output"]):
            second_result = s25y.evaluate_claim_evidence_closure(second_case)
        first_again = s25y.evaluate_claim_evidence_closure(first_case)

        self.assertEqual(first_case, first_before)
        self.assertEqual(first_result, first_again)
        self.assertEqual(second_result["classification"], s25y.COVERAGE_COMPLETE)
        self.assertNotEqual(first_result["x_case_digest"], second_result["x_case_digest"])
        self.assertEqual(second_result["covered_atom_ids"], list(s25y.ATOM_IDS))

    def test_isolated_next_boundary_is_positive_only_for_the_public_allowlist(self) -> None:
        x_case = s25x_tests.build_synthetic_next_s25x_case(["WINDOW_DIGEST"])
        with patch.object(s25x, "evaluate_projection_delta", return_value=x_case["s25w_output"]):
            x_output = s25x.evaluate_delta_claim_containment(x_case)
        case = self._case_from_x(x_case, x_output)
        with patch.object(s25y, "evaluate_delta_claim_containment", return_value=x_output):
            result = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result["classification"], s25y.COVERAGE_COMPLETE)
        self.assertEqual(result["covered_atom_ids"], list(s25y.ATOM_IDS))

    def test_fixed_claim_scope_atom_has_an_independent_oracle(self) -> None:
        case = self._case()
        atom = next(item for item in case["claim_atoms"] if item["atom_id"] == "CLAIM_SCOPE")

        self.assertEqual(atom["claim_scope"], "S25W_MEMBER_DELTA_ONLY")
        self.assertEqual(atom["evidence_kind"], "X_RESULT_FIELD")
        self.assertEqual(atom["evidence_member_ids"], [])
        self.assertEqual(atom["value_digest"], "462cf773412c961c86ee48d0b408bd430c7f127cabe6b9784e4d6e6c79e93627")

    def test_public_coverage_map_matches_an_independent_relation(self) -> None:
        expected = (
            ("X_CASE_BINDING", "X_BINDING", ()),
            ("X_RESULT_BINDING", "X_BINDING", ()),
            ("CLAIM_SCOPE", "X_RESULT_FIELD", ()),
            ("TRANSITION", "X_TRANSITION", tuple(s25x.ALLOWED_MEMBER_IDS)),
            ("MEMBER_DELTA", "MEMBER_PROVENANCE", tuple(s25x.ALLOWED_MEMBER_IDS)),
            ("MEMBER_PROVENANCE", "MEMBER_PROVENANCE", tuple(s25x.ALLOWED_MEMBER_IDS)),
            ("AUTHORITY_BOUNDARY", "AUTHORITY_BOUNDARY", ("SECURITY",)),
        )
        self.assertEqual(s25y.ATOM_COVERAGE_MAP, expected)

    def test_public_atom_builder_is_deterministic_and_fixed(self) -> None:
        case = self._case()
        atoms = s25y.build_claim_atoms(case["expected"]["x_case_digest"], case["expected"]["x_result_digest"], case["s25x_output"])

        self.assertEqual([atom["atom_id"] for atom in atoms], list(s25y.ATOM_IDS))
        self.assertEqual([atom["atom_id"] for atom in atoms], [atom["atom_id"] for atom in case["claim_atoms"]])
        self.assertEqual(s25y.coverage_digest(case["expected"]["x_case_digest"], case["expected"]["x_result_digest"], atoms), case["expected"]["coverage_digest"])

    def test_missing_extra_duplicate_unknown_and_ordered_atoms_are_incomplete(self) -> None:
        mutations = {
            "missing": lambda atoms: atoms.pop(),
            "extra": lambda atoms: atoms.append(deepcopy(atoms[-1])),
            "duplicate": lambda atoms: atoms.__setitem__(1, deepcopy(atoms[0])),
            "unknown": lambda atoms: atoms.__setitem__(0, {**atoms[0], "atom_id": "UNKNOWN"}),
            "order": lambda atoms: atoms.reverse(),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = self._case()
                mutate(case["claim_atoms"])
                self._reseal(case)

                result = s25y.evaluate_claim_evidence_closure(case)

                self.assertEqual(result["classification"], s25y.COVERAGE_INCOMPLETE)

    def test_atom_value_and_evidence_drift_cannot_be_hidden_by_resealing(self) -> None:
        for field, value in (("value_digest", "f" * 64), ("evidence_kind", "FORGED"), ("evidence_member_ids", ["IDENTITY"])):
            with self.subTest(field=field):
                case = self._case()
                case["claim_atoms"][0][field] = value
                case["expected"]["coverage_digest"] = s25y.coverage_digest(
                    case["expected"]["x_case_digest"], case["expected"]["x_result_digest"], case["claim_atoms"]
                )
                self._reseal(case)

                result = s25y.evaluate_claim_evidence_closure(case)

                self.assertEqual(result["classification"], s25y.COVERAGE_INCOMPLETE)
                self.assertEqual(result["reason"], "ATOM_BINDING_MISMATCH")
                self.assertEqual(result["uncovered_atom_ids"], ["X_CASE_BINDING"])
                self.assertEqual(result["status"], "TEST_BLOCKED")
                self.assertEqual(result["decision"], "HOLD")
                self.assertTrue(all(result[field] is False for field in s25x.FALSE_FLAGS))

    def test_atom_missing_and_extra_keys_are_schema_invalid(self) -> None:
        case = self._case()
        case["claim_atoms"][0].pop("value_digest")
        self._reseal(case)
        result_missing = s25y.evaluate_claim_evidence_closure(case)

        case = self._case()
        case["claim_atoms"][0]["extra"] = "not allowed"
        self._reseal(case)
        result_extra = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result_missing["classification"], s25y.COVERAGE_INCOMPLETE)
        self.assertEqual(result_missing["reason"], "ATOM_SCHEMA_INVALID")
        self.assertEqual(result_extra["classification"], s25y.COVERAGE_INCOMPLETE)
        self.assertEqual(result_extra["reason"], "ATOM_SCHEMA_INVALID")

    def test_unsupported_atom_scope_is_explicitly_classified(self) -> None:
        case = self._case()
        case["claim_atoms"][0]["claim_scope"] = "SUCCESSOR_CONTINUITY"
        self._reseal(case)

        result = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result["classification"], s25y.SCOPE_UNSUPPORTED)
        self.assertEqual(result["coverage_scope"], s25y.UNSUPPORTED_SCOPE)
        self.assertEqual(result["claim_scope"], s25y.UNSUPPORTED_SCOPE)

    def test_coverage_digest_reseal_does_not_authorize_incomplete_atoms(self) -> None:
        case = self._case()
        case["claim_atoms"][0]["value_digest"] = "a" * 64
        case["expected"]["coverage_digest"] = s25y.coverage_digest(
            case["expected"]["x_case_digest"], case["expected"]["x_result_digest"], case["claim_atoms"]
        )
        self._reseal(case)

        result = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result["classification"], s25y.COVERAGE_INCOMPLETE)
        self.assertEqual(result["reason"], "ATOM_BINDING_MISMATCH")
        self.assertEqual(result["uncovered_atom_ids"], ["X_CASE_BINDING"])

    def test_expected_case_result_and_claim_bindings_cannot_drift(self) -> None:
        for field in ("x_case_digest", "x_result_digest", "claim_digest"):
            with self.subTest(field=field):
                case = self._case()
                case["expected"][field] = "e" * 64
                self._reseal(case)

                result = s25y.evaluate_claim_evidence_closure(case)

                self.assertEqual(result["classification"], s25y.COVERAGE_INCOMPLETE)
                self.assertEqual(result["reason"], "EXPECTED_BINDING_MISMATCH")

    def test_forged_s25x_output_is_rejected_even_after_outer_resealing(self) -> None:
        case = self._case()
        case["s25x_output"]["reason"] = "FORGED"
        self._reseal(case)

        result = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result["classification"], s25y.X_REJECTED)
        self.assertEqual(result["reason"], "S25X_RESULT_MISMATCH")

    def test_s25x_output_binding_is_strict_about_bool_and_integer_types(self) -> None:
        case = self._case()
        case["s25x_output"]["changed_member_count"] = True
        self._reseal(case)

        result = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result["classification"], s25y.X_REJECTED)
        self.assertEqual(result["reason"], "S25X_RESULT_MISMATCH")

    def test_malformed_or_nonpositive_s25x_output_is_not_promoted(self) -> None:
        case = self._case()
        malformed: dict[str, object] = {"classification": s25x.DELTA_CLAIM_CONTAINED}
        case["s25x_output"] = malformed
        case["expected"]["x_result_digest"] = self._digest(malformed)
        self._reseal(case)
        with patch.object(s25y, "evaluate_delta_claim_containment", return_value=malformed):
            result_malformed = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result_malformed["classification"], s25y.X_REJECTED)
        self.assertEqual(result_malformed["reason"], "S25X_NOT_POSITIVE")

        case = self._case()
        nonpositive = deepcopy(case["s25x_output"])
        nonpositive["classification"] = s25x.CLAIM_NOT_CONTAINED
        nonpositive["status"] = "TEST_BLOCKED"
        nonpositive["decision"] = "HOLD"
        case["s25x_output"] = nonpositive
        case["expected"]["x_result_digest"] = self._digest(nonpositive)
        self._reseal(case)
        with patch.object(s25y, "evaluate_delta_claim_containment", return_value=nonpositive):
            result_nonpositive = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result_nonpositive["classification"], s25y.X_REJECTED)
        self.assertEqual(result_nonpositive["reason"], "S25X_NOT_POSITIVE")

    def test_x_exception_is_fail_closed(self) -> None:
        case = self._case()
        with patch.object(s25y, "evaluate_delta_claim_containment", side_effect=RuntimeError("boom")):
            result = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result["classification"], s25y.X_REJECTED)
        self.assertEqual(result["reason"], "S25X_RESULT_UNREADABLE")

    def test_x_case_digest_drift_is_rejected(self) -> None:
        case = self._case()
        case["s25x_case"]["unexpected"] = "drift"
        self._reseal(case)

        result = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result["classification"], s25y.X_REJECTED)
        self.assertEqual(result["reason"], "S25X_CASE_DIGEST_DRIFT")

    def test_provenance_missing_extra_duplicate_unknown_and_reorder_are_rejected(self) -> None:
        mutations = {
            "missing": lambda provenance: provenance.pop(),
            "extra": lambda provenance: provenance.append(deepcopy(provenance[-1])),
            "duplicate": lambda provenance: provenance.__setitem__(1, deepcopy(provenance[0])),
            "unknown": lambda provenance: provenance.__setitem__(0, {**provenance[0], "member_id": "UNKNOWN"}),
            "reorder": lambda provenance: provenance.reverse(),
            "before_member_digest": lambda provenance: provenance[0].__setitem__("before_member_digest", "f" * 64),
            "after_member_digest": lambda provenance: provenance[0].__setitem__("after_member_digest", "f" * 64),
            "before_value_digest": lambda provenance: provenance[0].__setitem__("before_value_digest", "f" * 64),
            "after_value_digest": lambda provenance: provenance[0].__setitem__("after_value_digest", "f" * 64),
            "before_context_digest": lambda provenance: provenance[0].__setitem__("before_context_digest", "f" * 64),
            "after_context_digest": lambda provenance: provenance[0].__setitem__("after_context_digest", "f" * 64),
            "changed": lambda provenance: provenance[0].__setitem__("changed", True),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = self._case()
                output = deepcopy(case["s25x_output"])
                mutate(output["member_provenance"])
                self._sync_output(case, output)
                with patch.object(s25y, "evaluate_delta_claim_containment", return_value=output):
                    result = s25y.evaluate_claim_evidence_closure(case)

                self.assertEqual(result["classification"], s25y.X_REJECTED)
                self.assertEqual(result["reason"], "S25X_PROVENANCE_INVALID")

    def test_provenance_item_missing_and_extra_keys_are_rejected(self) -> None:
        for mode in ("missing", "extra"):
            with self.subTest(mode=mode):
                case = self._case()
                output = deepcopy(case["s25x_output"])
                if mode == "missing":
                    output["member_provenance"][0].pop("before_value_digest")
                else:
                    output["member_provenance"][0]["extra"] = "not allowed"
                self._sync_output(case, output)
                with patch.object(s25y, "evaluate_delta_claim_containment", return_value=output):
                    result = s25y.evaluate_claim_evidence_closure(case)

                self.assertEqual(result["classification"], s25y.X_REJECTED)
                self.assertEqual(result["reason"], "S25X_PROVENANCE_INVALID")

    def test_authority_status_or_flag_escalation_is_rejected(self) -> None:
        for field, value in (("write_authorized", True), ("production_status", "PRODUCTION_AUTHORIZED"), ("authority_claim", "CLAIMED")):
            with self.subTest(field=field):
                case = self._case()
                output = deepcopy(case["s25x_output"])
                output[field] = value
                self._sync_output(case, output)
                with patch.object(s25y, "evaluate_delta_claim_containment", return_value=output):
                    result = s25y.evaluate_claim_evidence_closure(case)

                self.assertEqual(result["classification"], s25y.X_REJECTED)
                self.assertEqual(result["reason"], "S25X_NOT_POSITIVE")

    def test_missing_and_extra_envelope_keys_are_input_invalid(self) -> None:
        case = self._case()
        case.pop("claim_atoms")
        self.assertEqual(s25y.evaluate_claim_evidence_closure(case)["classification"], s25y.INPUT_INVALID)

        case = self._case()
        case["extra"] = "not allowed"
        self._reseal(case)
        self.assertEqual(s25y.evaluate_claim_evidence_closure(case)["classification"], s25y.INPUT_INVALID)

    def test_duplicate_json_keys_are_input_invalid(self) -> None:
        case = self._case()
        raw = json.dumps(case, sort_keys=True, separators=(",", ":"))
        raw = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '","input_digest":"' + ("1" * 64) + '"}'

        result = s25y.evaluate_claim_evidence_closure(raw)

        self.assertEqual(result["classification"], s25y.INPUT_INVALID)

    def test_parser_rejects_invalid_utf8_constants_and_oversized_bytes(self) -> None:
        self.assertEqual(s25y.evaluate_claim_evidence_closure(b"\xff")["classification"], s25y.INPUT_INVALID)
        self.assertEqual(s25y.evaluate_claim_evidence_closure(b"{\"x\":NaN}")["classification"], s25y.INPUT_INVALID)
        self.assertEqual(s25y.evaluate_claim_evidence_closure(b"{" + b" " * (2 * 1024 * 1024 + 1) + b"}")["classification"], s25y.INPUT_INVALID)

    def test_bool_float_and_unsafe_values_are_input_invalid(self) -> None:
        case = self._case()
        case["expected"]["required_atom_count"] = True
        self._reseal(case)
        result_bool = s25y.evaluate_claim_evidence_closure(case)

        case = self._case()
        case["expected"]["required_atom_count"] = 1.5
        result_float = s25y.evaluate_claim_evidence_closure(case)

        self.assertEqual(result_bool["classification"], s25y.INPUT_INVALID)
        self.assertEqual(result_float["classification"], s25y.INPUT_INVALID)

        for value in ("/tmp/secret", "~/secret", "https://example.invalid", "\\\\server\\share"):
            with self.subTest(value=value):
                case = self._case()
                case["claim_atoms"][0]["evidence_kind"] = value
                self._reseal(case)
                self.assertEqual(s25y.evaluate_claim_evidence_closure(case)["classification"], s25y.INPUT_INVALID)

    def test_recursive_and_over_budget_inputs_are_invalid(self) -> None:
        case = self._case()
        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        case["s25x_case"]["recursive"] = recursive
        self.assertEqual(s25y.evaluate_claim_evidence_closure(case)["classification"], s25y.INPUT_INVALID)

        case = self._case()
        padding: object = "leaf"
        for _ in range(7):
            padding = [padding] * 4
        case["s25x_case"]["padding"] = padding
        self.assertEqual(s25y.evaluate_claim_evidence_closure(case)["classification"], s25y.INPUT_INVALID)

        case = self._case()
        case["s25x_case"]["padding"] = ["x"] * 2049
        self.assertEqual(s25y.evaluate_claim_evidence_closure(case)["classification"], s25y.INPUT_INVALID)

        case = self._case()
        deep: object = "leaf"
        for _ in range(66):
            deep = [deep]
        case["s25x_case"]["padding"] = deep
        self.assertEqual(s25y.evaluate_claim_evidence_closure(case)["classification"], s25y.INPUT_INVALID)

    def test_bytes_input_and_no_file_or_network_discovery_are_supported(self) -> None:
        case = self._case()
        raw = json.dumps(case, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch("socket.socket", side_effect=AssertionError("network is forbidden")):
            result = s25y.evaluate_claim_evidence_closure(raw)

        self.assertEqual(result["classification"], s25y.COVERAGE_COMPLETE)

    def test_only_public_x_boundary_is_imported(self) -> None:
        source = Path(s25y.__file__).read_text(encoding="utf-8")

        self.assertIn("w5_s25x_delta_claim_containment", source)
        self.assertNotIn("w5_s25v", source)
        self.assertNotIn("test_w5_s25", source)


def build_complete_s25y_case() -> dict[str, object]:
    """Public test-only fixture boundary for downstream W5 cards."""

    return W5S25YClaimEvidenceClosureTests._case()


if __name__ == "__main__":
    unittest.main()
