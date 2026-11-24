"""Adversarial tests for the pure S25U provenance-projection gate."""

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

import support.w5_s25t_receipt_provenance as s25t  # noqa: E402
import support.w5_s25u_provenance_monotonicity as s25u  # noqa: E402
import test_w5_s25t_receipt_provenance as s25t_tests  # noqa: E402


class W5S25UProvenanceMonotonicityTests(unittest.TestCase):
    FALSE_FLAGS = (
        "capability_issued",
        "write_authorized",
        "mutation_allowed",
        "persistence_performed",
        "cas_attempted",
        "fence_issued",
        "resume_allowed",
        "receipt_emitted",
        "receipt_committed",
        "commit_authorized",
        "floor_advanced",
    )

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
            **{field: result[field] for field in cls.FALSE_FLAGS},
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
            "projection_digest": "",
        }
        projection["projection_digest"] = cls._digest({key: value for key, value in projection.items() if key != "projection_digest"})
        return projection

    @classmethod
    def _case(cls, before: dict[str, object], after: dict[str, object], transition_kind: str) -> dict[str, object]:
        before_result = s25t.evaluate_receipt_provenance(before)
        after_result = s25t.evaluate_receipt_provenance(after)
        before_projection = cls._projection(before, before_result)
        after_projection = cls._projection(after, after_result)
        before_expected = before["expected"]
        expected: dict[str, object] = {
            "before_case_digest": before_projection["s25t_case_digest"],
            "after_case_digest": after_projection["s25t_case_digest"],
            "before_result_digest": before_projection["s25t_result_digest"],
            "after_result_digest": after_projection["s25t_result_digest"],
            "before_projection_digest": before_projection["projection_digest"],
            "after_projection_digest": after_projection["projection_digest"],
            "subject_digest": before_projection["subject_digest"],
            "scope_digest": before_projection["scope_digest"],
            "baseline_digest": before_projection["baseline_digest"],
            "observer_id": before_projection["observer_id"],
            "comparison_group": before_projection["comparison_group"],
            "epoch": before_projection["epoch"],
            "before_sequence": before_projection["current_sequence"],
            "after_sequence": after_projection["current_sequence"],
            "before_observation_id": before_projection["observation_id"],
            "after_observation_id": after_projection["observation_id"],
            "before_idempotency_key": before_projection["idempotency_key"],
            "after_idempotency_key": after_projection["idempotency_key"],
            "transition_kind": transition_kind,
            "required_source_count": 6,
            "required_observation_count": 6,
        }
        case: dict[str, object] = {
            "schema_version": s25u.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25u.CANONICALIZATION,
            "expected": expected,
            "before_case": before,
            "after_case": after,
            "before_projection": before_projection,
            "after_projection": after_projection,
            "input_digest": "",
        }
        case["input_digest"] = s25u.input_digest(case)
        return case

    @classmethod
    def _base_s25t(cls) -> dict[str, object]:
        return s25t_tests.build_complete_s25t_case()

    @classmethod
    def _partial_s25t(cls) -> dict[str, object]:
        case = cls._base_s25t()
        observation = case["observations"][0]
        observation.update(
            {
                "observation_state": "ABSENT",
                "comparison_status": "NOT_COMPARABLE",
                "freshness_status": "UNKNOWN",
                "coverage_status": "PARTIAL",
                "receipt_digest": None,
            }
        )
        s25t_tests.reseal_s25t_observation(case, 0)
        return case

    @classmethod
    def _stale_s25t(cls) -> dict[str, object]:
        case = cls._base_s25t()
        observation = case["observations"][0]
        observation.update(
            {
                "observation_state": "STALE",
                "comparison_status": "NOT_COMPARABLE",
                "freshness_status": "STALE",
                "coverage_status": "PARTIAL",
                "receipt_digest": None,
            }
        )
        s25t_tests.reseal_s25t_observation(case, 0)
        return case

    @staticmethod
    def _reseal(case: dict[str, object]) -> None:
        case["input_digest"] = s25u.input_digest(case)

    def test_identical_positive_projections_are_monotonic_witness_only(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROVENANCE_PROJECTION_MONOTONIC)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["reason"], "MONOTONIC_NO_CHANGE")
        self.assertFalse(result["floor_advanced"])
        self.assertFalse(result["mutation_allowed"])

    def test_input_is_unchanged_and_repeated_calls_have_no_hidden_seen_state(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        before = deepcopy(case)

        first = s25u.evaluate_provenance_monotonicity(case)
        second = s25u.evaluate_provenance_monotonicity(deepcopy(case))
        third = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(case, before)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_safe_evidence_degradation_is_explicit_and_non_escalating(self) -> None:
        before = self._base_s25t()
        after = self._partial_s25t()
        case = self._case(before, after, "EVIDENCE_DEGRADED")

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROVENANCE_PROJECTION_MONOTONIC)
        self.assertEqual(result["reason"], "SAFE_NON_ESCALATING_DOWNGRADE")
        self.assertEqual(result["after_status"], "TEST_BLOCKED")

    def test_blocked_to_positive_status_escalation_is_rejected(self) -> None:
        before = self._partial_s25t()
        after = self._base_s25t()
        case = self._case(before, after, "EVIDENCE_DEGRADED")

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "STATUS_ESCALATION_OR_INVALID_DEGRADATION")

    def test_blocked_to_recovery_sideways_transition_is_reviewed(self) -> None:
        before = self._partial_s25t()
        after = self._stale_s25t()
        case = self._case(before, after, "EVIDENCE_DEGRADED")

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROJECTION_CONFLICT)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")

    def test_forged_after_status_is_rejected_even_when_projection_is_resealed(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        case["after_projection"]["status"] = "TEST_BLOCKED"
        case["after_projection"]["decision"] = "HOLD"
        case["after_projection"]["projection_digest"] = self._digest(
            {key: value for key, value in case["after_projection"].items() if key != "projection_digest"}
        )
        case["expected"]["after_projection_digest"] = case["after_projection"]["projection_digest"]
        self._reseal(case)

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "S25T_PROJECTION_MISMATCH")

    def test_projection_digest_resealing_cannot_hide_context_drift(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        case["after_projection"]["scope_digest"] = "f" * 64
        case["after_projection"]["projection_digest"] = self._digest(
            {key: value for key, value in case["after_projection"].items() if key != "projection_digest"}
        )
        case["expected"]["after_projection_digest"] = case["after_projection"]["projection_digest"]
        self._reseal(case)

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "S25T_PROJECTION_MISMATCH")

    def test_expected_identity_drift_is_not_authorized_by_resealing(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        case["expected"]["scope_digest"] = "e" * 64
        self._reseal(case)

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROJECTION_CONFLICT)
        self.assertEqual(result["reason"], "IDENTITY_OR_CONTEXT_DRIFT")

    def test_unsealed_outer_digest_is_invalid(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        case["expected"]["after_sequence"] += 1

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], "INPUT_INVALID")
        self.assertEqual(result["reason"], "CASE_DIGEST_DRIFT")

    def test_next_sequence_requires_contiguous_public_s25t_state(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NEXT_SEQUENCE")

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROJECTION_OUT_OF_WINDOW)
        self.assertEqual(result["reason"], "SEQUENCE_GAP_OR_ROLLBACK")

    def test_unknown_transition_kind_is_blocked(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        case["expected"]["transition_kind"] = "SIDEWAYS"
        self._reseal(case)

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROJECTION_REJECTED)
        self.assertEqual(result["reason"], "TRANSITION_KIND_INVALID")

    def test_nonpositive_s25t_case_is_still_a_safe_projection(self) -> None:
        before = self._partial_s25t()
        case = self._case(before, deepcopy(before), "NO_CHANGE")

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROVENANCE_PROJECTION_MONOTONIC)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["before_status"], "TEST_BLOCKED")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        raw = json.dumps(case, sort_keys=True, separators=(",", ":"))
        raw = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '","input_digest":"' + ("1" * 64) + '"}'

        result = s25u.evaluate_provenance_monotonicity(raw)

        self.assertEqual(result["classification"], "INPUT_INVALID")

    def test_bool_and_float_counters_are_rejected(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        case["expected"]["epoch"] = True
        self._reseal(case)
        result_bool = s25u.evaluate_provenance_monotonicity(case)

        case = self._case(base, deepcopy(base), "NO_CHANGE")
        case["expected"]["epoch"] = 1.5
        case["input_digest"] = "0" * 64
        result_float = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result_bool["reason"], "EXPECTED_COUNTER_INVALID")
        self.assertEqual(result_float["reason"], "CASE_UNREADABLE_OR_TOO_DEEP")

    def test_unsafe_uri_and_path_are_not_admissible(self) -> None:
        for unsafe in ("/tmp/projection", "https://example.invalid/projection", "file:///tmp/projection", r"\\server\share\projection"):
            with self.subTest(unsafe=unsafe):
                base = self._base_s25t()
                case = self._case(base, deepcopy(base), "NO_CHANGE")
                case["expected"]["observer_id"] = unsafe
                self._reseal(case)
                result = s25u.evaluate_provenance_monotonicity(case)
                self.assertEqual(result["classification"], "INPUT_INVALID")

    def test_invalid_nested_s25t_case_is_rejected_not_downgraded(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        case["before_case"]["input_digest"] = "0" * 64
        self._reseal(case)

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.S25T_REJECTED)
        self.assertEqual(result["status"], "TEST_BLOCKED")

    def test_recursive_case_is_rejected_without_recursion_error(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        case["after_case"] = recursive

        result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], "INPUT_INVALID")

    def test_no_file_or_network_discovery_is_needed(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch("socket.socket", side_effect=AssertionError("network is forbidden")):
            result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.PROVENANCE_PROJECTION_MONOTONIC)

    def test_s25t_exception_is_rejected_fail_closed(self) -> None:
        base = self._base_s25t()
        case = self._case(base, deepcopy(base), "NO_CHANGE")
        with patch.object(s25u, "evaluate_receipt_provenance", side_effect=RuntimeError("synthetic failure")):
            result = s25u.evaluate_provenance_monotonicity(case)

        self.assertEqual(result["classification"], s25u.S25T_REJECTED)
        self.assertEqual(result["status"], "TEST_BLOCKED")


if __name__ == "__main__":
    unittest.main()


def build_complete_s25u_case() -> dict[str, object]:
    """Public test-only fixture boundary for downstream W5 cards."""

    base = W5S25UProvenanceMonotonicityTests._base_s25t()
    return W5S25UProvenanceMonotonicityTests._case(base, deepcopy(base), "NO_CHANGE")


def build_s25u_case_from_s25t_cases(
    before: dict[str, object], after: dict[str, object], transition_kind: str
) -> dict[str, object]:
    """Build a downstream fixture without exposing private helpers to support code."""

    return W5S25UProvenanceMonotonicityTests._case(before, after, transition_kind)
