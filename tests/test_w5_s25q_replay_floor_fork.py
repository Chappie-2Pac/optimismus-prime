"""W5-S25Q tests for pure replay-floor and fork-conflict validation."""

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

from support.w5_s25o_status_precedence import (  # noqa: E402
    LOCKED_TEST_PASS,
    PRODUCTION_NOT_AUTHORIZED,
    PROPOSAL_ONLY,
    RECOVERY_REQUIRED,
    TEST_BLOCKED,
    input_digest as precedence_input_digest,
)
from support.w5_s25p_fresh_revalidation import (  # noqa: E402
    evaluate_fresh_revalidation,
    input_digest as fresh_input_digest,
)
from support.w5_s25q_replay_floor_fork import (  # noqa: E402
    FLOOR_ADVANCE_ELIGIBLE,
    FORK_CONFLICT,
    MANUAL_REVIEW,
    RECOVERY_REQUIRED as Q_RECOVERY_REQUIRED,
    TEST_BLOCKED as Q_TEST_BLOCKED,
    evaluate_replay_floor_fork,
    input_digest,
)


class W5S25QReplayFloorForkTests(unittest.TestCase):
    @staticmethod
    def _hash(char: str) -> str:
        return hashlib.sha256(char.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical(value: object) -> bytes:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def _digest(cls, value: object) -> str:
        return hashlib.sha256(cls._canonical(value)).hexdigest()

    @classmethod
    def _report(cls, status: str, evidence_state: str, *, sealed: bool) -> dict[str, object]:
        decisions = {
            LOCKED_TEST_PASS: "TEST_ONLY_PASS",
            PROPOSAL_ONLY: "DESIGN_ONLY",
            TEST_BLOCKED: "HOLD",
            RECOVERY_REQUIRED: "MANUAL_REVIEW",
        }
        return {
            "status": status,
            "decision": decisions[status],
            "evidence_state": evidence_state,
            "seal_status": "SEALED_TEST_ONLY" if sealed else "UNSEALED",
            "production_status": PRODUCTION_NOT_AUTHORIZED,
            "authority_claim": "NOT_CLAIMED",
            "capability_issued": False,
            "write_authorized": False,
            "mutation_allowed": False,
            "persistence_performed": False,
            "cas_attempted": False,
            "fence_issued": False,
            "resume_allowed": False,
        }

    @classmethod
    def _precedence_case(cls, baseline: dict[str, object], candidate: dict[str, object]) -> dict[str, object]:
        case: dict[str, object] = {
            "schema_version": "s25o.status-precedence.v1",
            "observation_mode": "OBSERVE_ONLY",
            "baseline": baseline,
            "candidate": candidate,
            "event": {
                "kind": "NO_CHANGE",
                "field": "oracle.result",
                "baseline_evidence_state": baseline["evidence_state"],
                "candidate_evidence_state": candidate["evidence_state"],
            },
            "canonicalization": "s25m-canonical-json-v1",
            "input_digest": "",
        }
        case["input_digest"] = precedence_input_digest(case)
        return case

    @classmethod
    def _fresh_case(cls) -> dict[str, object]:
        baseline = cls._report(LOCKED_TEST_PASS, "COMPLETE", sealed=True)
        candidate = cls._report(LOCKED_TEST_PASS, "COMPLETE", sealed=True)
        precedence = cls._precedence_case(baseline, candidate)
        subject = cls._hash("a")
        scope = cls._hash("b")
        base_digest = cls._digest(baseline)
        previous: dict[str, object] = {
            "subject_digest": subject,
            "scope_digest": scope,
            "observation_epoch": 7,
            "observation_sequence": 40,
            "status": LOCKED_TEST_PASS,
            "baseline_digest": base_digest,
            "candidate_digest": cls._hash("e"),
            "evidence_digest": cls._hash("f"),
            "pass_digest": "",
        }
        current: dict[str, object] = {
            "subject_digest": subject,
            "scope_digest": scope,
            "observation_epoch": 7,
            "observation_sequence": 41,
            "snapshot_state": "CURRENT",
            "revalidation_performed": True,
            "baseline_digest": base_digest,
            "candidate_digest": "",
            "evidence_digest": "",
        }
        fresh: dict[str, object] = {
            "schema_version": "s25p.fresh-revalidation.v1",
            "observation_mode": "TEST_ONLY",
            "expected": {
                "subject_digest": subject,
                "scope_digest": scope,
                "baseline_digest": base_digest,
                "previous_pass_digest": "",
            },
            "current": current,
            "previous": previous,
            "precedence_case": precedence,
            "freshness_anchor": {
                "source": "EXTERNAL_TEST_ONLY",
                "snapshot_state": "CURRENT",
                "revalidation_performed": True,
                "observation_epoch": 7,
                "observation_sequence": 41,
                "anchor_digest": "",
            },
            "replay_guard": {
                "schema": "s25p.external-replay-floor.v1",
                "floor_sequence": 40,
                "used_pass_digests": [],
            },
            "canonicalization": "s25m-canonical-json-v1",
            "input_digest": "",
        }
        cls._refresh_fresh(fresh)
        return fresh

    @classmethod
    def _refresh_fresh(cls, case: dict[str, object]) -> None:
        precedence = case["precedence_case"]
        current = case["current"]
        previous = case["previous"]
        baseline_digest = cls._digest(precedence["baseline"])
        current["candidate_digest"] = cls._digest(
            {
                "subject_digest": current["subject_digest"],
                "scope_digest": current["scope_digest"],
                "baseline_digest": baseline_digest,
                "report": precedence["candidate"],
                "observation_epoch": current["observation_epoch"],
                "observation_sequence": current["observation_sequence"],
            }
        )
        current["evidence_digest"] = cls._digest(
            {
                "subject_digest": current["subject_digest"],
                "scope_digest": current["scope_digest"],
                "precedence_digest": precedence["input_digest"],
                "baseline_report": precedence["baseline"],
                "candidate_report": precedence["candidate"],
                "event": precedence["event"],
            }
        )
        case["expected"]["baseline_digest"] = baseline_digest
        current["baseline_digest"] = baseline_digest
        previous["baseline_digest"] = baseline_digest
        previous["pass_digest"] = cls._digest({key: value for key, value in previous.items() if key != "pass_digest"})
        case["expected"]["previous_pass_digest"] = previous["pass_digest"]
        anchor = case["freshness_anchor"]
        anchor["anchor_digest"] = cls._digest(
            {
                "subject_digest": case["expected"]["subject_digest"],
                "scope_digest": case["expected"]["scope_digest"],
                "baseline_digest": case["expected"]["baseline_digest"],
                "snapshot_state": current["snapshot_state"],
                "revalidation_performed": current["revalidation_performed"],
                "observation_epoch": current["observation_epoch"],
                "observation_sequence": current["observation_sequence"],
                "precedence_digest": precedence["input_digest"],
            }
        )
        case["replay_guard"]["floor_sequence"] = previous["observation_sequence"]
        case["replay_guard"]["used_pass_digests"] = [previous["pass_digest"]]
        case["input_digest"] = fresh_input_digest(case)

    @classmethod
    def _observation_digest(cls, node: dict[str, object]) -> str:
        return cls._digest({key: value for key, value in node.items() if key != "observation_digest"})

    @classmethod
    def _pass_digest(cls, current: dict[str, object]) -> str:
        unsigned = {key: value for key, value in current.items() if key not in {"pass_digest", "observation_digest"}}
        return cls._digest({"current": unsigned, "s25p_result_digest": current["s25p_result_digest"]})

    @classmethod
    def _transition_digest(cls, transition: dict[str, object]) -> str:
        after = {key: value for key, value in transition["after"].items() if key != "head_digest"}
        return cls._digest(
            {
                "schema": transition["schema"],
                "source": transition["source"],
                "observation_id": transition["observation_id"],
                "idempotency_key": transition["idempotency_key"],
                "before": transition["before"],
                "after": after,
                "cas_status": transition["cas_status"],
            }
        )

    @classmethod
    def _case(cls, *, previous_status: str = LOCKED_TEST_PASS) -> dict[str, object]:
        fresh = cls._fresh_case()
        s25p_result = evaluate_fresh_revalidation(fresh)
        subject = fresh["current"]["subject_digest"]
        scope = fresh["current"]["scope_digest"]
        baseline = fresh["current"]["baseline_digest"]
        decisions = {
            LOCKED_TEST_PASS: "TEST_ONLY_PASS",
            PROPOSAL_ONLY: "DESIGN_ONLY",
            TEST_BLOCKED: "HOLD",
            RECOVERY_REQUIRED: "MANUAL_REVIEW",
        }
        previous: dict[str, object] = {
            "subject_digest": subject,
            "scope_digest": scope,
            "baseline_digest": baseline,
            "epoch": 7,
            "observation_sequence": 40,
            "pass_digest": cls._hash("p"),
            "status": previous_status,
            "decision": decisions[previous_status],
            "candidate_digest": cls._hash("q"),
            "evidence_digest": cls._hash("r"),
            "observation_digest": "",
        }
        previous["observation_digest"] = cls._observation_digest(previous)
        current: dict[str, object] = {
            "subject_digest": subject,
            "scope_digest": scope,
            "baseline_digest": baseline,
            "epoch": 7,
            "observation_sequence": 41,
            "previous_pass_digest": previous["pass_digest"],
            "candidate_digest": fresh["current"]["candidate_digest"],
            "evidence_digest": fresh["current"]["evidence_digest"],
            "pass_digest": "",
            "status": s25p_result["status"],
            "decision": s25p_result["decision"],
            "observation_digest": "",
            "s25p_case": fresh,
            "s25p_result_digest": cls._digest(s25p_result),
        }
        current["pass_digest"] = cls._pass_digest(current)
        current["observation_digest"] = cls._observation_digest(current)
        parent_key = cls._digest(
            {
                "subject_digest": subject,
                "scope_digest": scope,
                "baseline_digest": baseline,
                "epoch": 7,
                "observation_sequence": 40,
                "pass_digest": previous["pass_digest"],
            }
        )
        candidate_key = cls._digest({"parent_key": parent_key, "observation_sequence": 41, "pass_digest": current["pass_digest"]})
        before = {
            "subject_digest": subject,
            "scope_digest": scope,
            "baseline_digest": baseline,
            "epoch": 7,
            "floor_sequence": 40,
            "floor_pass_digest": previous["pass_digest"],
            "state_version": 41,
            "head_digest": cls._hash("h"),
            "successor_index_digest": cls._hash("i"),
            "used_pass_digests": [previous["pass_digest"]],
            "used_observation_digests": [previous["observation_digest"]],
        }
        index = {
            "parent_key": parent_key,
            "candidate_key": candidate_key,
            "entry_status": "ABSENT",
            "existing_successor_pass_digest": None,
            "candidate_count": 1,
            "candidate_pass_digests": [current["pass_digest"]],
            "candidate_keys": [candidate_key],
            "lineage": "SINGLE",
            "registry_state_version": before["state_version"],
            "registry_head_digest": before["head_digest"],
        }
        after = deepcopy(before)
        after["floor_sequence"] = 41
        after["floor_pass_digest"] = current["pass_digest"]
        after["state_version"] = 42
        after["successor_index_digest"] = cls._digest(index)
        after["used_pass_digests"] = before["used_pass_digests"] + [current["pass_digest"]]
        after["used_observation_digests"] = before["used_observation_digests"] + [current["observation_digest"]]
        after["head_digest"] = ""
        transition: dict[str, object] = {
            "schema": "s25q.external-floor-transition.v1",
            "source": "EXTERNAL_TEST_ONLY",
            "observation_id": "obs-41",
            "idempotency_key": "idem-41",
            "before": before,
            "after": after,
            "cas_status": "WOULD_ADVANCE",
            "transition_digest": "",
        }
        transition["transition_digest"] = cls._transition_digest(transition)
        after["head_digest"] = cls._digest({"before_head_digest": before["head_digest"], "transition_digest": transition["transition_digest"]})
        expected = {
            "subject_digest": subject,
            "scope_digest": scope,
            "baseline_digest": baseline,
            "epoch": 7,
            "predecessor_sequence": 40,
            "predecessor_pass_digest": previous["pass_digest"],
            "successor_sequence": 41,
            "successor_pass_digest": current["pass_digest"],
            "current_case_digest": fresh["input_digest"],
            "floor_before_state_version": before["state_version"],
            "floor_before_head_digest": before["head_digest"],
        }
        case = {
            "schema_version": "s25q.external-replay-floor.v1",
            "observation_mode": "TEST_ONLY",
            "canonicalization": "s25m-canonical-json-v1",
            "expected": expected,
            "previous": previous,
            "current": current,
            "floor_transition": transition,
            "successor_index": index,
            "input_digest": "",
        }
        case["input_digest"] = input_digest(case)
        return case

    @classmethod
    def _reseal(cls, case: dict[str, object]) -> None:
        transition = case["floor_transition"]
        transition["transition_digest"] = cls._transition_digest(transition)
        case["input_digest"] = input_digest(case)

    def test_valid_single_successor_is_only_a_proposal(self) -> None:
        result = evaluate_replay_floor_fork(self._case())

        self.assertEqual(result["classification"], FLOOR_ADVANCE_ELIGIBLE)
        self.assertEqual(result["status"], LOCKED_TEST_PASS)
        self.assertFalse(result["floor_advanced"])

    def test_parent_digest_mismatch_requires_review(self) -> None:
        case = self._case()
        case["current"]["previous_pass_digest"] = self._hash("x")
        case["input_digest"] = input_digest(case)

        result = evaluate_replay_floor_fork(case)

        self.assertEqual(result["status"], Q_RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], MANUAL_REVIEW)

    def test_replay_in_floor_never_advanced(self) -> None:
        case = self._case()
        case["current"]["pass_digest"] = case["previous"]["pass_digest"]
        case["input_digest"] = input_digest(case)

        result = evaluate_replay_floor_fork(case)

        self.assertNotEqual(result["status"], LOCKED_TEST_PASS)

    def test_floor_rollback_gap_and_jump_never_advance(self) -> None:
        for mutation in (39, 42, 45):
            case = self._case()
            case["floor_transition"]["after"]["floor_sequence"] = mutation
            self._reseal(case)

            result = evaluate_replay_floor_fork(case)

            self.assertNotEqual(result["status"], LOCKED_TEST_PASS)

    def test_boolean_float_and_duplicate_floor_history_never_advance(self) -> None:
        boolean_counter = self._case()
        boolean_counter["floor_transition"]["after"]["state_version"] = True
        boolean_counter["input_digest"] = input_digest(boolean_counter)

        float_counter = self._case()
        float_counter["floor_transition"]["after"]["state_version"] = 42.0

        duplicate_history = self._case()
        duplicate_history["floor_transition"]["before"]["used_pass_digests"].append(
            duplicate_history["previous"]["pass_digest"]
        )
        duplicate_history["input_digest"] = input_digest(duplicate_history)

        for case in (boolean_counter, float_counter, duplicate_history):
            result = evaluate_replay_floor_fork(case)
            self.assertNotEqual(result["status"], LOCKED_TEST_PASS)
            self.assertFalse(result["floor_advanced"])

    def test_same_sequence_fork_is_not_selected(self) -> None:
        case = self._case()
        index = case["successor_index"]
        alternate = self._hash("z")
        alternate_key = self._hash("y")
        index.update(
            {
                "entry_status": "CONFLICT",
                "candidate_count": 2,
                "candidate_pass_digests": [case["current"]["pass_digest"], alternate],
                "candidate_keys": [index["candidate_key"], alternate_key],
                "lineage": "FORK",
                "existing_successor_pass_digest": alternate,
            }
        )
        case["floor_transition"]["cas_status"] = "CONFLICT"
        case["floor_transition"]["after"] = deepcopy(case["floor_transition"]["before"])
        self._reseal(case)

        result = evaluate_replay_floor_fork(case)

        self.assertEqual(result["classification"], FORK_CONFLICT)
        self.assertEqual(result["status"], Q_RECOVERY_REQUIRED)

    def test_merge_claim_is_not_constructed(self) -> None:
        case = self._case()
        index = case["successor_index"]
        index.update(
            {
                "entry_status": "MERGE_UNRESOLVED",
                "candidate_count": 2,
                "candidate_pass_digests": [case["current"]["pass_digest"], self._hash("z")],
                "candidate_keys": [index["candidate_key"], self._hash("y")],
                "lineage": "MERGE",
                "existing_successor_pass_digest": self._hash("z"),
            }
        )
        case["floor_transition"]["cas_status"] = "CONFLICT"
        case["floor_transition"]["after"] = deepcopy(case["floor_transition"]["before"])
        self._reseal(case)

        result = evaluate_replay_floor_fork(case)

        self.assertEqual(result["classification"], FORK_CONFLICT)
        self.assertEqual(result["status"], Q_RECOVERY_REQUIRED)

    def test_exact_successor_replay_is_blocked_and_does_not_advance(self) -> None:
        case = self._case()
        index = case["successor_index"]
        index["entry_status"] = "EXACT_MATCH"
        index["existing_successor_pass_digest"] = case["current"]["pass_digest"]
        case["floor_transition"]["cas_status"] = "IDEMPOTENT_MATCH"
        case["floor_transition"]["after"] = deepcopy(case["floor_transition"]["before"])
        self._reseal(case)

        result = evaluate_replay_floor_fork(case)

        self.assertEqual(result["reason"], "FLOOR_IDEMPOTENT_REPLAY")
        self.assertEqual(result["status"], Q_TEST_BLOCKED)
        self.assertEqual(result["replay_status"], "REPLAY")

    def test_status_cannot_rise_above_previous_pass(self) -> None:
        case = self._case(previous_status=TEST_BLOCKED)
        case["previous"]["observation_digest"] = self._observation_digest(case["previous"])
        case["floor_transition"]["before"]["used_observation_digests"] = [case["previous"]["observation_digest"]]
        self._reseal(case)

        result = evaluate_replay_floor_fork(case)

        self.assertEqual(result["status"], Q_RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "STATUS_ESCALATION_AFTER_PREVIOUS_PASS")

    def test_s25p_stale_result_never_becomes_a_floor_pass(self) -> None:
        case = self._case()
        case["current"]["s25p_case"]["current"]["snapshot_state"] = "STALE"
        case["current"]["s25p_case"]["input_digest"] = fresh_input_digest(case["current"]["s25p_case"])
        case["input_digest"] = input_digest(case)

        result = evaluate_replay_floor_fork(case)

        self.assertNotEqual(result["status"], LOCKED_TEST_PASS)

    def test_subject_scope_baseline_epoch_and_sequence_drift_never_advance(self) -> None:
        mutations = (
            ("subject_digest", self._hash("s")),
            ("scope_digest", self._hash("t")),
            ("baseline_digest", self._hash("u")),
            ("epoch", 8),
            ("observation_sequence", 42),
        )
        for field, value in mutations:
            case = self._case()
            case["current"][field] = value
            case["input_digest"] = input_digest(case)

            result = evaluate_replay_floor_fork(case)

            self.assertNotEqual(result["status"], LOCKED_TEST_PASS, field)

    def test_duplicate_json_and_unsafe_values_are_blocked_without_echo(self) -> None:
        duplicate = evaluate_replay_floor_fork(
            b'{"schema_version":"s25q.external-replay-floor.v1","schema_version":"other"}'
        )
        unsafe = self._case()
        unsafe["floor_transition"]["observation_id"] = "file:///etc/passwd"
        unsafe_result = evaluate_replay_floor_fork(unsafe)

        self.assertEqual(duplicate["status"], Q_TEST_BLOCKED)
        self.assertEqual(unsafe_result["status"], Q_TEST_BLOCKED)
        self.assertNotIn("file:///etc/passwd", repr(unsafe_result))

    def test_recursive_and_broken_mappings_never_raise(self) -> None:
        recursive = self._case()
        cycle: list[object] = []
        cycle.append(cycle)
        recursive["current"]["cycle"] = cycle
        broken = {"broken": "mapping"}

        self.assertEqual(evaluate_replay_floor_fork(recursive)["status"], Q_TEST_BLOCKED)
        self.assertEqual(evaluate_replay_floor_fork(broken)["status"], Q_TEST_BLOCKED)
        with self.assertRaisesRegex(ValueError, "cannot be canonicalized"):
            input_digest(recursive)

    def test_input_is_unchanged_and_all_authority_flags_are_negative(self) -> None:
        case = self._case()
        before = deepcopy(case)

        result = evaluate_replay_floor_fork(case)

        self.assertEqual(case, before)
        self.assertFalse(result["floor_advanced"])
        self.assertEqual(result["production_status"], PRODUCTION_NOT_AUTHORIZED)
        self.assertEqual(result["authority_claim"], "NOT_CLAIMED")
        for field in (
            "capability_issued",
            "write_authorized",
            "mutation_allowed",
            "persistence_performed",
            "cas_attempted",
            "fence_issued",
            "resume_allowed",
        ):
            self.assertFalse(result[field])

    def test_forged_nested_s25p_result_is_not_accepted(self) -> None:
        case = self._case()
        forged = evaluate_fresh_revalidation(case["current"]["s25p_case"])
        forged["forged_field"] = "must-not-cross-the-boundary"

        with patch(
            "support.w5_s25q_replay_floor_fork.evaluate_fresh_revalidation",
            return_value=forged,
        ):
            result = evaluate_replay_floor_fork(case)

        self.assertEqual(result["status"], Q_TEST_BLOCKED)
        self.assertEqual(result["reason"], "S25P_RESULT_INVALID")

    def test_semantically_forged_s25p_classification_cannot_promote(self) -> None:
        case = self._case()
        forged = evaluate_fresh_revalidation(case["current"]["s25p_case"])
        forged.update(
            {
                "classification": "PRECEDENCE_REJECTED",
                "status": LOCKED_TEST_PASS,
                "decision": "TEST_ONLY_PASS",
                "precedence_classification": "STATUS_ESCALATION_REJECTED",
                "precedence_reason": "LOCKED_PASS_AFTER_NEGATIVE_EVIDENCE",
                "precedence_digest_status": "MATCH",
                "assurance_rank": 2,
            }
        )

        with patch(
            "support.w5_s25q_replay_floor_fork.evaluate_fresh_revalidation",
            return_value=forged,
        ):
            result = evaluate_replay_floor_fork(case)

        self.assertEqual(result["status"], Q_TEST_BLOCKED)
        self.assertEqual(result["reason"], "S25P_RESULT_INVALID")

    def test_semantically_forged_s25p_acceptance_flags_cannot_promote(self) -> None:
        case = self._case()
        forged = evaluate_fresh_revalidation(case["current"]["s25p_case"])
        forged["sequence_status"] = "ROLLBACK"
        forged["reason"] = "STATUS_UNCHANGED"

        with patch(
            "support.w5_s25q_replay_floor_fork.evaluate_fresh_revalidation",
            return_value=forged,
        ):
            result = evaluate_replay_floor_fork(case)

        self.assertEqual(result["status"], Q_TEST_BLOCKED)
        self.assertEqual(result["reason"], "S25P_RESULT_INVALID")

    def test_invalid_nested_s25o_event_field_cannot_promote_forged_s25p(self) -> None:
        case = self._case()
        forged = evaluate_fresh_revalidation(case["current"]["s25p_case"])
        case["current"]["s25p_case"]["precedence_case"]["event"]["field"] = "not-an-allowed-field"

        case["current"]["pass_digest"] = self._pass_digest(case["current"])
        case["current"]["observation_digest"] = self._observation_digest(case["current"])
        case["expected"]["successor_pass_digest"] = case["current"]["pass_digest"]
        case["successor_index"]["candidate_key"] = self._digest(
            {"parent_key": case["successor_index"]["parent_key"], "observation_sequence": 41, "pass_digest": case["current"]["pass_digest"]}
        )
        case["successor_index"]["candidate_keys"] = [case["successor_index"]["candidate_key"]]
        case["successor_index"]["candidate_pass_digests"] = [case["current"]["pass_digest"]]
        case["floor_transition"]["after"]["floor_pass_digest"] = case["current"]["pass_digest"]
        case["floor_transition"]["after"]["used_pass_digests"][-1] = case["current"]["pass_digest"]
        case["floor_transition"]["after"]["used_observation_digests"][-1] = case["current"]["observation_digest"]
        case["floor_transition"]["after"]["successor_index_digest"] = self._digest(case["successor_index"])
        case["floor_transition"]["transition_digest"] = self._transition_digest(case["floor_transition"])
        case["floor_transition"]["after"]["head_digest"] = self._digest(
            {
                "before_head_digest": case["floor_transition"]["before"]["head_digest"],
                "transition_digest": case["floor_transition"]["transition_digest"],
            }
        )
        case["input_digest"] = input_digest(case)

        with patch(
            "support.w5_s25q_replay_floor_fork.evaluate_fresh_revalidation",
            return_value=forged,
        ):
            result = evaluate_replay_floor_fork(case)

        self.assertEqual(result["status"], Q_TEST_BLOCKED)
        self.assertEqual(result["reason"], "S25P_RESULT_INVALID")

    def test_stateful_mapping_is_snapshotted_before_digest_and_validation(self) -> None:
        signed = self._case()
        signed["current"]["previous_pass_digest"] = self._hash("x")
        signed["input_digest"] = input_digest(signed)
        valid = self._case()

        class StatefulMapping(dict[str, object]):
            def __init__(self, signed: dict[str, object], later: dict[str, object]) -> None:
                super().__init__(signed)
                self._signed = signed
                self._later = later
                self._calls = 0

            def items(self):  # type: ignore[no-untyped-def]
                self._calls += 1
                return (self._signed if self._calls == 1 else self._later).items()

        hostile = StatefulMapping(signed, valid)

        result = evaluate_replay_floor_fork(hostile)

        self.assertNotEqual(result["status"], LOCKED_TEST_PASS)
        self.assertFalse(result["floor_advanced"])

    def test_support_is_stdlib_only_and_public_s25p_only(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25q_replay_floor_fork.py").read_text()
        for forbidden in (
            "import os",
            "import pathlib",
            "import socket",
            "import subprocess",
            "import sqlite3",
            "open(",
            "write_text",
            "write_bytes",
            "unlink(",
            "rename(",
            "install(",
            "commit(",
            "_revalidation_pass_digest",
            "_previous_pass_digest",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("evaluate_fresh_revalidation", source)
        self.assertIn("FLOOR_ADVANCE_PROPOSAL_ONLY", source)


if __name__ == "__main__":
    unittest.main()
