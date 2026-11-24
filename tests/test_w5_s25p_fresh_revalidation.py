"""W5-S25P tests for fresh, bound, test-only revalidation."""

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
    evaluate_status_precedence as precedence_evaluate,
    input_digest as precedence_input_digest,
)
from support.w5_s25p_fresh_revalidation import (  # noqa: E402
    HOLD,
    MANUAL_REVIEW,
    evaluate_fresh_revalidation,
    input_digest,
)


class W5S25PFreshRevalidationTests(unittest.TestCase):
    class _BrokenMapping(dict):
        def __iter__(self):
            raise TypeError("broken iterator")

        def items(self):
            raise KeyError("broken items")

    @staticmethod
    def _hash(char: str) -> str:
        return char * 64

    @classmethod
    def _report(cls, status: str, evidence_state: str, *, sealed: bool = True) -> dict[str, object]:
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
    def _precedence_case(
        cls,
        baseline: dict[str, object],
        candidate: dict[str, object],
        kind: str,
        field: str = "oracle.result",
    ) -> dict[str, object]:
        case: dict[str, object] = {
            "schema_version": "s25o.status-precedence.v1",
            "observation_mode": "OBSERVE_ONLY",
            "baseline": baseline,
            "candidate": candidate,
            "event": {
                "kind": kind,
                "field": field,
                "baseline_evidence_state": baseline["evidence_state"],
                "candidate_evidence_state": candidate["evidence_state"],
            },
            "canonicalization": "s25m-canonical-json-v1",
            "input_digest": "",
        }
        case["input_digest"] = precedence_input_digest(case)
        return case

    @staticmethod
    def _canonical(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def _digest(cls, value: object) -> str:
        return hashlib.sha256(cls._canonical(value)).hexdigest()

    @classmethod
    def _refresh(cls, case: dict[str, object]) -> None:
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
        case["current"]["baseline_digest"] = baseline_digest
        case["previous"]["baseline_digest"] = baseline_digest
        case["previous"]["pass_digest"] = cls._digest(
            {key: value for key, value in previous.items() if key != "pass_digest"}
        )
        case["expected"]["previous_pass_digest"] = previous["pass_digest"]
        anchor = case["freshness_anchor"]
        anchor["snapshot_state"] = current["snapshot_state"]
        anchor["revalidation_performed"] = current["revalidation_performed"]
        anchor["observation_epoch"] = current["observation_epoch"]
        anchor["observation_sequence"] = current["observation_sequence"]
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
        case["input_digest"] = input_digest(case)

    @classmethod
    def _refresh_anchor_only(cls, case: dict[str, object]) -> None:
        expected = case["expected"]
        current = case["current"]
        precedence = case["precedence_case"]
        anchor = case["freshness_anchor"]
        anchor["snapshot_state"] = current["snapshot_state"]
        anchor["revalidation_performed"] = current["revalidation_performed"]
        anchor["observation_epoch"] = current["observation_epoch"]
        anchor["observation_sequence"] = current["observation_sequence"]
        anchor["anchor_digest"] = cls._digest(
            {
                "subject_digest": expected["subject_digest"],
                "scope_digest": expected["scope_digest"],
                "baseline_digest": expected["baseline_digest"],
                "snapshot_state": current["snapshot_state"],
                "revalidation_performed": current["revalidation_performed"],
                "observation_epoch": current["observation_epoch"],
                "observation_sequence": current["observation_sequence"],
                "precedence_digest": precedence["input_digest"],
            }
        )
        case["input_digest"] = input_digest(case)

    @classmethod
    def _case(
        cls,
        baseline_status: str = LOCKED_TEST_PASS,
        candidate_status: str = LOCKED_TEST_PASS,
        *,
        baseline_state: str = "COMPLETE",
        candidate_state: str = "COMPLETE",
        candidate_sealed: bool = True,
        event_kind: str = "NO_CHANGE",
        event_field: str = "oracle.result",
        previous_status: str = LOCKED_TEST_PASS,
    ) -> dict[str, object]:
        baseline = cls._report(baseline_status, baseline_state, sealed=baseline_status == LOCKED_TEST_PASS)
        candidate = cls._report(candidate_status, candidate_state, sealed=candidate_sealed)
        precedence = cls._precedence_case(baseline, candidate, event_kind, event_field)
        subject = cls._hash("a")
        scope = cls._hash("b")
        base_digest = cls._digest(baseline)
        previous: dict[str, object] = {
            "subject_digest": subject,
            "scope_digest": scope,
            "observation_epoch": 4,
            "observation_sequence": 17,
            "status": previous_status,
            "baseline_digest": base_digest,
            "candidate_digest": cls._hash("e"),
            "evidence_digest": cls._hash("f"),
            "pass_digest": "",
        }
        current: dict[str, object] = {
            "subject_digest": subject,
            "scope_digest": scope,
            "observation_epoch": 4,
            "observation_sequence": 18,
            "snapshot_state": "CURRENT",
            "revalidation_performed": True,
            "baseline_digest": base_digest,
            "candidate_digest": "",
            "evidence_digest": "",
        }
        case: dict[str, object] = {
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
                "observation_epoch": 4,
                "observation_sequence": 18,
                "anchor_digest": "",
            },
            "replay_guard": {
                "schema": "s25p.external-replay-floor.v1",
                "floor_sequence": 17,
                "used_pass_digests": [],
            },
            "canonicalization": "s25m-canonical-json-v1",
            "input_digest": "",
        }
        cls._refresh(case)
        return case

    @classmethod
    def _evaluate(cls, case: dict[str, object]) -> dict[str, object]:
        return evaluate_fresh_revalidation(case)

    def test_fresh_locked_no_change_is_delegated_to_s25o(self) -> None:
        result = self._evaluate(self._case())

        self.assertEqual(result["classification"], "FRESH_REVALIDATION_ACCEPTED")
        self.assertEqual(result["status"], LOCKED_TEST_PASS)
        self.assertEqual(result["precedence_classification"], "NO_ESCALATION")

    def test_fresh_downgrade_preserves_s25o_proposal(self) -> None:
        result = self._evaluate(
            self._case(
                candidate_status=PROPOSAL_ONLY,
                candidate_state="PROPOSED",
                candidate_sealed=False,
                event_kind="EVIDENCE_DOWNGRADED",
                event_field="lockfile.hash_mode",
            )
        )

        self.assertEqual(result["status"], PROPOSAL_ONLY)
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["precedence_classification"], "SAFE_NON_ESCALATING_DOWNGRADE")

    def test_fresh_removed_evidence_preserves_s25o_hold(self) -> None:
        result = self._evaluate(
            self._case(
                candidate_status=TEST_BLOCKED,
                candidate_state="MISSING",
                event_kind="EVIDENCE_REMOVED",
                event_field="sbom.includes_native",
            )
        )

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["decision"], HOLD)
        self.assertEqual(result["precedence_classification"], "SAFE_NON_ESCALATING_DOWNGRADE")

    def test_s25o_rejection_never_becomes_a_fresh_pass(self) -> None:
        result = self._evaluate(
            self._case(
                baseline_status=TEST_BLOCKED,
                baseline_state="MISSING",
                candidate_status=PROPOSAL_ONLY,
                candidate_state="PROPOSED",
                candidate_sealed=False,
                event_kind="EVIDENCE_DOWNGRADED",
            )
        )

        self.assertEqual(result["classification"], "PRECEDENCE_REJECTED")
        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], MANUAL_REVIEW)
        self.assertNotEqual(result["status"], LOCKED_TEST_PASS)

    def test_sequence_rollback_and_gap_are_manual_review(self) -> None:
        rollback = self._case()
        rollback["current"]["observation_sequence"] = rollback["previous"]["observation_sequence"]
        self._refresh(rollback)
        gap = self._case()
        gap["current"]["observation_sequence"] += 2
        self._refresh(gap)

        rollback_result = self._evaluate(rollback)
        gap_result = self._evaluate(gap)

        self.assertEqual(rollback_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(rollback_result["decision"], MANUAL_REVIEW)
        self.assertEqual(gap_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(gap_result["decision"], MANUAL_REVIEW)

    def test_stale_snapshot_and_skipped_revalidation_are_blocked(self) -> None:
        stale = self._case()
        stale["current"]["snapshot_state"] = "STALE"
        stale["input_digest"] = input_digest(stale)
        skipped = self._case()
        skipped["current"]["revalidation_performed"] = False
        skipped["input_digest"] = input_digest(skipped)

        self.assertEqual(self._evaluate(stale)["status"], TEST_BLOCKED)
        self.assertEqual(self._evaluate(skipped)["status"], TEST_BLOCKED)

    def test_subject_scope_and_baseline_mismatch_require_manual_review(self) -> None:
        subject = self._case()
        subject["current"]["subject_digest"] = self._hash("c")
        self._refresh(subject)
        scope = self._case()
        scope["current"]["scope_digest"] = self._hash("d")
        self._refresh(scope)
        expected_baseline = self._case()
        expected_baseline["expected"]["baseline_digest"] = self._hash("f")
        self._refresh_anchor_only(expected_baseline)
        current_baseline = self._case()
        current_baseline["current"]["baseline_digest"] = self._hash("f")
        current_baseline["input_digest"] = input_digest(current_baseline)

        self.assertEqual(self._evaluate(subject)["status"], RECOVERY_REQUIRED)
        self.assertEqual(self._evaluate(scope)["status"], RECOVERY_REQUIRED)
        self.assertEqual(self._evaluate(expected_baseline)["status"], RECOVERY_REQUIRED)
        self.assertEqual(self._evaluate(current_baseline)["status"], RECOVERY_REQUIRED)

    def test_reused_candidate_or_evidence_digest_requires_manual_review(self) -> None:
        candidate_replay = self._case()
        candidate_replay["previous"]["candidate_digest"] = candidate_replay["current"]["candidate_digest"]
        self._refresh(candidate_replay)
        evidence_replay = self._case()
        evidence_replay["previous"]["evidence_digest"] = evidence_replay["current"]["evidence_digest"]
        self._refresh(evidence_replay)

        self.assertEqual(self._evaluate(candidate_replay)["status"], RECOVERY_REQUIRED)
        self.assertEqual(self._evaluate(evidence_replay)["status"], RECOVERY_REQUIRED)

    def test_external_replay_floor_rejects_current_pass_digest(self) -> None:
        case = self._case()
        current_pass = self._digest(
            {
                "schema_version": case["schema_version"],
                "observation_mode": case["observation_mode"],
                "expected": case["expected"],
                "current": case["current"],
                "previous": case["previous"],
                "precedence_digest": case["precedence_case"]["input_digest"],
                "freshness_anchor": case["freshness_anchor"],
            }
        )
        case["replay_guard"]["used_pass_digests"] = [case["previous"]["pass_digest"], current_pass]
        case["input_digest"] = input_digest(case)

        result = self._evaluate(case)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["replay_status"], "REPLAY")

    def test_same_precedence_evidence_with_new_sequence_is_replay(self) -> None:
        case = self._case()
        case["previous"]["evidence_digest"] = case["current"]["evidence_digest"]
        self._refresh(case)

        result = self._evaluate(case)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["replay_status"], "REPLAY")

    def test_previous_pass_anchor_and_digest_drift_are_fail_closed(self) -> None:
        anchor = self._case()
        anchor["expected"]["previous_pass_digest"] = self._hash("c")
        anchor["input_digest"] = input_digest(anchor)
        drift = self._case()
        drift["current"]["candidate_digest"] = self._hash("d")
        drift["input_digest"] = input_digest(drift)

        self.assertEqual(self._evaluate(anchor)["status"], RECOVERY_REQUIRED)
        self.assertEqual(self._evaluate(drift)["status"], TEST_BLOCKED)

    def test_epoch_change_is_manual_review_and_bool_sequence_is_blocked(self) -> None:
        epoch = self._case()
        epoch["current"]["observation_epoch"] = 5
        self._refresh(epoch)
        boolean = self._case()
        boolean["current"]["observation_sequence"] = True
        boolean["input_digest"] = input_digest(boolean)

        self.assertEqual(self._evaluate(epoch)["status"], RECOVERY_REQUIRED)
        self.assertEqual(self._evaluate(boolean)["status"], TEST_BLOCKED)

    def test_unknown_precedence_and_duplicate_json_never_promote(self) -> None:
        unknown = self._case()
        unknown["precedence_case"]["candidate"]["status"] = "UNKNOWN_STATUS"
        unknown["precedence_case"]["input_digest"] = precedence_input_digest(unknown["precedence_case"])
        self._refresh(unknown)
        duplicate = evaluate_fresh_revalidation(
            b'{"schema_version":"s25p.fresh-revalidation.v1","schema_version":"other"}'
        )

        self.assertEqual(self._evaluate(unknown)["status"], TEST_BLOCKED)
        self.assertEqual(duplicate["status"], TEST_BLOCKED)

    def test_untrusted_s25o_result_is_not_passed_through(self) -> None:
        case = self._case()
        fake_result = {
            "schema_version": "s25o.status-precedence.v1",
            "observation_mode": "OBSERVE_ONLY",
            "classification": "UNKNOWN_CLASSIFICATION",
            "status": LOCKED_TEST_PASS,
            "decision": "TEST_ONLY_PASS",
            "production_status": PRODUCTION_NOT_AUTHORIZED,
            "authority_claim": "NOT_CLAIMED",
            "assurance_rank": 2,
            "capability_issued": False,
            "write_authorized": False,
            "mutation_allowed": False,
            "persistence_performed": False,
            "cas_attempted": False,
            "fence_issued": False,
            "resume_allowed": False,
        }

        with patch("support.w5_s25p_fresh_revalidation.evaluate_status_precedence", return_value=fake_result):
            result = self._evaluate(case)

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["reason"], "PRECEDENCE_RESULT_INVALID")

    def test_inconsistent_or_unsafe_s25o_result_is_not_passed_through(self) -> None:
        case = self._case()
        inconsistent = precedence_evaluate(case["precedence_case"])
        inconsistent["candidate_status"] = PROPOSAL_ONLY
        inconsistent["reason"] = "ssh://untrusted.example.invalid/result"

        with patch("support.w5_s25p_fresh_revalidation.evaluate_status_precedence", return_value=inconsistent):
            result = self._evaluate(case)

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["reason"], "PRECEDENCE_RESULT_INVALID")
        self.assertNotIn("ssh://untrusted.example.invalid/result", repr(result))

    def test_claim_level_fake_downgrade_cannot_promote_a_blocked_baseline(self) -> None:
        case = self._case(
            baseline_status=TEST_BLOCKED,
            baseline_state="MISSING",
            candidate_status=PROPOSAL_ONLY,
            candidate_state="PROPOSED",
            candidate_sealed=False,
            event_kind="EVIDENCE_DOWNGRADED",
            event_field="lockfile.hash_mode",
        )
        fake = precedence_evaluate(case["precedence_case"])
        fake.update(
            classification="SAFE_NON_ESCALATING_DOWNGRADE",
            status=PROPOSAL_ONLY,
            decision="DESIGN_ONLY",
            degradation="EVIDENCE_DOWNGRADED",
            digest_status="MATCH",
            assurance_rank=1,
        )

        with patch("support.w5_s25p_fresh_revalidation.evaluate_status_precedence", return_value=fake):
            result = self._evaluate(case)

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["reason"], "PRECEDENCE_RESULT_INVALID")

    def test_same_sequence_substitution_cannot_promote_after_prior_block(self) -> None:
        original = self._case(
            candidate_status=TEST_BLOCKED,
            candidate_state="MISSING",
            event_kind="EVIDENCE_REMOVED",
        )
        original["previous"]["status"] = TEST_BLOCKED
        self._refresh(original)
        self.assertEqual(self._evaluate(original)["status"], TEST_BLOCKED)

        replacement = deepcopy(original)
        baseline = deepcopy(replacement["precedence_case"]["baseline"])
        replacement["precedence_case"]["candidate"] = baseline
        replacement["precedence_case"]["event"] = {
            "kind": "NO_CHANGE",
            "field": "oracle.result",
            "baseline_evidence_state": baseline["evidence_state"],
            "candidate_evidence_state": baseline["evidence_state"],
        }
        replacement["precedence_case"]["input_digest"] = precedence_input_digest(replacement["precedence_case"])
        self._refresh(replacement)

        result = self._evaluate(replacement)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], MANUAL_REVIEW)
        self.assertEqual(result["reason"], "STATUS_ESCALATION_AFTER_PRIOR_PASS")

    def test_previous_status_is_required_and_allowlisted(self) -> None:
        missing = self._case()
        del missing["previous"]["status"]
        missing["input_digest"] = input_digest(missing)
        unknown = self._case(previous_status="UNKNOWN_STATUS")

        missing_result = self._evaluate(missing)
        unknown_result = self._evaluate(unknown)

        self.assertEqual(missing_result["status"], TEST_BLOCKED)
        self.assertEqual(unknown_result["status"], TEST_BLOCKED)
        self.assertEqual(unknown_result["reason"], "PREVIOUS_STATUS_INVALID")

    def test_exact_repeat_without_external_floor_update_never_increases_status(self) -> None:
        case = self._case()

        first = self._evaluate(case)
        second = self._evaluate(deepcopy(case))

        self.assertEqual(second["status"], first["status"])
        self.assertEqual(second["decision"], first["decision"])

    def test_unsafe_values_are_blocked_without_echo(self) -> None:
        case = self._case()
        case["expected"]["subject_digest"] = "ssh://user@example.invalid"

        result = self._evaluate(case)

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertNotIn("ssh://user@example.invalid", repr(result))

    def test_recursive_and_broken_mappings_never_raise(self) -> None:
        recursive = self._case()
        cycle: list[object] = []
        cycle.append(cycle)
        recursive["current"]["cycle"] = cycle
        broken = self._BrokenMapping()

        recursive_result = self._evaluate(recursive)
        broken_result = self._evaluate(broken)

        self.assertEqual(recursive_result["status"], TEST_BLOCKED)
        self.assertEqual(broken_result["status"], TEST_BLOCKED)
        with self.assertRaisesRegex(ValueError, "cannot be canonicalized"):
            input_digest(recursive)
        with self.assertRaisesRegex(ValueError, "cannot be canonicalized"):
            input_digest(broken)

    def test_input_is_unchanged_and_all_security_flags_remain_negative(self) -> None:
        case = self._case()
        before = deepcopy(case)

        result = self._evaluate(case)

        self.assertEqual(case, before)
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

    def test_support_surface_is_stdlib_only_and_delegates_public_s25o(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25p_fresh_revalidation.py").read_text()
        for forbidden in (
            "import cryptography",
            "from cryptography",
            "import nacl",
            "from nacl",
            "import OpenSSL",
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
            "recover(",
            "commit(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("evaluate_status_precedence", source)
        self.assertIn("FRESHNESS_BOUND_TO_S25O", source)


if __name__ == "__main__":
    unittest.main()
