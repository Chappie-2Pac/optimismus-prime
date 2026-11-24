"""W5-S25O tests for monotone, fail-closed status transitions."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from support.w5_s25o_status_precedence import (  # noqa: E402
    HOLD,
    LOCKED_TEST_PASS,
    MANUAL_REVIEW,
    PRODUCTION_NOT_AUTHORIZED,
    PROPOSAL_ONLY,
    RECOVERY_REQUIRED,
    TEST_BLOCKED,
    evaluate_status_precedence,
    input_digest,
)


class W5S25OStatusPrecedenceTests(unittest.TestCase):
    class _BrokenMapping(dict):
        def __iter__(self):
            raise TypeError("broken mapping iterator")

        def items(self):
            raise KeyError("broken mapping items")

    class _BrokenGetMapping(dict):
        def get(self, *args, **kwargs):
            raise RuntimeError("broken mapping get")

    class _BrokenGetItemMapping(dict):
        def __getitem__(self, key):
            raise IndexError(f"broken mapping item: {key}")

    @staticmethod
    def _hash(char: str) -> str:
        return char * 64

    @classmethod
    def _report(
        cls,
        status: str,
        evidence_state: str,
        *,
        sealed: bool = True,
    ) -> dict[str, object]:
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
    def _case(
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
        case["input_digest"] = input_digest(case)
        return case

    @classmethod
    def _evaluate(cls, case: dict[str, object]) -> dict[str, object]:
        return evaluate_status_precedence(case)

    def test_no_change_of_locked_pass_is_not_escalation(self) -> None:
        report = self._report(LOCKED_TEST_PASS, "COMPLETE")
        result = self._evaluate(self._case(report, deepcopy(report), "NO_CHANGE"))

        self.assertEqual(result["classification"], "NO_ESCALATION")
        self.assertEqual(result["status"], LOCKED_TEST_PASS)
        self.assertEqual(result["decision"], "TEST_ONLY_PASS")

    def test_removed_evidence_must_fall_to_blocked_or_recovery(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(TEST_BLOCKED, "MISSING")

        result = self._evaluate(self._case(baseline, candidate, "EVIDENCE_REMOVED", "sbom.includes_native"))

        self.assertEqual(result["classification"], "SAFE_NON_ESCALATING_DOWNGRADE")
        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["decision"], HOLD)
        self.assertEqual(result["assurance_rank"], 0)

    def test_complete_downgrade_can_become_unsealed_proposal(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(PROPOSAL_ONLY, "PROPOSED", sealed=False)

        result = self._evaluate(self._case(baseline, candidate, "EVIDENCE_DOWNGRADED", "lockfile.hash_mode"))

        self.assertEqual(result["classification"], "SAFE_NON_ESCALATING_DOWNGRADE")
        self.assertEqual(result["status"], PROPOSAL_ONLY)
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["assurance_rank"], 1)

    def test_unknown_evidence_is_hold_not_proposal_or_pass(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(TEST_BLOCKED, "UNKNOWN")

        result = self._evaluate(self._case(baseline, candidate, "EVIDENCE_UNKNOWN", "provider"))

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["decision"], HOLD)

    def test_stale_and_drifted_evidence_require_manual_review(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        stale = self._report(RECOVERY_REQUIRED, "STALE")
        drift = self._report(RECOVERY_REQUIRED, "DRIFT")

        stale_result = self._evaluate(self._case(baseline, stale, "EVIDENCE_STALE", "projection_digests"))
        drift_result = self._evaluate(self._case(baseline, drift, "EVIDENCE_DRIFT", "provider.native"))

        self.assertEqual(stale_result["classification"], "SAFE_NON_ESCALATING_DOWNGRADE")
        self.assertEqual(stale_result["decision"], MANUAL_REVIEW)
        self.assertEqual(drift_result["classification"], "SAFE_NON_ESCALATING_DOWNGRADE")
        self.assertEqual(drift_result["decision"], MANUAL_REVIEW)

    def test_malformed_evidence_is_blocked(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(TEST_BLOCKED, "MALFORMED")

        result = self._evaluate(self._case(baseline, candidate, "EVIDENCE_MALFORMED", "graph.edge"))

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["decision"], HOLD)

    def test_locked_pass_after_negative_event_is_rejected(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(LOCKED_TEST_PASS, "COMPLETE")

        result = self._evaluate(self._case(baseline, candidate, "EVIDENCE_REMOVED", "oracle.result"))

        self.assertEqual(result["classification"], "INPUT_INVALID")
        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["decision"], HOLD)

    def test_blocked_to_proposal_after_downgrade_is_rejected(self) -> None:
        baseline = self._report(TEST_BLOCKED, "MISSING")
        candidate = self._report(PROPOSAL_ONLY, "PROPOSED", sealed=False)

        result = self._evaluate(self._case(baseline, candidate, "EVIDENCE_DOWNGRADED", "lockfile"))

        self.assertEqual(result["classification"], "STATUS_ESCALATION_REJECTED")
        self.assertEqual(result["reason"], "CLAIM_LEVEL_INCREASED")

    def test_drift_cannot_be_labelled_as_proposal(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(PROPOSAL_ONLY, "PROPOSED", sealed=False)

        result = self._evaluate(self._case(baseline, candidate, "EVIDENCE_DRIFT", "oracle"))

        self.assertEqual(result["classification"], "INPUT_INVALID")
        self.assertEqual(result["status"], TEST_BLOCKED)

    def test_invalid_status_decision_and_negative_flags_are_blocked(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        bad_decision = self._report(LOCKED_TEST_PASS, "COMPLETE")
        bad_decision["decision"] = "HOLD"
        flags = self._report(TEST_BLOCKED, "MISSING")
        flags["capability_issued"] = True
        hostname_status = self._case(
            baseline,
            self._report(TEST_BLOCKED, "MISSING"),
            "EVIDENCE_REMOVED",
        )
        hostname_status["candidate"]["status"] = "198.51.100.7"
        hostname_status["input_digest"] = input_digest(hostname_status)

        bad_result = self._evaluate(self._case(baseline, bad_decision, "EVIDENCE_REMOVED"))
        flag_result = self._evaluate(self._case(baseline, flags, "EVIDENCE_REMOVED"))
        hostname_result = self._evaluate(hostname_status)

        self.assertEqual(bad_result["classification"], "INPUT_INVALID")
        self.assertEqual(flag_result["classification"], "INPUT_INVALID")
        self.assertEqual(flag_result["status"], TEST_BLOCKED)
        self.assertEqual(hostname_result["candidate_status"], "UNKNOWN")
        self.assertNotIn("198.51.100.7", repr(hostname_result))

    def test_event_state_and_kind_must_match_the_reports(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(TEST_BLOCKED, "MISSING")
        mismatch = self._case(baseline, candidate, "EVIDENCE_REMOVED")
        mismatch["event"]["candidate_evidence_state"] = "UNKNOWN"
        mismatch["input_digest"] = input_digest(mismatch)
        unknown_kind = self._case(baseline, candidate, "EVIDENCE_REMOVED")
        unknown_kind["event"]["kind"] = "EVIDENCE_MAGIC"
        unknown_kind["input_digest"] = input_digest(unknown_kind)

        mismatch_result = self._evaluate(mismatch)
        unknown_result = self._evaluate(unknown_kind)

        self.assertEqual(mismatch_result["classification"], "INPUT_INVALID")
        self.assertEqual(unknown_result["classification"], "INPUT_INVALID")

    def test_stale_root_digest_and_duplicate_json_are_blocked(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(TEST_BLOCKED, "MISSING")
        stale = self._case(baseline, candidate, "EVIDENCE_REMOVED")
        stale["event"]["field"] = "sbom"
        stale_result = self._evaluate(stale)
        raw = b'{"schema_version":"s25o.status-precedence.v1","schema_version":"other"}'
        duplicate_result = evaluate_status_precedence(raw)

        self.assertEqual(stale_result["classification"], "INPUT_INVALID")
        self.assertEqual(stale_result["reason"], "CASE_DIGEST_DRIFT")
        self.assertEqual(duplicate_result["classification"], "INPUT_INVALID")

    def test_unsafe_and_unhashable_event_values_never_raise(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(TEST_BLOCKED, "MISSING")
        unsafe = self._case(baseline, candidate, "EVIDENCE_REMOVED")
        unsafe["event"]["field"] = "https://example.invalid/status"
        unhashable = self._case(baseline, candidate, "EVIDENCE_REMOVED")
        unhashable["event"]["field"] = []
        unhashable["input_digest"] = input_digest(unhashable)

        unsafe_result = self._evaluate(unsafe)
        self.assertEqual(unsafe_result["status"], TEST_BLOCKED)
        self.assertEqual(unsafe_result["reason"], "CASE_VALUE_NOT_SAFE")
        self.assertEqual(self._evaluate(unhashable)["status"], TEST_BLOCKED)

        for uri in ("ssh://user@example.invalid/status", "mailto:ops@example.invalid", "data:text/plain,secret"):
            uri_case = self._case(baseline, candidate, "EVIDENCE_REMOVED")
            uri_case["event"]["field"] = uri
            uri_result = self._evaluate(uri_case)
            self.assertEqual(uri_result["reason"], "CASE_VALUE_NOT_SAFE")
            self.assertNotIn(uri, repr(uri_result))

    def test_recursive_and_broken_mappings_are_blocked_not_raised(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(TEST_BLOCKED, "MISSING")
        recursive = self._case(baseline, candidate, "EVIDENCE_REMOVED")
        cycle: list[object] = []
        cycle.append(cycle)
        recursive["event"]["field"] = cycle
        broken = self._BrokenMapping()

        recursive_result = self._evaluate(recursive)
        broken_result = self._evaluate(broken)

        with self.assertRaisesRegex(ValueError, "cannot be canonicalized"):
            input_digest(recursive)
        with self.assertRaisesRegex(ValueError, "cannot be canonicalized"):
            input_digest(broken)

        self.assertEqual(recursive_result["status"], TEST_BLOCKED)
        self.assertEqual(recursive_result["reason"], "CASE_UNREADABLE_OR_TOO_DEEP")
        self.assertEqual(broken_result["status"], TEST_BLOCKED)
        self.assertEqual(broken_result["reason"], "CASE_UNREADABLE_OR_TOO_DEEP")

        get_case = self._case(baseline, candidate, "EVIDENCE_REMOVED")
        get_result = self._evaluate(self._BrokenGetMapping(get_case))
        item_case = self._case(baseline, candidate, "EVIDENCE_REMOVED")
        item_result = self._evaluate(self._BrokenGetItemMapping(item_case))
        self.assertEqual(get_result["reason"], "CASE_UNREADABLE_OR_TOO_DEEP")
        self.assertEqual(item_result["reason"], "CASE_UNREADABLE_OR_TOO_DEEP")

    def test_input_is_unchanged_and_negative_flags_are_fixed(self) -> None:
        baseline = self._report(LOCKED_TEST_PASS, "COMPLETE")
        candidate = self._report(TEST_BLOCKED, "UNKNOWN")
        case = self._case(baseline, candidate, "EVIDENCE_UNKNOWN")
        before = deepcopy(case)

        result = self._evaluate(case)

        self.assertEqual(case, before)
        self.assertEqual(result["production_status"], PRODUCTION_NOT_AUTHORIZED)
        self.assertFalse(result["capability_issued"])
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["persistence_performed"])

    def test_support_surface_is_stdlib_only_and_nonmutating(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25o_status_precedence.py").read_text()
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
            "import time",
            "sqlite3",
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
        self.assertIn("LOCKED_TEST_PASS", source)
        self.assertIn("PRODUCTION_NOT_AUTHORIZED", source)


if __name__ == "__main__":
    unittest.main()
