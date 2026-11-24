"""Adversarial tests for the pure S25R receipt/reconciliation witness."""

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

from support.w5_s25q_replay_floor_fork import (  # noqa: E402
    evaluate_replay_floor_fork,
)
from support.w5_s25r_receipt_reconciliation import (  # noqa: E402
    RECEIPT_BUNDLE_RECONCILED,
    evaluate_receipt_reconciliation,
    input_digest,
)
from test_w5_s25q_replay_floor_fork import W5S25QReplayFloorForkTests  # noqa: E402


class W5S25RReceiptReconciliationTests(unittest.TestCase):
    REQUIRED_KINDS = ["S25Q_RESULT", "PARENT_CANDIDATE", "TRANSITION", "HEAD", "HISTORY", "INDEX"]

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _history_digest(cls, node: dict[str, object]) -> str:
        return cls._digest({"used_pass_digests": node["used_pass_digests"], "used_observation_digests": node["used_observation_digests"]})

    @classmethod
    def _receipt_digest(cls, receipt: dict[str, object]) -> str:
        return cls._digest({key: value for key, value in receipt.items() if key != "receipt_digest"})

    @classmethod
    def _set_digest(cls, receipt_set: dict[str, object]) -> str:
        return cls._digest(
            {
                "schema": receipt_set["schema"],
                "required_kinds": receipt_set["required_kinds"],
                "receipt_digests": sorted(receipt_set["receipt_digests"]),
            }
        )

    @classmethod
    def _base(cls) -> dict[str, object]:
        q_case = W5S25QReplayFloorForkTests._case()
        q_result = evaluate_replay_floor_fork(q_case)
        previous = q_case["previous"]
        current = q_case["current"]
        transition = q_case["floor_transition"]
        before = transition["before"]
        after = transition["after"]
        index = q_case["successor_index"]
        expected: dict[str, object] = {
            "subject_digest": previous["subject_digest"],
            "scope_digest": previous["scope_digest"],
            "baseline_digest": previous["baseline_digest"],
            "epoch": previous["epoch"],
            "previous_sequence": previous["observation_sequence"],
            "previous_pass_digest": previous["pass_digest"],
            "previous_observation_digest": previous["observation_digest"],
            "current_sequence": current["observation_sequence"],
            "current_pass_digest": current["pass_digest"],
            "current_observation_digest": current["observation_digest"],
            "parent_key": index["parent_key"],
            "candidate_key": index["candidate_key"],
            "transition_digest": transition["transition_digest"],
            "before_state_version": before["state_version"],
            "after_state_version": after["state_version"],
            "before_head_digest": before["head_digest"],
            "after_head_digest": after["head_digest"],
            "before_history_digest": cls._history_digest(before),
            "after_history_digest": cls._history_digest(after),
            "before_successor_index_digest": before["successor_index_digest"],
            "after_successor_index_digest": after["successor_index_digest"],
            "successor_index_digest": cls._digest(index),
            "s25q_case_digest": q_case["input_digest"],
            "s25q_result_digest": cls._digest(q_result),
            "s25q_classification": q_result["classification"],
            "s25q_status": q_result["status"],
            "s25q_decision": q_result["decision"],
            "s25p_classification": q_result["s25p_classification"],
            "observation_id": transition["observation_id"],
            "idempotency_key": transition["idempotency_key"],
            "receipt_set_digest": "",
        }
        common = {
            "observation_id": expected["observation_id"],
            "idempotency_key": expected["idempotency_key"],
            "subject_digest": expected["subject_digest"],
            "scope_digest": expected["scope_digest"],
            "baseline_digest": expected["baseline_digest"],
            "epoch": expected["epoch"],
            "previous_sequence": expected["previous_sequence"],
            "previous_pass_digest": expected["previous_pass_digest"],
            "previous_observation_digest": expected["previous_observation_digest"],
            "current_sequence": expected["current_sequence"],
            "current_pass_digest": expected["current_pass_digest"],
            "current_observation_digest": expected["current_observation_digest"],
            "parent_key": expected["parent_key"],
            "candidate_key": expected["candidate_key"],
            "transition_digest": expected["transition_digest"],
            "before_state_version": expected["before_state_version"],
            "after_state_version": expected["after_state_version"],
            "before_head_digest": expected["before_head_digest"],
            "after_head_digest": expected["after_head_digest"],
            "before_history_digest": expected["before_history_digest"],
            "after_history_digest": expected["after_history_digest"],
            "index_digest": expected["successor_index_digest"],
        }
        payloads = {
            "S25Q_RESULT": {
                "s25q_result_digest": expected["s25q_result_digest"],
                "classification": q_result["classification"],
                "status": q_result["status"],
                "decision": q_result["decision"],
                "s25p_classification": q_result["s25p_classification"],
                "reason": q_result["reason"],
                "floor_advanced": False,
            },
            "PARENT_CANDIDATE": {
                "previous_sequence": expected["previous_sequence"],
                "current_sequence": expected["current_sequence"],
                "previous_pass_digest": expected["previous_pass_digest"],
                "current_pass_digest": expected["current_pass_digest"],
                "parent_key": expected["parent_key"],
                "candidate_key": expected["candidate_key"],
            },
            "TRANSITION": {
                "schema": transition["schema"],
                "source": transition["source"],
                "observation_id": transition["observation_id"],
                "idempotency_key": transition["idempotency_key"],
                "cas_status": transition["cas_status"],
            },
            "HEAD": {
                "before_head_digest": expected["before_head_digest"],
                "after_head_digest": expected["after_head_digest"],
                "transition_digest": expected["transition_digest"],
            },
            "HISTORY": {
                "before_history_digest": expected["before_history_digest"],
                "after_history_digest": expected["after_history_digest"],
                "appended_pass_digest": after["used_pass_digests"][-1],
                "appended_observation_digest": after["used_observation_digests"][-1],
            },
            "INDEX": {
                "successor_index_digest": expected["successor_index_digest"],
                "registry_state_version": index["registry_state_version"],
                "registry_head_digest": index["registry_head_digest"],
                "candidate_count": index["candidate_count"],
                "candidate_pass_digests": index["candidate_pass_digests"],
                "candidate_keys": index["candidate_keys"],
                "lineage": index["lineage"],
                "entry_status": index["entry_status"],
            },
        }
        receipts: list[dict[str, object]] = []
        for kind in cls.REQUIRED_KINDS:
            receipt = {"kind": kind, "receipt_digest": "", **common, "payload": payloads[kind]}
            receipt["receipt_digest"] = cls._receipt_digest(receipt)
            receipts.append(receipt)
        receipt_set: dict[str, object] = {
            "schema": "s25r.receipt-set.v1",
            "required_kinds": list(cls.REQUIRED_KINDS),
            "receipt_count": len(receipts),
            "receipts": receipts,
            "receipt_digests": [receipt["receipt_digest"] for receipt in receipts],
            "set_digest": "",
        }
        receipt_set["set_digest"] = cls._set_digest(receipt_set)
        expected["receipt_set_digest"] = receipt_set["set_digest"]
        case: dict[str, object] = {
            "schema_version": "s25r.receipt-reconciliation-witness.v1",
            "observation_mode": "TEST_ONLY",
            "canonicalization": "s25m-canonical-json-v1",
            "expected": expected,
            "previous": deepcopy(previous),
            "current": {key: value for key, value in current.items() if key != "s25p_case"},
            "floor_transition": deepcopy(transition),
            "successor_index": deepcopy(index),
            "s25q_case": deepcopy(q_case),
            "receipt_set": receipt_set,
            "input_digest": "",
        }
        case["input_digest"] = input_digest(case)
        return case

    @classmethod
    def _reseal_receipt(cls, case: dict[str, object], position: int) -> None:
        receipts = case["receipt_set"]["receipts"]
        receipts[position]["receipt_digest"] = cls._receipt_digest(receipts[position])
        case["receipt_set"]["receipt_digests"] = [receipt["receipt_digest"] for receipt in receipts]
        case["receipt_set"]["set_digest"] = cls._set_digest(case["receipt_set"])
        case["expected"]["receipt_set_digest"] = case["receipt_set"]["set_digest"]
        case["input_digest"] = input_digest(case)

    @classmethod
    def _reseal_case(cls, case: dict[str, object]) -> None:
        case["input_digest"] = input_digest(case)

    @classmethod
    def _bind_q_result(cls, case: dict[str, object], q_result: dict[str, object]) -> None:
        expected = case["expected"]
        expected["s25q_result_digest"] = cls._digest(q_result)
        expected["s25q_classification"] = q_result["classification"]
        expected["s25q_status"] = q_result["status"]
        expected["s25q_decision"] = q_result["decision"]
        expected["s25p_classification"] = q_result.get("s25p_classification", expected["s25p_classification"])
        receipt = next(item for item in case["receipt_set"]["receipts"] if item["kind"] == "S25Q_RESULT")
        receipt["payload"] = {
            "s25q_result_digest": expected["s25q_result_digest"],
            "classification": q_result["classification"],
            "status": q_result["status"],
            "decision": q_result["decision"],
            "s25p_classification": q_result.get("s25p_classification", expected["s25p_classification"]),
            "reason": q_result["reason"],
            "floor_advanced": False,
        }
        cls._reseal_receipt(case, case["receipt_set"]["receipts"].index(receipt))

    def test_complete_bundle_is_only_a_read_only_witness(self) -> None:
        result = evaluate_receipt_reconciliation(self._base())

        self.assertEqual(result["classification"], RECEIPT_BUNDLE_RECONCILED)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertTrue(result["witness_only"])
        self.assertTrue(result["receipt_witnessed"])
        self.assertFalse(result["floor_advanced"])

    def test_input_is_unchanged_and_all_mutation_flags_are_negative(self) -> None:
        case = self._base()
        before = deepcopy(case)

        result = evaluate_receipt_reconciliation(case)

        self.assertEqual(case, before)
        for field in (
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
        ):
            self.assertFalse(result[field])

    def test_missing_receipt_is_blocked(self) -> None:
        case = self._base()
        case["receipt_set"]["receipts"].pop()
        case["receipt_set"]["receipt_count"] -= 1
        case["receipt_set"]["receipt_digests"] = [receipt["receipt_digest"] for receipt in case["receipt_set"]["receipts"]]
        case["receipt_set"]["set_digest"] = self._set_digest(case["receipt_set"])
        case["expected"]["receipt_set_digest"] = case["receipt_set"]["set_digest"]
        self._reseal_case(case)

        result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["reason"], "RECEIPTS_PARTIAL")

    def test_duplicate_receipt_is_blocked_and_never_selected(self) -> None:
        case = self._base()
        duplicate = deepcopy(case["receipt_set"]["receipts"][0])
        case["receipt_set"]["receipts"].append(duplicate)
        case["receipt_set"]["receipt_count"] += 1
        case["receipt_set"]["receipt_digests"].append(duplicate["receipt_digest"])
        case["receipt_set"]["set_digest"] = self._set_digest(case["receipt_set"])
        case["expected"]["receipt_set_digest"] = case["receipt_set"]["set_digest"]
        self._reseal_case(case)

        result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["reason"], "RECEIPTS_DUPLICATE")

    def test_receipt_order_is_canonicalized_but_required_kinds_remain_exact(self) -> None:
        case = self._base()
        case["receipt_set"]["receipts"] = list(reversed(case["receipt_set"]["receipts"]))
        case["receipt_set"]["receipt_digests"] = [receipt["receipt_digest"] for receipt in case["receipt_set"]["receipts"]]
        case["receipt_set"]["set_digest"] = self._set_digest(case["receipt_set"])
        case["expected"]["receipt_set_digest"] = case["receipt_set"]["set_digest"]
        self._reseal_case(case)

        result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["classification"], RECEIPT_BUNDLE_RECONCILED)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")

    def test_receipt_identifiers_are_bound(self) -> None:
        for field, value in (("observation_id", "other-observation"), ("idempotency_key", "other-idempotency")):
            case = self._base()
            case["receipt_set"]["receipts"][0][field] = value
            self._reseal_receipt(case, 0)

            result = evaluate_receipt_reconciliation(case)

            self.assertEqual(result["classification"], "RECEIPT_CONFLICT", field)
            self.assertEqual(result["reason"], "RECEIPT_STALE_OR_CONFLICTING", field)

    def test_stale_sequence_and_old_pass_are_reviewed(self) -> None:
        case = self._base()
        case["receipt_set"]["receipts"][1]["current_sequence"] = case["expected"]["previous_sequence"]
        self._reseal_receipt(case, 1)

        result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["classification"], "RECEIPT_REPLAY")
        self.assertEqual(result["reason"], "RECEIPT_REPLAY")

    def test_cross_identity_receipt_is_conflict(self) -> None:
        case = self._base()
        case["receipt_set"]["receipts"][2]["subject_digest"] = self._hash("foreign-subject")
        self._reseal_receipt(case, 2)

        result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["classification"], "RECEIPT_CONFLICT")
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "RECEIPT_IDENTITY_MISMATCH")

    def test_transition_head_history_and_index_drift_are_not_reconciled(self) -> None:
        for field, value in (
            ("transition_digest", self._hash("foreign-transition")),
            ("before_head_digest", self._hash("foreign-before-head")),
            ("after_history_digest", self._hash("foreign-history")),
            ("index_digest", self._hash("foreign-index")),
        ):
            case = self._base()
            case["receipt_set"]["receipts"][3][field] = value
            self._reseal_receipt(case, 3)

            result = evaluate_receipt_reconciliation(case)

            self.assertEqual(result["status"], "RECOVERY_REQUIRED", field)
            self.assertEqual(result["reason"], "RECEIPT_STALE_OR_CONFLICTING", field)

    def test_q_nonpositive_result_never_becomes_witness(self) -> None:
        case = self._base()
        fake = evaluate_replay_floor_fork(case["s25q_case"])
        fake.update({"classification": "FLOOR_BLOCKED", "status": "TEST_BLOCKED", "decision": "HOLD", "reason": "FLOOR_IDEMPOTENT_REPLAY"})

        with patch("support.w5_s25r_receipt_reconciliation.evaluate_replay_floor_fork", return_value=fake):
            result = evaluate_receipt_reconciliation(case)

        self.assertNotEqual(result["classification"], RECEIPT_BUNDLE_RECONCILED)
        self.assertEqual(result["classification"], "RECEIPT_REJECTED")
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["reason"], "S25Q_RESULT_INVALID")

    def test_forged_q_positive_flags_are_blocked(self) -> None:
        case = self._base()
        fake = evaluate_replay_floor_fork(case["s25q_case"])
        fake["floor_advanced"] = True

        with patch("support.w5_s25r_receipt_reconciliation.evaluate_replay_floor_fork", return_value=fake):
            result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["reason"], "S25Q_RESULT_INVALID")

    def test_forged_q_status_fields_are_blocked(self) -> None:
        case = self._base()
        fake = evaluate_replay_floor_fork(case["s25q_case"])
        fake["sequence_status"] = "ROLLBACK"
        fake["binding_status"] = "MISMATCH"
        fake["replay_status"] = "REPLAY"

        with patch("support.w5_s25r_receipt_reconciliation.evaluate_replay_floor_fork", return_value=fake):
            result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["reason"], "S25Q_RESULT_INVALID")

    def test_forged_positive_q_status_cannot_be_resealed_as_a_witness(self) -> None:
        for status, decision in (("TEST_BLOCKED", "HOLD"), ("RECOVERY_REQUIRED", "MANUAL_REVIEW")):
            with self.subTest(status=status):
                case = self._base()
                fake = evaluate_replay_floor_fork(case["s25q_case"])
                fake.update({"status": status, "decision": decision})
                self._bind_q_result(case, fake)

                with patch("support.w5_s25r_receipt_reconciliation.evaluate_replay_floor_fork", return_value=fake):
                    result = evaluate_receipt_reconciliation(case)

                self.assertEqual(result["status"], "TEST_BLOCKED")
                self.assertEqual(result["reason"], "S25Q_RESULT_INVALID")

    def test_forged_nonpositive_q_status_cannot_claim_locked_pass(self) -> None:
        case = self._base()
        fake = evaluate_replay_floor_fork(case["s25q_case"])
        fake.update({
            "classification": "FLOOR_REJECTED",
            "status": "LOCKED_TEST_PASS",
            "decision": "TEST_ONLY_PASS",
            "reason": "FORGED_NONPOSITIVE_STATUS",
        })
        self._bind_q_result(case, fake)

        with patch("support.w5_s25r_receipt_reconciliation.evaluate_replay_floor_fork", return_value=fake):
            result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["reason"], "S25Q_RESULT_INVALID")

    def test_forged_q_status_projection_and_s25p_reason_are_blocked(self) -> None:
        for field, value in (("baseline_status", "TEST_BLOCKED"), ("candidate_status", "TEST_BLOCKED"), ("s25p_reason", "FORGED")):
            with self.subTest(field=field):
                case = self._base()
                fake = evaluate_replay_floor_fork(case["s25q_case"])
                fake[field] = value
                self._bind_q_result(case, fake)

                with patch("support.w5_s25r_receipt_reconciliation.evaluate_replay_floor_fork", return_value=fake):
                    result = evaluate_receipt_reconciliation(case)

                self.assertEqual(result["status"], "TEST_BLOCKED", field)
                self.assertEqual(result["reason"], "S25Q_RESULT_INVALID", field)

    def test_forged_positive_q_result_cannot_cross_a_fork_case(self) -> None:
        case = self._base()
        case["s25q_case"]["successor_index"]["lineage"] = "FORK"
        case["successor_index"]["lineage"] = "FORK"
        case["input_digest"] = input_digest(case)
        fake = evaluate_replay_floor_fork(self._base()["s25q_case"])

        with patch("support.w5_s25r_receipt_reconciliation.evaluate_replay_floor_fork", return_value=fake):
            result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["classification"], "S25Q_REJECTED")
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "EXPECTED_BINDING_MISMATCH")

    def test_receipt_set_digest_drift_is_blocked(self) -> None:
        case = self._base()
        case["expected"]["receipt_set_digest"] = self._hash("wrong-set")
        self._reseal_case(case)

        result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["reason"], "RECEIPT_SET_BINDING_MISMATCH")

    def test_expected_projection_drift_is_reviewed(self) -> None:
        case = self._base()
        case["expected"]["after_head_digest"] = self._hash("wrong-head")
        self._reseal_case(case)

        result = evaluate_receipt_reconciliation(case)

        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "EXPECTED_BINDING_MISMATCH")

    def test_duplicate_json_and_unsafe_values_are_blocked_without_echo(self) -> None:
        duplicate = evaluate_receipt_reconciliation(
            b'{"schema_version":"s25r.receipt-reconciliation-witness.v1","schema_version":"other"}'
        )
        unsafe = self._base()
        unsafe["receipt_set"]["receipts"][0]["observation_id"] = "file:///etc/passwd"
        unsafe_result = evaluate_receipt_reconciliation(unsafe)

        self.assertEqual(duplicate["status"], "TEST_BLOCKED")
        self.assertEqual(unsafe_result["status"], "TEST_BLOCKED")
        self.assertNotIn("file:///etc/passwd", repr(unsafe_result))

    def test_recursive_and_broken_mappings_never_raise(self) -> None:
        recursive = self._base()
        cycle: list[object] = []
        cycle.append(cycle)
        recursive["receipt_set"]["cycle"] = cycle
        broken = {"broken": "mapping"}

        self.assertEqual(evaluate_receipt_reconciliation(recursive)["status"], "TEST_BLOCKED")
        self.assertEqual(evaluate_receipt_reconciliation(broken)["status"], "TEST_BLOCKED")
        with self.assertRaisesRegex(ValueError, "cannot be canonicalized"):
            input_digest(recursive)

    def test_stateful_mapping_is_snapshotted_before_digest_and_validation(self) -> None:
        signed = self._base()
        signed["receipt_set"]["receipts"].pop()
        signed["receipt_set"]["receipt_count"] -= 1
        signed["receipt_set"]["receipt_digests"] = [receipt["receipt_digest"] for receipt in signed["receipt_set"]["receipts"]]
        signed["receipt_set"]["set_digest"] = self._set_digest(signed["receipt_set"])
        signed["expected"]["receipt_set_digest"] = signed["receipt_set"]["set_digest"]
        self._reseal_case(signed)
        valid = self._base()

        class StatefulMapping(dict[str, object]):
            def __init__(self, first: dict[str, object], later: dict[str, object]) -> None:
                super().__init__(first)
                self._first = first
                self._later = later
                self._calls = 0

            def items(self):  # type: ignore[no-untyped-def]
                self._calls += 1
                return (self._first if self._calls == 1 else self._later).items()

        result = evaluate_receipt_reconciliation(StatefulMapping(signed, valid))

        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertEqual(result["reason"], "RECEIPTS_PARTIAL")

    def test_float_bool_and_duplicate_history_values_are_blocked(self) -> None:
        float_case = self._base()
        float_case["expected"]["after_state_version"] = 42.0
        bool_case = self._base()
        bool_case["expected"]["after_state_version"] = True
        duplicate_case = self._base()
        duplicate_case["s25q_case"]["floor_transition"]["before"]["used_pass_digests"].append(
            duplicate_case["s25q_case"]["previous"]["pass_digest"]
        )
        duplicate_case["input_digest"] = input_digest(duplicate_case)

        for case in (float_case, bool_case, duplicate_case):
            result = evaluate_receipt_reconciliation(case)
            self.assertNotEqual(result["classification"], RECEIPT_BUNDLE_RECONCILED)
            self.assertFalse(result["floor_advanced"])

    def test_support_is_pure_and_delegates_only_public_s25q(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25r_receipt_reconciliation.py").read_text()
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
            "w5_s25q_replay_floor_fork import _",
            "w5_s25p_fresh_revalidation import _",
            "receipt_committed = True",
            "floor_advanced = True",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("evaluate_replay_floor_fork", source)
        self.assertIn("RECEIPT_BUNDLE_RECONCILED", source)


if __name__ == "__main__":
    unittest.main()
