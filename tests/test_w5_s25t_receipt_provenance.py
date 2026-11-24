"""Adversarial tests for the pure S25T receipt-provenance gate."""

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
from support.w5_s25r_receipt_reconciliation import (  # noqa: E402
    evaluate_receipt_reconciliation,
)
import test_w5_s25r_receipt_reconciliation as s25r_tests  # noqa: E402


class W5S25TReceiptProvenanceTests(unittest.TestCase):
    REQUIRED_KINDS = ["S25Q_RESULT", "PARENT_CANDIDATE", "TRANSITION", "HEAD", "HISTORY", "INDEX"]

    @staticmethod
    def _digest(value: object) -> str:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _source_digest(cls, source: dict[str, object]) -> str:
        return cls._digest({key: value for key, value in source.items() if key != "source_digest"})

    @classmethod
    def _cell_digest(cls, cell: dict[str, object]) -> str:
        return cls._digest({key: value for key, value in cell.items() if key != "cell_digest"})

    @classmethod
    def _window_id(cls, window: dict[str, object]) -> str:
        return cls._digest(
            {
                "schema": window["schema"],
                "observer_id": window["observer_id"],
                "comparison_group": window["comparison_group"],
                "subject_digest": window["subject_digest"],
                "scope_digest": window["scope_digest"],
                "baseline_digest": window["baseline_digest"],
                "epoch": window["epoch"],
                "start_sequence": window["start_sequence"],
                "target_sequence": window["target_sequence"],
                "end_sequence": window["end_sequence"],
            }
        )

    @classmethod
    def _window_digest(cls, window: dict[str, object]) -> str:
        unsigned = {key: value for key, value in window.items() if key not in {"window_id", "window_digest"}}
        unsigned["expected_cells"] = sorted(unsigned["expected_cells"], key=lambda item: item["cell_digest"])
        unsigned["window_id"] = window["window_id"]
        return cls._digest(unsigned)

    @classmethod
    def _observation_digest(cls, observation: dict[str, object]) -> str:
        return cls._digest({key: value for key, value in observation.items() if key != "observation_digest"})

    @classmethod
    def _source_set_digest(cls, source_set: dict[str, object]) -> str:
        return cls._digest(
            {
                "schema": source_set["schema"],
                "required_source_ids": source_set["required_source_ids"],
                "source_digests": sorted(source_set["source_digests"]),
            }
        )

    @classmethod
    def _observation_set_digest(cls, observations: list[dict[str, object]]) -> str:
        return cls._digest(
            {
                "schema": "s25t.observation-set.v1",
                "observation_digests": sorted(item["observation_digest"] for item in observations),
            }
        )

    @classmethod
    def _base(cls) -> dict[str, object]:
        r_case = s25r_tests.W5S25RReceiptReconciliationTests._base()
        r_result = evaluate_receipt_reconciliation(r_case)
        r_expected = r_case["expected"]
        observer_id = "observer-alpha"
        comparison_group = "s25r-receipt-bundle"
        source_ids = [f"s25r-source-{kind.lower()}" for kind in cls.REQUIRED_KINDS]

        projection: dict[str, object] = {
            "schema": "s25t.s25r-projection.v1",
            "s25r_case_digest": r_case["input_digest"],
            "s25r_result_digest": cls._digest(r_result),
            "classification": r_result["classification"],
            "status": r_result["status"],
            "decision": r_result["decision"],
            "reason": r_result["reason"],
            "reconciliation_status": r_result["reconciliation_status"],
            "witness_only": r_result["witness_only"],
            "receipt_count": r_result["receipt_count"],
            "receipt_witnessed": r_result["receipt_witnessed"],
            "s25q_classification": r_result["s25q_classification"],
            "s25q_status": r_result["s25q_status"],
            "subject_digest": r_expected["subject_digest"],
            "scope_digest": r_expected["scope_digest"],
            "baseline_digest": r_expected["baseline_digest"],
            "epoch": r_expected["epoch"],
            "observation_id": r_expected["observation_id"],
            "idempotency_key": r_expected["idempotency_key"],
            "previous_sequence": r_expected["previous_sequence"],
            "current_sequence": r_expected["current_sequence"],
            "previous_pass_digest": r_expected["previous_pass_digest"],
            "current_pass_digest": r_expected["current_pass_digest"],
            "previous_observation_digest": r_expected["previous_observation_digest"],
            "current_observation_digest": r_expected["current_observation_digest"],
            "receipt_set_digest": r_expected["receipt_set_digest"],
            "receipt_digests": [
                {"kind": kind, "receipt_digest": next(item["receipt_digest"] for item in r_case["receipt_set"]["receipts"] if item["kind"] == kind)}
                for kind in cls.REQUIRED_KINDS
            ],
            "production_status": r_result["production_status"],
            "authority_claim": r_result["authority_claim"],
            "write_authorized": r_result["write_authorized"],
            "mutation_allowed": r_result["mutation_allowed"],
            "persistence_performed": r_result["persistence_performed"],
            "cas_attempted": r_result["cas_attempted"],
            "fence_issued": r_result["fence_issued"],
            "resume_allowed": r_result["resume_allowed"],
            "receipt_emitted": r_result["receipt_emitted"],
            "receipt_committed": r_result["receipt_committed"],
            "commit_authorized": r_result["commit_authorized"],
            "floor_advanced": r_result["floor_advanced"],
        }
        projection["projection_digest"] = cls._digest(projection)

        sources: list[dict[str, object]] = []
        for kind, source_id in zip(cls.REQUIRED_KINDS, source_ids):
            source: dict[str, object] = {
                "schema": "s25t.receipt-source.v1",
                "source_id": source_id,
                "observer_id": observer_id,
                "comparison_group": comparison_group,
                "subject_digest": r_expected["subject_digest"],
                "scope_digest": r_expected["scope_digest"],
                "baseline_digest": r_expected["baseline_digest"],
                "epoch": r_expected["epoch"],
                "source_digest": "",
            }
            source["source_digest"] = cls._source_digest(source)
            sources.append(source)
        source_set: dict[str, object] = {
            "schema": "s25t.source-set.v1",
            "required_source_ids": source_ids,
            "source_count": len(sources),
            "sources": sources,
            "source_digests": [source["source_digest"] for source in sources],
            "set_digest": "",
        }
        source_set["set_digest"] = cls._source_set_digest(source_set)

        cells: list[dict[str, object]] = []
        for kind, source_id in zip(cls.REQUIRED_KINDS, source_ids):
            cell: dict[str, object] = {
                "source_id": source_id,
                "observer_id": observer_id,
                "receipt_kind": kind,
                "epoch": r_expected["epoch"],
                "observation_sequence": r_expected["current_sequence"],
                "cell_digest": "",
            }
            cell["cell_digest"] = cls._cell_digest(cell)
            cells.append(cell)
        window: dict[str, object] = {
            "schema": "s25t.observation-window.v1",
            "window_id": "",
            "observer_id": observer_id,
            "comparison_group": comparison_group,
            "subject_digest": r_expected["subject_digest"],
            "scope_digest": r_expected["scope_digest"],
            "baseline_digest": r_expected["baseline_digest"],
            "epoch": r_expected["epoch"],
            "start_sequence": r_expected["previous_sequence"],
            "target_sequence": r_expected["current_sequence"],
            "end_sequence": r_expected["current_sequence"],
            "start_observation_digest": r_expected["previous_observation_digest"],
            "end_observation_digest": r_expected["current_observation_digest"],
            "required_receipt_kinds": list(cls.REQUIRED_KINDS),
            "expected_cells": cells,
            "required_cell_count": len(cells),
            "coverage_status": "COMPLETE",
            "freshness_status": "FRESH",
            "comparison_status": "COMPARABLE",
            "window_digest": "",
        }
        window["window_id"] = cls._window_id(window)
        window["window_digest"] = cls._window_digest(window)

        observations: list[dict[str, object]] = []
        receipt_by_kind = {item["kind"]: item for item in r_case["receipt_set"]["receipts"]}
        for kind, source in zip(cls.REQUIRED_KINDS, sources):
            observation: dict[str, object] = {
                "schema": "s25t.receipt-observation.v1",
                "cell_digest": next(cell["cell_digest"] for cell in cells if cell["receipt_kind"] == kind),
                "source_id": source["source_id"],
                "source_digest": source["source_digest"],
                "observer_id": observer_id,
                "comparison_group": comparison_group,
                "receipt_kind": kind,
                "observation_id": r_expected["observation_id"],
                "idempotency_key": r_expected["idempotency_key"],
                "subject_digest": r_expected["subject_digest"],
                "scope_digest": r_expected["scope_digest"],
                "baseline_digest": r_expected["baseline_digest"],
                "epoch": r_expected["epoch"],
                "observation_sequence": r_expected["current_sequence"],
                "observation_state": "PRESENT",
                "comparison_status": "COMPARABLE",
                "freshness_status": "FRESH",
                "coverage_status": "COMPLETE",
                "receipt_digest": receipt_by_kind[kind]["receipt_digest"],
                "s25r_projection_digest": projection["projection_digest"],
                "observation_digest": "",
            }
            observation["observation_digest"] = cls._observation_digest(observation)
            observations.append(observation)
        observation_set_digest = cls._observation_set_digest(observations)

        expected: dict[str, object] = {
            "s25r_case_digest": r_case["input_digest"],
            "s25r_result_digest": projection["s25r_result_digest"],
            "s25r_projection_digest": projection["projection_digest"],
            "subject_digest": r_expected["subject_digest"],
            "scope_digest": r_expected["scope_digest"],
            "baseline_digest": r_expected["baseline_digest"],
            "epoch": r_expected["epoch"],
            "previous_sequence": r_expected["previous_sequence"],
            "current_sequence": r_expected["current_sequence"],
            "previous_pass_digest": r_expected["previous_pass_digest"],
            "current_pass_digest": r_expected["current_pass_digest"],
            "previous_observation_digest": r_expected["previous_observation_digest"],
            "current_observation_digest": r_expected["current_observation_digest"],
            "observation_id": r_expected["observation_id"],
            "idempotency_key": r_expected["idempotency_key"],
            "observer_id": observer_id,
            "comparison_group": comparison_group,
            "window_digest": window["window_digest"],
            "source_set_digest": source_set["set_digest"],
            "observation_set_digest": observation_set_digest,
            "required_source_count": len(sources),
            "required_observation_count": len(observations),
        }
        case: dict[str, object] = {
            "schema_version": s25t.HARNESS_SCHEMA,
            "observation_mode": "TEST_ONLY",
            "canonicalization": s25t.CANONICALIZATION,
            "expected": expected,
            "s25r_case": r_case,
            "s25r_projection": projection,
            "sources": source_set,
            "window": window,
            "observations": observations,
            "input_digest": "",
        }
        case["input_digest"] = s25t.input_digest(case)
        return case

    @classmethod
    def _reseal(cls, case: dict[str, object]) -> None:
        case["input_digest"] = s25t.input_digest(case)

    @classmethod
    def _reseal_observation(cls, case: dict[str, object], position: int) -> None:
        observation = case["observations"][position]
        observation["observation_digest"] = cls._observation_digest(observation)
        case["expected"]["observation_set_digest"] = cls._observation_set_digest(case["observations"])
        cls._reseal(case)

    @classmethod
    def _reseal_window(cls, case: dict[str, object]) -> None:
        window = case["window"]
        window["window_id"] = cls._window_id(window)
        window["window_digest"] = cls._window_digest(window)
        case["expected"]["window_digest"] = window["window_digest"]
        cls._reseal(case)

    def test_complete_provenance_is_only_a_read_only_witness(self) -> None:
        result = s25t.evaluate_receipt_provenance(self._base())

        self.assertEqual(result["classification"], s25t.PROVENANCE_WITNESS_RECONCILED)
        self.assertEqual(result["status"], "PROPOSAL_ONLY")
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["provenance_status"], "COMPLETE")
        self.assertTrue(result["witness_only"])
        self.assertTrue(result["source_witnessed"])
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["resume_allowed"])

    def test_input_is_unchanged_and_digest_is_stable(self) -> None:
        case = self._base()
        before = deepcopy(case)

        first = s25t.evaluate_receipt_provenance(case)
        second = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(case, before)
        self.assertEqual(first, second)
        self.assertEqual(case["input_digest"], s25t.input_digest(case))

    def test_reordering_sources_and_observations_preserves_set_comparison(self) -> None:
        case = self._base()
        case["sources"]["sources"] = list(reversed(case["sources"]["sources"]))
        case["sources"]["source_digests"] = [source["source_digest"] for source in case["sources"]["sources"]]
        case["observations"] = list(reversed(case["observations"]))
        self._reseal(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_WITNESS_RECONCILED)

    def test_missing_observation_is_partial_and_never_positive(self) -> None:
        case = self._base()
        case["observations"].pop()
        self._reseal(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_PARTIAL)
        self.assertEqual(result["status"], "TEST_BLOCKED")
        self.assertNotEqual(result["provenance_status"], "COMPLETE")

    def test_absent_observation_is_partial_even_when_resealed(self) -> None:
        case = self._base()
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
        self._reseal_observation(case, 0)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_PARTIAL)
        self.assertEqual(result["reason"], "PARTIAL_OBSERVATION")

    def test_unknown_source_id_is_fail_closed(self) -> None:
        case = self._base()
        case["observations"][0]["source_id"] = "s25r-source-unknown"
        self._reseal_observation(case, 0)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertIn(result["classification"], {s25t.PROVENANCE_UNKNOWN, "INPUT_INVALID", s25t.PROVENANCE_REJECTED})
        self.assertNotEqual(result["classification"], s25t.PROVENANCE_WITNESS_RECONCILED)

    def test_duplicate_source_is_rejected(self) -> None:
        case = self._base()
        case["sources"]["sources"][1] = deepcopy(case["sources"]["sources"][0])
        case["sources"]["source_digests"][1] = case["sources"]["sources"][0]["source_digest"]
        case["sources"]["set_digest"] = self._source_set_digest(case["sources"])
        case["expected"]["source_set_digest"] = case["sources"]["set_digest"]
        self._reseal(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_REJECTED)
        self.assertEqual(result["reason"], "SOURCES_DUPLICATE")

    def test_extra_source_cannot_expand_required_coverage(self) -> None:
        case = self._base()
        extra = deepcopy(case["sources"]["sources"][0])
        extra["source_id"] = "s25r-source-extra"
        extra["source_digest"] = self._source_digest(extra)
        case["sources"]["sources"].append(extra)
        case["sources"]["source_digests"].append(extra["source_digest"])
        case["sources"]["source_count"] += 1
        case["sources"]["set_digest"] = self._source_set_digest(case["sources"])
        case["expected"]["source_set_digest"] = case["sources"]["set_digest"]
        self._reseal(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertNotEqual(result["classification"], s25t.PROVENANCE_WITNESS_RECONCILED)

    def test_cross_source_observer_identity_is_conflict(self) -> None:
        case = self._base()
        case["sources"]["sources"][2]["observer_id"] = "observer-other"
        case["sources"]["sources"][2]["source_digest"] = self._source_digest(case["sources"]["sources"][2])
        case["sources"]["source_digests"][2] = case["sources"]["sources"][2]["source_digest"]
        case["sources"]["set_digest"] = self._source_set_digest(case["sources"])
        case["expected"]["source_set_digest"] = case["sources"]["set_digest"]
        self._reseal(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_CONFLICT)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")

    def test_window_sequence_gap_is_out_of_window(self) -> None:
        case = self._base()
        case["window"]["target_sequence"] += 1
        case["window"]["end_sequence"] = case["window"]["target_sequence"]
        self._reseal_window(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_OUT_OF_WINDOW)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")

    def test_bad_window_status_never_reaches_positive_path(self) -> None:
        for field, value, classification in (
            ("coverage_status", "PARTIAL", s25t.PROVENANCE_PARTIAL),
            ("freshness_status", "STALE", s25t.PROVENANCE_STALE),
            ("freshness_status", "FUTURE", s25t.PROVENANCE_OUT_OF_WINDOW),
            ("comparison_status", "NOT_COMPARABLE", s25t.PROVENANCE_PARTIAL),
        ):
            with self.subTest(field=field, value=value):
                case = self._base()
                case["window"][field] = value
                self._reseal_window(case)

                result = s25t.evaluate_receipt_provenance(case)

                self.assertEqual(result["classification"], classification)
                self.assertNotEqual(result["classification"], s25t.PROVENANCE_WITNESS_RECONCILED)

    def test_receipt_kind_and_source_id_mapping_cannot_be_rotated(self) -> None:
        case = self._base()
        window = case["window"]
        cells = {cell["receipt_kind"]: cell for cell in window["expected_cells"]}
        first_kind, second_kind = self.REQUIRED_KINDS[:2]
        first_source = cells[first_kind]["source_id"]
        cells[first_kind]["source_id"], cells[second_kind]["source_id"] = cells[second_kind]["source_id"], first_source
        for cell in window["expected_cells"]:
            cell["cell_digest"] = self._cell_digest(cell)
        source_by_id = {source["source_id"]: source for source in case["sources"]["sources"]}
        for observation in case["observations"]:
            cell = cells[observation["receipt_kind"]]
            observation["source_id"] = cell["source_id"]
            observation["source_digest"] = source_by_id[cell["source_id"]]["source_digest"]
            observation["cell_digest"] = cell["cell_digest"]
            observation["observation_digest"] = self._observation_digest(observation)
        case["expected"]["observation_set_digest"] = self._observation_set_digest(case["observations"])
        self._reseal_window(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_OUT_OF_WINDOW)
        self.assertNotEqual(result["classification"], s25t.PROVENANCE_WITNESS_RECONCILED)

    def test_stale_observation_requires_review(self) -> None:
        case = self._base()
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
        self._reseal_observation(case, 0)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_STALE)
        self.assertEqual(result["decision"], "MANUAL_REVIEW")

    def test_future_observation_is_out_of_window(self) -> None:
        case = self._base()
        observation = case["observations"][0]
        observation.update(
            {
                "observation_state": "FUTURE",
                "comparison_status": "NOT_COMPARABLE",
                "freshness_status": "FUTURE",
                "coverage_status": "PARTIAL",
                "receipt_digest": None,
            }
        )
        self._reseal_observation(case, 0)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_OUT_OF_WINDOW)

    def test_receipt_digest_mismatch_is_conflict_after_resealing_observation(self) -> None:
        case = self._base()
        case["observations"][0]["receipt_digest"] = "0" * 64
        self._reseal_observation(case, 0)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_CONFLICT)
        self.assertEqual(result["reason"], "RECEIPT_BINDING_MISMATCH")

    def test_projection_digest_mismatch_is_conflict(self) -> None:
        case = self._base()
        case["observations"][0]["s25r_projection_digest"] = "1" * 64
        self._reseal_observation(case, 0)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_CONFLICT)
        self.assertEqual(result["reason"], "OBSERVATION_PROJECTION_MISMATCH")

    def test_present_stale_or_future_observation_has_precise_review_class(self) -> None:
        for freshness, classification in (("STALE", s25t.PROVENANCE_STALE), ("FUTURE", s25t.PROVENANCE_OUT_OF_WINDOW)):
            with self.subTest(freshness=freshness):
                case = self._base()
                case["observations"][0]["freshness_status"] = freshness
                self._reseal_observation(case, 0)

                result = s25t.evaluate_receipt_provenance(case)

                self.assertEqual(result["classification"], classification)
                self.assertEqual(result["status"], "RECOVERY_REQUIRED")

    def test_forged_s25r_projection_is_rejected_even_when_outer_case_is_resealed(self) -> None:
        case = self._base()
        case["s25r_projection"]["reason"] = "FORGED"
        case["s25r_projection"]["projection_digest"] = self._digest(
            {key: value for key, value in case["s25r_projection"].items() if key != "projection_digest"}
        )
        case["expected"]["s25r_projection_digest"] = case["s25r_projection"]["projection_digest"]
        self._reseal(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_REJECTED)
        self.assertEqual(result["reason"], "S25R_PROJECTION_MISMATCH")

    def test_nonpositive_s25r_is_rejected_before_provenance_claim(self) -> None:
        case = self._base()
        with patch.object(s25t, "evaluate_receipt_reconciliation", return_value={
            "schema_version": "s25r.receipt-reconciliation-witness.v1",
            "observation_mode": "TEST_ONLY",
            "classification": "RECEIPT_CONFLICT",
            "status": "RECOVERY_REQUIRED",
            "decision": "MANUAL_REVIEW",
            "reason": "RECEIPT_CONFLICT",
            "reconciliation_status": "NOT_CLAIMED",
            "witness_only": False,
            "receipt_count": 0,
            "receipt_witnessed": False,
            "s25q_classification": "FLOOR_BLOCKED",
            "s25q_status": "TEST_BLOCKED",
            "production_status": "PRODUCTION_NOT_AUTHORIZED",
            "authority_claim": "NOT_CLAIMED",
            "capability_issued": False,
            "write_authorized": False,
            "mutation_allowed": False,
            "persistence_performed": False,
            "cas_attempted": False,
            "fence_issued": False,
            "resume_allowed": False,
            "receipt_emitted": False,
            "receipt_committed": False,
            "commit_authorized": False,
            "floor_advanced": False,
        }):
            self._reseal(case)
            result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.S25R_REJECTED)
        self.assertEqual(result["status"], "TEST_BLOCKED")

    def test_resealed_outer_digest_does_not_authorize_missing_s25r_context(self) -> None:
        case = self._base()
        case["s25r_case"]["expected"]["subject_digest"] = "2" * 64
        self._reseal(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertNotEqual(result["classification"], s25t.PROVENANCE_WITNESS_RECONCILED)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        raw = json.dumps(self._base(), sort_keys=True, separators=(",", ":"))
        raw = raw[:-1] + ',"input_digest":"' + ("0" * 64) + '","input_digest":"' + ("1" * 64) + '"}'

        result = s25t.evaluate_receipt_provenance(raw)

        self.assertEqual(result["classification"], "INPUT_INVALID")

    def test_float_and_bool_as_counter_are_rejected(self) -> None:
        case = self._base()
        case["expected"]["epoch"] = True
        self._reseal(case)

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_REJECTED)
        self.assertEqual(result["reason"], "EXPECTED_COUNTER_INVALID")

    def test_uri_and_absolute_path_values_are_not_admissible(self) -> None:
        for unsafe in ("/tmp/receipt", "https://example.invalid/receipt", "file:///tmp/receipt", r"\\server\share\receipt"):
            with self.subTest(unsafe=unsafe):
                case = self._base()
                case["expected"]["observer_id"] = unsafe
                case["input_digest"] = s25t.input_digest(case)
                result = s25t.evaluate_receipt_provenance(case)
                self.assertEqual(result["classification"], "INPUT_INVALID")

    def test_recursive_mapping_is_rejected_without_recursion_error(self) -> None:
        case = self._base()
        recursive: dict[str, object] = {}
        recursive["self"] = recursive
        case["s25r_case"] = recursive

        result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], "INPUT_INVALID")

    def test_no_file_or_network_discovery_is_needed(self) -> None:
        case = self._base()
        with patch("builtins.open", side_effect=AssertionError("I/O is forbidden")), patch("socket.socket", side_effect=AssertionError("network is forbidden")):
            result = s25t.evaluate_receipt_provenance(case)

        self.assertEqual(result["classification"], s25t.PROVENANCE_WITNESS_RECONCILED)


def build_complete_s25t_case() -> dict[str, object]:
    """Public test-fixture boundary for downstream pure-gate tests."""

    return W5S25TReceiptProvenanceTests._base()


def reseal_s25t_observation(case: dict[str, object], position: int) -> None:
    """Rebuild one fixture observation without exposing support internals."""

    W5S25TReceiptProvenanceTests._reseal_observation(case, position)


if __name__ == "__main__":
    unittest.main()
