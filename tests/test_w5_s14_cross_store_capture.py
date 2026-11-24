"""Adversarial tests for the W5-S14 read-only capture producer."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    CrossStoreCaptureError,
    CrossStoreSnapshotError,
    build_cross_store_snapshot_envelope,
    capture_cross_store_snapshot,
    evaluate_cross_store_capture,
)
from test_w5_s13_cross_store_snapshot import W5S13CrossStoreSnapshotTests  # noqa: E402


class _Clock:
    def __init__(self, values: list[int]) -> None:
        self.values = list(values)
        self.calls = 0

    def sample(self) -> int:
        self.calls += 1
        if not self.values:
            raise AssertionError("clock exhausted")
        return self.values.pop(0)


class _Reader:
    def __init__(self, record: dict, *, adapter_id: str, mutate_second=None, fail: bool = False) -> None:
        self.record = copy.deepcopy(record)
        self.adapter_id = adapter_id
        self.mutate_second = mutate_second
        self.fail = fail
        self.calls = 0

    def read_snapshot(self) -> dict:
        self.calls += 1
        if self.fail:
            raise RuntimeError("source unavailable")
        result = copy.deepcopy(self.record)
        if self.calls == 2 and self.mutate_second is not None:
            self.mutate_second(result)
        return result


class _Cohort:
    def __init__(self, record: dict, *, mutate_second=None, fail: bool = False) -> None:
        self.record = copy.deepcopy(record)
        self.mutate_second = mutate_second
        self.fail = fail
        self.calls = 0

    def read_cohort(self) -> dict:
        self.calls += 1
        if self.fail:
            raise RuntimeError("cohort unavailable")
        result = copy.deepcopy(self.record)
        if self.calls == 2 and self.mutate_second is not None:
            self.mutate_second(result)
        return result


class _Hostile:
    def __deepcopy__(self, memo):
        raise RuntimeError("hostile deepcopy")


class _HostileCohort:
    def read_cohort(self) -> dict:
        return {
            "fence": _Hostile(),
            "lease": {},
            "generation": {},
        }


class W5S14CrossStoreCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        helper = W5S13CrossStoreSnapshotTests()
        fixture = helper.s12_fixture()
        self.envelope = helper.envelope(fixture)
        self.readers = {
            participant_id: _Reader(
                {
                    "source_id": self.envelope["observations"][participant_id]["source_id"],
                    "snapshot_id": self.envelope["observations"][participant_id]["snapshot_id"],
                    "source_identity_sha256": self.envelope["observations"][participant_id]["source_identity_sha256"],
                    "source_cursor": copy.deepcopy(self.envelope["observations"][participant_id]["source_cursor"]),
                    "projection": copy.deepcopy(self.envelope["observations"][participant_id]["observed"]),
                    "read_only": True,
                },
                adapter_id=f"adapter-{participant_id}",
            )
            for participant_id in sorted(self.envelope["observations"])
        }
        self.cohort = _Cohort(
            {
                "fence": copy.deepcopy(self.envelope["fence"]),
                "lease": copy.deepcopy(self.envelope["s12_input"]["lease"]),
                "generation": {
                    participant_id: {
                        "generation": self.envelope["observations"][participant_id]["source_cursor"]["generation"],
                        "generation_id": self.envelope["observations"][participant_id]["source_cursor"]["generation_id"],
                    }
                    for participant_id in sorted(self.envelope["observations"])
                },
            }
        )

    def kwargs(self, *, readers=None, clock=None, cohort=None) -> dict:
        capture = self.envelope["capture"]
        return {
            "transaction_id": self.envelope["transaction_id"],
            "observer": copy.deepcopy(self.envelope["observer"]),
            "source_identities": copy.deepcopy(self.envelope["sources"]),
            "readers": readers or self.readers,
            "source_capabilities": {
                participant_id: {
                    "adapter_id": f"adapter-{participant_id}",
                    "allowed_root_or_binding": f"binding-{participant_id}",
                    "read_only_capability": True,
                    "write_capability": False,
                    "lock_capability": False,
                    "network_capability": False,
                    "process_capability": False,
                }
                for participant_id in sorted(self.envelope["sources"])
            },
            "capture_context": {key: copy.deepcopy(capture[key]) for key in (
                "capture_id",
                "sequence_domain",
                "sequence_no",
                "barrier_id",
                "clock_domain_id",
                "clock_sample_id",
            )},
            "clock": clock or _Clock([100, 100]),
            "cohort": cohort or self.cohort,
            "expected_projection_manifest": copy.deepcopy(self.envelope["expected_projection_manifest"]),
            "fence": copy.deepcopy(self.envelope["fence"]),
            "replay": copy.deepcopy(self.envelope["replay"]),
            "s12_input": copy.deepcopy(self.envelope["s12_input"]),
        }

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["authoritative_decision"])
        self.assertFalse(result["external_action"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_two_pass_capture_builds_valid_s13_envelope(self) -> None:
        kwargs = self.kwargs()
        captured = capture_cross_store_snapshot(**kwargs)
        self.assertEqual(captured, self.envelope)
        self.assertEqual(kwargs["clock"].calls, 2)
        self.assertEqual(kwargs["cohort"].calls, 2)
        self.assertTrue(all(reader.calls == 2 for reader in self.readers.values()))

    def test_evaluator_returns_actionless_captured_read_only(self) -> None:
        result = evaluate_cross_store_capture(**self.kwargs())
        self.assertEqual(result["status"], "CAPTURED_READ_ONLY")
        self.assertEqual(result["reason"], "S13_ENVELOPE_VALIDATED")
        self.assertEqual(result["envelope"]["schema_version"], "prime-cross-store-observation-v1")
        self.assert_actionless(result)

    def test_second_pass_projection_drift_is_recovery_required(self) -> None:
        readers = dict(self.readers)

        def mutate(record: dict) -> None:
            record["projection"]["observed"]["state"]["phase"] = "drift"

        readers["prime_queue"] = _Reader(self.readers["prime_queue"].record, adapter_id="adapter-prime_queue", mutate_second=mutate)
        result = evaluate_cross_store_capture(**self.kwargs(readers=readers))
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "CAPTURE_TOCTOU_DETECTED")
        self.assert_actionless(result)

    def test_source_identity_drift_is_recovery_required(self) -> None:
        readers = dict(self.readers)

        def mutate(record: dict) -> None:
            record["source_identity_sha256"] = "0" * 64

        readers["prime_ledger"] = _Reader(self.readers["prime_ledger"].record, adapter_id="adapter-prime_ledger", mutate_second=mutate)
        result = evaluate_cross_store_capture(**self.kwargs(readers=readers))
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "CAPTURE_SOURCE_DRIFT")
        self.assert_actionless(result)

    def test_clock_drift_and_unsafe_reader_fail_closed(self) -> None:
        result = evaluate_cross_store_capture(**self.kwargs(clock=_Clock([100, 99])))
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "CAPTURE_CLOCK_DRIFT")
        self.assert_actionless(result)

        readers = dict(self.readers)
        unsafe = copy.deepcopy(self.readers["control_plane"].record)
        unsafe["read_only"] = False
        readers["control_plane"] = _Reader(unsafe, adapter_id="adapter-control_plane")
        result = evaluate_cross_store_capture(**self.kwargs(readers=readers))
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "CAPTURE_UNSAFE_SOURCE")
        self.assert_actionless(result)

        wrong_adapter = dict(self.readers)
        wrong_adapter["control_plane"] = _Reader(
            self.readers["control_plane"].record, adapter_id="unapproved-control-plane-adapter"
        )
        result = evaluate_cross_store_capture(**self.kwargs(readers=wrong_adapter))
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "CAPTURE_SOURCE_UNOBSERVABLE")
        self.assert_actionless(result)

        unsafe_capabilities = self.kwargs()
        unsafe_capabilities["source_capabilities"]["control_plane"]["write_capability"] = True
        result = evaluate_cross_store_capture(**unsafe_capabilities)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "CAPTURE_UNSAFE_SOURCE")
        self.assert_actionless(result)

    def test_fence_lease_and_generation_cohort_drift_require_recovery(self) -> None:
        def mutate_fence(record: dict) -> None:
            record["fence"]["worker_id"] = "foreign-worker"

        result = evaluate_cross_store_capture(**self.kwargs(cohort=_Cohort(self.cohort.record, mutate_second=mutate_fence)))
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "CAPTURE_FENCE_DRIFT")
        self.assert_actionless(result)

        def mutate_lease(record: dict) -> None:
            record["lease"]["observed_at"] += 1

        result = evaluate_cross_store_capture(**self.kwargs(cohort=_Cohort(self.cohort.record, mutate_second=mutate_lease)))
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "CAPTURE_LEASE_DRIFT")
        self.assert_actionless(result)

        def mutate_generation(record: dict) -> None:
            record["generation"]["prime_queue"]["generation"] += 1

        result = evaluate_cross_store_capture(
            **self.kwargs(cohort=_Cohort(self.cohort.record, mutate_second=mutate_generation))
        )
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "CAPTURE_GENERATION_DRIFT")
        self.assert_actionless(result)

    def test_unavailable_reader_missing_reader_and_s13_rejection_hold_or_recovery(self) -> None:
        readers = dict(self.readers)
        readers["receipt_projection"] = _Reader(self.readers["receipt_projection"].record, adapter_id="adapter-receipt_projection", fail=True)
        result = evaluate_cross_store_capture(**self.kwargs(readers=readers))
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "CAPTURE_SOURCE_UNOBSERVABLE")
        self.assert_actionless(result)

        result = evaluate_cross_store_capture(**self.kwargs(cohort=_Cohort(self.cohort.record, fail=True)))
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "CAPTURE_SOURCE_UNOBSERVABLE")
        self.assert_actionless(result)

        incomplete = dict(self.readers)
        del incomplete["prime_queue"]
        result = evaluate_cross_store_capture(**self.kwargs(readers=incomplete))
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "CAPTURE_SCHEMA_INVALID")
        self.assert_actionless(result)

        forged = self.kwargs()
        forged["fence"]["worker_id"] = "foreign-worker"
        forged["cohort"] = _Cohort(
            {
                **self.cohort.record,
                "fence": copy.deepcopy(forged["fence"]),
            }
        )
        with self.assertRaises(CrossStoreCaptureError) as caught:
            capture_cross_store_snapshot(**forged)
        self.assertEqual(caught.exception.code, "CAPTURE_S13_REJECTED")
        self.assertEqual(caught.exception.source_code, "SNAPSHOT_FENCE_DRIFT")

        forged_for_evaluator = self.kwargs()
        forged_for_evaluator["fence"]["worker_id"] = "foreign-worker"
        forged_for_evaluator["cohort"] = _Cohort(
            {
                **self.cohort.record,
                "fence": copy.deepcopy(forged_for_evaluator["fence"]),
            }
        )
        result = evaluate_cross_store_capture(**forged_for_evaluator)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "SNAPSHOT_FENCE_DRIFT")
        self.assert_actionless(result)

        result = evaluate_cross_store_capture(**self.kwargs(cohort=_HostileCohort()))
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "CAPTURE_SCHEMA_INVALID")
        self.assert_actionless(result)

    def test_output_isolated_and_module_has_no_live_io_imports(self) -> None:
        kwargs = self.kwargs()
        captured = capture_cross_store_snapshot(**kwargs)
        kwargs["source_identities"]["control_plane"]["source_id"] = "mutated"
        kwargs["s12_input"]["hook_trace"].clear()
        self.assertNotEqual(captured["sources"]["control_plane"]["source_id"], "mutated")
        self.assertTrue(captured["s12_input"]["hook_trace"])

        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/cross_store_capture.py").read_text()
        for forbidden in ("import sqlite3", "import subprocess", "import socket", "import requests", "import urllib", "open("):
            self.assertNotIn(forbidden, source)

    def test_public_s13_builder_rejects_unstable_second_sample(self) -> None:
        kwargs = self.kwargs()
        source_samples = {
            participant_id: copy.deepcopy(reader.record)
            for participant_id, reader in self.readers.items()
        }
        source_samples_after = copy.deepcopy(source_samples)
        source_samples_after["prime_queue"]["projection"]["observed"]["state"]["phase"] = "drift"
        context = copy.deepcopy(kwargs["capture_context"])
        context.update({"clock_before": 100, "clock_after": 100})
        with self.assertRaises(CrossStoreSnapshotError) as caught:
            build_cross_store_snapshot_envelope(
                transaction_id=kwargs["transaction_id"],
                observer=kwargs["observer"],
                sources=kwargs["source_identities"],
                source_samples=source_samples,
                source_samples_after=source_samples_after,
                capture_context=context,
                expected_projection_manifest=kwargs["expected_projection_manifest"],
                fence=kwargs["fence"],
                replay=kwargs["replay"],
                s12_input=kwargs["s12_input"],
            )
        self.assertEqual(caught.exception.code, "SNAPSHOT_TOCTOU_DETECTED")


if __name__ == "__main__":
    unittest.main()
