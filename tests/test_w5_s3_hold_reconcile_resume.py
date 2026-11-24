"""Adversarial W5-S3 decision-gate tests."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash  # noqa: E402
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    build_mother_observation,
    evaluate_hrr,
    source_attestation_template,
    verify_blocked_ack_bundle_s1,
    verify_dispatch_bridge_bundle_s1,
    verify_hrr_decision,
)
from test_w5_s0_dispatch_bridge import (  # noqa: E402
    W5S0DispatchBridgeTests,
    _source_reseal,
)

# Reuse the established W5-S0 fixture builder without asking pytest to collect
# that imported TestCase a second time in this module.
W5S0DispatchBridgeTests.__test__ = False


def _epoch(timestamp: str) -> int:
    return int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).replace(tzinfo=timezone.utc).timestamp())


def _control(bundle: dict) -> dict:
    runtime = bundle["runtime"]
    run = runtime["run"]
    card = runtime["cards"][0]
    attempt = runtime["attempts"][0]
    dispatch = runtime["dispatches"][0]
    spawn_event = next(event for event in runtime["events"] if event["event_type"] == "SPAWN_REQUESTED")
    process_identity = None
    if dispatch["pid"] is not None:
        process_identity = {
            "pid": dispatch["pid"],
            "process_starttime": dispatch["process_starttime"],
            "boot_id": dispatch["boot_id"],
            "pidfd_ref": dispatch["pidfd_ref"],
            "cgroup_ref": dispatch["cgroup_ref"],
            "run_token": dispatch["run_token"],
            "fencing_epoch": dispatch["fencing_epoch"],
            "command_hash": dispatch["command_hash"],
        }
    return {
        "run": {
            "run_id": run["run_id"],
            "state": run["state"],
            "active_dispatch_id": run["active_dispatch_id"],
            "queue_hash": run["queue_hash"],
            "policy_hash": run["policy_hash"],
            "fencing_epoch": run["fencing_epoch"],
            "lease_token": run["lease_token"],
        },
        "card": {
            "card_id": card["card_id"],
            "run_id": card["run_id"],
            "state": card["state"],
            "active_attempt_id": card["active_attempt_id"],
            "acceptance_txn_id": card["acceptance_txn_id"],
            "next_card_intent_id": card["next_card_intent_id"],
            "card_hash": card["card_hash"],
            "source_queue_hash": card["source_queue_hash"],
        },
        "attempt": {
            "attempt_id": attempt["attempt_id"],
            "attempt_no": attempt["attempt_no"],
            "retry_of": attempt["retry_of"],
            "run_id": attempt["run_id"],
            "card_id": attempt["card_id"],
            "state": attempt["state"],
            "dispatch_id": attempt["dispatch_id"],
            "worker_id": attempt["worker_id"],
            "command_hash": attempt["command_hash"],
            "input_snapshot_hash": attempt["input_snapshot_hash"],
            "context_pack_hash": attempt["context_pack_hash"],
            "deadline_policy_hash": attempt["deadline_policy_hash"],
        },
        "dispatch": {
            "dispatch_id": dispatch["dispatch_id"],
            "run_id": dispatch["run_id"],
            "attempt_id": dispatch["attempt_id"],
            "state": dispatch["state"],
            "run_token": dispatch["run_token"],
            "owner_id": dispatch["owner_id"],
            "fencing_epoch": dispatch["fencing_epoch"],
            "command_hash": dispatch["command_hash"],
            "ack_deadline_at": dispatch["ack_deadline_at"],
            "lease_expires_at": dispatch["lease_expires_at"],
            "spawn_requested_at_epoch": _epoch(spawn_event["created_at"]),
            "spawn_attempt_no": dispatch["spawn_attempt_no"],
            "max_spawn_attempts": dispatch["max_spawn_attempts"],
            "process_identity": process_identity,
        },
        "lease": {
            "owner_id": run["lease_owner_id"],
            "token": run["lease_token"],
            "fencing_epoch": run["fencing_epoch"],
            "expires_at": run["lease_expires_at"],
        },
        "runtime_hash": canonical_hash(runtime),
    }


def _verified_fixture() -> tuple[dict, dict, dict, dict]:
    W5S0DispatchBridgeTests.setUpClass()
    helper = W5S0DispatchBridgeTests()
    cp, bundle, authority = helper.bundle()
    bundle["schema"] = "w5-dispatch-bridge-bundle.v2-source-attested"
    bundle["source_attestation"] = source_attestation_template()
    authority = _source_reseal(authority, bundle["source_attestation"])
    result = verify_dispatch_bridge_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT)
    observation = build_mother_observation(result)
    return helper, bundle, authority, {
        "result": result,
        "observation": observation,
        "control": _control(bundle),
        "cp": cp,
    }


def _blocked_fixture() -> tuple[dict, dict, dict, dict]:
    W5S0DispatchBridgeTests.setUpClass()
    helper = W5S0DispatchBridgeTests()
    cp, bundle, authority = helper.blocked_bundle()
    result = verify_blocked_ack_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT)
    observation = build_mother_observation(result)
    return helper, bundle, authority, {
        "result": result,
        "observation": observation,
        "control": _control(bundle),
        "cp": cp,
    }


def _input(bundle: dict, authority: dict, observation: dict, control: dict, now: int, *, candidate=None, observed=None, live_runtime=None) -> dict:
    return {
        "schema_version": "w5-hrr-input-v1",
        "now_epoch": now,
        "w5_bundle": bundle,
        "w5_authority": authority,
        "w5_observation": observation,
        "live_runtime": copy.deepcopy(bundle.get("runtime", {})) if live_runtime is None else live_runtime,
        "control": control,
        "candidate_identity": candidate,
        "candidate_observed_epoch": observed,
    }


class W5S3HoldReconcileResumeTests(unittest.TestCase):
    def tearDown(self) -> None:
        # The reused W5 fixture helper owns temporary directories and SQLite
        # handles through its unittest cleanup stack.
        for helper in getattr(self, "_helpers", []):
            helper.doCleanups()

    def _keep(self, fixture):
        self._helpers = getattr(self, "_helpers", [])
        self._helpers.append(fixture[0])
        return fixture[1:]

    def test_verified_is_resume_decision_only_and_idempotent(self) -> None:
        bundle, authority, data = self._keep(_verified_fixture())
        control = data["control"]
        item = _input(
            bundle,
            authority,
            data["observation"],
            control,
            control["lease"]["expires_at"] - 1,
        )
        before_input = json.dumps(item, sort_keys=True, separators=(",", ":"))
        before_snapshot = data["cp"].snapshot(control["run"]["run_id"])
        before_spawn_requests = data["cp"].executor.spawn_request_count(control["dispatch"]["dispatch_id"])
        first = evaluate_hrr(item, source_root=REPO_ROOT)
        second = evaluate_hrr(copy.deepcopy(item), source_root=REPO_ROOT)
        after_snapshot = data["cp"].snapshot(control["run"]["run_id"])
        after_spawn_requests = data["cp"].executor.spawn_request_count(control["dispatch"]["dispatch_id"])
        self.assertEqual(first, second)
        self.assertEqual(before_input, json.dumps(item, sort_keys=True, separators=(",", ":")))
        self.assertEqual(before_snapshot, after_snapshot)
        self.assertEqual(before_spawn_requests, after_spawn_requests)
        self.assertEqual(data["cp"].integrity_check(), "ok")
        self.assertEqual(first["decision"], "RESUME")
        self.assertEqual(first["reason"], "C4_VERIFIED")
        self.assertEqual(first["identity"]["dispatch_id"], control["dispatch"]["dispatch_id"])
        self.assertTrue(all(value is False for value in first["execution"].values()))
        self.assertEqual(verify_hrr_decision(first), first)
        self.assertEqual(
            verify_hrr_decision(first, input_value=item, source_root=REPO_ROOT),
            first,
        )

    def test_blocked_holds_before_deadline_and_stale_after_deadline(self) -> None:
        bundle, authority, data = self._keep(_blocked_fixture())
        control = data["control"]
        before = evaluate_hrr(
            _input(
                bundle,
                authority,
                data["observation"],
                control,
                control["dispatch"]["ack_deadline_at"] - 1,
            ),
            source_root=REPO_ROOT,
        )
        after = evaluate_hrr(
            _input(
                bundle,
                authority,
                data["observation"],
                control,
                control["dispatch"]["ack_deadline_at"],
            ),
            source_root=REPO_ROOT,
        )
        self.assertEqual((before["decision"], before["reason"]), ("HOLD", "ACK_NOT_CONFIRMED"))
        self.assertEqual((after["decision"], after["reason"]), ("HOLD", "STALE_LEASE"))
        self.assertTrue(all(value is False for value in after["execution"].values()))

    def test_candidate_is_reconcile_only_and_foreign_or_late_identity_holds(self) -> None:
        bundle, authority, data = self._keep(_blocked_fixture())
        control = data["control"]
        dispatch = control["dispatch"]
        candidate = {
            "pid": 42001,
            "process_starttime": "candidate-start",
            "boot_id": "candidate-boot",
            "pidfd_ref": "candidate-pidfd",
            "cgroup_ref": "candidate-cgroup",
            "run_token": dispatch["run_token"],
            "fencing_epoch": dispatch["fencing_epoch"],
            "command_hash": dispatch["command_hash"],
        }
        input_value = _input(
            bundle,
            authority,
            data["observation"],
            control,
            dispatch["ack_deadline_at"] - 1,
            candidate=candidate,
            observed=dispatch["ack_deadline_at"] - 1,
        )
        self.assertEqual(
            (evaluate_hrr(input_value, source_root=REPO_ROOT)["decision"], evaluate_hrr(input_value, source_root=REPO_ROOT)["reason"]),
            ("RECONCILE", "IDENTITY_REQUIRES_RECONCILIATION"),
        )
        foreign = copy.deepcopy(input_value)
        foreign["candidate_identity"]["run_token"] = "foreign-token"
        foreign_result = evaluate_hrr(foreign, source_root=REPO_ROOT)
        self.assertEqual((foreign_result["decision"], foreign_result["reason"]), ("HOLD", "FOREIGN_IDENTITY"))
        late = copy.deepcopy(input_value)
        late["candidate_observed_epoch"] = dispatch["ack_deadline_at"]
        late_result = evaluate_hrr(late, source_root=REPO_ROOT)
        self.assertEqual((late_result["decision"], late_result["reason"]), ("HOLD", "LATE_ACK"))
        future = copy.deepcopy(input_value)
        future["candidate_observed_epoch"] = dispatch["ack_deadline_at"] - 1
        future["now_epoch"] = dispatch["ack_deadline_at"] - 2
        future_result = evaluate_hrr(future, source_root=REPO_ROOT)
        self.assertEqual((future_result["decision"], future_result["reason"]), ("HOLD", "OBSERVATION_FROM_FUTURE"))

    def test_observation_alone_and_live_snapshot_drift_cannot_resume(self) -> None:
        bundle, authority, data = self._keep(_verified_fixture())
        control = data["control"]
        observation_only = _input(
            {},
            {},
            data["observation"],
            control,
            control["lease"]["expires_at"] - 1,
        )
        result = evaluate_hrr(observation_only, source_root=REPO_ROOT)
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], "INCOMPATIBLE_SOURCE")
        drifted = copy.deepcopy(control)
        drifted["runtime_hash"] = "0" * 64
        result = evaluate_hrr(
            _input(
                bundle,
                authority,
                data["observation"],
                drifted,
                control["lease"]["expires_at"] - 1,
            ),
            source_root=REPO_ROOT,
        )
        self.assertEqual((result["decision"], result["reason"]), ("HOLD", "LIVE_RUNTIME_DRIFT"))
        live_drift = copy.deepcopy(bundle["runtime"])
        live_drift["run"]["state"] = "RUNNING"
        result = evaluate_hrr(
            _input(
                bundle,
                authority,
                data["observation"],
                control,
                control["lease"]["expires_at"] - 1,
                live_runtime=live_drift,
            ),
            source_root=REPO_ROOT,
        )
        self.assertEqual((result["decision"], result["reason"]), ("HOLD", "LIVE_RUNTIME_DRIFT"))

    def test_unknown_fields_type_confusion_and_fence_drift_fail_closed(self) -> None:
        bundle, authority, data = self._keep(_blocked_fixture())
        control = data["control"]
        item = _input(
            bundle,
            authority,
            data["observation"],
            control,
            control["lease"]["expires_at"] - 1,
        )
        unknown = copy.deepcopy(item)
        unknown["control"]["unexpected"] = True
        self.assertEqual(evaluate_hrr(unknown, source_root=REPO_ROOT)["reason"], "INVALID_INPUT")
        confused = copy.deepcopy(item)
        confused["now_epoch"] = True
        self.assertEqual(evaluate_hrr(confused, source_root=REPO_ROOT)["reason"], "INVALID_INPUT")
        fence = copy.deepcopy(item)
        fence["control"]["lease"]["fencing_epoch"] = 2
        result = evaluate_hrr(fence, source_root=REPO_ROOT)
        self.assertEqual((result["decision"], result["reason"]), ("HOLD", "FENCE_DRIFT"))
        time_drift = copy.deepcopy(item)
        time_drift["control"]["dispatch"]["spawn_requested_at_epoch"] += 1
        result = evaluate_hrr(time_drift, source_root=REPO_ROOT)
        self.assertEqual((result["decision"], result["reason"]), ("HOLD", "CONTROL_TIME_DRIFT"))

    def test_gate_source_has_no_mutation_or_transport_surface(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/s3_gate.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket", "urllib", "Popen(", "os.system(", "os.kill(", "write_text(", "write_bytes("):
            self.assertNotIn(forbidden, source)

    def test_decision_validator_rejects_forged_resume_and_reconcile(self) -> None:
        forged = {
            "schema_version": "w5-hrr-decision-v1",
            "decision": "RESUME",
            "reason": "C4_VERIFIED",
            "identity": None,
            "state": None,
            "fencing_epoch": None,
            "source_attestation_hash": None,
            "control_snapshot_sha256": None,
            "permission": "read_only",
            "external_action": False,
            "execution": {
                "mutation": False,
                "spawn": False,
                "lease_reclaim": False,
                "acceptance": False,
                "next_card": False,
                "network": False,
            },
        }
        with self.assertRaises(ValueError):
            verify_hrr_decision(forged)


if __name__ == "__main__":
    unittest.main()
