"""Adversarial W5-S4 Prime↔HRR binding tests."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROL_ROOT = REPO_ROOT / "modules" / "mother-control-plane"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(CONTROL_ROOT))

from modules.w4_small_loop_s0 import canonical_hash  # noqa: E402
from control_plane import FixedClock  # noqa: E402
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    PrimeBindingError,
    capture_consistent_control_snapshot,
    capture_stable_control_snapshot,
    control_from_runtime_snapshot,
    evaluate_prime_binding,
    evaluate_prime_binding_from_control_plane,
    fresh_hrr_input_from_control_plane,
    verify_prime_binding,
)
from test_w5_s3_hold_reconcile_resume import (  # noqa: E402
    REPO_ROOT as S3_REPO_ROOT,
    _blocked_fixture,
    _input,
    _verified_fixture,
)


class _StableReader:
    def __init__(self, snapshot: dict, *, change_on_second: bool = False, capture: dict | None = None) -> None:
        self.snapshot_value = copy.deepcopy(snapshot)
        self.change_on_second = change_on_second
        self.capture_value = copy.deepcopy(capture)
        self.snapshot_calls = 0
        self.integrity_calls = 0
        self.capture_calls = 0

    def snapshot(self, _run_id: str) -> dict:
        self.snapshot_calls += 1
        result = copy.deepcopy(self.snapshot_value)
        if self.change_on_second and self.snapshot_calls == 2:
            result["run"]["state"] = "RUNNING"
        return result

    def integrity_check(self) -> str:
        self.integrity_calls += 1
        return "ok"

    def capture_read_only_snapshot(self, _run_id: str) -> dict:
        self.capture_calls += 1
        if self.capture_value is None:
            raise AssertionError("secure capture not configured")
        return copy.deepcopy(self.capture_value)


def _prime_state(control: dict, *, gate: str = "continue", identity: dict | None = None) -> dict:
    w5_identity = copy.deepcopy(identity or {key: control[key] for key in ("run_id", "card_id", "attempt_id", "dispatch_id")})
    active_task_id = "task-w5-s4-001"
    return {
        "schema_version": "prime-resume-state-v1",
        "binding_id": canonical_hash({
            "prime_run_id": "prime-run-2026-11-15-001",
            "active_task_id": active_task_id,
            "w5_identity": w5_identity,
        }),
        "prime_run_id": "prime-run-2026-11-15-001",
        "active_task_id": active_task_id,
        "active_task_sha256": "5" * 64,
        "status": "in_progress",
        "resume_gate": gate,
        "resume_gate_reason": "",
        "stop_reason": "",
        "hold_reason": "" if gate == "continue" else "awaiting-evidence",
        "next_action": {"action": "continue" if gate == "continue" else "hold", "task_id": active_task_id},
        "resume_packet_sha256": "1" * 64,
        "session_sha256": "2" * 64,
        "tasks_sha256": "3" * 64,
        "queue_sha256": "4" * 64,
        "policy_sha256": "6" * 64,
        "writer_lease_sha256": "7" * 64,
        "w5_identity": w5_identity,
    }


def _capture_for(cp, run_id: str, runtime: dict) -> dict:
    """Use real anchor/marker/clock metadata with the fixture's W5 runtime."""
    capture = capture_consistent_control_snapshot(cp, run_id)
    capture["runtime"] = copy.deepcopy(runtime)
    capture["runtime_sha256"] = canonical_hash(runtime)
    return capture


def _bind_clock(hrr_input: dict, capture: dict) -> dict:
    hrr_input["now_epoch"] = capture["clock_after_epoch"]
    return hrr_input


class W5S4PrimeBindingTests(unittest.TestCase):
    def tearDown(self) -> None:
        for helper in getattr(self, "_helpers", []):
            helper.doCleanups()

    def _keep(self, fixture):
        self._helpers = getattr(self, "_helpers", [])
        self._helpers.append(fixture[0])
        return fixture[1:]

    def test_verified_binds_fresh_resume_and_stays_actionless(self) -> None:
        bundle, authority, data = self._keep(_verified_fixture())
        control = data["control"]
        hrr_input = _input(
            bundle,
            authority,
            data["observation"],
            control,
            control["lease"]["expires_at"] - 1,
        )
        capture = _capture_for(data["cp"], control["run"]["run_id"], bundle["runtime"])
        _bind_clock(hrr_input, capture)
        prime = _prime_state(control["run"] | control["card"] | control["attempt"] | control["dispatch"])
        binding = evaluate_prime_binding(prime, hrr_input, control_capture=capture, source_root=REPO_ROOT)
        self.assertEqual((binding["binding_status"], binding["reason"]), ("BOUND_READ_ONLY", "BOUND_RESUME"))
        self.assertTrue(binding["resume_allowed"])
        self.assertEqual(binding["decision"], "RESUME")
        self.assertEqual(binding["hrr"]["input_sha256"], canonical_hash(hrr_input))
        self.assertEqual(binding["hrr"]["decision_sha256"], canonical_hash({
            "schema_version": "w5-hrr-decision-v1",
            "decision": "RESUME",
            "reason": "C4_VERIFIED",
            "identity": binding["w5"]["identity"],
            "state": binding["w5"]["state"],
            "fencing_epoch": binding["w5"]["fencing_epoch"],
            "source_attestation_hash": binding["w5"]["source_attestation_hash"],
            "control_snapshot_sha256": binding["w5"]["control_snapshot_sha256"],
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
        }))
        self.assertTrue(all(value is False for value in binding["execution"].values()))
        self.assertEqual(verify_prime_binding(binding), binding)
        self.assertEqual(
            verify_prime_binding(
                binding,
                prime_state=prime,
                hrr_input=hrr_input,
                control_capture=capture,
                source_root=REPO_ROOT,
            ),
            binding,
        )
        self.assertEqual(data["cp"].integrity_check(), "ok")

    def test_blocked_and_reconcile_are_bound_but_never_actions(self) -> None:
        bundle, authority, data = self._keep(_blocked_fixture())
        control = data["control"]
        data["cp"].clock = FixedClock(
            now_value="2026-01-01T00:00:59Z",
            epoch_value=control["dispatch"]["ack_deadline_at"] - 1,
        )
        hrr_input = _input(
            bundle,
            authority,
            data["observation"],
            control,
            control["lease"]["expires_at"] - 1,
        )
        capture = _capture_for(data["cp"], control["run"]["run_id"], bundle["runtime"])
        _bind_clock(hrr_input, capture)
        prime = _prime_state(control["run"] | control["card"] | control["attempt"] | control["dispatch"], gate="hold")
        before_spawn_requests = data["cp"].executor.spawn_request_count(control["dispatch"]["dispatch_id"])
        held = evaluate_prime_binding(prime, hrr_input, control_capture=capture, source_root=REPO_ROOT)
        self.assertEqual((held["binding_status"], held["reason"], held["decision"]), ("BOUND_READ_ONLY", "HRR_HOLD", "HOLD"))
        self.assertFalse(held["resume_allowed"])
        candidate = {
            "pid": 42001,
            "process_starttime": "candidate-start",
            "boot_id": "candidate-boot",
            "pidfd_ref": "candidate-pidfd",
            "cgroup_ref": "candidate-cgroup",
            "run_token": control["dispatch"]["run_token"],
            "fencing_epoch": control["dispatch"]["fencing_epoch"],
            "command_hash": control["dispatch"]["command_hash"],
        }
        reconcile_input = _input(
            bundle,
            authority,
            data["observation"],
            control,
            control["dispatch"]["ack_deadline_at"] - 1,
            candidate=candidate,
            observed=control["dispatch"]["ack_deadline_at"] - 2,
        )
        _bind_clock(reconcile_input, capture)
        reconciled = evaluate_prime_binding(prime, reconcile_input, control_capture=capture, source_root=REPO_ROOT)
        self.assertEqual(
            (reconciled["binding_status"], reconciled["reason"], reconciled["decision"]),
            ("BOUND_READ_ONLY", "RECONCILE_ACTION_REQUIRED", "RECONCILE"),
        )
        self.assertFalse(reconciled["resume_allowed"])
        self.assertTrue(all(value is False for value in reconciled["execution"].values()))
        self.assertEqual(
            data["cp"].executor.spawn_request_count(control["dispatch"]["dispatch_id"]),
            before_spawn_requests,
        )

    def test_prime_identity_and_gate_drift_fail_closed(self) -> None:
        bundle, authority, data = self._keep(_verified_fixture())
        control = data["control"]
        hrr_input = _input(
            bundle,
            authority,
            data["observation"],
            control,
            control["lease"]["expires_at"] - 1,
        )
        capture = _capture_for(data["cp"], control["run"]["run_id"], bundle["runtime"])
        _bind_clock(hrr_input, capture)
        drifted_identity = _prime_state(control["run"] | control["card"] | control["attempt"] | control["dispatch"], identity={
            "run_id": "foreign-run",
            "card_id": control["card"]["card_id"],
            "attempt_id": control["attempt"]["attempt_id"],
            "dispatch_id": control["dispatch"]["dispatch_id"],
        })
        self.assertEqual(
            evaluate_prime_binding(drifted_identity, hrr_input, control_capture=capture, source_root=REPO_ROOT)["reason"],
            "PRIME_IDENTITY_DRIFT",
        )
        closed = _prime_state(control["run"] | control["card"] | control["attempt"] | control["dispatch"], gate="hold")
        self.assertEqual(
            evaluate_prime_binding(closed, hrr_input, control_capture=capture, source_root=REPO_ROOT)["reason"],
            "PRIME_GATE_CLOSED",
        )

        blocked_bundle, blocked_authority, blocked_data = self._keep(_blocked_fixture())
        blocked_control = blocked_data["control"]
        blocked_input = _input(
            blocked_bundle,
            blocked_authority,
            blocked_data["observation"],
            blocked_control,
            blocked_control["lease"]["expires_at"] - 1,
        )
        blocked_capture = _capture_for(blocked_data["cp"], blocked_control["run"]["run_id"], blocked_bundle["runtime"])
        _bind_clock(blocked_input, blocked_capture)
        open_for_hold = _prime_state(
            blocked_control["run"] | blocked_control["card"] | blocked_control["attempt"] | blocked_control["dispatch"],
            gate="continue",
        )
        self.assertEqual(
            evaluate_prime_binding(open_for_hold, blocked_input, control_capture=blocked_capture, source_root=REPO_ROOT)["reason"],
            "PRIME_GATE_DRIFT",
        )

    def test_resume_requires_complete_prime_state_and_coherent_capture(self) -> None:
        bundle, authority, data = self._keep(_verified_fixture())
        control = data["control"]
        capture = _capture_for(data["cp"], control["run"]["run_id"], bundle["runtime"])
        hrr_input = _bind_clock(
            _input(
                bundle,
                authority,
                data["observation"],
                control,
                control["lease"]["expires_at"] - 1,
            ),
            capture,
        )
        prime = _prime_state(control["run"] | control["card"] | control["attempt"] | control["dispatch"])
        without_capture = evaluate_prime_binding(prime, hrr_input, source_root=REPO_ROOT)
        self.assertEqual((without_capture["binding_status"], without_capture["reason"]), ("HOLD", "CONTROL_SNAPSHOT_INVALID"))

        paused = copy.deepcopy(prime)
        paused["status"] = "paused"
        paused_result = evaluate_prime_binding(paused, hrr_input, control_capture=capture, source_root=REPO_ROOT)
        self.assertEqual(paused_result["reason"], "PRIME_GATE_DRIFT")

        wrong_action = copy.deepcopy(prime)
        wrong_action["next_action"] = {"action": "continue", "task_id": "other-task"}
        wrong_action_result = evaluate_prime_binding(wrong_action, hrr_input, control_capture=capture, source_root=REPO_ROOT)
        self.assertEqual(wrong_action_result["reason"], "INVALID_PRIME_STATE")

        with self.assertRaises(PrimeBindingError):
            fresh_hrr_input_from_control_plane(
                _StableReader(bundle["runtime"], capture=capture),
                control["run"]["run_id"],
                now_epoch=capture["clock_after_epoch"] + 1,
                w5_bundle=bundle,
                w5_authority=authority,
                w5_observation=data["observation"],
                control_capture=capture,
            )

    def test_control_projection_and_stable_capture_are_read_only(self) -> None:
        bundle, _authority, data = self._keep(_verified_fixture())
        snapshot = bundle["runtime"]
        projected = control_from_runtime_snapshot(snapshot)
        for section in ("run", "card", "attempt", "dispatch", "lease"):
            self.assertEqual(projected[section], data["control"][section])
        reader = _StableReader(snapshot)
        captured = capture_stable_control_snapshot(reader, data["control"]["run"]["run_id"])
        self.assertEqual(captured, snapshot)
        self.assertEqual(reader.snapshot_calls, 2)
        self.assertEqual(reader.integrity_calls, 3)

    def test_unstable_capture_is_rejected_before_binding(self) -> None:
        bundle, _authority, data = self._keep(_verified_fixture())
        reader = _StableReader(bundle["runtime"], change_on_second=True)
        with self.assertRaises(PrimeBindingError):
            capture_stable_control_snapshot(reader, data["control"]["run"]["run_id"])

    def test_control_plane_adapter_recomputes_from_fresh_snapshot(self) -> None:
        bundle, authority, data = self._keep(_verified_fixture())
        control = data["control"]
        capture = _capture_for(data["cp"], control["run"]["run_id"], bundle["runtime"])
        reader = _StableReader(bundle["runtime"], capture=capture)
        prime = _prime_state(control["run"] | control["card"] | control["attempt"] | control["dispatch"])
        binding = evaluate_prime_binding_from_control_plane(
            reader,
            control["run"]["run_id"],
            prime,
            now_epoch=capture["clock_after_epoch"],
            w5_bundle=bundle,
            w5_authority=authority,
            w5_observation=data["observation"],
            source_root=S3_REPO_ROOT,
        )
        self.assertEqual((binding["binding_status"], binding["reason"]), ("BOUND_READ_ONLY", "BOUND_RESUME"))
        self.assertEqual(reader.capture_calls, 1)
        self.assertEqual(data["cp"].integrity_check(), "ok")

    def test_forged_or_stale_binding_cannot_verify_with_fresh_inputs(self) -> None:
        bundle, authority, data = self._keep(_verified_fixture())
        control = data["control"]
        hrr_input = _input(
            bundle,
            authority,
            data["observation"],
            control,
            control["lease"]["expires_at"] - 1,
        )
        capture = _capture_for(data["cp"], control["run"]["run_id"], bundle["runtime"])
        _bind_clock(hrr_input, capture)
        prime = _prime_state(control["run"] | control["card"] | control["attempt"] | control["dispatch"])
        binding = evaluate_prime_binding(prime, hrr_input, control_capture=capture, source_root=REPO_ROOT)
        forged = copy.deepcopy(binding)
        forged["resume_allowed"] = False
        with self.assertRaises(PrimeBindingError):
            verify_prime_binding(
                forged,
                prime_state=prime,
                hrr_input=hrr_input,
                control_capture=capture,
                source_root=REPO_ROOT,
            )
        changed_input = copy.deepcopy(hrr_input)
        changed_input["now_epoch"] += 1
        with self.assertRaises(PrimeBindingError):
            verify_prime_binding(
                binding,
                prime_state=prime,
                hrr_input=changed_input,
                control_capture=capture,
                source_root=REPO_ROOT,
            )

    def test_binding_surface_has_no_mutation_or_transport_calls(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/prime_binding.py").read_text(encoding="utf-8")
        for forbidden in (
            "subprocess",
            "socket",
            "urllib",
            "Popen(",
            "os.system(",
            "os.kill(",
            "reconcile_dispatch(",
            "reclaim_lease(",
            "write_text(",
            "write_bytes(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
