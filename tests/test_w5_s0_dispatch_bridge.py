"""W5-S0 externalized Continue-to-ack bridge tests."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROL_ROOT = REPO_ROOT / "modules" / "mother-control-plane"
FIXTURE = REPO_ROOT / "tests" / "mother_control_plane" / "fixtures" / "p0_single_card.json"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(CONTROL_ROOT))

from control_plane import ControlPlane  # noqa: E402
from modules.w4_small_loop_s0 import canonical_hash, canonical_json  # noqa: E402
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    configure_trusted_authority,
    freeze_trusted_authorities,
    source_attestation_template,
    verify_blocked_ack_bundle_s1,
    verify_dispatch_bridge_bundle,
    verify_dispatch_bridge_bundle_s1,
)
from modules.w5_dispatch_bridge_s0.mother_observation import build_mother_observation  # noqa: E402


AUTHORITY_ID = "w25-authority-fixture-001"
AUTHORITY_KEY_ID = "w4-test-key-2026"
AUTHORITY_KEY = b"w4-test-authority-key-2026"


def _reseal(authority: dict, *, key: bytes = AUTHORITY_KEY) -> dict:
    core = {name: value for name, value in authority.items() if name not in {"authority_hash", "authority_mac"}}
    authority["authority_hash"] = canonical_hash(core)
    authority["authority_mac"] = hmac.new(key, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest()
    return authority


def _source_reseal(authority: dict, source_attestation: dict) -> dict:
    core = {name: value for name, value in authority.items() if name not in {"authority_hash", "authority_mac"}}
    core["schema"] = "w5-w25-bridge-authority.v2-source-attested"
    core["source_attestation_hash"] = canonical_hash(source_attestation)
    core["bundle_schema_hash"] = canonical_hash("w5-dispatch-bridge-bundle.v2-source-attested")
    return _reseal(core)


def _blocked_runtime_reseal(bundle: dict, authority: dict) -> dict:
    authority["runtime_hash"] = canonical_hash(bundle["runtime"])
    authority["marker_commitments"] = {
        marker["operation_key"]: marker["marker_hash"]
        for marker in bundle["runtime"]["commit_markers"]
    }
    return _reseal(authority)


class W5S0DispatchBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = json.loads(FIXTURE.read_text(encoding="utf-8"))
        configure_trusted_authority(authority_id=AUTHORITY_ID, key_id=AUTHORITY_KEY_ID, key=AUTHORITY_KEY)
        freeze_trusted_authorities()

    @staticmethod
    def projection(cp: ControlPlane, run_id: str) -> dict:
        cursor = cp.conn.cursor()
        try:
            return cp._runtime_projection(cursor, run_id)
        finally:
            cursor.close()

    def bundle(self) -> tuple[ControlPlane, dict, dict]:
        root = tempfile.TemporaryDirectory(prefix="w5-s0-")
        self.addCleanup(root.cleanup)
        cp = ControlPlane(Path(root.name) / "control.sqlite")
        self.addCleanup(cp.close)
        spec = copy.deepcopy(self.spec)

        # This is a test-only adapter fixture. W5 itself never invokes these
        # private controller phases; it consumes their sealed projection.
        cp.create_project(spec)
        state_witnesses = {}
        c0_before = self.projection(cp, spec["run_id"])
        cp._ensure_run_and_card(spec)
        state_witnesses["run-admit"] = {
            "before_projection": c0_before,
            "after_projection": self.projection(cp, spec["run_id"]),
        }

        def capture_phase(operation: str, callback) -> None:
            before = self.projection(cp, spec["run_id"])
            callback()
            state_witnesses[operation] = {
                "before_projection": before,
                "after_projection": self.projection(cp, spec["run_id"]),
            }

        capture_phase("dispatch-intent", lambda: cp._dispatch_intent(spec))
        capture_phase("claim-lease", lambda: cp._claim_lease(spec))
        capture_phase("spawn-request", lambda: cp._spawn_request(spec))
        capture_phase("executor-ack", lambda: cp._executor_ack(spec))

        first = cp.snapshot(spec["run_id"])
        first["projects"] = copy.deepcopy(state_witnesses["executor-ack"]["after_projection"]["projects"])
        dispatch_id = first["dispatches"][0]["dispatch_id"]
        first_spawn_request_count = cp.executor.spawn_request_count(dispatch_id)
        first_ack_count = sum(event["event_type"] == "EXECUTOR_ACKED" for event in first["events"])
        cp._dispatch_intent(spec)
        cp._claim_lease(spec)
        cp._spawn_request(spec)
        cp._executor_ack(spec)
        runtime = cp.snapshot(spec["run_id"])
        runtime["projects"] = copy.deepcopy(state_witnesses["executor-ack"]["after_projection"]["projects"])

        run = runtime["run"]
        card = runtime["cards"][0]
        attempt = runtime["attempts"][0]
        dispatch = runtime["dispatches"][0]
        ack_event = next(event for event in runtime["events"] if event["event_type"] == "EXECUTOR_ACKED")
        c1_marker = next(marker for marker in runtime["commit_markers"] if marker["operation_key"] == "dispatch-intent")
        policy = {
            "schema": "w5-bridge-policy.v1",
            "phase": "C0-C4",
            "max_cards": 1,
            "max_dispatches": 1,
            "max_workers": 1,
            "require_ack_before_running": True,
            "allow_following_card": False,
            "process_mode": "fake-only",
            "continue_replay": "idempotent",
        }
        continue_intent = {
            "schema": "w5-continue-intent.v1",
            "continue_id": f"continue-{run['run_id']}-001",
            "ordinal": 1,
            "actor_id": "mother-session-w5-s0",
            "actor_session_id": "mother-session-w5-s0-001",
            "run_id": run["run_id"],
            "card_id": card["card_id"],
            "card_hash": card["card_hash"],
            "attempt_id": attempt["attempt_id"],
            "dispatch_id": dispatch["dispatch_id"],
            "dispatch_key": dispatch["dispatch_key"],
            "idempotency_key": dispatch["idempotency_key"],
            "expected_pre_state_hash": c1_marker["payload"]["_before_state_hash"],
            "expected_fencing_epoch": run["fencing_epoch"],
            "intent": "CONTINUE",
        }
        worker_claim = {
            "schema": "w5-worker-claim.v1",
            "claim_id": f"claim-{dispatch['dispatch_id']}-001",
            "worker_id": attempt["worker_id"],
            "worker_session_id": "worker-session-w5-s0-001",
            "worker_backend": "fake-worker",
            "run_id": run["run_id"],
            "card_id": card["card_id"],
            "attempt_id": attempt["attempt_id"],
            "dispatch_id": dispatch["dispatch_id"],
            "run_token": dispatch["run_token"],
            "fencing_epoch": dispatch["fencing_epoch"],
            "command_hash": dispatch["command_hash"],
            "claim_epoch": 1767225600,
            "claim_before_ack_event_no": ack_event["event_no"] - 1,
            "provenance": "external-authority-only",
            "status": "CLAIMED",
        }
        identity = {field: dispatch[field] for field in ("pid", "process_starttime", "boot_id", "pidfd_ref", "cgroup_ref", "run_token", "fencing_epoch", "command_hash")}
        process_ack = {
            "schema": "w5-process-ack.v1",
            "ack_id": f"ack-{dispatch['dispatch_id']}-001",
            "dispatch_id": dispatch["dispatch_id"],
            "attempt_id": attempt["attempt_id"],
            "worker_id": attempt["worker_id"],
            "ack_event_id": ack_event["event_id"],
            "ack_event_no": ack_event["event_no"],
            "ack_epoch": 1767225600,
            "ack_deadline_at": dispatch["ack_deadline_at"],
            "status": "EXECUTOR_ACKED",
            "identity": identity,
        }
        runtime_hash = canonical_hash(runtime)
        replay = {
            "schema": "w5-dispatch-replay.v1",
            "continue_id": continue_intent["continue_id"],
            "first_continue_id": continue_intent["continue_id"],
            "second_continue_id": continue_intent["continue_id"],
            "first_continue_hash": canonical_hash(continue_intent),
            "second_continue_hash": canonical_hash(continue_intent),
            "second_continue_outcome": "IDEMPOTENT_REPLAY",
            "continue_calls": 2,
            "first_runtime_hash": canonical_hash(first),
            "second_runtime_hash": runtime_hash,
            "first_event_count": len(first["events"]),
            "second_event_count": len(runtime["events"]),
            "first_attempt_count": len(first["attempts"]),
            "second_attempt_count": len(runtime["attempts"]),
            "first_dispatch_count": len(first["dispatches"]),
            "second_dispatch_count": len(runtime["dispatches"]),
            "first_spawn_request_count": first_spawn_request_count,
            "second_spawn_request_count": cp.executor.spawn_request_count(dispatch["dispatch_id"]),
            "first_ack_count": first_ack_count,
            "second_ack_count": sum(event["event_type"] == "EXECUTOR_ACKED" for event in runtime["events"]),
            "status": "IDEMPOTENT_REPLAY",
            "no_duplicate_dispatch": True,
            "no_duplicate_spawn": True,
        }
        authority_core = {
            "schema": "w5-w25-bridge-authority.v1",
            "authority_id": AUTHORITY_ID,
            "key_id": AUTHORITY_KEY_ID,
            "run_id": run["run_id"],
            "card_id": card["card_id"],
            "attempt_id": attempt["attempt_id"],
            "dispatch_id": dispatch["dispatch_id"],
            "fencing_epoch": run["fencing_epoch"],
            "policy_hash": canonical_hash(policy),
            "runtime_hash": runtime_hash,
            "state_witness_hash": canonical_hash(state_witnesses),
            "event_chain_hash": canonical_hash(runtime["events"]),
            "marker_commitments": {marker["operation_key"]: marker["marker_hash"] for marker in runtime["commit_markers"]},
            "continue_hash": canonical_hash(continue_intent),
            "worker_claim_hash": canonical_hash(worker_claim),
            "process_ack_hash": canonical_hash(process_ack),
            "replay_hash": canonical_hash(replay),
            "executor": {
                "worker_id": worker_claim["worker_id"],
                "worker_session_id": worker_claim["worker_session_id"],
                "worker_backend": worker_claim["worker_backend"],
                "controller_owner_id": run["lease_owner_id"],
                "identity_hash": canonical_hash(identity),
            },
        }
        authority = _reseal(authority_core)
        bundle = {
            "schema": "w5-dispatch-bridge-bundle.v1",
            "source": {"kind": "w25-s0", "version": "w25-s0", "canonicalization": "json-sortkeys-v1"},
            "runtime": runtime,
            "bridge_policy": policy,
            "continue_intent": continue_intent,
            "worker_claim": worker_claim,
            "process_ack": process_ack,
            "replay_evidence": replay,
            "state_witnesses": state_witnesses,
        }
        return cp, bundle, authority

    def blocked_bundle(self) -> tuple[ControlPlane, dict, dict]:
        root = tempfile.TemporaryDirectory(prefix="w5-s1-blocked-")
        self.addCleanup(root.cleanup)
        cp = ControlPlane(Path(root.name) / "control.sqlite")
        self.addCleanup(cp.close)
        spec = copy.deepcopy(self.spec)
        cp.create_project(spec)
        state_witnesses = {}
        c0_before = self.projection(cp, spec["run_id"])
        cp._ensure_run_and_card(spec)
        state_witnesses["run-admit"] = {
            "before_projection": c0_before,
            "after_projection": self.projection(cp, spec["run_id"]),
        }

        def capture_phase(operation: str, callback) -> None:
            before = self.projection(cp, spec["run_id"])
            callback()
            state_witnesses[operation] = {
                "before_projection": before,
                "after_projection": self.projection(cp, spec["run_id"]),
            }

        capture_phase("dispatch-intent", lambda: cp._dispatch_intent(spec))
        capture_phase("claim-lease", lambda: cp._claim_lease(spec))
        capture_phase("spawn-request", lambda: cp._spawn_request(spec))
        first = cp.snapshot(spec["run_id"])
        first["projects"] = copy.deepcopy(state_witnesses["spawn-request"]["after_projection"]["projects"])
        dispatch_id = first["dispatches"][0]["dispatch_id"]
        first_spawn_request_count = cp.executor.spawn_request_count(dispatch_id)
        first_ack_count = sum(event["event_type"] == "EXECUTOR_ACKED" for event in first["events"])
        cp._dispatch_intent(spec)
        cp._claim_lease(spec)
        cp._spawn_request(spec)
        runtime = cp.snapshot(spec["run_id"])
        runtime["projects"] = copy.deepcopy(state_witnesses["spawn-request"]["after_projection"]["projects"])
        run = runtime["run"]
        card = runtime["cards"][0]
        attempt = runtime["attempts"][0]
        dispatch = runtime["dispatches"][0]
        c1_marker = next(marker for marker in runtime["commit_markers"] if marker["operation_key"] == "dispatch-intent")
        policy = {
            "schema": "w5-bridge-blocked-policy.v1",
            "phase": "C0-C3",
            "max_cards": 1,
            "max_dispatches": 1,
            "max_workers": 1,
            "require_ack_before_running": True,
            "allow_following_card": False,
            "process_mode": "fake-only",
            "blocked_reason": "ACK_NOT_CONFIRMED",
        }
        continue_intent = {
            "schema": "w5-continue-intent.v1",
            "continue_id": f"continue-{run['run_id']}-blocked-001",
            "ordinal": 1,
            "actor_id": "mother-session-w5-s1",
            "actor_session_id": "mother-session-w5-s1-001",
            "run_id": run["run_id"],
            "card_id": card["card_id"],
            "card_hash": card["card_hash"],
            "attempt_id": attempt["attempt_id"],
            "dispatch_id": dispatch["dispatch_id"],
            "dispatch_key": dispatch["dispatch_key"],
            "idempotency_key": dispatch["idempotency_key"],
            "expected_pre_state_hash": c1_marker["payload"]["_before_state_hash"],
            "expected_fencing_epoch": run["fencing_epoch"],
            "intent": "CONTINUE",
        }
        spawn_event = next(event for event in runtime["events"] if event["event_type"] == "SPAWN_REQUESTED")
        blocked_ack = {
            "schema": "w5-blocked-ack-observation.v1",
            "status": "BLOCKED",
            "reason": "ACK_NOT_CONFIRMED",
            "run_id": run["run_id"],
            "card_id": card["card_id"],
            "attempt_id": attempt["attempt_id"],
            "dispatch_id": dispatch["dispatch_id"],
            "dispatch_state": dispatch["state"],
            "observed_event_id": spawn_event["event_id"],
            "observed_event_no": spawn_event["event_no"],
            "ack_deadline_at": dispatch["ack_deadline_at"],
            "observed_epoch": dispatch["ack_deadline_at"] - 59,
        }
        missing_evidence = {
            "schema": "w5-missing-ack-evidence.v1",
            "worker_claim": "ABSENT",
            "process_ack": "ABSENT",
            "executor_ack_event": "ABSENT",
            "executor_ack_marker": "ABSENT",
            "runtime_process_identity": "ABSENT",
        }
        replay = {
            "schema": "w5-blocked-ack-replay.v1",
            "continue_id": continue_intent["continue_id"],
            "first_continue_id": continue_intent["continue_id"],
            "second_continue_id": continue_intent["continue_id"],
            "first_continue_hash": canonical_hash(continue_intent),
            "second_continue_hash": canonical_hash(continue_intent),
            "second_continue_outcome": "IDEMPOTENT_REPLAY",
            "continue_calls": 2,
            "first_runtime_hash": canonical_hash(first),
            "second_runtime_hash": canonical_hash(runtime),
            "first_event_count": len(first["events"]),
            "second_event_count": len(runtime["events"]),
            "first_attempt_count": len(first["attempts"]),
            "second_attempt_count": len(runtime["attempts"]),
            "first_dispatch_count": len(first["dispatches"]),
            "second_dispatch_count": len(runtime["dispatches"]),
            "first_spawn_request_count": first_spawn_request_count,
            "second_spawn_request_count": cp.executor.spawn_request_count(dispatch_id),
            "first_ack_count": first_ack_count,
            "second_ack_count": sum(event["event_type"] == "EXECUTOR_ACKED" for event in runtime["events"]),
            "status": "IDEMPOTENT_REPLAY",
            "no_duplicate_dispatch": True,
            "no_duplicate_spawn": True,
        }
        source_attestation = source_attestation_template()
        authority_core = {
            "schema": "w5-w25-blocked-authority.v1",
            "authority_id": AUTHORITY_ID,
            "key_id": AUTHORITY_KEY_ID,
            "run_id": run["run_id"],
            "card_id": card["card_id"],
            "attempt_id": attempt["attempt_id"],
            "dispatch_id": dispatch["dispatch_id"],
            "fencing_epoch": run["fencing_epoch"],
            "policy_hash": canonical_hash(policy),
            "runtime_hash": canonical_hash(runtime),
            "state_witness_hash": canonical_hash(state_witnesses),
            "event_chain_hash": canonical_hash(runtime["events"]),
            "marker_commitments": {marker["operation_key"]: marker["marker_hash"] for marker in runtime["commit_markers"]},
            "continue_hash": canonical_hash(continue_intent),
            "replay_hash": canonical_hash(replay),
            "blocked_ack_hash": canonical_hash(blocked_ack),
            "missing_evidence_hash": canonical_hash(missing_evidence),
            "source_attestation_hash": canonical_hash(source_attestation),
            "bundle_schema_hash": canonical_hash("w5-blocked-ack-bundle.v1"),
        }
        authority = _reseal(authority_core)
        bundle = {
            "schema": "w5-blocked-ack-bundle.v1",
            "source": {"kind": "w25-s0", "version": "w25-s0", "canonicalization": "json-sortkeys-v1"},
            "runtime": runtime,
            "bridge_policy": policy,
            "continue_intent": continue_intent,
            "replay_evidence": replay,
            "blocked_ack": blocked_ack,
            "missing_evidence": missing_evidence,
            "state_witnesses": state_witnesses,
            "source_attestation": source_attestation,
        }
        return cp, bundle, authority

    def test_valid_bridge_is_verified_without_authorizing_process_or_next_card(self) -> None:
        _cp, bundle, authority = self.bundle()
        result = verify_dispatch_bridge_bundle(bundle, authority=authority)
        self.assertEqual("BRIDGE_VERIFIED", result.status)
        self.assertTrue(result.verified)
        self.assertFalse(result.accepted)
        self.assertEqual("C2_DISPATCH_CLAIMED", result.bridge["controller_claim"])
        self.assertEqual("EXECUTOR_ACKED", result.bridge["state"]["dispatch"])

    def test_source_attested_w5_s1_requires_the_pinned_local_w25_source(self) -> None:
        _cp, bundle, authority = self.bundle()
        bundle["schema"] = "w5-dispatch-bridge-bundle.v2-source-attested"
        bundle["source_attestation"] = source_attestation_template()
        authority = _source_reseal(authority, bundle["source_attestation"])
        result = verify_dispatch_bridge_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT)
        self.assertEqual("BRIDGE_VERIFIED", result.status)
        self.assertEqual("w5-w25-source-attestation.v1", bundle["source_attestation"]["schema"])
        self.assertTrue(result.bridge["source_attestation_hash"])

        authority["source_attestation_hash"] = "0" * 64
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT).status)

        _cp, bundle, authority = self.bundle()
        bundle["schema"] = "w5-dispatch-bridge-bundle.v2-source-attested"
        bundle["source_attestation"] = source_attestation_template()
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT).status)

        _cp, bundle, authority = self.bundle()
        bundle["schema"] = "w5-dispatch-bridge-bundle.v2-source-attested"
        bundle["source_attestation"] = source_attestation_template()
        authority = _source_reseal(authority, bundle["source_attestation"])
        bundle["source_attestation"]["entries"]["modules/mother-control-plane/control_plane.py"] = "0" * 64
        self.assertEqual("INCOMPATIBLE_SOURCE", verify_dispatch_bridge_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT).status)

        _cp, bundle, authority = self.bundle()
        bundle["schema"] = "w5-dispatch-bridge-bundle.v2-source-attested"
        bundle["source_attestation"] = source_attestation_template()
        authority = _source_reseal(authority, bundle["source_attestation"])
        bundle["source_attestation"]["unexpected"] = True
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT).status)

    def test_verified_and_blocked_w5_s1_results_project_to_mother_observation(self) -> None:
        _cp, bundle, authority = self.bundle()
        bundle["schema"] = "w5-dispatch-bridge-bundle.v2-source-attested"
        bundle["source_attestation"] = source_attestation_template()
        authority = _source_reseal(authority, bundle["source_attestation"])
        verified = verify_dispatch_bridge_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT)
        verified_observation = build_mother_observation(verified)
        self.assertEqual("BRIDGE_VERIFIED", verified_observation["status"])
        self.assertEqual(verified.bridge["dispatch_id"], verified_observation["identity"]["dispatch_id"])
        self.assertEqual(verified.bridge["source_attestation_hash"], verified_observation["source_attestation_hash"])
        self.assertTrue(all(value is False for value in verified_observation["execution"].values()))

        _cp, blocked_bundle, blocked_authority = self.blocked_bundle()
        blocked = verify_blocked_ack_bundle_s1(
            blocked_bundle,
            authority=blocked_authority,
            source_root=REPO_ROOT,
        )
        blocked_observation = build_mother_observation(blocked)
        self.assertEqual("BLOCKED", blocked_observation["status"])
        self.assertEqual("ACK_NOT_CONFIRMED", blocked_observation["findings"][0])
        self.assertEqual("SPAWN_REQUESTED", blocked_observation["state"]["dispatch"])
        self.assertTrue(all(value is False for value in blocked_observation["execution"].values()))

    def test_explicit_blocked_ack_wait_is_c0_c3_only_and_authenticated(self) -> None:
        _cp, bundle, authority = self.blocked_bundle()
        result = verify_blocked_ack_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT)
        self.assertEqual("BLOCKED", result.status)
        self.assertEqual("SPAWN_REQUESTED", result.bridge["state"]["dispatch"])
        self.assertFalse(result.accepted)

        at_deadline = copy.deepcopy(bundle)
        at_deadline["blocked_ack"]["observed_epoch"] = at_deadline["blocked_ack"]["ack_deadline_at"]
        at_deadline_authority = copy.deepcopy(authority)
        at_deadline_authority["blocked_ack_hash"] = canonical_hash(at_deadline["blocked_ack"])
        _blocked_runtime_reseal(at_deadline, at_deadline_authority)
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(at_deadline, authority=at_deadline_authority, source_root=REPO_ROOT).status)

        before_spawn = copy.deepcopy(bundle)
        before_spawn["blocked_ack"]["observed_epoch"] = before_spawn["blocked_ack"]["ack_deadline_at"] - 60
        before_spawn_authority = copy.deepcopy(authority)
        before_spawn_authority["blocked_ack_hash"] = canonical_hash(before_spawn["blocked_ack"])
        _blocked_runtime_reseal(before_spawn, before_spawn_authority)
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(before_spawn, authority=before_spawn_authority, source_root=REPO_ROOT).status)

        drifted_authority = copy.deepcopy(authority)
        drifted_authority["bundle_schema_hash"] = "0" * 64
        _reseal(drifted_authority)
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(bundle, authority=drifted_authority, source_root=REPO_ROOT).status)

        foreign_marker = copy.deepcopy(bundle)
        foreign_marker["runtime"]["commit_markers"][0]["run_id"] = "foreign-run"
        foreign_marker_authority = copy.deepcopy(authority)
        _blocked_runtime_reseal(foreign_marker, foreign_marker_authority)
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(foreign_marker, authority=foreign_marker_authority, source_root=REPO_ROOT).status)

        wrong_marker_event = copy.deepcopy(bundle)
        marker = wrong_marker_event["runtime"]["commit_markers"][0]
        payload = json.loads(marker["payload_json"])
        payload["_after_event_id"] = wrong_marker_event["runtime"]["events"][7]["event_id"]
        marker["payload"] = payload
        marker["payload_json"] = canonical_json(payload)
        marker["marker_hash"] = canonical_hash({
            "run_id": marker["run_id"],
            "commit_point": marker["commit_point"],
            "operation_key": marker["operation_key"],
            "status": marker["status"],
            "payload": payload,
        })
        wrong_marker_event_authority = copy.deepcopy(authority)
        _blocked_runtime_reseal(wrong_marker_event, wrong_marker_event_authority)
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(wrong_marker_event, authority=wrong_marker_event_authority, source_root=REPO_ROOT).status)

        _cp, bundle, authority = self.blocked_bundle()
        bundle["blocked_ack"]["reason"] = "EXECUTOR_ACKED"
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT).status)

        _cp, bundle, authority = self.blocked_bundle()
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(bundle, authority={}, source_root=REPO_ROOT).status)

        _cp, bundle, authority = self.blocked_bundle()
        bundle["runtime"]["dispatches"][0]["state"] = "RECONCILING"
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT).status)

        _cp, bundle, authority = self.blocked_bundle()
        bundle["runtime"]["commit_markers"].append(copy.deepcopy(bundle["runtime"]["commit_markers"][-1]))
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT).status)

        _cp, bundle, authority = self.bundle()
        bundle["schema"] = "w5-blocked-ack-bundle.v1"
        bundle["source_attestation"] = source_attestation_template()
        self.assertEqual("INVALID_EVIDENCE", verify_blocked_ack_bundle_s1(bundle, authority=authority, source_root=REPO_ROOT).status)

    def test_idempotent_replay_does_not_create_second_dispatch_or_spawn(self) -> None:
        _cp, bundle, authority = self.bundle()
        result = verify_dispatch_bridge_bundle(bundle, authority=authority)
        self.assertEqual("IDEMPOTENT_REPLAY", result.replay["status"])
        self.assertEqual(1, result.replay["first_spawn_request_count"])
        self.assertEqual(1, result.replay["second_dispatch_count"])
        self.assertEqual(1, result.replay["second_spawn_request_count"])

    def test_s0_rejects_ack_wait_mutations_and_forged_ack(self) -> None:
        _cp, bundle, authority = self.bundle()
        bundle["runtime"]["dispatches"][0]["state"] = "SPAWN_REQUESTED"
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["runtime"]["attempts"][0]["state"] = "ADMITTED"
        bundle["runtime"]["attempts"][0]["worker_id"] = None
        bundle["runtime"]["dispatches"][0]["state"] = "SPAWN_REQUESTED"
        for field in ("pid", "process_starttime", "boot_id", "pidfd_ref", "cgroup_ref"):
            bundle["runtime"]["dispatches"][0][field] = None
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["runtime"]["dispatches"][0]["state"] = "SPAWN_REQUESTED"
        bundle["runtime"]["dispatches"][0]["run_token"] = "foreign-token"
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["process_ack"]["identity"]["run_token"] = "foreign-token"
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

    def test_stale_fence_late_ack_and_c5_leak_fail_closed(self) -> None:
        _cp, bundle, authority = self.bundle()
        bundle["runtime"]["dispatches"][0]["fencing_epoch"] += 1
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["process_ack"]["ack_epoch"] = bundle["process_ack"]["ack_deadline_at"] + 1
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["runtime"]["events"].append(
            {
                "event_id": "event-forged-c5",
                "event_no": len(bundle["runtime"]["events"]) + 1,
                "run_id": bundle["runtime"]["run"]["run_id"],
                "entity_type": "Dispatch",
                "entity_id": bundle["runtime"]["dispatches"][0]["dispatch_id"],
                "event_type": "DISPATCH_RUNNING",
                "from_state": "EXECUTOR_ACKED",
                "to_state": "RUNNING",
                "payload": {},
            }
        )
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        spawn_event = next(event for event in bundle["runtime"]["events"] if event["event_type"] == "SPAWN_REQUESTED")
        spawn_event["payload"]["command_hash"] = "foreign-command"
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["state_witnesses"]["executor-ack"]["after_projection"]["runs"][0]["state"] = "READY"
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["runtime"]["events"][0]["payload_json"] = canonical_json({"foreign": True})
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["runtime"]["events"][0]["unexpected"] = True
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["state_witnesses"]["executor-ack"]["after_projection"]["runs"][0]["unexpected"] = True
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

    def test_duplicate_continue_and_authority_or_source_drift_fail_closed(self) -> None:
        _cp, bundle, authority = self.bundle()
        bundle["replay_evidence"]["second_spawn_request_count"] = 2
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["continue_intent"]["continue_id"] = "duplicate-continue"
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["replay_evidence"]["first_continue_id"] = "different-call"
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["source"]["kind"] = "local-mother"
        self.assertEqual("INCOMPATIBLE_SOURCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        authority["authority_mac"] = hmac.new(b"wrong-authority-key-2026", canonical_json({name: value for name, value in authority.items() if name not in {"authority_hash", "authority_mac"}}).encode("utf-8"), hashlib.sha256).hexdigest()
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

    def test_external_worker_claim_is_required_and_controller_claim_is_not_worker_claim(self) -> None:
        _cp, bundle, authority = self.bundle()
        bundle["worker_claim"]["worker_id"] = bundle["runtime"]["run"]["lease_owner_id"]
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["worker_claim"]["claim_epoch"] = bundle["process_ack"]["ack_epoch"] + 1
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        spawn_no = next(event["event_no"] for event in bundle["runtime"]["events"] if event["event_type"] == "SPAWN_REQUESTED")
        bundle["worker_claim"]["claim_before_ack_event_no"] = spawn_no - 1
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        bundle["runtime"]["attempts"][0]["worker_id"] = "foreign-worker"
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

        _cp, bundle, authority = self.bundle()
        del bundle["worker_claim"]
        self.assertEqual("INVALID_EVIDENCE", verify_dispatch_bridge_bundle(bundle, authority=authority).status)

    def test_no_real_process_or_network_surface(self) -> None:
        root = REPO_ROOT / "modules" / "w5_dispatch_bridge_s0"
        source = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.py"))
        for forbidden in ("subprocess", "socket", "urllib", "Popen(", "os.system(", "os.kill(", "write_text(", "write_bytes("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
