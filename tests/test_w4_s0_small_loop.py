"""W4-S0 bounded small-loop verifier acceptance tests."""

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
W25_ROOT = REPO_ROOT / "modules" / "mother-control-plane"
FIXTURE = REPO_ROOT / "tests" / "mother_control_plane" / "fixtures" / "p0_single_card.json"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(W25_ROOT))

from control_plane import ControlPlane  # noqa: E402
from modules.w4_small_loop_s0 import (  # noqa: E402
    canonical_attempt_state_hash,
    canonical_hash,
    canonical_json,
    configure_trusted_authority,
    freeze_trusted_authorities,
    reconstruct_receipt_hashes,
    verify_small_loop_bundle,
    verify_tool_trace,
)
from modules.w4_small_loop_s0.models import W4EvidenceError  # noqa: E402
from modules.w4_small_loop_s0.verifier import _verify_progress_history  # noqa: E402


AUTHORITY_KEY = b"w4-test-authority-key-2026"
AUTHORITY_KEY_ID = "w4-test-key-2026"


def _reseal_authority(authority: dict, *, key: bytes = AUTHORITY_KEY) -> dict:
    core = {name: value for name, value in authority.items() if name not in {"authority_hash", "authority_mac"}}
    authority["authority_hash"] = canonical_hash(core)
    authority["authority_mac"] = hmac.new(key, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest()
    return authority


class W4S0SmallLoopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = json.loads(FIXTURE.read_text(encoding="utf-8"))
        configure_trusted_authority(
            authority_id="w25-authority-fixture-001",
            key_id=AUTHORITY_KEY_ID,
            key=AUTHORITY_KEY,
        )
        freeze_trusted_authorities()

    def bundle(self) -> tuple[ControlPlane, dict, dict]:
        root = tempfile.TemporaryDirectory(prefix="w4-s0-")
        self.addCleanup(root.cleanup)
        cp = ControlPlane(Path(root.name) / "control.sqlite")
        self.addCleanup(cp.close)
        snapshot = cp.run_p0(copy.deepcopy(self.spec))
        runtime = copy.deepcopy(snapshot)
        run = runtime["run"]
        card = runtime["cards"][0]
        attempt = runtime["attempts"][0]
        dispatch = runtime["dispatches"][0]
        validation = next(item for item in runtime["receipts"] if item["receipt_kind"] == "validation")

        checkpoint_row = dict(cp.conn.execute("SELECT * FROM checkpoints").fetchone())
        checkpoint_payload = json.loads(checkpoint_row["payload_json"])
        running_event = cp.conn.execute(
            "SELECT event_id FROM events WHERE run_id=? AND event_type='ATTEMPT_RUNNING'",
            (run["run_id"],),
        ).fetchone()[0]
        checkpoint_state = {
            "attempt_id": attempt["attempt_id"],
            "card_id": card["card_id"],
            "state": "RUNNING",
            "state_version": 3,
            "last_transition_event_id": running_event,
            "result": None,
        }
        self.assertEqual(checkpoint_row["state_hash"], canonical_attempt_state_hash(checkpoint_state))
        policy_core = {
            "admission_budget": json.loads(run["budget_json"]),
            "max_turns": 6,
            "max_tool_calls": 24,
            "no_progress_limit": 2,
            "same_failure_limit": 2,
            "consecutive_failure_limit": 6,
            "allowed_tools": ["read", "grep", "glob", "write", "edit", "bash"],
            "budget_epoch": "w4-budget-001",
        }
        policy = {"schema": "w4-loop-policy.v1", **policy_core, "budget_hash": canonical_hash(policy_core)}
        manifest_row = dict(cp.conn.execute("SELECT * FROM artifact_manifests").fetchone())
        manifest_scope = json.loads(manifest_row["scope_json"])
        manifest = {
            "artifact_manifest_hash": manifest_row["artifact_manifest_hash"],
            "attempt_id": manifest_row["attempt_id"],
            "artifact_hashes": json.loads(manifest_row["artifact_hashes_json"]),
            "scope": manifest_scope["scope"],
        }
        artifacts = [
            dict(row)
            for row in cp.conn.execute(
                "SELECT artifact_id,attempt_id,artifact_manifest_hash,artifact_hash,scope_ref FROM artifacts ORDER BY artifact_id"
            )
        ]
        rebuilt = reconstruct_receipt_hashes(validation)
        progress = rebuilt["progress_payload"]
        history = [
            {
                "turn_no": 1,
                "attempt_no": 1,
                "canonical_state_hash": progress["canonical_state_hash"],
                "artifact_hashes": list(progress["artifact_hashes"]),
                "validation_result": copy.deepcopy(progress["validation_result"]),
                "receipt_body_hash": progress["receipt_body_hash"],
                "next_state": progress["next_state"],
                "progress_signature": rebuilt["progress_signature"],
            }
        ]
        checkpoint = {
            "checkpoint_id": checkpoint_row["checkpoint_id"],
            "attempt_id": checkpoint_row["attempt_id"],
            "attempt_no": 1,
            "state_hash": checkpoint_row["state_hash"],
            "receipt_id": checkpoint_row["receipt_id"],
            "payload": checkpoint_payload,
            "payload_hash": canonical_hash(checkpoint_payload),
            "parent_checkpoint_hash": None,
            "bindings": {
                "run_id": run["run_id"],
                "card_id": card["card_id"],
                "attempt_id": attempt["attempt_id"],
                "plan_version": run["plan_version"],
                "queue_hash": run["queue_hash"],
                "policy_hash": run["policy_hash"],
                "context_pack_hash": run["context_pack_hash"],
                "input_snapshot_hash": attempt["input_snapshot_hash"],
                "capability_set_hash": card["capability_set_hash"],
                "budget_hash": policy["budget_hash"],
                "fencing_epoch": run["fencing_epoch"],
            },
            "created_at": checkpoint_row["created_at"],
        }
        checkpoint["checkpoint_hash"] = canonical_hash(checkpoint)
        identity = {
            "run_id": run["run_id"],
            "attempt_id": attempt["attempt_id"],
            "capability_set_hash": card["capability_set_hash"],
            "policy_hash": run["policy_hash"],
            "budget_hash": policy["budget_hash"],
        }
        trace = {
            "schema": "w4-tool-trace.v1",
            **identity,
            "calls": [],
            "failures": [],
            "gate": None,
        }
        review_request = {
            "review_domain_id": "w4-independent-review-v1",
            "reviewer_id": "reviewer-feynman",
            "reviewer_session_id": "review-session-001",
            "reviewer_backend": "deterministic-reviewer-v1",
            "executor_session_id": "worker-session-001",
            "criteria": [
                "receipt-and-progress-hashes-reconstruct",
                "checkpoint-is-current-and-bound",
                "tool-circuit-is-closed",
                "no-acceptance-or-next-card-is-reachable",
            ],
        }
        marker_commitments = {
            row["operation_key"]: row["marker_hash"]
            for row in cp.conn.execute("SELECT operation_key,marker_hash FROM marker_commitments ORDER BY operation_key")
        }
        authority_core = {
            "schema": "w4-w25-authority.v1",
            "authority_id": "w25-authority-fixture-001",
            "key_id": AUTHORITY_KEY_ID,
            "run_id": run["run_id"],
            "card_id": card["card_id"],
            "attempt_id": attempt["attempt_id"],
            "budget": json.loads(run["budget_json"]),
            "budget_hash": policy["budget_hash"],
            "budget_epoch": policy["budget_epoch"],
            "marker_commitments": marker_commitments,
            "checkpoint": {
                "checkpoint_id": checkpoint["checkpoint_id"],
                "state_hash": checkpoint["state_hash"],
                "state_version": checkpoint_state["state_version"],
                "last_transition_event_id": checkpoint_state["last_transition_event_id"],
            },
            "event_chain_hash": canonical_hash(runtime["events"]),
            "tool_trace_hash": canonical_hash(trace),
            "final": {
                "attempt_state_hash": canonical_attempt_state_hash(attempt),
                "state": attempt["state"],
                "result": attempt["result"],
                "state_version": attempt["state_version"],
                "last_transition_event_id": attempt["last_transition_event_id"],
                "receipt_id": validation["receipt_id"],
                "receipt_hash": validation["receipt_hash"],
                "receipt_body_hash": validation["receipt_body_hash"],
                "progress_signature": validation["progress_signature"],
            },
            "executor": {
                "worker_id": attempt["worker_id"],
                "session_id": review_request["executor_session_id"],
                "backend": dispatch["executor_kind"],
            },
            "review": {
                "review_domain_id": review_request["review_domain_id"],
                "reviewer_id": review_request["reviewer_id"],
                "reviewer_session_id": review_request["reviewer_session_id"],
                "reviewer_backend": review_request["reviewer_backend"],
            },
        }
        authority = _reseal_authority(dict(authority_core))
        bundle = {
            "schema": "w4-small-loop-bundle.v1",
            "source": {"kind": "w25-s0", "version": "w25-s0", "canonicalization": "json-sortkeys-v1"},
            "runtime": runtime,
            "evidence": {
                "artifact_manifest": manifest,
                "artifacts": artifacts,
                "checkpoint": checkpoint,
                "checkpoint_state": checkpoint_state,
                "progress_history": history,
            },
            "loop_policy": policy,
            "tool_trace": trace,
            "review_request": review_request,
        }
        return cp, bundle, snapshot, authority

    def test_valid_w25_bundle_reaches_review_preparation_only(self) -> None:
        _cp, bundle, before, authority = self.bundle()
        original = copy.deepcopy(bundle)
        result = verify_small_loop_bundle(bundle, authority=authority)
        self.assertEqual("READY_FOR_REVIEW", result.status)
        self.assertTrue(result.ready_for_review)
        self.assertFalse(result.accepted)
        self.assertEqual("PENDING", result.review_preparation["decision"])
        self.assertFalse(result.review_preparation["self_accept"])
        self.assertFalse(result.review_preparation["accepted"])
        self.assertNotEqual(result.review_preparation["prep_id"], result.receipt["review_id"])
        self.assertEqual(original, bundle)
        self.assertEqual("VERIFYING", before["run"]["state"])
        self.assertNotIn("DONE", {bundle["runtime"]["cards"][0]["state"]})

    def test_golden_vectors_match_w25_reconstruction(self) -> None:
        _cp, bundle, _snapshot, authority = self.bundle()
        validation = next(item for item in bundle["runtime"]["receipts"] if item["receipt_kind"] == "validation")
        rebuilt = reconstruct_receipt_hashes(validation)
        self.assertTrue(rebuilt["valid"])
        self.assertEqual(rebuilt["receipt_body_hash"], validation["receipt_body_hash"])
        self.assertEqual(rebuilt["progress_signature"], validation["progress_signature"])
        self.assertEqual(rebuilt["receipt_hash"], validation["receipt_hash"])
        self.assertEqual("READY_FOR_REVIEW", verify_small_loop_bundle(bundle, authority=authority).status)

    def test_single_field_tampering_is_fail_closed(self) -> None:
        mutations = (
            ("receipt_card", lambda b: b["runtime"]["receipts"][1].update(card_hash="foreign-card")),
            ("receipt_core", lambda b: b["runtime"]["receipts"][1]["core"].update(result="ACCEPTED")),
            ("manifest_hashes", lambda b: b["evidence"]["artifact_manifest"].update(artifact_hashes=[])),
            ("checkpoint_payload", lambda b: b["evidence"]["checkpoint"]["payload"].update(state="BLOCKED")),
            ("checkpoint_state_hash", lambda b: b["evidence"]["checkpoint"].update(state_hash="0" * 64)),
            ("checkpoint_state", lambda b: b["evidence"]["checkpoint_state"].update(state_version=4)),
            ("budget", lambda b: b["loop_policy"]["admission_budget"].update(walltime_seconds=61)),
            ("tool_binding", lambda b: b["tool_trace"].update(budget_hash="0" * 64)),
            ("review_identity", lambda b: b["review_request"].update(reviewer_id=b["runtime"]["attempts"][0]["worker_id"])),
        )
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                _cp, bundle, _snapshot, authority = self.bundle()
                mutate(bundle)
                self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

    def test_source_terminal_and_stale_bindings_fail_closed(self) -> None:
        _cp, bundle, _snapshot, authority = self.bundle()
        bundle["source"]["kind"] = "local-mother"
        self.assertEqual("INCOMPATIBLE_SOURCE", verify_small_loop_bundle(bundle, authority=authority).status)

        _cp, bundle, _snapshot, authority = self.bundle()
        bundle["runtime"]["acceptance_txns"][0]["state"] = "COMMITTED"
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

        _cp, bundle, _snapshot, authority = self.bundle()
        bundle["evidence"]["checkpoint"]["bindings"]["budget_hash"] = "stale-budget"
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

        _cp, bundle, _snapshot, authority = self.bundle()
        bundle["runtime"]["next_card_intents"].append({"next_card_intent_id": "forbidden"})
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

    def test_external_authority_is_required_for_marker_budget_and_checkpoint_roots(self) -> None:
        with self.assertRaises(RuntimeError):
            configure_trusted_authority(
                authority_id="w25-authority-fixture-001",
                key_id=AUTHORITY_KEY_ID,
                key=b"wrong-authority-key-2026",
            )

        _cp, bundle, _snapshot, authority = self.bundle()
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle).status)

        _cp, bundle, _snapshot, authority = self.bundle()
        bundle["tool_trace"]["calls"].append(
            {"call_seq": 1, "turn_no": 1, "tool": "read", "command_sha256": "e" * 64, "outcome": "success"}
        )
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

        _cp, bundle, _snapshot, authority = self.bundle()
        authority["authority_mac"] = hmac.new(
            b"wrong-authority-key-2026",
            canonical_json({name: value for name, value in authority.items() if name not in {"authority_hash", "authority_mac"}}).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(
            "INVALID_EVIDENCE",
            verify_small_loop_bundle(bundle, authority=authority).status,
        )

        _cp, bundle, _snapshot, authority = self.bundle()
        checkpoint_marker = next(item for item in bundle["runtime"]["commit_markers"] if item["operation_key"] == "checkpoint")
        checkpoint_marker["marker_hash"] = "0" * 64
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

        _cp, bundle, _snapshot, authority = self.bundle()
        running_event = next(item for item in bundle["runtime"]["events"] if item["event_type"] == "ATTEMPT_RUNNING")
        running_event["to_state"] = "SUBMITTED"
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

        _cp, bundle, _snapshot, authority = self.bundle()
        bundle["runtime"]["acceptance_txns"] = [None]
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

        _cp, bundle, _snapshot, authority = self.bundle()
        bundle["runtime"]["attempts"][0]["state_version"] += 1
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

        _cp, bundle, _snapshot, authority = self.bundle()
        bundle["runtime"]["events"][0]["event_type"] = "FORGED_EVENT"
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

    def test_tool_circuit_requires_exact_gate_and_never_self_repairs(self) -> None:
        _cp, bundle, _snapshot, authority = self.bundle()
        identity = {
            key: bundle["tool_trace"][key]
            for key in ("run_id", "attempt_id", "capability_set_hash", "policy_hash", "budget_hash")
        }
        command_hash = "a" * 64
        calls = [
            {"call_seq": 1, "turn_no": 1, "tool": "bash", "command_sha256": command_hash, "outcome": "failure"},
            {"call_seq": 2, "turn_no": 1, "tool": "bash", "command_sha256": command_hash, "outcome": "failure"},
        ]
        failures = [
            {**calls[0], "error_class": "timeout", "count": 1, "consecutive": 1},
            {**calls[1], "error_class": "timeout", "count": 2, "consecutive": 2},
        ]
        gate = {"call_seq": 2, "turn_no": 1, "tool": "bash", "command_sha256": command_hash, "error_class": "timeout", "count": 2, "consecutive": 2, "reason": "repeated tool failure"}
        trace = {"schema": "w4-tool-trace.v1", **identity, "calls": calls, "failures": failures, "gate": gate}
        report = verify_tool_trace(trace, identity=identity, policy=bundle["loop_policy"])
        self.assertEqual("OPEN", report["status"])
        self.assertEqual(2, report["call_count"])

        trace["gate"] = None
        with self.assertRaises(W4EvidenceError):
            verify_tool_trace(trace, identity=identity, policy=bundle["loop_policy"])
        trace["gate"] = gate
        trace["calls"].append({"call_seq": 3, "turn_no": 1, "tool": "read", "command_sha256": "b" * 64, "outcome": "success"})
        with self.assertRaises(W4EvidenceError):
            verify_tool_trace(trace, identity=identity, policy=bundle["loop_policy"])

    def test_different_error_classes_do_not_count_as_same_failure(self) -> None:
        _cp, bundle, _snapshot, _authority = self.bundle()
        identity = {
            key: bundle["tool_trace"][key]
            for key in ("run_id", "attempt_id", "capability_set_hash", "policy_hash", "budget_hash")
        }
        command_hash = "d" * 64
        calls = [
            {"call_seq": 1, "turn_no": 1, "tool": "bash", "command_sha256": command_hash, "outcome": "failure"},
            {"call_seq": 2, "turn_no": 1, "tool": "bash", "command_sha256": command_hash, "outcome": "failure"},
        ]
        trace = {
            "schema": "w4-tool-trace.v1",
            **identity,
            "calls": calls,
            "failures": [
                {**calls[0], "error_class": "timeout", "count": 1, "consecutive": 1},
                {**calls[1], "error_class": "permission", "count": 1, "consecutive": 2},
            ],
            "gate": None,
        }
        report = verify_tool_trace(trace, identity=identity, policy=bundle["loop_policy"])
        self.assertEqual("CLOSED", report["status"])

    def test_open_tool_circuit_blocks_full_bundle_without_review(self) -> None:
        _cp, bundle, _snapshot, authority = self.bundle()
        identity = {
            key: bundle["tool_trace"][key]
            for key in ("run_id", "attempt_id", "capability_set_hash", "policy_hash", "budget_hash")
        }
        command_hash = "c" * 64
        calls = [
            {"call_seq": 1, "turn_no": 1, "tool": "bash", "command_sha256": command_hash, "outcome": "failure"},
            {"call_seq": 2, "turn_no": 1, "tool": "bash", "command_sha256": command_hash, "outcome": "failure"},
        ]
        bundle["tool_trace"] = {
            "schema": "w4-tool-trace.v1",
            **identity,
            "calls": calls,
            "failures": [
                {**calls[0], "error_class": "timeout", "count": 1, "consecutive": 1},
                {**calls[1], "error_class": "timeout", "count": 2, "consecutive": 2},
            ],
            "gate": {
                "call_seq": 2,
                "turn_no": 1,
                "tool": "bash",
                "command_sha256": command_hash,
                "error_class": "timeout",
                "count": 2,
                "consecutive": 2,
                "reason": "repeated tool failure",
            },
        }
        authority["tool_trace_hash"] = canonical_hash(bundle["tool_trace"])
        _reseal_authority(authority)
        result = verify_small_loop_bundle(bundle, authority=authority)
        self.assertEqual("BLOCKED", result.status)
        self.assertEqual("OPEN", result.tool_circuit["status"])
        self.assertIsNone(result.review_preparation)
        self.assertFalse(result.accepted)

    def test_progress_signature_excludes_unbound_log_text_but_rejects_duplicate_success(self) -> None:
        _cp, bundle, _snapshot, authority = self.bundle()
        validation = next(item for item in bundle["runtime"]["receipts"] if item["receipt_kind"] == "validation")
        original = copy.deepcopy(validation)
        validation["unbound_log_text"] = "different model wording"
        self.assertEqual(reconstruct_receipt_hashes(validation), reconstruct_receipt_hashes(original))

        duplicate = copy.deepcopy(bundle["evidence"]["progress_history"][0])
        duplicate["turn_no"] = 2
        bundle["evidence"]["progress_history"].append(duplicate)
        self.assertEqual("INVALID_EVIDENCE", verify_small_loop_bundle(bundle, authority=authority).status)

    def test_no_progress_threshold_is_terminal(self) -> None:
        _cp, bundle, _snapshot, _authority = self.bundle()
        validation = next(item for item in bundle["runtime"]["receipts"] if item["receipt_kind"] == "validation")
        first = copy.deepcopy(bundle["evidence"]["progress_history"][0])
        second = copy.deepcopy(first)
        second["turn_no"] = 2
        third = copy.deepcopy(first)
        third["turn_no"] = 3
        third["next_state"] = "EVIDENCE_VERIFIED"
        third["progress_signature"] = canonical_hash(
            {
                "card_id": validation["card_id"],
                "attempt_id": validation["attempt_id"],
                "attempt_no": 1,
                "canonical_state_hash": third["canonical_state_hash"],
                "artifact_hashes": sorted(third["artifact_hashes"]),
                "validation_result": third["validation_result"],
                "receipt_body_hash": third["receipt_body_hash"],
                "next_state": third["next_state"],
            }
        )
        validation_after_continuation = copy.deepcopy(validation)
        validation_after_continuation["progress_signature"] = third["progress_signature"]
        with self.assertRaises(W4EvidenceError):
            _verify_progress_history(
                [first, second, third],
                validation_after_continuation,
                bundle["loop_policy"],
            )

    def test_reviewer_same_identity_is_blocked_without_acceptance(self) -> None:
        _cp, bundle, _snapshot, authority = self.bundle()
        bundle["review_request"]["reviewer_session_id"] = bundle["review_request"]["executor_session_id"]
        result = verify_small_loop_bundle(bundle, authority=authority)
        self.assertEqual("INVALID_EVIDENCE", result.status)
        self.assertFalse(result.accepted)

    def test_w4_paths_have_no_execution_or_network_surface(self) -> None:
        root = REPO_ROOT / "modules" / "w4_small_loop_s0"
        source = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.py"))
        for forbidden in ("subprocess", "socket", "urllib", "Popen(", "os.system(", "os.kill(", "write_text(", "write_bytes("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
