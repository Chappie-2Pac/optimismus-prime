"""W2.5-S0 acceptance tests for the isolated P0 single-card harness."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = REPO_ROOT / "modules" / "mother-control-plane"
FIXTURE_PATH = REPO_ROOT / "tests" / "mother_control_plane" / "fixtures" / "p0_single_card.json"
sys.path.insert(0, str(MODULE_ROOT))

from control_plane import (  # noqa: E402
    ControlPlane,
    EvidenceError,
    FencingError,
    P0Disabled,
    StateConflict,
    canonical_hash,
)
from fault_injection import COMMIT_POINTS, HOOKS, FaultPlan, InjectedCrash  # noqa: E402


class W25SingleCardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    def open_cp(self, root: str, *, fault: FaultPlan | None = None) -> ControlPlane:
        return ControlPlane(Path(root) / "control.sqlite", fault_plan=fault)

    def dispatch_id(self) -> str:
        return f"dispatch-attempt-{self.spec['card_id']}-001"

    def assert_p0_invariants(self, cp: ControlPlane, snapshot: dict) -> None:
        self.assertEqual("ok", cp.integrity_check())
        self.assertEqual("VERIFYING", snapshot["run"]["state"])
        self.assertEqual(1, snapshot["counts"]["runs"])
        self.assertEqual(1, snapshot["counts"]["cards"])
        self.assertEqual(1, snapshot["counts"]["attempts"])
        self.assertEqual(1, snapshot["counts"]["dispatches"])
        self.assertEqual(2, snapshot["counts"]["receipts"])
        self.assertEqual("SUBMITTED", snapshot["cards"][0]["state"])
        self.assertEqual("EVIDENCE_VERIFIED", snapshot["attempts"][0]["state"])
        self.assertEqual("EVIDENCE_VERIFIED", snapshot["attempts"][0]["result"])
        self.assertEqual("COMPLETED", snapshot["dispatches"][0]["state"])
        self.assertEqual(1, len(snapshot["reviews"]))
        self.assertEqual("NOT_REQUESTED", snapshot["reviews"][0]["state"])
        self.assertTrue(all(receipt["state"] in {"SEALED", "VERIFIED"} for receipt in snapshot["receipts"]))
        self.assertEqual(0, len(snapshot["next_card_intents"]))
        self.assertNotEqual("DONE", snapshot["cards"][0]["state"])
        self.assertTrue(all(txn["state"] != "COMMITTED" for txn in snapshot["acceptance_txns"]))
        self.assertTrue(all(cp.reconstruct_receipt_hashes(receipt["receipt_id"])["valid"] for receipt in snapshot["receipts"]))

    def test_happy_path_is_p0_only_and_replay_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="w25-s0-") as root:
            cp = self.open_cp(root)
            try:
                first = cp.run_p0(self.spec)
                self.assert_p0_invariants(cp, first)
                first_event_count = len(first["events"])
                first_hashes = [receipt["receipt_hash"] for receipt in first["receipts"]]
                second = cp.run_p0(copy.deepcopy(self.spec))
                self.assert_p0_invariants(cp, second)
                self.assertEqual(first_event_count, len(second["events"]))
                self.assertEqual(first_hashes, [receipt["receipt_hash"] for receipt in second["receipts"]])
                self.assertEqual(1, cp.executor.spawn_count(self.dispatch_id()))
                self.assertEqual(1, cp.executor.spawn_request_count(self.dispatch_id()))
                self.assertEqual(0, cp.conn.execute("SELECT COUNT(*) FROM next_card_intents").fetchone()[0])
            finally:
                cp.close()

    def test_all_72_faults_recover_twice_without_duplicate_or_done(self) -> None:
        for commit_point in COMMIT_POINTS:
            for hook in HOOKS:
                with self.subTest(fault=f"{commit_point}.{hook}"), tempfile.TemporaryDirectory(prefix="w25-fault-") as root:
                    fault = FaultPlan.for_fault(commit_point, hook)
                    cp = self.open_cp(root, fault=fault)
                    try:
                        with self.assertRaises(InjectedCrash):
                            cp.run_p0(self.spec)
                    finally:
                        cp.close()
                    cp = self.open_cp(root)
                    try:
                        recovered = cp.recover(self.spec["run_id"], self.spec)
                        replayed = cp.recover(self.spec["run_id"], self.spec)
                        self.assert_p0_invariants(cp, recovered)
                        self.assertEqual(len(recovered["events"]), len(replayed["events"]))
                        self.assertEqual(recovered["counts"], replayed["counts"])
                        self.assertEqual(1, cp.executor.spawn_count(self.dispatch_id()))
                        expected_reopen_spawn_requests = 1 if int(commit_point[1:]) < 4 else 0
                        self.assertEqual(expected_reopen_spawn_requests, cp.executor.spawn_request_count(self.dispatch_id()))
                        observation = cp.conn.execute(
                            "SELECT commit_point,hook,injected FROM fault_observations"
                        ).fetchone()
                        self.assertIsNotNone(observation)
                        self.assertEqual((commit_point, hook, 1), tuple(observation))
                        markers = {marker["commit_point"]: marker for marker in recovered["commit_markers"]}
                        self.assertEqual(set(COMMIT_POINTS), set(markers))
                        for point in ("C8", "C9", "C10", "C11"):
                            self.assertEqual("SUPPRESSED", markers[point]["status"])
                    finally:
                        cp.close()

    def test_all_hooks_are_exercised_and_p0_suppressed_points_are_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="w25-hooks-") as root:
            cp = self.open_cp(root)
            try:
                snapshot = cp.run_p0(self.spec)
                self.assert_p0_invariants(cp, snapshot)
                self.assertEqual(set(f"{point}.{hook}" for point in COMMIT_POINTS for hook in HOOKS), set(cp.hook_trace))
                markers = {marker["commit_point"]: marker for marker in snapshot["commit_markers"]}
                self.assertEqual("NOT_REACHED_P0", json.loads(markers["C8"]["payload_json"])["evidence"])
                self.assertEqual("NOT_REACHED_P0", json.loads(markers["C10"]["payload_json"])["evidence"])
                self.assertEqual("NOT_REACHED_P0", json.loads(markers["C11"]["payload_json"])["evidence"])
            finally:
                cp.close()

    def test_hashes_are_reproducible_across_fresh_databases(self) -> None:
        outputs: list[tuple[str, str, str]] = []
        for _ in range(2):
            with tempfile.TemporaryDirectory(prefix="w25-determinism-") as root:
                cp = self.open_cp(root)
                try:
                    snapshot = cp.run_p0(self.spec)
                    validation = next(item for item in snapshot["receipts"] if item["receipt_kind"] == "validation")
                    rebuilt = cp.reconstruct_receipt_hashes(validation["receipt_id"])
                    outputs.append((validation["receipt_body_hash"], validation["progress_signature"], validation["receipt_hash"]))
                    self.assertTrue(rebuilt["valid"])
                finally:
                    cp.close()
        self.assertEqual(outputs[0], outputs[1])

    def test_recovery_survives_close_and_reopen(self) -> None:
        with tempfile.TemporaryDirectory(prefix="w25-reopen-") as root:
            first = self.open_cp(root, fault=FaultPlan.for_fault("C6", "after_commit_marker"))
            try:
                with self.assertRaises(InjectedCrash):
                    first.run_p0(self.spec)
            finally:
                first.close()
            reopened = self.open_cp(root)
            try:
                snapshot = reopened.recover(self.spec["run_id"])
                self.assert_p0_invariants(reopened, snapshot)
                self.assertEqual(1, reopened.executor.spawn_count(self.dispatch_id()))
                self.assertEqual(0, reopened.executor.spawn_request_count(self.dispatch_id()))
                self.assertEqual(1, reopened.conn.execute("SELECT COUNT(*) FROM fault_observations WHERE commit_point='C6' AND hook='after_commit_marker'").fetchone()[0])
            finally:
                reopened.close()

    def test_receipt_core_progress_and_state_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="w25-tamper-") as root:
            cp = self.open_cp(root)
            try:
                snapshot = cp.run_p0(self.spec)
                receipt_id = next(item["receipt_id"] for item in snapshot["receipts"] if item["receipt_kind"] == "validation")
                original = cp.conn.execute("SELECT core_json FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()[0]
                tampered = json.loads(original)
                tampered["result"] = "ACCEPTED"
                cp.conn.execute("UPDATE receipts SET core_json=? WHERE receipt_id=?", (json.dumps(tampered), receipt_id))
                with self.assertRaises(EvidenceError):
                    cp.validate_receipt(receipt_id)

                cp.conn.execute("UPDATE receipts SET core_json=? WHERE receipt_id=?", (original, receipt_id))
                manifest_hash = cp.conn.execute("SELECT artifact_manifest_hash FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()[0]
                manifest_json = cp.conn.execute("SELECT artifact_hashes_json FROM artifact_manifests WHERE artifact_manifest_hash=?", (manifest_hash,)).fetchone()[0]
                cp.conn.execute("UPDATE artifact_manifests SET artifact_hashes_json='[]' WHERE artifact_manifest_hash=?", (manifest_hash,))
                with self.assertRaises(EvidenceError):
                    cp.validate_receipt(receipt_id)
                cp.conn.execute("UPDATE artifact_manifests SET artifact_hashes_json=? WHERE artifact_manifest_hash=?", (manifest_json, manifest_hash))

                artifact_id = cp.conn.execute("SELECT artifact_id FROM artifacts WHERE artifact_manifest_hash=?", (manifest_hash,)).fetchone()[0]
                original_artifact_hash = cp.conn.execute("SELECT artifact_hash FROM artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()[0]
                cp.conn.execute("UPDATE artifacts SET artifact_hash='tampered-artifact' WHERE artifact_id=?", (artifact_id,))
                with self.assertRaises(EvidenceError):
                    cp.validate_receipt(receipt_id)
                cp.conn.execute("UPDATE artifacts SET artifact_hash=? WHERE artifact_id=?", (original_artifact_hash, artifact_id))
                original_scope_ref = cp.conn.execute("SELECT scope_ref FROM artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()[0]
                cp.conn.execute("UPDATE artifacts SET scope_ref='fake://tampered-scope' WHERE artifact_id=?", (artifact_id,))
                with self.assertRaises(EvidenceError):
                    cp.validate_receipt(receipt_id)
                cp.conn.execute("UPDATE artifacts SET scope_ref=? WHERE artifact_id=?", (original_scope_ref, artifact_id))

                original_validation = cp.conn.execute("SELECT validation_result_json FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()[0]
                cp.conn.execute("UPDATE receipts SET validation_result_json='{}' WHERE receipt_id=?", (receipt_id,))
                with self.assertRaises(StateConflict):
                    cp.recover(self.spec["run_id"], self.spec)
                cp.conn.execute("UPDATE receipts SET validation_result_json=? WHERE receipt_id=?", (original_validation, receipt_id))

                # A state write outside the transition/event path must also
                # invalidate the state-bound validation receipt.
                cp.conn.execute("UPDATE attempts SET state='BLOCKED' WHERE attempt_id=?", (f"attempt-{self.spec['card_id']}-001",))
                with self.assertRaises(EvidenceError):
                    cp.validate_receipt(receipt_id)
            finally:
                cp.close()

    def test_replay_rejects_canonical_state_drift_after_last_marker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="w25-marker-drift-") as root:
            cp = self.open_cp(root)
            try:
                cp.run_p0(self.spec)
                marker = cp.conn.execute(
                    "SELECT payload_json,marker_hash FROM commit_markers WHERE run_id=? AND operation_key='spawn-request'",
                    (self.spec["run_id"],),
                ).fetchone()
                original_marker_payload, original_marker_hash = marker
                marker_payload = json.loads(original_marker_payload)
                marker_payload["tampered"] = True
                tampered_marker_hash = canonical_hash(
                    {
                        "run_id": self.spec["run_id"],
                        "commit_point": "C3",
                        "operation_key": "spawn-request",
                        "status": "COMMITTED",
                        "payload": marker_payload,
                    }
                )
                cp.conn.execute(
                    "UPDATE commit_markers SET payload_json=?,marker_hash=? WHERE run_id=? AND operation_key='spawn-request'",
                    (json.dumps(marker_payload), tampered_marker_hash, self.spec["run_id"]),
                )
                with self.assertRaises(EvidenceError):
                    cp.recover(self.spec["run_id"], self.spec)
                cp.conn.execute(
                    "UPDATE commit_markers SET payload_json=?,marker_hash=? WHERE run_id=? AND operation_key='spawn-request'",
                    (original_marker_payload, original_marker_hash, self.spec["run_id"]),
                )

                anchor_hash = cp.conn.execute("SELECT projection_hash FROM runtime_anchors WHERE run_id=?", (self.spec["run_id"],)).fetchone()[0]
                cp.conn.execute("UPDATE runtime_anchors SET projection_hash='tampered-anchor' WHERE run_id=?", (self.spec["run_id"],))
                with self.assertRaises(StateConflict):
                    cp.recover(self.spec["run_id"], self.spec)
                cp.conn.execute("UPDATE runtime_anchors SET projection_hash=? WHERE run_id=?", (anchor_hash, self.spec["run_id"]))

                cp.conn.execute("UPDATE cards SET state='READY' WHERE card_id=?", (self.spec["card_id"],))
                with cp._transaction() as cur:
                    cp._record_event(
                        cur,
                        run_id=self.spec["run_id"],
                        entity_type="Run",
                        entity_id=self.spec["run_id"],
                        event_type="POST_MARKER_AUDIT",
                        from_state="VERIFYING",
                        to_state="VERIFYING",
                    )
                with self.assertRaises(StateConflict):
                    cp.recover(self.spec["run_id"], self.spec)
            finally:
                cp.close()

    def test_lease_reclaim_fences_old_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="w25-lease-") as root:
            cp = self.open_cp(root)
            try:
                cp.run_p0(self.spec)
                old = cp.lease_snapshot(self.spec["run_id"])
                cp.expire_lease(self.spec["run_id"])
                new = cp.reclaim_lease(self.spec["run_id"], new_owner_id="recovered-owner", reason="test-reclaim")
                self.assertEqual(int(old["fencing_epoch"]) + 1, int(new["fencing_epoch"]))
                with self.assertRaises(FencingError):
                    cp.assert_fencing(self.spec["run_id"], owner_id=old["lease_owner_id"], lease_token=old["lease_token"], fencing_epoch=old["fencing_epoch"])
                cp.assert_fencing(self.spec["run_id"], owner_id=new["lease_owner_id"], lease_token=new["lease_token"], fencing_epoch=new["fencing_epoch"])
            finally:
                cp.close()

    def test_ack_reconciliation_adopts_only_exact_identity(self) -> None:
        dispatch_id = self.dispatch_id()
        with tempfile.TemporaryDirectory(prefix="w25-reconcile-adopt-") as root:
            cp = self.open_cp(root, fault=FaultPlan.for_fault("C4", "after_replace"))
            try:
                with self.assertRaises(InjectedCrash):
                    cp.run_p0(self.spec)
                identity = cp.executor.identity_for(dispatch_id)
                self.assertIsNotNone(identity)
                adopted = cp.reconcile_dispatch(self.spec["run_id"], dispatch_id, identity)
                self.assertEqual("ADOPTED", adopted["status"])
                self.assertEqual(1, adopted["spawn_count"])
                cp.fault = FaultPlan.none()
                snapshot = cp.recover(self.spec["run_id"], self.spec)
                self.assert_p0_invariants(cp, snapshot)
                self.assertEqual(1, cp.executor.spawn_count(dispatch_id))
            finally:
                cp.close()

        with tempfile.TemporaryDirectory(prefix="w25-reconcile-foreign-") as root:
            cp = self.open_cp(root, fault=FaultPlan.for_fault("C4", "after_replace"))
            try:
                with self.assertRaises(InjectedCrash):
                    cp.run_p0(self.spec)
                identity = cp.executor.identity_for(dispatch_id)
                self.assertIsNotNone(identity)
                foreign = replace(identity, run_token="foreign-run-token")
                result = cp.reconcile_dispatch(self.spec["run_id"], dispatch_id, foreign)
                self.assertEqual("RECOVERY_REQUIRED", result["status"])
                state = cp.conn.execute("SELECT state FROM runs WHERE run_id=?", (self.spec["run_id"],)).fetchone()[0]
                attempt_state = cp.conn.execute("SELECT state FROM attempts WHERE attempt_id=?", (f"attempt-{self.spec['card_id']}-001",)).fetchone()[0]
                self.assertEqual("RECOVERY_REQUIRED", state)
                self.assertEqual("UNCERTAIN", attempt_state)
                with self.assertRaises(StateConflict):
                    cp.recover(self.spec["run_id"], self.spec)
                self.assertEqual(1, cp.executor.spawn_count(dispatch_id))
            finally:
                cp.close()

        with tempfile.TemporaryDirectory(prefix="w25-reconcile-stale-lease-") as root:
            cp = self.open_cp(root, fault=FaultPlan.for_fault("C4", "after_replace"))
            try:
                with self.assertRaises(InjectedCrash):
                    cp.run_p0(self.spec)
                identity = cp.executor.identity_for(dispatch_id)
                self.assertIsNotNone(identity)
                cp.expire_lease(self.spec["run_id"])
                cp.reclaim_lease(self.spec["run_id"], new_owner_id="new-owner")
                result = cp.reconcile_dispatch(self.spec["run_id"], dispatch_id, identity)
                self.assertEqual("RECOVERY_REQUIRED", result["status"])
            finally:
                cp.close()

    def test_p0_acceptance_and_next_card_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="w25-acceptance-") as root:
            cp = self.open_cp(root)
            try:
                cp.run_p0(self.spec)
                with self.assertRaises(P0Disabled):
                    cp.attempt_acceptance(self.spec["run_id"])
                self.assertEqual(0, cp.conn.execute("SELECT COUNT(*) FROM next_card_intents").fetchone()[0])
                self.assertEqual(0, cp.conn.execute("SELECT COUNT(*) FROM acceptance_txns WHERE state='COMMITTED'").fetchone()[0])
                with self.assertRaises(sqlite3.IntegrityError):
                    cp.conn.execute("UPDATE cards SET state='DONE' WHERE card_id=?", (self.spec["card_id"],))
                txn_id = cp.conn.execute("SELECT acceptance_txn_id FROM acceptance_txns LIMIT 1").fetchone()[0]
                with self.assertRaises(sqlite3.IntegrityError):
                    cp.conn.execute("UPDATE acceptance_txns SET state='COMMITTED' WHERE acceptance_txn_id=?", (txn_id,))
                with self.assertRaises(sqlite3.IntegrityError):
                    cp.conn.execute("UPDATE meta SET value='1' WHERE key='acceptance_enabled'")
                with self.assertRaises(sqlite3.IntegrityError):
                    cp.conn.execute("UPDATE meta SET key='acceptance_enabled' WHERE key='profile'")
                with self.assertRaises(sqlite3.IntegrityError):
                    cp.conn.execute("DELETE FROM meta WHERE key='acceptance_enabled'")
                with self.assertRaises(sqlite3.IntegrityError):
                    cp.conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('acceptance_enabled','1')")
                with self.assertRaises(sqlite3.IntegrityError):
                    cp.conn.execute("UPDATE acceptance_txns SET acceptance_enabled=1 WHERE acceptance_txn_id=?", (txn_id,))
            finally:
                cp.close()

    def test_forbidden_transition_and_idempotency_conflict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="w25-negative-") as root:
            cp = self.open_cp(root, fault=FaultPlan.for_fault("C3", "after_commit_marker"))
            try:
                with self.assertRaises(InjectedCrash):
                    cp.run_p0(self.spec)
                dispatch_id = self.dispatch_id()
                with self.assertRaises(StateConflict):
                    cp.transition_for_test("Dispatch", dispatch_id, "COMPLETED", self.spec["run_id"])
                cp.fault = FaultPlan.none()
                cp.recover(self.spec["run_id"], self.spec)
                changed = copy.deepcopy(self.spec)
                changed["command_hash"] = canonical_hash({"command": "different"})
                with self.assertRaises(StateConflict):
                    cp.run_p0(changed)
            finally:
                cp.close()

    def test_fake_executor_has_no_real_process_or_network_surface(self) -> None:
        source = (MODULE_ROOT / "control_plane.py").read_text(encoding="utf-8") + (MODULE_ROOT / "fake_executor.py").read_text(encoding="utf-8")
        for forbidden in ("import subprocess", "import socket", "Popen(", "os.kill(", "os.fork(", "/proc/"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
