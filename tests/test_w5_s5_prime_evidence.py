"""Adversarial W5-S5 real Prime filesystem evidence tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash
from modules.w5_dispatch_bridge_s0 import (
    PRIME_FILESYSTEM_EVIDENCE_SCHEMA,
    PrimeEvidenceError,
    build_prime_state_from_capture,
    capture_prime_evidence,
    evaluate_prime_binding_from_prime_evidence,
)
from test_w5_s3_hold_reconcile_resume import _verified_fixture


class W5S5PrimeEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "prime-root"
        self.run_id = "20261115T120000Z-s5-prime"
        self.run = self.root / "runtime" / "runs" / self.run_id
        self.card_root = self.root / "Plan" / "local-ai"
        self.packet_dir = self.root / "runtime" / "operator" / "resume-packet" / "20261115T120001Z-s5"
        self._build_fixture()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def _build_fixture(self) -> None:
        self.card_root.mkdir(parents=True)
        self.run.mkdir(parents=True)
        (self.run / "out").mkdir()
        self._write_json(
            self.card_root / "QUEUE.json",
            {"schema": 1, "project_id": "prime-root", "tasks": [{"id": "card-001", "status": "RUNNING", "card": "card-001.md", "depends_on": []}]},
        )
        (self.card_root / "card-001.md").write_text("# card-001\nS5 fixture\n", encoding="utf-8")
        session = {
            "state_schema_version": 2,
            "run_id": self.run_id,
            "project": "prime-root",
            "role": "mother-session",
            "status": "in_progress",
            "resume_gate": "open",
            "resume_gate_reason": "",
            "stop_reason": "",
            "hold_reason": "",
            "active_task_id": "card-001",
            "latest_task_id": 1,
            "latest_artifact_id": 1,
            "latest_event_id": 2,
            "updated_at": "2026-11-15T12:00:00Z",
        }
        self._write_json(self.run / "session_state.json", session)
        self._write_json(self.run / "tasks.json", {"tasks": [{"task_id": "card-001", "status": "in_progress"}]})
        (self.run / "events.jsonl").write_text(
            "{" + '"event_id":"event-001","type":"run_started"' + "}\n"
            "{" + '"event_id":"event-002","type":"task_added","task_id":"card-001"' + "}\n",
            encoding="utf-8",
        )
        artifact = self.run / "out" / "artifact.txt"
        artifact.write_text("artifact\n", encoding="utf-8")
        (self.run / "artifacts.jsonl").write_text(
            json.dumps({"artifact_id": "artifact-001", "run_id": self.run_id, "path": str(artifact), "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "size": artifact.stat().st_size}) + "\n",
            encoding="utf-8",
        )
        self._write_json(
            self.run / "writer" / "active.d" / "owner.json",
            {"schema_version": 1, "token": "writer-token-0123456789", "pid": 4242, "starttime": "start", "boot_id": "boot", "run_dir": str(self.run), "role": "mother-session", "expires_at_epoch": 4102444800},
        )
        self._write_json(
            self.root / "mcp" / "prime_adapter_manifest.json",
            {"schema_version": "prime-adapter-v1", "adapter_id": "optimismus-prime", "effects": {"read_only": True, "local_write": False, "external_action": False, "network": False}},
        )
        state_hash = hashlib.sha256((self.run / "session_state.json").read_bytes()).hexdigest()
        tasks_hash = hashlib.sha256((self.run / "tasks.json").read_bytes()).hexdigest()
        self._write_json(
            self.packet_dir / "resume_packet.json",
            {
                "schema_version": "prime-resume-packet-v1",
                "packet_id": self.packet_dir.name,
                "source": {"run_id": self.run_id, "run_dir": str(self.run), "session_state_sha256": state_hash, "tasks_sha256": tasks_hash},
                "state": {"status": "in_progress", "resume_gate": "open", "active_task_id": "card-001"},
                "next": {"action": "continue", "task_id": "card-001"},
            },
        )

    def _capture(self, **kwargs):
        return capture_prime_evidence(self.root, f"runtime/runs/{self.run_id}", **kwargs)

    def test_valid_capture_is_raw_byte_bound_and_stable(self) -> None:
        capture = self._capture()
        self.assertEqual(capture["schema_version"], PRIME_FILESYSTEM_EVIDENCE_SCHEMA)
        self.assertEqual(capture["capture_status"], "STABLE_READ_ONLY")
        self.assertTrue(capture["binding_projection"]["eligible"])
        self.assertEqual(capture["binding_projection"]["missing_proofs"], [])
        self.assertEqual(capture["files"]["session_state"]["sha256"], hashlib.sha256((self.run / "session_state.json").read_bytes()).hexdigest())
        self.assertTrue(all(value is False for value in capture["execution"].values()))
        self.assertEqual(capture, self._capture())

    def test_builder_is_explicit_and_produces_s4_state_only_when_eligible(self) -> None:
        capture = self._capture()
        identity = {"run_id": self.run_id, "card_id": "card-001", "attempt_id": "attempt-001", "dispatch_id": "dispatch-001"}
        state = build_prime_state_from_capture(capture, w5_identity=identity)
        self.assertEqual(state["schema_version"], "prime-resume-state-v1")
        self.assertEqual(state["active_task_sha256"], capture["files"]["active_card"]["sha256"])
        self.assertEqual(state["binding_id"], canonical_hash({"prime_run_id": self.run_id, "active_task_id": "card-001", "w5_identity": identity}))

    def test_missing_optional_authority_is_reported_not_invented(self) -> None:
        (self.run / "writer" / "active.d" / "owner.json").unlink()
        (self.root / "mcp" / "prime_adapter_manifest.json").unlink()
        for child in self.packet_dir.iterdir():
            child.unlink()
        self.packet_dir.rmdir()
        capture = self._capture()
        missing = set(capture["binding_projection"]["missing_proofs"])
        self.assertFalse(capture["binding_projection"]["eligible"])
        self.assertTrue({"WRITER_LEASE_NOT_OBSERVED", "POLICY_MISSING", "RESUME_PACKET_NOT_OBSERVED"} <= missing)
        with self.assertRaises(PrimeEvidenceError) as context:
            build_prime_state_from_capture(capture, w5_identity={"run_id": self.run_id, "card_id": "card-001", "attempt_id": "a", "dispatch_id": "d"})
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_BINDING_INELIGIBLE")

    def test_path_traversal_and_symlink_are_rejected(self) -> None:
        with self.assertRaises(PrimeEvidenceError) as traversal:
            capture_prime_evidence(self.root, f"runtime/runs/../runs/{self.run_id}")
        self.assertEqual(traversal.exception.code, "PRIME_EVIDENCE_PATH_ESCAPE")
        state = self.run / "session_state.json"
        replacement = self.root / "replacement-state.json"
        replacement.write_bytes(state.read_bytes())
        state.unlink()
        state.symlink_to(replacement)
        with self.assertRaises(PrimeEvidenceError) as symlink:
            self._capture()
        self.assertEqual(symlink.exception.code, "PRIME_EVIDENCE_PATH_SYMLINK")

    def test_root_symlink_is_rejected(self) -> None:
        alias = Path(self._tmp.name) / "prime-root-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(PrimeEvidenceError) as context:
            capture_prime_evidence(alias, f"runtime/runs/{self.run_id}")
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_ROOT_SYMLINK")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        (self.run / "session_state.json").write_text('{"run_id":"' + self.run_id + '","run_id":"forged"}\n', encoding="utf-8")
        with self.assertRaises(PrimeEvidenceError) as context:
            self._capture()
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_JSON_DUPLICATE_KEY")

    def test_toc_tou_hook_replacing_file_fails_closed(self) -> None:
        fired = False

        def hook(stage: str, relative_path: str | None) -> None:
            nonlocal fired
            if not fired and stage == "after_read" and relative_path == f"runtime/runs/{self.run_id}/session_state.json":
                fired = True
                state = self.run / "session_state.json"
                state.write_bytes(state.read_bytes() + b" ")

        with self.assertRaises(PrimeEvidenceError) as context:
            self._capture(hook=hook)
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_TOCTOU_DRIFT")

    def test_cross_file_drift_fails_closed_when_relationships_disagree(self) -> None:
        fired = False

        def hook(stage: str, relative_path: str | None) -> None:
            nonlocal fired
            if not fired and stage == "after_read" and relative_path == f"runtime/runs/{self.run_id}/session_state.json":
                fired = True
                self._write_json(self.run / "tasks.json", {"tasks": []})

        capture = self._capture(hook=hook)
        self.assertFalse(capture["binding_projection"]["eligible"])
        self.assertIn("ACTIVE_TASK_NOT_IN_TASK_LEDGER", capture["binding_projection"]["missing_proofs"])

    def test_finalization_hook_detects_late_change(self) -> None:
        fired = False

        def hook(stage: str, relative_path: str | None) -> None:
            nonlocal fired
            if not fired and stage == "before_finalize":
                fired = True
                queue = self.card_root / "QUEUE.json"
                queue.write_bytes(queue.read_bytes() + b" ")

        with self.assertRaises(PrimeEvidenceError) as context:
            self._capture(hook=hook)
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_SNAPSHOT_UNSTABLE")

    def test_json_whitespace_changes_raw_hash_and_capture_hash(self) -> None:
        first = self._capture()
        state = self.run / "session_state.json"
        state.write_bytes(state.read_bytes() + b"\n")
        second = self._capture()
        self.assertNotEqual(first["files"]["session_state"]["sha256"], second["files"]["session_state"]["sha256"])
        self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])

    def test_forged_capture_hash_cannot_be_projected(self) -> None:
        forged = copy.deepcopy(self._capture())
        forged["snapshot_sha256"] = "0" * 64
        with self.assertRaises(PrimeEvidenceError) as context:
            build_prime_state_from_capture(forged, w5_identity={"run_id": self.run_id, "card_id": "card-001", "attempt_id": "a", "dispatch_id": "d"})
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_BINDING_INELIGIBLE")

    def test_binding_adapter_converts_evidence_path_error_to_actionless_hold(self) -> None:
        helper, bundle, authority, data = _verified_fixture()
        try:
            result = evaluate_prime_binding_from_prime_evidence(
                data["cp"],
                data["control"]["run"]["run_id"],
                self.root,
                "../escape",
                now_epoch=data["cp"].clock.epoch(),
                w5_bundle=bundle,
                w5_authority=authority,
                w5_observation=data["observation"],
                source_root=REPO_ROOT,
            )
        finally:
            helper.doCleanups()
        self.assertEqual((result["binding_status"], result["reason"]), ("HOLD", "PRIME_EVIDENCE_PATH_ESCAPE"))
        self.assertFalse(result["resume_allowed"])
        self.assertIsNotNone(result["hrr"]["input_sha256"])
        self.assertTrue(all(value is False for value in result["execution"].values()))


if __name__ == "__main__":
    unittest.main()
