"""Adversarial W5-S6 cooperative writer-manifest tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w5_dispatch_bridge_s0 import (
    PRIME_FILESYSTEM_EVIDENCE_V2_SCHEMA,
    PrimeEvidenceError,
    build_prime_state_from_evidence_v2,
    build_writer_manifest_from_capture,
    capture_prime_evidence,
    capture_prime_evidence_v2,
    evaluate_prime_binding_from_prime_evidence_v2,
)
from test_w5_s3_hold_reconcile_resume import _verified_fixture


class _ManifestFixture:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "prime-root"
        self.run_id = "20261115T120000Z-s6-prime"
        self.run = self.root / "runtime" / "runs" / self.run_id
        self.card_root = self.root / "Plan" / "local-ai"
        self.packet_dir = self.root / "runtime" / "operator" / "resume-packet" / "20261115T120001Z-s6"
        self.build()

    def close(self) -> None:
        self.tmp.cleanup()

    def write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def build(self) -> None:
        self.card_root.mkdir(parents=True)
        self.run.mkdir(parents=True)
        (self.run / "out").mkdir()
        self.write_json(
            self.card_root / "QUEUE.json",
            {"schema": 1, "project_id": "prime-root", "tasks": [{"id": "card-001", "status": "RUNNING", "card": "card-001.md", "depends_on": []}]},
        )
        (self.card_root / "card-001.md").write_text("# card-001\nS6 fixture\n", encoding="utf-8")
        self.write_json(
            self.run / "session_state.json",
            {
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
            },
        )
        self.write_json(self.run / "tasks.json", {"tasks": [{"task_id": "card-001", "status": "in_progress"}]})
        (self.run / "events.jsonl").write_text(
            '{"event_id":"event-001","type":"run_started"}\n'
            '{"event_id":"event-002","type":"task_added","task_id":"card-001"}\n',
            encoding="utf-8",
        )
        artifact = self.run / "out" / "artifact.txt"
        artifact.write_text("artifact\n", encoding="utf-8")
        (self.run / "artifacts.jsonl").write_text(
            json.dumps({"artifact_id": "artifact-001", "run_id": self.run_id, "path": str(artifact), "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "size": artifact.stat().st_size}) + "\n",
            encoding="utf-8",
        )
        self.write_json(
            self.run / "writer" / "active.d" / "owner.json",
            {"schema_version": 1, "token": "writer-token-0123456789", "pid": 4242, "starttime": "start", "boot_id": "boot", "run_dir": str(self.run), "role": "mother-session", "expires_at_epoch": 4102444800},
        )
        self.write_json(
            self.root / "mcp" / "prime_adapter_manifest.json",
            {"schema_version": "prime-adapter-v1", "adapter_id": "optimismus-prime", "effects": {"read_only": True, "local_write": False, "external_action": False, "network": False}},
        )
        state_hash = hashlib.sha256((self.run / "session_state.json").read_bytes()).hexdigest()
        tasks_hash = hashlib.sha256((self.run / "tasks.json").read_bytes()).hexdigest()
        self.write_json(
            self.packet_dir / "resume_packet.json",
            {
                "schema_version": "prime-resume-packet-v1",
                "packet_id": self.packet_dir.name,
                "source": {"run_id": self.run_id, "run_dir": str(self.run), "session_state_sha256": state_hash, "tasks_sha256": tasks_hash},
                "state": {"status": "in_progress", "resume_gate": "open", "active_task_id": "card-001"},
                "next": {"action": "continue", "task_id": "card-001"},
            },
        )

    def capture(self) -> dict:
        return capture_prime_evidence(self.root, f"runtime/runs/{self.run_id}")

    def install_manifest(self, *, generation_id: str = "gen-000001", generation: int = 1) -> dict:
        manifest = build_writer_manifest_from_capture(self.capture(), generation_id=generation_id, generation=generation)
        self.write_json(self.run / "writer" / "snapshot-manifest.json", manifest)
        return manifest


class W5S6WriterManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _ManifestFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_matched_manifest_is_stable_and_explicitly_untrusted(self) -> None:
        self.fixture.install_manifest()
        first = capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}")
        second = capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}")
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], PRIME_FILESYSTEM_EVIDENCE_V2_SCHEMA)
        self.assertEqual(first["writer_snapshot"]["status"], "MATCHED")
        self.assertTrue(first["writer_snapshot"]["coherent"])
        self.assertFalse(first["writer_snapshot"]["trusted"])
        self.assertTrue(first["binding_projection"]["eligible"])
        self.assertTrue(all(value is False for value in first["execution"].values()))

    def test_source_set_mismatch_fails_eligibility_without_rewriting_manifest(self) -> None:
        original_manifest = self.fixture.install_manifest()
        tasks = self.fixture.run / "tasks.json"
        tasks.write_bytes(tasks.read_bytes() + b"\n")
        capture = capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}")
        self.assertEqual(capture["writer_snapshot"]["status"], "SOURCE_SET_MISMATCH")
        self.assertFalse(capture["writer_snapshot"]["coherent"])
        self.assertFalse(capture["binding_projection"]["eligible"])
        self.assertIn("PRIME_EVIDENCE_WRITER_GENERATION_MISMATCH", capture["binding_projection"]["missing_proofs"])
        self.assertEqual(json.loads((self.fixture.run / "writer" / "snapshot-manifest.json").read_text()), original_manifest)

    def test_run_and_root_bindings_are_checked(self) -> None:
        manifest = self.fixture.install_manifest()
        forged = copy.deepcopy(manifest)
        forged["run_id"] = "foreign-run"
        self.fixture.write_json(self.fixture.run / "writer" / "snapshot-manifest.json", forged)
        capture = capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}")
        self.assertEqual(capture["writer_snapshot"]["status"], "SOURCE_SET_MISMATCH")
        self.assertFalse(capture["binding_projection"]["eligible"])

    def test_manifest_duplicate_keys_are_rejected(self) -> None:
        self.fixture.install_manifest()
        path = self.fixture.run / "writer" / "snapshot-manifest.json"
        path.write_text('{"schema_version":"prime-writer-manifest-v1","schema_version":"forged"}\n', encoding="utf-8")
        with self.assertRaises(PrimeEvidenceError) as context:
            capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}")
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_JSON_DUPLICATE_KEY")

    def test_manifest_source_change_is_detected_as_drift(self) -> None:
        self.fixture.install_manifest()
        fired = False

        def hook(stage: str, relative_path: str | None) -> None:
            nonlocal fired
            if not fired and stage == "after_read" and relative_path == f"runtime/runs/{self.fixture.run_id}/writer/snapshot-manifest.json":
                fired = True
                tasks = self.fixture.run / "tasks.json"
                tasks.write_bytes(tasks.read_bytes() + b" ")

        with self.assertRaises(PrimeEvidenceError) as context:
            capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}", manifest_hook=hook)
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_WRITER_MANIFEST_DRIFT")

    def test_late_manifest_change_is_detected(self) -> None:
        self.fixture.install_manifest()
        fired = False

        def hook(stage: str, _relative_path: str | None) -> None:
            nonlocal fired
            if not fired and stage == "before_finalize":
                fired = True
                path = self.fixture.run / "writer" / "snapshot-manifest.json"
                path.write_bytes(path.read_bytes() + b" ")

        with self.assertRaises(PrimeEvidenceError) as context:
            capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}", manifest_hook=hook)
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_WRITER_MANIFEST_DRIFT")

    def test_missing_manifest_does_not_change_v1_but_blocks_v2(self) -> None:
        v1 = self.fixture.capture()
        self.assertTrue(v1["binding_projection"]["eligible"])
        with self.assertRaises(PrimeEvidenceError) as context:
            capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}")
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_WRITER_GENERATION_NOT_OBSERVED")

    def test_v2_builder_keeps_s4_shape_and_can_require_explicit_run(self) -> None:
        self.fixture.install_manifest()
        capture = capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}")
        state = build_prime_state_from_evidence_v2(
            capture,
            w5_identity={"run_id": "w5-run", "card_id": "card-001", "attempt_id": "attempt-001", "dispatch_id": "dispatch-001"},
            expected_prime_run_id=self.fixture.run_id,
        )
        self.assertEqual(state["schema_version"], "prime-resume-state-v1")
        with self.assertRaises(PrimeEvidenceError) as context:
            build_prime_state_from_evidence_v2(
                capture,
                w5_identity={"run_id": "w5-run", "card_id": "card-001", "attempt_id": "attempt-001", "dispatch_id": "dispatch-001"},
                expected_prime_run_id="foreign-run",
            )
        self.assertEqual(context.exception.code, "PRIME_EVIDENCE_RUN_BINDING_MISMATCH")

    def test_v2_binding_never_promotes_self_attestation_to_resume(self) -> None:
        helper, bundle, authority, data = _verified_fixture()
        card_id = data["control"]["card"]["card_id"]
        session_path = self.fixture.run / "session_state.json"
        session = json.loads(session_path.read_text())
        session["active_task_id"] = card_id
        self.fixture.write_json(session_path, session)
        self.fixture.write_json(self.fixture.run / "tasks.json", {"tasks": [{"task_id": card_id, "status": "in_progress"}]})
        queue = json.loads((self.fixture.card_root / "QUEUE.json").read_text())
        queue["tasks"][0]["id"] = card_id
        self.fixture.write_json(self.fixture.card_root / "QUEUE.json", queue)
        packet = json.loads((self.fixture.packet_dir / "resume_packet.json").read_text())
        packet["source"]["session_state_sha256"] = hashlib.sha256(session_path.read_bytes()).hexdigest()
        packet["source"]["tasks_sha256"] = hashlib.sha256((self.fixture.run / "tasks.json").read_bytes()).hexdigest()
        packet["state"]["active_task_id"] = card_id
        packet["next"]["task_id"] = card_id
        self.fixture.write_json(self.fixture.packet_dir / "resume_packet.json", packet)
        self.fixture.install_manifest()
        try:
            with patch(
                "modules.w5_dispatch_bridge_s0.prime_binding.evaluate_prime_binding",
                return_value={
                    "binding_status": "BOUND_READ_ONLY",
                    "reason": "BOUND_RESUME",
                    "resume_allowed": True,
                    "execution": {"resume": False, "reconcile": False, "mutation": False, "network": False},
                },
            ):
                result = evaluate_prime_binding_from_prime_evidence_v2(
                    data["cp"],
                    data["control"]["run"]["run_id"],
                    self.fixture.root,
                    f"runtime/runs/{self.fixture.run_id}",
                    now_epoch=data["cp"].clock.epoch(),
                    w5_bundle=bundle,
                    w5_authority=authority,
                    w5_observation=data["observation"],
                    expected_prime_run_id=self.fixture.run_id,
                    source_root=REPO_ROOT,
                )
        finally:
            helper.doCleanups()
        self.assertEqual(result["binding_status"], "HOLD")
        self.assertEqual(result["reason"], "PRIME_EVIDENCE_WRITER_ATTESTATION_UNTRUSTED")
        self.assertFalse(result["resume_allowed"])
        self.assertTrue(all(value is False for value in result["execution"].values()))


if __name__ == "__main__":
    unittest.main()
