"""Contract and adversarial tests for the W5-to-local-Mother boundary."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = REPO_ROOT / "modules"
W5_ROOT = MODULE_ROOT / "w5_dispatch_bridge_s0"
MOTHER_ROOT = MODULE_ROOT / "local-mother-session"

import sys

sys.path.insert(0, str(REPO_ROOT))

from modules.w5_dispatch_bridge_s0 import DispatchBridgeResult  # noqa: E402
from modules.w5_dispatch_bridge_s0.mother_observation import (  # noqa: E402
    EXPECTED_SOURCE_ATTESTATION_HASH,
    MotherObservationError,
    build_mother_observation,
    verify_mother_observation,
)


SOURCE_HASH = EXPECTED_SOURCE_ATTESTATION_HASH


def verified_result() -> DispatchBridgeResult:
    return DispatchBridgeResult(
        status="BRIDGE_VERIFIED",
        bridge={
            "run_id": "run-001",
            "card_id": "card-001",
            "attempt_id": "attempt-001",
            "dispatch_id": "dispatch-001",
            "controller_claim": "C2_DISPATCH_CLAIMED",
            "worker_claim": "claim-001",
            "process_ack": "ack-001",
            "state": {
                "run": "DISPATCHING",
                "card": "CLAIMED",
                "attempt": "STARTING",
                "dispatch": "EXECUTOR_ACKED",
            },
            "source_attestation_hash": SOURCE_HASH,
        },
        replay={"schema": "w5-dispatch-replay.v1"},
    )


def blocked_result() -> DispatchBridgeResult:
    return DispatchBridgeResult(
        status="BLOCKED",
        findings=("ACK_NOT_CONFIRMED",),
        bridge={
            "run_id": "run-001",
            "card_id": "card-001",
            "attempt_id": "attempt-001",
            "dispatch_id": "dispatch-001",
            "state": {
                "run": "DISPATCHING",
                "card": "CLAIMED",
                "attempt": "ADMITTED",
                "dispatch": "SPAWN_REQUESTED",
            },
            "source_attestation_hash": SOURCE_HASH,
        },
    )


def load_session_module():
    spec = importlib.util.spec_from_file_location("prime_session_test", MOTHER_ROOT / "session.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class W5LocalMotherContractTests(unittest.TestCase):
    def test_verified_result_projects_to_read_only_observation(self):
        observation = build_mother_observation(verified_result())
        self.assertEqual(observation["status"], "BRIDGE_VERIFIED")
        self.assertEqual(observation["source_attestation_hash"], SOURCE_HASH)
        self.assertEqual(observation["identity"]["dispatch_id"], "dispatch-001")
        self.assertEqual(observation["state"]["dispatch"], "EXECUTOR_ACKED")
        self.assertEqual(observation["permission"], "read_only")
        self.assertEqual(observation["acceptance_status"], "pending")
        self.assertFalse(observation["external_action"])
        self.assertEqual(observation["execution"], {
            "process_start": False,
            "network": False,
            "acceptance": False,
            "next_card": False,
        })
        self.assertEqual(verify_mother_observation(observation), observation)

    def test_blocked_result_remains_blocked_and_carries_no_execution_rights(self):
        observation = build_mother_observation(blocked_result())
        self.assertEqual(observation["status"], "BLOCKED")
        self.assertEqual(observation["state"]["attempt"], "ADMITTED")
        self.assertEqual(observation["findings"], ["ACK_NOT_CONFIRMED"])
        self.assertTrue(all(value is False for value in observation["execution"].values()))
        self.assertEqual(verify_mother_observation(observation), observation)

    def test_invalid_upstream_result_is_safe_null_context(self):
        for status in ("INCOMPATIBLE_SOURCE", "INVALID_EVIDENCE"):
            observation = build_mother_observation(
                DispatchBridgeResult(status=status, findings=("source drift",))
            )
            self.assertIsNone(observation["identity"])
            self.assertIsNone(observation["state"])
            self.assertIsNone(observation["source_attestation_hash"])
            self.assertEqual(verify_mother_observation(observation), observation)

    def test_s0_and_result_schema_drift_are_rejected(self):
        s0_bridge = dict(verified_result().bridge or {})
        s0_bridge.pop("source_attestation_hash")
        with self.assertRaises(MotherObservationError):
            build_mother_observation(
                DispatchBridgeResult(
                    status="BRIDGE_VERIFIED", bridge=s0_bridge, replay={"schema": "replay"}
                )
            )
        malformed = verified_result().as_dict()
        malformed["unexpected"] = True
        with self.assertRaises(MotherObservationError):
            build_mother_observation(malformed)

        malformed = verified_result().as_dict()
        malformed["bridge"]["source_attestation_hash"] = "b" * 64
        with self.assertRaises(MotherObservationError):
            build_mother_observation(malformed)

        class MaliciousResult:
            called = False

            def as_dict(self):
                self.called = True
                raise AssertionError("must not execute arbitrary result methods")

        malicious = MaliciousResult()
        with self.assertRaises(MotherObservationError):
            build_mother_observation(malicious)
        self.assertFalse(malicious.called)
        malformed = verified_result().as_dict()
        malformed["accepted"] = True
        with self.assertRaises(MotherObservationError):
            build_mother_observation(malformed)

    def test_observation_tampering_and_blocked_c4_contamination_are_rejected(self):
        observation = build_mother_observation(blocked_result())
        tampered = json.loads(json.dumps(observation))
        tampered["execution"]["next_card"] = True
        with self.assertRaises(MotherObservationError):
            verify_mother_observation(tampered)

        tampered = json.loads(json.dumps(observation))
        tampered["external_action"] = True
        with self.assertRaises(MotherObservationError):
            verify_mother_observation(tampered)

        c4 = blocked_result().as_dict()
        c4["bridge"]["process_ack"] = "late-ack"
        with self.assertRaises(MotherObservationError):
            build_mother_observation(c4)

        contaminated = blocked_result()
        contaminated = DispatchBridgeResult(
            status=contaminated.status,
            findings=("ACK_NOT_CONFIRMED", "process_ack=late"),
            bridge=contaminated.bridge,
        )
        with self.assertRaises(MotherObservationError):
            build_mother_observation(contaminated)

        tampered = json.loads(json.dumps(observation))
        tampered["state"]["dispatch"] = "EXECUTOR_ACKED"
        with self.assertRaises(MotherObservationError):
            verify_mother_observation(tampered)

    def test_reader_is_optional_but_strict_and_session_helper_uses_it(self):
        session = load_session_module()
        with tempfile.TemporaryDirectory(prefix="w5-mother-") as directory:
            runs_root = Path(directory) / "runs"
            run = runs_root / "run-001"
            run.mkdir(parents=True)
            self.assertIsNone(
                session.load_w5_observation(
                    REPO_ROOT, run, MOTHER_ROOT, runs_root=runs_root
                )
            )
            observation = build_mother_observation(verified_result())
            (run / "w5-observation.json").write_text(
                json.dumps(observation), encoding="utf-8"
            )
            (run / "w5-result.json").write_text(
                json.dumps(verified_result().as_dict()), encoding="utf-8"
            )
            self.assertEqual(
                session.load_w5_observation(
                    REPO_ROOT, run, MOTHER_ROOT, runs_root=runs_root
                ),
                observation,
            )
            outside = run.parent / "w5-outside.json"
            outside.write_text(json.dumps(observation), encoding="utf-8")
            (run / "w5-observation.json").unlink()
            (run / "w5-observation.json").symlink_to(outside)
            with self.assertRaises(ValueError):
                session.load_w5_observation(
                    REPO_ROOT, run, MOTHER_ROOT, runs_root=runs_root
                )

    def test_prepare_writes_observation_to_cockpit_and_source_snapshot(self):
        session = load_session_module()
        with tempfile.TemporaryDirectory(prefix="w5-prepare-") as directory:
            project = Path(directory) / "project"
            run = project / "work/prime-local/runs/run-001"
            run.mkdir(parents=True)
            observation = build_mother_observation(verified_result())
            (run / "w5-observation.json").write_text(
                json.dumps(observation), encoding="utf-8"
            )
            (run / "w5-result.json").write_text(
                json.dumps(verified_result().as_dict()), encoding="utf-8"
            )
            argv = [
                "session.py",
                "prepare",
                str(project),
                str(REPO_ROOT),
                str(run),
                "",
                str(MOTHER_ROOT),
            ]
            with patch.dict(os.environ, {}, clear=True), patch.object(session.sys, "argv", argv):
                session.main()
            cockpit = (run / "cockpit.md").read_text(encoding="utf-8")
            self.assertIn("W5-Observation (nur lesender Hintergrundbeleg)", cockpit)
            self.assertIn('"next_card": false', cockpit)
            sources = json.loads((run / "sources.json").read_text(encoding="utf-8"))
            self.assertTrue(any(item["path"] == str(run / "w5-observation.json") for item in sources))

    def test_reader_rejects_foreign_roots_loader_aliases_pair_drift_and_oversize(self):
        session = load_session_module()
        with tempfile.TemporaryDirectory(prefix="w5-boundary-") as directory:
            base = Path(directory)
            runs_root = base / "runs"
            run = runs_root / "run-001"
            run.mkdir(parents=True)
            observation = build_mother_observation(verified_result())
            (run / "w5-observation.json").write_text(
                json.dumps(observation), encoding="utf-8"
            )
            (run / "w5-result.json").write_text(
                json.dumps(verified_result().as_dict()), encoding="utf-8"
            )

            foreign = base / "foreign"
            foreign.mkdir()
            with self.assertRaises(ValueError):
                session.load_w5_observation(
                    REPO_ROOT, foreign, MOTHER_ROOT, runs_root=runs_root
                )

            alias = base / "runs-alias"
            alias.symlink_to(runs_root, target_is_directory=True)
            with self.assertRaises(ValueError):
                session.load_w5_observation(
                    REPO_ROOT, alias / "run-001", MOTHER_ROOT, runs_root=runs_root
                )

            module_alias = base / "module-alias"
            module_alias.symlink_to(MOTHER_ROOT, target_is_directory=True)
            with self.assertRaises(ValueError):
                session.load_w5_observation(
                    REPO_ROOT, run, module_alias, runs_root=runs_root
                )

            prime_alias = base / "prime-alias"
            prime_alias.symlink_to(REPO_ROOT, target_is_directory=True)
            with self.assertRaises(ValueError):
                session.load_w5_observation(
                    prime_alias, run, MOTHER_ROOT, runs_root=runs_root
                )

            (run / "w5-result.json").write_text(
                json.dumps(blocked_result().as_dict()), encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                session.load_w5_observation(
                    REPO_ROOT, run, MOTHER_ROOT, runs_root=runs_root
                )

            (run / "w5-result.json").write_text(
                json.dumps(verified_result().as_dict()), encoding="utf-8"
            )
            (run / "w5-observation.json").write_bytes(b"{" + b'"x":"' + b"a" * 70000 + b'"}')
            with self.assertRaises(ValueError):
                session.load_w5_observation(
                    REPO_ROOT, run, MOTHER_ROOT, runs_root=runs_root
                )

    def test_adapter_has_no_execution_or_transport_implementation(self):
        source = (W5_ROOT / "mother_observation.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket", "urllib", "Popen", "ledger"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
