"""Adversarial W5-S8 read-only external-head/CAS-precondition tests."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash, canonical_json  # noqa: E402
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    PRIME_WRITER_ANCHOR_SCHEMA,
    PRIME_WRITER_HEAD_SCHEMA,
    capture_consistent_control_snapshot,
    capture_prime_evidence_v2,
    configure_trusted_prime_anchor,
    configure_trusted_prime_head,
    evaluate_prime_writer_head,
    freeze_trusted_prime_anchors,
    freeze_trusted_prime_heads,
    verify_prime_writer_head,
)
from test_w5_s3_hold_reconcile_resume import _verified_fixture  # noqa: E402
from test_w5_s6_writer_manifest import _ManifestFixture  # noqa: E402


ANCHOR_AUTHORITY_ID = "prime-anchor-test-authority"
ANCHOR_KEY_ID = "prime-anchor-test-key"
ANCHOR_KEY = b"prime-anchor-test-secret-2026"
HEAD_AUTHORITY_ID = "prime-head-test-authority"
HEAD_KEY_ID = "prime-head-test-key"
HEAD_KEY = b"prime-head-test-secret-2026"


def _seal_anchor(capture: dict) -> dict:
    writer = capture["writer_snapshot"]
    root = capture["root"]
    payload = {
        "evidence_schema": capture["schema_version"],
        "snapshot_sha256": capture["snapshot_sha256"],
        "run_id": root["run_id"],
        "run_relative_path": root["run_relative_path"],
        "root_binding_sha256": root["root_binding_sha256"],
        "generation": writer["generation"],
        "generation_id": writer["generation_id"],
        "covered_source_set_sha256": writer["covered_source_set_sha256"],
    }
    anchor = {
        "schema_version": PRIME_WRITER_ANCHOR_SCHEMA,
        "authority_id": ANCHOR_AUTHORITY_ID,
        "key_id": ANCHOR_KEY_ID,
        "payload": payload,
        "payload_sha256": canonical_hash(payload),
    }
    anchor["authority_mac"] = hmac.new(
        ANCHOR_KEY,
        canonical_json(anchor).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return anchor


def _control_values(control_capture: dict) -> tuple[dict, str]:
    runtime = control_capture["runtime"]
    run = runtime["run"]
    card = runtime["cards"][0]
    attempt = runtime["attempts"][0]
    dispatch = runtime["dispatches"][0]
    lease_claim = canonical_hash(
        {
            "run_id": run["run_id"],
            "owner_id": run["lease_owner_id"],
            "token": run["lease_token"],
            "fencing_epoch": run["fencing_epoch"],
            "expires_at": run["lease_expires_at"],
        }
    )
    return (
        {
            "run_id": run["run_id"],
            "card_id": card["card_id"],
            "attempt_id": attempt["attempt_id"],
            "dispatch_id": dispatch["dispatch_id"],
            "runtime_sha256": control_capture["runtime_sha256"],
            "projection_sha256": control_capture["projection_sha256"],
            "capture_sha256": canonical_hash(control_capture),
            "queue_sha256": run["queue_hash"],
            "policy_sha256": run["policy_hash"],
            "card_hash": card["card_hash"],
            "lease_claim_sha256": lease_claim,
            "lease_owner_id": run["lease_owner_id"],
            "lease_expires_at": run["lease_expires_at"],
            "fencing_epoch": run["fencing_epoch"],
        },
        lease_claim,
    )


def _seal_head(capture: dict, control_capture: dict, anchor: dict, *, sequence: int = 42, previous: str | None = "a" * 64) -> dict:
    control, _ = _control_values(control_capture)
    files = capture["files"]
    payload = {
        "anchor_sha256": canonical_hash(anchor),
        "prime_run_id": capture["root"]["run_id"],
        "prime_root_binding_sha256": capture["root"]["root_binding_sha256"],
        "prime_snapshot_sha256": capture["snapshot_sha256"],
        "prime_generation": capture["writer_snapshot"]["generation"],
        "prime_generation_id": capture["writer_snapshot"]["generation_id"],
        "prime_active_task_id": capture["parsed"]["session_state"]["active_task_id"],
        "prime_queue_sha256": files["queue"]["sha256"],
        "prime_policy_sha256": files["policy"]["sha256"],
        "prime_active_card_sha256": files["active_card"]["sha256"],
        "prime_resume_packet_sha256": files["resume_packet"]["sha256"],
        "prime_writer_lease_sha256": files["writer_lease"]["sha256"],
        "w5_run_id": control["run_id"],
        "w5_card_id": control["card_id"],
        "w5_attempt_id": control["attempt_id"],
        "w5_dispatch_id": control["dispatch_id"],
        "w5_runtime_sha256": control["runtime_sha256"],
        "w5_projection_sha256": control["projection_sha256"],
        "w5_capture_sha256": control["capture_sha256"],
        "w5_queue_hash": control["queue_sha256"],
        "w5_policy_hash": control["policy_sha256"],
        "w5_card_hash": control["card_hash"],
        "w5_lease_claim_sha256": control["lease_claim_sha256"],
        "w5_lease_owner_id": control["lease_owner_id"],
        "w5_lease_expires_at": control["lease_expires_at"],
        "w5_fencing_epoch": control["fencing_epoch"],
        "head_sequence": sequence,
        "previous_head_sha256": previous,
    }
    head = {
        "schema_version": PRIME_WRITER_HEAD_SCHEMA,
        "protocol": "hmac-sha256-canonical-json-v1",
        "authority_id": HEAD_AUTHORITY_ID,
        "key_id": HEAD_KEY_ID,
        "payload": payload,
        "payload_sha256": canonical_hash(payload),
    }
    head["authority_mac"] = hmac.new(
        HEAD_KEY,
        canonical_json(head).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return head


class W5S8ExternalHeadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configure_trusted_prime_anchor(
            authority_id=ANCHOR_AUTHORITY_ID,
            key_id=ANCHOR_KEY_ID,
            key=ANCHOR_KEY,
        )
        freeze_trusted_prime_anchors()
        configure_trusted_prime_head(
            authority_id=HEAD_AUTHORITY_ID,
            key_id=HEAD_KEY_ID,
            key=HEAD_KEY,
        )
        freeze_trusted_prime_heads()

    def setUp(self) -> None:
        self.fixture = _ManifestFixture()
        helper, bundle, authority, data = _verified_fixture()
        self.helper = helper
        self.data = data
        card_id = data["control"]["card"]["card_id"]
        session_path = self.fixture.run / "session_state.json"
        session = json.loads(session_path.read_text(encoding="utf-8"))
        session["active_task_id"] = card_id
        self.fixture.write_json(session_path, session)
        self.fixture.write_json(self.fixture.run / "tasks.json", {"tasks": [{"task_id": card_id, "status": "in_progress"}]})
        queue = json.loads((self.fixture.card_root / "QUEUE.json").read_text(encoding="utf-8"))
        queue["tasks"][0]["id"] = card_id
        self.fixture.write_json(self.fixture.card_root / "QUEUE.json", queue)
        packet = json.loads((self.fixture.packet_dir / "resume_packet.json").read_text(encoding="utf-8"))
        packet["source"]["session_state_sha256"] = hashlib.sha256(session_path.read_bytes()).hexdigest()
        packet["source"]["tasks_sha256"] = hashlib.sha256((self.fixture.run / "tasks.json").read_bytes()).hexdigest()
        packet["state"]["active_task_id"] = card_id
        packet["next"]["task_id"] = card_id
        self.fixture.write_json(self.fixture.packet_dir / "resume_packet.json", packet)
        self.fixture.install_manifest(generation_id="gen-000007", generation=7)
        self.capture = capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}")
        self.control_capture = capture_consistent_control_snapshot(data["cp"], data["control"]["run"]["run_id"])
        self.anchor = _seal_anchor(self.capture)
        self.head = _seal_head(self.capture, self.control_capture, self.anchor)
        self.expected_identity = {
            "run_id": data["control"]["run"]["run_id"],
            "card_id": data["control"]["card"]["card_id"],
            "attempt_id": data["control"]["attempt"]["attempt_id"],
            "dispatch_id": data["control"]["dispatch"]["dispatch_id"],
        }

    def tearDown(self) -> None:
        self.fixture.close()
        self.helper.doCleanups()

    def kwargs(self) -> dict:
        return {
            "last_accepted_generation": 6,
            "last_accepted_head_sequence": 41,
            "last_accepted_head_sha256": "a" * 64,
            "expected_current_head": {
                "head_sequence": 42,
                "head_sha256": canonical_hash(self.head),
            },
            "expected_prime_run_id": self.fixture.run_id,
            "expected_w5_identity": self.expected_identity,
        }

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["external_action"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_valid_head_is_current_read_only_and_stable(self) -> None:
        first = verify_prime_writer_head(self.capture, self.anchor, self.control_capture, self.head, **self.kwargs())
        second = verify_prime_writer_head(self.capture, self.anchor, self.control_capture, self.head, **self.kwargs())
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "PRECONDITION_SATISFIED_READ_ONLY")
        self.assertTrue(first["current_head"])
        self.assertTrue(first["generation_bound"])
        self.assertTrue(first["queue_bound"])
        self.assertTrue(first["fencing_bound"])
        self.assert_actionless(first)

    def test_missing_current_head_is_not_a_cas_precondition(self) -> None:
        args = self.kwargs()
        args["expected_current_head"] = None
        result = evaluate_prime_writer_head(self.capture, self.anchor, self.control_capture, self.head, **args)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "PRIME_HEAD_CURRENT_HEAD_UNPROVEN")
        self.assert_actionless(result)

    def test_current_head_mismatch_is_hold(self) -> None:
        args = self.kwargs()
        args["expected_current_head"] = {"head_sequence": 42, "head_sha256": "f" * 64}
        result = evaluate_prime_writer_head(self.capture, self.anchor, self.control_capture, self.head, **args)
        self.assertEqual(result["reason"], "PRIME_HEAD_CURRENT_HEAD_MISMATCH")
        self.assert_actionless(result)

    def test_generation_and_head_replay_are_rejected(self) -> None:
        args = self.kwargs()
        args["last_accepted_generation"] = 7
        result = evaluate_prime_writer_head(self.capture, self.anchor, self.control_capture, self.head, **args)
        self.assertEqual(result["reason"], "PRIME_HEAD_ANCHOR_INVALID")
        self.assert_actionless(result)

        args = self.kwargs()
        args["last_accepted_head_sequence"] = 42
        args["last_accepted_head_sha256"] = canonical_hash(self.head)
        result = evaluate_prime_writer_head(self.capture, self.anchor, self.control_capture, self.head, **args)
        self.assertEqual(result["reason"], "PRIME_HEAD_REPLAY_OR_DOWNGRADE")
        self.assert_actionless(result)

    def test_parent_chain_and_unknown_head_key_fail_closed(self) -> None:
        forged = copy.deepcopy(self.head)
        forged["payload"]["previous_head_sha256"] = "b" * 64
        forged["payload_sha256"] = canonical_hash(forged["payload"])
        forged["authority_mac"] = hmac.new(HEAD_KEY, canonical_json({key: forged[key] for key in ("schema_version", "protocol", "authority_id", "key_id", "payload", "payload_sha256")}).encode("utf-8"), hashlib.sha256).hexdigest()
        result = evaluate_prime_writer_head(self.capture, self.anchor, self.control_capture, forged, **self.kwargs())
        self.assertEqual(result["reason"], "PRIME_HEAD_PARENT_MISMATCH")
        self.assert_actionless(result)

        unknown = copy.deepcopy(self.head)
        unknown["authority_id"] = "prime-head-rogue"
        unknown["key_id"] = "prime-head-rogue"
        result = evaluate_prime_writer_head(self.capture, self.anchor, self.control_capture, unknown, **self.kwargs())
        self.assertEqual(result["reason"], "PRIME_HEAD_TRUST_ROOT_UNKNOWN")
        self.assert_actionless(result)

    def test_signed_queue_and_fence_mutations_are_not_accepted(self) -> None:
        forged = copy.deepcopy(self.head)
        forged["payload"]["w5_queue_hash"] = "forged-queue-hash"
        forged["payload"]["w5_fencing_epoch"] = 2
        forged["payload_sha256"] = canonical_hash(forged["payload"])
        forged["authority_mac"] = hmac.new(HEAD_KEY, canonical_json({key: forged[key] for key in ("schema_version", "protocol", "authority_id", "key_id", "payload", "payload_sha256")}).encode("utf-8"), hashlib.sha256).hexdigest()
        result = evaluate_prime_writer_head(self.capture, self.anchor, self.control_capture, forged, **self.kwargs())
        self.assertEqual(result["reason"], "PRIME_HEAD_W5_EVIDENCE_MISMATCH")
        self.assert_actionless(result)

    def test_expired_control_lease_is_hold_without_mutation(self) -> None:
        stale = copy.deepcopy(self.control_capture)
        expiry = stale["clock_after_epoch"]
        stale["runtime"]["run"]["lease_expires_at"] = expiry
        stale["runtime"]["dispatches"][0]["lease_expires_at"] = expiry
        stale["runtime_sha256"] = canonical_hash(stale["runtime"])
        before = copy.deepcopy(stale)
        result = evaluate_prime_writer_head(self.capture, self.anchor, stale, self.head, **self.kwargs())
        self.assertEqual(result["reason"], "PRIME_HEAD_LEASE_EXPIRED")
        self.assert_actionless(result)
        self.assertEqual(stale, before)

    def test_duplicate_raw_head_and_missing_w5_identity_hold(self) -> None:
        raw = '{"schema_version":"prime-writer-head-v1","schema_version":"forged"}'
        result = evaluate_prime_writer_head(self.capture, self.anchor, self.control_capture, raw, **self.kwargs())
        self.assertEqual(result["reason"], "PRIME_HEAD_JSON_DUPLICATE_KEY")
        self.assert_actionless(result)

        args = self.kwargs()
        args["expected_w5_identity"] = None
        result = evaluate_prime_writer_head(self.capture, self.anchor, self.control_capture, self.head, **args)
        self.assertEqual(result["reason"], "PRIME_HEAD_W5_IDENTITY_UNBOUND")
        self.assert_actionless(result)

    def test_first_head_requires_sequence_one_and_no_parent(self) -> None:
        first = _seal_head(self.capture, self.control_capture, self.anchor, sequence=1, previous=None)
        args = self.kwargs()
        args["last_accepted_head_sequence"] = 0
        args["last_accepted_head_sha256"] = None
        args["expected_current_head"] = {"head_sequence": 1, "head_sha256": canonical_hash(first)}
        result = verify_prime_writer_head(self.capture, self.anchor, self.control_capture, first, **args)
        self.assertEqual(result["head_sequence"], 1)
        self.assert_actionless(result)


if __name__ == "__main__":
    unittest.main()
