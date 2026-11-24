"""Adversarial W5-S7 external-anchor verification tests."""

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
    PrimeAnchorError,
    configure_trusted_prime_anchor,
    evaluate_prime_external_anchor,
    freeze_trusted_prime_anchors,
    capture_prime_evidence_v2,
    verify_prime_external_anchor,
)
from test_w5_s6_writer_manifest import _ManifestFixture  # noqa: E402


AUTHORITY_ID = "prime-anchor-test-authority"
KEY_ID = "prime-anchor-test-key"
KEY = b"prime-anchor-test-secret-2026"


def _seal_anchor(capture: dict, *, key: bytes = KEY, authority_id: str = AUTHORITY_ID, key_id: str = KEY_ID) -> dict:
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
        "authority_id": authority_id,
        "key_id": key_id,
        "payload": payload,
        "payload_sha256": canonical_hash(payload),
    }
    anchor["authority_mac"] = hmac.new(
        key,
        canonical_json(anchor).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return anchor


class W5S7ExternalAnchorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configure_trusted_prime_anchor(authority_id=AUTHORITY_ID, key_id=KEY_ID, key=KEY)
        freeze_trusted_prime_anchors()

    def setUp(self) -> None:
        self.fixture = _ManifestFixture()
        self.fixture.install_manifest(generation_id="gen-000007", generation=7)
        self.capture = capture_prime_evidence_v2(self.fixture.root, f"runtime/runs/{self.fixture.run_id}")

    def tearDown(self) -> None:
        self.fixture.close()

    def anchor(self) -> dict:
        return _seal_anchor(self.capture)

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["external_action"])
        self.assertFalse(result["resume_allowed"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_valid_external_anchor_is_current_and_stable_without_authority(self) -> None:
        anchor = self.anchor()
        first = verify_prime_external_anchor(
            self.capture,
            anchor,
            last_accepted_generation=0,
            expected_prime_run_id=self.fixture.run_id,
        )
        second = verify_prime_external_anchor(
            self.capture,
            anchor,
            last_accepted_generation=0,
            expected_prime_run_id=self.fixture.run_id,
        )
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "MATCHED_CURRENT")
        self.assertTrue(first["trusted"])
        self.assertTrue(first["fresh"])
        self.assertTrue(first["replay_protected"])
        self.assertFalse(self.capture["writer_snapshot"]["trusted"])
        self.assert_actionless(first)

    def test_missing_external_generation_is_hold_and_replay_unproven(self) -> None:
        result = evaluate_prime_external_anchor(self.capture, self.anchor(), last_accepted_generation=None)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "PRIME_ANCHOR_REPLAY_UNPROVEN")
        self.assert_actionless(result)

    def test_unknown_key_cannot_enrol_itself(self) -> None:
        anchor = _seal_anchor(self.capture, authority_id="prime-anchor-rogue-authority", key_id="prime-anchor-rogue-key")
        result = evaluate_prime_external_anchor(self.capture, anchor, last_accepted_generation=0)
        self.assertEqual(result["reason"], "PRIME_ANCHOR_TRUST_ROOT_UNKNOWN")
        self.assert_actionless(result)
        with self.assertRaises(RuntimeError):
            configure_trusted_prime_anchor(
                authority_id="prime-anchor-rogue-authority",
                key_id="prime-anchor-rogue-key",
                key=b"rogue-secret-key-2026",
            )

    def test_missing_anchor_is_hold_without_v2_fallback(self) -> None:
        result = evaluate_prime_external_anchor(self.capture, None, last_accepted_generation=0)
        self.assertEqual(result["reason"], "PRIME_ANCHOR_NOT_OBSERVED")
        self.assert_actionless(result)
        self.assertFalse(self.capture["writer_snapshot"]["trusted"])

    def test_payload_hash_and_mac_drift_fail_closed(self) -> None:
        payload_drift = self.anchor()
        payload_drift["payload"]["generation_id"] = "gen-forged"
        result = evaluate_prime_external_anchor(self.capture, payload_drift, last_accepted_generation=0)
        self.assertEqual(result["reason"], "PRIME_ANCHOR_PAYLOAD_HASH_INVALID")
        self.assert_actionless(result)

        mac_drift = self.anchor()
        mac_drift["authority_mac"] = "0" * 64
        result = evaluate_prime_external_anchor(self.capture, mac_drift, last_accepted_generation=0)
        self.assertEqual(result["reason"], "PRIME_ANCHOR_SIGNATURE_INVALID")
        self.assert_actionless(result)

    def test_signed_semantic_binding_mutations_fail_closed(self) -> None:
        fields = (
            ("run_id", "foreign-run"),
            ("run_relative_path", "runtime/runs/foreign-run"),
            ("root_binding_sha256", "1" * 64),
            ("snapshot_sha256", "2" * 64),
            ("generation", 8),
            ("generation_id", "gen-000008"),
            ("covered_source_set_sha256", "3" * 64),
        )
        expected = {
            "run_id": "PRIME_ANCHOR_RUN_BINDING_MISMATCH",
            "run_relative_path": "PRIME_ANCHOR_RUN_PATH_MISMATCH",
            "root_binding_sha256": "PRIME_ANCHOR_ROOT_BINDING_MISMATCH",
            "snapshot_sha256": "PRIME_ANCHOR_SNAPSHOT_MISMATCH",
            "generation": "PRIME_ANCHOR_GENERATION_MISMATCH",
            "generation_id": "PRIME_ANCHOR_GENERATION_ID_MISMATCH",
            "covered_source_set_sha256": "PRIME_ANCHOR_SOURCE_SET_MISMATCH",
        }
        for field, value in fields:
            with self.subTest(field=field):
                forged = self.anchor()
                forged["payload"][field] = value
                forged["payload_sha256"] = canonical_hash(forged["payload"])
                forged["authority_mac"] = hmac.new(
                    KEY,
                    canonical_json({name: forged[name] for name in ("schema_version", "authority_id", "key_id", "payload", "payload_sha256")}).encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                result = evaluate_prime_external_anchor(self.capture, forged, last_accepted_generation=0)
                self.assertEqual(result["reason"], expected[field])
                self.assert_actionless(result)

    def test_generation_replay_and_downgrade_are_rejected(self) -> None:
        result = evaluate_prime_external_anchor(self.capture, self.anchor(), last_accepted_generation=7)
        self.assertEqual(result["reason"], "PRIME_ANCHOR_REPLAY_OR_DOWNGRADE")
        self.assert_actionless(result)

        older = copy.deepcopy(self.anchor())
        older["payload"]["generation"] = 6
        older["payload_sha256"] = canonical_hash(older["payload"])
        older["authority_mac"] = hmac.new(
            KEY,
            canonical_json({name: older[name] for name in ("schema_version", "authority_id", "key_id", "payload", "payload_sha256")}).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        result = evaluate_prime_external_anchor(self.capture, older, last_accepted_generation=7)
        self.assertEqual(result["reason"], "PRIME_ANCHOR_GENERATION_MISMATCH")
        self.assert_actionless(result)

    def test_duplicate_raw_json_keys_are_rejected(self) -> None:
        raw = '{"schema_version":"prime-writer-anchor-v1","schema_version":"forged"}'
        result = evaluate_prime_external_anchor(self.capture, raw, last_accepted_generation=0)
        self.assertEqual(result["reason"], "PRIME_ANCHOR_JSON_DUPLICATE_KEY")
        self.assert_actionless(result)

    def test_forged_capture_snapshot_cannot_be_attested(self) -> None:
        forged_capture = copy.deepcopy(self.capture)
        forged_capture["snapshot_sha256"] = "f" * 64
        result = evaluate_prime_external_anchor(forged_capture, self.anchor(), last_accepted_generation=0)
        self.assertEqual(result["reason"], "PRIME_ANCHOR_EVIDENCE_INVALID")
        self.assert_actionless(result)


if __name__ == "__main__":
    unittest.main()
