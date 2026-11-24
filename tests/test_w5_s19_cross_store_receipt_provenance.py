"""Adversarial tests for the W5-S19 read-only provenance boundary."""

from __future__ import annotations

import copy
import hashlib
import hmac
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash, canonical_json  # noqa: E402
from modules.w5_dispatch_bridge_s0 import cross_store_owner as s17  # noqa: E402
from modules.w5_dispatch_bridge_s0.cross_store_receipt_provenance import (  # noqa: E402
    RECEIPT_PROVENANCE_SCHEMA,
    verify_receipt_provenance,
)
from modules.w5_dispatch_bridge_s0.replay_owner_adapter import advance_from_s17_preflight  # noqa: E402
from modules.w5_dispatch_bridge_s0.replay_owner_store import ReplayOwnerStore  # noqa: E402
from test_w5_s13_cross_store_snapshot import W5S13CrossStoreSnapshotTests  # noqa: E402
from test_w5_s17_cross_store_owner import (  # noqa: E402
    OWNER_AUTHORITY,
    OWNER_KEY,
    OWNER_KEY_ID,
    W5S17CrossStoreOwnerTests,
    _signed_owner,
)


SCOPE_KEYS = (
    "replay_namespace",
    "registry_id",
    "registry_version",
    "registry_epoch",
    "registry_sha256",
    "profile_set_sha256",
    "source_set_sha256",
    "cohort_binding_sha256",
    "host_id",
    "host_instance_id",
    "worker_epoch",
)


class W5S19ReceiptProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        source = W5S17CrossStoreOwnerTests()
        source.setUp()
        self.source = source
        self.bundle = copy.deepcopy(source.bundle)
        self.s15_input = copy.deepcopy(source.s15_input)
        self.request = copy.deepcopy(source.request)
        self.owner = self._owner_aligned_with_s13_fence()
        s13 = W5S13CrossStoreSnapshotTests()
        s13.setUp()
        self.snapshot = s13.envelope(s13.s12_fixture())
        self.temp = tempfile.TemporaryDirectory()
        self.scope_id = "s19-provenance-scope"
        self.db_path = Path(self.temp.name) / f"{self.scope_id}.sqlite3"
        self.lease_token = "s19-provenance-lease-token-0123456789"
        self.clock = lambda: 100
        owner = s17.parse_owner_observation(self.owner)["payload"]
        binding = {key: owner[key] for key in SCOPE_KEYS}
        with self._open() as store:
            store.create_scope(
                scope_id=self.scope_id,
                scope_binding=binding,
                owner_id=owner["owner_id"],
                owner_instance_id=owner["owner_instance_id"],
                owner_epoch=owner["owner_epoch"],
                fencing_epoch=owner["fencing_epoch"],
                lease_token=self.lease_token,
                lease_expires_at=1000,
                initial_state_version=owner["state_version"],
                initial_sequence=owner["last_sequence"],
                initial_attestation_set_sha256=owner["last_attestation_set_sha256"],
                initial_nonce_sha256=owner["last_nonce_sha256"],
                initial_head_sha256=owner["head_sha256"],
                initial_idempotency_index_sha256=owner["idempotency_index_sha256"],
            )
            committed = advance_from_s17_preflight(
                store,
                worker_attestations=self.bundle["worker_attestations"],
                replay_observation=self.bundle["replay_observation"],
                replay_floor=self.bundle["replay_floor"],
                host_runtime_attestation=self.bundle["host_runtime_attestation"],
                s15_input=self.s15_input,
                owner_observation=self.owner,
                request=self.request,
                lease_token=self.lease_token,
            )
        self.assertEqual(committed["status"], "OWNER_CAS_COMMITTED")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _open(self) -> ReplayOwnerStore:
        return ReplayOwnerStore(self.db_path, scope_id=self.scope_id, owner_root=self.temp.name, clock=self.clock)

    def _owner_aligned_with_s13_fence(self) -> dict:
        """Create a signed synthetic S17 observation with the S13 fixture epoch."""

        source = W5S17CrossStoreOwnerTests()
        source.setUp()
        payload = copy.deepcopy(s17.parse_owner_observation(source.owner)["payload"])
        payload["fencing_epoch"] = 3
        payload["observation_sha256"] = canonical_hash(
            {key: value for key, value in payload.items() if key not in {"observation_sha256", "head_sha256"}}
        )
        payload["head_sha256"] = canonical_hash(s17._head_core(payload))
        core = {
            "schema_version": s17.OWNER_OBSERVATION_SCHEMA,
            "attestation_id": "owner-observation-s19-1",
            "authority_id": OWNER_AUTHORITY,
            "key_id": OWNER_KEY_ID,
            "protocol": s17.OWNER_PROTOCOL,
            "payload": payload,
            "payload_sha256": canonical_hash(payload),
        }
        return {
            **core,
            "authority_mac": hmac.new(OWNER_KEY, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest(),
        }

    def _evaluate(self, **overrides: object) -> dict:
        values = {
            "worker_attestations": copy.deepcopy(self.bundle["worker_attestations"]),
            "replay_observation": copy.deepcopy(self.bundle["replay_observation"]),
            "replay_floor": copy.deepcopy(self.bundle["replay_floor"]),
            "host_runtime_attestation": copy.deepcopy(self.bundle["host_runtime_attestation"]),
            "s15_input": copy.deepcopy(self.s15_input),
            "owner_observation": copy.deepcopy(self.owner),
            "request": copy.deepcopy(self.request),
            "cross_store_snapshot": copy.deepcopy(self.snapshot),
        }
        values.update(overrides)
        with self._open() as store:
            return verify_receipt_provenance(store, **values)

    def _assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["authoritative_decision"])
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["mutation_performed"])
        self.assertFalse(result["receipt_emitted"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertFalse(result["external_action"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_full_chain_revalidates_without_receipt_or_consume_authority(self) -> None:
        result = self._evaluate()
        self.assertEqual(result["schema_version"], RECEIPT_PROVENANCE_SCHEMA)
        self.assertEqual(result["status"], "PROVENANCE_REVALIDATED")
        self.assertEqual(result["decision"], "ATOMIC_CONSUME_RECHECK_REQUIRED")
        self.assertEqual(result["owner_resolution_status"], "REPLAYED")
        self.assertEqual(result["projection_status"], "COMMITTED_READ_ONLY")
        self._assert_actionless(result)
        core = result["provenance_core"]
        self.assertEqual(core["s16"]["s15_authorization_sha256"].__len__(), 64)
        self.assertEqual(
            {item["participant_id"] for item in core["projection"]["participants"]},
            {"control_plane", "knowledge_ledger", "prime_ledger", "prime_queue", "receipt_projection"},
        )
        witness = core["s18"]["owner_commit_witness"]
        self.assertEqual(witness["store_schema_version"], "prime-replay-registry-owner-store-v1")
        self.assertEqual(witness["baseline_state_version"] + 1, witness["revalidation_state"]["state_version"])
        self.assertEqual(witness["operation"]["fencing_epoch"], core["s18"]["fencing_epoch"])
        self.assertEqual(witness["operation_record_sha256"], core["s18"]["operation_record_sha256"])

    def test_projection_toctou_drift_is_recovery_required(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["observations"]["prime_queue"]["sample_b"]["projection"]["observed"]["phase"] = "tampered"
        result = self._evaluate(cross_store_snapshot=snapshot)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "PROJECTION_SNAPSHOT_TOCTOU_DETECTED")
        self._assert_actionless(result)

    def test_s16_signature_drift_is_hold(self) -> None:
        bundle = copy.deepcopy(self.bundle)
        bundle["worker_attestations"]["control_plane"]["authority_mac"] = "0" * 64
        result = self._evaluate(**bundle)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["reason"], {"WORKER_ATTESTATION_SIGNATURE_INVALID", "S16_PROVENANCE_INVALID"})
        self._assert_actionless(result)

    def test_owner_signature_drift_is_hold(self) -> None:
        owner = copy.deepcopy(self.owner)
        owner["authority_mac"] = "0" * 64
        result = self._evaluate(owner_observation=owner)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "OWNER_SIGNATURE_INVALID")
        self._assert_actionless(result)

    def test_persisted_s18_event_drift_is_recovery_required(self) -> None:
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "UPDATE replay_owner_events SET payload_json=? WHERE scope_id=? AND event_type='OWNER_CAS_COMMITTED'",
                ("{}", self.scope_id),
            )
        result = self._evaluate()
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self._assert_actionless(result)

    def test_foreign_transaction_projection_is_hold(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        snapshot["replay"]["transaction_id"] = "foreign-transaction"
        result = self._evaluate(cross_store_snapshot=snapshot)
        self.assertEqual(result["status"], "HOLD")
        self._assert_actionless(result)

    def test_input_mapping_isolated(self) -> None:
        snapshot = copy.deepcopy(self.snapshot)
        original = copy.deepcopy(snapshot)
        result = self._evaluate(cross_store_snapshot=snapshot)
        self.assertEqual(result["status"], "PROVENANCE_REVALIDATED")
        self.assertEqual(snapshot, original)

    def test_s19_source_has_no_mutation_or_external_io_surface(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/cross_store_receipt_provenance.py").read_text()
        for forbidden in (
            "import sqlite3",
            "import subprocess",
            "import socket",
            "import urllib",
            "os.system",
            "os.kill",
            "_advance_validated",
            "quarantine_scope",
            "receipt_emitted\": True",
            "consume_allowed\": True",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
