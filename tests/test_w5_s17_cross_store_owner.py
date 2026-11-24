"""Adversarial tests for the W5-S17 replay-owner preflight."""

from __future__ import annotations

import copy
import hashlib
import hmac
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash, canonical_json  # noqa: E402
from modules.w5_dispatch_bridge_s0 import cross_store_owner as s17  # noqa: E402
from modules.w5_dispatch_bridge_s0 import verify_worker_host_attestation  # noqa: E402
from test_w5_s16_worker_attestation import W5S16WorkerAttestationTests  # noqa: E402


OWNER_AUTHORITY = "source-replay-owner-s17-test-authority"
OWNER_KEY_ID = "source-replay-owner-s17-test-key"
OWNER_KEY = b"s17-owner-test-trust-root-0123456789"

s17.configure_trusted_owner_authority(authority_id=OWNER_AUTHORITY, key_id=OWNER_KEY_ID, key=OWNER_KEY)
s17.freeze_trusted_owner_authorities()


def _signed_owner(*, attestation_id: str, payload: dict) -> dict:
    core = {
        "schema_version": s17.OWNER_OBSERVATION_SCHEMA,
        "attestation_id": attestation_id,
        "authority_id": OWNER_AUTHORITY,
        "key_id": OWNER_KEY_ID,
        "protocol": s17.OWNER_PROTOCOL,
        "payload": payload,
        "payload_sha256": canonical_hash(payload),
    }
    return {**core, "authority_mac": hmac.new(OWNER_KEY, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest()}


class W5S17CrossStoreOwnerTests(unittest.TestCase):
    def setUp(self) -> None:
        source = W5S16WorkerAttestationTests()
        source.setUp()
        self.source = source
        self.s15_input = source.s15_input
        self.bundle = copy.deepcopy(source.bundle)
        self.s16_proof = verify_worker_host_attestation(**self.bundle, s15_input=self.s15_input)
        self.replay = self.s16_proof["replay_observation"]["payload"]
        self.authorization = self.s16_proof["worker_authorization"]
        self.owner = self._build_owner()
        self.request = self._build_request()

    def _build_owner(self) -> dict:
        replay = self.replay
        auth = self.authorization
        payload = {
            "owner_id": "replay-owner-s17",
            "owner_instance_id": "owner-instance-s17-1",
            "snapshot_id": "owner-snapshot-s17-1",
            "owner_schema_version": "prime-replay-registry-owner-v1",
            "replay_namespace": replay["replay_namespace"],
            "registry_id": replay["registry_id"],
            "registry_version": replay["registry_version"],
            "registry_epoch": replay["registry_epoch"],
            "registry_sha256": replay["registry_sha256"],
            "profile_set_sha256": replay["profile_set_sha256"],
            "source_set_sha256": replay["source_set_sha256"],
            "cohort_binding_sha256": replay["cohort_binding_sha256"],
            "host_id": replay["host_id"],
            "host_instance_id": replay["host_instance_id"],
            "worker_epoch": replay["worker_epoch"],
            "state_version": 4,
            "owner_epoch": 2,
            "fencing_epoch": 7,
            "last_sequence": replay["last_accepted_sequence"],
            "last_attestation_set_sha256": replay["last_accepted_attestation_set_sha256"],
            "last_nonce_sha256": replay["last_accepted_nonce_sha256"],
            "journal_status": "CLEAN",
            "active_transaction_id_or_null": None,
            "active_intent_sha256_or_null": None,
            "idempotency_index_sha256": canonical_hash({"entries": []}),
            "observed_at": 123456,
        }
        payload["observation_sha256"] = canonical_hash(payload)
        payload["head_sha256"] = canonical_hash(s17._head_core(payload))
        return _signed_owner(attestation_id="owner-observation-s17-1", payload=payload)

    def _build_request(self) -> dict:
        return {
            "schema_version": s17.OWNER_REQUEST_SCHEMA,
            "contract_role": s17.OWNER_ROLE,
            "transaction_id": self.replay["transaction_id"],
            "idempotency_key": "s17-" + "idempotency-1",
            "operation": s17.OWNER_OPERATION,
            "safety": {
                "read_only": True,
                "owner_write": False,
                "owner_cas": False,
                "owner_consume": False,
                "prime_consume": False,
                "sqlite_write": False,
                "queue_write": False,
                "lock": False,
                "recovery": False,
                "external_action": False,
            },
        }

    def _values(self) -> dict:
        return {
            **self.bundle,
            "s15_input": self.s15_input,
            "owner_observation": self.owner,
            "request": self.request,
        }

    def _evaluate(self, **overrides: object) -> dict:
        values = self._values()
        values.update(overrides)
        return s17.evaluate_replay_owner_preflight(**values)

    def _assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["external_action"])
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["recovery_allowed"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["owner_state_advanced"])
        self.assertFalse(result["idempotency_reserved"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_valid_owner_preflight_is_only_a_cas_candidate(self) -> None:
        result = self._evaluate()
        self.assertEqual(result["status"], "OWNER_PREVIEW_ONLY")
        self.assertEqual(result["decision"], "CAS_RECHECK_REQUIRED")
        self.assertEqual(result["reason"], "OWNER_STATE_MATCHED")
        self.assertEqual(result["idempotency_status"], "UNRESOLVED_REQUIRES_OWNER_CAS")
        self.assertEqual(result["candidate"]["next_sequence"], self.replay["last_accepted_sequence"] + 1)
        self.assertTrue(result["owner_cas_required"])
        self._assert_actionless(result)

    def test_identical_input_has_identical_preflight_digest(self) -> None:
        first = self._evaluate()
        second = self._evaluate()
        self.assertEqual(first["preflight_sha256"], second["preflight_sha256"])
        self.assertEqual(first["candidate"], second["candidate"])
        self.assertEqual(first["owner_observation_sha256"], first["candidate"]["owner_observation_sha256"])
        self.assertNotEqual(first["owner_observation_sha256"], first["owner_envelope_sha256"])

    def test_s16_signature_failure_holds(self) -> None:
        invalid = copy.deepcopy(self.bundle)
        invalid["worker_attestations"]["control_plane"]["authority_mac"] = "0" * 64
        result = self._evaluate(worker_attestations=invalid["worker_attestations"])
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "OWNER_S16_INVALID")
        self._assert_actionless(result)

    def test_owner_signature_failure_holds(self) -> None:
        invalid = copy.deepcopy(self.owner)
        invalid["authority_mac"] = "0" * 64
        result = self._evaluate(owner_observation=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "OWNER_SIGNATURE_INVALID")
        self._assert_actionless(result)

    def test_owner_scope_mismatch_holds(self) -> None:
        invalid = copy.deepcopy(self.owner)
        invalid["payload"]["source_set_sha256"] = "f" * 64
        invalid["payload"]["observation_sha256"] = canonical_hash({key: invalid["payload"][key] for key in invalid["payload"] if key not in {"head_sha256", "observation_sha256"}})
        invalid["payload"]["head_sha256"] = canonical_hash(s17._head_core(invalid["payload"]))
        invalid = _signed_owner(attestation_id="owner-observation-foreign-scope", payload=invalid["payload"])
        result = self._evaluate(owner_observation=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "OWNER_SCOPE_MISMATCH")

    def test_foreign_owner_schema_version_holds(self) -> None:
        invalid = copy.deepcopy(self.owner)
        invalid["payload"]["owner_schema_version"] = "foreign-owner-schema-v99"
        invalid["payload"]["observation_sha256"] = canonical_hash({key: invalid["payload"][key] for key in invalid["payload"] if key not in {"head_sha256", "observation_sha256"}})
        invalid["payload"]["head_sha256"] = canonical_hash(s17._head_core(invalid["payload"]))
        invalid = _signed_owner(attestation_id="owner-observation-foreign-schema", payload=invalid["payload"])
        result = self._evaluate(owner_observation=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "OWNER_SCHEMA_INVALID")

    def test_owner_head_mismatch_holds(self) -> None:
        invalid = copy.deepcopy(self.owner)
        invalid["payload"]["last_sequence"] = 2
        invalid["payload"]["last_attestation_set_sha256"] = "a" * 64
        invalid["payload"]["last_nonce_sha256"] = "b" * 64
        invalid["payload"]["observation_sha256"] = canonical_hash({key: invalid["payload"][key] for key in invalid["payload"] if key not in {"head_sha256", "observation_sha256"}})
        invalid["payload"]["head_sha256"] = canonical_hash(s17._head_core(invalid["payload"]))
        invalid = _signed_owner(attestation_id="owner-observation-foreign-head", payload=invalid["payload"])
        result = self._evaluate(owner_observation=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "OWNER_HEAD_CONFLICT")

    def test_state_version_and_fencing_are_bound_but_not_authorized(self) -> None:
        invalid = copy.deepcopy(self.owner)
        invalid["payload"]["state_version"] = 0
        invalid = _signed_owner(attestation_id="owner-observation-invalid-version", payload=invalid["payload"])
        result = self._evaluate(owner_observation=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "OWNER_SCHEMA_INVALID")

        valid = self._evaluate()
        self.assertEqual(valid["owner_fencing_epoch"], 7)
        self.assertFalse(valid["cas_authorized"])

    def test_open_or_active_owner_journal_requires_separate_recovery(self) -> None:
        invalid = copy.deepcopy(self.owner)
        invalid["payload"]["journal_status"] = "OPEN"
        invalid["payload"]["active_transaction_id_or_null"] = "owner-tx-open"
        invalid["payload"]["active_intent_sha256_or_null"] = "a" * 64
        invalid["payload"]["observation_sha256"] = canonical_hash({key: invalid["payload"][key] for key in invalid["payload"] if key not in {"head_sha256", "observation_sha256"}})
        invalid["payload"]["head_sha256"] = canonical_hash(s17._head_core(invalid["payload"]))
        invalid = _signed_owner(attestation_id="owner-observation-open", payload=invalid["payload"])
        result = self._evaluate(owner_observation=invalid)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "OWNER_ACTIVE_TRANSACTION")
        self._assert_actionless(result)

    def test_request_cannot_inject_target_head_or_unsafe_capability(self) -> None:
        invalid = copy.deepcopy(self.request)
        invalid["next_sequence"] = 99
        result = self._evaluate(request=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "OWNER_REQUEST_INVALID")

        invalid = copy.deepcopy(self.request)
        invalid["safety"]["owner_cas"] = True
        result = self._evaluate(request=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "OWNER_REQUEST_INVALID")

    def test_owner_operation_is_not_idempotent_replay_or_receipt_proof(self) -> None:
        result = self._evaluate()
        self.assertNotIn("receipt", result)
        self.assertNotIn("recovery", result)
        self.assertNotEqual(result["status"], "IDEMPOTENT_REPLAY")
        self.assertNotEqual(result["status"], "COMMITTED_PROVEN")
        self._assert_actionless(result)

    def test_input_isolation(self) -> None:
        before_owner = copy.deepcopy(self.owner)
        before_request = copy.deepcopy(self.request)
        result = self._evaluate()
        self.assertEqual(result["status"], "OWNER_PREVIEW_ONLY")
        self.assertEqual(self.owner, before_owner)
        self.assertEqual(self.request, before_request)

    def test_module_has_no_live_io_or_mutation_surface(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/cross_store_owner.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket", "urllib", "Popen(", "os.system(", "os.kill(", "write_text(", "write_bytes(", "sqlite3"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
