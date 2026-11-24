"""Adversarial tests for the W5-S15 immutable source-attestation gate."""

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
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    CROSS_STORE_ATTESTATION_SCHEMA,
    CROSS_STORE_ATTESTATION_VERIFICATION_SCHEMA,
    SOURCE_ATTESTATION_PROTOCOL,
    SOURCE_AUTHORIZATION_SCHEMA,
    SOURCE_PROFILE_CURSOR_SCHEMA,
    SOURCE_PROFILE_SCHEMA,
    SOURCE_REGISTRY_SCHEMA,
    configure_trusted_source_authority,
    evaluate_attested_cross_store_capture,
    freeze_trusted_source_authorities,
    verify_cross_store_source_attestation,
)
from test_w5_s14_cross_store_capture import (  # noqa: E402
    W5S14CrossStoreCaptureTests,
    _Cohort,
)


AUTHORITY_ID = "source-attestation-test-authority"
KEY_ID = "source-attestation-test-key"
KEY = b"s15-test-trust-root-0123456789"

configure_trusted_source_authority(authority_id=AUTHORITY_ID, key_id=KEY_ID, key=KEY)
freeze_trusted_source_authorities()


class W5S15SourceAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.s14 = W5S14CrossStoreCaptureTests()
        self.s14.setUp()
        self.s14_input = self.s14.kwargs()
        self.profiles = self._profiles()
        self.registry = self._registry()
        self.cohort_binding = self._cohort_binding()
        self.attestation = self._attestation()

    def _profiles(self) -> dict[str, dict]:
        profiles = {}
        for participant_id in sorted(self.s14.envelope["sources"]):
            source = self.s14.envelope["sources"][participant_id]
            capability = self.s14_input["source_capabilities"][participant_id]
            core = {
                "schema_version": SOURCE_PROFILE_SCHEMA,
                "participant_id": participant_id,
                "adapter_version": "adapter-v1",
                "source_kind": source["source_kind"],
                "source_id": source["source_id"],
                "source_instance_id": source["source_instance_id"],
                "source_schema": source["source_schema"],
                "adapter_id": capability["adapter_id"],
                "allowed_root_or_binding": capability["allowed_root_or_binding"],
                "adapter_code_sha256": canonical_hash(f"adapter-code-{participant_id}"),
                "source_binding_sha256": canonical_hash(f"source-binding-{participant_id}"),
                "snapshot_mode": "FROZEN_EXPORT",
                "cursor_schema": SOURCE_PROFILE_CURSOR_SCHEMA,
                "capabilities": {
                    "read_only_capability": True,
                    "write_capability": False,
                    "lock_capability": False,
                    "network_capability": False,
                    "process_capability": False,
                },
            }
            profiles[participant_id] = {**core, "profile_sha256": canonical_hash(core)}
        return profiles

    def _registry(self) -> dict:
        profile_set_sha256 = canonical_hash(self.profiles)
        core = {
            "schema_version": SOURCE_REGISTRY_SCHEMA,
            "registry_id": "source-registry-test",
            "registry_version": "revision-1",
            "frozen": True,
            "profile_set_sha256": profile_set_sha256,
        }
        return {**core, "registry_sha256": canonical_hash(core)}

    def _cohort_binding(self) -> dict:
        capture = self.s14_input["capture_context"]
        generation = {
            participant_id: {
                "generation": self.s14.envelope["observations"][participant_id]["source_cursor"]["generation"],
                "generation_id": self.s14.envelope["observations"][participant_id]["source_cursor"]["generation_id"],
            }
            for participant_id in sorted(self.s14.envelope["observations"])
        }
        return {
            **copy.deepcopy(capture),
            "cohort_id": "cohort-test-1",
            "cohort_revision": "revision-1",
            "fence_sha256": canonical_hash(self.s14_input["fence"]),
            "lease_sha256": canonical_hash(self.s14_input["s12_input"]["lease"]),
            "generation_vector": generation,
        }

    def _attestation(self, *, transaction_id: str | None = None, payload_overrides: dict | None = None) -> dict:
        observer = self.s14_input["observer"]
        payload = {
            "transaction_id": transaction_id or self.s14_input["transaction_id"],
            "observer_id": observer["observer_id"],
            "observer_instance_id": observer["observer_instance_id"],
            "observer_sha256": canonical_hash(observer),
            "registry_id": self.registry["registry_id"],
            "registry_version": self.registry["registry_version"],
            "registry_sha256": self.registry["registry_sha256"],
            "profile_set_sha256": canonical_hash(self.profiles),
            "source_set_sha256": canonical_hash(sorted(source["source_id"] for source in self.s14.envelope["sources"].values())),
            "capture_context_sha256": canonical_hash(self.s14_input["capture_context"]),
            "cohort_binding_sha256": canonical_hash(self.cohort_binding),
            "attestation_nonce": "nonce-test-1",
        }
        if payload_overrides:
            payload.update(payload_overrides)
        attestation_id = "attestation-test-1"
        core = {
            "schema_version": CROSS_STORE_ATTESTATION_SCHEMA,
            "attestation_id": attestation_id,
            "authority_id": AUTHORITY_ID,
            "key_id": KEY_ID,
            "protocol": SOURCE_ATTESTATION_PROTOCOL,
            "payload": payload,
            "payload_sha256": canonical_hash(payload),
        }
        mac = hmac.new(KEY, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest()
        return {**core, "authority_mac": mac}

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["external_action"])
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["authoritative_decision"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_valid_attestation_invokes_s14_only_after_preflight(self) -> None:
        result = evaluate_attested_cross_store_capture(
            source_profiles=self.profiles,
            attestation=self.attestation,
            trust_registry=self.registry,
            cohort_binding=self.cohort_binding,
            s14_input=self.s14_input,
        )
        self.assertEqual(result["schema_version"], CROSS_STORE_ATTESTATION_VERIFICATION_SCHEMA)
        self.assertEqual(result["status"], "CAPTURED_READ_ONLY")
        self.assertEqual(result["provenance_status"], "VALIDATED_READ_ONLY")
        self.assertEqual(result["capture_result"]["status"], "CAPTURED_READ_ONLY")
        self.assertEqual(result["provenance"]["authorization"]["schema_version"], SOURCE_AUTHORIZATION_SCHEMA)
        self.assertEqual(
            result["provenance"]["authorization_sha256"],
            canonical_hash({key: value for key, value in result["provenance"]["authorization"].items() if key != "authorization_sha256"}),
        )
        self.assertEqual(self.s14_input["clock"].calls, 2)
        self.assertEqual(self.s14_input["cohort"].calls, 2)
        self.assertTrue(all(reader.calls == 2 for reader in self.s14.readers.values()))
        self.assert_actionless(result)

    def test_invalid_attestation_does_not_invoke_s14_callbacks(self) -> None:
        invalid = copy.deepcopy(self.attestation)
        invalid["authority_mac"] = "0" * 64
        result = evaluate_attested_cross_store_capture(
            source_profiles=self.profiles,
            attestation=invalid,
            trust_registry=self.registry,
            cohort_binding=self.cohort_binding,
            s14_input=self.s14_input,
        )
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "ATTESTATION_SIGNATURE_INVALID")
        self.assertEqual(self.s14_input["clock"].calls, 0)
        self.assertEqual(self.s14_input["cohort"].calls, 0)
        self.assertTrue(all(reader.calls == 0 for reader in self.s14.readers.values()))
        self.assert_actionless(result)

    def test_transaction_observer_registry_and_cohort_binding_fail_closed(self) -> None:
        for changed in (
            {"transaction_id": "foreign-transaction"},
            {"observer_id": "foreign-observer"},
            {"registry_version": "revision-foreign"},
            {"cohort_binding_sha256": "0" * 64},
        ):
            attestation = self._attestation(payload_overrides=changed)
            result = evaluate_attested_cross_store_capture(
                source_profiles=self.profiles,
                attestation=attestation,
                trust_registry=self.registry,
                cohort_binding=self.cohort_binding,
                s14_input=self.s14_input,
            )
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(self.s14_input["clock"].calls, 0)
            self.assert_actionless(result)

    def test_unsafe_profile_or_registry_is_hold_before_callbacks(self) -> None:
        unsafe_profiles = copy.deepcopy(self.profiles)
        unsafe_profiles["control_plane"]["capabilities"]["write_capability"] = True
        result = evaluate_attested_cross_store_capture(
            source_profiles=unsafe_profiles,
            attestation=self.attestation,
            trust_registry=self.registry,
            cohort_binding=self.cohort_binding,
            s14_input=self.s14_input,
        )
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["reason"], {"ATTESTATION_PROFILE_INVALID", "ATTESTATION_CAPABILITY_MISMATCH"})
        self.assertEqual(self.s14_input["clock"].calls, 0)
        self.assert_actionless(result)

        unfrozen = copy.deepcopy(self.registry)
        unfrozen["frozen"] = False
        result = evaluate_attested_cross_store_capture(
            source_profiles=self.profiles,
            attestation=self.attestation,
            trust_registry=unfrozen,
            cohort_binding=self.cohort_binding,
            s14_input=self.s14_input,
        )
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "ATTESTATION_REGISTRY_NOT_FROZEN")
        self.assert_actionless(result)

        non_boolean = copy.deepcopy(self.s14_input)
        non_boolean["source_capabilities"]["control_plane"]["read_only_capability"] = 1
        result = evaluate_attested_cross_store_capture(
            source_profiles=self.profiles,
            attestation=self.attestation,
            trust_registry=self.registry,
            cohort_binding=self.cohort_binding,
            s14_input=non_boolean,
        )
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "ATTESTATION_CAPABILITY_MISMATCH")
        self.assertEqual(non_boolean["clock"].calls, 0)
        self.assert_actionless(result)

    def test_s14_drift_remains_recovery_after_validated_provenance(self) -> None:
        readers = dict(self.s14.readers)

        def mutate(record: dict) -> None:
            record["projection"]["observed"]["state"]["phase"] = "drift"

        from test_w5_s14_cross_store_capture import _Reader

        readers["prime_queue"] = _Reader(
            self.s14.readers["prime_queue"].record,
            adapter_id="adapter-prime_queue",
            mutate_second=mutate,
        )
        s14_input = dict(self.s14_input)
        s14_input["readers"] = readers
        result = evaluate_attested_cross_store_capture(
            source_profiles=self.profiles,
            attestation=self.attestation,
            trust_registry=self.registry,
            cohort_binding=self.cohort_binding,
            s14_input=s14_input,
        )
        self.assertEqual(result["provenance_status"], "VALIDATED_READ_ONLY")
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "CAPTURE_TOCTOU_DETECTED")
        self.assert_actionless(result)

    def test_direct_provenance_verification_is_pure_and_isolated(self) -> None:
        proof = verify_cross_store_source_attestation(
            source_profiles=self.profiles,
            attestation=self.attestation,
            trust_registry=self.registry,
            cohort_binding=self.cohort_binding,
            s14_input=self.s14_input,
        )
        self.assertTrue(proof["read_only"])
        self.assertFalse(proof["external_action"])
        self.assertEqual(proof["registry_sha256"], self.registry["registry_sha256"])
        self.profiles["control_plane"]["adapter_id"] = "mutated-after-proof"
        self.assertNotEqual(proof["profiles"]["control_plane"]["adapter_id"], "mutated-after-proof")

    def test_module_stays_read_only_and_has_no_live_io_surface(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/cross_store_attestation.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket", "urllib", "Popen(", "os.system(", "os.kill(", "write_text(", "write_bytes("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
