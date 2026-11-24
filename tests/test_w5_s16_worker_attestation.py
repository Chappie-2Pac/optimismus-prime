"""Adversarial tests for the W5-S16 worker/host/replay gate."""

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
    GATE_BINDING_SCHEMA,
    HOST_RUNTIME_ATTESTATION_SCHEMA,
    REPLAY_FLOOR_SCHEMA,
    REPLAY_OBSERVATION_SCHEMA,
    WORKER_ATTESTATION_PROTOCOL,
    WORKER_ATTESTATION_SCHEMA,
    configure_trusted_host_authority,
    configure_trusted_replay_authority,
    configure_trusted_replay_floor_authority,
    configure_trusted_worker_authority,
    evaluate_worker_attested_cross_store_capture,
    freeze_trusted_host_authorities,
    freeze_trusted_replay_authorities,
    freeze_trusted_replay_floor_authorities,
    freeze_trusted_worker_authorities,
    verify_worker_host_attestation,
)
from modules.w5_dispatch_bridge_s0 import cross_store_worker_attestation as s16  # noqa: E402
from modules.w5_dispatch_bridge_s0.cross_store_attestation import verify_cross_store_source_attestation  # noqa: E402
from test_w5_s15_source_attestation import W5S15SourceAttestationTests  # noqa: E402


WORKER_AUTHORITY = "source-worker-attestation-s16-test-authority"
WORKER_KEY_ID = "source-worker-attestation-s16-test-key"
WORKER_KEY = b"s16-worker-test-trust-root-0123456789"
HOST_AUTHORITY = "source-host-attestation-s16-test-authority"
HOST_KEY_ID = "source-host-attestation-s16-test-key"
HOST_KEY = b"s16-host-test-trust-root-0123456789"
REPLAY_AUTHORITY = "source-replay-observation-s16-test-authority"
REPLAY_KEY_ID = "source-replay-observation-s16-test-key"
REPLAY_KEY = b"s16-replay-test-trust-root-0123456789"
FLOOR_AUTHORITY = "source-replay-floor-s16-test-authority"
FLOOR_KEY_ID = "source-replay-floor-s16-test-key"
FLOOR_KEY = b"s16-floor-test-trust-root-0123456789"

configure_trusted_worker_authority(authority_id=WORKER_AUTHORITY, key_id=WORKER_KEY_ID, key=WORKER_KEY)
configure_trusted_host_authority(authority_id=HOST_AUTHORITY, key_id=HOST_KEY_ID, key=HOST_KEY)
configure_trusted_replay_authority(authority_id=REPLAY_AUTHORITY, key_id=REPLAY_KEY_ID, key=REPLAY_KEY)
configure_trusted_replay_floor_authority(authority_id=FLOOR_AUTHORITY, key_id=FLOOR_KEY_ID, key=FLOOR_KEY)
freeze_trusted_worker_authorities()
freeze_trusted_host_authorities()
freeze_trusted_replay_authorities()
freeze_trusted_replay_floor_authorities()


def _signed_envelope(*, schema: str, authority: str, key_id: str, key: bytes, attestation_id: str, payload: dict) -> dict:
    core = {
        "schema_version": schema,
        "attestation_id": attestation_id,
        "authority_id": authority,
        "key_id": key_id,
        "protocol": WORKER_ATTESTATION_PROTOCOL,
        "payload": payload,
        "payload_sha256": canonical_hash(payload),
    }
    return {**core, "authority_mac": hmac.new(key, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest()}


class W5S16WorkerAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        s15 = W5S15SourceAttestationTests()
        s15.setUp()
        self.s15 = s15
        self.s15_input = {
            "source_profiles": s15.profiles,
            "attestation": s15.attestation,
            "trust_registry": s15.registry,
            "cohort_binding": s15.cohort_binding,
            "s14_input": s15.s14_input,
        }
        self.bundle = self._build_bundle()

    def _build_bundle(self) -> dict:
        proof = verify_cross_store_source_attestation(**self.s15_input)
        participants = sorted(s16.SNAPSHOT_PARTICIPANT_IDS)
        registry = {key: proof[key] for key in ("registry_id", "registry_version", "registry_sha256")}
        common = {
            "transaction_id": self.s15_input["s14_input"]["transaction_id"],
            "observer_sha256": canonical_hash(self.s15_input["s14_input"]["observer"]),
            "authorization_sha256": proof["authorization_sha256"],
            **registry,
            "profile_set_sha256": proof["profile_set_sha256"],
            "source_set_sha256": proof["source_set_sha256"],
            "cohort_binding_sha256": proof["cohort_binding_sha256"],
            "host_id": "host-s16-test",
            "host_instance_id": "host-instance-s16-1",
            "replay_namespace": "replay-s16-test",
            "gate_nonce_sha256": canonical_hash("nonce-s16-1"),
            "attestation_sequence": 1,
            "registry_epoch": 0,
            "evidence_epoch": 1,
            "floor_epoch": 1,
            "worker_epoch": 1,
            "previous_attestation_set_sha256": None,
        }
        gate_binding = canonical_hash(
            {"schema_version": GATE_BINDING_SCHEMA, **{key: common[key] for key in sorted(s16.COMMON_BINDING_KEYS)}}
        )
        scope = {
            key: common[key]
            for key in (
                "registry_id",
                "registry_version",
                "registry_sha256",
                "profile_set_sha256",
                "source_set_sha256",
                "cohort_binding_sha256",
                "replay_namespace",
            )
        }
        floor_payload = {
            "floor_id": "floor-s16-1",
            **scope,
            "registry_epoch": common["registry_epoch"],
            "worker_epoch": common["worker_epoch"],
            "scope_sha256": canonical_hash(scope),
            "floor_epoch": 1,
            "last_accepted_sequence": 0,
            "last_accepted_attestation_set_sha256": None,
            "last_accepted_nonce_sha256": None,
        }
        floor_payload["replay_head_sha256"] = canonical_hash(
            {
                key: floor_payload[key]
                for key in (
                    "registry_id",
                    "registry_version",
                    "registry_sha256",
                    "profile_set_sha256",
                    "source_set_sha256",
                    "cohort_binding_sha256",
                    "replay_namespace",
                    "last_accepted_sequence",
                    "last_accepted_attestation_set_sha256",
                    "last_accepted_nonce_sha256",
                )
            }
        )
        floor_payload["floor_sha256"] = canonical_hash(floor_payload)
        floor_envelope = _signed_envelope(
            schema=REPLAY_FLOOR_SCHEMA,
            authority=FLOOR_AUTHORITY,
            key_id=FLOOR_KEY_ID,
            key=FLOOR_KEY,
            attestation_id="floor-envelope-s16-1",
            payload=floor_payload,
        )
        floor_sha256 = canonical_hash(floor_envelope)

        replay_payload = {
            "observation_id": "replay-s16-1",
            **{
                key: common[key]
                for key in (
                    "transaction_id",
                    "observer_sha256",
                    "authorization_sha256",
                    "registry_id",
                    "registry_version",
                    "registry_sha256",
                    "registry_epoch",
                    "profile_set_sha256",
                    "source_set_sha256",
                    "cohort_binding_sha256",
                    "host_id",
                    "host_instance_id",
                    "replay_namespace",
                    "gate_nonce_sha256",
                    "evidence_epoch",
                    "floor_epoch",
                    "attestation_sequence",
                    "previous_attestation_set_sha256",
                    "worker_epoch",
                )
            },
            "gate_binding_sha256": gate_binding,
            "state_floor_sha256": floor_sha256,
            "scope_sha256": canonical_hash(scope),
            "last_accepted_sequence": 0,
            "last_accepted_attestation_set_sha256": None,
            "last_accepted_nonce_sha256": None,
            "observation_sequence": 1,
        }
        replay_payload["replay_head_sha256"] = canonical_hash(
            {key: replay_payload[key] for key in sorted(s16.REPLAY_PAYLOAD_KEYS - {"replay_head_sha256"})}
        )
        replay_envelope = _signed_envelope(
            schema=REPLAY_OBSERVATION_SCHEMA,
            authority=REPLAY_AUTHORITY,
            key_id=REPLAY_KEY_ID,
            key=REPLAY_KEY,
            attestation_id="replay-envelope-s16-1",
            payload=replay_payload,
        )
        replay_sha256 = canonical_hash(replay_envelope)

        host_policy = {
            "policy_id": "host-policy-s16-1",
            "read_only_capability": True,
            "write_capability": False,
            "lock_capability": False,
            "network_capability": False,
            "process_capability": False,
        }
        runtime_bindings = {}
        for participant_id in participants:
            runtime_core = {
                "participant_id": participant_id,
                "host_id": common["host_id"],
                "host_instance_id": common["host_instance_id"],
                "runtime_id": f"runtime-{participant_id}-s16",
                "runtime_policy_sha256": canonical_hash("runtime-policy-s16"),
                "runtime_build_sha256": canonical_hash(f"runtime-build-{participant_id}-s16"),
                "read_only_capability": True,
                "write_capability": False,
                "lock_capability": False,
                "network_capability": False,
                "process_capability": False,
            }
            runtime_bindings[participant_id] = {
                **runtime_core,
                "runtime_binding_sha256": canonical_hash(runtime_core),
            }
        runtime_set_sha256 = canonical_hash(
            {
                participant_id: {
                    key: runtime_bindings[participant_id][key]
                    for key in sorted(s16.RUNTIME_BINDING_KEYS - {"runtime_binding_sha256"})
                }
                for participant_id in participants
            }
        )
        host_payload = {
            **common,
            "replay_observation_sha256": replay_sha256,
            "attestation_nonce": "nonce-s16-1",
            "host_policy": host_policy,
            "host_policy_sha256": canonical_hash(host_policy),
            "runtime_bindings": runtime_bindings,
            "runtime_set_sha256": runtime_set_sha256,
            "gate_binding_sha256": gate_binding,
            "state_floor_sha256": floor_sha256,
        }
        host_payload["host_binding_sha256"] = canonical_hash(
            {key: host_payload[key] for key in sorted(s16.HOST_PAYLOAD_KEYS - {"host_binding_sha256"})}
        )
        host_envelope = _signed_envelope(
            schema=HOST_RUNTIME_ATTESTATION_SCHEMA,
            authority=HOST_AUTHORITY,
            key_id=HOST_KEY_ID,
            key=HOST_KEY,
            attestation_id="host-envelope-s16-1",
            payload=host_payload,
        )

        worker_payloads = {}
        for participant_id in participants:
            profile = proof["profiles"][participant_id]
            source_identity = self.s15_input["s14_input"]["source_identities"][participant_id]
            runtime = runtime_bindings[participant_id]
            worker_payloads[participant_id] = {
                **common,
                "participant_id": participant_id,
                "adapter_id": profile["adapter_id"],
                "adapter_instance_id": f"adapter-instance-{participant_id}-s16",
                "allowed_root_or_binding": profile["allowed_root_or_binding"],
                "worker_id": f"worker-{participant_id}-s16",
                "worker_epoch": 1,
                "runtime_id": runtime["runtime_id"],
                "host_binding_sha256": host_payload["host_binding_sha256"],
                "runtime_binding_sha256": runtime["runtime_binding_sha256"],
                "adapter_code_sha256": profile["adapter_code_sha256"],
                "source_binding_sha256": profile["source_binding_sha256"],
                "source_identity_sha256": source_identity["source_identity_sha256"],
                "profile_sha256": profile["profile_sha256"],
                "execution_mode": "ISOLATED_READ_ONLY",
                "read_only": True,
                "read_only_capability": True,
                "write_capability": False,
                "lock_capability": False,
                "network_capability": False,
                "process_capability": False,
                "replay_observation_sha256": replay_sha256,
                "attestation_nonce": "nonce-s16-1",
                "attestation_set_sha256": "0" * 64,
                "gate_binding_sha256": gate_binding,
                "state_floor_sha256": floor_sha256,
            }
        fake_envelopes = {
            participant_id: {
                "attestation_id": f"worker-envelope-{participant_id}-s16",
                "authority_id": WORKER_AUTHORITY,
                "key_id": WORKER_KEY_ID,
                "protocol": WORKER_ATTESTATION_PROTOCOL,
                "payload": worker_payloads[participant_id],
            }
            for participant_id in participants
        }
        worker_set_sha256 = s16._worker_set_digest(fake_envelopes)
        worker_envelopes = {}
        for participant_id in participants:
            worker_payloads[participant_id]["attestation_set_sha256"] = worker_set_sha256
            worker_envelopes[participant_id] = _signed_envelope(
                schema=WORKER_ATTESTATION_SCHEMA,
                authority=WORKER_AUTHORITY,
                key_id=WORKER_KEY_ID,
                key=WORKER_KEY,
                attestation_id=f"worker-envelope-{participant_id}-s16",
                payload=worker_payloads[participant_id],
            )
        return {
            "worker_attestations": worker_envelopes,
            "host_runtime_attestation": host_envelope,
            "replay_observation": replay_envelope,
            "replay_floor": floor_envelope,
        }

    def _evaluate(self, *, bundle: dict | None = None, s15_input: dict | None = None) -> dict:
        values = bundle or self.bundle
        return evaluate_worker_attested_cross_store_capture(
            **values,
            s15_input=s15_input or self.s15_input,
        )

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["external_action"])
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["authoritative_decision"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_valid_bundle_invokes_s15_and_s14_once_after_preflight(self) -> None:
        result = self._evaluate()
        self.assertEqual(result["status"], "CAPTURED_READ_ONLY")
        self.assertEqual(result["worker_provenance_status"], "VALIDATED_READ_ONLY")
        self.assertEqual(result["replay_status"], "EXTERNALLY_CHECKED_NOT_ADVANCED")
        self.assertEqual(result["s15_result"]["status"], "CAPTURED_READ_ONLY")
        self.assertEqual(self.s15_input["s14_input"]["clock"].calls, 2)
        self.assertEqual(self.s15_input["s14_input"]["cohort"].calls, 2)
        self.assertTrue(all(reader.calls == 2 for reader in self.s15.s14.readers.values()))
        self.assert_actionless(result)

    def test_pure_verification_does_not_invoke_s14(self) -> None:
        proof = verify_worker_host_attestation(**self.bundle, s15_input=self.s15_input)
        self.assertTrue(proof["read_only"])
        self.assertFalse(proof["external_action"])
        self.assertEqual(self.s15_input["s14_input"]["clock"].calls, 0)
        self.assertEqual(self.s15_input["s14_input"]["cohort"].calls, 0)
        self.assertTrue(all(reader.calls == 0 for reader in self.s15.s14.readers.values()))

    def test_bad_worker_host_or_replay_signature_holds_before_callbacks(self) -> None:
        for part in ("worker_attestations", "host_runtime_attestation", "replay_observation", "replay_floor"):
            invalid = copy.deepcopy(self.bundle)
            if part == "worker_attestations":
                first = sorted(invalid[part])[0]
                invalid[part][first]["authority_mac"] = "0" * 64
            else:
                invalid[part]["authority_mac"] = "0" * 64
            result = self._evaluate(bundle=invalid)
            self.assertEqual(result["status"], "HOLD", part)
            self.assertEqual(self.s15_input["s14_input"]["clock"].calls, 0, part)
            self.assert_actionless(result)

    def test_correctly_resigned_foreign_worker_digests_are_rejected(self) -> None:
        invalid = copy.deepcopy(self.bundle)
        participant = sorted(invalid["worker_attestations"])[0]
        payload = invalid["worker_attestations"][participant]["payload"]
        payload["replay_observation_sha256"] = "1" * 64
        payload["state_floor_sha256"] = "2" * 64
        invalid["worker_attestations"][participant] = _signed_envelope(
            schema=WORKER_ATTESTATION_SCHEMA,
            authority=WORKER_AUTHORITY,
            key_id=WORKER_KEY_ID,
            key=WORKER_KEY,
            attestation_id="worker-envelope-foreign-digests",
            payload=payload,
        )
        result = self._evaluate(bundle=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "WORKER_ATTESTATION_BINDING_MISMATCH")
        self.assertEqual(self.s15_input["s14_input"]["clock"].calls, 0)

    def test_worker_set_digest_binds_signed_claim_identity(self) -> None:
        original = s16._worker_set_digest(self.bundle["worker_attestations"])
        altered = copy.deepcopy(self.bundle["worker_attestations"])
        participant = sorted(altered)[0]
        altered[participant] = _signed_envelope(
            schema=WORKER_ATTESTATION_SCHEMA,
            authority=WORKER_AUTHORITY,
            key_id=WORKER_KEY_ID,
            key=WORKER_KEY,
            attestation_id="worker-envelope-rotated-identity",
            payload=altered[participant]["payload"],
        )
        self.assertNotEqual(original, s16._worker_set_digest(altered))

    def test_replay_floor_cannot_use_observation_trust_root(self) -> None:
        invalid = copy.deepcopy(self.bundle)
        invalid["replay_floor"] = _signed_envelope(
            schema=REPLAY_FLOOR_SCHEMA,
            authority=REPLAY_AUTHORITY,
            key_id=REPLAY_KEY_ID,
            key=REPLAY_KEY,
            attestation_id="floor-with-observation-root",
            payload=invalid["replay_floor"]["payload"],
        )
        result = self._evaluate(bundle=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "WORKER_ATTESTATION_TRUST_ROOT_UNKNOWN")

    def test_host_runtime_binding_and_policy_mismatch_holds(self) -> None:
        invalid = copy.deepcopy(self.bundle)
        invalid["host_runtime_attestation"]["payload"]["runtime_bindings"]["prime_queue"]["write_capability"] = True
        result = self._evaluate(bundle=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["reason"], {"WORKER_ATTESTATION_PAYLOAD_INVALID", "WORKER_ATTESTATION_SIGNATURE_INVALID"})

        # A correctly re-signed host claim must still disagree with the
        # worker claim; this exercises the independent host/runtime binding,
        # not merely the envelope MAC check.
        invalid = copy.deepcopy(self.bundle)
        host_payload = invalid["host_runtime_attestation"]["payload"]
        runtime = host_payload["runtime_bindings"]["prime_queue"]
        runtime["runtime_id"] = "runtime-foreign-s16"
        runtime_core = {key: runtime[key] for key in sorted(s16.RUNTIME_BINDING_KEYS - {"runtime_binding_sha256"})}
        runtime["runtime_binding_sha256"] = canonical_hash(runtime_core)
        host_payload["runtime_set_sha256"] = canonical_hash(
            {
                participant_id: {
                    key: host_payload["runtime_bindings"][participant_id][key]
                    for key in sorted(s16.RUNTIME_BINDING_KEYS - {"runtime_binding_sha256"})
                }
                for participant_id in sorted(s16.SNAPSHOT_PARTICIPANT_IDS)
            }
        )
        host_payload["host_binding_sha256"] = canonical_hash(
            {key: host_payload[key] for key in sorted(s16.HOST_PAYLOAD_KEYS - {"host_binding_sha256"})}
        )
        invalid["host_runtime_attestation"] = _signed_envelope(
            schema=HOST_RUNTIME_ATTESTATION_SCHEMA,
            authority=HOST_AUTHORITY,
            key_id=HOST_KEY_ID,
            key=HOST_KEY,
            attestation_id="host-envelope-s16-resigned",
            payload=host_payload,
        )
        result = self._evaluate(bundle=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "WORKER_ATTESTATION_BINDING_MISMATCH")

        invalid = copy.deepcopy(self.bundle)
        participant = sorted(invalid["worker_attestations"])[0]
        invalid["worker_attestations"][participant]["payload"]["runtime_id"] = "runtime-foreign"
        result = self._evaluate(bundle=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["reason"], {"WORKER_ATTESTATION_PAYLOAD_INVALID", "WORKER_ATTESTATION_SIGNATURE_INVALID"})

    def test_replay_floor_sequence_parent_nonce_and_epoch_fail_closed(self) -> None:
        invalid = copy.deepcopy(self.bundle)
        invalid["worker_attestations"]["control_plane"]["payload"]["attestation_nonce"] = "nonce-s16-reused"
        result = self._evaluate(bundle=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["reason"], {"WORKER_ATTESTATION_PAYLOAD_INVALID", "WORKER_ATTESTATION_BINDING_MISMATCH"})

        invalid = copy.deepcopy(self.bundle)
        invalid["replay_observation"]["payload"]["last_accepted_sequence"] = 1
        result = self._evaluate(bundle=invalid)
        self.assertEqual(result["status"], "HOLD")
        self.assertIn(result["reason"], {"WORKER_ATTESTATION_PAYLOAD_INVALID", "WORKER_ATTESTATION_REPLAY_OBSERVATION_INVALID"})

    def test_s14_drift_remains_recovery_after_validated_s16(self) -> None:
        from test_w5_s14_cross_store_capture import _Reader

        readers = dict(self.s15.s14.readers)

        def mutate(record: dict) -> None:
            record["projection"]["observed"]["state"]["phase"] = "s16-drift"

        readers["prime_queue"] = _Reader(
            self.s15.s14.readers["prime_queue"].record,
            adapter_id="adapter-prime_queue",
            mutate_second=mutate,
        )
        s14_input = dict(self.s15_input["s14_input"])
        s14_input["readers"] = readers
        s15_input = dict(self.s15_input)
        s15_input["s14_input"] = s14_input
        result = self._evaluate(s15_input=s15_input)
        self.assertEqual(result["worker_provenance_status"], "VALIDATED_READ_ONLY")
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "CAPTURE_TOCTOU_DETECTED")
        self.assert_actionless(result)

    def test_static_s15_material_is_snapshotted_before_s15_evaluation(self) -> None:
        original_evaluator = s16.evaluate_attested_cross_store_capture

        def mutate_original_input(**kwargs: dict) -> dict:
            self.s15_input["source_profiles"]["control_plane"]["adapter_id"] = "mutated-after-s16-preflight"
            self.s15_input["s14_input"]["source_capabilities"]["control_plane"]["adapter_id"] = "mutated-after-s16-preflight"
            return original_evaluator(**kwargs)

        s16.evaluate_attested_cross_store_capture = mutate_original_input
        try:
            result = self._evaluate()
        finally:
            s16.evaluate_attested_cross_store_capture = original_evaluator
        self.assertEqual(result["status"], "CAPTURED_READ_ONLY")
        self.assertEqual(result["worker_provenance_status"], "VALIDATED_READ_ONLY")
        self.assert_actionless(result)

    def test_module_has_no_live_io_or_mutation_surface(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/cross_store_worker_attestation.py").read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket", "urllib", "Popen(", "os.system(", "os.kill(", "write_text(", "write_bytes(", "sqlite3"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
