"""Adversarial tests for the pure W5-S13 snapshot adapter."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash  # noqa: E402
from modules.w5_dispatch_bridge_s0 import (  # noqa: E402
    CROSS_STORE_PARTICIPANT_IDS,
    HOOK_IDS,
    adapt_cross_store_snapshot,
    build_cross_store_fixture,
    build_cross_store_hook_trace,
    evaluate_cross_store_snapshot,
    inject_cross_store_fault,
)
from test_w5_s11_transaction_authority import W5S11TransactionAuthorityTests  # noqa: E402


class W5S13CrossStoreSnapshotTests(unittest.TestCase):
    def projection(self, participant_id: str, *, after: bool) -> dict:
        phase = "after" if after else "before"
        version = 2 if after else 1
        generation = 2 if after else 1
        state = {"participant": participant_id, "phase": phase}
        journal = {"participant": participant_id, "journal": phase}
        return {
            "state": state,
            "journal": journal,
            "state_sha256": canonical_hash(state),
            "journal_sha256": canonical_hash(journal),
            "version": version,
            "generation": generation,
            "generation_id": canonical_hash({"participant": participant_id, "generation": generation}),
            "parent_hash": canonical_hash({"participant": participant_id, "phase": "before"}) if after else None,
        }

    def s12_fixture(self, *, observed: str = "after", hook_count: int | None = None) -> dict:
        participants = {}
        for participant_id in sorted(CROSS_STORE_PARTICIPANT_IDS):
            before = self.projection(participant_id, after=False)
            after = self.projection(participant_id, after=True)
            participants[participant_id] = {
                "expected_before": before,
                "expected_after": after,
                "observed": copy.deepcopy(after if observed == "after" else before),
            }

        contract = copy.deepcopy(W5S11TransactionAuthorityTests().contract())
        transaction_id = contract["transaction_id"]
        subject_material = {
            "subject": copy.deepcopy(contract["subject"]),
            "subject_binding": copy.deepcopy(contract["subject_binding"]),
        }
        if hook_count is None:
            hook_count = len(HOOK_IDS)
        hook_trace = build_cross_store_hook_trace(transaction_id=transaction_id, fencing_epoch=3)[:hook_count]
        lease = {
            "owner_id": "fixture-owner",
            "token_sha256": canonical_hash({"transaction_id": transaction_id, "owner": "fixture-owner"}),
            "issued_at": 90,
            "observed_at": 100,
            "expires_at": 200,
            "fencing_epoch": 3,
        }
        return build_cross_store_fixture(
            transaction_id=transaction_id,
            fencing_epoch=3,
            participants=participants,
            hook_trace=hook_trace,
            contract_material=contract,
            subject_binding_material=subject_material,
            lease=lease,
        )

    def envelope(self, fixture: dict) -> dict:
        source_ids = sorted(CROSS_STORE_PARTICIPANT_IDS)
        sources = {}
        observations = {}
        for participant_id in source_ids:
            identity = {
                "participant_id": participant_id,
                "source_kind": "frozen_projection",
                "source_id": participant_id,
                "source_instance_id": f"{participant_id}-instance-001",
                "source_schema": "frozen-source-v1",
                "snapshot_id": f"snapshot-{participant_id}-001",
                "snapshot_mode": "FROZEN_EXPORT",
            }
            sources[participant_id] = {
                **identity,
                "source_identity_sha256": canonical_hash(identity),
            }
            bundle = copy.deepcopy(fixture["participants"][participant_id])
            projection = bundle["observed"]
            cursor = {
                "cursor_id": f"cursor-{participant_id}-001",
                "version": projection["version"],
                "generation": projection["generation"],
                "generation_id": projection["generation_id"],
                "journal_sha256": projection["journal_sha256"],
            }
            sample = {
                "participant_id": participant_id,
                "source_identity_sha256": sources[participant_id]["source_identity_sha256"],
                "snapshot_id": sources[participant_id]["snapshot_id"],
                "source_cursor": copy.deepcopy(cursor),
                "projection": copy.deepcopy(bundle),
            }
            content = {
                "participant_id": participant_id,
                "source_identity_sha256": sources[participant_id]["source_identity_sha256"],
                "snapshot_id": sources[participant_id]["snapshot_id"],
                "source_cursor": copy.deepcopy(cursor),
                "observed": copy.deepcopy(bundle),
            }
            observations[participant_id] = {
                "source_id": participant_id,
                "snapshot_id": sources[participant_id]["snapshot_id"],
                "source_identity_sha256": sources[participant_id]["source_identity_sha256"],
                "sample_a": copy.deepcopy(sample),
                "sample_b": copy.deepcopy(sample),
                "source_cursor": cursor,
                "source_cursor_sha256": canonical_hash(cursor),
                "observed": bundle,
                "observed_sha256": canonical_hash(bundle),
                "content_sha256": canonical_hash(content),
                "read_only": True,
            }

        source_set = sorted(sources[participant_id]["source_id"] for participant_id in source_ids)
        capture = {
            "capture_id": "capture-s13-001",
            "sequence_domain": "s13-capture-sequence",
            "sequence_no": 7,
            "barrier_id": "barrier-s13-001",
            "clock_domain_id": "s13-clock",
            "clock_sample_id": "clock-s13-001",
            "clock_before": 100,
            "clock_after": 100,
            "source_set_sha256": canonical_hash(source_set),
            "events": [],
            "stable": True,
            "read_only": True,
            "external_action": False,
            "execution": {"resume": False, "reconcile": False, "mutation": False, "network": False},
        }
        for ordinal, (participant_id, pass_name) in enumerate(
            ((participant_id, pass_name) for participant_id in source_ids for pass_name in ("before", "after")),
            start=1,
        ):
            event = {
                "ordinal": ordinal,
                "participant_id": participant_id,
                "pass": pass_name,
                "source_identity_sha256": sources[participant_id]["source_identity_sha256"],
                "observation_sha256": "",
                "clock_sample_id": capture["clock_sample_id"],
            }
            material = {
                "capture_id": capture["capture_id"],
                "sequence_domain": capture["sequence_domain"],
                "sequence_no": capture["sequence_no"],
                "barrier_id": capture["barrier_id"],
                "ordinal": ordinal,
                "participant_id": participant_id,
                "pass": pass_name,
                "source_identity_sha256": event["source_identity_sha256"],
                "content_sha256": observations[participant_id]["content_sha256"],
                "clock_sample_id": event["clock_sample_id"],
            }
            event["observation_sha256"] = canonical_hash(material)
            capture["events"].append(event)

        contract = fixture["bindings"]["contract"]
        manifest_body = {
            "schema_version": "prime-cross-store-projection-manifest-v1",
            "contract_digest": canonical_hash(contract),
            "precondition_plan_sha256": contract["precondition_plan_sha256"],
            "participants": {
                participant_id: {
                    "before": copy.deepcopy(fixture["participants"][participant_id]["expected_before"]),
                    "after": copy.deepcopy(fixture["participants"][participant_id]["expected_after"]),
                    "target_id": participant_id,
                }
                for participant_id in source_ids
            },
        }
        manifest = {**manifest_body, "manifest_sha256": canonical_hash(manifest_body)}

        fence = {
            "owner_id": "s13-owner",
            "worker_id": "s13-observer-instance-001",
            "token_sha256": canonical_hash({"transaction_id": fixture["transaction_id"], "owner": "s13-owner"}),
            "fencing_epoch": 3,
            "issued_at": 90,
            "expires_at": 200,
            "clock_domain_id": capture["clock_domain_id"],
            "fence_cursor": "fence-cursor-003",
            "fence_observation_sha256": "",
        }
        fence["fence_observation_sha256"] = canonical_hash(
            {key: fence[key] for key in sorted(fence) if key != "fence_observation_sha256"}
        )

        contract = fixture["bindings"]["contract"]
        subject_material = copy.deepcopy(fixture["bindings"]["subject_binding"])
        replay = {
            "registry_source_id": "idempotency-registry-s13",
            "idempotency_key": contract["idempotency_key"],
            "transaction_id": fixture["transaction_id"],
            "contract_digest": canonical_hash(contract),
            "subject_binding_digest": canonical_hash(subject_material),
            "status": "UNIQUE_OBSERVED",
            "conflict": False,
            "observation_sha256": "",
        }
        replay["observation_sha256"] = canonical_hash(
            {key: replay[key] for key in sorted(replay) if key != "observation_sha256"}
        )

        return {
            "schema_version": "prime-cross-store-observation-v1",
            "contract_role": "cross_store_snapshot_adapter_read_only",
            "transaction_id": fixture["transaction_id"],
            "observer": {
                "observer_id": "s13-observer",
                "observer_instance_id": "s13-observer-instance-001",
                "implementation_id": "s13-adapter-v1",
                "mode": "READ_ONLY_IMPORT",
            },
            "sources": sources,
            "source_set": source_set,
            "source_set_sha256": canonical_hash(source_set),
            "expected_projection_manifest": manifest,
            "capture": capture,
            "observations": observations,
            "fence": fence,
            "replay": replay,
            "s12_input": {
                "contract_material": copy.deepcopy(contract),
                "subject_binding_material": subject_material,
                "effect_set": copy.deepcopy(fixture["bindings"]["effect_set"]),
                "marker_material": copy.deepcopy(fixture["bindings"]["marker"]),
                "lease": copy.deepcopy(fixture["lease"]),
                "hook_trace": copy.deepcopy(fixture["hook_trace"]),
                "fault_hook_or_null": fixture["fault_hook_or_null"],
            },
            "safety": {
                "read_only": True,
                "lock_acquired": False,
                "lock_held": False,
                "reservation": False,
                "mutation_performed": False,
                "authoritative_commit": False,
                "recovery_invoked": False,
                "process_started": False,
                "process_stopped": False,
                "network_used": False,
                "external_action": False,
            },
        }

    def reseal_fence(self, envelope: dict) -> None:
        fence = envelope["fence"]
        fence["fence_observation_sha256"] = canonical_hash(
            {key: fence[key] for key in sorted(fence) if key != "fence_observation_sha256"}
        )

    def assert_actionless(self, result: dict) -> None:
        self.assertEqual(result["permission"], "read_only")
        self.assertFalse(result["mutation_allowed"])
        self.assertFalse(result["authoritative_decision"])
        self.assertFalse(result["external_action"])
        self.assertFalse(result["resume_allowed"])
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["cas_authorized"])
        self.assertTrue(all(value is False for value in result["execution"].values()))

    def test_stable_envelope_adapts_full_s11_to_committed_s12_deterministically(self) -> None:
        envelope = self.envelope(self.s12_fixture())
        first = adapt_cross_store_snapshot(envelope)
        second = adapt_cross_store_snapshot(json.loads(json.dumps(envelope, sort_keys=True)))
        self.assertEqual(first, second)
        self.assertEqual(first["status"], "ADAPTED_READ_ONLY")
        self.assertEqual(first["classification_status"], "COMMITTED")
        self.assertTrue(first["source_gates"]["source_set"])
        self.assertTrue(first["toctou_gate"]["verified"])
        self.assertEqual(first["live_binding"], "BOUNDED_FROZEN_SNAPSHOT")
        self.assert_actionless(first)

    def test_prepared_and_split_prefixes_remain_s12_classifications(self) -> None:
        prepared = adapt_cross_store_snapshot(self.envelope(self.s12_fixture(observed="before", hook_count=4)))
        self.assertEqual(prepared["classification_status"], "PREPARED")
        self.assert_actionless(prepared)

        split = inject_cross_store_fault(self.s12_fixture(), "T3.sqlite_after_commit")
        result = adapt_cross_store_snapshot(self.envelope(split))
        self.assertEqual(result["classification_status"], "IN_DOUBT")
        self.assertEqual(result["classification_reason"], "PROJECTION_PENDING")
        self.assert_actionless(result)

    def test_toctou_cursor_and_fence_drift_are_recovery_required(self) -> None:
        envelope = self.envelope(self.s12_fixture())
        envelope["observations"]["prime_queue"]["sample_b"]["projection"]["observed"]["phase"] = "tampered"
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "SNAPSHOT_TOCTOU_DETECTED")
        self.assert_actionless(result)

        envelope = self.envelope(self.s12_fixture())
        envelope["observations"]["prime_queue"]["source_cursor_sha256"] = "0" * 64
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "SNAPSHOT_SOURCE_DRIFT")
        self.assert_actionless(result)

        envelope = self.envelope(self.s12_fixture())
        envelope["fence"]["token_sha256"] = "0" * 64
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "SNAPSHOT_FENCE_DRIFT")
        self.assert_actionless(result)

    def test_expired_fence_is_recovery_required_before_s12(self) -> None:
        envelope = self.envelope(self.s12_fixture())
        envelope["fence"]["expires_at"] = 100
        self.reseal_fence(envelope)
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "SNAPSHOT_LEASE_EXPIRED")
        self.assert_actionless(result)

        envelope = self.envelope(self.s12_fixture())
        envelope["fence"]["worker_id"] = "foreign-observer-instance"
        self.reseal_fence(envelope)
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "SNAPSHOT_FENCE_DRIFT")
        self.assert_actionless(result)

        envelope = self.envelope(self.s12_fixture())
        envelope["s12_input"]["lease"]["expires_at"] = 100
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "RECOVERY_REQUIRED")
        self.assertEqual(result["reason"], "SNAPSHOT_LEASE_EXPIRED")
        self.assert_actionless(result)

    def test_full_s11_contract_subject_replay_and_safety_gates_fail_closed(self) -> None:
        envelope = self.envelope(self.s12_fixture())
        del envelope["s12_input"]["contract_material"]["continuity_gate"]
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "SNAPSHOT_S12_BINDING_INVALID")
        self.assert_actionless(result)

        envelope = self.envelope(self.s12_fixture())
        envelope["s12_input"]["subject_binding_material"]["subject"]["card_id"] = "forged-card"
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "SNAPSHOT_S12_BINDING_INVALID")
        self.assert_actionless(result)

        envelope = self.envelope(self.s12_fixture())
        envelope["replay"]["idempotency_key"] = "replay-conflict"
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "SNAPSHOT_S12_BINDING_INVALID")
        self.assert_actionless(result)

        envelope = self.envelope(self.s12_fixture())
        envelope["capture"]["external_action"] = True
        result = evaluate_cross_store_snapshot(envelope)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "SNAPSHOT_UNSAFE_REQUEST")
        self.assert_actionless(result)

    def test_duplicate_json_input_is_a_hold_and_mapping_input_isolated(self) -> None:
        result = evaluate_cross_store_snapshot('{"schema_version":"one","schema_version":"two"}')
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["reason"], "SNAPSHOT_JSON_DUPLICATE_KEY")
        self.assert_actionless(result)

        envelope = self.envelope(self.s12_fixture())
        result = adapt_cross_store_snapshot(envelope)
        envelope["observations"]["control_plane"]["observed"] = None
        self.assertEqual(result["classification_status"], "COMMITTED")

    def test_adapter_has_no_live_io_or_mutation_imports(self) -> None:
        source = (REPO_ROOT / "modules/w5_dispatch_bridge_s0/cross_store_snapshot.py").read_text()
        for forbidden in ("import sqlite3", "import subprocess", "import socket", "import requests", "import urllib", "open("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
