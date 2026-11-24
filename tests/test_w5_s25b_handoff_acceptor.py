"""Adversarial S25B authority-backed, RECOVERY-only handoff tests."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w4_small_loop_s0 import canonical_hash, canonical_json  # noqa: E402
from modules.w5_dispatch_bridge_s0.handoff_acceptor import (  # noqa: E402
    HANDOFF_ACCEPTED_RECOVERY,
    HANDOFF_CONFLICT,
    HANDOFF_HOLD,
    HANDOFF_REPLAYED,
    HandoffAcceptor,
    InjectedHandoffCrash,
    configure_trusted_handoff_authority,
    configure_trusted_termination_authority,
    freeze_trusted_handoff_authorities,
    freeze_trusted_termination_authorities,
)
from modules.w5_dispatch_bridge_s0.handoff_preflight import build_handoff_observation  # noqa: E402
from modules.w5_dispatch_bridge_s0.prime_queue_writer import (  # noqa: E402
    InjectedPrimeQueueWriterCrash,
    PrimeQueueWriter,
)
from support.prime_fixture import make_project  # noqa: E402


AUTHORITY_KEY = b"s25b-authority-key-0123456789"
TERMINATION_KEY = b"s25b-termination-key-0123456789"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sign(value: dict[str, object], key: bytes) -> str:
    core = {name: value[name] for name in sorted(value) if name != "authority_mac"}
    return hmac.new(key, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest()


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class AdvancingClock:
    def __init__(self, *values: int) -> None:
        self.values = list(values)

    def __call__(self) -> int:
        return self.values.pop(0) if len(self.values) > 1 else self.values[0]


class W5S25BHandoffAcceptorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configure_trusted_handoff_authority(authority_id="runtime-authority", key=AUTHORITY_KEY)
        configure_trusted_termination_authority(authority_id="termination-authority", key=TERMINATION_KEY)
        freeze_trusted_handoff_authorities()
        freeze_trusted_termination_authorities()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="w5-s25b-handoff-")
        self.addCleanup(self.temp.cleanup)
        self.root = make_project(Path(self.temp.name))
        self.queue_path = self.root / "Plan" / "local-ai" / "QUEUE.json"
        queue = json.loads(self.queue_path.read_text(encoding="utf-8"))
        queue["tasks"][0]["owner"] = "codex"
        self.queue_path.write_text(json.dumps(queue), encoding="utf-8")
        self.clock = MutableClock(200)
        self.writer = PrimeQueueWriter(self.root, clock=self.clock)
        self.addCleanup(self.writer.close)
        self.old_lease = "s25b-old-lease-token-012345"
        self.new_lease = "s25b-new-lease-token-012345"
        self.scope_id = "s25b-scope"
        self.lease = {
            "owner_id": "old-owner",
            "owner_instance_id": "old-instance",
            "owner_epoch": 4,
            "fencing_epoch": 9,
            "lease_token": self.old_lease,
        }
        self.writer.create_scope(scope_id=self.scope_id, **self.lease, lease_expires_at=1000)
        request = {
            "scope_id": self.scope_id,
            "transaction_id": "s25b-tx",
            "idempotency_key": "s25b-idem",
            "card_id": "card-1",
            "command": "start",
            "actor": "codex",
            "expected_queue_sha256": self._queue_hash(),
            **self.lease,
        }
        self.writer.fault_points.add("after_prepare")
        with self.assertRaises(InjectedPrimeQueueWriterCrash):
            self.writer.execute_transition(**request)
        self.writer.fault_points.clear()
        self.observation, self.grant = self._handoff_inputs()
        self.authority, self.termination = self._attestations()

    def _queue_hash(self) -> str:
        return hashlib.sha256(self.queue_path.read_bytes()).hexdigest()

    def _handoff_inputs(self) -> tuple[dict[str, object], dict[str, object]]:
        scope = self.writer.read_scope(self.scope_id)
        operation = self.writer.conn.execute(
            "SELECT * FROM prime_queue_writer_operations WHERE scope_id=?",
            (self.scope_id,),
        ).fetchone()
        self.assertIsNotNone(operation)
        before = operation["expected_queue_sha256"]
        after = operation["after_queue_sha256"]
        transaction = {
            "status": "EXACT",
            "manifest_sha256": digest(b"manifest"),
            "before_sha256": before,
            "after_sha256": after,
            "queue_sha256": self._queue_hash(),
            "terminal_marker": "ABSENT",
        }
        observation = build_handoff_observation(
            observation_id="s25b-observation",
            observed_at=150,
            root={
                "root_binding_sha256": scope["root_binding_sha256"],
                "active_scope_id": self.scope_id,
                "active_fencing_epoch": scope["fencing_epoch"],
            },
            scope={
                key: scope[key]
                for key in (
                    "scope_id",
                    "root_binding_sha256",
                    "owner_id",
                    "owner_instance_id",
                    "owner_epoch",
                    "fencing_epoch",
                    "lease_token_sha256",
                    "lease_expires_at",
                    "scope_status",
                    "active_operation_id",
                    "active_phase",
                    "event_seq",
                )
            },
            operation={
                "transaction_id": operation["transaction_id"],
                "idempotency_key": operation["idempotency_key"],
                "intent_sha256": operation["intent_sha256"],
                "state": operation["state"],
                "expected_queue_sha256": operation["expected_queue_sha256"],
                "after_queue_sha256": operation["after_queue_sha256"],
            },
            transaction=transaction,
        )
        grant = {
            "schema_version": "prime-queue-handoff-grant-v1",
            "handoff_id": "s25b-handoff",
            "authority_id": "runtime-authority",
            "authority_epoch": 3,
            "authority_proof": "s25a-opaque-proof",
            "root_binding_sha256": scope["root_binding_sha256"],
            "scope_id": self.scope_id,
            "transaction_id": operation["transaction_id"],
            "idempotency_key": operation["idempotency_key"],
            "intent_sha256": operation["intent_sha256"],
            "expected_active_phase": scope["active_phase"],
            "expected_operation_state": operation["state"],
            "expected_event_seq": scope["event_seq"],
            "old_owner_id": scope["owner_id"],
            "old_owner_instance_id": scope["owner_instance_id"],
            "old_owner_epoch": scope["owner_epoch"],
            "old_fencing_epoch": scope["fencing_epoch"],
            "old_lease_token_sha256": scope["lease_token_sha256"],
            "old_lease_expires_at": scope["lease_expires_at"],
            "new_owner_id": "new-owner",
            "new_owner_instance_id": "new-instance",
            "new_owner_epoch": 5,
            "new_fencing_epoch": 10,
            "new_lease_token_sha256": digest(self.new_lease.encode()),
            "new_lease_expires_at": 1000,
            "handoff_kind": "AUTHORIZED_TERMINATION",
            "liveness_evidence_sha256": digest(b"termination-evidence"),
            "reason": "trusted termination handoff",
            "issued_at": 150,
        }
        return observation, grant

    def _attestations(self) -> tuple[dict[str, object], dict[str, object]]:
        grant_sha = canonical_hash(self.grant)
        authority: dict[str, object] = {
            "schema_version": "prime-queue-handoff-authority-v1",
            "protocol": "hmac-sha256-canonical-json-v1",
            "authority_id": "runtime-authority",
            "authority_epoch": 3,
            "decision": "ACCEPT_RECOVERY",
            "handoff_id": self.grant["handoff_id"],
            "grant_sha256": grant_sha,
            "root_binding_sha256": self.grant["root_binding_sha256"],
            "scope_id": self.grant["scope_id"],
            "transaction_id": self.grant["transaction_id"],
            "old_fencing_epoch": self.grant["old_fencing_epoch"],
            "new_fencing_epoch": self.grant["new_fencing_epoch"],
            "issued_at": 150,
            "expires_at": 900,
            "nonce": "authority-nonce",
            "policy_hash": digest(b"policy"),
            "authority_mac": "0" * 64,
        }
        authority["authority_mac"] = sign(authority, AUTHORITY_KEY)
        termination: dict[str, object] = {
            "schema_version": "prime-queue-termination-attestation-v1",
            "protocol": "hmac-sha256-canonical-json-v1",
            "termination_authority_id": "termination-authority",
            "termination_authority_epoch": 1,
            "source_id": "supervisor-1",
            "source_epoch": 2,
            "handoff_id": self.grant["handoff_id"],
            "grant_sha256": grant_sha,
            "old_owner_id": self.grant["old_owner_id"],
            "old_owner_instance_id": self.grant["old_owner_instance_id"],
            "old_fencing_epoch": self.grant["old_fencing_epoch"],
            "transaction_id": self.grant["transaction_id"],
            "intent_sha256": self.grant["intent_sha256"],
            "process_pid": 1234,
            "process_start_time": 42,
            "boot_id": "boot-1",
            "run_token_hash": digest(b"run-token"),
            "cgroup_identity_hash": digest(b"cgroup"),
            "outcome": "TERMINATED",
            "observed_at": 160,
            "expires_at": 900,
            "evidence_sha256": digest(b"termination-evidence"),
            "authority_mac": "0" * 64,
        }
        termination["authority_mac"] = sign(termination, TERMINATION_KEY)
        return authority, termination

    def acceptor(self, **kwargs: object) -> HandoffAcceptor:
        return HandoffAcceptor(self.writer, clock=self.clock, **kwargs)

    def accept(self, **changes: object) -> dict[str, object]:
        observation = copy.deepcopy(self.observation)
        grant = copy.deepcopy(self.grant)
        authority = copy.deepcopy(self.authority)
        termination = copy.deepcopy(self.termination)
        for name, value in changes.items():
            if name.startswith("grant_"):
                grant[name[6:]] = value
            elif name.startswith("authority_"):
                authority[name[10:]] = value
            elif name.startswith("termination_"):
                termination[name[12:]] = value
            else:
                raise AssertionError(name)
        if "authority_mac" in changes:
            authority["authority_mac"] = sign(authority, AUTHORITY_KEY)
        if "termination_mac" in changes:
            termination["authority_mac"] = sign(termination, TERMINATION_KEY)
        return self.acceptor().accept_handoff(
            observation=observation,
            grant=grant,
            authority_attestation=authority,
            termination_attestation=termination,
            new_lease_token=self.new_lease,
            now=self.clock.value,
        )

    def test_valid_handoff_is_single_store_recovery_only(self) -> None:
        before = self.queue_path.read_bytes()

        result = self.accept()

        self.assertEqual(result["status"], HANDOFF_ACCEPTED_RECOVERY)
        self.assertTrue(result["authority_verified"])
        self.assertTrue(result["termination_verified"])
        self.assertTrue(result["root_cas_committed"])
        self.assertTrue(result["scope_cas_committed"])
        self.assertTrue(result["claim_cas_committed"])
        self.assertTrue(result["handoff_event_committed"])
        self.assertFalse(result["queue_mutation_performed"])
        self.assertFalse(result["recovery_executed"])
        self.assertFalse(result["resume_allowed"])
        self.assertEqual(result["target_phase"], "RECOVERY")
        self.assertEqual(self.queue_path.read_bytes(), before)
        scope = self.writer.read_scope(self.scope_id)
        self.assertEqual(scope["owner_id"], "new-owner")
        self.assertEqual(scope["fencing_epoch"], 10)
        self.assertEqual(scope["active_phase"], "RECOVERY")
        self.assertEqual(scope["scope_status"], "IN_DOUBT")
        operation = self.writer.read_operation(self.scope_id, "s25b-idem")
        self.assertEqual(operation["status"], "PREPARED")
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_handoff_events").fetchone()[0], 1)

    def test_identical_retry_is_replayed_without_second_fence_or_event(self) -> None:
        first = self.accept()
        self.assertEqual(first["status"], HANDOFF_ACCEPTED_RECOVERY)
        scope_before = self.writer.read_scope(self.scope_id)

        replay = self.accept()

        self.assertEqual(replay["status"], HANDOFF_REPLAYED)
        self.assertFalse(replay["handoff_mutation_performed"])
        self.assertEqual(self.writer.read_scope(self.scope_id), scope_before)
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_handoff_events").fetchone()[0], 1)

    def test_invalid_authority_or_termination_never_mutates(self) -> None:
        invalid_authority = copy.deepcopy(self.authority)
        invalid_authority["authority_mac"] = "0" * 64
        result = self.acceptor().accept_handoff(
            observation=self.observation,
            grant=self.grant,
            authority_attestation=invalid_authority,
            termination_attestation=self.termination,
            new_lease_token=self.new_lease,
            now=self.clock.value,
        )
        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertEqual(self.writer.read_scope(self.scope_id)["fencing_epoch"], 9)

        invalid_term = copy.deepcopy(self.termination)
        invalid_term["authority_mac"] = "0" * 64
        self.termination = invalid_term
        result = self.accept()
        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_handoff_events").fetchone()[0], 0)

    def test_lease_expiry_alone_is_not_termination_authority(self) -> None:
        self.termination["outcome"] = "UNVERIFIED"
        self.termination["authority_mac"] = sign(self.termination, TERMINATION_KEY)

        result = self.accept()

        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertEqual(self.writer.read_scope(self.scope_id)["owner_id"], "old-owner")

    def test_termination_evidence_is_bound_to_s25a_liveness_digest(self) -> None:
        termination = copy.deepcopy(self.termination)
        termination["evidence_sha256"] = digest(b"different-evidence")
        termination["authority_mac"] = sign(termination, TERMINATION_KEY)

        result = self.acceptor().accept_handoff(
            observation=self.observation,
            grant=self.grant,
            authority_attestation=self.authority,
            termination_attestation=termination,
            new_lease_token=self.new_lease,
            now=self.clock.value,
        )

        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_handoff_events").fetchone()[0], 0)

    def test_new_lease_and_attestations_are_rechecked_at_cas_time(self) -> None:
        advancing = AdvancingClock(200, 1001)
        result = HandoffAcceptor(self.writer, clock=advancing).accept_handoff(
            observation=self.observation,
            grant=self.grant,
            authority_attestation=self.authority,
            termination_attestation=self.termination,
            new_lease_token=self.new_lease,
        )

        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertEqual(self.writer.read_scope(self.scope_id)["fencing_epoch"], 9)

    def test_changed_handoff_id_or_intent_is_conflict_after_acceptance(self) -> None:
        self.assertEqual(self.accept()["status"], HANDOFF_ACCEPTED_RECOVERY)
        changed = copy.deepcopy(self.grant)
        changed["handoff_id"] = "s25b-other-handoff"
        changed["intent_sha256"] = digest(b"other-intent")
        authority = copy.deepcopy(self.authority)
        authority["handoff_id"] = changed["handoff_id"]
        authority["grant_sha256"] = canonical_hash(changed)
        authority["authority_mac"] = sign(authority, AUTHORITY_KEY)
        termination = copy.deepcopy(self.termination)
        termination["handoff_id"] = changed["handoff_id"]
        termination["grant_sha256"] = canonical_hash(changed)
        termination["intent_sha256"] = changed["intent_sha256"]
        termination["authority_mac"] = sign(termination, TERMINATION_KEY)

        result = self.acceptor().accept_handoff(
            observation=self.observation,
            grant=changed,
            authority_attestation=authority,
            termination_attestation=termination,
            new_lease_token=self.new_lease,
            now=self.clock.value,
        )

        self.assertIn(result["status"], {HANDOFF_CONFLICT, HANDOFF_HOLD})
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_handoff_events").fetchone()[0], 1)

    def test_crash_before_commit_rolls_back_and_retry_can_accept(self) -> None:
        crashing = self.acceptor(fault_points={"before_commit"})
        with self.assertRaises(InjectedHandoffCrash):
            crashing.accept_handoff(
                observation=self.observation,
                grant=self.grant,
                authority_attestation=self.authority,
                termination_attestation=self.termination,
                new_lease_token=self.new_lease,
                now=self.clock.value,
            )
        self.assertEqual(self.writer.read_scope(self.scope_id)["fencing_epoch"], 9)
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_handoff_events").fetchone()[0], 0)
        self.assertEqual(self.accept()["status"], HANDOFF_ACCEPTED_RECOVERY)

    def test_response_loss_after_commit_replays(self) -> None:
        crashing = self.acceptor(fault_points={"after_commit"})
        with self.assertRaises(InjectedHandoffCrash):
            crashing.accept_handoff(
                observation=self.observation,
                grant=self.grant,
                authority_attestation=self.authority,
                termination_attestation=self.termination,
                new_lease_token=self.new_lease,
                now=self.clock.value,
            )
        self.assertEqual(self.writer.read_scope(self.scope_id)["fencing_epoch"], 10)
        self.assertEqual(self.writer.conn.execute("SELECT COUNT(*) FROM prime_queue_writer_handoff_events").fetchone()[0], 1)
        self.assertEqual(self.accept()["status"], HANDOFF_REPLAYED)

    def test_new_lease_and_scope_are_bound_in_same_cas(self) -> None:
        changed = copy.deepcopy(self.grant)
        changed["new_lease_expires_at"] = 199
        authority = copy.deepcopy(self.authority)
        authority["grant_sha256"] = canonical_hash(changed)
        authority["authority_mac"] = sign(authority, AUTHORITY_KEY)
        termination = copy.deepcopy(self.termination)
        termination["grant_sha256"] = canonical_hash(changed)
        termination["authority_mac"] = sign(termination, TERMINATION_KEY)

        result = self.acceptor().accept_handoff(
            observation=self.observation,
            grant=changed,
            authority_attestation=authority,
            termination_attestation=termination,
            new_lease_token=self.new_lease,
            now=self.clock.value,
        )

        self.assertEqual(result["status"], HANDOFF_HOLD)
        self.assertEqual(self.writer.read_scope(self.scope_id)["fencing_epoch"], 9)

    def test_source_surface_has_no_queue_file_writer_or_recovery_call(self) -> None:
        source = (REPO_ROOT / "modules" / "w5_dispatch_bridge_s0" / "handoff_acceptor.py").read_text()
        for forbidden in ("os.replace", "durable_new", "recover_locked", "execute_transition", "write_bytes", "write_text"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
