"""W5-S25J tests for pure cryptographic/provenance evidence only."""

from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from support.w5_s25j_crypto_boundary import (  # noqa: E402
    ALREADY_QUARANTINED,
    GRANT_FORMAT,
    HOLD,
    INCONCLUSIVE,
    REJECTED_BINDING,
    REJECTED_CRYPTO,
    REJECTED_REPLAY,
    REJECTED_TRUST,
    STALE,
    TEST_ALGORITHM,
    UNKNOWN,
    VERIFIED_NO_CAPABILITY,
    WOULD_MATCH,
    evaluate_fake_cas,
    verify_authority_grant,
)


SECRET = b"s25j-test-authority-secret"
DOMAIN_SEPARATOR = b"S25J/QUARANTINE-GRANT/v1\x00"
_DEFAULT = object()


class W5S25JCryptoBoundaryTests(unittest.TestCase):
    @staticmethod
    def _payload() -> dict[str, object]:
        return {
            "action": "PERSIST_QUARANTINE",
            "grant_id": "grant-1",
            "authority_sequence": 1,
            "target": {
                "root_binding": "root-1",
                "store_instance_id": "store-1",
                "scope_id": "scope-1",
                "transaction_id": "tx-1",
                "idempotency_key": "idem-1",
            },
            "expected": {
                "state": "IN_DOUBT",
                "generation": "generation-1",
                "event_head": "event-1",
                "handoff_head": "handoff-1",
                "subject_fence": "fence-1",
            },
            "lease": {"lease_id": "lease-1", "not_before": 100, "expires_at": 200},
            "provenance": {
                "observer_schema": "prime-queue-quarantine-observer-v1",
                "observation_id": "observation-1",
                "evidence_digest": "evidence-1",
            },
            "allowed_transition": "PENDING_TO_QUARANTINED",
            "cross_store": False,
            "max_effects": 1,
        }

    @classmethod
    def _signing_bytes(cls, envelope: dict[str, object]) -> bytes:
        payload = envelope["payload"]
        unsigned = {
            "algorithm": envelope["algorithm"],
            "authority_id": envelope["authority_id"],
            "format": envelope["format"],
            "key_id": envelope["key_id"],
            "payload": payload,
        }
        return DOMAIN_SEPARATOR + json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def _envelope(cls) -> dict[str, object]:
        envelope: dict[str, object] = {
            "format": GRANT_FORMAT,
            "algorithm": TEST_ALGORITHM,
            "authority_id": "authority-1",
            "key_id": "key-1",
            "payload": cls._payload(),
            "signature": "",
        }
        signature = hmac.new(SECRET, cls._signing_bytes(envelope), hashlib.sha256).digest()
        envelope["signature"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return envelope

    @staticmethod
    def _trust() -> dict[str, object]:
        return {
            "key-1": {
                "status": "ACTIVE",
                "algorithm": TEST_ALGORITHM,
                "authority_id": "authority-1",
                "secret": SECRET,
                "revoked_grant_ids": [],
            }
        }

    @classmethod
    def _replay(cls, *, used: list[str] | None = None, sequence: int = 0) -> dict[str, object]:
        return {
            "schema": "s25j.replay-snapshot.v1",
            "snapshot_id": "replay-1",
            "used_grant_ids": list(used or []),
            "last_sequences": {"authority-1": sequence},
        }

    @classmethod
    def _expected_binding(cls) -> dict[str, object]:
        payload = cls._payload()
        target = payload["target"]
        expected = payload["expected"]
        lease = payload["lease"]
        provenance = payload["provenance"]
        return {
            "action": payload["action"],
            "authority_id": "authority-1",
            "grant_id": payload["grant_id"],
            "authority_sequence": payload["authority_sequence"],
            "root_binding": target["root_binding"],
            "store_instance_id": target["store_instance_id"],
            "scope_id": target["scope_id"],
            "transaction_id": target["transaction_id"],
            "idempotency_key": target["idempotency_key"],
            "state": expected["state"],
            "generation": expected["generation"],
            "event_head": expected["event_head"],
            "handoff_head": expected["handoff_head"],
            "subject_fence": expected["subject_fence"],
            "lease_id": lease["lease_id"],
            "observation_schema": provenance["observer_schema"],
            "observation_id": provenance["observation_id"],
            "evidence_digest": provenance["evidence_digest"],
            "allowed_transition": payload["allowed_transition"],
            "cross_store": payload["cross_store"],
            "max_effects": payload["max_effects"],
        }

    def _verify(self, envelope: object = _DEFAULT, *, trust: object = _DEFAULT, replay: object = _DEFAULT, expected: object = _DEFAULT, now: int = 150) -> dict[str, object]:
        return verify_authority_grant(
            self._envelope() if envelope is _DEFAULT else envelope,
            self._trust() if trust is _DEFAULT else trust,
            replay_snapshot=self._replay() if replay is _DEFAULT else replay,
            expected_binding=self._expected_binding() if expected is _DEFAULT else expected,
            now=now,
        )

    def test_valid_golden_vector_is_verified_without_capability(self) -> None:
        result = self._verify()

        self.assertEqual(result["status"], VERIFIED_NO_CAPABILITY)
        self.assertEqual(result["crypto_status"], "VALID")
        self.assertEqual(result["trust_status"], "ACTIVE")
        self.assertEqual(result["replay_status"], "UNUSED")
        self.assertEqual(result["binding_status"], "MATCH")
        self.assertFalse(result["capability_issued"])
        self.assertFalse(result["write_authorized"])
        self.assertFalse(result["persistence_performed"])
        self.assertFalse(result["fence_issued"])

    def test_signature_bit_flip_is_rejected_crypto(self) -> None:
        envelope = self._envelope()
        signature = str(envelope["signature"])
        envelope["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]

        result = self._verify(envelope)

        self.assertEqual(result["status"], REJECTED_CRYPTO)
        self.assertEqual(result["reason"], "SIGNATURE_INVALID")
        self.assertFalse(result["write_authorized"])

    def test_unknown_and_revoked_keys_are_rejected_trust(self) -> None:
        unknown = self._verify(trust={})
        revoked_trust = self._trust()
        revoked_trust["key-1"]["status"] = "REVOKED"
        revoked = self._verify(trust=revoked_trust)

        self.assertEqual(unknown["status"], REJECTED_TRUST)
        self.assertEqual(revoked["status"], REJECTED_TRUST)

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self) -> None:
        duplicate = b'{"format":"s25j.quarantine-grant.v1","format":"other"}'
        nonfinite = b'{"format":"s25j.quarantine-grant.v1","value":NaN}'

        duplicate_result = self._verify(duplicate)
        nonfinite_result = self._verify(nonfinite)

        self.assertEqual(duplicate_result["status"], REJECTED_CRYPTO)
        self.assertEqual(nonfinite_result["status"], REJECTED_CRYPTO)

    def test_scope_or_generation_binding_mismatch_is_rejected(self) -> None:
        expected = self._expected_binding()
        expected["scope_id"] = "other-scope"
        result = self._verify(expected=expected)

        self.assertEqual(result["status"], REJECTED_BINDING)
        self.assertEqual(result["reason"], "LOCAL_BINDING_MISMATCH")

    def test_expired_and_future_leases_hold(self) -> None:
        expired = self._verify(now=200)
        future = self._verify(now=99)

        self.assertEqual(expired["status"], HOLD)
        self.assertEqual(future["status"], HOLD)
        self.assertEqual(expired["reason"], "LEASE_NOT_CURRENT")

    def test_missing_or_untrusted_replay_snapshot_is_inconclusive(self) -> None:
        missing = self._verify(replay=None)
        untrusted = self._verify(replay={"schema": "other"})

        self.assertEqual(missing["status"], INCONCLUSIVE)
        self.assertEqual(untrusted["status"], INCONCLUSIVE)
        self.assertEqual(missing["replay_status"], "UNKNOWN")

    def test_replayed_grant_and_sequence_are_rejected(self) -> None:
        grant_replay = self._verify(replay=self._replay(used=["grant-1"]))
        sequence_replay = self._verify(replay=self._replay(sequence=1))

        self.assertEqual(grant_replay["status"], REJECTED_REPLAY)
        self.assertEqual(sequence_replay["status"], REJECTED_REPLAY)

    def test_revoked_grant_and_sequence_floor_are_rejected(self) -> None:
        revoked_trust = self._trust()
        revoked_trust["key-1"]["revoked_grant_ids"] = ["grant-1"]
        revoked_grant = self._verify(trust=revoked_trust)
        floor_trust = self._trust()
        floor_trust["key-1"]["sequence_floor"] = 1
        revoked_sequence = self._verify(trust=floor_trust)

        self.assertEqual(revoked_grant["status"], REJECTED_REPLAY)
        self.assertEqual(revoked_sequence["status"], REJECTED_REPLAY)

    def test_canonical_key_order_does_not_change_signature(self) -> None:
        envelope = self._envelope()
        reordered = {
            "signature": envelope["signature"],
            "payload": deepcopy(envelope["payload"]),
            "key_id": envelope["key_id"],
            "authority_id": envelope["authority_id"],
            "algorithm": envelope["algorithm"],
            "format": envelope["format"],
        }

        result = self._verify(reordered)

        self.assertEqual(result["status"], VERIFIED_NO_CAPABILITY)

    def test_fake_cas_is_evidence_only(self) -> None:
        expected = {"state": "IN_DOUBT", "generation": "g1", "fence": "f1"}
        matching = evaluate_fake_cas(expected, dict(expected))
        stale = evaluate_fake_cas(expected, {**expected, "fence": "f2"})
        unknown = evaluate_fake_cas(expected, {"state": "IN_DOUBT", "generation": float("nan")})
        already = evaluate_fake_cas(expected, {**expected, "state": "QUARANTINED"})

        self.assertEqual(matching["result"], WOULD_MATCH)
        self.assertEqual(stale["result"], STALE)
        self.assertEqual(unknown["result"], UNKNOWN)
        self.assertEqual(already["result"], ALREADY_QUARANTINED)
        for result in (matching, stale, unknown, already):
            self.assertFalse(result["mutation_performed"])
            self.assertFalse(result["persisted"])
            self.assertFalse(result["write_authorized"])

    def test_crypto_support_surface_is_stdlib_only_and_nonmutating(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25j_crypto_boundary.py").read_text()
        for forbidden in (
            "cryptography",
            "nacl",
            "bcrypt",
            "PrimeQueueWriter",
            "RecoveryExecutor",
            "HandoffAcceptor",
            "sqlite3",
            "fcntl",
            "pathlib",
            "subprocess",
            "socket",
            "ssl",
            "urllib",
            "open(",
            "Path.",
            "write_bytes",
            "write_text",
            "replace(",
            "rename(",
            "unlink(",
            "mkdir(",
            "quarantine(",
            "recover_operation(",
            "execute_recovery(",
            "durable_new(",
            "_claim_phase(",
            "_mark_state(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("hmac.compare_digest", source)


if __name__ == "__main__":
    unittest.main()
