"""W5-S25K tests for the isolated asymmetric Authority design contract."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from support.w5_s25k_replay_matrix import (  # noqa: E402
    DESIGN_ONLY,
    HOLD,
    MANUAL_REVIEW,
    NOT_CLAIMED,
    RECOVERY_REQUIRED,
    TEST_BLOCKED,
    evaluate_asymmetric_contract,
)


class W5S25KReplayMatrixTests(unittest.TestCase):
    @staticmethod
    def _observation() -> dict[str, object]:
        return {
            "case_id": "active-key-exact-bindings",
            "architecture": {
                "format": "s25k.quarantine-grant.v1",
                "algorithm": "Ed25519-v1",
                "canonicalization": "RFC8785-JCS-v1",
                "domain_separator": "S25K/QUARANTINE-GRANT/v1\x00",
                "fallback": "NONE",
                "private_key_policy": "EXTERNAL_ONLY",
                "trust_root_source": "EXTERNAL_PINNED_BUNDLE",
                "revocation_source": "EXTERNAL_SIGNED_SNAPSHOT",
            },
            "dependency": {
                "lock_status": "PROPOSED_HASH_PINNED",
                "package": "cryptography",
                "package_version": "50.0.2",
                "package_hash": "sha256:" + "0" * 64,
                "backend": "OpenSSL",
                "backend_version": "4.0.3",
                "python_version": "3.10.12",
                "fallback": "NONE",
            },
            "vector": {
                "vector_id": "RFC8032-ED25519-1",
                "status": "DECLARED_EXTERNAL_FIXTURE",
                "private_key_source": "ISOLATED_FIXTURE",
                "signature_source": "EXTERNAL_ORACLE",
            },
            "trust": {
                "root_status": "PINNED",
                "authority_status": "ACTIVE",
                "root_id": "root-1",
                "root_fingerprint": "sha256:" + "1" * 64,
                "authority_id": "authority-1",
                "key_id": "key-1",
                "authority_sequence": 7,
            },
            "revocation": {
                "snapshot_status": "CLEAR",
                "key_revoked": False,
                "grant_revoked": False,
                "sequence_floor": 6,
            },
            "replay": {
                "snapshot_status": "PRESENT",
                "grant_status": "UNUSED",
                "sequence_status": "ABOVE_FLOOR",
                "incarnation_status": "PROVEN",
            },
            "binding": {
                "authority_store_independent": True,
                "root": "MATCH",
                "authority_store": "MATCH",
                "scope": "MATCH",
                "store": "MATCH",
                "transaction": "MATCH",
                "idempotency": "MATCH",
                "evidence": "MATCH",
                "generation": "MATCH",
                "fence": "MATCH",
            },
            "lease": {
                "status": "FRESH",
                "now": 150,
                "not_before": 100,
                "expires_at": 200,
            },
            "generation": {
                "status": "MATCH",
                "incarnation": "PROVEN",
                "aba": False,
                "reused": False,
                "foreign_writer": False,
            },
            "clock": {"status": "FRESH", "monotonic": True},
            "faults": {"crash_phase": "NONE", "cas_outcome": "NOT_ATTEMPTED", "foreign_writer": "NONE"},
        }

    def test_complete_contract_is_design_only_and_never_authorizes(self) -> None:
        result = evaluate_asymmetric_contract(self._observation())

        self.assertEqual(result["status"], NOT_CLAIMED)
        self.assertEqual(result["decision"], DESIGN_ONLY)
        self.assertEqual(result["reason"], "ASYMMETRIC_CONTRACT_DESIGN_ONLY")
        self.assertEqual(result["cryptographic_status"], "NOT_VERIFIED")
        self.assertEqual(result["dependency_status"], "PROPOSED_HASH_PINNED")
        for field in (
            "authority_claim",
            "architecture_claim",
            "cross_store_atomicity",
            "exactly_once_claim",
        ):
            self.assertEqual(result[field], NOT_CLAIMED)
        for field in (
            "capability_issued",
            "write_authorized",
            "cas_attempted",
            "cas_committed",
            "fence_issued",
            "persistence_performed",
            "quarantine_persisted",
            "mutation_allowed",
            "resume_allowed",
            "recovery_authority",
        ):
            self.assertFalse(result[field])

    def test_missing_section_fails_closed(self) -> None:
        observation = self._observation()
        observation.pop("revocation")

        result = evaluate_asymmetric_contract(observation)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], MANUAL_REVIEW)
        self.assertIn("MISSING_REVOCATION", result["audit_gaps"])

    def test_unsealed_dependency_is_test_blocked_not_green(self) -> None:
        observation = self._observation()
        observation["dependency"]["lock_status"] = "UNLOCKED"

        result = evaluate_asymmetric_contract(observation)

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["decision"], HOLD)
        self.assertEqual(result["dependency_status"], TEST_BLOCKED)
        self.assertFalse(result["write_authorized"])

    def test_backend_or_hash_mismatch_is_test_blocked(self) -> None:
        for field, value in (("backend", "other"), ("package_hash", "not-a-hash")):
            observation = self._observation()
            observation["dependency"][field] = value

            result = evaluate_asymmetric_contract(observation)

            self.assertEqual(result["status"], TEST_BLOCKED)
            self.assertEqual(result["decision"], HOLD)

    def test_algorithm_downgrade_and_fallback_are_not_implicit(self) -> None:
        for field, value in (("algorithm", "HMAC-SHA256-TEST-ONLY"), ("fallback", "HMAC")):
            observation = self._observation()
            observation["architecture"][field] = value

            result = evaluate_asymmetric_contract(observation)

            self.assertEqual(result["status"], HOLD)
            self.assertEqual(result["decision"], HOLD)

    def test_legacy_canonicalization_and_domain_drift_fail_closed(self) -> None:
        legacy = self._observation()
        legacy["architecture"]["canonicalization"] = "json-sortkeys-v1"
        domain = self._observation()
        domain["architecture"]["domain_separator"] = "other"

        legacy_result = evaluate_asymmetric_contract(legacy)
        domain_result = evaluate_asymmetric_contract(domain)

        self.assertEqual(legacy_result["status"], HOLD)
        self.assertEqual(domain_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(domain_result["decision"], MANUAL_REVIEW)

    def test_external_vector_is_metadata_only(self) -> None:
        observation = self._observation()
        observation["vector"]["status"] = "MATCHED_AND_AUTHORIZED"

        result = evaluate_asymmetric_contract(observation)

        self.assertEqual(result["status"], HOLD)
        self.assertEqual(result["cryptographic_status"], "NOT_CLAIMED")

    def test_unknown_revocation_or_replay_snapshot_holds(self) -> None:
        for section, field, value in (
            ("revocation", "snapshot_status", "STALE"),
            ("replay", "snapshot_status", "MISSING"),
        ):
            observation = self._observation()
            observation[section][field] = value

            result = evaluate_asymmetric_contract(observation)

            self.assertEqual(result["status"], HOLD)
            self.assertEqual(result["decision"], HOLD)

    def test_revocation_and_replay_contradictions_require_manual_review(self) -> None:
        for section, field, value in (
            ("revocation", "key_revoked", True),
            ("replay", "grant_status", "REPLAYED"),
            ("replay", "sequence_status", "AT_OR_BELOW_FLOOR"),
        ):
            observation = self._observation()
            observation[section][field] = value

            result = evaluate_asymmetric_contract(observation)

            self.assertEqual(result["status"], RECOVERY_REQUIRED)
            self.assertEqual(result["decision"], MANUAL_REVIEW)

    def test_lease_boundaries_hold(self) -> None:
        for now in (99, 200):
            observation = self._observation()
            observation["lease"]["now"] = now

            result = evaluate_asymmetric_contract(observation)

            self.assertEqual(result["status"], HOLD)
            self.assertEqual(result["reason"], "LEASE_NOT_CURRENT")

    def test_binding_mismatch_and_unknown_are_distinct(self) -> None:
        mismatch = self._observation()
        mismatch["binding"]["scope"] = "MISMATCH"
        unknown = self._observation()
        unknown["binding"]["scope"] = "UNKNOWN"

        mismatch_result = evaluate_asymmetric_contract(mismatch)
        unknown_result = evaluate_asymmetric_contract(unknown)

        self.assertEqual(mismatch_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(unknown_result["status"], HOLD)

    def test_generation_aba_and_missing_incarnation_proof_require_review(self) -> None:
        for field, value in (("aba", True), ("incarnation", "UNKNOWN")):
            observation = self._observation()
            observation["generation"][field] = value

            result = evaluate_asymmetric_contract(observation)

            self.assertEqual(result["status"], RECOVERY_REQUIRED)
            self.assertEqual(result["decision"], MANUAL_REVIEW)

    def test_clock_and_unknown_outcomes_fail_closed(self) -> None:
        non_monotonic = self._observation()
        non_monotonic["clock"] = {"status": "NON_MONOTONIC", "monotonic": False}
        unknown_cas = self._observation()
        unknown_cas["faults"]["crash_phase"] = "AFTER_UNKNOWN_CAS"

        clock_result = evaluate_asymmetric_contract(non_monotonic)
        cas_result = evaluate_asymmetric_contract(unknown_cas)

        self.assertEqual(clock_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(cas_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(cas_result["reason"], "UNKNOWN_OUTCOME_REQUIRES_REVIEW")

    def test_process_restart_never_grants_resume(self) -> None:
        for phase in ("BEFORE_VERIFICATION", "AFTER_VERIFICATION", "AFTER_DESIGN_ONLY"):
            observation = self._observation()
            observation["faults"]["crash_phase"] = phase

            result = evaluate_asymmetric_contract(observation)

            self.assertEqual(result["status"], NOT_CLAIMED)
            self.assertEqual(result["decision"], DESIGN_ONLY)
            self.assertIn("PROCESS_RESTART", result["audit_gaps"])
            self.assertFalse(result["resume_allowed"])

    def test_dangerous_untrusted_claim_is_rejected(self) -> None:
        observation = self._observation()
        observation["authorized"] = True

        result = evaluate_asymmetric_contract(observation)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["decision"], MANUAL_REVIEW)
        self.assertEqual(result["reason"], "UNTRUSTED_AUTHORITY_CLAIM")
        self.assertFalse(result["write_authorized"])

    def test_authority_store_must_be_independent(self) -> None:
        observation = self._observation()
        observation["binding"]["authority_store_independent"] = False

        result = evaluate_asymmetric_contract(observation)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "AUTHORITY_NOT_INDEPENDENT")

    def test_result_is_not_mutated_by_fixture_reuse(self) -> None:
        observation = self._observation()
        before = deepcopy(observation)

        evaluate_asymmetric_contract(observation)

        self.assertEqual(observation, before)

    def test_support_surface_is_stdlib_only_and_nonmutating(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25k_replay_matrix.py").read_text()
        for forbidden in (
            "import cryptography",
            "from cryptography",
            "nacl",
            "bcrypt",
            "sqlite3",
            "os.open(",
            "subprocess",
            "socket",
            "urllib",
            "time.",
            "datetime",
            "Path(",
            "write_bytes",
            "write_text",
            "replace(",
            "rename(",
            "unlink(",
            "mkdir(",
            "commit(",
            "quarantine(",
            "recover_operation(",
            "execute_recovery(",
            "cas(",
            "fence(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("evaluate_asymmetric_contract", source)


if __name__ == "__main__":
    unittest.main()
