"""W5-S25L tests for public golden-vector and canonicalization metadata."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from support.w5_s25l_canonicalization_boundary import (  # noqa: E402
    DESIGN_ONLY,
    HOLD,
    JCS_CANONICALIZATION,
    LEGACY_REGRESSION_ONLY,
    MANUAL_REVIEW,
    NOT_CLAIMED,
    RECOVERY_REQUIRED,
    RFC8032_SOURCE,
    S25K_DOMAIN_SEPARATOR_HEX,
    S25K_FORMAT,
    TEST_BLOCKED,
    evaluate_canonicalization_policy,
    evaluate_legacy_boundary,
    evaluate_preimage_contract,
    evaluate_rfc8032_vector,
)


class W5S25LCanonicalizationBoundaryTests(unittest.TestCase):
    @staticmethod
    def _vector(vector_id: str = "RFC8032-ED25519-1") -> dict[str, object]:
        vectors = {
            "RFC8032-ED25519-1": {
                "message_hex": "",
                "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "signature_hex": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            },
            "RFC8032-ED25519-2": {
                "message_hex": "72",
                "public_key_hex": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "signature_hex": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            },
            "RFC8032-ED25519-3": {
                "message_hex": "af82",
                "public_key_hex": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "signature_hex": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            },
            "RFC8032-ED25519-SHA-ABC": {
                "message_hex": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "public_key_hex": "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "signature_hex": "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            },
        }
        values = vectors[vector_id]
        return {
            "vector_id": vector_id,
            "algorithm": "Ed25519",
            "source": RFC8032_SOURCE,
            "private_key_material": "NOT_INCLUDED",
            "verification_status": "NOT_RUN",
            **values,
        }

    @staticmethod
    def _long_vector() -> dict[str, object]:
        return {
            "vector_id": "RFC8032-ED25519-1024",
            "algorithm": "Ed25519",
            "source": RFC8032_SOURCE,
            "private_key_material": "NOT_INCLUDED",
            "verification_status": "NOT_RUN",
            "message_length": 1023,
            "message_sha256": "358c67baee6b3e0265787951d1840a8468b9e9044852f1c67229a892b2cc0d22",
            "public_key_hex": "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            "signature_hex": "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
        }

    @staticmethod
    def _preimage() -> dict[str, object]:
        return {
            "case_id": "s25k-grant-preimage",
            "format": S25K_FORMAT,
            "algorithm": "Ed25519-v1",
            "canonicalization": JCS_CANONICALIZATION,
            "domain_separator_hex": S25K_DOMAIN_SEPARATOR_HEX,
            "preimage_fields": ["algorithm", "canonicalization", "format", "authority_id", "key_id", "payload"],
            "authority_id_bound": True,
            "key_id_bound": True,
            "payload_bound": True,
            "jcs_execution": "NOT_IMPLEMENTED",
        }

    @staticmethod
    def _policy() -> dict[str, object]:
        return {
            "case_id": "jcs-policy",
            "canonicalization": JCS_CANONICALIZATION,
            "sort_order": "UTF16_CODE_UNITS",
            "unicode_normalization": "PRESERVE_NO_NORMALIZATION",
            "duplicate_keys": "REJECT",
            "float_policy": "ECMASCRIPT_FINITE",
            "array_order": "PRESERVE",
            "utf8": "UTF8",
            "implementation_status": "NOT_IMPLEMENTED",
        }

    def test_public_rfc_vectors_are_exact_metadata_without_crypto_claim(self) -> None:
        for vector_id in (
            "RFC8032-ED25519-1",
            "RFC8032-ED25519-2",
            "RFC8032-ED25519-3",
            "RFC8032-ED25519-SHA-ABC",
        ):
            result = evaluate_rfc8032_vector(self._vector(vector_id))

            self.assertEqual(result["status"], NOT_CLAIMED)
            self.assertEqual(result["decision"], DESIGN_ONLY)
            self.assertEqual(result["vector_status"], "METADATA_EXACT")
            self.assertEqual(result["signature_verification"], NOT_CLAIMED)
            self.assertFalse(result["capability_issued"])

    def test_long_rfc_vector_is_blocked_until_full_message_fixture_exists(self) -> None:
        result = evaluate_rfc8032_vector(self._long_vector())

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["decision"], HOLD)
        self.assertEqual(result["reason"], "FULL_MESSAGE_FIXTURE_REQUIRED")
        self.assertEqual(result["vector_status"], "METADATA_EXACT")

    def test_vector_bitflip_is_manual_review(self) -> None:
        for field in ("message_hex", "public_key_hex", "signature_hex"):
            vector = self._vector()
            value = str(vector[field])
            vector[field] = ("0" if value[:1] != "0" else "1") + value[1:]

            result = evaluate_rfc8032_vector(vector)

            self.assertEqual(result["status"], RECOVERY_REQUIRED)
            self.assertEqual(result["decision"], MANUAL_REVIEW)
            self.assertEqual(result["reason"], "VECTOR_BYTES_MISMATCH" if field != "message_hex" else "MESSAGE_BYTES_MISMATCH")

    def test_unknown_algorithm_source_or_vector_holds(self) -> None:
        for mutation in (
            {"algorithm": "Ed25519ph"},
            {"source": "LOCAL_MEMORY"},
            {"vector_id": "RFC8032-ED25519-UNKNOWN"},
        ):
            vector = self._vector()
            vector.update(mutation)

            result = evaluate_rfc8032_vector(vector)

            self.assertEqual(result["status"], HOLD if mutation.get("vector_id") else TEST_BLOCKED if mutation.get("source") else HOLD)

    def test_private_seed_and_validity_claim_are_rejected(self) -> None:
        private = self._vector()
        private["private_key_material"] = "seed-present"
        claimed = self._vector()
        claimed["verification_status"] = "VALID"

        private_result = evaluate_rfc8032_vector(private)
        claimed_result = evaluate_rfc8032_vector(claimed)

        self.assertEqual(private_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(claimed_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(claimed_result["reason"], "VERIFICATION_OVERCLAIM")

    def test_preimage_contract_is_exact_but_jcs_remains_test_blocked(self) -> None:
        result = evaluate_preimage_contract(self._preimage())

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["decision"], HOLD)
        self.assertEqual(result["reason"], "JCS_NOT_IMPLEMENTED")
        self.assertEqual(result["canonicalization_status"], "NOT_IMPLEMENTED")
        self.assertFalse(result["write_authorized"])

    def test_preimage_domain_algorithm_and_field_mutations_are_reviewed(self) -> None:
        for field, value in (
            ("domain_separator_hex", "00"),
            ("algorithm", "Ed25519ph"),
            ("format", "other"),
            ("canonicalization", "json-sortkeys-v1"),
            ("preimage_fields", ["payload"]),
        ):
            preimage = self._preimage()
            preimage[field] = value

            result = evaluate_preimage_contract(preimage)

            self.assertEqual(result["status"], RECOVERY_REQUIRED)
            self.assertEqual(result["decision"], MANUAL_REVIEW)

    def test_preimage_binding_and_execution_unknown_are_fail_closed(self) -> None:
        missing_binding = self._preimage()
        missing_binding["key_id_bound"] = False
        unknown_execution = self._preimage()
        unknown_execution["jcs_execution"] = "UNKNOWN"
        claimed_execution = self._preimage()
        claimed_execution["jcs_execution"] = "INDEPENDENT_MATCH"

        missing_result = evaluate_preimage_contract(missing_binding)
        unknown_result = evaluate_preimage_contract(unknown_execution)
        claimed_result = evaluate_preimage_contract(claimed_execution)

        self.assertEqual(missing_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(unknown_result["status"], HOLD)
        self.assertEqual(claimed_result["status"], RECOVERY_REQUIRED)

    def test_jcs_policy_is_explicitly_not_implemented(self) -> None:
        result = evaluate_canonicalization_policy(self._policy())

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["reason"], "JCS_NOT_IMPLEMENTED")

    def test_jcs_policy_mutations_are_manual_review(self) -> None:
        for field, value in (
            ("sort_order", "PYTHON_CODEPOINTS"),
            ("unicode_normalization", "NFC"),
            ("duplicate_keys", "LAST_WINS"),
            ("float_policy", "PYTHON_JSON"),
            ("array_order", "SORTED"),
            ("utf8", "ASCII_ESCAPE"),
        ):
            policy = self._policy()
            policy[field] = value

            result = evaluate_canonicalization_policy(policy)

            self.assertEqual(result["status"], RECOVERY_REQUIRED)
            self.assertEqual(result["decision"], MANUAL_REVIEW)

    def test_jcs_policy_unknown_or_claimed_backend_is_not_green(self) -> None:
        unknown = self._policy()
        unknown["implementation_status"] = "UNKNOWN"
        claimed = self._policy()
        claimed["implementation_status"] = "INDEPENDENT_MATCH"

        unknown_result = evaluate_canonicalization_policy(unknown)
        claimed_result = evaluate_canonicalization_policy(claimed)

        self.assertEqual(unknown_result["status"], HOLD)
        self.assertEqual(claimed_result["status"], RECOVERY_REQUIRED)

    def test_legacy_regression_is_never_jcs(self) -> None:
        result = evaluate_legacy_boundary(
            {
                "case_id": "legacy-v1",
                "legacy_id": "json-sortkeys-v1",
                "legacy_status": "REGRESSION_ONLY",
                "jcs_status": "NOT_IMPLEMENTED",
                "labeled_as_jcs": False,
            }
        )

        self.assertEqual(result["status"], NOT_CLAIMED)
        self.assertEqual(result["decision"], LEGACY_REGRESSION_ONLY)
        self.assertEqual(result["canonicalization_status"], "LEGACY_ONLY")

    def test_legacy_label_or_jcs_overclaim_is_manual_review(self) -> None:
        labeled = {
            "legacy_id": "json-sortkeys-v1",
            "legacy_status": "REGRESSION_ONLY",
            "jcs_status": "NOT_IMPLEMENTED",
            "labeled_as_jcs": True,
        }
        claimed = {
            "legacy_id": "json-sortkeys-v1",
            "legacy_status": "REGRESSION_ONLY",
            "jcs_status": "INDEPENDENT_MATCH",
            "labeled_as_jcs": False,
        }

        labeled_result = evaluate_legacy_boundary(labeled)
        claimed_result = evaluate_legacy_boundary(claimed)

        self.assertEqual(labeled_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(claimed_result["status"], RECOVERY_REQUIRED)

    def test_all_results_have_no_authority_or_mutation_flags(self) -> None:
        observations = [
            evaluate_rfc8032_vector(self._vector()),
            evaluate_preimage_contract(self._preimage()),
            evaluate_canonicalization_policy(self._policy()),
            evaluate_legacy_boundary(
                {
                    "legacy_id": "json-sortkeys-v1",
                    "legacy_status": "REGRESSION_ONLY",
                    "jcs_status": "NOT_IMPLEMENTED",
                    "labeled_as_jcs": False,
                }
            ),
        ]
        for result in observations:
            self.assertEqual(result["authority_claim"], NOT_CLAIMED)
            self.assertFalse(result["capability_issued"])
            self.assertFalse(result["write_authorized"])
            self.assertFalse(result["persistence_performed"])
            self.assertFalse(result["cas_attempted"])
            self.assertFalse(result["fence_issued"])

    def test_inputs_are_not_mutated(self) -> None:
        vector = self._vector()
        preimage = self._preimage()
        policy = self._policy()
        snapshots = [deepcopy(value) for value in (vector, preimage, policy)]

        evaluate_rfc8032_vector(vector)
        evaluate_preimage_contract(preimage)
        evaluate_canonicalization_policy(policy)

        self.assertEqual(vector, snapshots[0])
        self.assertEqual(preimage, snapshots[1])
        self.assertEqual(policy, snapshots[2])

    def test_support_surface_is_stdlib_only_and_nonmutating(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25l_canonicalization_boundary.py").read_text()
        for forbidden in (
            "import cryptography",
            "from cryptography",
            "import nacl",
            "from nacl",
            "import OpenSSL",
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
            "verify_signature(",
            "sign(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("evaluate_rfc8032_vector", source)
        self.assertIn("RFC8032-ED25519-1", source)


if __name__ == "__main__":
    unittest.main()
