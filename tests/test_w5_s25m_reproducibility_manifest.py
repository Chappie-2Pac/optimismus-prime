"""W5-S25M tests for the pure reproducibility-manifest contract."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from support.w5_s25m_reproducibility_manifest import (  # noqa: E402
    DESIGN_ONLY,
    LOCKED_TEST_PASS,
    NOT_CLAIMED,
    PRODUCTION_NOT_AUTHORIZED,
    PROPOSAL_ONLY,
    TEST_BLOCKED,
    evaluate_reproducibility_manifest,
    manifest_digest,
)


class W5S25MReproducibilityManifestTests(unittest.TestCase):
    @staticmethod
    def _raw_manifest(*, sealed: bool = False) -> dict[str, object]:
        h1 = "1" * 64
        h2 = "2" * 64
        h3 = "3" * 64
        h4 = "4" * 64
        h5 = "5" * 64
        h6 = "6" * 64
        h7 = "7" * 64
        return {
            "schema_version": "s25m.reproducibility-manifest.v1",
            "profile": "TEST",
            "source": {
                "repository_id": "optimismus-prime",
                "commit": "commit-test-1",
                "tree_sha256": h1,
            },
            "runtime": {
                "python_implementation": "CPython",
                "python_version": "3.10.12",
                "python_abi": "cp310",
                "platform_tag": "manylinux_2_36_x86_64",
                "os_id": "linux",
                "architecture": "x86_64",
                "libc_id": "glibc-2.36",
                "runtime_image_sha256": h2,
            },
            "lock": {
                "lock_status": "LOCKED" if sealed else "PROPOSED",
                "lockfile_sha256": h3,
                "lock_format": "requirements-hashes-v1",
                "resolver_name": "test-resolver",
                "resolver_version": "1.0.0",
                "hash_mode": "REQUIRED",
                "dependency_graph_sha256": h4,
                "artifact_set_sha256": h5,
            },
            "artifacts": [
                {
                    "name": "cryptography",
                    "normalized_name": "cryptography",
                    "version": "50.0.2",
                    "dependency_role": "DIRECT",
                    "artifact_type": "WHEEL",
                    "filename": "cryptography-50.0.2-cp310.whl",
                    "sha256": h1,
                    "source_reference": "https://example.invalid/artifacts/cryptography",
                    "platform_tag": "manylinux_2_36_x86_64",
                    "abi_tag": "cp310",
                    "parent_purls": [],
                },
                {
                    "name": "cffi",
                    "normalized_name": "cffi",
                    "version": "1.17.1",
                    "dependency_role": "TRANSITIVE",
                    "artifact_type": "WHEEL",
                    "filename": "cffi-1.17.1-cp310.whl",
                    "sha256": h2,
                    "source_reference": "https://example.invalid/artifacts/cffi",
                    "platform_tag": "manylinux_2_36_x86_64",
                    "abi_tag": "cp310",
                    "parent_purls": ["pkg:pypi/cryptography@50.0.2"],
                },
                {
                    "name": "libcrypto",
                    "normalized_name": "libcrypto",
                    "version": "3.0.2",
                    "dependency_role": "TRANSITIVE",
                    "artifact_type": "NATIVE",
                    "filename": "libcrypto.so.3",
                    "sha256": h3,
                    "source_reference": "https://example.invalid/artifacts/libcrypto",
                    "platform_tag": "linux-x86_64",
                    "abi_tag": "system",
                    "parent_purls": ["pkg:pypi/cryptography@50.0.2"],
                },
            ],
            "provider": {
                "algorithm": "Ed25519",
                "package_purl": "pkg:pypi/cryptography@50.0.2",
                "package_version": "50.0.2",
                "package_artifact_sha256": h1,
                "effective_provider": "OpenSSL",
                "provider_version": "4.0.3",
                "provider_build_id": "openssl-provider-build-1",
                "native_artifact_sha256": h3,
                "provider_config_sha256": h4,
                "signature_encoding": "raw-ed25519-32-64",
                "canonicalization_profile": "RFC8785-JCS-v1",
            },
            "fips": {
                "required": False,
                "status": "NOT_REQUIRED",
                "module_id": "not-required",
                "module_version": "not-required",
                "module_sha256": h5,
                "self_test_id": "not-required",
                "self_test_result": "NOT_REQUIRED",
                "validation_reference": "not-required",
            },
            "sbom": {
                "format": "SPDX",
                "version": "2.3",
                "document_sha256": h6,
                "closure_sha256": h7,
                "generator_name": "test-sbom",
                "generator_version": "1.0.0",
                "component_count": 3,
                "includes_transitive": True,
                "includes_native": True,
                "unresolved_component_count": 0,
            },
            "oracle": {
                "oracle_id": "rfc8032-independent",
                "oracle_type": "CROSS_PROVIDER",
                "oracle_artifact_sha256": h6,
                "implementation_id": "independent-test-oracle",
                "implementation_version": "1.0.0",
                "provider_id": "independent-provider",
                "vector_set_sha256": h7,
                "input_digest": h1,
                "output_digest": h2,
                "independence": "INDEPENDENT" if sealed else "SELF_CHECK_ONLY",
                "result": "PASS",
            },
            "digest_algorithm": "SHA-256",
            "canonicalization": "s25m-canonical-json-v1",
            "seal_status": "SEALED_TEST_ONLY" if sealed else "UNSEALED",
            "manifest_digest": "",
        }

    @classmethod
    def _fresh_manifest(cls, *, sealed: bool = False) -> dict[str, object]:
        manifest = cls._raw_manifest(sealed=sealed)
        manifest["manifest_digest"] = manifest_digest(manifest)
        return manifest

    def test_unsealed_manifest_is_proposal_only(self) -> None:
        manifest = self._fresh_manifest()

        result = evaluate_reproducibility_manifest(manifest)

        self.assertEqual(result["status"], PROPOSAL_ONLY)
        self.assertEqual(result["decision"], DESIGN_ONLY)
        self.assertEqual(result["digest_status"], "MATCH")
        self.assertEqual(result["production_status"], PRODUCTION_NOT_AUTHORIZED)
        self.assertEqual(result["environment_probe"], NOT_CLAIMED)
        self.assertFalse(result["capability_issued"])

    def test_sealed_synthetic_manifest_is_test_only_pass(self) -> None:
        result = evaluate_reproducibility_manifest(self._fresh_manifest(sealed=True))

        self.assertEqual(result["status"], LOCKED_TEST_PASS)
        self.assertEqual(result["decision"], "TEST_ONLY_PASS")
        self.assertEqual(result["dependency_status"], "LOCKED")
        self.assertEqual(result["provider_status"], "IDENTIFIED")
        self.assertEqual(result["sbom_status"], "COMPLETE")
        self.assertEqual(result["oracle_status"], "INDEPENDENT_PASS")
        self.assertEqual(result["production_status"], PRODUCTION_NOT_AUTHORIZED)

    def test_missing_or_unknown_top_level_schema_is_blocked(self) -> None:
        missing = self._fresh_manifest()
        missing.pop("oracle")
        unknown = self._fresh_manifest()
        unknown["unexpected"] = True

        missing_result = evaluate_reproducibility_manifest(missing)
        unknown_result = evaluate_reproducibility_manifest(unknown)

        self.assertEqual(missing_result["status"], TEST_BLOCKED)
        self.assertEqual(unknown_result["status"], TEST_BLOCKED)

    def test_duplicate_raw_json_keys_are_rejected_before_mapping_loss(self) -> None:
        raw = b'{"schema_version":"s25m.reproducibility-manifest.v1","schema_version":"other"}'

        result = evaluate_reproducibility_manifest(raw)

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["reason"], "MANIFEST_JSON_INVALID")

    def test_digest_is_deterministic_and_mutation_is_blocked(self) -> None:
        manifest = self._fresh_manifest()
        same = deepcopy(manifest)
        self.assertEqual(manifest_digest(manifest), manifest_digest(same))
        manifest["runtime"]["python_version"] = "3.11.0"

        result = evaluate_reproducibility_manifest(manifest)

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["reason"], "MANIFEST_DIGEST_MISMATCH")

    def test_invalid_lock_and_artifact_hashes_are_blocked(self) -> None:
        lock = self._fresh_manifest()
        lock["lock"]["lockfile_sha256"] = "not-a-hash"
        lock["manifest_digest"] = manifest_digest(lock)
        artifact = self._fresh_manifest()
        artifact["artifacts"][0]["sha256"] = "bad"
        artifact["manifest_digest"] = manifest_digest(artifact)

        lock_result = evaluate_reproducibility_manifest(lock)
        artifact_result = evaluate_reproducibility_manifest(artifact)

        self.assertEqual(lock_result["status"], TEST_BLOCKED)
        self.assertEqual(artifact_result["status"], TEST_BLOCKED)

    def test_direct_transitive_and_native_closure_is_required(self) -> None:
        manifest = self._fresh_manifest()
        manifest["artifacts"] = [manifest["artifacts"][0], manifest["artifacts"][1]]
        manifest["manifest_digest"] = manifest_digest(manifest)

        result = evaluate_reproducibility_manifest(manifest)

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["reason"], "ARTIFACT_CLOSURE_INCOMPLETE")

    def test_provider_profile_and_fips_are_not_assumed(self) -> None:
        provider = self._fresh_manifest(sealed=True)
        provider["provider"]["algorithm"] = "HMAC"
        provider["manifest_digest"] = manifest_digest(provider)
        fips = self._fresh_manifest(sealed=True)
        fips["fips"]["required"] = True
        fips["fips"]["status"] = "UNKNOWN"
        fips["manifest_digest"] = manifest_digest(fips)

        provider_result = evaluate_reproducibility_manifest(provider)
        fips_result = evaluate_reproducibility_manifest(fips)

        self.assertEqual(provider_result["status"], TEST_BLOCKED)
        self.assertEqual(provider_result["reason"], "PROVIDER_PROFILE_MISMATCH")
        self.assertEqual(fips_result["status"], TEST_BLOCKED)
        self.assertEqual(fips_result["reason"], "FIPS_REQUIRED_NOT_VERIFIED")

    def test_sbom_closure_and_oracle_independence_are_required(self) -> None:
        sbom = self._fresh_manifest(sealed=True)
        sbom["sbom"]["includes_native"] = False
        sbom["manifest_digest"] = manifest_digest(sbom)
        oracle = self._fresh_manifest(sealed=True)
        oracle["oracle"]["independence"] = "SELF_CHECK_ONLY"
        oracle["manifest_digest"] = manifest_digest(oracle)

        sbom_result = evaluate_reproducibility_manifest(sbom)
        oracle_result = evaluate_reproducibility_manifest(oracle)

        self.assertEqual(sbom_result["status"], TEST_BLOCKED)
        self.assertEqual(sbom_result["reason"], "SBOM_CLOSURE_INCOMPLETE")
        self.assertEqual(oracle_result["status"], TEST_BLOCKED)
        self.assertEqual(oracle_result["reason"], "INDEPENDENT_ORACLE_NOT_PASSED")

    def test_host_path_time_and_float_leaks_are_blocked(self) -> None:
        path = self._fresh_manifest()
        path["runtime"]["platform_tag"] = "/tmp/fixture/runtime"
        float_value = self._fresh_manifest()
        float_value["runtime"]["python_version"] = 3.10

        path_result = evaluate_reproducibility_manifest(path)
        float_result = evaluate_reproducibility_manifest(float_value)

        self.assertEqual(path_result["status"], TEST_BLOCKED)
        self.assertEqual(float_result["status"], TEST_BLOCKED)

    def test_input_is_not_mutated_and_flags_are_always_negative(self) -> None:
        manifest = self._fresh_manifest(sealed=True)
        before = deepcopy(manifest)

        result = evaluate_reproducibility_manifest(manifest)

        self.assertEqual(manifest, before)
        self.assertEqual(result["authority_claim"], NOT_CLAIMED)
        for field in (
            "capability_issued",
            "write_authorized",
            "persistence_performed",
            "cas_attempted",
            "fence_issued",
            "mutation_allowed",
            "resume_allowed",
        ):
            self.assertFalse(result[field])

    def test_support_surface_is_stdlib_only_and_nonmutating(self) -> None:
        source = (REPO_ROOT / "tests" / "support" / "w5_s25m_reproducibility_manifest.py").read_text()
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
            "pathlib",
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
            "install(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("manifest_digest", source)
        self.assertIn("PRODUCTION_NOT_AUTHORIZED", source)

if __name__ == "__main__":
    unittest.main()
