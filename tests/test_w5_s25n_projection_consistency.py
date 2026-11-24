"""W5-S25N tests for pure evidence-projection consistency."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from support.w5_s25n_projection_consistency import (  # noqa: E402
    CANONICALIZATION,
    HARNESS_SCHEMA,
    LOCKED_TEST_PASS,
    NOT_CLAIMED,
    PRODUCTION_NOT_AUTHORIZED,
    PROPOSAL_ONLY,
    RECOVERY_REQUIRED,
    TEST_BLOCKED,
    evaluate_projection_consistency,
    projection_digest,
    projection_set_digest,
)


class W5S25NProjectionConsistencyTests(unittest.TestCase):
    @staticmethod
    def _hash(char: str) -> str:
        return char * 64

    @classmethod
    def _expected_subject(cls) -> dict[str, str]:
        return {
            "s25m_manifest_digest": cls._hash("a"),
            "source_tree_sha256": cls._hash("b"),
        }

    @classmethod
    def _raw(cls, *, sealed: bool = True) -> dict[str, object]:
        h = cls._hash
        app = "pkg:pypi/cryptography@50.0.2"
        cffi = "pkg:pypi/cffi@1.17.1"
        native = "native:libcrypto@3.0.2"
        platform = "manylinux_2_36_x86_64"
        artifacts = [
            {
                "component_id": app,
                "purl": app,
                "name": "cryptography",
                "normalized_name": "cryptography",
                "version": "50.0.2",
                "role": "DIRECT",
                "artifact_type": "WHEEL",
                "filename": "cryptography-50.0.2-cp310.whl",
                "sha256": h("1"),
                "platform_tag": platform,
                "abi_tag": "cp310",
                "parent_component_ids": [],
            },
            {
                "component_id": cffi,
                "purl": cffi,
                "name": "cffi",
                "normalized_name": "cffi",
                "version": "1.17.1",
                "role": "TRANSITIVE",
                "artifact_type": "WHEEL",
                "filename": "cffi-1.17.1-cp310.whl",
                "sha256": h("2"),
                "platform_tag": platform,
                "abi_tag": "cp310",
                "parent_component_ids": [app],
            },
            {
                "component_id": native,
                "purl": native,
                "name": "libcrypto",
                "normalized_name": "libcrypto",
                "version": "3.0.2",
                "role": "TRANSITIVE",
                "artifact_type": "NATIVE",
                "filename": "libcrypto-3.0.2.so",
                "sha256": h("3"),
                "platform_tag": platform,
                "abi_tag": "system",
                "parent_component_ids": [app],
            },
        ]
        graph = {
            "graph_sha256": h("4"),
            "resolver_name": "test-resolver",
            "resolver_version": "1.0.0",
            "runtime_python_abi": "cp310",
            "platform_tag": platform,
            "nodes": [
                {"component_id": app, "purl": app, "version": "50.0.2", "role": "DIRECT", "artifact_sha256": h("1")},
                {"component_id": cffi, "purl": cffi, "version": "1.17.1", "role": "TRANSITIVE", "artifact_sha256": h("2")},
                {"component_id": native, "purl": native, "version": "3.0.2", "role": "TRANSITIVE", "artifact_sha256": h("3")},
            ],
            "edges": [
                {"parent_component_id": app, "child_component_id": cffi, "child_digest": h("2")},
                {"parent_component_id": app, "child_component_id": native, "child_digest": h("3")},
            ],
        }
        component_ids = [app, cffi, native]
        result: dict[str, object] = {
            "schema_version": HARNESS_SCHEMA,
            "profile": "TEST",
            "observation_mode": "OBSERVE_ONLY",
            "seal_status": "SEALED_TEST_ONLY" if sealed else "UNSEALED",
            "subject": {
                "s25m_manifest_digest": h("a"),
                "source_tree_sha256": h("b"),
            },
            "anchors": {
                "lockfile_sha256": h("6"),
                "dependency_graph_sha256": h("4"),
                "artifact_set_sha256": h("5"),
                "provider_config_sha256": h("6"),
                "fips_module_sha256": h("7"),
                "sbom_document_sha256": h("8"),
                "sbom_closure_sha256": h("9"),
                "oracle_artifact_sha256": h("5"),
                "oracle_vector_set_sha256": h("c"),
            },
            "runtime": {
                "python_abi": "cp310",
                "platform_tag": platform,
                "architecture": "x86_64",
                "os_id": "linux",
            },
            "lockfile": {
                "status": "LOCKED" if sealed else "PROPOSED",
                "hash_mode": "REQUIRED",
                "lockfile_sha256": h("6"),
                "resolver_name": "test-resolver",
                "resolver_version": "1.0.0",
                "dependency_graph_sha256": h("4"),
                "artifact_set_sha256": h("5"),
                "component_ids": component_ids,
            },
            "dependency_graph": graph,
            "artifacts": {
                "artifact_set_sha256": h("5"),
                "items": artifacts,
            },
            "provider": {
                "package_component_id": app,
                "package_artifact_sha256": h("1"),
                "provider_id": "openssl",
                "provider_version": "3.0.2",
                "native_component_id": native,
                "native_artifact_sha256": h("3"),
                "provider_config_sha256": h("6"),
                "algorithm": "Ed25519",
                "canonicalization_profile": "RFC8785-JCS-v1",
            },
            "fips": {
                "required": False,
                "status": "NOT_REQUIRED",
                "provider_id": "openssl",
                "module_component_id": "not-required",
                "module_sha256": h("7"),
                "config_sha256": h("6"),
                "self_test_result": "NOT_REQUIRED",
                "validation_reference": "not-required",
            },
            "sbom": {
                "document_sha256": h("8"),
                "closure_sha256": h("9"),
                "dependency_graph_sha256": h("4"),
                "artifact_set_sha256": h("5"),
                "component_count": 3,
                "component_ids": component_ids,
                "native_component_ids": [native],
                "includes_transitive": True,
                "includes_native": True,
                "unresolved_count": 0,
            },
            "oracle": {
                "oracle_id": "independent-test-oracle",
                "result": "PASS",
                "independence": "INDEPENDENT",
                "input_digest": h("5"),
                "output_digest": h("6"),
                "artifact_set_sha256": h("5"),
                "provider_id": "oracle-provider",
                "provider_version": "1.0.0",
                "native_artifact_sha256": h("d"),
                "subject_manifest_digest": h("a"),
                "target_provider_id": "openssl",
                "target_provider_version": "3.0.2",
                "target_native_artifact_sha256": h("3"),
                "vector_set_sha256": h("c"),
            },
            "projection_digests": {},
            "canonicalization": CANONICALIZATION,
            "projection_set_digest": "",
        }
        result["projection_digests"] = {
            name: projection_digest(result[name])
            for name in (
                "runtime",
                "lockfile",
                "dependency_graph",
                "artifacts",
                "provider",
                "fips",
                "sbom",
                "oracle",
            )
        }
        result["projection_set_digest"] = projection_set_digest(result)
        return result

    @classmethod
    def _fresh(cls, *, sealed: bool = True) -> dict[str, object]:
        return cls._raw(sealed=sealed)

    @classmethod
    def _evaluate(cls, value: object) -> dict[str, object]:
        return evaluate_projection_consistency(value, expected_subject=cls._expected_subject())

    @classmethod
    def _refresh(cls, manifest: dict[str, object], *names: str) -> None:
        selected = names or (
            "runtime",
            "lockfile",
            "dependency_graph",
            "artifacts",
            "provider",
            "fips",
            "sbom",
            "oracle",
        )
        for name in selected:
            manifest["projection_digests"][name] = projection_digest(manifest[name])
        manifest["projection_set_digest"] = projection_set_digest(manifest)

    def test_sealed_consistent_synthetic_set_is_test_only(self) -> None:
        result = self._evaluate(self._fresh())

        self.assertEqual(result["status"], LOCKED_TEST_PASS)
        self.assertEqual(result["decision"], "TEST_ONLY_PASS")
        self.assertEqual(result["projection_status"], "CONSISTENT")
        self.assertEqual(result["production_status"], PRODUCTION_NOT_AUTHORIZED)
        self.assertEqual(result["authority_claim"], NOT_CLAIMED)
        self.assertFalse(result["capability_issued"])

    def test_sealed_set_without_external_subject_anchor_is_blocked(self) -> None:
        result = evaluate_projection_consistency(self._fresh())

        self.assertEqual(result["status"], TEST_BLOCKED)
        self.assertEqual(result["decision"], "HOLD")
        self.assertEqual(result["reason"], "SUBJECT_EXPECTATION_MISSING")

    def test_unsealed_consistent_set_is_proposal_only(self) -> None:
        result = self._evaluate(self._fresh(sealed=False))

        self.assertEqual(result["status"], PROPOSAL_ONLY)
        self.assertEqual(result["decision"], "DESIGN_ONLY")
        self.assertEqual(result["projection_status"], "CONSISTENT")
        self.assertEqual(result["dependency_status"], "CONSISTENT_PROPOSED")

    def test_schema_and_duplicate_json_are_blocked(self) -> None:
        missing = self._fresh()
        missing.pop("oracle")
        unknown = self._fresh()
        unknown["unexpected"] = True
        raw = b'{"schema_version":"s25n.projection-consistency.v1","schema_version":"other"}'

        self.assertEqual(self._evaluate(missing)["status"], TEST_BLOCKED)
        self.assertEqual(self._evaluate(unknown)["status"], TEST_BLOCKED)
        duplicate = self._evaluate(raw)
        self.assertEqual(duplicate["status"], TEST_BLOCKED)
        self.assertEqual(duplicate["reason"], "PROJECTION_JSON_INVALID")

    def test_subject_and_anchor_drift_is_recovery_required(self) -> None:
        subject = self._fresh()
        subject["subject"]["s25m_manifest_digest"] = self._hash("d")
        subject["oracle"]["subject_manifest_digest"] = self._hash("d")
        self._refresh(subject, "oracle")
        anchor = self._fresh()
        anchor["anchors"]["artifact_set_sha256"] = self._hash("d")
        anchor["projection_set_digest"] = projection_set_digest(anchor)

        subject_result = self._evaluate(subject)
        anchor_result = self._evaluate(anchor)

        self.assertEqual(subject_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(subject_result["reason"], "SUBJECT_BINDING_DRIFT")
        self.assertEqual(anchor_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(anchor_result["reason"], "ARTIFACT_ANCHOR_DRIFT")

    def test_stale_root_digest_is_recovery_required(self) -> None:
        manifest = self._fresh()
        manifest["profile"] = "PREPROD"

        result = self._evaluate(manifest)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "PROJECTION_SET_DIGEST_DRIFT")

    def test_stale_projection_payload_digest_is_recovery_required(self) -> None:
        manifest = self._fresh()
        manifest["provider"]["provider_version"] = "9.9.9"
        manifest["projection_set_digest"] = projection_set_digest(manifest)

        result = self._evaluate(manifest)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "PROJECTION_PAYLOAD_DIGEST_DRIFT")

    def test_lock_component_set_drift_is_recovery_required(self) -> None:
        manifest = self._fresh()
        manifest["lockfile"]["component_ids"] = manifest["lockfile"]["component_ids"][:-1]
        self._refresh(manifest, "lockfile")

        result = self._evaluate(manifest)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "LOCKFILE_COMPONENT_SET_DRIFT")

    def test_graph_parent_and_child_digest_drift_is_recovery_required(self) -> None:
        manifest = self._fresh()
        manifest["dependency_graph"]["edges"][0]["child_digest"] = self._hash("d")
        self._refresh(manifest, "dependency_graph")

        result = self._evaluate(manifest)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "GRAPH_CHILD_DIGEST_DRIFT")

    def test_extra_component_is_not_accepted_as_partial_closure(self) -> None:
        manifest = self._fresh()
        extra = deepcopy(manifest["artifacts"]["items"][1])
        extra["component_id"] = "pkg:pypi/extra@1.0.0"
        extra["purl"] = extra["component_id"]
        extra["name"] = "extra"
        extra["normalized_name"] = "extra"
        extra["version"] = "1.0.0"
        extra["filename"] = "extra-1.0.0-cp310.whl"
        manifest["artifacts"]["items"].append(extra)
        self._refresh(manifest, "artifacts")

        result = self._evaluate(manifest)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "LOCKFILE_COMPONENT_SET_DRIFT")

    def test_resolver_and_runtime_projection_drift_is_recovery_required(self) -> None:
        resolver = self._fresh()
        resolver["dependency_graph"]["resolver_version"] = "2.0.0"
        self._refresh(resolver, "dependency_graph")
        runtime = self._fresh()
        runtime["artifacts"]["items"][0]["abi_tag"] = "cp311"
        self._refresh(runtime, "artifacts")

        resolver_result = self._evaluate(resolver)
        runtime_result = self._evaluate(runtime)

        self.assertEqual(resolver_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(resolver_result["reason"], "RESOLVER_PROJECTION_DRIFT")
        self.assertEqual(runtime_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(runtime_result["reason"], "ARTIFACT_RUNTIME_TAG_DRIFT")

    def test_provider_and_fips_binding_drift_are_fail_closed(self) -> None:
        provider = self._fresh()
        provider["provider"]["native_artifact_sha256"] = self._hash("d")
        self._refresh(provider, "provider")
        fips = self._fresh()
        fips["fips"]["required"] = True
        fips["fips"]["status"] = "UNKNOWN"
        fips["fips"]["self_test_result"] = "UNKNOWN"
        fips["fips"]["module_component_id"] = "native:libcrypto@3.0.2"
        fips["fips"]["module_sha256"] = self._hash("3")
        fips["anchors"]["fips_module_sha256"] = self._hash("3")
        self._refresh(fips, "fips")

        provider_result = self._evaluate(provider)
        fips_result = self._evaluate(fips)

        self.assertEqual(provider_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(provider_result["reason"], "PROVIDER_ARTIFACT_BINDING_DRIFT")
        self.assertEqual(fips_result["status"], TEST_BLOCKED)
        self.assertEqual(fips_result["decision"], "HOLD")
        self.assertEqual(fips_result["reason"], "FIPS_EVIDENCE_UNKNOWN")

    def test_fips_wheel_cannot_be_promoted_to_native_module(self) -> None:
        manifest = self._fresh()
        manifest["fips"]["required"] = True
        manifest["fips"]["status"] = "VERIFIED"
        manifest["fips"]["self_test_result"] = "PASS"
        manifest["fips"]["module_component_id"] = "pkg:pypi/cryptography@50.0.2"
        manifest["fips"]["module_sha256"] = self._hash("1")
        manifest["anchors"]["fips_module_sha256"] = self._hash("1")
        self._refresh(manifest, "fips")

        result = self._evaluate(manifest)

        self.assertEqual(result["status"], RECOVERY_REQUIRED)
        self.assertEqual(result["reason"], "FIPS_MODULE_BINDING_DRIFT")

    def test_sbom_closure_and_component_identity_are_checked(self) -> None:
        incomplete = self._fresh()
        incomplete["sbom"]["includes_native"] = False
        self._refresh(incomplete, "sbom")
        drift = self._fresh()
        drift["sbom"]["component_ids"] = drift["sbom"]["component_ids"][:-1]
        drift["sbom"]["component_count"] = 2
        self._refresh(drift, "sbom")

        incomplete_result = self._evaluate(incomplete)
        drift_result = self._evaluate(drift)

        self.assertEqual(incomplete_result["status"], TEST_BLOCKED)
        self.assertEqual(incomplete_result["reason"], "SBOM_CLOSURE_INCOMPLETE")
        self.assertEqual(drift_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(drift_result["reason"], "SBOM_COMPONENT_SET_DRIFT")

    def test_oracle_replay_and_unknown_result_are_not_passes(self) -> None:
        replay = self._fresh()
        replay["oracle"]["artifact_set_sha256"] = self._hash("d")
        replay["anchors"]["oracle_artifact_sha256"] = self._hash("d")
        self._refresh(replay, "oracle")
        unknown = self._fresh()
        unknown["oracle"]["result"] = "UNKNOWN"
        self._refresh(unknown, "oracle")
        target = self._fresh()
        target["artifacts"]["items"][2]["sha256"] = self._hash("d")
        target["dependency_graph"]["nodes"][2]["artifact_sha256"] = self._hash("d")
        target["dependency_graph"]["edges"][1]["child_digest"] = self._hash("d")
        target["provider"]["native_artifact_sha256"] = self._hash("d")
        self._refresh(target, "artifacts", "dependency_graph", "provider")

        replay_result = self._evaluate(replay)
        unknown_result = self._evaluate(unknown)
        target_result = self._evaluate(target)

        self.assertEqual(replay_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(replay_result["reason"], "ORACLE_SCOPE_DRIFT")
        self.assertEqual(unknown_result["status"], TEST_BLOCKED)
        self.assertEqual(unknown_result["decision"], "HOLD")
        self.assertEqual(target_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(target_result["reason"], "ORACLE_TARGET_IDENTITY_DRIFT")

    def test_duplicate_component_and_unknown_resolver_are_fail_closed(self) -> None:
        duplicate = self._fresh()
        duplicate["artifacts"]["items"].append(deepcopy(duplicate["artifacts"]["items"][0]))
        self._refresh(duplicate, "artifacts")
        unknown = self._fresh()
        unknown["lockfile"]["resolver_name"] = "UNKNOWN"
        self._refresh(unknown, "lockfile")

        duplicate_result = self._evaluate(duplicate)
        unknown_result = self._evaluate(unknown)

        self.assertEqual(duplicate_result["status"], RECOVERY_REQUIRED)
        self.assertEqual(duplicate_result["reason"], "DUPLICATE_COMPONENT_ID")
        self.assertEqual(unknown_result["status"], TEST_BLOCKED)
        self.assertEqual(unknown_result["decision"], "HOLD")

    def test_canonicalization_and_unsafe_values_are_blocked(self) -> None:
        canonical = self._fresh()
        canonical["canonicalization"] = "RFC8785-JCS-v1"
        canonical["projection_set_digest"] = projection_set_digest(canonical)
        path = self._fresh()
        path["artifacts"]["items"][0]["filename"] = "file:///tmp/fixture/a.whl"
        uri = self._fresh()
        uri["artifacts"]["items"][0]["filename"] = "  file:/tmp/fixture/a.whl"
        unc = self._fresh()
        unc["artifacts"]["items"][0]["filename"] = "\\\\server\\share\\a.whl"
        floating = self._fresh()
        floating["runtime"]["python_abi"] = 3.10
        surrogate = self._fresh()
        surrogate["runtime"]["architecture"] = "\ud800"

        self.assertEqual(self._evaluate(canonical)["status"], TEST_BLOCKED)
        self.assertEqual(self._evaluate(path)["status"], TEST_BLOCKED)
        self.assertEqual(self._evaluate(uri)["status"], TEST_BLOCKED)
        self.assertEqual(self._evaluate(unc)["status"], TEST_BLOCKED)
        self.assertEqual(self._evaluate(floating)["status"], TEST_BLOCKED)
        self.assertEqual(self._evaluate(surrogate)["status"], TEST_BLOCKED)

    def test_unhashable_boundary_values_are_blocked_not_raised(self) -> None:
        cases = []
        artifact = self._fresh()
        artifact["artifacts"]["items"][0]["component_id"] = []
        self._refresh(artifact, "artifacts")
        cases.append(artifact)
        node = self._fresh()
        node["dependency_graph"]["nodes"][0]["component_id"] = []
        self._refresh(node, "dependency_graph")
        cases.append(node)
        edge = self._fresh()
        edge["dependency_graph"]["edges"][0]["parent_component_id"] = []
        self._refresh(edge, "dependency_graph")
        cases.append(edge)
        lock = self._fresh()
        lock["lockfile"]["status"] = []
        self._refresh(lock, "lockfile")
        cases.append(lock)
        profile = self._fresh()
        profile["profile"] = []
        cases.append(profile)
        fips = self._fresh()
        fips["fips"]["status"] = []
        self._refresh(fips, "fips")
        cases.append(fips)

        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(self._evaluate(case)["status"], TEST_BLOCKED)

    def test_json_order_and_whitespace_do_not_change_the_result(self) -> None:
        manifest = self._fresh()
        compact = json.dumps(manifest, separators=(",", ":"))
        pretty = json.dumps(manifest, indent=2)

        compact_result = self._evaluate(compact)
        pretty_result = self._evaluate(pretty)

        self.assertEqual(compact_result["status"], LOCKED_TEST_PASS)
        self.assertEqual(pretty_result["status"], LOCKED_TEST_PASS)
        self.assertEqual(compact_result["digest_status"], "MATCH")
        self.assertEqual(pretty_result["digest_status"], "MATCH")

    def test_coherent_new_synthetic_closure_is_not_hardcoded_to_fixture(self) -> None:
        manifest = self._fresh()
        new_package_hash = self._hash("d")
        new_graph_hash = self._hash("e")
        new_artifact_set_hash = self._hash("f")
        manifest["artifacts"]["items"][0]["sha256"] = new_package_hash
        manifest["dependency_graph"]["nodes"][0]["artifact_sha256"] = new_package_hash
        manifest["provider"]["package_artifact_sha256"] = new_package_hash
        manifest["dependency_graph"]["graph_sha256"] = new_graph_hash
        manifest["lockfile"]["dependency_graph_sha256"] = new_graph_hash
        manifest["anchors"]["dependency_graph_sha256"] = new_graph_hash
        manifest["sbom"]["dependency_graph_sha256"] = new_graph_hash
        manifest["artifacts"]["artifact_set_sha256"] = new_artifact_set_hash
        manifest["lockfile"]["artifact_set_sha256"] = new_artifact_set_hash
        manifest["anchors"]["artifact_set_sha256"] = new_artifact_set_hash
        manifest["sbom"]["artifact_set_sha256"] = new_artifact_set_hash
        manifest["oracle"]["artifact_set_sha256"] = new_artifact_set_hash
        manifest["oracle"]["input_digest"] = new_artifact_set_hash
        manifest["anchors"]["oracle_artifact_sha256"] = new_artifact_set_hash
        self._refresh(manifest, "dependency_graph", "lockfile", "sbom", "artifacts", "provider", "oracle")

        result = self._evaluate(manifest)

        self.assertEqual(result["status"], LOCKED_TEST_PASS)

    def test_input_is_unchanged_and_negative_flags_remain_fixed(self) -> None:
        manifest = self._fresh()
        before = deepcopy(manifest)

        result = self._evaluate(manifest)

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
        source = (REPO_ROOT / "tests" / "support" / "w5_s25n_projection_consistency.py").read_text()
        for forbidden in (
            "import cryptography",
            "from cryptography",
            "import nacl",
            "from nacl",
            "import OpenSSL",
            "import os",
            "import pathlib",
            "import socket",
            "import subprocess",
            "import time",
            "sqlite3",
            "open(",
            "write_bytes",
            "write_text",
            "replace(",
            "rename(",
            "unlink(",
            "mkdir(",
            "commit(",
            "install(",
            "verify_signature(",
            "sign(",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("projection_set_digest", source)
        self.assertIn("PRODUCTION_NOT_AUTHORIZED", source)


if __name__ == "__main__":
    unittest.main()
