from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.understanding_s0 import UnderstandingRegistry
from modules.understanding_s0.model import sha256_json
from modules.understanding_s2 import EventStreamBuilder, ScopeArtifact
from modules.understanding_s3 import verify_contextual_stream_bundle


class W3S3ContextBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="w3-s3-")
        self.base = Path(self.tempdir.name)
        self.project = self.base / "project"
        self.output = self.base / "output"
        self.project.mkdir()
        self.output.mkdir()
        (self.project / "README.md").write_text("context bundle fixture\n", encoding="utf-8")
        (self.project / "src").mkdir()
        (self.project / "src" / "main.py").write_text("print('s3')\n", encoding="utf-8")
        self.registry = UnderstandingRegistry(
            self.output,
            clock=lambda: "2026-11-15T12:00:00+00:00",
            scan_id_factory=lambda: "scan-000001",
        )
        self.registry.register_project("demo", self.project, (self.base,))
        self.registry.register_source("demo", "workspace")
        self.scan = self.registry.scan("demo", "workspace")
        self.profile = self.registry.project("demo")
        self.source = self.registry.source("demo", "workspace")
        self.scope = ScopeArtifact.from_registry(self.profile, self.source)
        self.manifest_one = self.scan.manifest.to_dict()
        self.event_one = self.scan.event.to_dict()
        self.event_two = copy.deepcopy(self.event_one)
        self.event_two["scan_id"] = "scan-000002"
        self.event_two["sequence_no"] = 2
        self.event_two["previous_event_hash"] = self.event_one["event_hash"]
        self._rehash_event(self.event_two)
        builder = EventStreamBuilder("stream-000001", self.scope, self.profile, self.source)
        builder.append(self.event_one)
        builder.append(self.event_two)
        self.stream = builder.seal()
        self.manifests = [self.manifest_one]

    def tearDown(self) -> None:
        self.registry.close()
        self.tempdir.cleanup()

    @staticmethod
    def _rehash_manifest(manifest: dict) -> None:
        payload = {
            key: value for key, value in manifest.items() if key not in {"observed_at", "manifest_hash"}
        }
        manifest["manifest_hash"] = sha256_json(payload)

    @staticmethod
    def _rehash_event(event: dict) -> None:
        event["event_hash"] = sha256_json({key: value for key, value in event.items() if key != "event_hash"})

    @staticmethod
    def _rehash_stream(stream: dict) -> None:
        stream["event_count"] = len(stream["events"])
        stream["head_event_hash"] = stream["events"][-1]["event_hash"]
        stream["stream_hash"] = sha256_json(
            {key: value for key, value in stream.items() if key != "stream_hash"}
        )

    def test_valid_two_event_context_bundle_is_accepted(self) -> None:
        result = verify_contextual_stream_bundle(
            self.stream,
            self.scope,
            self.profile,
            self.source,
            self.manifests,
            authority=self.registry,
        )
        self.assertTrue(result.accepted, result.to_dict())
        self.assertEqual(result.checked_hash, self.stream.stream_hash)

        without_authority = verify_contextual_stream_bundle(
            self.stream, self.scope, self.profile, self.source, self.manifests
        )
        self.assertFalse(without_authority.accepted)
        self.assertIn("AUTHORITY_REQUIRED", {item.code for item in without_authority.findings})

    def test_manifest_catalog_requires_exact_references(self) -> None:
        missing = verify_contextual_stream_bundle(
            self.stream, self.scope, self.profile, self.source, []
        )
        self.assertFalse(missing.accepted)
        self.assertIn("MANIFEST_MISSING", {item.code for item in missing.findings})

        extra = copy.deepcopy(self.manifest_one)
        extra["source_device"] += 1
        self._rehash_manifest(extra)
        unreferenced = verify_contextual_stream_bundle(
            self.stream, self.scope, self.profile, self.source, [*self.manifests, extra]
        )
        self.assertFalse(unreferenced.accepted)
        self.assertIn("MANIFEST_UNREFERENCED", {item.code for item in unreferenced.findings})

        duplicate = verify_contextual_stream_bundle(
            self.stream, self.scope, self.profile, self.source, [self.manifest_one, self.manifest_one]
        )
        self.assertFalse(duplicate.accepted)
        self.assertIn("MANIFEST_DUPLICATE", {item.code for item in duplicate.findings})

    def test_rehashed_semantic_manifest_tampering_is_rejected(self) -> None:
        tampered_manifest = copy.deepcopy(self.manifest_one)
        tampered_manifest["coverage"]["files_indexed"] += 1
        self._rehash_manifest(tampered_manifest)
        tampered_stream = self.stream.to_dict()
        tampered_stream["events"][0]["manifest_hash"] = tampered_manifest["manifest_hash"]
        self._rehash_event(tampered_stream["events"][0])
        self._rehash_stream(tampered_stream)

        result = verify_contextual_stream_bundle(
            tampered_stream,
            self.scope,
            self.profile,
            self.source,
            [tampered_manifest],
        )
        self.assertFalse(result.accepted)
        self.assertIn("COVERAGE_INVALID", {item.code for item in result.findings})

    def test_event_manifest_timestamp_and_device_bindings_are_semantic(self) -> None:
        timestamp_stream = self.stream.to_dict()
        timestamp_stream["events"][1]["finished_at"] = "2026-11-15T14:00:01+00:00"
        self._rehash_event(timestamp_stream["events"][1])
        self._rehash_stream(timestamp_stream)
        timestamp_result = verify_contextual_stream_bundle(
            timestamp_stream, self.scope, self.profile, self.source, self.manifests
        )
        self.assertFalse(timestamp_result.accepted)
        self.assertIn("TIMESTAMP_MISMATCH", {item.code for item in timestamp_result.findings})

        bad_device_manifest = copy.deepcopy(self.manifest_one)
        bad_device_manifest["observed_at"] = "2026-11-15T14:00:01+00:00"
        bad_device_manifest["source_device"] += 1
        self._rehash_manifest(bad_device_manifest)
        device_stream = self.stream.to_dict()
        device_stream["events"][1]["manifest_hash"] = bad_device_manifest["manifest_hash"]
        device_stream["events"][1]["finished_at"] = bad_device_manifest["observed_at"]
        device_stream["events"][1]["started_at"] = "2026-11-15T14:00:00+00:00"
        self._rehash_event(device_stream["events"][1])
        self._rehash_stream(device_stream)
        device_result = verify_contextual_stream_bundle(
            device_stream,
            self.scope,
            self.profile,
            self.source,
            [self.manifest_one, bad_device_manifest],
        )
        self.assertFalse(device_result.accepted)
        self.assertIn("DEVICE_MISMATCH", {item.code for item in device_result.findings})

    def test_original_s2_order_is_not_silently_rewritten(self) -> None:
        tampered = self.stream.to_dict()
        tampered["events"][1]["sequence_no"] = 1
        tampered["events"][1]["previous_event_hash"] = None
        self._rehash_event(tampered["events"][1])
        self._rehash_stream(tampered)
        result = verify_contextual_stream_bundle(
            tampered, self.scope, self.profile, self.source, self.manifests
        )
        self.assertFalse(result.accepted)
        self.assertIn("EVENT_SEQUENCE_GAP", {item.code for item in result.findings})

    def test_scope_registry_and_authority_bindings_fail_closed(self) -> None:
        wrong_scope = ScopeArtifact.from_registry(self.profile, self.source, max_files=1)
        scope_result = verify_contextual_stream_bundle(
            self.stream, wrong_scope, self.profile, self.source, self.manifests
        )
        self.assertFalse(scope_result.accepted)
        self.assertIn("SCOPE_MISMATCH", {item.code for item in scope_result.findings})

        forged_profile = self.profile.to_dict()
        forged_profile["path_policy_hash"] = "f" * 64
        authority_result = verify_contextual_stream_bundle(
            self.stream,
            self.scope,
            forged_profile,
            self.source,
            self.manifests,
            authority=self.registry,
        )
        self.assertFalse(authority_result.accepted)
        self.assertIn("PROVENANCE_AUTHORITY_MISMATCH", {item.code for item in authority_result.findings})

        multi_source_profile = self.profile.to_dict()
        multi_source_profile["source_ids"] = [self.source.source_id, "other-source"]
        multi_source_result = verify_contextual_stream_bundle(
            self.stream,
            self.scope,
            multi_source_profile,
            self.source,
            self.manifests,
            authority=self.registry,
        )
        self.assertFalse(multi_source_result.accepted)
        self.assertIn("CONTEXT_MULTI_SOURCE_UNSUPPORTED", {item.code for item in multi_source_result.findings})

    def test_manifest_schema_version_is_part_of_the_context_contract(self) -> None:
        future_manifest = copy.deepcopy(self.manifest_one)
        future_manifest["schema_version"] = "source-manifest.v9"
        self._rehash_manifest(future_manifest)
        future_stream = self.stream.to_dict()
        future_stream["events"][0]["manifest_hash"] = future_manifest["manifest_hash"]
        self._rehash_event(future_stream["events"][0])
        self._rehash_stream(future_stream)
        result = verify_contextual_stream_bundle(
            future_stream,
            self.scope,
            self.profile,
            self.source,
            [future_manifest],
            authority=self.registry,
        )
        self.assertFalse(result.accepted)
        self.assertIn("MANIFEST_SCHEMA_UNSUPPORTED", {item.code for item in result.findings})

    def test_verifier_is_read_only_and_does_not_mutate_inputs(self) -> None:
        before = []
        for path in sorted(self.base.rglob("*")):
            if path.is_file() and not path.is_symlink():
                before.append((path.relative_to(self.base).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
        profile = self.profile.to_dict()
        source = self.source.to_dict()
        manifests = copy.deepcopy(self.manifests)
        result = verify_contextual_stream_bundle(
            self.stream, self.scope, profile, source, manifests, authority=self.registry
        )
        self.assertTrue(result.accepted, result.to_dict())
        self.assertEqual(manifests, self.manifests)
        after = []
        for path in sorted(self.base.rglob("*")):
            if path.is_file() and not path.is_symlink():
                after.append((path.relative_to(self.base).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
