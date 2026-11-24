from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.understanding_s0 import UnderstandingRegistry
from modules.understanding_s0.model import canonical_json_bytes, sha256_json
from modules.understanding_s2 import (
    EventStreamBuilder,
    EventStreamError,
    EventStreamStore,
    ScopeArtifactError,
    ScopeArtifactStore,
    ScopeArtifact,
    ScanScope,
    verify_event_stream_artifact,
    verify_scope_artifact,
)


class W3S2ScopeAndEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="w3-s2-")
        self.base = Path(self.tempdir.name)
        self.project = self.base / "project"
        self.output = self.base / "output"
        self.project.mkdir()
        self.output.mkdir()
        (self.project / "README.md").write_text("scope stream fixture\n", encoding="utf-8")
        (self.project / "src").mkdir()
        (self.project / "src" / "main.py").write_text("print('s2')\n", encoding="utf-8")
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
        self.scope_artifact = ScopeArtifact.from_registry(self.profile, self.source)
        self.event_one = self.scan.event.to_dict()
        self.event_two = self._next_event(self.event_one, "scan-000002", 2, "13:00:00")
        self.event_three = self._next_event(self.event_two, "scan-000003", 3, "14:00:00")

    def tearDown(self) -> None:
        self.registry.close()
        self.tempdir.cleanup()

    @staticmethod
    def _rehash_event(event: dict) -> None:
        body = {key: value for key, value in event.items() if key != "event_hash"}
        event["event_hash"] = sha256_json(body)

    @classmethod
    def _next_event(cls, previous: dict, scan_id: str, sequence: int, hour: str) -> dict:
        event = copy.deepcopy(previous)
        event["scan_id"] = scan_id
        event["sequence_no"] = sequence
        event["previous_event_hash"] = previous["event_hash"]
        event["started_at"] = f"2026-11-15T{hour}+00:00"
        event["finished_at"] = f"2026-11-15T{hour[:2]}:00:01+00:00"
        cls._rehash_event(event)
        return event

    @staticmethod
    def _rehash_stream(stream: dict) -> None:
        stream["event_count"] = len(stream["events"])
        stream["head_event_hash"] = stream["events"][-1]["event_hash"]
        payload = {key: value for key, value in stream.items() if key != "stream_hash"}
        stream["stream_hash"] = sha256_json(payload)

    def test_scope_artifact_is_self_describing_and_w3s1_compatible(self) -> None:
        artifact = self.scope_artifact.to_dict()

        self.assertEqual(artifact["scope_hash"], self.scope_artifact.scope_hash)
        self.assertEqual(artifact["artifact_hash"], self.scope_artifact.artifact_hash)
        self.assertTrue(verify_scope_artifact(self.scope_artifact, self.profile, self.source).accepted)
        self.assertTrue(verify_scope_artifact(artifact, self.profile.to_dict(), self.source.to_dict()).accepted)
        self.assertTrue(verify_scope_artifact(self.scope_artifact, authority=self.registry).accepted)
        self.assertFalse(verify_scope_artifact(self.scope_artifact).accepted)
        self.assertTrue(verify_scope_artifact(self.scope_artifact, integrity_only=True).accepted)

        tampered = copy.deepcopy(artifact)
        tampered["provenance"]["path_policy_hash"] = "f" * 64
        self.assertFalse(verify_scope_artifact(tampered).accepted)

        foreign_source = self.source.to_dict()
        foreign_source["project_id"] = "foreign"
        rejected_binding = verify_scope_artifact(self.scope_artifact, self.profile, foreign_source)
        self.assertFalse(rejected_binding.accepted)

        forged_profile = self.profile.to_dict()
        forged_profile["path_policy_hash"] = "f" * 64
        profile_body = {key: value for key, value in forged_profile.items() if key != "registry_snapshot_hash"}
        forged_profile["registry_snapshot_hash"] = sha256_json(
            {"profile": profile_body, "sources": [self.source.to_dict()]}
        )
        rejected_policy = verify_scope_artifact(self.scope_artifact, forged_profile, self.source)
        self.assertFalse(rejected_policy.accepted)
        self.assertIn("POLICY_HASH_MISMATCH", {item.code for item in rejected_policy.findings})
        rejected_authority = verify_scope_artifact(
            self.scope_artifact, forged_profile, self.source, authority=self.registry
        )
        self.assertFalse(rejected_authority.accepted)
        self.assertIn("PROVENANCE_AUTHORITY_MISMATCH", {item.code for item in rejected_authority.findings})

        scope = copy.deepcopy(artifact["scope"])
        scope["max_files"] = True
        with self.assertRaises(ScopeArtifactError):
            ScanScope.from_dict(scope)
        scope["max_files"] = None
        scope["root_relative"] = "src\\main"
        with self.assertRaises(ScopeArtifactError):
            ScanScope.from_dict(scope)

    def test_scope_store_is_write_once_bounded_and_no_follow(self) -> None:
        with ScopeArtifactStore(self.output) as store:
            relative = store.write_once(self.scope_artifact, self.profile, self.source)
            self.assertEqual(relative, f"scopes/{self.scope_artifact.scope_hash}.json")
            self.assertEqual(store.write_once(self.scope_artifact, self.profile, self.source), relative)
            loaded = store.read(self.scope_artifact.scope_hash, self.profile, self.source)
            self.assertEqual(loaded.to_dict(), self.scope_artifact.to_dict())

        path = self.output / relative
        original = path.read_bytes()
        path.write_bytes(b"different\n")
        with ScopeArtifactStore(self.output) as store:
            with self.assertRaises(ScopeArtifactError):
                store.write_once(self.scope_artifact, self.profile, self.source)
        self.assertEqual(path.read_bytes(), b"different\n")
        path.write_bytes(original)

        bad_output = self.base / "bad-scope-output"
        bad_output.mkdir()
        outside = self.base / "outside"
        outside.mkdir()
        os.symlink(outside, bad_output / "scopes")
        with ScopeArtifactStore(bad_output) as store:
            with self.assertRaises(ScopeArtifactError):
                store.write_once(self.scope_artifact, self.profile, self.source)
        self.assertFalse((outside / f"{self.scope_artifact.scope_hash}.json").exists())

    def test_scope_loader_rejects_duplicate_json_and_tampered_hashes(self) -> None:
        with ScopeArtifactStore(self.output) as store:
            relative = store.write_once(self.scope_artifact, self.profile, self.source)
            path = self.output / relative
            valid = path.read_text(encoding="utf-8").rstrip()
            duplicate = valid[:-1] + ',"artifact_hash":"' + self.scope_artifact.artifact_hash + '"}'
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaises(ScopeArtifactError):
                store.read(self.scope_artifact.scope_hash)
            path.write_bytes(canonical_json_bytes(self.scope_artifact.to_dict()) + b"\n")
            path.write_text(json.dumps(self.scope_artifact.to_dict(), indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(ScopeArtifactError):
                store.read(self.scope_artifact.scope_hash, self.profile, self.source)

    def test_three_event_stream_is_sealed_and_bound_to_external_scope(self) -> None:
        builder = EventStreamBuilder("stream-000001", self.scope_artifact, self.profile, self.source)
        builder.append(self.event_one)
        builder.append(self.event_two)
        builder.append(self.event_three)
        artifact = builder.seal()

        self.assertTrue(builder.sealed)
        self.assertEqual(artifact.event_count, 3)
        self.assertEqual(artifact.head_event_hash, self.event_three["event_hash"])
        checked = verify_event_stream_artifact(artifact, self.scope_artifact, self.profile, self.source)
        self.assertTrue(checked.accepted, checked.to_dict())
        self.assertFalse(verify_event_stream_artifact(artifact).accepted)
        self.assertIn("SCOPE_CONTEXT_MISSING", {item.code for item in verify_event_stream_artifact(artifact).findings})
        original_hash = artifact.stream_hash
        with self.assertRaises(TypeError):
            artifact.events[0]["status"] = "DENIED"  # type: ignore[index]
        self.assertEqual(artifact.stream_hash, original_hash)

        with self.assertRaises(EventStreamError):
            builder.append(self.event_one)
        with self.assertRaises(EventStreamError):
            builder.seal()

    def test_stream_store_is_write_once_and_reloads_canonically(self) -> None:
        builder = EventStreamBuilder("stream-000001", self.scope_artifact, self.profile, self.source)
        builder.append(self.event_one)
        builder.append(self.event_two)
        artifact = builder.seal()

        with EventStreamStore(self.output) as store:
            relative = store.write_once(artifact, self.scope_artifact, self.profile, self.source)
            self.assertEqual(relative, f"streams/stream-000001/{artifact.stream_hash}.json")
            self.assertEqual(store.write_once(artifact, self.scope_artifact, self.profile, self.source), relative)
            loaded = store.read("stream-000001", artifact.stream_hash, self.scope_artifact, self.profile, self.source)
            self.assertEqual(loaded.to_dict(), artifact.to_dict())
        wrong_hash = "0" * 64
        wrong_path = self.output / "streams" / "stream-000001" / f"{wrong_hash}.json"
        wrong_path.write_bytes((self.output / relative).read_bytes())
        with EventStreamStore(self.output) as store:
            with self.assertRaises(EventStreamError):
                store.read("stream-000001", wrong_hash, self.scope_artifact, self.profile, self.source)
        self.assertEqual(list((self.output / "streams" / "stream-000001").glob(".*.tmp-*")), [])

        bad_output = self.base / "bad-stream-output"
        bad_output.mkdir()
        outside = self.base / "stream-outside"
        outside.mkdir()
        (bad_output / "streams").mkdir()
        os.symlink(outside, bad_output / "streams" / "stream-000001")
        with EventStreamStore(bad_output) as store:
            with self.assertRaises(EventStreamError):
                store.write_once(artifact, self.scope_artifact, self.profile, self.source)

    def test_stream_rejects_gaps_predecessors_duplicates_and_bindings(self) -> None:
        builder = EventStreamBuilder("stream-000001", self.scope_artifact, self.profile, self.source)
        builder.append(self.event_one)
        gap = copy.deepcopy(self.event_two)
        gap["sequence_no"] = 3
        gap["previous_event_hash"] = self.event_one["event_hash"]
        self._rehash_event(gap)
        with self.assertRaises(EventStreamError):
            builder.append(gap)

        builder.append(self.event_two)
        artifact = builder.seal()
        tampered = copy.deepcopy(artifact.to_dict())
        tampered["events"][1]["sequence_no"] = 3
        self._rehash_event(tampered["events"][1])
        self._rehash_stream(tampered)
        rejected_gap = verify_event_stream_artifact(tampered, self.scope_artifact, self.profile, self.source)
        self.assertFalse(rejected_gap.accepted)
        self.assertIn("EVENT_SEQUENCE_GAP", {item.code for item in rejected_gap.findings})

        duplicate_scan = copy.deepcopy(artifact.to_dict())
        duplicate_scan["events"][1]["scan_id"] = duplicate_scan["events"][0]["scan_id"]
        self._rehash_event(duplicate_scan["events"][1])
        self._rehash_stream(duplicate_scan)
        rejected_duplicate = verify_event_stream_artifact(duplicate_scan, self.scope_artifact, self.profile, self.source)
        self.assertFalse(rejected_duplicate.accepted)
        self.assertIn("DUPLICATE_SCAN_ID", {item.code for item in rejected_duplicate.findings})

        foreign = copy.deepcopy(artifact.to_dict())
        foreign["events"][1]["project_id"] = "foreign"
        self._rehash_event(foreign["events"][1])
        self._rehash_stream(foreign)
        rejected_foreign = verify_event_stream_artifact(foreign, self.scope_artifact, self.profile, self.source)
        self.assertFalse(rejected_foreign.accepted)
        self.assertIn("PROJECT_MISMATCH", {item.code for item in rejected_foreign.findings})

        stale_event_hash = copy.deepcopy(artifact.to_dict())
        stale_event_hash["events"][1]["status"] = "DENIED"
        self._rehash_stream(stale_event_hash)
        rejected_stale_hash = verify_event_stream_artifact(
            stale_event_hash, self.scope_artifact, self.profile, self.source
        )
        self.assertFalse(rejected_stale_hash.accepted)
        self.assertIn("EVENT_HASH_MISMATCH", {item.code for item in rejected_stale_hash.findings})

    def test_stream_schema_hash_and_capability_boundaries_fail_closed(self) -> None:
        builder = EventStreamBuilder("stream-000001", self.scope_artifact, self.profile, self.source)
        bad_schema = copy.deepcopy(self.event_one)
        bad_schema["schema_version"] = "future.v9"
        self._rehash_event(bad_schema)
        with self.assertRaises(EventStreamError):
            builder.append(bad_schema)

        wrong_scope = copy.deepcopy(self.event_one)
        wrong_scope["scope_hash"] = "0" * 64
        self._rehash_event(wrong_scope)
        with self.assertRaises(EventStreamError):
            builder.append(wrong_scope)

        wrong_capability = copy.deepcopy(self.event_one)
        wrong_capability["network_access"] = True
        self._rehash_event(wrong_capability)
        with self.assertRaises(EventStreamError):
            builder.append(wrong_capability)

    def test_stream_output_duplicate_keys_are_not_accepted(self) -> None:
        builder = EventStreamBuilder("stream-000001", self.scope_artifact, self.profile, self.source)
        builder.append(self.event_one)
        artifact = builder.seal()
        with EventStreamStore(self.output) as store:
            relative = store.write_once(artifact, self.scope_artifact, self.profile, self.source)
            path = self.output / relative
            valid = path.read_text(encoding="utf-8").rstrip()
            duplicate = valid[:-1] + ',"stream_hash":"' + artifact.stream_hash + '"}'
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaises(EventStreamError):
                store.read(artifact.stream_id, artifact.stream_hash, self.scope_artifact, self.profile, self.source)
            path.write_text(json.dumps(artifact.to_dict(), indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(EventStreamError):
                store.read(artifact.stream_id, artifact.stream_hash, self.scope_artifact, self.profile, self.source)

    def test_stream_store_reverifies_event_semantics_after_loading(self) -> None:
        builder = EventStreamBuilder("stream-000001", self.scope_artifact, self.profile, self.source)
        builder.append(self.event_one)
        artifact = builder.seal()
        with EventStreamStore(self.output) as store:
            store.write_once(artifact, self.scope_artifact, self.profile, self.source)

        tampered = copy.deepcopy(artifact.to_dict())
        tampered["events"][0]["manifest_hash"] = "not-a-sha256"
        self._rehash_event(tampered["events"][0])
        self._rehash_stream(tampered)
        tampered_hash = tampered["stream_hash"]
        tampered_path = self.output / "streams" / artifact.stream_id / f"{tampered_hash}.json"
        tampered_path.write_bytes(canonical_json_bytes(tampered) + b"\n")
        with EventStreamStore(self.output) as store:
            with self.assertRaises(EventStreamError):
                store.read(artifact.stream_id, tampered_hash, self.scope_artifact, self.profile, self.source)


if __name__ == "__main__":
    unittest.main()
