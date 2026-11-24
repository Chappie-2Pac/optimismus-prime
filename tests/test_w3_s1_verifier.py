from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.understanding_s0 import UnderstandingRegistry
from modules.understanding_s0.model import sha256_json
from modules.understanding_s1 import (
    verify_bundle,
    verify_event_stream,
    verify_event,
    verify_manifest,
    verify_output_bundle,
    verify_source,
)


class W3S1VerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="w3-s1-")
        self.base = Path(self.tempdir.name)
        self.project = self.base / "project"
        self.output = self.base / "output"
        self.project.mkdir()
        self.output.mkdir()
        (self.project / "README.md").write_text("verifier fixture\n", encoding="utf-8")
        (self.project / "src").mkdir()
        (self.project / "src" / "main.py").write_text("print('verified')\n", encoding="utf-8")
        self.registry = UnderstandingRegistry(
            self.output,
            clock=lambda: "2026-11-15T12:00:00+00:00",
            scan_id_factory=lambda: "scan-000001",
        )
        self.registry.register_project("demo", self.project, (self.base,))
        self.registry.register_source("demo", "workspace")
        self.scan = self.registry.scan("demo", "workspace")
        self.profile_path = "registry/projects/demo/v0002.json"
        self.source_path = "registry/sources/demo/workspace.json"
        self.manifest_path = f"manifests/{self.scan.manifest.manifest_hash}.json"
        self.event_path = "events/scan-000001.json"
        self.profile = self._load(self.profile_path)
        self.source = self._load(self.source_path)
        self.manifest = self._load(self.manifest_path)
        self.event = self._load(self.event_path)
        self.scope = {
            "scope_version": "scan-scope.v1",
            "project_id": "demo",
            "source_id": "workspace",
            "root_relative": "",
            "include_rules": ["regular-files"],
            "exclude_rules": [],
            "file_types": ["regular"],
            "follow_symlinks": False,
            "cross_device": False,
            "max_files": None,
            "max_bytes": None,
        }

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _load(self, relative: str) -> dict:
        return json.loads((self.output / relative).read_text(encoding="utf-8"))

    @staticmethod
    def _manifest_rehash(manifest: dict) -> None:
        payload = {key: value for key, value in manifest.items() if key not in {"observed_at", "manifest_hash"}}
        manifest["manifest_hash"] = sha256_json(payload)

    @staticmethod
    def _event_rehash(event: dict) -> None:
        body = {key: value for key, value in event.items() if key != "event_hash"}
        event["event_hash"] = sha256_json(body)

    def test_valid_bundle_and_explicit_output_loader_are_accepted(self) -> None:
        result = verify_bundle(self.profile, self.source, self.manifest, self.event, self.scope)
        self.assertTrue(result.accepted, result.to_dict())
        self.assertTrue(verify_source(self.source, self.profile).accepted)
        self.assertTrue(verify_manifest(self.manifest, self.profile, self.source, self.scope).accepted)
        self.assertTrue(verify_event(self.event, self.manifest, self.profile, self.source, self.scope).accepted)

        loaded = verify_output_bundle(
            self.output,
            self.profile_path,
            self.source_path,
            self.manifest_path,
            self.event_path,
            self.scope,
        )
        self.assertTrue(loaded.accepted, loaded.to_dict())

    def test_scope_is_external_evidence_not_repeated_manifest_data(self) -> None:
        wrong_scope = copy.deepcopy(self.scope)
        wrong_scope["max_files"] = 1

        result = verify_bundle(self.profile, self.source, self.manifest, self.event, wrong_scope)

        self.assertFalse(result.accepted)
        self.assertIn("SCOPE_MISMATCH", {item.code for item in result.findings})

    def test_manifest_payload_tampering_is_rejected(self) -> None:
        tampered = copy.deepcopy(self.manifest)
        tampered["files"][0]["sha256"] = "0" * 64

        result = verify_bundle(self.profile, self.source, tampered, self.event, self.scope)

        self.assertFalse(result.accepted)
        self.assertIn("MANIFEST_HASH_MISMATCH", {item.code for item in result.findings})

    def test_semantically_invalid_manifest_is_rejected_even_after_rehash(self) -> None:
        tampered = copy.deepcopy(self.manifest)
        tampered["status"] = "PARTIAL"
        tampered["coverage"]["complete"] = False
        tampered["coverage"]["absence_claims"] = "forbidden"
        tampered["coverage"]["lower_bound_only"] = True
        tampered["coverage"]["reason_codes"] = ["FORGED_REASON"]
        self._manifest_rehash(tampered)

        result = verify_bundle(self.profile, self.source, tampered, self.event, self.scope)

        self.assertFalse(result.accepted)
        codes = {item.code for item in result.findings}
        self.assertTrue({"COVERAGE_INVALID", "MANIFEST_BINDING"}.intersection(codes))

    def test_event_hash_and_cross_record_coverage_are_verified(self) -> None:
        tampered = copy.deepcopy(self.event)
        tampered["coverage"]["files_indexed"] += 1
        self._event_rehash(tampered)
        result = verify_bundle(self.profile, self.source, self.manifest, tampered, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("COVERAGE_INVALID", {item.code for item in result.findings})

        bad_hash = copy.deepcopy(self.event)
        bad_hash["event_hash"] = "f" * 64
        result = verify_bundle(self.profile, self.source, self.manifest, bad_hash, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("EVENT_HASH_MISMATCH", {item.code for item in result.findings})

    def test_reviewed_coverage_device_path_and_numeric_boundaries_are_rejected(self) -> None:
        unobserved = copy.deepcopy(self.manifest)
        unobserved["coverage"]["directories_seen"] = 0
        self._manifest_rehash(unobserved)
        result = verify_bundle(self.profile, self.source, unobserved, self.event, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("COVERAGE_INVALID", {item.code for item in result.findings})

        foreign_device = copy.deepcopy(self.manifest)
        foreign_device["files"][0]["device"] += 1
        self._manifest_rehash(foreign_device)
        result = verify_bundle(self.profile, self.source, foreign_device, self.event, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("DEVICE_MISMATCH", {item.code for item in result.findings})

        noncanonical_path = copy.deepcopy(self.manifest)
        noncanonical_path["files"][0]["relative_path"] = "./" + noncanonical_path["files"][0]["relative_path"]
        self._manifest_rehash(noncanonical_path)
        result = verify_bundle(self.profile, self.source, noncanonical_path, self.event, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("PATH_INVALID", {item.code for item in result.findings})

        numeric_event = copy.deepcopy(self.event)
        numeric_event["sequence_no"] = True
        self._event_rehash(numeric_event)
        result = verify_bundle(self.profile, self.source, self.manifest, numeric_event, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("SCHEMA_TYPE", {item.code for item in result.findings})

        naive_event = copy.deepcopy(self.event)
        naive_event["started_at"] = "2026-11-15T12:00:00"
        naive_event["finished_at"] = "2026-11-15T12:00:01"
        self._event_rehash(naive_event)
        result = verify_bundle(self.profile, self.source, self.manifest, naive_event, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("TIMESTAMP_INVALID", {item.code for item in result.findings})

    def test_registry_scope_and_side_effect_bindings_are_fail_closed(self) -> None:
        tampered = copy.deepcopy(self.manifest)
        tampered["registry_snapshot_hash"] = "1" * 64
        self._manifest_rehash(tampered)
        result = verify_bundle(self.profile, self.source, tampered, self.event, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("REGISTRY_BINDING", {item.code for item in result.findings})

        bad_event = copy.deepcopy(self.event)
        bad_event["read_only"] = False
        self._event_rehash(bad_event)
        result = verify_bundle(self.profile, self.source, self.manifest, bad_event, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("CAPABILITY_VIOLATION", {item.code for item in result.findings})

    def test_unknown_fields_duplicate_keys_and_invalid_timestamps_are_rejected(self) -> None:
        unknown = copy.deepcopy(self.manifest)
        unknown["future_field"] = True
        result = verify_bundle(self.profile, self.source, unknown, self.event, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("SCHEMA_UNKNOWN_FIELDS", {item.code for item in result.findings})

        bad_event = copy.deepcopy(self.event)
        bad_event["started_at"] = "2026-11-15T13:00:00+00:00"
        bad_event["finished_at"] = "2026-11-15T12:00:00+00:00"
        self._event_rehash(bad_event)
        result = verify_bundle(self.profile, self.source, self.manifest, bad_event, self.scope)
        self.assertFalse(result.accepted)
        self.assertIn("TIMESTAMP_INVALID", {item.code for item in result.findings})

        duplicate_text = (self.output / self.event_path).read_text(encoding="utf-8").rstrip()
        duplicate_text = duplicate_text[:-1] + ',"event_hash":"' + self.event["event_hash"] + '"}'
        copied = self.base / "duplicate-output"
        shutil.copytree(self.output, copied)
        (copied / self.event_path).write_text(duplicate_text, encoding="utf-8")
        loaded = verify_output_bundle(
            copied,
            self.profile_path,
            self.source_path,
            self.manifest_path,
            self.event_path,
            self.scope,
        )
        self.assertFalse(loaded.accepted)
        self.assertIn("OUTPUT_READ_FAILED", {item.code for item in loaded.findings})

    def test_event_stream_rejects_duplicate_or_reordered_records(self) -> None:
        self.assertTrue(verify_event_stream([self.event]).accepted)
        duplicate = verify_event_stream([self.event, self.event])
        self.assertFalse(duplicate.accepted)
        self.assertIn("DUPLICATE_EVENT", {item.code for item in duplicate.findings})

        later = copy.deepcopy(self.event)
        later["sequence_no"] = 3
        later["previous_event_hash"] = self.event["event_hash"]
        self._event_rehash(later)
        gap = verify_event_stream([self.event, later])
        self.assertFalse(gap.accepted)
        self.assertIn("EVENT_SEQUENCE_GAP", {item.code for item in gap.findings})

    def test_output_loader_rejects_symlink_root_and_symlink_artifact(self) -> None:
        root_link = self.base / "output-link"
        os.symlink(self.output, root_link)
        rejected_root = verify_output_bundle(
            root_link,
            self.profile_path,
            self.source_path,
            self.manifest_path,
            self.event_path,
            self.scope,
        )
        self.assertFalse(rejected_root.accepted)
        self.assertIn("OUTPUT_ROOT_REJECTED", {item.code for item in rejected_root.findings})

        copied = self.base / "symlink-output"
        shutil.copytree(self.output, copied)
        target = copied / self.event_path
        target.unlink()
        os.symlink(self.output / self.event_path, target)
        rejected_file = verify_output_bundle(
            copied,
            self.profile_path,
            self.source_path,
            self.manifest_path,
            self.event_path,
            self.scope,
        )
        self.assertFalse(rejected_file.accepted)
        self.assertIn("OUTPUT_READ_FAILED", {item.code for item in rejected_file.findings})

    def test_verification_is_read_only(self) -> None:
        def fingerprint(root: Path):
            values = []
            for path in sorted(root.rglob("*")):
                if path.is_file() and not path.is_symlink():
                    values.append((path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
            return tuple(values)

        before_source = fingerprint(self.project)
        before_output = fingerprint(self.output)
        result = verify_output_bundle(
            self.output,
            self.profile_path,
            self.source_path,
            self.manifest_path,
            self.event_path,
            self.scope,
        )
        self.assertTrue(result.accepted, result.to_dict())
        self.assertEqual(before_source, fingerprint(self.project))
        self.assertEqual(before_output, fingerprint(self.output))


if __name__ == "__main__":
    unittest.main()
