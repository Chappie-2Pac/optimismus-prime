from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

# Some existing Prime pytest entry points choose a parent directory as their
# rootdir. Keep this test import deterministic without adding a package marker
# to the already dirty top-level ``modules`` tree.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.understanding_s0 import UnderstandingRegistry
from modules.understanding_s0.registry import ArtifactConflict, RegistryError


class W3S0UnderstandingHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="w3-s0-")
        self.base = Path(self.tempdir.name)
        self.project = self.base / "project"
        self.output = self.base / "output"
        self.outside = self.base / "outside"
        self.project.mkdir()
        self.output.mkdir()
        self.outside.mkdir()
        (self.project / "README.md").write_text("project explanation\n", encoding="utf-8")
        (self.project / "src").mkdir()
        (self.project / "src" / "main.py").write_text("print('safe')\n", encoding="utf-8")
        (self.outside / "secret.txt").write_text("must not be read\n", encoding="utf-8")
        self.source_before = self._source_fingerprint()
        self.scan_numbers = iter(("scan-000001", "scan-000002", "scan-000003"))
        self.registry = UnderstandingRegistry(
            self.output,
            clock=lambda: "2026-11-15T12:00:00+00:00",
            scan_id_factory=lambda: next(self.scan_numbers),
        )
        self.profile = self.registry.register_project(
            "demo",
            self.project,
            (self.base,),
        )
        self.source = self.registry.register_source("demo", "workspace")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _source_fingerprint(self):
        result = []
        for path in sorted(self.project.rglob("*")):
            relative = path.relative_to(self.project).as_posix()
            st = os.lstat(path)
            result.append((relative, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ino))
            if path.is_file() and not path.is_symlink():
                result.append((relative, hashlib.sha256(path.read_bytes()).hexdigest()))
        return tuple(result)

    def test_complete_scan_is_hash_bound_and_does_not_write_source(self) -> None:
        first = self.registry.scan("demo", "workspace")
        second = self.registry.scan("demo", "workspace")

        self.assertEqual(first.manifest.status, "COMPLETE")
        self.assertTrue(first.manifest.coverage.complete)
        self.assertEqual(first.manifest.coverage.absence_claims, "allowed")
        self.assertFalse(first.manifest.coverage.lower_bound_only)
        self.assertEqual(first.manifest.manifest_hash, second.manifest.manifest_hash)
        self.assertEqual(first.manifest.registry_snapshot_hash, self.registry.project("demo").registry_snapshot_hash)
        self.assertEqual(first.manifest.scope_hash, second.manifest.scope_hash)
        self.assertEqual(first.event.kind, "SCAN_COMPLETED")
        self.assertTrue(first.event.read_only)
        self.assertEqual(first.event.source_writes, 0)
        self.assertFalse(first.event.network_access)
        self.assertEqual(first.event.process_starts, 0)
        self.assertEqual(self.source_before, self._source_fingerprint())
        self.assertTrue((self.output / "manifests" / f"{first.manifest.manifest_hash}.json").is_file())
        self.assertTrue((self.output / "events" / "scan-000001.json").is_file())

    def test_partial_scan_is_lower_bound_only_and_has_no_negative_claims(self) -> None:
        result = self.registry.scan("demo", "workspace", max_files=1)

        self.assertEqual(result.manifest.status, "PARTIAL")
        self.assertEqual(result.event.kind, "SCAN_PARTIAL")
        self.assertFalse(result.manifest.coverage.complete)
        self.assertTrue(result.manifest.coverage.unknown_remainder)
        self.assertTrue(result.manifest.coverage.lower_bound_only)
        self.assertEqual(result.manifest.coverage.absence_claims, "forbidden")
        self.assertIn("FILE_BUDGET_EXCEEDED", result.manifest.coverage.reason_codes)
        self.assertEqual(result.manifest.coverage.files_indexed, 1)

    def test_byte_budget_is_visible_and_never_exceeded(self) -> None:
        budget = (self.project / "README.md").stat().st_size

        result = self.registry.scan("demo", "workspace", max_bytes=budget)

        self.assertEqual(result.manifest.status, "PARTIAL")
        self.assertIn("BYTE_BUDGET_EXCEEDED", result.manifest.coverage.reason_codes)
        self.assertLessEqual(result.manifest.coverage.bytes_indexed, budget)
        self.assertEqual(result.manifest.coverage.absence_claims, "forbidden")

    def test_symlink_is_recorded_and_never_followed(self) -> None:
        os.symlink(self.outside, self.project / "escape")
        source_before_scan = self._source_fingerprint()

        result = self.registry.scan("demo", "workspace")

        denied = {(item.relative_path, item.reason_code) for item in result.manifest.denied_entries}
        self.assertIn(("escape", "SYMLINK_NOT_FOLLOWED"), denied)
        self.assertEqual(result.manifest.status, "PARTIAL")
        self.assertNotIn("escape/secret.txt", {item.relative_path for item in result.manifest.files})
        self.assertEqual(result.manifest.coverage.absence_claims, "forbidden")
        self.assertEqual(source_before_scan, self._source_fingerprint())

    def test_special_file_is_denied_without_opening_it(self) -> None:
        fifo = self.project / "named-pipe"
        os.mkfifo(fifo)

        result = self.registry.scan("demo", "workspace")

        denied = {(item.relative_path, item.reason_code) for item in result.manifest.denied_entries}
        self.assertIn(("named-pipe", "SPECIAL_FILE_DENIED"), denied)
        self.assertEqual(result.manifest.coverage.absence_claims, "forbidden")

    def test_sensitive_material_is_denied_before_content_read(self) -> None:
        (self.project / ".env").write_text("API_KEY=do-not-read\n", encoding="utf-8")
        (self.project / ".git").mkdir()
        (self.project / ".git" / "config").write_text("secret remote\n", encoding="utf-8")

        result = self.registry.scan("demo", "workspace")

        denied = {(item.relative_path, item.reason_code) for item in result.manifest.denied_entries}
        self.assertIn((".env", "SENSITIVE_PATH_DENIED"), denied)
        self.assertIn((".git", "SENSITIVE_PATH_DENIED"), denied)
        indexed = {item.relative_path for item in result.manifest.files}
        self.assertNotIn(".env", indexed)
        self.assertNotIn(".git/config", indexed)
        self.assertEqual(result.manifest.coverage.absence_claims, "forbidden")

    def test_empty_registered_scope_is_complete_not_partial(self) -> None:
        empty = self.project / "empty"
        empty.mkdir()
        self.registry.register_source("demo", "empty", "empty")

        result = self.registry.scan("demo", "empty")

        self.assertEqual(result.manifest.status, "COMPLETE")
        self.assertEqual(result.manifest.files, ())
        self.assertTrue(result.manifest.coverage.complete)
        self.assertEqual(result.manifest.coverage.absence_claims, "allowed")

    def test_provenance_drift_is_not_promoted_to_a_file_record(self) -> None:
        def mutate_after_read(relative_path: str) -> None:
            if relative_path == "README.md":
                replacement = self.project / "README.replacement"
                replacement.write_text("changed during scan\n", encoding="utf-8")
                os.replace(replacement, self.project / "README.md")

        result = self.registry.scan(
            "demo", "workspace", after_read_hook=mutate_after_read, test_only_hook=True
        )

        self.assertEqual(result.manifest.status, "PARTIAL")
        self.assertIn("PROVENANCE_DRIFT", result.manifest.coverage.reason_codes)
        self.assertNotIn("README.md", {item.relative_path for item in result.manifest.files})
        self.assertEqual(result.manifest.coverage.absence_claims, "forbidden")

    def test_same_size_same_mtime_content_mutation_is_caught_by_second_hash(self) -> None:
        def mutate_without_metadata_change(relative_path: str) -> None:
            if relative_path == "README.md":
                path = self.project / relative_path
                before = os.stat(path)
                path.write_bytes(b"X" * before.st_size)
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

        result = self.registry.scan(
            "demo", "workspace", after_read_hook=mutate_without_metadata_change, test_only_hook=True
        )

        self.assertEqual(result.manifest.status, "PARTIAL")
        self.assertIn("PROVENANCE_DRIFT", result.manifest.coverage.reason_codes)
        self.assertNotIn("README.md", {item.relative_path for item in result.manifest.files})

    def test_directory_entry_drift_is_visible_in_coverage(self) -> None:
        def add_entry_after_read(relative_path: str) -> None:
            if relative_path == "README.md":
                (self.project / "appeared-during-scan.txt").write_text("late\n", encoding="utf-8")

        result = self.registry.scan(
            "demo", "workspace", after_read_hook=add_entry_after_read, test_only_hook=True
        )

        self.assertEqual(result.manifest.status, "PARTIAL")
        self.assertIn("DIRECTORY_DRIFT", result.manifest.coverage.reason_codes)
        self.assertEqual(result.manifest.coverage.absence_claims, "forbidden")

    def test_traversal_and_unapproved_sources_fail_closed(self) -> None:
        with self.assertRaises(RegistryError):
            self.registry.register_source("demo", "escape-source", "../outside")
        with self.assertRaises(RegistryError):
            self.registry.register_source("demo", "not-approved", approved=False)
        with self.assertRaises(RegistryError):
            self.registry.scan("unknown", "workspace")
        with self.assertRaises(RegistryError):
            self.registry.scan("demo", "workspace", after_read_hook=lambda _: None)

    def test_project_root_must_be_inside_an_allowed_real_root(self) -> None:
        linked_root = self.base / "project-link"
        os.symlink(self.project, linked_root)
        with self.assertRaises((RegistryError, ValueError)):
            self.registry.register_project("linked", linked_root, (self.base,))
        with self.assertRaises((RegistryError, ValueError)):
            self.registry.register_project("outside", self.outside, (self.project,))
        with self.assertRaises(RegistryError):
            self.registry.register_project("proc", "/proc", ("/",))
        with self.assertRaises(RegistryError):
            self.registry.register_project("broad", "/", ("/",))

    def test_output_domain_cannot_be_inside_source_or_be_a_symlink(self) -> None:
        nested_output = self.project / "generated"
        nested_output.mkdir()
        nested_registry = UnderstandingRegistry(nested_output)
        with self.assertRaises((RegistryError, ValueError)):
            nested_registry.register_project("nested", self.project, (self.base,))

        output_target = self.base / "real-output"
        output_target.mkdir()
        output_link = self.base / "output-link"
        os.symlink(output_target, output_link)
        with self.assertRaises((RegistryError, ValueError)):
            UnderstandingRegistry(output_link)

        project_under_output = self.output / "project-under-output"
        project_under_output.mkdir()
        with self.assertRaises(RegistryError):
            self.registry.register_project("output-parent", project_under_output, (self.output,))

    def test_output_fd_remains_in_original_domain_after_path_replacement(self) -> None:
        moved_output = self.base / "output-moved"
        os.rename(self.output, moved_output)
        os.symlink(self.outside, self.output)

        result = self.registry.scan("demo", "workspace")

        self.assertTrue((moved_output / "manifests" / f"{result.manifest.manifest_hash}.json").is_file())
        self.assertFalse((self.outside / "manifests").exists())

    def test_registered_project_identity_drift_blocks_replacement_root(self) -> None:
        old_project = self.base / "project-old"
        os.rename(self.project, old_project)
        self.project.mkdir()
        (self.project / "replacement.txt").write_text("not registered\n", encoding="utf-8")

        result = self.registry.scan("demo", "workspace")

        self.assertEqual(result.manifest.status, "DENIED")
        self.assertIn("REGISTRY_ROOT_DRIFT", result.manifest.coverage.reason_codes)
        self.assertEqual(result.manifest.files, ())
        self.assertEqual(result.manifest.coverage.absence_claims, "forbidden")

    def test_same_name_child_directory_replacement_is_partial(self) -> None:
        def replace_child_after_read(relative_path: str) -> None:
            if relative_path == "src/main.py":
                old_src = self.project / "src"
                moved_src = self.project / "src-old"
                os.rename(old_src, moved_src)
                new_src = self.project / "src"
                new_src.mkdir()
                (new_src / "main.py").write_text("replacement\n", encoding="utf-8")

        result = self.registry.scan(
            "demo", "workspace", after_read_hook=replace_child_after_read, test_only_hook=True
        )

        self.assertEqual(result.manifest.status, "PARTIAL")
        self.assertIn("DIRECTORY_DRIFT", result.manifest.coverage.reason_codes)
        self.assertEqual(result.manifest.coverage.absence_claims, "forbidden")

    def test_append_only_artifacts_are_idempotent_and_conflicts_are_not_overwritten(self) -> None:
        registry = UnderstandingRegistry(
            self.output,
            clock=lambda: "2026-11-15T12:00:00+00:00",
            scan_id_factory=lambda: "scan-fixed",
        )
        registry.register_project("other", self.project, (self.base,))
        registry.register_source("other", "workspace")
        first = registry.scan("other", "workspace")
        second = registry.scan("other", "workspace")
        self.assertEqual(first.event.to_dict(), second.event.to_dict())

        event_path = self.output / "events" / "scan-fixed.json"
        event_path.write_bytes(b"tampered\n")
        with self.assertRaises(ArtifactConflict):
            registry.scan("other", "workspace")

    def test_registry_artifacts_expose_the_scope_and_policy_commitments(self) -> None:
        result = self.registry.scan("demo", "workspace")
        event = (self.output / "events" / f"{result.event.scan_id}.json").read_text(encoding="utf-8")
        manifest = (self.output / "manifests" / f"{result.manifest.manifest_hash}.json").read_text(encoding="utf-8")

        self.assertIn(result.manifest.registry_snapshot_hash, event)
        self.assertIn(result.manifest.scope_hash, event)
        self.assertIn(result.manifest.registry_snapshot_hash, manifest)
        self.assertIn(result.manifest.scope_hash, manifest)
        self.assertIn('"read_only":true', event)
        self.assertIn('"network_access":false', event)
        self.assertIn('"process_starts":0', event)


if __name__ == "__main__":
    unittest.main()
