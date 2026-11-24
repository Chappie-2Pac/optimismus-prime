"""File-descriptor based, read-only source scanner for W3-S0."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import os
import stat
from typing import Callable, List, Optional, Set

from .model import (
    Coverage,
    DeniedEntry,
    FileRecord,
    ProjectProfile,
    ScanEvent,
    ScanResult,
    SourceManifest,
    SourceSpec,
)
from .path_policy import PathPolicyError, open_directory_nofollow, open_relative_directory


Clock = Callable[[], str]
AfterReadHook = Callable[[str], None]


SENSITIVE_COMPONENTS = {
    ".env",
    ".git",
    ".gnupg",
    ".netrc",
    ".network-pki",
    ".ssh",
    "credentials",
    "id_rsa",
    "secrets",
    "token",
    "tokens",
}
SENSITIVE_SUFFIXES = (".key", ".pem", ".p12", ".pfx")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class _State:
    max_files: Optional[int]
    max_bytes: Optional[int]
    files: List[FileRecord] = field(default_factory=list)
    denied: List[DeniedEntry] = field(default_factory=list)
    directories_seen: int = 0
    entries_seen: int = 0
    bytes_indexed: int = 0
    unknown_remainder: bool = False
    reasons: Set[str] = field(default_factory=set)

    def deny(self, relative_path: str, entry_kind: str, reason: str, detail: str, unknown: bool = True) -> None:
        self.denied.append(DeniedEntry(relative_path, entry_kind, reason, detail[:240]))
        self.reasons.add(reason)
        if unknown:
            self.unknown_remainder = True

    def budget_stop(self, reason: str) -> None:
        self.reasons.add(reason)
        self.unknown_remainder = True

    def coverage(self) -> Coverage:
        complete = not self.denied and not self.unknown_remainder
        return Coverage(
            requested_scope="registered-source-root",
            directories_seen=self.directories_seen,
            entries_seen=self.entries_seen,
            files_indexed=len(self.files),
            bytes_indexed=self.bytes_indexed,
            denied_entries=len(self.denied),
            complete=complete,
            unknown_remainder=self.unknown_remainder,
            absence_claims="allowed" if complete else "forbidden",
            reason_codes=tuple(sorted(self.reasons)),
            eligible_entries=None,
            lower_bound_only=not complete,
        )


class ReadOnlyScanner:
    """Scan only an already registered source; never writes to that source."""

    def __init__(self, clock: Optional[Clock] = None):
        self._clock = clock or utc_now

    @staticmethod
    def _identity(st: os.stat_result) -> tuple[int, int, int, int, int]:
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, stat.S_IMODE(st.st_mode))

    @staticmethod
    def _stable_identity(st: os.stat_result) -> tuple[int, int, int]:
        return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode))

    @staticmethod
    def _join(relative_directory: str, name: str) -> str:
        return name if not relative_directory else f"{relative_directory}/{name}"

    @staticmethod
    def _sensitive(relative_path: str) -> bool:
        for component in relative_path.split("/"):
            lowered = component.lower()
            if (lowered in SENSITIVE_COMPONENTS
                    or lowered.startswith(".env.")
                    or lowered.endswith(SENSITIVE_SUFFIXES)):
                return True
        return False

    def _walk(self, fd: int, relative_directory: str, source_device: int, state: _State,
              after_read_hook: Optional[AfterReadHook]) -> None:
        try:
            names = sorted(os.listdir(fd))
        except OSError as exc:
            state.deny(relative_directory or ".", "directory", "DIRECTORY_READ_FAILED", str(exc))
            return

        for name in names:
            if state.max_files is not None and len(state.files) >= state.max_files:
                state.budget_stop("FILE_BUDGET_EXCEEDED")
                return

            relative_path = self._join(relative_directory, name)
            state.entries_seen += 1
            try:
                before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError as exc:
                state.deny(relative_path, "unknown", "ENTRY_STAT_FAILED", str(exc))
                continue

            mode = before.st_mode
            if stat.S_ISLNK(mode):
                state.deny(relative_path, "symlink", "SYMLINK_NOT_FOLLOWED", "link targets are never read")
                continue

            if self._sensitive(relative_path):
                state.deny(
                    relative_path,
                    "directory" if stat.S_ISDIR(mode) else "file",
                    "SENSITIVE_PATH_DENIED",
                    "policy excludes secret or control material",
                    unknown=stat.S_ISDIR(mode),
                )
                continue

            if stat.S_ISDIR(mode):
                if before.st_dev != source_device:
                    state.deny(relative_path, "directory", "DEVICE_BOUNDARY", "directory is on another device")
                    continue
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
                try:
                    child_fd = os.open(name, flags, dir_fd=fd)
                except OSError as exc:
                    state.deny(relative_path, "directory", "DIRECTORY_OPEN_FAILED", str(exc))
                    continue
                try:
                    child_stat = os.fstat(child_fd)
                    if child_stat.st_dev != source_device:
                        state.deny(relative_path, "directory", "DEVICE_BOUNDARY", "directory changed device")
                        continue
                    child_identity = self._stable_identity(child_stat)
                    state.directories_seen += 1
                    self._walk(child_fd, relative_path, source_device, state, after_read_hook)
                    try:
                        path_after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if (not stat.S_ISDIR(path_after.st_mode)
                                or self._stable_identity(path_after) != child_identity):
                            state.deny(
                                relative_path,
                                "directory",
                                "DIRECTORY_DRIFT",
                                "directory identity changed during scan",
                            )
                    except OSError as exc:
                        state.deny(relative_path, "directory", "DIRECTORY_DRIFT", str(exc))
                finally:
                    os.close(child_fd)
                continue

            if not stat.S_ISREG(mode):
                state.deny(relative_path, "special", "SPECIAL_FILE_DENIED", "only regular files are indexed", unknown=False)
                continue

            if state.max_bytes is not None and state.bytes_indexed + before.st_size > state.max_bytes:
                state.deny(relative_path, "file", "BYTE_BUDGET_EXCEEDED", "file was not read")
                state.budget_stop("BYTE_BUDGET_EXCEEDED")
                return

            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                file_fd = os.open(name, flags, dir_fd=fd)
            except OSError as exc:
                state.deny(relative_path, "file", "FILE_OPEN_FAILED", str(exc))
                continue

            try:
                opened = os.fstat(file_fd)
                if not stat.S_ISREG(opened.st_mode) or self._identity(opened) != self._identity(before):
                    state.deny(relative_path, "file", "PROVENANCE_DRIFT", "file identity changed before read")
                    continue
                digest = hashlib.sha256()
                bytes_read = 0
                while True:
                    read_size = 1024 * 1024
                    if state.max_bytes is not None:
                        remaining = state.max_bytes - state.bytes_indexed - bytes_read
                        if remaining < 0:
                            state.deny(relative_path, "file", "BYTE_BUDGET_EXCEEDED", "read budget exceeded")
                            state.budget_stop("BYTE_BUDGET_EXCEEDED")
                            return
                        read_size = min(read_size, remaining + 1)
                    chunk = os.read(file_fd, read_size)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    digest.update(chunk)
                    if (state.max_bytes is not None
                            and state.bytes_indexed + bytes_read > state.max_bytes):
                        state.deny(relative_path, "file", "BYTE_BUDGET_EXCEEDED", "read budget exceeded")
                        state.budget_stop("BYTE_BUDGET_EXCEEDED")
                        return
                if after_read_hook is not None:
                    after_read_hook(relative_path)
                after = os.fstat(file_fd)
                try:
                    path_after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError as exc:
                    state.deny(relative_path, "file", "PROVENANCE_DRIFT", str(exc))
                    continue
                if (not stat.S_ISREG(path_after.st_mode)
                        or self._identity(after) != self._identity(opened)
                        or self._identity(path_after) != self._identity(opened)):
                    state.deny(relative_path, "file", "PROVENANCE_DRIFT", "file changed during read")
                    continue
                verify_fd = os.open(name, flags, dir_fd=fd)
                try:
                    verify_before = os.fstat(verify_fd)
                    if self._identity(verify_before) != self._identity(opened):
                        state.deny(relative_path, "file", "PROVENANCE_DRIFT", "file changed before verification")
                        continue
                    verify_digest = hashlib.sha256()
                    verify_bytes = 0
                    while True:
                        read_size = 1024 * 1024
                        if state.max_bytes is not None:
                            remaining = state.max_bytes - state.bytes_indexed - verify_bytes
                            if remaining < 0:
                                state.deny(relative_path, "file", "BYTE_BUDGET_EXCEEDED", "verification budget exceeded")
                                state.budget_stop("BYTE_BUDGET_EXCEEDED")
                                return
                            read_size = min(read_size, remaining + 1)
                        chunk = os.read(verify_fd, read_size)
                        if not chunk:
                            break
                        verify_bytes += len(chunk)
                        verify_digest.update(chunk)
                        if (state.max_bytes is not None
                                and state.bytes_indexed + verify_bytes > state.max_bytes):
                            state.deny(relative_path, "file", "BYTE_BUDGET_EXCEEDED", "verification budget exceeded")
                            state.budget_stop("BYTE_BUDGET_EXCEEDED")
                            return
                    verify_after = os.fstat(verify_fd)
                    if (self._identity(verify_after) != self._identity(opened)
                            or verify_digest.digest() != digest.digest()):
                        state.deny(relative_path, "file", "PROVENANCE_DRIFT", "content changed during verification")
                        continue
                finally:
                    os.close(verify_fd)
                state.files.append(
                    FileRecord(
                        relative_path=relative_path,
                        size=after.st_size,
                        mtime_ns=after.st_mtime_ns,
                        mode=stat.S_IMODE(after.st_mode),
                        device=after.st_dev,
                        inode=after.st_ino,
                        link_count=after.st_nlink,
                        sha256=digest.hexdigest(),
                    )
                )
                state.bytes_indexed += after.st_size
            except OSError as exc:
                state.deny(relative_path, "file", "FILE_READ_FAILED", str(exc))
            finally:
                os.close(file_fd)

        try:
            final_names = sorted(os.listdir(fd))
        except OSError as exc:
            state.deny(relative_directory or ".", "directory", "DIRECTORY_READ_FAILED", str(exc))
            return
        if final_names != names:
            state.deny(
                relative_directory or ".",
                "directory",
                "DIRECTORY_DRIFT",
                "directory entries changed during scan",
            )

    def scan(
        self,
        project: ProjectProfile,
        source: SourceSpec,
        scan_id: str,
        started_at: str,
        registry_snapshot_hash: str,
        scope_hash: str,
        max_files: Optional[int] = None,
        max_bytes: Optional[int] = None,
        after_read_hook: Optional[AfterReadHook] = None,
    ) -> ScanResult:
        if max_files is not None and max_files < 0:
            raise ValueError("max_files must be non-negative")
        if max_bytes is not None and max_bytes < 0:
            raise ValueError("max_bytes must be non-negative")

        state = _State(max_files=max_files, max_bytes=max_bytes)
        source_device: Optional[int] = None
        root_fd: Optional[int] = None
        source_fd: Optional[int] = None
        try:
            root_fd = open_directory_nofollow(project.canonical_root)
            root_stat = os.fstat(root_fd)
            if self._stable_identity(root_stat) != (project.root_device, project.root_inode, stat.S_IFDIR):
                state.deny(
                    source.relative_root or ".",
                    "source",
                    "REGISTRY_ROOT_DRIFT",
                    "registered project root identity changed",
                )
            else:
                source_fd = open_relative_directory(root_fd, source.relative_root)
                source_stat = os.fstat(source_fd)
                source_device = source_stat.st_dev
                expected_source = (source.root_device, source.root_inode, stat.S_IFDIR)
                if self._stable_identity(source_stat) != expected_source:
                    state.deny(
                        source.relative_root or ".",
                        "source",
                        "SOURCE_ROOT_DRIFT",
                        "registered source root identity changed",
                    )
                elif source_stat.st_dev != root_stat.st_dev:
                    state.deny(
                        source.relative_root or ".",
                        "directory",
                        "DEVICE_BOUNDARY",
                        "source root is on another device",
                    )
                else:
                    state.directories_seen = 1
                    self._walk(source_fd, "", source_device, state, after_read_hook)
        except (OSError, PathPolicyError) as exc:
            state.deny(source.relative_root or ".", "source", "SOURCE_UNAVAILABLE", str(exc))
        finally:
            if root_fd is not None and source_fd is not None and state.directories_seen:
                verify_root_fd: Optional[int] = None
                verify_source_fd: Optional[int] = None
                try:
                    verify_root_fd = open_directory_nofollow(project.canonical_root)
                    verify_root_stat = os.fstat(verify_root_fd)
                    verify_source_fd = open_relative_directory(verify_root_fd, source.relative_root)
                    verify_source_stat = os.fstat(verify_source_fd)
                    if (self._stable_identity(verify_root_stat)
                            != (project.root_device, project.root_inode, stat.S_IFDIR)
                            or self._stable_identity(verify_source_stat)
                            != (source.root_device, source.root_inode, stat.S_IFDIR)):
                        state.deny(
                            source.relative_root or ".",
                            "source",
                            "SOURCE_ROOT_DRIFT",
                            "registered source scope changed during scan",
                        )
                except (OSError, PathPolicyError) as exc:
                    state.deny(source.relative_root or ".", "source", "SOURCE_ROOT_DRIFT", str(exc))
                finally:
                    if verify_source_fd is not None:
                        os.close(verify_source_fd)
                    if verify_root_fd is not None:
                        os.close(verify_root_fd)
            if source_fd is not None:
                os.close(source_fd)
            if root_fd is not None:
                os.close(root_fd)

        coverage = state.coverage()
        status = "COMPLETE" if coverage.complete else "PARTIAL"
        if not state.directories_seen:
            status = "DENIED"
        finished_at = self._clock()
        manifest = SourceManifest(
            schema_version="source-manifest.v1",
            project_id=project.project_id,
            source_id=source.source_id,
            relative_root=source.relative_root,
            path_policy_hash=project.path_policy_hash,
            registry_snapshot_hash=registry_snapshot_hash,
            scope_hash=scope_hash,
            status=status,
            state="SEALED",
            coverage=coverage,
            files=tuple(sorted(state.files, key=lambda item: item.relative_path)),
            denied_entries=tuple(sorted(state.denied, key=lambda item: (item.relative_path, item.reason_code))),
            source_device=source_device,
            observed_at=finished_at,
        )
        event = ScanEvent(
            schema_version="scan-event.v1",
            scan_id=scan_id,
            project_id=project.project_id,
            source_id=source.source_id,
            registry_snapshot_hash=registry_snapshot_hash,
            scope_hash=scope_hash,
            sequence_no=1,
            kind=("SCAN_COMPLETED" if status == "COMPLETE" else
                  "SCAN_PARTIAL" if status == "PARTIAL" else "SCAN_BLOCKED"),
            previous_event_hash=None,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            manifest_hash=manifest.manifest_hash,
            coverage=coverage,
            reason_codes=coverage.reason_codes,
            read_only=True,
            source_writes=0,
            network_access=False,
            process_starts=0,
        )
        return ScanResult(manifest=manifest, event=event)

