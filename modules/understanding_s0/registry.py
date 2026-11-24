"""Explicit-output Project Registry around the W3-S0 read-only scanner."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import stat
from typing import Callable, Dict, Optional, Tuple

from .model import ProjectProfile, ScanResult, SourceSpec, canonical_json_bytes, sha256_json
from .path_policy import (
    PathPolicyError,
    absolute_path,
    is_same_or_under,
    normalized_relative,
    open_directory_nofollow,
    open_output_root,
    open_relative_directory,
    overlaps_protected_root,
    require_directory,
    safe_trust,
    validate_id,
)
from .scanner import ReadOnlyScanner, utc_now


Clock = Callable[[], str]
IdFactory = Callable[[], str]


class RegistryError(ValueError):
    """The registry refuses an unproven or conflicting operation."""


class ArtifactConflict(RegistryError):
    """An append-only artifact path already contains different bytes."""


class UnderstandingRegistry:
    """Small W3-S0 registry; no Prime runtime or project files are mutated."""

    def __init__(
        self,
        output_root: os.PathLike[str] | str,
        clock: Optional[Clock] = None,
        scan_id_factory: Optional[IdFactory] = None,
    ) -> None:
        self.output_root = absolute_path(output_root, "output root")
        if overlaps_protected_root(self.output_root):
            raise RegistryError("output root overlaps a protected system root")
        try:
            output_fd = open_output_root(self.output_root)
        except (OSError, PathPolicyError) as exc:
            raise RegistryError(f"output root rejected by path policy: {exc}") from exc
        self._output_fd = output_fd
        self._clock = clock or utc_now
        self._scan_id_factory = scan_id_factory or self._default_scan_id
        self._projects: Dict[str, ProjectProfile] = {}
        self._sources: Dict[Tuple[str, str], SourceSpec] = {}
        self._scan_counter = 0

    def close(self) -> None:
        output_fd = getattr(self, "_output_fd", None)
        if output_fd is not None:
            self._output_fd = None
            os.close(output_fd)

    def __enter__(self) -> "UnderstandingRegistry":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def _default_scan_id(self) -> str:
        self._scan_counter += 1
        return f"scan-{self._scan_counter:06d}"

    def _write_once(self, relative_path: str, payload: object) -> None:
        parts = Path(relative_path).parts
        if (not parts or Path(relative_path).is_absolute()
                or any(part in ("", ".", "..", os.sep) for part in parts)):
            raise RegistryError("invalid output artifact path")
        if self._output_fd is None:
            raise RegistryError("registry is closed")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        directory_fd = os.dup(self._output_fd)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                st = os.stat(part, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                    raise RegistryError(f"output path component is not a directory: {part}")
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd

            target_name = parts[-1]
            data = canonical_json_bytes(payload) + b"\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
            try:
                fd = os.open(target_name, flags, 0o600, dir_fd=directory_fd)
            except FileExistsError:
                st = os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    raise RegistryError(f"output artifact is not a regular file: {target_name}")
                read_fd = os.open(
                    target_name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                with os.fdopen(read_fd, "rb") as handle:
                    existing = handle.read()
                if existing != data:
                    raise ArtifactConflict(f"append-only artifact conflict: {relative_path}")
                return
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.fsync(directory_fd)
            except BaseException:
                try:
                    os.unlink(target_name, dir_fd=directory_fd)
                except OSError:
                    pass
                raise
        finally:
            os.close(directory_fd)

    @staticmethod
    def _policy_hash(project_root: str, allowed_roots: Tuple[str, ...]) -> str:
        return sha256_json(
            {
                "policy_version": "path-policy.v1",
                "canonical_root": project_root,
                "allowed_roots": list(allowed_roots),
                "symlinks": "deny",
                "special_files": "deny",
                "device_boundaries": "deny",
                "source_writes": "deny",
                "network": "deny",
                "process_starts": "deny",
            }
        )

    @staticmethod
    def _registry_hash(profile: ProjectProfile, sources: Tuple[SourceSpec, ...]) -> str:
        body = profile.to_dict()
        body.pop("registry_snapshot_hash", None)
        return sha256_json({"profile": body, "sources": [item.to_dict() for item in sources]})

    def _emit_profile(self, profile: ProjectProfile) -> None:
        self._write_once(
            f"registry/projects/{profile.project_id}/v{profile.version:04d}.json",
            profile.to_dict(),
        )

    def register_project(
        self,
        project_id: str,
        canonical_root: os.PathLike[str] | str,
        allowed_roots: Tuple[os.PathLike[str] | str, ...] | list[os.PathLike[str] | str],
    ) -> ProjectProfile:
        validate_id(project_id, "project_id")
        if project_id in self._projects:
            raise RegistryError(f"project already registered: {project_id}")
        project_path = absolute_path(canonical_root, "canonical_root")
        if overlaps_protected_root(project_path):
            raise RegistryError("canonical_root overlaps a protected system root")
        allowed = tuple(sorted({absolute_path(item, "allowed_root") for item in allowed_roots}))
        if not allowed:
            raise RegistryError("at least one allowed root is required")
        try:
            project_stat = require_directory(project_path, "canonical_root")
            for allowed_root in allowed:
                require_directory(allowed_root, "allowed_root")
        except (OSError, PathPolicyError) as exc:
            raise RegistryError(f"project rejected by path policy: {exc}") from exc
        if not any(is_same_or_under(project_path, root) for root in allowed):
            raise RegistryError("canonical_root is outside every allowed_root")
        if (is_same_or_under(self.output_root, project_path)
                or is_same_or_under(project_path, self.output_root)):
            raise RegistryError("project and output roots may not contain one another")

        profile = ProjectProfile(
            schema_version="project-profile.v1",
            project_id=project_id,
            canonical_root=project_path,
            allowed_roots=allowed,
            root_device=project_stat.st_dev,
            root_inode=project_stat.st_ino,
            path_policy_hash=self._policy_hash(project_path, allowed),
            registry_snapshot_hash="",
            status="REGISTERED",
            version=1,
            source_ids=(),
        )
        profile = replace(profile, registry_snapshot_hash=self._registry_hash(profile, ()))
        self._projects[project_id] = profile
        self._emit_profile(profile)
        # Keep the device observation in the registration path; it is not
        # persisted as an authority field, but the component check is required.
        if not stat.S_ISDIR(project_stat.st_mode):
            raise RegistryError("canonical_root changed during registration")
        return profile

    def register_source(
        self,
        project_id: str,
        source_id: str,
        relative_root: str = "",
        *,
        kind: str = "filesystem",
        trust: str = "reviewed",
        approved: bool = True,
    ) -> SourceSpec:
        validate_id(source_id, "source_id")
        profile = self._projects.get(project_id)
        if profile is None:
            raise RegistryError(f"unknown project: {project_id}")
        key = (project_id, source_id)
        if key in self._sources:
            raise RegistryError(f"source already registered: {source_id}")
        try:
            relative = normalized_relative(relative_root, "relative_root")
            safe_trust(trust)
        except PathPolicyError as exc:
            raise RegistryError(f"source rejected by path policy: {exc}") from exc
        if not approved:
            raise RegistryError("unapproved sources cannot enter the read-only scan")

        try:
            root_fd = open_directory_nofollow(profile.canonical_root)
            source_fd = open_relative_directory(root_fd, relative)
            try:
                source_stat = os.fstat(source_fd)
                project_stat = os.fstat(root_fd)
                if source_stat.st_dev != project_stat.st_dev:
                    raise RegistryError("source crosses a device boundary")
            finally:
                os.close(source_fd)
        except (OSError, PathPolicyError) as exc:
            raise RegistryError(f"source rejected by path policy: {exc}") from exc
        finally:
            if "root_fd" in locals():
                os.close(root_fd)

        source = SourceSpec(
            schema_version="source-spec.v1",
            project_id=project_id,
            source_id=source_id,
            relative_root=relative,
            root_device=source_stat.st_dev,
            root_inode=source_stat.st_ino,
            kind=kind,
            trust=trust,
            approval="explicit",
            status="REGISTERED",
        )
        self._sources[key] = source
        updated = replace(
            profile,
            status="READY",
            version=profile.version + 1,
            source_ids=tuple(sorted((*profile.source_ids, source_id))),
        )
        updated = replace(
            updated,
            registry_snapshot_hash=self._registry_hash(
                updated,
                tuple(sorted(
                    (item for item in self._sources.values() if item.project_id == project_id),
                    key=lambda item: item.source_id,
                )),
            ),
        )
        self._projects[project_id] = updated
        self._emit_profile(updated)
        self._write_once(f"registry/sources/{project_id}/{source_id}.json", source.to_dict())
        return source

    def project(self, project_id: str) -> ProjectProfile:
        try:
            return self._projects[project_id]
        except KeyError as exc:
            raise RegistryError(f"unknown project: {project_id}") from exc

    def source(self, project_id: str, source_id: str) -> SourceSpec:
        try:
            return self._sources[(project_id, source_id)]
        except KeyError as exc:
            raise RegistryError(f"unknown source: {project_id}/{source_id}") from exc

    def snapshot(self) -> dict:
        return {
            "schema_version": "project-registry.v1",
            "projects": [self._projects[key].to_dict() for key in sorted(self._projects)],
            "sources": [self._sources[key].to_dict() for key in sorted(self._sources)],
        }

    def scan(
        self,
        project_id: str,
        source_id: str,
        *,
        max_files: Optional[int] = None,
        max_bytes: Optional[int] = None,
        after_read_hook=None,
        test_only_hook: bool = False,
    ) -> ScanResult:
        if after_read_hook is not None and not test_only_hook:
            raise RegistryError("after_read_hook is reserved for adversarial tests")
        profile = self.project(project_id)
        source = self.source(project_id, source_id)
        scan_id = self._scan_id_factory()
        validate_id(scan_id, "scan_id")
        started_at = self._clock()
        scope_hash = sha256_json(
            {
                "scope_version": "scan-scope.v1",
                "project_id": project_id,
                "source_id": source_id,
                "root_relative": source.relative_root,
                "include_rules": ["regular-files"],
                "exclude_rules": [],
                "file_types": ["regular"],
                "follow_symlinks": False,
                "cross_device": False,
                "max_files": max_files,
                "max_bytes": max_bytes,
            }
        )
        result = ReadOnlyScanner(clock=self._clock).scan(
            profile,
            source,
            scan_id,
            started_at,
            profile.registry_snapshot_hash,
            scope_hash,
            max_files=max_files,
            max_bytes=max_bytes,
            after_read_hook=after_read_hook,
        )
        self._write_once(
            f"manifests/{result.manifest.manifest_hash}.json",
            result.manifest.to_dict(),
        )
        self._write_once(f"events/{result.event.scan_id}.json", result.event.to_dict())
        return result

