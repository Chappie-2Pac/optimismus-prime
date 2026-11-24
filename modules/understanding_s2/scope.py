"""W3-S2 self-describing scan-scope artifacts.

W3-S0 computes a scope hash at scan time and W3-S1 can verify a supplied
scope.  This module makes that previously external value into a durable,
hash-bound artifact without changing either earlier wave.  The artifact is
still deliberately small: the scope remains the exact W3-S0 ``scan-scope``
object and provenance is kept in a separate, explicit envelope.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import json
import os
import re
import stat
from typing import Any, Dict, Mapping, Optional, Tuple

from modules.understanding_s0.model import canonical_json_bytes, sha256_json
from modules.understanding_s0.registry import UnderstandingRegistry
from modules.understanding_s0.path_policy import (
    PathPolicyError,
    absolute_path,
    normalized_relative,
    open_output_root,
    overlaps_protected_root,
    validate_id,
)
from modules.understanding_s1.verifier import Finding, VerificationResult, verify_scope, verify_source


HEX64 = re.compile(r"^[0-9a-f]{64}$")
SCOPE_KEYS = frozenset(
    {
        "scope_version",
        "project_id",
        "source_id",
        "root_relative",
        "include_rules",
        "exclude_rules",
        "file_types",
        "follow_symlinks",
        "cross_device",
        "max_files",
        "max_bytes",
    }
)
PROVENANCE_KEYS = frozenset(
    {
        "project_id",
        "source_id",
        "path_policy_hash",
        "registry_snapshot_hash",
        "source_root_relative",
        "source_root_device",
        "source_root_inode",
    }
)
ARTIFACT_KEYS = frozenset({"schema_version", "scope", "scope_hash", "provenance", "artifact_hash"})
MAX_SCOPE_ARTIFACT_BYTES = 64 * 1024
MAX_JSON_DEPTH = 32
AT_FDCWD = -100
AT_SYMLINK_FOLLOW = 0x400


class ScopeArtifactError(ValueError):
    """The scope artifact is malformed, unsafe, or conflicts with history."""


class ScopeArtifactConflict(ScopeArtifactError):
    """A write-once scope path already contains different bytes."""


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ScopeArtifactError(f"{field} must be non-empty text")
    return value


def _require_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ScopeArtifactError(f"{field} must be lowercase SHA-256")
    return value


def _require_nonnegative_int(value: Any, field: str, *, allow_none: bool = False) -> Optional[int]:
    if allow_none and value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ScopeArtifactError(f"{field} must be a non-negative integer or null")
    return value


def _require_sorted_strings(value: Any, field: str) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise ScopeArtifactError(f"{field} must be a list of strings")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise ScopeArtifactError(f"{field} must be sorted and unique")
    return result


def _exact_keys(value: Any, expected: frozenset[str], field: str) -> None:
    if not isinstance(value, dict):
        raise ScopeArtifactError(f"{field} must be an object")
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise ScopeArtifactError(f"{field} is missing: {', '.join(missing)}")
    if unknown:
        raise ScopeArtifactError(f"{field} contains unknown fields: {', '.join(unknown)}")


@dataclass(frozen=True)
class ScanScope:
    """The canonical W3-S0 scan scope, represented without its hash."""

    project_id: str
    source_id: str
    root_relative: str
    max_files: Optional[int] = None
    max_bytes: Optional[int] = None
    scope_version: str = "scan-scope.v1"
    include_rules: Tuple[str, ...] = ("regular-files",)
    exclude_rules: Tuple[str, ...] = ()
    file_types: Tuple[str, ...] = ("regular",)
    follow_symlinks: bool = False
    cross_device: bool = False

    def __post_init__(self) -> None:
        if self.scope_version != "scan-scope.v1":
            raise ScopeArtifactError("unsupported scan scope schema")
        try:
            validate_id(self.project_id, "project_id")
            validate_id(self.source_id, "source_id")
        except PathPolicyError as exc:
            raise ScopeArtifactError(str(exc)) from exc
        try:
            normalized = normalized_relative(self.root_relative, "root_relative")
        except (PathPolicyError, TypeError) as exc:
            raise ScopeArtifactError(str(exc)) from exc
        if "\\" in self.root_relative:
            raise ScopeArtifactError("root_relative must use POSIX separators")
        if self.root_relative != normalized:
            raise ScopeArtifactError("root_relative must be normalized")
        self._check_policy_list(self.include_rules, "include_rules", ("regular-files",))
        self._check_policy_list(self.exclude_rules, "exclude_rules", ())
        self._check_policy_list(self.file_types, "file_types", ("regular",))
        if self.follow_symlinks is not False or self.cross_device is not False:
            raise ScopeArtifactError("scope must deny symlinks and device crossing")
        _require_nonnegative_int(self.max_files, "max_files", allow_none=True)
        _require_nonnegative_int(self.max_bytes, "max_bytes", allow_none=True)

    @staticmethod
    def _check_policy_list(value: Any, field: str, expected: Tuple[str, ...]) -> None:
        if not isinstance(value, tuple) or value != expected:
            raise ScopeArtifactError(f"{field} does not match the W3-S0 policy")

    @classmethod
    def from_registry(
        cls,
        profile: Mapping[str, Any] | Any,
        source: Mapping[str, Any] | Any,
        *,
        max_files: Optional[int] = None,
        max_bytes: Optional[int] = None,
    ) -> "ScanScope":
        profile_data = profile.to_dict() if hasattr(profile, "to_dict") else dict(profile)
        source_data = source.to_dict() if hasattr(source, "to_dict") else dict(source)
        if source_data.get("project_id") != profile_data.get("project_id"):
            raise ScopeArtifactError("source is not bound to the supplied project")
        return cls(
            project_id=_require_text(profile_data.get("project_id"), "project_id"),
            source_id=_require_text(source_data.get("source_id"), "source_id"),
            root_relative=_require_text(source_data.get("relative_root"), "relative_root")
            if source_data.get("relative_root")
            else "",
            max_files=max_files,
            max_bytes=max_bytes,
        )

    @classmethod
    def from_dict(cls, value: Any) -> "ScanScope":
        _exact_keys(value, SCOPE_KEYS, "scope")
        include_rules = _require_sorted_strings(value["include_rules"], "include_rules")
        exclude_rules = _require_sorted_strings(value["exclude_rules"], "exclude_rules")
        file_types = _require_sorted_strings(value["file_types"], "file_types")
        return cls(
            project_id=_require_text(value["project_id"], "project_id"),
            source_id=_require_text(value["source_id"], "source_id"),
            root_relative=value["root_relative"]
            if isinstance(value["root_relative"], str)
            else _require_text(value["root_relative"], "root_relative"),
            max_files=_require_nonnegative_int(value["max_files"], "max_files", allow_none=True),
            max_bytes=_require_nonnegative_int(value["max_bytes"], "max_bytes", allow_none=True),
            scope_version=_require_text(value["scope_version"], "scope_version"),
            include_rules=include_rules,
            exclude_rules=exclude_rules,
            file_types=file_types,
            follow_symlinks=value["follow_symlinks"],
            cross_device=value["cross_device"],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope_version": self.scope_version,
            "project_id": self.project_id,
            "source_id": self.source_id,
            "root_relative": self.root_relative,
            "include_rules": list(self.include_rules),
            "exclude_rules": list(self.exclude_rules),
            "file_types": list(self.file_types),
            "follow_symlinks": self.follow_symlinks,
            "cross_device": self.cross_device,
            "max_files": self.max_files,
            "max_bytes": self.max_bytes,
        }

    @property
    def scope_hash(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True)
class ScopeProvenance:
    """Registry facts that explain where a scope was admitted from."""

    project_id: str
    source_id: str
    path_policy_hash: str
    registry_snapshot_hash: str
    source_root_relative: str
    source_root_device: int
    source_root_inode: int

    def __post_init__(self) -> None:
        try:
            validate_id(self.project_id, "project_id")
            validate_id(self.source_id, "source_id")
        except PathPolicyError as exc:
            raise ScopeArtifactError(str(exc)) from exc
        _require_hash(self.path_policy_hash, "path_policy_hash")
        _require_hash(self.registry_snapshot_hash, "registry_snapshot_hash")
        try:
            normalized = normalized_relative(self.source_root_relative, "source_root_relative")
        except (PathPolicyError, TypeError) as exc:
            raise ScopeArtifactError(str(exc)) from exc
        if "\\" in self.source_root_relative:
            raise ScopeArtifactError("source_root_relative must use POSIX separators")
        if normalized != self.source_root_relative:
            raise ScopeArtifactError("source_root_relative must be normalized")
        _require_nonnegative_int(self.source_root_device, "source_root_device")
        _require_nonnegative_int(self.source_root_inode, "source_root_inode")

    @classmethod
    def from_registry(cls, profile: Mapping[str, Any] | Any, source: Mapping[str, Any] | Any) -> "ScopeProvenance":
        profile_data = profile.to_dict() if hasattr(profile, "to_dict") else dict(profile)
        source_data = source.to_dict() if hasattr(source, "to_dict") else dict(source)
        if source_data.get("project_id") != profile_data.get("project_id"):
            raise ScopeArtifactError("source is not bound to the supplied project")
        return cls(
            project_id=_require_text(profile_data.get("project_id"), "project_id"),
            source_id=_require_text(source_data.get("source_id"), "source_id"),
            path_policy_hash=_require_hash(profile_data.get("path_policy_hash"), "path_policy_hash"),
            registry_snapshot_hash=_require_hash(
                profile_data.get("registry_snapshot_hash"), "registry_snapshot_hash"
            ),
            source_root_relative=source_data.get("relative_root")
            if isinstance(source_data.get("relative_root"), str)
            else _require_text(source_data.get("relative_root"), "relative_root"),
            source_root_device=_require_nonnegative_int(source_data.get("root_device"), "root_device"),  # type: ignore[arg-type]
            source_root_inode=_require_nonnegative_int(source_data.get("root_inode"), "root_inode"),  # type: ignore[arg-type]
        )

    @classmethod
    def from_dict(cls, value: Any) -> "ScopeProvenance":
        _exact_keys(value, PROVENANCE_KEYS, "provenance")
        return cls(
            project_id=_require_text(value["project_id"], "provenance.project_id"),
            source_id=_require_text(value["source_id"], "provenance.source_id"),
            path_policy_hash=_require_hash(value["path_policy_hash"], "provenance.path_policy_hash"),
            registry_snapshot_hash=_require_hash(
                value["registry_snapshot_hash"], "provenance.registry_snapshot_hash"
            ),
            source_root_relative=value["source_root_relative"],
            source_root_device=_require_nonnegative_int(value["source_root_device"], "source_root_device"),  # type: ignore[arg-type]
            source_root_inode=_require_nonnegative_int(value["source_root_inode"], "source_root_inode"),  # type: ignore[arg-type]
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_id": self.project_id,
            "source_id": self.source_id,
            "path_policy_hash": self.path_policy_hash,
            "registry_snapshot_hash": self.registry_snapshot_hash,
            "source_root_relative": self.source_root_relative,
            "source_root_device": self.source_root_device,
            "source_root_inode": self.source_root_inode,
        }


@dataclass(frozen=True)
class ScopeArtifact:
    """A self-describing scope plus its registry/device provenance."""

    scope: ScanScope
    provenance: ScopeProvenance
    schema_version: str = "scan-scope-artifact.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "scan-scope-artifact.v1":
            raise ScopeArtifactError("unsupported scope artifact schema")
        if (
            self.scope.project_id != self.provenance.project_id
            or self.scope.source_id != self.provenance.source_id
            or self.scope.root_relative != self.provenance.source_root_relative
        ):
            raise ScopeArtifactError("scope and provenance identity differ")

    @classmethod
    def from_registry(
        cls,
        profile: Mapping[str, Any] | Any,
        source: Mapping[str, Any] | Any,
        *,
        max_files: Optional[int] = None,
        max_bytes: Optional[int] = None,
    ) -> "ScopeArtifact":
        scope = ScanScope.from_registry(profile, source, max_files=max_files, max_bytes=max_bytes)
        return cls(scope=scope, provenance=ScopeProvenance.from_registry(profile, source))

    @classmethod
    def from_dict(cls, value: Any) -> "ScopeArtifact":
        _exact_keys(value, ARTIFACT_KEYS, "scope artifact")
        scope = ScanScope.from_dict(value["scope"])
        provenance = ScopeProvenance.from_dict(value["provenance"])
        artifact = cls(scope=scope, provenance=provenance, schema_version=value["schema_version"])
        if value["scope_hash"] != artifact.scope_hash:
            raise ScopeArtifactError("scope_hash does not match canonical scope")
        if value["artifact_hash"] != artifact.artifact_hash:
            raise ScopeArtifactError("artifact_hash does not match canonical artifact body")
        return artifact

    @property
    def scope_hash(self) -> str:
        return self.scope.scope_hash

    def hash_payload(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scope": self.scope.to_dict(),
            "scope_hash": self.scope_hash,
            "provenance": self.provenance.to_dict(),
        }

    @property
    def artifact_hash(self) -> str:
        return sha256_json(self.hash_payload())

    def to_dict(self) -> Dict[str, Any]:
        return {**self.hash_payload(), "artifact_hash": self.artifact_hash}


def _as_dict(value: Mapping[str, Any] | Any) -> Dict[str, Any]:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if not isinstance(value, dict):
        raise ScopeArtifactError("expected an object")
    return value


def _authority_context(authority: Any, project_id: str, source_id: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if not isinstance(authority, UnderstandingRegistry):
        raise ScopeArtifactError("authority must be an UnderstandingRegistry")
    try:
        profile = authority.project(project_id)
        source = authority.source(project_id, source_id)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ScopeArtifactError(f"registry authority could not resolve the scope: {exc}") from exc
    return _as_dict(profile), _as_dict(source)


def verify_scope_artifact(
    artifact: Any,
    profile: Optional[Mapping[str, Any] | Any] = None,
    source: Optional[Mapping[str, Any] | Any] = None,
    *,
    integrity_only: bool = False,
    authority: Any = None,
) -> VerificationResult:
    """Verify structure, hashes, provenance, and optionally registry binding."""

    findings = []
    checked_hash: Optional[str] = None
    try:
        data = _as_dict(artifact)
        parsed = ScopeArtifact.from_dict(data)
        checked_hash = parsed.artifact_hash
    except (ScopeArtifactError, TypeError, ValueError) as exc:
        findings.append(Finding("SCOPE_ARTIFACT_INVALID", str(exc)[:300], "scan-scope-artifact"))
        return VerificationResult(False, "scan-scope-artifact", checked_hash, tuple(findings))

    context_profile: Optional[Dict[str, Any]] = None
    context_source: Optional[Dict[str, Any]] = None
    if authority is not None:
        try:
            context_profile, context_source = _authority_context(
                authority, parsed.scope.project_id, parsed.scope.source_id
            )
        except ScopeArtifactError as exc:
            findings.append(Finding("PROVENANCE_AUTHORITY_INVALID", str(exc)[:300], "scan-scope-artifact"))
        else:
            try:
                if profile is not None and _as_dict(profile) != context_profile:
                    findings.append(
                        Finding(
                            "PROVENANCE_AUTHORITY_MISMATCH",
                            "supplied profile differs from the live registry authority",
                            "scan-scope-artifact",
                        )
                    )
                if source is not None and _as_dict(source) != context_source:
                    findings.append(
                        Finding(
                            "PROVENANCE_AUTHORITY_MISMATCH",
                            "supplied source differs from the live registry authority",
                            "scan-scope-artifact",
                        )
                    )
            except (ScopeArtifactError, TypeError, ValueError) as exc:
                findings.append(Finding("PROVENANCE_CONTEXT_INVALID", str(exc)[:300], "scan-scope-artifact"))
    elif profile is None and source is None:
        if not integrity_only:
            findings.append(
                Finding(
                    "PROVENANCE_CONTEXT_MISSING",
                    "profile and source are required for an authoritative result",
                    "scan-scope-artifact",
                )
            )
    elif (profile is None) != (source is None):
        findings.append(
            Finding(
                "PROVENANCE_CONTEXT_INCOMPLETE",
                "profile and source must be supplied together",
                "scan-scope-artifact",
            )
        )
    elif profile is not None and source is not None:
        context_profile = _as_dict(profile)
        context_source = _as_dict(source)

    if context_profile is not None and context_source is not None:
        try:
            profile_data = context_profile
            source_data = context_source
            expected_policy_hash = sha256_json(
                {
                    "policy_version": "path-policy.v1",
                    "canonical_root": profile_data["canonical_root"],
                    "allowed_roots": profile_data["allowed_roots"],
                    "symlinks": "deny",
                    "special_files": "deny",
                    "device_boundaries": "deny",
                    "source_writes": "deny",
                    "network": "deny",
                    "process_starts": "deny",
                }
            )
            if profile_data.get("path_policy_hash") != expected_policy_hash:
                findings.append(
                    Finding(
                        "POLICY_HASH_MISMATCH",
                        "profile path_policy_hash does not match the canonical policy",
                        "scan-scope-artifact",
                    )
                )
            source_result = verify_source(source_data, profile_data)
            findings.extend(source_result.findings)
            scope_result = verify_scope(parsed.scope.to_dict(), profile_data, source_data)
            findings.extend(scope_result.findings)
            expected = ScopeProvenance.from_registry(profile_data, source_data)
        except (ScopeArtifactError, TypeError, ValueError) as exc:
            findings.append(
                Finding(
                    "PROVENANCE_CONTEXT_INVALID",
                    str(exc)[:300],
                    "scan-scope-artifact",
                )
            )
        else:
            if parsed.provenance != expected:
                findings.append(
                    Finding(
                        "PROVENANCE_MISMATCH",
                        "scope provenance differs from the supplied registry records",
                        "scan-scope-artifact",
                    )
                )
    return VerificationResult(not findings, "scan-scope-artifact", checked_hash, tuple(findings))


def _parse_json_bytes(data: bytes) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    parsed = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {value}")),
    )
    _check_json_depth(parsed)
    return parsed


def _check_json_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ScopeArtifactError("JSON nesting exceeds the depth limit")
    if isinstance(value, dict):
        for item in value.values():
            _check_json_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_json_depth(item, depth + 1)


def _publish_once(directory_fd: int, target: str, data: bytes) -> None:
    """Publish complete bytes from an unnamed inode without following a path."""

    try:
        tmpfile_flag = os.O_TMPFILE
    except AttributeError as exc:
        raise ScopeArtifactError("O_TMPFILE is required for safe publication") from exc
    fd = os.open(".", os.O_WRONLY | tmpfile_flag | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        handle = os.fdopen(fd, "wb", closefd=False)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        # Python exposes linkat's directory FDs but not AT_EMPTY_PATH.  Calling
        # libc here links the already-open inode, so a named temp path cannot
        # be swapped for a symlink between validation and publication.
        libc = ctypes.CDLL(None, use_errno=True)
        linkat = libc.linkat
        linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        linkat.restype = ctypes.c_int
        source_path = f"/proc/self/fd/{fd}".encode("ascii")
        if linkat(AT_FDCWD, source_path, directory_fd, target.encode("utf-8"), AT_SYMLINK_FOLLOW) != 0:
            error = ctypes.get_errno()
            if error != errno.EEXIST:
                raise OSError(error, os.strerror(error))
            st = os.stat(target, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise ScopeArtifactError("existing scope artifact is not a regular file")
            read_fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
            with os.fdopen(read_fd, "rb") as read_handle:
                existing = read_handle.read(MAX_SCOPE_ARTIFACT_BYTES + 1)
            if existing != data:
                raise ScopeArtifactConflict(f"scope artifact conflict: {target}")
        else:
            os.fsync(directory_fd)
    finally:
        if fd is not None:
            os.close(fd)


class ScopeArtifactStore:
    """Materialize scope artifacts below one explicit, no-follow output root."""

    def __init__(self, output_root: os.PathLike[str] | str):
        self.output_root = absolute_path(output_root, "output root")
        if overlaps_protected_root(self.output_root):
            raise ScopeArtifactError("output root overlaps a protected system root")
        try:
            self._output_fd = open_output_root(self.output_root)
        except (OSError, PathPolicyError) as exc:
            raise ScopeArtifactError(f"output root rejected by path policy: {exc}") from exc

    def close(self) -> None:
        output_fd = getattr(self, "_output_fd", None)
        if output_fd is not None:
            self._output_fd = None
            os.close(output_fd)

    def __enter__(self) -> "ScopeArtifactStore":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    @staticmethod
    def relative_path(scope_hash: str) -> str:
        _require_hash(scope_hash, "scope_hash")
        return f"scopes/{scope_hash}.json"

    def write_once(
        self,
        artifact: ScopeArtifact,
        profile: Optional[Mapping[str, Any] | Any] = None,
        source: Optional[Mapping[str, Any] | Any] = None,
        authority: Any = None,
    ) -> str:
        result = verify_scope_artifact(artifact, profile, source, authority=authority)
        if not result.accepted:
            raise ScopeArtifactError("refusing to materialize an invalid scope artifact")
        if self._output_fd is None:
            raise ScopeArtifactError("scope artifact store is closed")
        parts = ("scopes", f"{artifact.scope_hash}.json")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        directory_fd = os.dup(self._output_fd)
        try:
            try:
                os.mkdir(parts[0], 0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            st = os.stat(parts[0], dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise ScopeArtifactError("scope output directory is not a real directory")
            next_fd = os.open(parts[0], directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
            data = canonical_json_bytes(artifact.to_dict()) + b"\n"
            if len(data) > MAX_SCOPE_ARTIFACT_BYTES:
                raise ScopeArtifactError("scope artifact exceeds the size limit")
            target = parts[1]
            _publish_once(directory_fd, target, data)
            return self.relative_path(artifact.scope_hash)
        finally:
            os.close(directory_fd)

    def read(
        self,
        scope_hash: str,
        profile: Optional[Mapping[str, Any] | Any] = None,
        source: Optional[Mapping[str, Any] | Any] = None,
        authority: Any = None,
    ) -> ScopeArtifact:
        if self._output_fd is None:
            raise ScopeArtifactError("scope artifact store is closed")
        directory_fd = os.open(
            "scopes",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=self._output_fd,
        )
        try:
            fd = os.open(
                f"{_require_hash(scope_hash, 'scope_hash')}.json",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                st = os.fstat(fd)
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                    raise ScopeArtifactError("scope artifact is not a regular file")
                if st.st_size > MAX_SCOPE_ARTIFACT_BYTES:
                    raise ScopeArtifactError("scope artifact exceeds the size limit")
                with os.fdopen(fd, "rb") as handle:
                    data = handle.read(MAX_SCOPE_ARTIFACT_BYTES + 1)
                fd = None
            finally:
                if fd is not None:
                    os.close(fd)
        finally:
            os.close(directory_fd)
        try:
            parsed = ScopeArtifact.from_dict(_parse_json_bytes(data))
        except (ScopeArtifactError, UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
            raise ScopeArtifactError(f"scope artifact is invalid: {exc}") from exc
        if data != canonical_json_bytes(parsed.to_dict()) + b"\n":
            raise ScopeArtifactError("scope artifact bytes are not canonical")
        if parsed.scope_hash != scope_hash:
            raise ScopeArtifactError("scope artifact hash does not match its requested path")
        result = verify_scope_artifact(parsed, profile, source, authority=authority)
        if not result.accepted:
            raise ScopeArtifactError("scope artifact failed authoritative verification")
        return parsed
