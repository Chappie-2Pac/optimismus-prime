"""Immutable W3-S0 records and deterministic serialization helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Dict, Optional, Tuple


def canonical_json_bytes(value: Any) -> bytes:
    """Return the only JSON representation used for content hashes."""

    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True)
class ProjectProfile:
    schema_version: str
    project_id: str
    canonical_root: str
    allowed_roots: Tuple[str, ...]
    root_device: int
    root_inode: int
    path_policy_hash: str
    registry_snapshot_hash: str
    status: str
    version: int
    source_ids: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "canonical_root": self.canonical_root,
            "allowed_roots": list(self.allowed_roots),
            "root_device": self.root_device,
            "root_inode": self.root_inode,
            "path_policy_hash": self.path_policy_hash,
            "registry_snapshot_hash": self.registry_snapshot_hash,
            "status": self.status,
            "version": self.version,
            "source_ids": list(self.source_ids),
        }


@dataclass(frozen=True)
class SourceSpec:
    schema_version: str
    project_id: str
    source_id: str
    relative_root: str
    root_device: int
    root_inode: int
    kind: str
    trust: str
    approval: str
    status: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "source_id": self.source_id,
            "relative_root": self.relative_root,
            "root_device": self.root_device,
            "root_inode": self.root_inode,
            "kind": self.kind,
            "trust": self.trust,
            "approval": self.approval,
            "status": self.status,
        }


@dataclass(frozen=True)
class FileRecord:
    relative_path: str
    size: int
    mtime_ns: int
    mode: int
    device: int
    inode: int
    link_count: int
    sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "mode": self.mode,
            "device": self.device,
            "inode": self.inode,
            "link_count": self.link_count,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class DeniedEntry:
    relative_path: str
    entry_kind: str
    reason_code: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "entry_kind": self.entry_kind,
            "reason_code": self.reason_code,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Coverage:
    requested_scope: str
    directories_seen: int
    entries_seen: int
    files_indexed: int
    bytes_indexed: int
    denied_entries: int
    complete: bool
    unknown_remainder: bool
    absence_claims: str
    reason_codes: Tuple[str, ...]
    eligible_entries: Optional[int] = None
    lower_bound_only: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested_scope": self.requested_scope,
            "directories_seen": self.directories_seen,
            "entries_seen": self.entries_seen,
            "files_indexed": self.files_indexed,
            "bytes_indexed": self.bytes_indexed,
            "denied_entries": self.denied_entries,
            "complete": self.complete,
            "unknown_remainder": self.unknown_remainder,
            "absence_claims": self.absence_claims,
            "reason_codes": list(self.reason_codes),
            "eligible_entries": self.eligible_entries,
            "lower_bound_only": self.lower_bound_only,
        }


@dataclass(frozen=True)
class SourceManifest:
    schema_version: str
    project_id: str
    source_id: str
    relative_root: str
    path_policy_hash: str
    registry_snapshot_hash: str
    scope_hash: str
    status: str
    state: str
    coverage: Coverage
    files: Tuple[FileRecord, ...]
    denied_entries: Tuple[DeniedEntry, ...]
    source_device: Optional[int]
    observed_at: str

    def hash_payload(self) -> Dict[str, Any]:
        """Return time-independent data bound by ``manifest_hash``."""

        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "source_id": self.source_id,
            "relative_root": self.relative_root,
            "path_policy_hash": self.path_policy_hash,
            "registry_snapshot_hash": self.registry_snapshot_hash,
            "scope_hash": self.scope_hash,
            "status": self.status,
            "state": self.state,
            "coverage": self.coverage.to_dict(),
            "files": [item.to_dict() for item in self.files],
            "denied_entries": [item.to_dict() for item in self.denied_entries],
            "source_device": self.source_device,
        }

    @property
    def manifest_hash(self) -> str:
        return sha256_json(self.hash_payload())

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.hash_payload(),
            "observed_at": self.observed_at,
            "manifest_hash": self.manifest_hash,
        }


@dataclass(frozen=True)
class ScanEvent:
    schema_version: str
    scan_id: str
    project_id: str
    source_id: str
    registry_snapshot_hash: str
    scope_hash: str
    sequence_no: int
    kind: str
    previous_event_hash: Optional[str]
    status: str
    started_at: str
    finished_at: str
    manifest_hash: str
    coverage: Coverage
    reason_codes: Tuple[str, ...]
    read_only: bool
    source_writes: int
    network_access: bool
    process_starts: int

    def body(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "source_id": self.source_id,
            "registry_snapshot_hash": self.registry_snapshot_hash,
            "scope_hash": self.scope_hash,
            "sequence_no": self.sequence_no,
            "kind": self.kind,
            "previous_event_hash": self.previous_event_hash,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "manifest_hash": self.manifest_hash,
            "coverage": self.coverage.to_dict(),
            "reason_codes": list(self.reason_codes),
            "read_only": self.read_only,
            "source_writes": self.source_writes,
            "network_access": self.network_access,
            "process_starts": self.process_starts,
        }

    def to_dict(self) -> Dict[str, Any]:
        body = self.body()
        return {**body, "event_hash": sha256_json(body)}


@dataclass(frozen=True)
class ScanResult:
    manifest: SourceManifest
    event: ScanEvent

