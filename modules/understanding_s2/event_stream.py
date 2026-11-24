"""W3-S2 append-only ScanEvent stream construction and verification."""

from __future__ import annotations

from collections.abc import Mapping as ABCMapping
from dataclasses import dataclass
import ctypes
import errno
import json
import os
import re
import stat
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple

from modules.understanding_s0.model import canonical_json_bytes, sha256_json
from modules.understanding_s0.path_policy import (
    PathPolicyError,
    absolute_path,
    open_output_root,
    overlaps_protected_root,
    validate_id,
)
from modules.understanding_s1.verifier import (
    Finding,
    VerificationResult,
    verify_event_stream,
)

from .scope import (
    ScopeArtifact,
    ScopeArtifactError,
    verify_scope_artifact,
)


HEX64 = re.compile(r"^[0-9a-f]{64}$")
STREAM_KEYS = frozenset(
    {
        "schema_version",
        "stream_id",
        "project_id",
        "source_id",
        "registry_snapshot_hash",
        "scope_hash",
        "event_count",
        "head_event_hash",
        "state",
        "events",
        "stream_hash",
    }
)
MAX_EVENTS = 4096
MAX_EVENT_BYTES = 1024 * 1024
MAX_STREAM_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 64
AT_FDCWD = -100
AT_SYMLINK_FOLLOW = 0x400
COVERAGE_KEYS = frozenset(
    {
        "requested_scope",
        "directories_seen",
        "entries_seen",
        "files_indexed",
        "bytes_indexed",
        "denied_entries",
        "complete",
        "unknown_remainder",
        "absence_claims",
        "reason_codes",
        "eligible_entries",
        "lower_bound_only",
    }
)


class EventStreamError(ValueError):
    """An event cannot be appended or a stream cannot be sealed safely."""


class EventStreamConflict(EventStreamError):
    """A write-once stream artifact path already contains different bytes."""


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise EventStreamError(f"{field} must be non-empty text")
    return value


def _require_hash(value: Any, field: str, *, allow_none: bool = False) -> Optional[str]:
    if allow_none and value is None:
        return None
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise EventStreamError(f"{field} must be lowercase SHA-256 or null")
    return value


def _exact_keys(value: Any, expected: frozenset[str], field: str) -> None:
    if not isinstance(value, dict):
        raise EventStreamError(f"{field} must be an object")
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise EventStreamError(f"{field} is missing: {', '.join(missing)}")
    if unknown:
        raise EventStreamError(f"{field} contains unknown fields: {', '.join(unknown)}")


def _normalize_json_object(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise EventStreamError(f"{field} must be an object")
    try:
        _check_json_depth(value)
        normalized = json.loads(canonical_json_bytes(value).decode("utf-8"))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise EventStreamError(f"{field} is not canonical JSON: {exc}") from exc
    if not isinstance(normalized, dict):
        raise EventStreamError(f"{field} must be an object")
    if len(canonical_json_bytes(normalized)) > MAX_EVENT_BYTES:
        raise EventStreamError(f"{field} exceeds the size limit")
    return normalized


def _check_json_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise EventStreamError("JSON nesting exceeds the depth limit")
    if isinstance(value, dict):
        for item in value.values():
            _check_json_depth(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _check_json_depth(item, depth + 1)


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, ABCMapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, list):
        return [_plain(item) for item in value]
    return value


def _finding_result(findings: list[Finding], checked_hash: Optional[str] = None) -> VerificationResult:
    return VerificationResult(
        accepted=not findings,
        artifact="scan-event-stream",
        checked_hash=checked_hash,
        findings=tuple(findings),
    )


def _event_contract_findings(
    events: Tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]],
    *,
    project_id: Optional[str] = None,
    source_id: Optional[str] = None,
    registry_snapshot_hash: Optional[str] = None,
    scope_hash: Optional[str] = None,
) -> list[Finding]:
    findings: list[Finding] = []
    seen_event_hashes = set()
    seen_scan_ids = set()
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            continue
        if event.get("schema_version") != "scan-event.v1":
            findings.append(Finding("SCHEMA_VERSION", "event schema is not scan-event.v1", "scan-event-stream"))
        scan_id = event.get("scan_id")
        try:
            validate_id(scan_id, "scan_id")
        except (PathPolicyError, TypeError):
            findings.append(Finding("ID_INVALID", "scan_id is not a stable identifier", "scan-event-stream"))
        scan_key = scan_id if isinstance(scan_id, str) else repr(scan_id)
        if scan_key in seen_scan_ids:
            findings.append(Finding("DUPLICATE_SCAN_ID", "scan_id occurs more than once", "scan-event-stream"))
        seen_scan_ids.add(scan_key)
        event_hash = event.get("event_hash")
        try:
            _require_hash(event_hash, "event_hash")
        except EventStreamError:
            findings.append(Finding("HASH_FORMAT", "event_hash is not lowercase SHA-256", "scan-event-stream"))
        event_key = event_hash if isinstance(event_hash, str) else repr(event_hash)
        if event_key in seen_event_hashes:
            findings.append(Finding("DUPLICATE_EVENT", "event hash occurs more than once", "scan-event-stream"))
        seen_event_hashes.add(event_key)
        previous = event.get("previous_event_hash")
        if index == 1:
            if previous is not None:
                findings.append(Finding("EVENT_CHAIN_MISMATCH", "first event must have no predecessor", "scan-event-stream"))
        else:
            try:
                _require_hash(previous, "previous_event_hash")
            except EventStreamError:
                findings.append(Finding("HASH_FORMAT", "previous_event_hash is not lowercase SHA-256", "scan-event-stream"))
        if project_id is not None and event.get("project_id") != project_id:
            findings.append(Finding("PROJECT_MISMATCH", "event project_id differs from stream", "scan-event-stream"))
        if source_id is not None and event.get("source_id") != source_id:
            findings.append(Finding("SOURCE_MISMATCH", "event source_id differs from stream", "scan-event-stream"))
        if registry_snapshot_hash is not None and event.get("registry_snapshot_hash") != registry_snapshot_hash:
            findings.append(Finding("REGISTRY_BINDING", "event registry snapshot differs from stream", "scan-event-stream"))
        if scope_hash is not None and event.get("scope_hash") != scope_hash:
            findings.append(Finding("SCOPE_MISMATCH", "event scope differs from stream", "scan-event-stream"))
        manifest_hash = event.get("manifest_hash")
        try:
            _require_hash(manifest_hash, "manifest_hash")
        except EventStreamError:
            findings.append(Finding("HASH_FORMAT", "manifest_hash is not lowercase SHA-256", "scan-event-stream"))
        coverage = event.get("coverage")
        if not isinstance(coverage, dict) or set(coverage) != COVERAGE_KEYS:
            findings.append(Finding("COVERAGE_SCHEMA", "event coverage does not have the exact W3-S0 shape", "scan-event-stream"))
        elif (
            not isinstance(coverage.get("requested_scope"), str)
            or any(
                isinstance(coverage.get(field), bool)
                or not isinstance(coverage.get(field), int)
                or coverage.get(field) < 0
                for field in ("directories_seen", "entries_seen", "files_indexed", "bytes_indexed", "denied_entries")
            )
            or not isinstance(coverage.get("complete"), bool)
            or not isinstance(coverage.get("unknown_remainder"), bool)
            or not isinstance(coverage.get("absence_claims"), str)
            or not isinstance(coverage.get("reason_codes"), list)
            or any(not isinstance(item, str) for item in coverage.get("reason_codes", []))
            or (
                coverage.get("eligible_entries") is not None
                and (
                    isinstance(coverage.get("eligible_entries"), bool)
                    or not isinstance(coverage.get("eligible_entries"), int)
                    or coverage.get("eligible_entries") < 0
                )
            )
            or not isinstance(coverage.get("lower_bound_only"), bool)
        ):
            findings.append(Finding("COVERAGE_SCHEMA", "event coverage contains invalid field types", "scan-event-stream"))
    return findings


def _event_hash_findings(events: Tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]]) -> list[Finding]:
    """Recompute every member hash explicitly at the S2 boundary."""

    findings: list[Finding] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        body = {key: value for key, value in event.items() if key != "event_hash"}
        try:
            computed = sha256_json(body)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            findings.append(Finding("EVENT_HASH_INVALID", str(exc)[:300], "scan-event-stream"))
            continue
        if event.get("event_hash") != computed:
            findings.append(Finding("EVENT_HASH_MISMATCH", "event_hash does not match its canonical body", "scan-event-stream"))
    return findings


@dataclass(frozen=True)
class EventStreamArtifact:
    """A sealed, immutable snapshot of an append-only event chain."""

    stream_id: str
    project_id: str
    source_id: str
    registry_snapshot_hash: str
    scope_hash: str
    events: Tuple[Mapping[str, Any], ...]
    schema_version: str = "scan-event-stream.v1"
    state: str = "SEALED"

    def __post_init__(self) -> None:
        if self.schema_version != "scan-event-stream.v1":
            raise EventStreamError("unsupported event stream schema")
        if self.state != "SEALED":
            raise EventStreamError("only sealed streams can be materialized")
        try:
            validate_id(self.stream_id, "stream_id")
            validate_id(self.project_id, "project_id")
            validate_id(self.source_id, "source_id")
        except PathPolicyError as exc:
            raise EventStreamError(str(exc)) from exc
        _require_hash(self.registry_snapshot_hash, "registry_snapshot_hash")
        _require_hash(self.scope_hash, "scope_hash")
        if not isinstance(self.events, tuple) or not self.events:
            raise EventStreamError("event stream must contain at least one event")
        if len(self.events) > MAX_EVENTS:
            raise EventStreamError("event stream exceeds the event-count limit")
        normalized = []
        for event in self.events:
            normalized.append(_freeze(_normalize_json_object(event, "event")))
        object.__setattr__(self, "events", tuple(normalized))

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def head_event_hash(self) -> str:
        event_hash = self.events[-1].get("event_hash")
        if not isinstance(event_hash, str):
            raise EventStreamError("last event has no event_hash")
        return event_hash

    def hash_payload(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "stream_id": self.stream_id,
            "project_id": self.project_id,
            "source_id": self.source_id,
            "registry_snapshot_hash": self.registry_snapshot_hash,
            "scope_hash": self.scope_hash,
            "event_count": self.event_count,
            "head_event_hash": self.head_event_hash,
            "state": self.state,
            "events": [_plain(event) for event in self.events],
        }

    @property
    def stream_hash(self) -> str:
        return sha256_json(self.hash_payload())

    def to_dict(self) -> Dict[str, Any]:
        return {**self.hash_payload(), "stream_hash": self.stream_hash}

    @classmethod
    def from_dict(cls, value: Any) -> "EventStreamArtifact":
        _exact_keys(value, STREAM_KEYS, "event stream")
        events_value = value["events"]
        if not isinstance(events_value, list):
            raise EventStreamError("events must be a list")
        artifact = cls(
            stream_id=_require_text(value["stream_id"], "stream_id"),
            project_id=_require_text(value["project_id"], "project_id"),
            source_id=_require_text(value["source_id"], "source_id"),
            registry_snapshot_hash=_require_hash(value["registry_snapshot_hash"], "registry_snapshot_hash"),  # type: ignore[arg-type]
            scope_hash=_require_hash(value["scope_hash"], "scope_hash"),  # type: ignore[arg-type]
            events=tuple(events_value),
            schema_version=_require_text(value["schema_version"], "schema_version"),
            state=_require_text(value["state"], "state"),
        )
        if isinstance(value["event_count"], bool) or not isinstance(value["event_count"], int):
            raise EventStreamError("event_count must be an integer")
        if value["event_count"] != artifact.event_count:
            raise EventStreamError("event_count does not match events")
        if value["head_event_hash"] != artifact.head_event_hash:
            raise EventStreamError("head_event_hash does not match the final event")
        if value["stream_hash"] != artifact.stream_hash:
            raise EventStreamError("stream_hash does not match canonical stream body")
        return artifact


class EventStreamBuilder:
    """Mutable only by append; sealing makes the resulting artifact immutable."""

    def __init__(
        self,
        stream_id: str,
        scope_artifact: ScopeArtifact | Mapping[str, Any] | Any,
        profile: Optional[Mapping[str, Any] | Any] = None,
        source: Optional[Mapping[str, Any] | Any] = None,
        authority: Any = None,
    ):
        try:
            validate_id(stream_id, "stream_id")
        except PathPolicyError as exc:
            raise EventStreamError(str(exc)) from exc
        if isinstance(scope_artifact, ScopeArtifact):
            parsed_scope = scope_artifact
        else:
            try:
                parsed_scope = ScopeArtifact.from_dict(scope_artifact)
            except (ScopeArtifactError, TypeError, ValueError) as exc:
                raise EventStreamError(f"scope artifact is invalid: {exc}") from exc
        scope_result = verify_scope_artifact(parsed_scope, profile, source, authority=authority)
        if not scope_result.accepted:
            raise EventStreamError("cannot bind a stream without authoritative scope provenance")
        self.stream_id = stream_id
        self.scope_artifact = parsed_scope
        self.profile = profile
        self.source = source
        self.authority = authority
        self._events: list[Dict[str, Any]] = []
        self._sealed = False

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def sealed(self) -> bool:
        return self._sealed

    def append(self, event: Mapping[str, Any]) -> None:
        if self._sealed:
            raise EventStreamError("sealed event stream cannot be appended")
        if len(self._events) >= MAX_EVENTS:
            raise EventStreamError("event stream exceeds the event-count limit")
        normalized = _normalize_json_object(event, "event")
        expected_sequence = len(self._events) + 1
        expected_previous = self._events[-1].get("event_hash") if self._events else None
        if normalized.get("sequence_no") != expected_sequence:
            raise EventStreamError(f"event sequence must be {expected_sequence}")
        if normalized.get("previous_event_hash") != expected_previous:
            raise EventStreamError("event predecessor does not match the current stream head")
        if normalized.get("project_id") != self.scope_artifact.scope.project_id:
            raise EventStreamError("event project_id is not bound to the scope")
        if normalized.get("source_id") != self.scope_artifact.scope.source_id:
            raise EventStreamError("event source_id is not bound to the scope")
        if normalized.get("registry_snapshot_hash") != self.scope_artifact.provenance.registry_snapshot_hash:
            raise EventStreamError("event registry snapshot is not bound to the scope provenance")
        if normalized.get("scope_hash") != self.scope_artifact.scope_hash:
            raise EventStreamError("event scope_hash is not bound to the supplied scope artifact")
        event_hash = normalized.get("event_hash")
        if any(item.get("event_hash") == event_hash for item in self._events):
            raise EventStreamError("duplicate event_hash")
        scan_id = normalized.get("scan_id")
        if any(item.get("scan_id") == scan_id for item in self._events):
            raise EventStreamError("duplicate scan_id")
        candidate = [*self._events, normalized]
        findings = _event_contract_findings(
            candidate,
            project_id=self.scope_artifact.scope.project_id,
            source_id=self.scope_artifact.scope.source_id,
            registry_snapshot_hash=self.scope_artifact.provenance.registry_snapshot_hash,
            scope_hash=self.scope_artifact.scope_hash,
        )
        result = verify_event_stream(candidate)
        findings.extend(result.findings)
        if findings:
            codes = ", ".join(sorted({item.code for item in findings}))
            raise EventStreamError(f"event fails stream verification: {codes}")
        self._events.append(normalized)

    def seal(self) -> EventStreamArtifact:
        if self._sealed:
            raise EventStreamError("event stream was already sealed")
        if not self._events:
            raise EventStreamError("cannot seal an empty event stream")
        artifact = EventStreamArtifact(
            stream_id=self.stream_id,
            project_id=self.scope_artifact.scope.project_id,
            source_id=self.scope_artifact.scope.source_id,
            registry_snapshot_hash=self.scope_artifact.provenance.registry_snapshot_hash,
            scope_hash=self.scope_artifact.scope_hash,
            events=tuple(self._events),
        )
        result = verify_event_stream_artifact(
            artifact, self.scope_artifact, self.profile, self.source, authority=self.authority
        )
        if not result.accepted:
            raise EventStreamError("refusing to seal an invalid event stream")
        self._sealed = True
        return artifact


def verify_event_stream_artifact(
    artifact: Any,
    scope_artifact: Optional[ScopeArtifact | Mapping[str, Any] | Any] = None,
    profile: Optional[Mapping[str, Any] | Any] = None,
    source: Optional[Mapping[str, Any] | Any] = None,
    *,
    authority: Any = None,
) -> VerificationResult:
    """Verify a sealed stream and require explicit scope evidence."""

    findings: list[Finding] = []
    checked_hash: Optional[str] = None
    try:
        parsed = artifact if isinstance(artifact, EventStreamArtifact) else EventStreamArtifact.from_dict(artifact)
        checked_hash = parsed.stream_hash
    except (EventStreamError, TypeError, ValueError) as exc:
        findings.append(Finding("EVENT_STREAM_ARTIFACT_INVALID", str(exc)[:300], "scan-event-stream"))
        return _finding_result(findings, checked_hash)

    plain_events = tuple(_plain(event) for event in parsed.events)
    findings.extend(_event_hash_findings(plain_events))
    stream_result = verify_event_stream(list(plain_events))
    findings.extend(stream_result.findings)
    findings.extend(
        _event_contract_findings(
            plain_events,
            project_id=parsed.project_id,
            source_id=parsed.source_id,
            registry_snapshot_hash=parsed.registry_snapshot_hash,
            scope_hash=parsed.scope_hash,
        )
    )

    if scope_artifact is None:
        findings.append(
            Finding(
                "SCOPE_CONTEXT_MISSING",
                "a stream hash alone is not sufficient; explicit scope evidence is required",
                "scan-event-stream",
            )
        )
    else:
        try:
            parsed_scope = scope_artifact if isinstance(scope_artifact, ScopeArtifact) else ScopeArtifact.from_dict(scope_artifact)
        except (ScopeArtifactError, TypeError, ValueError) as exc:
            findings.append(Finding("SCOPE_ARTIFACT_INVALID", str(exc)[:300], "scan-event-stream"))
        else:
            scope_result = verify_scope_artifact(parsed_scope, profile, source, authority=authority)
            findings.extend(scope_result.findings)
            if parsed.project_id != parsed_scope.scope.project_id:
                findings.append(Finding("PROJECT_MISMATCH", "stream project differs from scope", "scan-event-stream"))
            if parsed.source_id != parsed_scope.scope.source_id:
                findings.append(Finding("SOURCE_MISMATCH", "stream source differs from scope", "scan-event-stream"))
            if parsed.scope_hash != parsed_scope.scope_hash:
                findings.append(Finding("SCOPE_MISMATCH", "stream scope_hash differs from scope artifact", "scan-event-stream"))
            if parsed.registry_snapshot_hash != parsed_scope.provenance.registry_snapshot_hash:
                findings.append(Finding("REGISTRY_BINDING", "stream registry snapshot differs from scope provenance", "scan-event-stream"))
    return _finding_result(findings, checked_hash)


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


def _publish_once(directory_fd: int, target: str, data: bytes) -> None:
    """Publish complete bytes from an unnamed inode without following a path."""

    try:
        tmpfile_flag = os.O_TMPFILE
    except AttributeError as exc:
        raise EventStreamError("O_TMPFILE is required for safe publication") from exc
    fd = os.open(".", os.O_WRONLY | tmpfile_flag | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        handle = os.fdopen(fd, "wb", closefd=False)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
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
                raise EventStreamError("existing stream artifact is not a regular file")
            read_fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
            with os.fdopen(read_fd, "rb") as read_handle:
                existing = read_handle.read(MAX_STREAM_ARTIFACT_BYTES + 1)
            if existing != data:
                raise EventStreamConflict(f"event stream artifact conflict: {target}")
        else:
            os.fsync(directory_fd)
    finally:
        os.close(fd)


class EventStreamStore:
    """Write sealed stream snapshots once below an explicit output root."""

    def __init__(self, output_root: os.PathLike[str] | str):
        self.output_root = absolute_path(output_root, "output root")
        if overlaps_protected_root(self.output_root):
            raise EventStreamError("output root overlaps a protected system root")
        try:
            self._output_fd = open_output_root(self.output_root)
        except (OSError, PathPolicyError) as exc:
            raise EventStreamError(f"output root rejected by path policy: {exc}") from exc

    def close(self) -> None:
        output_fd = getattr(self, "_output_fd", None)
        if output_fd is not None:
            self._output_fd = None
            os.close(output_fd)

    def __enter__(self) -> "EventStreamStore":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    @staticmethod
    def relative_path(stream_id: str, stream_hash: str) -> str:
        try:
            validate_id(stream_id, "stream_id")
        except PathPolicyError as exc:
            raise EventStreamError(str(exc)) from exc
        _require_hash(stream_hash, "stream_hash")
        return f"streams/{stream_id}/{stream_hash}.json"

    def write_once(
        self,
        artifact: EventStreamArtifact,
        scope_artifact: ScopeArtifact | Mapping[str, Any] | Any,
        profile: Optional[Mapping[str, Any] | Any] = None,
        source: Optional[Mapping[str, Any] | Any] = None,
        authority: Any = None,
    ) -> str:
        result = verify_event_stream_artifact(
            artifact, scope_artifact, profile, source, authority=authority
        )
        if not result.accepted:
            raise EventStreamError("refusing to materialize an invalid event stream")
        if self._output_fd is None:
            raise EventStreamError("event stream store is closed")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        directory_fd = os.dup(self._output_fd)
        parts = ("streams", artifact.stream_id)
        try:
            for part in parts:
                try:
                    os.mkdir(part, 0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                st = os.stat(part, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                    raise EventStreamError(f"stream output component is not a directory: {part}")
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            target = f"{artifact.stream_hash}.json"
            data = canonical_json_bytes(artifact.to_dict()) + b"\n"
            if len(data) > MAX_STREAM_ARTIFACT_BYTES:
                raise EventStreamError("event stream artifact exceeds the size limit")
            _publish_once(directory_fd, target, data)
            return self.relative_path(artifact.stream_id, artifact.stream_hash)
        finally:
            os.close(directory_fd)

    def read(
        self,
        stream_id: str,
        stream_hash: str,
        scope_artifact: ScopeArtifact | Mapping[str, Any] | Any,
        profile: Optional[Mapping[str, Any] | Any] = None,
        source: Optional[Mapping[str, Any] | Any] = None,
        authority: Any = None,
    ) -> EventStreamArtifact:
        if self._output_fd is None:
            raise EventStreamError("event stream store is closed")
        try:
            validate_id(stream_id, "stream_id")
        except PathPolicyError as exc:
            raise EventStreamError(str(exc)) from exc
        _require_hash(stream_hash, "stream_hash")
        streams_fd = os.open(
            "streams",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=self._output_fd,
        )
        stream_fd = None
        fd = None
        try:
            stream_fd = os.open(stream_id, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=streams_fd)
            fd = os.open(f"{stream_hash}.json", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=stream_fd)
            st = os.fstat(fd)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise EventStreamError("event stream artifact is not a regular file")
            if st.st_size > MAX_STREAM_ARTIFACT_BYTES:
                raise EventStreamError("event stream artifact exceeds the size limit")
            with os.fdopen(fd, "rb") as handle:
                data = handle.read(MAX_STREAM_ARTIFACT_BYTES + 1)
            fd = None
        finally:
            if fd is not None:
                os.close(fd)
            if stream_fd is not None:
                os.close(stream_fd)
            os.close(streams_fd)
        try:
            parsed = EventStreamArtifact.from_dict(_parse_json_bytes(data))
        except (EventStreamError, UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
            raise EventStreamError(f"event stream artifact is invalid: {exc}") from exc
        if data != canonical_json_bytes(parsed.to_dict()) + b"\n":
            raise EventStreamError("event stream bytes are not canonical")
        if parsed.stream_id != stream_id or parsed.stream_hash != stream_hash:
            raise EventStreamError("event stream artifact does not match its requested path")
        result = verify_event_stream_artifact(
            parsed, scope_artifact, profile, source, authority=authority
        )
        if not result.accepted:
            raise EventStreamError("event stream artifact failed authoritative verification")
        return parsed
