"""W5-S5/S6 read-only capture of real Optimismus Prime filesystem evidence.

W5-S4 binds an already shaped ``prime-resume-state-v1`` mapping.  This module
does not pretend that mapping is a filesystem truth source.  It first captures
the canonical Prime ledgers as ``prime-filesystem-evidence-v1``.  Only a
separate, explicit builder may project a complete eligible capture into the
S4 mapping.

The capture is deliberately conservative: canonical run ledgers are required,
optional sidecars are reported as missing rather than invented, every regular
file is read twice through directory file descriptors with ``O_NOFOLLOW``, and
the complete source set is read again before finalization.  The opt-in S6
manifest path adds a consistency witness but never grants trust.  It never
writes, starts a process, uses a transport, or grants resume/reconcile
authority.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from modules.w4_small_loop_s0 import canonical_hash


PRIME_FILESYSTEM_EVIDENCE_SCHEMA = "prime-filesystem-evidence-v1"
PRIME_EVIDENCE_SCHEMA = PRIME_FILESYSTEM_EVIDENCE_SCHEMA
PRIME_FILESYSTEM_EVIDENCE_V2_SCHEMA = "prime-filesystem-evidence-v2"
PRIME_EVIDENCE_V2_SCHEMA = PRIME_FILESYSTEM_EVIDENCE_V2_SCHEMA
PRIME_STATE_SCHEMA = "prime-resume-state-v1"
PRIME_WRITER_MANIFEST_SCHEMA = "prime-writer-manifest-v1"
WRITER_GENERATION_SCHEMA = PRIME_WRITER_MANIFEST_SCHEMA
WRITER_MANIFEST_RELATIVE_PATH = ("writer", "snapshot-manifest.json")
WRITER_GENERATION_RELATIVE_PATH = WRITER_MANIFEST_RELATIVE_PATH
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TEXT = 512
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

RUN_ROOT_PREFIXES = (
    ("runtime", "runs"),
    ("runtime", "local-ai-support", "runs"),
    ("work", "prime-local", "runs"),
    ("work", "prime", "runs"),
)
PROJECT_FILES = {
    "queue": ("Plan", "local-ai", "QUEUE.json"),
    "policy": ("mcp", "prime_adapter_manifest.json"),
}
PACKET_ROOT = ("runtime", "operator", "resume-packet")
RUN_REQUIRED_FILES = {
    "session_state": ("session_state.json",),
    "tasks": ("tasks.json",),
    "events": ("events.jsonl",),
    "artifacts": ("artifacts.jsonl",),
}
WRITER_GENERATION_REQUIRED_FILES = tuple(RUN_REQUIRED_FILES)
RUN_OPTIONAL_FILES = {
    "writer_lease": ("writer", "active.d", "owner.json"),
}
EXECUTION_FLAGS = {"resume": False, "reconcile": False, "mutation": False, "network": False}

EVIDENCE_CODES = frozenset(
    {
        "PRIME_EVIDENCE_VERIFIED",
        "PRIME_EVIDENCE_ROOT_INVALID",
        "PRIME_EVIDENCE_ROOT_SYMLINK",
        "PRIME_EVIDENCE_PATH_ESCAPE",
        "PRIME_EVIDENCE_PATH_SYMLINK",
        "PRIME_EVIDENCE_PATH_MISMATCH",
        "PRIME_EVIDENCE_FILE_MISSING",
        "PRIME_EVIDENCE_FILE_UNREADABLE",
        "PRIME_EVIDENCE_FILE_TOO_LARGE",
        "PRIME_EVIDENCE_JSON_INVALID",
        "PRIME_EVIDENCE_JSON_SCHEMA",
        "PRIME_EVIDENCE_JSON_DUPLICATE_KEY",
        "PRIME_EVIDENCE_ENCODING_INVALID",
        "PRIME_EVIDENCE_RUN_ID_MISMATCH",
        "PRIME_EVIDENCE_ACTIVE_TASK_MISMATCH",
        "PRIME_EVIDENCE_ACTIVE_TASK_AMBIGUOUS",
        "PRIME_EVIDENCE_TOCTOU_DRIFT",
        "PRIME_EVIDENCE_SNAPSHOT_UNSTABLE",
        "PRIME_EVIDENCE_RESUME_PACKET_DRIFT",
        "PRIME_EVIDENCE_WRITER_LEASE_INVALID",
        "PRIME_EVIDENCE_POLICY_INVALID",
        "PRIME_EVIDENCE_WRITER_GENERATION_NOT_OBSERVED",
        "PRIME_EVIDENCE_WRITER_GENERATION_INVALID",
        "PRIME_EVIDENCE_WRITER_GENERATION_MISMATCH",
        "PRIME_EVIDENCE_WRITER_MANIFEST_DRIFT",
        "PRIME_EVIDENCE_WRITER_ATTESTATION_UNTRUSTED",
        "PRIME_EVIDENCE_RUN_BINDING_MISMATCH",
        "PRIME_EVIDENCE_BINDING_INELIGIBLE",
    }
)


class PrimeEvidenceError(ValueError):
    """A Prime evidence operation failed closed with a stable reason code."""

    def __init__(self, code: str, message: str, *, relative_path: str | None = None) -> None:
        if code not in EVIDENCE_CODES:
            raise ValueError(f"unknown Prime evidence code: {code}")
        self.code = code
        self.relative_path = relative_path
        suffix = f" [{relative_path}]" if relative_path else ""
        super().__init__(f"{code}{suffix}: {message}")


class _DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True)
class _FileSnapshot:
    relative_path: str
    data: bytes
    sha256: str
    fingerprint: tuple[int, int, int, int, int, int]
    directory_fingerprints: tuple[tuple[str, tuple[int, int, int, int, int, int]], ...]

    @property
    def size(self) -> int:
        return len(self.data)

    def metadata(self) -> dict[str, Any]:
        dev, ino, mode, size, mtime_ns, ctime_ns = self.fingerprint
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size": size,
            "dev": dev,
            "ino": ino,
            "mode": mode,
            "mtime_ns": mtime_ns,
            "ctime_ns": ctime_ns,
        }


def _fail(code: str, message: str, relative_path: str | None = None) -> None:
    raise PrimeEvidenceError(code, message, relative_path=relative_path)


def _stat_fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _root(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        _fail("PRIME_EVIDENCE_ROOT_INVALID", "Prime root must be absolute")
    try:
        raw = path.lstat()
    except OSError as exc:
        _fail("PRIME_EVIDENCE_ROOT_INVALID", str(exc))
    if stat.S_ISLNK(raw.st_mode):
        _fail("PRIME_EVIDENCE_ROOT_SYMLINK", "Prime root itself may not be a symlink")
    if not stat.S_ISDIR(raw.st_mode):
        _fail("PRIME_EVIDENCE_ROOT_INVALID", "Prime root is not a directory")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        _fail("PRIME_EVIDENCE_ROOT_INVALID", str(exc))
    if not resolved.is_dir():
        _fail("PRIME_EVIDENCE_ROOT_INVALID", "resolved Prime root is not a directory")
    return resolved


def _parts(value: str | Path, label: str) -> tuple[str, ...]:
    path = value if isinstance(value, Path) else Path(value) if isinstance(value, str) else None
    if path is None or "\x00" in str(path) or path.is_absolute() or not path.parts:
        _fail("PRIME_EVIDENCE_PATH_ESCAPE", f"{label} must be a relative path")
    result = tuple(path.parts)
    if any(part in {"", ".", ".."} for part in result):
        _fail("PRIME_EVIDENCE_PATH_ESCAPE", f"{label} contains traversal")
    if any("/" in part or "\\" in part for part in result):
        _fail("PRIME_EVIDENCE_PATH_ESCAPE", f"{label} contains an invalid component")
    return result


def _relative(parts: tuple[str, ...]) -> str:
    return "/".join(parts)


def _run_parts(value: str | Path) -> tuple[str, ...]:
    parts = _parts(value, "run_relative_path")
    if not any(parts[: len(prefix)] == prefix for prefix in RUN_ROOT_PREFIXES):
        _fail("PRIME_EVIDENCE_PATH_MISMATCH", "run path is not an allowlisted Prime run root")
    if RUN_ID_RE.fullmatch(parts[-1]) is None:
        _fail("PRIME_EVIDENCE_PATH_MISMATCH", "run directory name is not a Prime run id")
    return parts


def _os_error(exc: OSError, label: str, relative_path: str | None = None) -> None:
    if exc.errno == errno.ELOOP:
        _fail("PRIME_EVIDENCE_PATH_SYMLINK", str(exc), relative_path)
    if exc.errno == errno.ENOENT:
        _fail("PRIME_EVIDENCE_FILE_MISSING", str(exc), relative_path)
    if exc.errno in {errno.EACCES, errno.EPERM, errno.EISDIR, errno.ENXIO}:
        _fail("PRIME_EVIDENCE_FILE_UNREADABLE", str(exc), relative_path)
    _fail("PRIME_EVIDENCE_FILE_UNREADABLE", f"{label}: {exc}", relative_path)


def _dir_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        _fail("PRIME_EVIDENCE_ROOT_INVALID", "platform lacks no-follow directory support")
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_DIRECTORY | os.O_NOFOLLOW


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        _fail("PRIME_EVIDENCE_ROOT_INVALID", "platform lacks no-follow file support")
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | os.O_NOFOLLOW


def _open_directory_chain(
    root: Path,
    parts: tuple[str, ...],
    label: str,
) -> tuple[int, tuple[tuple[str, tuple[int, int, int, int, int, int]], ...]]:
    current: int | None = None
    opened: list[int] = []
    try:
        current = os.open(str(root), _dir_flags())
        opened.append(current)
        directories: list[tuple[str, tuple[int, int, int, int, int, int]]] = [("", _stat_fingerprint(os.fstat(current)))]
        for index, part in enumerate(parts):
            try:
                next_fd = os.open(part, _dir_flags(), dir_fd=current)
            except OSError as exc:
                _os_error(exc, label, _relative(parts[: index + 1]))
            opened.append(next_fd)
            os.close(current)
            opened.remove(current)
            current = next_fd
            directories.append((_relative(parts[: index + 1]), _stat_fingerprint(os.fstat(current))))
        return current, tuple(directories)
    except PrimeEvidenceError:
        raise
    except OSError as exc:
        _os_error(exc, label, _relative(parts))
    finally:
        for fd in list(opened):
            if fd != current:
                try:
                    os.close(fd)
                except OSError:
                    pass
    raise AssertionError("unreachable")


def _read_fd(fd: int, relative_path: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(fd, 1024 * 1024)
        except OSError as exc:
            _os_error(exc, "file read failed", relative_path)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_FILE_BYTES:
            _fail("PRIME_EVIDENCE_FILE_TOO_LARGE", "file exceeds evidence limit", relative_path)
        chunks.append(chunk)
    return b"".join(chunks)


def _read_pass(
    root: Path,
    parts: tuple[str, ...],
) -> tuple[bytes, tuple[int, int, int, int, int, int], tuple[tuple[str, tuple[int, int, int, int, int, int]], ...]]:
    relative_path = _relative(parts)
    if not parts:
        _fail("PRIME_EVIDENCE_PATH_ESCAPE", "empty file path", relative_path)
    parent_fd, directories = _open_directory_chain(root, parts[:-1], "file path")
    file_fd: int | None = None
    try:
        leaf = parts[-1]
        try:
            before_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            _os_error(exc, "file metadata read failed", relative_path)
        if stat.S_ISLNK(before_path.st_mode):
            _fail("PRIME_EVIDENCE_PATH_SYMLINK", "file may not be a symlink", relative_path)
        if not stat.S_ISREG(before_path.st_mode):
            _fail("PRIME_EVIDENCE_FILE_UNREADABLE", "file is not regular", relative_path)
        if before_path.st_size > MAX_FILE_BYTES:
            _fail("PRIME_EVIDENCE_FILE_TOO_LARGE", "file exceeds evidence limit", relative_path)
        try:
            file_fd = os.open(leaf, _file_flags(), dir_fd=parent_fd)
        except OSError as exc:
            _os_error(exc, "file open failed", relative_path)
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode):
            _fail("PRIME_EVIDENCE_FILE_UNREADABLE", "opened object is not regular", relative_path)
        first = _stat_fingerprint(opened)
        data = _read_fd(file_fd, relative_path)
        after = _stat_fingerprint(os.fstat(file_fd))
        if first != after:
            _fail("PRIME_EVIDENCE_TOCTOU_DRIFT", "file changed while open", relative_path)
        return data, after, directories
    except PrimeEvidenceError:
        raise
    except OSError as exc:
        _os_error(exc, "file read failed", relative_path)
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            pass
    raise AssertionError("unreachable")


def _invoke_hook(hook: Callable[[str, str | None], None] | None, stage: str, relative_path: str | None) -> None:
    if hook is not None:
        hook(stage, relative_path)


def _read_file(
    root: Path,
    parts: tuple[str, ...],
    *,
    hook: Callable[[str, str | None], None] | None,
    invoke_hook: bool = True,
) -> _FileSnapshot:
    relative_path = _relative(parts)
    first_data, first_fingerprint, first_directories = _read_pass(root, parts)
    if invoke_hook:
        _invoke_hook(hook, "after_read", relative_path)
    try:
        second_data, second_fingerprint, second_directories = _read_pass(root, parts)
    except PrimeEvidenceError as exc:
        if invoke_hook:
            _fail("PRIME_EVIDENCE_TOCTOU_DRIFT", str(exc), relative_path)
        raise
    if first_data != second_data or first_fingerprint != second_fingerprint or first_directories != second_directories:
        _fail("PRIME_EVIDENCE_TOCTOU_DRIFT", "two reads of one file differ", relative_path)
    return _FileSnapshot(
        relative_path=relative_path,
        data=first_data,
        sha256=hashlib.sha256(first_data).hexdigest(),
        fingerprint=first_fingerprint,
        directory_fingerprints=first_directories,
    )


def _read_optional(
    root: Path,
    parts: tuple[str, ...],
    *,
    hook: Callable[[str, str | None], None] | None,
    invoke_hook: bool = True,
) -> _FileSnapshot | None:
    try:
        return _read_file(root, parts, hook=hook, invoke_hook=invoke_hook)
    except PrimeEvidenceError as exc:
        if exc.code == "PRIME_EVIDENCE_FILE_MISSING":
            return None
        raise


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _json_value(data: bytes, relative_path: str, label: str) -> Any:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail("PRIME_EVIDENCE_ENCODING_INVALID", str(exc), relative_path)
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except _DuplicateJsonKey as exc:
        _fail("PRIME_EVIDENCE_JSON_DUPLICATE_KEY", str(exc), relative_path)
    except (ValueError, json.JSONDecodeError) as exc:
        _fail("PRIME_EVIDENCE_JSON_INVALID", str(exc), relative_path)
    raise AssertionError(f"unreachable JSON parse: {label}")


def _json_object(snapshot: _FileSnapshot, label: str) -> dict[str, Any]:
    value = _json_value(snapshot.data, snapshot.relative_path, label)
    if not isinstance(value, dict):
        _fail("PRIME_EVIDENCE_JSON_SCHEMA", f"{label} must be an object", snapshot.relative_path)
    return value


def _jsonl(snapshot: _FileSnapshot, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, raw in enumerate(snapshot.data.splitlines(), start=1):
        if not raw.strip():
            continue
        value = _json_value(raw, snapshot.relative_path, f"{label} line {line_no}")
        if not isinstance(value, dict):
            _fail("PRIME_EVIDENCE_JSON_SCHEMA", f"{label} line {line_no} must be an object", snapshot.relative_path)
        rows.append(value)
    return rows


def _text(value: Any, label: str, relative_path: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > MAX_TEXT or any(ord(char) < 32 for char in value):
        _fail("PRIME_EVIDENCE_JSON_SCHEMA", f"{label} must be bounded text", relative_path)
    if not empty and not value:
        _fail("PRIME_EVIDENCE_JSON_SCHEMA", f"{label} must not be empty", relative_path)
    return value


def _int(value: Any, label: str, relative_path: str) -> int:
    if type(value) is not int or value < 0:
        _fail("PRIME_EVIDENCE_JSON_SCHEMA", f"{label} must be a non-negative integer", relative_path)
    return value


def _path_parts(value: str | Path, label: str) -> tuple[str, ...]:
    return _parts(value, label)


def _validate_run_id(session: Mapping[str, Any], run_id: str, relative_path: str) -> None:
    if session.get("run_id") != run_id:
        _fail("PRIME_EVIDENCE_RUN_ID_MISMATCH", "session_state.run_id differs from run path", relative_path)


def _parse_session(snapshot: _FileSnapshot, run_id: str) -> dict[str, Any]:
    value = _json_object(snapshot, "session_state")
    _validate_run_id(value, run_id, snapshot.relative_path)
    required = ("status", "resume_gate", "resume_gate_reason", "stop_reason", "hold_reason", "active_task_id")
    for key in required:
        if key not in value:
            _fail("PRIME_EVIDENCE_JSON_SCHEMA", f"session_state.{key} is missing", snapshot.relative_path)
    status = _text(value["status"], "session_state.status", snapshot.relative_path)
    gate = _text(value["resume_gate"], "session_state.resume_gate", snapshot.relative_path)
    if gate not in {"open", "hold", "continue"}:
        _fail("PRIME_EVIDENCE_JSON_SCHEMA", "unsupported session resume gate", snapshot.relative_path)
    projection = {
        "run_id": run_id,
        "project": _text(value.get("project", ""), "session_state.project", snapshot.relative_path, empty=True),
        "role": _text(value.get("role", ""), "session_state.role", snapshot.relative_path, empty=True),
        "status": status,
        "resume_gate": gate,
        "resume_gate_reason": _text(value["resume_gate_reason"], "session_state.resume_gate_reason", snapshot.relative_path, empty=True),
        "stop_reason": _text(value["stop_reason"], "session_state.stop_reason", snapshot.relative_path, empty=True),
        "hold_reason": _text(value["hold_reason"], "session_state.hold_reason", snapshot.relative_path, empty=True),
        "active_task_id": _text(value["active_task_id"], "session_state.active_task_id", snapshot.relative_path, empty=True),
        "latest_task_id": _int(value.get("latest_task_id", 0), "session_state.latest_task_id", snapshot.relative_path),
        "latest_artifact_id": _int(value.get("latest_artifact_id", 0), "session_state.latest_artifact_id", snapshot.relative_path),
        "latest_event_id": _int(value.get("latest_event_id", 0), "session_state.latest_event_id", snapshot.relative_path),
        "updated_at": _text(value.get("updated_at", ""), "session_state.updated_at", snapshot.relative_path, empty=True),
    }
    return projection


def _parse_tasks(snapshot: _FileSnapshot) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    value = _json_object(snapshot, "tasks")
    raw_tasks = value.get("tasks")
    if not isinstance(raw_tasks, list):
        _fail("PRIME_EVIDENCE_JSON_SCHEMA", "tasks.tasks must be a list", snapshot.relative_path)
    tasks: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_tasks):
        if not isinstance(raw, Mapping):
            _fail("PRIME_EVIDENCE_JSON_SCHEMA", f"tasks[{index}] must be an object", snapshot.relative_path)
        task_id = _text(raw.get("task_id"), f"tasks[{index}].task_id", snapshot.relative_path)
        if SEGMENT_RE.fullmatch(task_id) is None:
            _fail("PRIME_EVIDENCE_JSON_SCHEMA", f"tasks[{index}].task_id is not safe", snapshot.relative_path)
        if task_id in by_id:
            _fail("PRIME_EVIDENCE_ACTIVE_TASK_AMBIGUOUS", "duplicate task id", snapshot.relative_path)
        status = _text(raw.get("status"), f"tasks[{index}].status", snapshot.relative_path)
        item = {"task_id": task_id, "status": status}
        by_id[task_id] = item
        tasks.append(item)
    return tasks, by_id


def _parse_ledger(snapshot: _FileSnapshot, *, kind: str, id_key: str, run_id: str) -> list[dict[str, Any]]:
    rows = _jsonl(snapshot, kind)
    prefix = "event-" if kind == "events" else "artifact-"
    for index, row in enumerate(rows, start=1):
        expected_id = f"{prefix}{index:03d}"
        if row.get(id_key) != expected_id:
            _fail("PRIME_EVIDENCE_JSON_SCHEMA", f"{kind} high-watermark sequence drift at {expected_id}", snapshot.relative_path)
        row_run_id = row.get("run_id")
        if row_run_id is not None and row_run_id != run_id:
            _fail("PRIME_EVIDENCE_RUN_ID_MISMATCH", f"{kind} row belongs to another run", snapshot.relative_path)
    return rows


def _artifact_paths_inside_run(rows: list[dict[str, Any]], root: Path, run_parts: tuple[str, ...]) -> bool:
    run_dir = root.joinpath(*run_parts)
    valid = True
    for row in rows:
        raw_path = row.get("path")
        if raw_path is None:
            continue
        if not isinstance(raw_path, str) or not raw_path:
            valid = False
            continue
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = run_dir / candidate
        try:
            candidate.resolve(strict=False).relative_to(run_dir.resolve(strict=True))
        except (OSError, ValueError):
            valid = False
    return valid


def _safe_optional_json(snapshot: _FileSnapshot | None, label: str) -> dict[str, Any] | None:
    if snapshot is None:
        return None
    return _json_object(snapshot, label)


def _policy_valid(value: Mapping[str, Any]) -> bool:
    return value.get("schema_version") == "prime-adapter-v1" and value.get("adapter_id") == "optimismus-prime" and value.get("effects") == {
        "read_only": True,
        "local_write": False,
        "external_action": False,
        "network": False,
    }


def _lease_claim(value: Mapping[str, Any], expected_run_dir: str) -> dict[str, Any] | None:
    if value.get("schema_version") != 1:
        return None
    token = value.get("token")
    pid = value.get("pid")
    if not isinstance(token, str) or len(token) < 16 or type(pid) is not int or pid < 1:
        return None
    for key in ("starttime", "boot_id", "run_dir", "role"):
        if not isinstance(value.get(key), str) or not value[key]:
            return None
    expires = value.get("expires_at_epoch")
    if isinstance(expires, bool) or not isinstance(expires, (int, float)) or expires <= 0 or value["run_dir"] != expected_run_dir:
        return None
    return {
        "schema_version": 1,
        "pid": pid,
        "starttime": value["starttime"],
        "boot_id": value["boot_id"],
        "run_dir": expected_run_dir,
        "role": value["role"],
        "expires_at_epoch": expires,
    }


def _discover_packet(root: Path) -> tuple[str, ...] | None:
    try:
        fd, _directories = _open_directory_chain(root, PACKET_ROOT, "resume packet root")
    except PrimeEvidenceError as exc:
        if exc.code == "PRIME_EVIDENCE_FILE_MISSING":
            return None
        raise
    try:
        try:
            names = sorted(os.listdir(fd))
        except OSError as exc:
            _os_error(exc, "resume packet directory listing", _relative(PACKET_ROOT))
    finally:
        os.close(fd)
    candidates: list[str] = []
    for name in names:
        if SEGMENT_RE.fullmatch(name) is None:
            continue
        try:
            metadata_fd, _candidate_dirs = _open_directory_chain(root, PACKET_ROOT + (name,), "resume packet directory")
        except PrimeEvidenceError as exc:
            if exc.code == "PRIME_EVIDENCE_PATH_SYMLINK":
                raise
            continue
        os.close(metadata_fd)
        candidates.append(name)
    return PACKET_ROOT + (max(candidates), "resume_packet.json") if candidates else None


def _packet_valid(
    value: Mapping[str, Any],
    *,
    root: Path,
    run_parts: tuple[str, ...],
    session_sha256: str,
    tasks_sha256: str,
    session: Mapping[str, Any],
) -> bool:
    if value.get("schema_version") != "prime-resume-packet-v1":
        return False
    source = value.get("source")
    state = value.get("state")
    next_value = value.get("next")
    if not isinstance(source, Mapping) or not isinstance(state, Mapping) or not isinstance(next_value, Mapping):
        return False
    expected_run_dir = str(root.joinpath(*run_parts))
    return (
        source.get("run_id") == session.get("run_id")
        and source.get("run_dir") == expected_run_dir
        and source.get("session_state_sha256") == session_sha256
        and source.get("tasks_sha256") == tasks_sha256
        and state.get("active_task_id") == session.get("active_task_id")
        and state.get("status") == session.get("status")
        and state.get("resume_gate") == session.get("resume_gate")
        and next_value.get("task_id") == session.get("active_task_id")
    )


def _merge_scopes(scopes: dict[str, tuple[int, int, int, int, int, int]], snapshot: _FileSnapshot) -> None:
    for relative_path, fingerprint in snapshot.directory_fingerprints:
        previous = scopes.get(relative_path)
        if previous is not None and previous != fingerprint:
            _fail("PRIME_EVIDENCE_SNAPSHOT_UNSTABLE", "shared directory changed during capture", relative_path)
        scopes[relative_path] = fingerprint


def _source_set(files: Mapping[str, _FileSnapshot | None]) -> str:
    rows = []
    for name in sorted(files):
        snapshot = files[name]
        if snapshot is None:
            continue
        metadata = snapshot.metadata()
        rows.append({key: metadata[key] for key in ("relative_path", "sha256", "size", "dev", "ino") } | {"name": name})
    return canonical_hash(rows)


def _manifest_source_set(sources: list[Mapping[str, Any]]) -> str:
    rows = [
        {
            "logical_name": source["logical_name"],
            "relative_path": source["relative_path"],
            "present": source["present"],
            "size": source["size"],
            "sha256": source["sha256"],
        }
        for source in sources
    ]
    return canonical_hash(sorted(rows, key=lambda row: (row["relative_path"], row["logical_name"])))


def _manifest_source_entries_from_capture(capture: Mapping[str, Any]) -> list[dict[str, Any]]:
    root = capture.get("root")
    files = capture.get("files")
    if not isinstance(root, Mapping) or not isinstance(files, Mapping):
        _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", "capture root/files are missing")
    entries: list[dict[str, Any]] = []
    for name in WRITER_GENERATION_REQUIRED_FILES:
        metadata = files.get(name)
        if not isinstance(metadata, Mapping):
            _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", f"required source is missing: {name}")
        expected_path = f"{root.get('run_relative_path')}/{RUN_REQUIRED_FILES[name][-1]}"
        if metadata.get("relative_path") != expected_path:
            _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", f"source path mismatch: {name}")
        required = ("relative_path", "sha256", "size", "dev", "ino", "mode", "mtime_ns", "ctime_ns")
        if any(key not in metadata for key in required):
            _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", f"source metadata incomplete: {name}")
        entries.append(
            {
                "logical_name": name,
                "relative_path": metadata["relative_path"],
                "present": True,
                "size": metadata["size"],
                "sha256": metadata["sha256"],
                "dev": metadata["dev"],
                "ino": metadata["ino"],
                "mode": metadata["mode"],
                "mtime_ns": metadata["mtime_ns"],
                "ctime_ns": metadata["ctime_ns"],
            }
        )
    return sorted(entries, key=lambda row: (row["relative_path"], row["logical_name"]))


def build_writer_manifest_from_capture(
    capture: Mapping[str, Any],
    *,
    generation_id: str,
    generation: int = 1,
) -> dict[str, Any]:
    """Build a manifest object without writing it or granting authority.

    This is a pure protocol helper for a cooperative writer or deterministic
    fixture.  Publication remains the writer's responsibility and is not
    performed by the evidence reader.
    """

    if capture.get("schema_version") != PRIME_FILESYSTEM_EVIDENCE_SCHEMA or capture.get("capture_status") != "STABLE_READ_ONLY":
        _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", "manifest source capture is not stable S5 evidence")
    if capture.get("binding_projection", {}).get("eligible") is not True:
        _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", "manifest source capture is not eligible")
    if type(generation) is not int or generation < 1:
        _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", "generation must be a positive integer")
    if not isinstance(generation_id, str) or SEGMENT_RE.fullmatch(generation_id) is None:
        _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", "generation_id is not a safe opaque identifier")
    root = capture.get("root")
    if not isinstance(root, Mapping):
        _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", "capture root is missing")
    sources = _manifest_source_entries_from_capture(capture)
    return {
        "schema_version": PRIME_WRITER_MANIFEST_SCHEMA,
        "protocol": "manifest-last-v1",
        "coverage_profile": "prime-run-ledgers-v1",
        "run_id": root["run_id"],
        "run_relative_path": root["run_relative_path"],
        "root_binding_sha256": root["root_binding_sha256"],
        "generation": generation,
        "generation_id": generation_id,
        "sealed": True,
        "sources": sources,
        "covered_source_set_sha256": _manifest_source_set(sources),
    }


def _root_binding(root: Path, run_parts: tuple[str, ...], run_fingerprint: tuple[int, int, int, int, int, int]) -> str:
    return canonical_hash({
        "project_root": str(root),
        "run_relative_path": _relative(run_parts),
        "run_id": run_parts[-1],
        "run_directory_fingerprint": list(run_fingerprint),
    })


def _validate_writer_manifest(
    snapshot: _FileSnapshot,
    *,
    root: Path,
    run_parts: tuple[str, ...],
    capture: Mapping[str, Any],
) -> dict[str, Any]:
    value = _json_object(snapshot, "writer snapshot manifest")
    expected_keys = {
        "schema_version",
        "protocol",
        "coverage_profile",
        "run_id",
        "run_relative_path",
        "root_binding_sha256",
        "generation",
        "generation_id",
        "sealed",
        "sources",
        "covered_source_set_sha256",
    }
    if set(value) != expected_keys:
        return {
            "status": "INVALID",
            "coherent": False,
            "trusted": False,
            "attestation": "UNTRUSTED_SELF_ATTESTATION",
            "manifest_sha256": snapshot.sha256,
            "reason_code": "PRIME_EVIDENCE_WRITER_GENERATION_INVALID",
        }
    generation = value["generation"]
    generation_id = value["generation_id"]
    if (
        value["schema_version"] != PRIME_WRITER_MANIFEST_SCHEMA
        or value["protocol"] != "manifest-last-v1"
        or value["coverage_profile"] != "prime-run-ledgers-v1"
        or type(generation) is not int
        or generation < 1
        or not isinstance(generation_id, str)
        or SEGMENT_RE.fullmatch(generation_id) is None
        or value["sealed"] is not True
        or not isinstance(value["sources"], list)
    ):
        return {
            "status": "INVALID",
            "coherent": False,
            "trusted": False,
            "attestation": "UNTRUSTED_SELF_ATTESTATION",
            "manifest_sha256": snapshot.sha256,
            "reason_code": "PRIME_EVIDENCE_WRITER_GENERATION_INVALID",
        }
    root_info = capture.get("root")
    if not isinstance(root_info, Mapping):
        _fail("PRIME_EVIDENCE_WRITER_GENERATION_INVALID", "capture root missing while validating manifest")
    expected_sources = _manifest_source_entries_from_capture(capture)
    sources = value["sources"]
    source_keys = {
        "logical_name",
        "relative_path",
        "present",
        "size",
        "sha256",
        "dev",
        "ino",
        "mode",
        "mtime_ns",
        "ctime_ns",
    }
    if any(not isinstance(item, Mapping) or set(item) != source_keys for item in sources):
        reason_code = "PRIME_EVIDENCE_WRITER_GENERATION_INVALID"
    elif (
        value["run_id"] != run_parts[-1]
        or value["run_relative_path"] != _relative(run_parts)
        or value["root_binding_sha256"] != root_info.get("root_binding_sha256")
        or sources != expected_sources
        or value["covered_source_set_sha256"] != _manifest_source_set(expected_sources)
    ):
        reason_code = "PRIME_EVIDENCE_WRITER_GENERATION_MISMATCH"
    else:
        return {
            "status": "MATCHED",
            "coherent": True,
            "trusted": False,
            "attestation": "UNTRUSTED_SELF_ATTESTATION",
            "manifest_sha256": snapshot.sha256,
            "manifest_relative_path": _relative(run_parts + WRITER_MANIFEST_RELATIVE_PATH),
            "generation": generation,
            "generation_id": generation_id,
            "covered_source_set_sha256": value["covered_source_set_sha256"],
            "covered_files": [entry["logical_name"] for entry in expected_sources],
        }
    return {
        "status": "SOURCE_SET_MISMATCH" if reason_code.endswith("MISMATCH") else "INVALID",
        "coherent": False,
        "trusted": False,
        "attestation": "UNTRUSTED_SELF_ATTESTATION",
        "manifest_sha256": snapshot.sha256,
        "reason_code": reason_code,
    }


def _normalized_status(raw_status: str) -> str:
    return {
        "running": "in_progress",
        "in_progress": "in_progress",
        "hold": "paused",
        "paused": "paused",
        "blocked": "blocked",
        "stopped": "stopped",
        "done": "stopped",
        "completed": "stopped",
    }.get(raw_status, "")


def _next_action(session: Mapping[str, Any], active_task: Mapping[str, Any] | None, tasks: list[Mapping[str, Any]]) -> str:
    raw_status = str(session["status"])
    if session["stop_reason"] or raw_status in {"done", "stopped", "completed"}:
        return "stop"
    if session["resume_gate"] == "hold":
        return "hold"
    statuses = {str(item.get("status")) for item in tasks}
    if tasks and statuses <= {"done", "verified"}:
        return "stop"
    if active_task is not None and str(active_task.get("status")) in {"pending", "in_progress", "ready", "running", "READY", "RUNNING"}:
        return "continue"
    return "hold"


def capture_prime_evidence(
    prime_root: str | Path,
    run_relative_path: str | Path,
    *,
    resume_packet_relative_path: str | Path | None = None,
    hook: Callable[[str, str | None], None] | None = None,
) -> dict[str, Any]:
    """Capture canonical Prime ledgers without creating any side effect.

    ``hook`` is a deterministic test seam.  Production callers leave it unset.
    The returned capture is stable evidence, not an authorization decision.
    """

    root = _root(prime_root)
    run_parts = _run_parts(run_relative_path)
    run_id = run_parts[-1]
    run_fd, run_directories = _open_directory_chain(root, run_parts, "Prime run directory")
    os.close(run_fd)
    run_fingerprint = run_directories[-1][1]

    file_parts: dict[str, tuple[str, ...]] = {
        name: run_parts + suffix for name, suffix in RUN_REQUIRED_FILES.items()
    }
    file_parts.update({name: run_parts + suffix for name, suffix in RUN_OPTIONAL_FILES.items()})
    file_parts.update(PROJECT_FILES)
    packet_parts = _discover_packet(root) if resume_packet_relative_path is None else _parts(resume_packet_relative_path, "resume_packet_relative_path")
    if packet_parts is not None:
        if packet_parts[-1] != "resume_packet.json" or packet_parts[: len(PACKET_ROOT)] != PACKET_ROOT:
            _fail("PRIME_EVIDENCE_PATH_MISMATCH", "resume packet path is outside canonical packet root")
        file_parts["resume_packet"] = packet_parts

    required_names = set(RUN_REQUIRED_FILES) | {"events", "artifacts"}
    optional_names = set(file_parts) - required_names
    files: dict[str, _FileSnapshot | None] = {}
    scopes: dict[str, tuple[int, int, int, int, int, int]] = {}
    for name in sorted(file_parts):
        if name in optional_names:
            snapshot = _read_optional(root, file_parts[name], hook=hook)
        else:
            snapshot = _read_file(root, file_parts[name], hook=hook)
        files[name] = snapshot
        if snapshot is not None:
            _merge_scopes(scopes, snapshot)

    session_snapshot = files["session_state"]
    tasks_snapshot = files["tasks"]
    events_snapshot = files["events"]
    artifacts_snapshot = files["artifacts"]
    assert session_snapshot is not None and tasks_snapshot is not None and events_snapshot is not None and artifacts_snapshot is not None
    session = _parse_session(session_snapshot, run_id)
    tasks, tasks_by_id = _parse_tasks(tasks_snapshot)
    events = _parse_ledger(events_snapshot, kind="events", id_key="event_id", run_id=run_id)
    artifacts = _parse_ledger(artifacts_snapshot, kind="artifacts", id_key="artifact_id", run_id=run_id)

    missing_proofs: list[str] = []
    active_task_id = session["active_task_id"]
    active_task = tasks_by_id.get(active_task_id) if active_task_id else None
    if active_task_id and active_task is None:
        missing_proofs.append("ACTIVE_TASK_NOT_IN_TASK_LEDGER")
    if session["latest_task_id"] != len(tasks):
        missing_proofs.append("TASK_HIGH_WATERMARK_DRIFT")
    if session["latest_event_id"] != len(events):
        missing_proofs.append("EVENT_HIGH_WATERMARK_DRIFT")
    if session["latest_artifact_id"] != len(artifacts):
        missing_proofs.append("ARTIFACT_HIGH_WATERMARK_DRIFT")
    if not _artifact_paths_inside_run(artifacts, root, run_parts):
        missing_proofs.append("ARTIFACT_PATH_OUTSIDE_RUN")

    queue_snapshot = files.get("queue")
    queue = _safe_optional_json(queue_snapshot, "QUEUE.json")
    active_card_snapshot: _FileSnapshot | None = None
    queue_task: dict[str, Any] | None = None
    if queue is None:
        missing_proofs.append("QUEUE_MISSING")
    else:
        raw_queue_tasks = queue.get("tasks")
        if queue.get("schema", 1) != 1 or not isinstance(raw_queue_tasks, list):
            missing_proofs.append("QUEUE_SCHEMA_INVALID")
        else:
            matches = [item for item in raw_queue_tasks if isinstance(item, Mapping) and item.get("id") == active_task_id]
            if len(matches) == 1:
                queue_task = dict(matches[0])
                card_value = queue_task.get("card")
                if isinstance(card_value, str):
                    card_parts = _path_parts(card_value, "queue card path")
                    active_card_parts = ("Plan", "local-ai") + card_parts
                    active_card_snapshot = _read_file(root, active_card_parts, hook=hook)
                    files["active_card"] = active_card_snapshot
                    _merge_scopes(scopes, active_card_snapshot)
                else:
                    missing_proofs.append("ACTIVE_CARD_PATH_MISSING")
            elif not matches:
                missing_proofs.append("ACTIVE_TASK_NOT_IN_QUEUE")
            else:
                missing_proofs.append("ACTIVE_TASK_AMBIGUOUS_IN_QUEUE")

    policy_snapshot = files.get("policy")
    policy = _safe_optional_json(policy_snapshot, "Prime policy manifest")
    policy_valid = policy is not None and _policy_valid(policy)
    if policy_snapshot is None:
        missing_proofs.append("POLICY_MISSING")
    elif not policy_valid:
        missing_proofs.append("POLICY_INVALID")

    expected_run_dir = str(root.joinpath(*run_parts))
    lease_snapshot = files.get("writer_lease")
    lease_claim = _lease_claim(_safe_optional_json(lease_snapshot, "writer lease") or {}, expected_run_dir) if lease_snapshot else None
    writer_observed = "valid" if lease_claim is not None else "not_observed" if lease_snapshot is None else "invalid"
    if lease_snapshot is None:
        missing_proofs.append("WRITER_LEASE_NOT_OBSERVED")
    elif lease_claim is None:
        missing_proofs.append("WRITER_LEASE_INVALID")

    packet_snapshot = files.get("resume_packet")
    packet = _safe_optional_json(packet_snapshot, "resume packet")
    packet_valid = packet_snapshot is not None and packet is not None and _packet_valid(
        packet,
        root=root,
        run_parts=run_parts,
        session_sha256=session_snapshot.sha256,
        tasks_sha256=tasks_snapshot.sha256,
        session=session,
    )
    if packet_snapshot is None:
        missing_proofs.append("RESUME_PACKET_NOT_OBSERVED")
    elif not packet_valid:
        missing_proofs.append("RESUME_PACKET_INVALID_OR_STALE")

    normalized_status = _normalized_status(session["status"])
    if not normalized_status or normalized_status == "stopped":
        missing_proofs.append("SESSION_NOT_RESUMABLE")
    if session["resume_gate"] not in {"open", "continue", "hold"}:
        missing_proofs.append("RESUME_GATE_INVALID")
    if active_task is None:
        missing_proofs.append("ACTIVE_TASK_MISSING")
    elif str(active_task.get("status")) not in {"pending", "in_progress", "ready", "running", "READY", "RUNNING"}:
        missing_proofs.append("ACTIVE_TASK_NOT_CONTINUABLE")

    _invoke_hook(hook, "before_finalize", None)
    for name in sorted(file_parts):
        original = files[name]
        final = _read_optional(root, file_parts[name], hook=None, invoke_hook=False) if name in optional_names else _read_file(root, file_parts[name], hook=None, invoke_hook=False)
        if (original is None) != (final is None):
            _fail("PRIME_EVIDENCE_SNAPSHOT_UNSTABLE", "optional file appeared or disappeared", file_parts[name] and _relative(file_parts[name]))
        if original is not None and final is not None:
            if original.data != final.data or original.fingerprint != final.fingerprint or original.directory_fingerprints != final.directory_fingerprints:
                _fail("PRIME_EVIDENCE_SNAPSHOT_UNSTABLE", "source file changed before finalization", original.relative_path)
            _merge_scopes(scopes, final)
    if "active_card" in files and files["active_card"] is not None and active_card_snapshot is not None:
        final_card = _read_file(root, tuple(active_card_snapshot.relative_path.split("/")), hook=None, invoke_hook=False)
        if final_card.data != active_card_snapshot.data or final_card.fingerprint != active_card_snapshot.fingerprint:
            _fail("PRIME_EVIDENCE_SNAPSHOT_UNSTABLE", "active card changed before finalization", active_card_snapshot.relative_path)

    files_metadata = {name: files[name].metadata() if files[name] is not None else None for name in sorted(files)}
    source_set_sha256 = _source_set(files)
    parsed = {
        "session_state": session,
        "task_count": len(tasks),
        "active_task": active_task,
        "event_count": len(events),
        "artifact_count": len(artifacts),
    }
    consistency = {
        "attempts": 2,
        "source_set_sha256": source_set_sha256,
        "run_id_match": True,
        "ledger_high_watermarks_match": not any(item.endswith("HIGH_WATERMARK_DRIFT") for item in missing_proofs),
        "writer_observed": writer_observed,
        "status": "stable",
    }
    missing_proofs = sorted(set(missing_proofs))
    binding_projection = {
        "eligible": not missing_proofs,
        "missing_proofs": missing_proofs,
        "next_action": _next_action(session, active_task, tasks),
    }
    digest_input = {
        "schema_version": PRIME_FILESYSTEM_EVIDENCE_SCHEMA,
        "root": {
            "project_root": str(root),
            "run_relative_path": _relative(run_parts),
            "run_id": run_id,
            "root_binding_sha256": _root_binding(root, run_parts, run_fingerprint),
            "symlink_free": True,
        },
        "files": files_metadata,
        "parsed": parsed,
        "consistency": consistency,
        "binding_projection": binding_projection,
    }
    return {
        **digest_input,
        "capture_status": "STABLE_READ_ONLY",
        "permission": "read_only",
        "external_action": False,
        "execution": dict(EXECUTION_FLAGS),
        "snapshot_sha256": canonical_hash(digest_input),
    }


def capture_prime_evidence_v2(
    prime_root: str | Path,
    run_relative_path: str | Path,
    *,
    resume_packet_relative_path: str | Path | None = None,
    manifest_hook: Callable[[str, str | None], None] | None = None,
) -> dict[str, Any]:
    """Capture S5 evidence plus a cooperative writer snapshot manifest.

    The manifest is a consistency witness, not a signature or authority.  A
    matching result is therefore marked ``trusted=False`` explicitly.  The
    S5 schema and API remain untouched; callers must opt into this v2 path.
    """

    root = _root(prime_root)
    run_parts = _run_parts(run_relative_path)
    before = capture_prime_evidence(
        root,
        run_relative_path,
        resume_packet_relative_path=resume_packet_relative_path,
    )
    manifest_parts = run_parts + WRITER_MANIFEST_RELATIVE_PATH
    try:
        manifest = _read_file(root, manifest_parts, hook=manifest_hook)
    except PrimeEvidenceError as exc:
        if exc.code == "PRIME_EVIDENCE_FILE_MISSING":
            _fail(
                "PRIME_EVIDENCE_WRITER_GENERATION_NOT_OBSERVED",
                "required writer snapshot manifest is missing",
                _relative(manifest_parts),
            )
        raise
    writer_snapshot = _validate_writer_manifest(
        manifest,
        root=root,
        run_parts=run_parts,
        capture=before,
    )
    _invoke_hook(manifest_hook, "before_finalize", None)
    after = capture_prime_evidence(
        root,
        run_relative_path,
        resume_packet_relative_path=resume_packet_relative_path,
    )
    final_manifest = _read_file(root, manifest_parts, hook=None, invoke_hook=False)
    if (
        before["snapshot_sha256"] != after["snapshot_sha256"]
        or manifest.data != final_manifest.data
        or manifest.fingerprint != final_manifest.fingerprint
        or manifest.directory_fingerprints != final_manifest.directory_fingerprints
    ):
        _fail(
            "PRIME_EVIDENCE_WRITER_MANIFEST_DRIFT",
            "writer manifest or covered S5 evidence changed during capture",
            _relative(manifest_parts),
        )
    final_writer_snapshot = _validate_writer_manifest(
        final_manifest,
        root=root,
        run_parts=run_parts,
        capture=after,
    )
    if final_writer_snapshot != writer_snapshot:
        _fail(
            "PRIME_EVIDENCE_WRITER_MANIFEST_DRIFT",
            "writer manifest projection changed during capture",
            _relative(manifest_parts),
        )
    files = dict(after["files"])
    files["writer_manifest"] = final_manifest.metadata()
    consistency = dict(after["consistency"])
    consistency["writer_manifest"] = final_writer_snapshot
    binding_projection = dict(after["binding_projection"])
    if not final_writer_snapshot.get("coherent", False):
        missing = set(binding_projection.get("missing_proofs", []))
        missing.add(final_writer_snapshot["reason_code"])
        binding_projection["missing_proofs"] = sorted(missing)
        binding_projection["eligible"] = False
    digest_input = {
        "schema_version": PRIME_FILESYSTEM_EVIDENCE_V2_SCHEMA,
        "root": after["root"],
        "files": files,
        "parsed": after["parsed"],
        "consistency": consistency,
        "binding_projection": binding_projection,
        "writer_snapshot": final_writer_snapshot,
    }
    return {
        **digest_input,
        "capture_status": "STABLE_READ_ONLY",
        "permission": "read_only",
        "external_action": False,
        "execution": dict(EXECUTION_FLAGS),
        "snapshot_sha256": canonical_hash(digest_input),
    }


def verify_prime_evidence_v2_capture(capture: Mapping[str, Any]) -> dict[str, Any]:
    """Verify the self-contained integrity of one V2 evidence mapping.

    This validates only the evidence object and its embedded snapshot hash.
    It does not authenticate the writer, establish freshness, or grant any
    execution authority.  Keeping this check separate lets a later external
    anchor verifier reuse the exact S6 contract without projecting an S4
    state or inventing a W5 identity.
    """

    if not isinstance(capture, Mapping):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "v2 capture must be an object")
    if capture.get("schema_version") != PRIME_FILESYSTEM_EVIDENCE_V2_SCHEMA or capture.get("capture_status") != "STABLE_READ_ONLY":
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "capture is not stable v2 filesystem evidence")
    digest_input = {
        key: capture[key]
        for key in ("schema_version", "root", "files", "parsed", "consistency", "binding_projection", "writer_snapshot")
    }
    if capture.get("snapshot_sha256") != canonical_hash(digest_input):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "v2 capture snapshot hash does not match")
    if (
        capture.get("permission") != "read_only"
        or capture.get("external_action") is not False
        or not isinstance(capture.get("execution"), Mapping)
        or set(capture["execution"]) != set(EXECUTION_FLAGS)
        or any(value is not False for value in capture["execution"].values())
    ):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "capture execution metadata is not read-only")
    projection = capture.get("binding_projection")
    if not isinstance(projection, Mapping) or projection.get("eligible") is not True or projection.get("missing_proofs"):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "required Prime binding proofs are missing")
    writer_snapshot = capture.get("writer_snapshot")
    consistency = capture.get("consistency")
    if (
        not isinstance(writer_snapshot, Mapping)
        or writer_snapshot.get("status") != "MATCHED"
        or writer_snapshot.get("coherent") is not True
        or writer_snapshot.get("trusted") is not False
        or not isinstance(consistency, Mapping)
        or consistency.get("writer_manifest") != writer_snapshot
    ):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "writer manifest is not a matched self-attested consistency witness")
    return dict(capture)


def _build_prime_state_from_verified_projection(
    capture: Mapping[str, Any],
    *,
    w5_identity: Mapping[str, Any],
    expected_prime_run_id: str | None = None,
) -> dict[str, Any]:
    projection = capture.get("binding_projection")
    if not isinstance(projection, Mapping) or projection.get("eligible") is not True or projection.get("missing_proofs"):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "required Prime binding proofs are missing")
    if (
        capture.get("permission") != "read_only"
        or capture.get("external_action") is not False
        or not isinstance(capture.get("execution"), Mapping)
        or set(capture["execution"]) != set(EXECUTION_FLAGS)
        or any(value is not False for value in capture["execution"].values())
    ):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "capture execution metadata is not read-only")
    identity = dict(w5_identity)
    if set(identity) != {"run_id", "card_id", "attempt_id", "dispatch_id"} or any(not isinstance(value, str) or not value for value in identity.values()):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "W5 identity is incomplete")
    root_info = capture.get("root")
    parsed = capture.get("parsed")
    files = capture.get("files")
    if not isinstance(root_info, Mapping) or not isinstance(parsed, Mapping) or not isinstance(files, Mapping):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "capture projection is malformed")
    if expected_prime_run_id is not None and root_info.get("run_id") != expected_prime_run_id:
        _fail("PRIME_EVIDENCE_RUN_BINDING_MISMATCH", "Prime run does not match the explicit expected run")
    session = parsed.get("session_state")
    if not isinstance(session, Mapping):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "session projection is missing")
    if session.get("run_id") != root_info.get("run_id"):
        _fail("PRIME_EVIDENCE_RUN_BINDING_MISMATCH", "session and root run IDs differ")
    active_task_id = session.get("active_task_id")
    if not isinstance(active_task_id, str) or not active_task_id or active_task_id != identity["card_id"]:
        _fail("PRIME_EVIDENCE_ACTIVE_TASK_MISMATCH", "Prime active task is not the W5 card")
    state = {
        "schema_version": PRIME_STATE_SCHEMA,
        "binding_id": canonical_hash({"prime_run_id": root_info["run_id"], "active_task_id": active_task_id, "w5_identity": identity}),
        "prime_run_id": root_info["run_id"],
        "active_task_id": active_task_id,
        "active_task_sha256": files["active_card"]["sha256"],
        "status": {"running": "in_progress", "in_progress": "in_progress", "hold": "paused", "paused": "paused", "blocked": "blocked"}.get(session["status"], "stopped"),
        "resume_gate": "continue" if session["resume_gate"] == "open" else session["resume_gate"],
        "resume_gate_reason": session["resume_gate_reason"],
        "stop_reason": session["stop_reason"],
        "hold_reason": session["hold_reason"],
        "next_action": {"action": projection["next_action"], "task_id": active_task_id},
        "resume_packet_sha256": files["resume_packet"]["sha256"],
        "session_sha256": files["session_state"]["sha256"],
        "tasks_sha256": files["tasks"]["sha256"],
        "queue_sha256": files["queue"]["sha256"],
        "policy_sha256": files["policy"]["sha256"],
        "writer_lease_sha256": files["writer_lease"]["sha256"],
        "w5_identity": identity,
    }
    return state


def build_prime_state_from_capture(
    capture: Mapping[str, Any],
    *,
    w5_identity: Mapping[str, Any],
    expected_prime_run_id: str | None = None,
) -> dict[str, Any]:
    """Project only an eligible fresh v1 filesystem capture into S4."""

    if capture.get("schema_version") != PRIME_FILESYSTEM_EVIDENCE_SCHEMA or capture.get("capture_status") != "STABLE_READ_ONLY":
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "capture is not stable v1 filesystem evidence")
    digest_input = {key: capture[key] for key in ("schema_version", "root", "files", "parsed", "consistency", "binding_projection")}
    if capture.get("snapshot_sha256") != canonical_hash(digest_input):
        _fail("PRIME_EVIDENCE_BINDING_INELIGIBLE", "capture snapshot hash does not match")
    return _build_prime_state_from_verified_projection(
        capture,
        w5_identity=w5_identity,
        expected_prime_run_id=expected_prime_run_id,
    )


def build_prime_state_from_evidence_v2(
    capture: Mapping[str, Any],
    *,
    w5_identity: Mapping[str, Any],
    expected_prime_run_id: str | None = None,
) -> dict[str, Any]:
    """Project a matched, explicitly opt-in v2 capture into unchanged S4-v1."""

    verify_prime_evidence_v2_capture(capture)
    return _build_prime_state_from_verified_projection(
        capture,
        w5_identity=w5_identity,
        expected_prime_run_id=expected_prime_run_id,
    )


__all__ = [
    "EVIDENCE_CODES",
    "MAX_FILE_BYTES",
    "PRIME_EVIDENCE_SCHEMA",
    "PRIME_EVIDENCE_V2_SCHEMA",
    "PRIME_FILESYSTEM_EVIDENCE_SCHEMA",
    "PRIME_FILESYSTEM_EVIDENCE_V2_SCHEMA",
    "PRIME_WRITER_MANIFEST_SCHEMA",
    "WRITER_GENERATION_SCHEMA",
    "WRITER_MANIFEST_RELATIVE_PATH",
    "PrimeEvidenceError",
    "build_prime_state_from_evidence_v2",
    "build_writer_manifest_from_capture",
    "build_prime_state_from_capture",
    "capture_prime_evidence",
    "capture_prime_evidence_v2",
    "verify_prime_evidence_v2_capture",
]
