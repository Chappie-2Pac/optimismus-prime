"""Component-wise path policy for the W3-S0 read-only boundary."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Iterable, Tuple


class PathPolicyError(ValueError):
    """A path cannot be admitted by the explicit W3-S0 policy."""


ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
TRUST_VALUES = {"trusted", "reviewed", "untrusted", "tainted", "historical", "hypothesis"}
PROTECTED_ROOTS = ("/proc", "/sys", "/dev")


def validate_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise PathPolicyError(f"{label} has an invalid stable identifier")
    return value


def absolute_path(value: os.PathLike[str] | str, label: str) -> str:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise PathPolicyError(f"{label} must be a non-empty text path")
    if not os.path.isabs(raw):
        raise PathPolicyError(f"{label} must be absolute")
    if ".." in Path(raw).parts:
        raise PathPolicyError(f"{label} contains traversal")
    return os.path.normpath(raw)


def relative_parts(value: str, label: str) -> Tuple[str, ...]:
    if not isinstance(value, str) or "\x00" in value:
        raise PathPolicyError(f"{label} must be text")
    if value in ("", "."):
        return ()
    if os.path.isabs(value):
        raise PathPolicyError(f"{label} must be relative")
    parts = PurePosixPath(value).parts
    clean = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == ".." or "/" in part:
            raise PathPolicyError(f"{label} contains traversal")
        clean.append(part)
    return tuple(clean)


def normalized_relative(value: str, label: str) -> str:
    return "/".join(relative_parts(value, label))


def is_same_or_under(candidate: str, ancestor: str) -> bool:
    try:
        return os.path.commonpath([candidate, ancestor]) == ancestor
    except ValueError:
        return False


def overlaps_protected_root(path: str) -> bool:
    """Reject both a protected root and a broad root that contains one."""

    return any(
        is_same_or_under(path, protected) or is_same_or_under(protected, path)
        for protected in PROTECTED_ROOTS
    )


def open_directory_nofollow(path: str) -> int:
    """Open every component with O_NOFOLLOW; never resolve a symlink."""

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    parts = Path(path).parts
    fd = os.open(os.sep, flags)
    try:
        for part in parts:
            if part in (os.sep, ""):
                continue
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_relative_directory(parent_fd: int, relative: str) -> int:
    parts = relative_parts(relative, "relative source root")
    if not parts:
        return os.dup(parent_fd)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.dup(parent_fd)
    try:
        for part in parts:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_output_root(path: str) -> int:
    """Validate and open the explicit output domain without following links."""

    return open_directory_nofollow(absolute_path(path, "output root"))


def require_directory(path: str, label: str) -> os.stat_result:
    """Check a directory itself without using a realpath shortcut."""

    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PathPolicyError(f"{label} must be a real directory, not a symlink")
    fd = open_directory_nofollow(path)
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def safe_trust(value: str) -> str:
    if value not in TRUST_VALUES:
        raise PathPolicyError(f"unknown source trust status: {value!r}")
    return value

