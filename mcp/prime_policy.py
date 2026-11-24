"""Fail-closed path and content policy for the local Prime MCP server."""

from __future__ import annotations

import re
from pathlib import Path


MAX_TEXT_BYTES = 256 * 1024
MAX_CARD_BYTES = 64 * 1024
MAX_PROJECTS = 32
MAX_RUNS = 200
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CARD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
SENSITIVE_RE = re.compile(
    r"(^|/)(\.env(?:\..*)?|credentials(?:\..*)?|secrets?(?:\..*)?|"
    r".*\.(?:key|pem|p12|pfx)|id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys)$",
    re.IGNORECASE,
)


class PolicyError(ValueError):
    """A request violates the server's explicit local read policy."""


def canonical_root(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise PolicyError("allowlist roots must be absolute")
    try:
        path = path.resolve(strict=True)
    except OSError as exc:
        raise PolicyError(f"allowlist root is unavailable: {value}") from exc
    if not path.is_dir():
        raise PolicyError(f"allowlist root is not a directory: {value}")
    return path


def _relative(root: Path, value: str | Path, *, label: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        raise PolicyError(f"{label} must be relative to its allowlisted root")
    if any(part in ("", ".", "..") for part in candidate.parts):
        raise PolicyError(f"{label} contains traversal or ambiguous components")
    if SENSITIVE_RE.search(candidate.as_posix()):
        raise PolicyError(f"{label} names a sensitive file")
    return candidate


def safe_path(root: Path, value: str | Path, *, label: str, directory: bool = False) -> Path:
    relative = _relative(root, value, label=label)
    candidate = (root / relative).resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PolicyError(f"{label} escapes its allowlist root") from exc
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise PolicyError(f"{label} may not traverse symlinks")
    if directory and not candidate.is_dir():
        raise PolicyError(f"{label} is not a directory")
    if not directory and not candidate.is_file():
        raise PolicyError(f"{label} is not a regular file")
    return candidate


def safe_generated_id(value: str, *, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PolicyError(f"invalid {label}")
    return value


def read_text(path: Path, *, limit: int = MAX_TEXT_BYTES) -> str:
    try:
        size = path.stat().st_size
        if size > limit:
            raise PolicyError(f"file exceeds read limit: {path}")
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(f"file is not UTF-8 text: {path}") from exc
