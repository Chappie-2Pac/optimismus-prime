"""Narrow, fail-closed Prime mutations backed by the local task engine.

This module deliberately does not expose arbitrary file writes, shell execution,
network access, form actions or external messages.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import Any

try:
    from .prime_policy import CARD_ID_RE, PolicyError, safe_generated_id, safe_path
except ImportError:  # direct server execution
    from prime_policy import CARD_ID_RE, PolicyError, safe_generated_id, safe_path


ENGINE_PATH = Path(__file__).resolve().parents[1] / "modules" / "local-mother-session" / "task_engine" / "local_ai_tasks.py"
STATE_PATH = Path(__file__).resolve().parents[1] / "modules" / "local-mother-session" / "task_engine" / "local_ai_state.py"
MCP_ACTORS = {"codex", "local-ai", "shared"}
MAX_REASON = 4096


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PolicyError(f"task engine unavailable: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _engine():
    return _load(ENGINE_PATH, "prime_local_ai_tasks_mcp")


def _state():
    return _load(STATE_PATH, "prime_local_ai_state_mcp")


def _actor(value: str) -> str:
    if value not in MCP_ACTORS:
        raise PolicyError("actor is not allowed for MCP card mutations")
    return value


def _reason(value: str | None, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > MAX_REASON:
        raise PolicyError("reason exceeds the MCP limit")
    if required and not value.strip():
        raise PolicyError("reason is required")
    return value


def _queue_hash(root: Path) -> str:
    return hashlib.sha256((root / "Plan/local-ai/QUEUE.json").read_bytes()).hexdigest()


def _load_queue(root: Path):
    engine = _engine()
    queue_hash = _queue_hash(root)
    queue, by = engine.load(root)
    return engine, queue_hash, queue, by


def _check_card(root: Path, card_id: str, expected: str, actor: str):
    card_id = safe_generated_id(card_id, label="card_id", pattern=CARD_ID_RE)
    if not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise PolicyError("expected_queue_sha256 must be a lowercase SHA-256")
    actor = _actor(actor)
    engine, current_hash, queue, by = _load_queue(root)
    if current_hash != expected:
        raise PolicyError("stale queue hash; reread queue before retrying")
    if card_id not in by:
        raise PolicyError(f"unknown card: {card_id}")
    card = by[card_id]
    owner = card.get("owner")
    if owner not in MCP_ACTORS:
        raise PolicyError(f"card owner is not MCP-compatible: {owner}")
    if owner != actor and not (owner == "shared" and actor in {"codex", "local-ai"}):
        raise PolicyError("actor does not own this card")
    return engine, current_hash, queue, by, card_id, actor


def capabilities() -> dict[str, Any]:
    return {
        "read_only": False,
        "safe_write_scope": ["prime_start_card", "prime_update_card", "prime_release_card", "prime_record_receipt"],
        "deferred": ["prime_create_run", "prime_append_run_note"],
        "requires_expected_queue_sha256": True,
        "allowed_actors": sorted(MCP_ACTORS),
        "engine_backed": True,
        "external_actions": False,
        "shell_or_network": False,
        "uploads_or_submits": False,
    }


def transition(root: Path, card_id: str, command: str, expected: str, actor: str, reason: str = "", result: str | None = None, cascade: bool = False) -> dict[str, Any]:
    engine, current_hash, _queue, by, card_id, actor = _check_card(root, card_id, expected, actor)
    card = by[card_id]
    if command not in {"start", "ready", "block", "accept", "release"}:
        raise PolicyError("unsupported safe card transition")
    if command == "start" and card.get("owner") == "shared":
        raise PolicyError("shared cards require an explicit actor handoff before start")
    state = _state()
    operation = "start" if command == "start" else command
    outcome = state.transition(root, engine.engine(), operation, card_id, current_hash, reason=_reason(reason), result=result, cascade=bool(cascade), actor="Plan")
    outcome["mcp_actor"] = actor
    outcome["new_queue_sha256"] = _queue_hash(root)
    return outcome


def release(root: Path, card_id: str, expected: str, actor: str, reason: str) -> dict[str, Any]:
    return transition(root, card_id, "release", expected, actor, reason=_reason(reason, required=True))


def record_receipt(root: Path, card_id: str, expected: str, actor: str, artifact_path: str, artifact_sha256: str, note: str = "") -> dict[str, Any]:
    _engine_module, current_hash, _queue, _by, card_id, actor = _check_card(root, card_id, expected, actor)
    if not isinstance(artifact_sha256, str) or len(artifact_sha256) != 64 or any(c not in "0123456789abcdef" for c in artifact_sha256):
        raise PolicyError("artifact_sha256 must be a lowercase SHA-256")
    artifact = safe_path(root, artifact_path, label="artifact")
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual != artifact_sha256:
        raise PolicyError("artifact hash does not match")
    note = _reason(note)
    control = root / "Plan" / "local-ai" / "control"
    receipts = control / "mcp-receipts"
    for directory in (control, receipts):
        if directory.is_symlink():
            raise PolicyError("receipt control path may not be a symlink")
        directory.mkdir(mode=0o700, exist_ok=True)
        if not directory.is_dir():
            raise PolicyError("receipt control path is not a directory")
    audit = control / "mcp-audit.jsonl"
    if audit.is_symlink():
        raise PolicyError("MCP audit path may not be a symlink")
    receipt_id = f"{card_id}-{artifact_sha256[:16]}"
    receipt_path = receipts / f"{receipt_id}.json"
    payload = {
        "schema": 1, "card_id": card_id, "actor": actor,
        "queue_sha256": current_hash, "artifact_path": artifact_path,
        "artifact_sha256": actual, "note": note,
    }
    encoded = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    created = False
    if receipt_path.exists():
        if receipt_path.read_bytes() != encoded:
            raise PolicyError("receipt already exists with different content")
    else:
        fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        created = True
    if created:
        line = (json.dumps({"operation": "record_receipt", "card_id": card_id, "actor": actor, "queue_sha256": current_hash, "receipt_id": receipt_id, "artifact_sha256": actual}, ensure_ascii=False, sort_keys=True) + "\n").encode()
        fd = os.open(audit, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            offset = 0
            while offset < len(line):
                offset += os.write(fd, line[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
    return {"receipt_id": receipt_id, "receipt_path": str(receipt_path.relative_to(root)), "receipt_sha256": hashlib.sha256(encoded).hexdigest(), "queue_sha256": current_hash}
