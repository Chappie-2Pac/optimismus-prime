#!/usr/bin/env python3
"""Read and validate the optional W5 observation file for one local run."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import stat
from typing import Any


OBSERVATION_NAME = "w5-observation.json"
RESULT_NAME = "w5-result.json"
MAX_OBSERVATION_BYTES = 65536
MAX_RESULT_BYTES = 262144
EXPECTED_ADAPTER_SHA256 = "ae0b1d2288faafe8a3cac90c4ce09277078a82064057b1cfc2be93a13aacee58"
SOURCE_ENTRIES = {
    "modules/mother-control-plane/control_plane.py": "34ce9e3e38bf2f99e3156847987659f2f4266ba5c6c095484c1800b17369a67b",
    "modules/mother-control-plane/fake_executor.py": "ec50a5a117b5c442b81dd359929344b1575ec357c687152c588531b1017bb4bd",
    "modules/mother-control-plane/fault_injection.py": "cbc42af2c8fd182b761b1427b296865ac29dd2f92883d4b9e4c70eccc196b312",
    "modules/mother-control-plane/schema/001_w0_core.sql": "2cc7dce963c47e2d7d2c1ebbf0e2e50ac097ca0f244b276ac86c16a9ff9dbd51",
}


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise ValueError(f"{label} darf kein Symlink sein")
    if not path.is_file():
        raise ValueError(f"{label} muss eine reguläre Datei sein")
    return path


def _reject_symlink_components(path: Path, label: str) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} enthält einen Symlink: {current}")


def _trusted_prime_root(prime: Path) -> Path:
    if prime.is_symlink():
        raise ValueError("Prime-Wurzel darf kein Symlink sein")
    _reject_symlink_components(prime, "Prime-Wurzel")
    root = prime.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Prime-Wurzel ist kein Verzeichnis")
    return root


def _sha256(path: Path) -> str:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 131072)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.close(fd)


def _read_json(path: Path, limit: int, label: str) -> Any:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError(f"{label} ist keine begrenzte reguläre Datei")
        payload = bytearray()
        while len(payload) <= limit:
            chunk = os.read(fd, min(131072, limit + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > limit or b"\0" in payload:
            raise ValueError(f"{label} ist zu groß oder binär")
        return json.loads(bytes(payload).decode("utf-8"))
    finally:
        os.close(fd)


def _prime_module(prime: Path, name: str, relative: str, expected_hash: str):
    root = _trusted_prime_root(prime)
    path = _regular_file(root / relative, name)
    _reject_symlink_components(path, name)
    if _sha256(path) != expected_hash:
        raise ValueError(f"{name} ist nicht die gepinnte Prime-Version")
    spec = importlib.util.spec_from_file_location("prime_w5_pinned_" + name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"{name} konnte nicht geladen werden")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    loaded = getattr(module, "__file__", None)
    if not loaded or Path(loaded).resolve() != path.resolve():
        raise ValueError(f"{name} wurde aus einer fremden Prime-Wurzel geladen")
    return module


def _verify_source_closure(root: Path) -> None:
    for relative, expected_hash in SOURCE_ENTRIES.items():
        path = root / relative
        _regular_file(path, f"Source-Closure {relative}")
        _reject_symlink_components(path, f"Source-Closure {relative}")
        if _sha256(path) != expected_hash:
            raise ValueError(f"Source-Closure geändert: {relative}")


def _adapter(prime: Path):
    root = _trusted_prime_root(prime)
    _verify_source_closure(root)
    module = _prime_module(
        prime,
        "mother_observation",
        "modules/w5_dispatch_bridge_s0/mother_observation.py",
        EXPECTED_ADAPTER_SHA256,
    )
    verify = getattr(module, "verify_mother_observation", None)
    build = getattr(module, "build_mother_observation", None)
    if not callable(verify) or not callable(build):
        raise ValueError("W5-Adapter ohne Observation-Prüfer")
    return module


def load_optional_w5_observation(
    run: str | Path,
    prime: str | Path,
    *,
    runs_root: str | Path,
) -> dict[str, Any] | None:
    """Return validated W5 context, or ``None`` when this run has no file."""

    runs_input = Path(runs_root)
    if runs_input.is_symlink():
        raise ValueError("verwaltetes Runs-Verzeichnis darf kein Symlink sein")
    _reject_symlink_components(runs_input, "verwaltetes Runs-Verzeichnis")
    runs_path = runs_input.resolve(strict=True)
    if not runs_path.is_dir():
        raise ValueError("verwaltetes Runs-Verzeichnis ist kein Verzeichnis")

    run_input = Path(run)
    if run_input.is_symlink():
        raise ValueError("Run-Verzeichnis darf kein Symlink sein")
    _reject_symlink_components(run_input, "Run-Verzeichnis")
    run_root = run_input.resolve(strict=True)
    if not run_root.is_dir() or run_root.parent != runs_path:
        raise ValueError("Run-Verzeichnis liegt außerhalb des verwalteten Runs-Verzeichnisses")
    path = run_root / OBSERVATION_NAME
    if path.is_symlink():
        raise ValueError("W5-Observation darf kein Symlink sein")
    if not path.exists():
        return None
    _regular_file(path, "W5-Observation")
    _reject_symlink_components(path, "W5-Observation")
    result_path = run_root / RESULT_NAME
    if result_path.is_symlink() or not result_path.exists():
        raise ValueError("W5-Observation benötigt den zugehörigen W5-Result-Snapshot")
    _regular_file(result_path, "W5-Result")
    _reject_symlink_components(result_path, "W5-Result")
    value = _read_json(path, MAX_OBSERVATION_BYTES, "W5-Observation")
    result = _read_json(result_path, MAX_RESULT_BYTES, "W5-Result")
    adapter = _adapter(Path(prime))
    observation = adapter.verify_mother_observation(value)
    expected = adapter.build_mother_observation(result)
    if observation != expected:
        raise ValueError("W5-Observation passt nicht zum W5-Result-Snapshot")
    return observation


__all__ = ["load_optional_w5_observation"]
