"""Versioned local source attestation for the W2.5-S0 bridge contract.

The attestation is deliberately independent of the runtime bundle's HMAC.
It pins the exact W2.5-S0 controller files understood by W5-S1 and compares
their bytes against the local source tree. A changed controller therefore
requires a new source-contract version instead of silently remaining
compatible.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from modules.w4_small_loop_s0.w25_compat import canonical_hash

from .models import W5EvidenceError, W5IncompatibleSource


SOURCE_ATTESTATION_SCHEMA = "w5-w25-source-attestation.v1"
SOURCE_CONTRACT = "w25-s0"
CANONICALIZATION = "json-sortkeys-v1"
SOURCE_ENTRIES = {
    "modules/mother-control-plane/control_plane.py": "34ce9e3e38bf2f99e3156847987659f2f4266ba5c6c095484c1800b17369a67b",
    "modules/mother-control-plane/fake_executor.py": "ec50a5a117b5c442b81dd359929344b1575ec357c687152c588531b1017bb4bd",
    "modules/mother-control-plane/fault_injection.py": "cbc42af2c8fd182b761b1427b296865ac29dd2f92883d4b9e4c70eccc196b312",
    "modules/mother-control-plane/schema/001_w0_core.sql": "2cc7dce963c47e2d7d2c1ebbf0e2e50ac097ca0f244b276ac86c16a9ff9dbd51",
}
SOURCE_CLOSURE_HASH = "c9106a92ad9d39b8a72ed906b6cb9c4ca8a0805cd318aa570b76f8c8a0a0488b"
_ATTESTATION_KEYS = {"schema", "source_contract", "canonicalization", "entries", "source_closure_hash"}


def source_attestation_template() -> dict[str, Any]:
    """Return the exact W2.5-S0 source claim expected by W5-S1."""

    return {
        "schema": SOURCE_ATTESTATION_SCHEMA,
        "source_contract": SOURCE_CONTRACT,
        "canonicalization": CANONICALIZATION,
        "entries": dict(SOURCE_ENTRIES),
        "source_closure_hash": SOURCE_CLOSURE_HASH,
    }


def _required_keys(value: Mapping[str, Any], label: str) -> None:
    missing = _ATTESTATION_KEYS - set(value)
    extra = set(value) - _ATTESTATION_KEYS
    if missing or extra:
        raise W5EvidenceError(f"{label}: schema drift; missing={sorted(missing)} extra={sorted(extra)}")


def _verify_shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise W5EvidenceError("source_attestation: object required")
    _required_keys(value, "source_attestation")
    if value["schema"] != SOURCE_ATTESTATION_SCHEMA or value["source_contract"] != SOURCE_CONTRACT or value["canonicalization"] != CANONICALIZATION:
        raise W5IncompatibleSource("SOURCE_ATTESTATION_CONTRACT_UNSUPPORTED")
    entries = value["entries"]
    if not isinstance(entries, Mapping) or dict(entries) != SOURCE_ENTRIES:
        raise W5IncompatibleSource("SOURCE_ATTESTATION_FILE_SET_DRIFT")
    if value["source_closure_hash"] != SOURCE_CLOSURE_HASH:
        raise W5IncompatibleSource("SOURCE_ATTESTATION_CLOSURE_DRIFT")
    core = {
        "schema": value["schema"],
        "source_contract": value["source_contract"],
        "canonicalization": value["canonicalization"],
        "entries": dict(entries),
    }
    if canonical_hash(core) != value["source_closure_hash"]:
        raise W5EvidenceError("SOURCE_ATTESTATION_HASH_INVALID")
    return dict(value)


def verify_source_attestation(value: Any, *, source_root: str | Path | None = None) -> dict[str, Any]:
    """Verify the pinned source contract against a local read-only tree."""

    attestation = _verify_shape(value)
    root = Path(source_root) if source_root is not None else Path(__file__).resolve().parents[2]
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise W5IncompatibleSource("SOURCE_ROOT_UNAVAILABLE") from exc
    for relative_path, expected_hash in SOURCE_ENTRIES.items():
        candidate = root / relative_path
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            payload = resolved.read_bytes()
        except (OSError, ValueError) as exc:
            raise W5IncompatibleSource(f"SOURCE_FILE_UNAVAILABLE:{relative_path}") from exc
        actual_hash = hashlib.sha256(payload).hexdigest()
        if actual_hash != expected_hash:
            raise W5IncompatibleSource(f"SOURCE_FILE_DRIFT:{relative_path}")
    return attestation
