"""W5-S1 source-attested façade over the frozen W5-S0 verifier."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any, Mapping

from modules.w4_small_loop_s0.authority import resolve_trusted_authority
from modules.w4_small_loop_s0.models import W4EvidenceError
from modules.w4_small_loop_s0.w25_compat import _hash64, _mapping, canonical_hash, canonical_json

from .models import DispatchBridgeResult, W5EvidenceError, W5IncompatibleSource
from .source_attestation import verify_source_attestation
from .verifier import AUTHORITY_KEYS, AUTHORITY_SCHEMA, BUNDLE_SCHEMA, TOP_LEVEL_KEYS, verify_dispatch_bridge_bundle


S1_BUNDLE_SCHEMA = "w5-dispatch-bridge-bundle.v2-source-attested"
S1_TOP_LEVEL_KEYS = set(TOP_LEVEL_KEYS) | {"source_attestation"}
S1_AUTHORITY_SCHEMA = "w5-w25-bridge-authority.v2-source-attested"
S1_AUTHORITY_KEYS = set(AUTHORITY_KEYS) | {"source_attestation_hash", "bundle_schema_hash"}


def _verify_s1_authority(authority: Mapping[str, Any], *, source_attestation: Mapping[str, Any]) -> dict[str, Any]:
    authority = _mapping(authority, "authority")
    missing = S1_AUTHORITY_KEYS - set(authority)
    extra = set(authority) - S1_AUTHORITY_KEYS
    if missing or extra:
        raise W5EvidenceError(f"authority: schema drift; missing={sorted(missing)} extra={sorted(extra)}")
    if authority.get("schema") != S1_AUTHORITY_SCHEMA:
        raise W5EvidenceError("W5-S1 authority schema unsupported")
    authority_id = authority.get("authority_id")
    key_id = authority.get("key_id")
    if not isinstance(authority_id, str) or not isinstance(key_id, str):
        raise W5EvidenceError("W5-S1 authority identity malformed")
    trusted_key = resolve_trusted_authority(authority_id=authority_id, key_id=key_id)
    if authority.get("source_attestation_hash") != canonical_hash(source_attestation) or authority.get("bundle_schema_hash") != canonical_hash(S1_BUNDLE_SCHEMA):
        raise W5EvidenceError("W5-S1 authority source/schema binding drift")
    core = {key: authority[key] for key in S1_AUTHORITY_KEYS if key not in {"authority_hash", "authority_mac"}}
    if _hash64(authority.get("authority_hash"), "authority.authority_hash") != canonical_hash(core):
        raise W5EvidenceError("W5-S1 authority hash drift")
    expected_mac = hmac.new(trusted_key, canonical_json(core).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(_hash64(authority.get("authority_mac"), "authority.authority_mac"), expected_mac):
        raise W5EvidenceError("W5-S1 authority MAC invalid")
    legacy = {key: authority[key] for key in AUTHORITY_KEYS}
    legacy["schema"] = AUTHORITY_SCHEMA
    legacy_core = {key: legacy[key] for key in AUTHORITY_KEYS if key not in {"authority_hash", "authority_mac"}}
    legacy["authority_hash"] = canonical_hash(legacy_core)
    legacy["authority_mac"] = hmac.new(trusted_key, canonical_json(legacy_core).encode("utf-8"), hashlib.sha256).hexdigest()
    return legacy


def verify_dispatch_bridge_bundle_s1(
    bundle: Mapping[str, Any],
    *,
    authority: Mapping[str, Any] | None = None,
    source_root: str | Path | None = None,
) -> DispatchBridgeResult:
    """Verify W5-S0 evidence only after local W2.5 source attestation."""

    try:
        if not isinstance(bundle, Mapping):
            raise W5EvidenceError("bundle: object required")
        missing = S1_TOP_LEVEL_KEYS - set(bundle)
        extra = set(bundle) - S1_TOP_LEVEL_KEYS
        if missing or extra:
            raise W5EvidenceError(f"bundle: schema drift; missing={sorted(missing)} extra={sorted(extra)}")
        if bundle.get("schema") != S1_BUNDLE_SCHEMA:
            raise W5IncompatibleSource("W5-S1_BUNDLE_SCHEMA_UNSUPPORTED")
        attestation = verify_source_attestation(bundle["source_attestation"], source_root=source_root)
        legacy_authority = _verify_s1_authority(authority, source_attestation=attestation)
        legacy_bundle = dict(bundle)
        legacy_bundle.pop("source_attestation")
        legacy_bundle["schema"] = BUNDLE_SCHEMA
        result = verify_dispatch_bridge_bundle(legacy_bundle, authority=legacy_authority)
        if result.bridge is None:
            return result
        bridge = dict(result.bridge)
        bridge["source_attestation_hash"] = canonical_hash(attestation)
        return DispatchBridgeResult(
            status=result.status,
            findings=result.findings,
            bridge=bridge,
            replay=result.replay,
        )
    except W5IncompatibleSource as exc:
        return DispatchBridgeResult(status="INCOMPATIBLE_SOURCE", findings=(str(exc),))
    except (W5EvidenceError, W4EvidenceError, OSError, TypeError, ValueError) as exc:
        return DispatchBridgeResult(status="INVALID_EVIDENCE", findings=(str(exc),))
