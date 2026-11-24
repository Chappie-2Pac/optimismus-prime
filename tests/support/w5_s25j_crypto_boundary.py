"""Pure, stdlib-only S25J verifier for synthetic Authority grants.

The HMAC envelope is explicitly a test vector format, not an independent
production trust root.  Verification returns evidence with no capability and
the fake CAS only compares immutable mappings; neither path changes state.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Mapping


HARNESS_SCHEMA = "prime-queue-crypto-boundary-v1"
GRANT_FORMAT = "s25j.quarantine-grant.v1"
TEST_ALGORITHM = "HMAC-SHA256-TEST-ONLY"
DOMAIN_SEPARATOR = b"S25J/QUARANTINE-GRANT/v1\x00"
OBSERVE_ONLY = "OBSERVE_ONLY"
VERIFIED_NO_CAPABILITY = "VERIFIED_NO_CAPABILITY"
REJECTED_CRYPTO = "REJECTED_CRYPTO"
REJECTED_TRUST = "REJECTED_TRUST"
REJECTED_BINDING = "REJECTED_BINDING"
REJECTED_REPLAY = "REJECTED_REPLAY"
INCONCLUSIVE = "INCONCLUSIVE"
HOLD = "HOLD"
WOULD_MATCH = "WOULD_MATCH"
STALE = "STALE"
UNKNOWN = "UNKNOWN"
ALREADY_QUARANTINED = "ALREADY_QUARANTINED"
NOT_CLAIMED = "NOT_CLAIMED"
CAS_NOT_ATTEMPTED = "CAS_NOT_ATTEMPTED"

_ENVELOPE_KEYS = frozenset({"format", "algorithm", "authority_id", "key_id", "payload", "signature"})
_PAYLOAD_KEYS = frozenset(
    {
        "action",
        "grant_id",
        "authority_sequence",
        "target",
        "expected",
        "lease",
        "provenance",
        "allowed_transition",
        "cross_store",
        "max_effects",
    }
)
_TARGET_KEYS = frozenset({"root_binding", "store_instance_id", "scope_id", "transaction_id", "idempotency_key"})
_EXPECTED_KEYS = frozenset({"state", "generation", "event_head", "handoff_head", "subject_fence"})
_LEASE_KEYS = frozenset({"lease_id", "not_before", "expires_at"})
_PROVENANCE_KEYS = frozenset({"observer_schema", "observation_id", "evidence_digest"})


class _Malformed(ValueError):
    pass


def _reject_constant(value: str) -> None:
    raise _Malformed(f"non-finite JSON number: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _Malformed(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_json_value(value: Any) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise _Malformed("floating-point JSON values are not allowed")
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _Malformed("JSON object keys must be strings")
            _validate_json_value(item)
        return
    raise _Malformed(f"unsupported JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return the narrow S25J canonical JSON representation."""

    _validate_json_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _parse_envelope(value: Mapping[str, Any] | bytes | str) -> Mapping[str, Any]:
    if isinstance(value, (bytes, str)):
        try:
            text = value.decode("utf-8") if isinstance(value, bytes) else value
            parsed = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, _Malformed) as exc:
            raise _Malformed("envelope_json_invalid") from exc
        if not isinstance(parsed, Mapping):
            raise _Malformed("envelope_not_object")
        return parsed
    if not isinstance(value, Mapping):
        raise _Malformed("envelope_not_mapping")
    return value


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not value or "=" in value.rstrip("="):
        raise _Malformed("signature_encoding_invalid")
    try:
        encoded = value.encode("ascii")
        padded = encoded + b"=" * (-len(encoded) % 4)
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError, base64.binascii.Error) as exc:
        raise _Malformed("signature_encoding_invalid") from exc
    if len(decoded) != hashlib.sha256().digest_size:
        raise _Malformed("signature_length_invalid")
    return decoded


def _signed_bytes(envelope: Mapping[str, Any], payload: Mapping[str, Any]) -> bytes:
    return DOMAIN_SEPARATOR + canonical_json(
        {
            "algorithm": envelope["algorithm"],
            "authority_id": envelope["authority_id"],
            "format": envelope["format"],
            "key_id": envelope["key_id"],
            "payload": payload,
        }
    )


def _keys_exact(mapping: Mapping[str, Any], expected: frozenset[str]) -> bool:
    return set(mapping) == set(expected)


def _output(
    status: str,
    reason: str,
    *,
    crypto: str = NOT_CLAIMED,
    trust: str = NOT_CLAIMED,
    replay: str = NOT_CLAIMED,
    binding: str = NOT_CLAIMED,
    gaps: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVE_ONLY,
        "status": status,
        "reason": reason,
        "audit_gaps": list(gaps or []),
        "crypto_status": crypto,
        "trust_status": trust,
        "replay_status": replay,
        "binding_status": binding,
        "authority_claim": NOT_CLAIMED,
        "capability_issued": False,
        "write_authorized": False,
        "persistence_performed": False,
        "resume_allowed": False,
        "repair_performed": False,
        "cas_claim": CAS_NOT_ATTEMPTED,
        "fence_issued": False,
        "cross_store_commit": False,
        "exactly_once_claim": NOT_CLAIMED,
    }


def _binding_projection(envelope: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    target = payload["target"]
    expected = payload["expected"]
    provenance = payload["provenance"]
    lease = payload["lease"]
    return {
        "action": payload["action"],
        "authority_id": envelope["authority_id"],
        "grant_id": payload["grant_id"],
        "authority_sequence": payload["authority_sequence"],
        "root_binding": target["root_binding"],
        "store_instance_id": target["store_instance_id"],
        "scope_id": target["scope_id"],
        "transaction_id": target["transaction_id"],
        "idempotency_key": target["idempotency_key"],
        "state": expected["state"],
        "generation": expected["generation"],
        "event_head": expected["event_head"],
        "handoff_head": expected["handoff_head"],
        "subject_fence": expected["subject_fence"],
        "lease_id": lease["lease_id"],
        "observation_schema": provenance["observer_schema"],
        "observation_id": provenance["observation_id"],
        "evidence_digest": provenance["evidence_digest"],
        "allowed_transition": payload["allowed_transition"],
        "cross_store": payload["cross_store"],
        "max_effects": payload["max_effects"],
    }


def verify_authority_grant(
    envelope_value: Mapping[str, Any] | bytes | str,
    trust_snapshot: Mapping[str, Any],
    *,
    replay_snapshot: Mapping[str, Any] | None,
    expected_binding: Mapping[str, Any] | None,
    now: int,
) -> dict[str, Any]:
    """Verify a synthetic grant and never turn it into a capability."""

    try:
        envelope = _parse_envelope(envelope_value)
        if not _keys_exact(envelope, _ENVELOPE_KEYS):
            raise _Malformed("envelope_keys_invalid")
        if envelope["format"] != GRANT_FORMAT or envelope["algorithm"] != TEST_ALGORITHM:
            return _output(REJECTED_CRYPTO, "FORMAT_OR_ALGORITHM_REJECTED", crypto="REJECTED")
        if not isinstance(envelope["authority_id"], str) or not isinstance(envelope["key_id"], str):
            raise _Malformed("authority_identity_invalid")
        payload = envelope["payload"]
        if not isinstance(payload, Mapping) or not _keys_exact(payload, _PAYLOAD_KEYS):
            raise _Malformed("payload_keys_invalid")
        for nested, keys in ((payload["target"], _TARGET_KEYS), (payload["expected"], _EXPECTED_KEYS), (payload["lease"], _LEASE_KEYS), (payload["provenance"], _PROVENANCE_KEYS)):
            if not isinstance(nested, Mapping) or not _keys_exact(nested, keys):
                raise _Malformed("nested_payload_invalid")
        if payload["action"] != "PERSIST_QUARANTINE" or payload["allowed_transition"] != "PENDING_TO_QUARANTINED":
            return _output(REJECTED_BINDING, "GRANT_ACTION_OR_TRANSITION_REJECTED", binding="REJECTED")
        if payload["cross_store"] is not False or payload["max_effects"] != 1:
            return _output(REJECTED_BINDING, "GRANT_EFFECT_BOUNDARY_REJECTED", binding="REJECTED")
        signed = _signed_bytes(envelope, payload)
        signature = _decode_signature(envelope["signature"])
    except (KeyError, TypeError, _Malformed, UnicodeError):
        return _output(REJECTED_CRYPTO, "GRANT_CANONICAL_OR_SCHEMA_INVALID", crypto="REJECTED")

    key_record = trust_snapshot.get(envelope["key_id"]) if isinstance(trust_snapshot, Mapping) else None
    if not isinstance(key_record, Mapping):
        return _output(REJECTED_TRUST, "AUTHORITY_KEY_UNKNOWN", trust="UNKNOWN")
    if key_record.get("status") != "ACTIVE" or key_record.get("algorithm") != TEST_ALGORITHM:
        return _output(REJECTED_TRUST, "AUTHORITY_KEY_NOT_ACTIVE", trust="REVOKED")
    if key_record.get("authority_id") != envelope["authority_id"]:
        return _output(REJECTED_TRUST, "AUTHORITY_ID_KEY_MISMATCH", trust="MISMATCH")
    secret = key_record.get("secret")
    if not isinstance(secret, bytes):
        return _output(INCONCLUSIVE, "TRUST_SECRET_UNAVAILABLE", trust="UNKNOWN")
    expected_signature = hmac.new(secret, signed, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_signature, signature):
        return _output(REJECTED_CRYPTO, "SIGNATURE_INVALID", crypto="INVALID")

    payload = payload
    grant_id = payload["grant_id"]
    sequence = payload["authority_sequence"]
    if not isinstance(grant_id, str) or not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
        return _output(REJECTED_BINDING, "SEQUENCE_OR_GRANT_INVALID", binding="REJECTED")
    if grant_id in set(key_record.get("revoked_grant_ids", ())):
        return _output(REJECTED_REPLAY, "GRANT_REVOKED", replay="REVOKED")
    try:
        sequence_floor = int(key_record.get("sequence_floor", 0))
    except (TypeError, ValueError):
        return _output(REJECTED_TRUST, "AUTHORITY_SEQUENCE_FLOOR_INVALID", trust="UNKNOWN")
    if sequence <= sequence_floor:
        return _output(REJECTED_REPLAY, "AUTHORITY_SEQUENCE_REVOKED", replay="REVOKED")
    lease = payload["lease"]
    if not all(isinstance(lease.get(key), int) and not isinstance(lease.get(key), bool) for key in ("not_before", "expires_at")):
        return _output(REJECTED_BINDING, "LEASE_WINDOW_INVALID", binding="REJECTED")
    if lease["expires_at"] <= lease["not_before"]:
        return _output(REJECTED_BINDING, "LEASE_WINDOW_INVALID", binding="REJECTED")
    if int(now) < lease["not_before"] or int(now) >= lease["expires_at"]:
        return _output(HOLD, "LEASE_NOT_CURRENT", binding="NOT_CURRENT")
    if replay_snapshot is None:
        return _output(INCONCLUSIVE, "REPLAY_SNAPSHOT_MISSING", replay="UNKNOWN")
    if replay_snapshot.get("schema") != "s25j.replay-snapshot.v1":
        return _output(INCONCLUSIVE, "REPLAY_SNAPSHOT_UNTRUSTED", replay="UNKNOWN")
    if grant_id in set(replay_snapshot.get("used_grant_ids", ())):
        return _output(REJECTED_REPLAY, "GRANT_ALREADY_USED", replay="REPLAYED")
    last_sequences = replay_snapshot.get("last_sequences")
    if not isinstance(last_sequences, Mapping):
        return _output(INCONCLUSIVE, "REPLAY_SEQUENCE_UNKNOWN", replay="UNKNOWN")
    if int(last_sequences.get(envelope["authority_id"], 0)) >= sequence:
        return _output(REJECTED_REPLAY, "AUTHORITY_SEQUENCE_REPLAYED", replay="REPLAYED")
    if expected_binding is None:
        return _output(INCONCLUSIVE, "LOCAL_BINDING_MISSING", binding="UNKNOWN")
    actual_binding = _binding_projection(envelope, payload)
    if set(expected_binding) != set(actual_binding) or any(
        expected_binding.get(key) != actual_binding.get(key) for key in actual_binding
    ):
        return _output(REJECTED_BINDING, "LOCAL_BINDING_MISMATCH", binding="MISMATCH")
    return _output(
        VERIFIED_NO_CAPABILITY,
        "SIGNATURE_TRUST_BINDING_AND_REPLAY_CHECKED",
        crypto="VALID",
        trust="ACTIVE",
        replay="UNUSED",
        binding="MATCH",
    )


def evaluate_fake_cas(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two synthetic precondition mappings without changing either."""

    base = {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVE_ONLY,
        "mutation_performed": False,
        "persisted": False,
        "cas_attempted": False,
        "write_authorized": False,
        "authority_claim": NOT_CLAIMED,
    }
    if not isinstance(expected, Mapping) or not isinstance(actual, Mapping):
        return {**base, "result": UNKNOWN, "reason": "PRECONDITION_MAPPING_MISSING"}
    if expected.get("state") == "QUARANTINED" or actual.get("state") == "QUARANTINED":
        return {**base, "result": ALREADY_QUARANTINED, "reason": "TARGET_ALREADY_QUARANTINED"}
    try:
        expected_digest = hashlib.sha256(canonical_json(expected)).hexdigest()
        actual_digest = hashlib.sha256(canonical_json(actual)).hexdigest()
    except _Malformed:
        return {**base, "result": UNKNOWN, "reason": "PRECONDITION_CANONICAL_INVALID"}
    result = WOULD_MATCH if hmac.compare_digest(expected_digest, actual_digest) else STALE
    return {
        **base,
        "result": result,
        "reason": "PRECONDITIONS_EQUAL" if result == WOULD_MATCH else "PRECONDITIONS_STALE",
        "expected_preconditions_digest": expected_digest,
        "actual_preconditions_digest": actual_digest,
    }


__all__ = [
    "ALREADY_QUARANTINED",
    "CAS_NOT_ATTEMPTED",
    "GRANT_FORMAT",
    "HARNESS_SCHEMA",
    "HOLD",
    "INCONCLUSIVE",
    "NOT_CLAIMED",
    "REJECTED_BINDING",
    "REJECTED_CRYPTO",
    "REJECTED_REPLAY",
    "REJECTED_TRUST",
    "STALE",
    "TEST_ALGORITHM",
    "UNKNOWN",
    "VERIFIED_NO_CAPABILITY",
    "WOULD_MATCH",
    "canonical_json",
    "evaluate_fake_cas",
    "verify_authority_grant",
]
