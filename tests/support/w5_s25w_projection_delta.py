"""Pure S25W delta witness for the public S25V projection contract."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from support.w5_s25v_projection_set_completeness import (
        ALLOWED_MEMBER_IDS,
        CANONICALIZATION as S25V_CANONICALIZATION,
        CONTEXT_KEYS as S25V_CONTEXT_KEYS,
        FALSE_FLAGS,
        HARNESS_SCHEMA as S25V_SCHEMA,
        MEMBER_DIGEST_FIELDS as S25V_MEMBER_DIGEST_FIELDS,
        MEMBER_KEYS as S25V_MEMBER_KEYS,
        PROJECTION_SET_SCHEMA as S25V_PROJECTION_SET_SCHEMA,
        PROJECTION_CONFLICT as S25V_PROJECTION_CONFLICT,
        PROJECTION_OUT_OF_WINDOW as S25V_PROJECTION_OUT_OF_WINDOW,
        PROJECTION_PARTIAL as S25V_PROJECTION_PARTIAL,
        PROJECTION_SET_COMPLETE as S25V_PROJECTION_SET_COMPLETE,
        PROJECTION_STALE as S25V_PROJECTION_STALE,
        RESULT_KEYS as S25V_RESULT_KEYS,
        evaluate_projection_set_completeness,
        input_digest as s25v_input_digest,
    )
except ImportError:  # pragma: no cover - direct support-module execution
    from w5_s25v_projection_set_completeness import (
        ALLOWED_MEMBER_IDS,
        CANONICALIZATION as S25V_CANONICALIZATION,
        CONTEXT_KEYS as S25V_CONTEXT_KEYS,
        FALSE_FLAGS,
        HARNESS_SCHEMA as S25V_SCHEMA,
        MEMBER_DIGEST_FIELDS as S25V_MEMBER_DIGEST_FIELDS,
        MEMBER_KEYS as S25V_MEMBER_KEYS,
        PROJECTION_SET_SCHEMA as S25V_PROJECTION_SET_SCHEMA,
        PROJECTION_CONFLICT as S25V_PROJECTION_CONFLICT,
        PROJECTION_OUT_OF_WINDOW as S25V_PROJECTION_OUT_OF_WINDOW,
        PROJECTION_PARTIAL as S25V_PROJECTION_PARTIAL,
        PROJECTION_SET_COMPLETE as S25V_PROJECTION_SET_COMPLETE,
        PROJECTION_STALE as S25V_PROJECTION_STALE,
        RESULT_KEYS as S25V_RESULT_KEYS,
        evaluate_projection_set_completeness,
        input_digest as s25v_input_digest,
    )


HARNESS_SCHEMA = "s25w.projection-delta-witness.v1"
CANONICALIZATION = S25V_CANONICALIZATION
TEST_ONLY = "TEST_ONLY"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

PROJECTION_DELTA_NO_CHANGE = "PROJECTION_DELTA_NO_CHANGE"
PROJECTION_DELTA_NEXT_SEQUENCE = "PROJECTION_DELTA_NEXT_SEQUENCE"
PROJECTION_DELTA_CONFLICT = "PROJECTION_DELTA_CONFLICT"
PROJECTION_DELTA_PARTIAL = "PROJECTION_DELTA_PARTIAL"
S25V_REJECTED = "S25V_REJECTED"
PROJECTION_STALE = "PROJECTION_STALE"
PROJECTION_OUT_OF_WINDOW = "PROJECTION_OUT_OF_WINDOW"
INPUT_INVALID = "INPUT_INVALID"

NO_CHANGE = "NO_CHANGE"
NEXT_SEQUENCE = "NEXT_SEQUENCE"
EVIDENCE_DEGRADED = "EVIDENCE_DEGRADED"
_TRANSITIONS = {NO_CHANGE, NEXT_SEQUENCE, EVIDENCE_DEGRADED}

# A successor may change only observation/provenance-window identity members.
# This is a fixed S25W rule; callers cannot extend it through the input.
NEXT_SEQUENCE_ALLOWED_MEMBER_IDS = (
    "S25T_CASE_DIGEST",
    "S25T_RESULT_DIGEST",
    "S25R_CASE_DIGEST",
    "S25R_RESULT_DIGEST",
    "S25R_PROJECTION_DIGEST",
    "SOURCE_SET_DIGEST",
    "WINDOW_DIGEST",
    "OBSERVATION_SET_DIGEST",
    "EPOCH_SEQUENCE",
    "OBSERVATION_KEYS",
)
NO_CHANGE_ALLOWED_MEMBER_IDS: tuple[str, ...] = ()

_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_MAX_DEPTH = 64
_MAX_STRING = 4096
_MAX_INTEGER = 2**63 - 1
_MAX_INPUT_BYTES = 2 * 1024 * 1024
_MAX_NODES = 10000
_MAX_CONTAINER_ITEMS = 2048
_MAX_KEY_LENGTH = 256

_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "s25v_case",
        "s25v_output",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "s25v_case_digest",
        "s25v_result_digest",
        "transition_kind",
        "before_projection_set_digest",
        "after_projection_set_digest",
        "before_projection_order_digest",
        "after_projection_order_digest",
        "required_member_count",
    }
)
_S25V_RESULT_KEYS = frozenset(S25V_RESULT_KEYS)
_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "transition_kind",
        "changed_member_ids",
        "unchanged_member_ids",
        "allowed_changed_member_ids",
        "changed_member_count",
        "before_projection_set_digest",
        "after_projection_set_digest",
        "before_projection_order_digest",
        "after_projection_order_digest",
        "delta_digest",
        "s25v_case_digest",
        "s25v_result_digest",
        "production_status",
        "authority_claim",
        *FALSE_FLAGS,
    }
)
_MEMBER_KEYS = frozenset(S25V_MEMBER_KEYS)
_ZERO_HASH = "0" * 64
DELTA_SCHEMA = "s25w.projection-delta.v1"
RESULT_KEYS = tuple(sorted(_OUTPUT_KEYS))
MEMBER_KEYS = tuple(S25V_MEMBER_KEYS)
MEMBER_DIGEST_FIELDS = tuple(S25V_MEMBER_DIGEST_FIELDS)
CONTEXT_KEYS = tuple(S25V_CONTEXT_KEYS)
PROJECTION_SET_SCHEMA = S25V_PROJECTION_SET_SCHEMA


class _DuplicateKey(ValueError):
    pass


class _Failure(ValueError):
    def __init__(self, classification: str, reason: str) -> None:
        super().__init__(reason)
        self.classification = classification
        self.reason = reason


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _parse(value: Mapping[str, Any] | bytes | str) -> Any:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, bytes):
        if len(value) > _MAX_INPUT_BYTES:
            raise ValueError("input too large")
        return json.loads(value.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_constant)
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_INPUT_BYTES:
            raise ValueError("input too large")
        return json.loads(value, object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_constant)
    raise TypeError("case must be a mapping, bytes or JSON string")


def _snapshot(value: Any, *, depth: int = 0, active: set[int] | None = None, budget: list[int] | None = None) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("value too deep")
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > _MAX_NODES:
        raise ValueError("value too large")
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, int) and not isinstance(value, bool) and abs(value) > _MAX_INTEGER:
            raise ValueError("integer out of range")
        if isinstance(value, str) and len(value) > _MAX_STRING:
            raise ValueError("string too long")
        return value
    if isinstance(value, float) or isinstance(value, (bytes, bytearray)):
        raise ValueError("unsafe scalar")
    if active is None:
        active = set()
    marker = id(value)
    if marker in active:
        raise ValueError("recursive value")
    active.add(marker)
    try:
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            if len(value) > _MAX_CONTAINER_ITEMS:
                raise ValueError("mapping too large")
            for key, item in value.items():
                if not isinstance(key, str) or len(key) > _MAX_KEY_LENGTH or key in result:
                    raise ValueError("invalid mapping key")
                result[key] = _snapshot(item, depth=depth + 1, active=active, budget=budget)
            return result
        if isinstance(value, (list, tuple)):
            if len(value) > _MAX_CONTAINER_ITEMS:
                raise ValueError("sequence too large")
            return [_snapshot(item, depth=depth + 1, active=active, budget=budget) for item in value]
        raise ValueError("unsupported value")
    finally:
        active.remove(marker)


def _safe_value(value: Any, *, depth: int = 0, active: set[int] | None = None) -> bool:
    if depth > _MAX_DEPTH:
        return False
    if value is None or isinstance(value, (bool, int)):
        return not isinstance(value, int) or isinstance(value, bool) or abs(value) <= _MAX_INTEGER
    if isinstance(value, str):
        return (
            len(value) <= _MAX_STRING
            and not any("\ud800" <= char <= "\udfff" for char in value)
            and not _ABSOLUTE_PATH.match(value)
            and not value.startswith("\\\\")
            and not _URI_SCHEME.match(value)
        )
    if isinstance(value, float) or isinstance(value, (bytes, bytearray)):
        return False
    if active is None:
        active = set()
    marker = id(value)
    if marker in active:
        return False
    active.add(marker)
    try:
        if isinstance(value, Mapping):
            return all(isinstance(key, str) and _safe_value(item, depth=depth + 1, active=active) for key, item in value.items())
        if isinstance(value, (list, tuple)):
            return all(_safe_value(item, depth=depth + 1, active=active) for item in value)
        return False
    except Exception:
        return False
    finally:
        active.remove(marker)


def _exact(value: Any, keys: frozenset[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == set(keys)


def _hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_HASH64.fullmatch(value))


def _integer(value: Any, *, positive: bool = False) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= _MAX_INTEGER and (not positive or value > 0)


def _result(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    transition_kind: str = "UNKNOWN",
    changed_member_ids: list[str] | None = None,
    unchanged_member_ids: list[str] | None = None,
    allowed_changed_member_ids: list[str] | None = None,
    changed_member_count: int = 0,
    before_set_digest: str = _ZERO_HASH,
    after_set_digest: str = _ZERO_HASH,
    before_order_digest: str = _ZERO_HASH,
    after_order_digest: str = _ZERO_HASH,
    delta_digest: str = _ZERO_HASH,
    s25v_case_digest: str = _ZERO_HASH,
    s25v_result_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": TEST_ONLY,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "transition_kind": transition_kind,
        "changed_member_ids": list(changed_member_ids or []),
        "unchanged_member_ids": list(unchanged_member_ids or []),
        "allowed_changed_member_ids": list(allowed_changed_member_ids or []),
        "changed_member_count": changed_member_count,
        "before_projection_set_digest": before_set_digest,
        "after_projection_set_digest": after_set_digest,
        "before_projection_order_digest": before_order_digest,
        "after_projection_order_digest": after_order_digest,
        "delta_digest": delta_digest,
        "s25v_case_digest": s25v_case_digest,
        "s25v_result_digest": s25v_result_digest,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
        **{field: False for field in FALSE_FLAGS},
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _result(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(reason: str, *, classification: str = S25V_REJECTED, **kwargs: Any) -> dict[str, Any]:
    return _result(classification, TEST_BLOCKED, HOLD, reason, **kwargs)


def _valid_s25v_result(result: Any) -> bool:
    if not isinstance(result, Mapping) or not _exact(result, _S25V_RESULT_KEYS) or not _safe_value(result):
        return False
    if result.get("schema_version") != S25V_SCHEMA or result.get("observation_mode") != TEST_ONLY:
        return False
    if result.get("classification") != S25V_PROJECTION_SET_COMPLETE or result.get("status") != PROPOSAL_ONLY or result.get("decision") != DESIGN_ONLY:
        return False
    if result.get("completeness_status") != "COMPLETE" or result.get("transition_kind") not in {NO_CHANGE, NEXT_SEQUENCE}:
        return False
    if result.get("production_status") != PRODUCTION_NOT_AUTHORIZED or result.get("authority_claim") != NOT_CLAIMED:
        return False
    if not all(_hash(result.get(field)) for field in ("before_projection_set_digest", "after_projection_set_digest", "before_projection_order_digest", "after_projection_order_digest")):
        return False
    if not all(_integer(result.get(field), positive=True) for field in ("before_member_count", "after_member_count", "required_member_count")):
        return False
    if any(result.get(field) != len(ALLOWED_MEMBER_IDS) for field in ("before_member_count", "after_member_count", "required_member_count")):
        return False
    return all(result.get(field) is False for field in FALSE_FLAGS)


_S25V_NONPOSITIVE_CLASSIFICATIONS = {
    S25V_PROJECTION_PARTIAL,
    S25V_PROJECTION_STALE,
    S25V_PROJECTION_OUT_OF_WINDOW,
    S25V_PROJECTION_CONFLICT,
    "PROJECTION_REJECTED",
    "INPUT_INVALID",
    "S25U_REJECTED",
    "S25T_REJECTED",
    "S25R_REJECTED",
}


def _valid_s25v_nonpositive_result(result: Any) -> bool:
    if not isinstance(result, Mapping) or not _exact(result, _S25V_RESULT_KEYS) or not _safe_value(result):
        return False
    if result.get("schema_version") != S25V_SCHEMA or result.get("observation_mode") != TEST_ONLY:
        return False
    if result.get("classification") not in _S25V_NONPOSITIVE_CLASSIFICATIONS:
        return False
    if result.get("status") not in {TEST_BLOCKED, "RECOVERY_REQUIRED"}:
        return False
    expected_decision = HOLD if result.get("status") == TEST_BLOCKED else "MANUAL_REVIEW"
    if result.get("decision") != expected_decision or result.get("completeness_status") not in {"PARTIAL", "NOT_CLAIMED"}:
        return False
    if result.get("transition_kind") not in _TRANSITIONS | {"UNKNOWN"}:
        return False
    if result.get("production_status") != PRODUCTION_NOT_AUTHORIZED or result.get("authority_claim") != NOT_CLAIMED:
        return False
    if not all(_hash(result.get(field)) for field in ("before_projection_set_digest", "after_projection_set_digest", "before_projection_order_digest", "after_projection_order_digest")):
        return False
    if not all(_integer(result.get(field)) for field in ("before_member_count", "after_member_count", "required_member_count")):
        return False
    if result.get("required_member_count") != len(ALLOWED_MEMBER_IDS):
        return False
    return all(result.get(field) is False for field in FALSE_FLAGS)


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    for field in (
        "s25v_case_digest",
        "s25v_result_digest",
        "before_projection_set_digest",
        "after_projection_set_digest",
        "before_projection_order_digest",
        "after_projection_order_digest",
    ):
        if not _hash(expected.get(field)):
            return "EXPECTED_DIGEST_INVALID"
    if expected.get("transition_kind") not in _TRANSITIONS:
        return "TRANSITION_KIND_INVALID"
    if not _integer(expected.get("required_member_count"), positive=True):
        return "EXPECTED_MEMBER_COUNT_INVALID"
    if expected["required_member_count"] != len(ALLOWED_MEMBER_IDS):
        return "EXPECTED_MEMBER_COUNT_INVALID"
    return None


def _member_digest(member: Mapping[str, Any]) -> str:
    return _digest({key: member[key] for key in S25V_MEMBER_DIGEST_FIELDS})


def member_digest(member: Mapping[str, Any]) -> str:
    """Return the public S25W member digest used by downstream claim gates."""

    if not isinstance(member, Mapping) or set(member) != set(_MEMBER_KEYS):
        raise ValueError("member schema is not exact")
    return _member_digest(member)


def _member_digests(s25v_case: Mapping[str, Any]) -> tuple[tuple[dict[str, str], str, str], tuple[dict[str, str], str, str]]:
    sides: list[tuple[dict[str, str], str, str]] = []
    for side in ("before_witness", "after_witness"):
        witness = s25v_case.get(side)
        if not isinstance(witness, Mapping) or not isinstance(witness.get("members"), list):
            raise _Failure(S25V_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
        members = witness["members"]
        if len(members) != len(ALLOWED_MEMBER_IDS):
            raise _Failure(S25V_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
        result: dict[str, str] = {}
        ids: list[str] = []
        for member in members:
            if not isinstance(member, Mapping) or not _exact(member, _MEMBER_KEYS) or not _safe_value(member):
                raise _Failure(S25V_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
            if member.get("observation_state") != "PRESENT" or not _hash(member.get("value_digest")) or not _hash(member.get("context_digest")) or not _hash(member.get("member_digest")):
                raise _Failure(S25V_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
            member_id = member.get("member_id")
            if member_id not in ALLOWED_MEMBER_IDS or member_id in result or member["member_digest"] != _member_digest(member):
                raise _Failure(S25V_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
            ids.append(member_id)
            result[member_id] = member["member_digest"]
        if ids != list(ALLOWED_MEMBER_IDS):
            raise _Failure(S25V_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
        digests = [result[member_id] for member_id in ALLOWED_MEMBER_IDS]
        expected_set_digest = _digest({"schema": S25V_PROJECTION_SET_SCHEMA, "member_digests": sorted(digests)})
        expected_order_digest = _digest({"schema": S25V_PROJECTION_SET_SCHEMA, "member_digests": digests})
        if witness.get("projection_set_digest") != expected_set_digest or witness.get("projection_order_digest") != expected_order_digest:
            raise _Failure(S25V_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
        sides.append((result, expected_set_digest, expected_order_digest))
    return sides[0], sides[1]


def _delta_digest(before: Mapping[str, str], after: Mapping[str, str], transition_kind: str) -> str:
    members = [
        {
            "member_id": member_id,
            "before_member_digest": before[member_id],
            "after_member_digest": after[member_id],
            "changed": before[member_id] != after[member_id],
        }
        for member_id in ALLOWED_MEMBER_IDS
    ]
    return _digest({"schema": DELTA_SCHEMA, "transition_kind": transition_kind, "members": members})


def _evaluate(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    try:
        snapshot = _snapshot(_parse(case))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")
    if not isinstance(snapshot, Mapping) or not _exact(snapshot, _TOP_LEVEL):
        return _invalid("CASE_SCHEMA_NOT_EXACT")
    if not _safe_value(snapshot):
        return _invalid("CASE_VALUE_NOT_SAFE")
    if snapshot.get("schema_version") != HARNESS_SCHEMA or snapshot.get("observation_mode") != TEST_ONLY or snapshot.get("canonicalization") != CANONICALIZATION:
        return _invalid("CASE_PROFILE_INVALID")
    if not _hash(snapshot.get("input_digest")) or snapshot["input_digest"] != input_digest(snapshot):
        return _invalid("CASE_DIGEST_DRIFT")
    expected_error = _validate_expected(snapshot["expected"])
    if expected_error:
        return _blocked(expected_error, classification=INPUT_INVALID)

    s25v_case = snapshot["s25v_case"]
    if not isinstance(s25v_case, Mapping) or not _safe_value(s25v_case):
        return _blocked("S25V_CASE_INVALID")
    try:
        if not _hash(s25v_case.get("input_digest")) or s25v_case["input_digest"] != s25v_input_digest(s25v_case):
            return _blocked("S25V_CASE_DIGEST_DRIFT")
    except Exception:
        return _blocked("S25V_CASE_UNREADABLE")
    try:
        actual_s25v = _snapshot(evaluate_projection_set_completeness(s25v_case))
    except Exception:
        return _blocked("S25V_RESULT_UNREADABLE")
    if snapshot["s25v_output"] != actual_s25v:
        return _blocked("S25V_RESULT_MISMATCH")
    if not _valid_s25v_result(actual_s25v):
        if not _valid_s25v_nonpositive_result(actual_s25v):
            return _blocked("S25V_RESULT_INVALID")
        classification = actual_s25v.get("classification") if isinstance(actual_s25v, Mapping) else None
        if classification == S25V_PROJECTION_PARTIAL:
            return _blocked("S25V_NOT_COMPLETE", classification=PROJECTION_DELTA_PARTIAL)
        if classification == S25V_PROJECTION_STALE:
            return _blocked("S25V_STALE", classification=PROJECTION_STALE)
        if classification == S25V_PROJECTION_OUT_OF_WINDOW:
            return _blocked("S25V_OUT_OF_WINDOW", classification=PROJECTION_OUT_OF_WINDOW)
        if classification == S25V_PROJECTION_CONFLICT:
            return _blocked("S25V_CONTEXT_CONFLICT", classification=PROJECTION_DELTA_CONFLICT)
        return _blocked("S25V_RESULT_INVALID")

    expected = snapshot["expected"]
    try:
        bindings = {
            "s25v_case_digest": s25v_input_digest(s25v_case),
            "s25v_result_digest": _digest(actual_s25v),
            "transition_kind": actual_s25v["transition_kind"],
            "before_projection_set_digest": actual_s25v["before_projection_set_digest"],
            "after_projection_set_digest": actual_s25v["after_projection_set_digest"],
            "before_projection_order_digest": actual_s25v["before_projection_order_digest"],
            "after_projection_order_digest": actual_s25v["after_projection_order_digest"],
            "required_member_count": len(ALLOWED_MEMBER_IDS),
        }
    except (KeyError, TypeError, ValueError):
        return _blocked("S25V_RESULT_BINDING_INVALID")
    if any(expected[field] != value for field, value in bindings.items()):
        return _blocked("EXPECTED_BINDING_MISMATCH", classification=PROJECTION_DELTA_CONFLICT)

    try:
        before_info, after_info = _member_digests(s25v_case)
    except _Failure as failure:
        return _blocked(failure.reason, classification=failure.classification)
    before, before_set_digest, before_order_digest = before_info
    after, after_set_digest, after_order_digest = after_info
    if (
        actual_s25v["before_projection_set_digest"] != before_set_digest
        or actual_s25v["after_projection_set_digest"] != after_set_digest
        or actual_s25v["before_projection_order_digest"] != before_order_digest
        or actual_s25v["after_projection_order_digest"] != after_order_digest
    ):
        return _blocked("S25V_RESULT_SEMANTIC_MISMATCH")
    changed = [member_id for member_id in ALLOWED_MEMBER_IDS if before[member_id] != after[member_id]]
    unchanged = [member_id for member_id in ALLOWED_MEMBER_IDS if member_id not in changed]
    allowed = list(NEXT_SEQUENCE_ALLOWED_MEMBER_IDS if actual_s25v["transition_kind"] == NEXT_SEQUENCE else NO_CHANGE_ALLOWED_MEMBER_IDS)
    delta_digest = _delta_digest(before, after, actual_s25v["transition_kind"])

    if actual_s25v["transition_kind"] == NO_CHANGE:
        if changed:
            return _blocked(
                "UNEXPECTED_MEMBER_DELTA",
                classification=PROJECTION_DELTA_CONFLICT,
                transition_kind=NO_CHANGE,
                changed_member_ids=changed,
                unchanged_member_ids=unchanged,
                allowed_changed_member_ids=allowed,
                changed_member_count=len(changed),
                before_set_digest=actual_s25v["before_projection_set_digest"],
                after_set_digest=actual_s25v["after_projection_set_digest"],
                before_order_digest=actual_s25v["before_projection_order_digest"],
                after_order_digest=actual_s25v["after_projection_order_digest"],
                delta_digest=delta_digest,
                s25v_case_digest=bindings["s25v_case_digest"],
                s25v_result_digest=bindings["s25v_result_digest"],
            )
        classification = PROJECTION_DELTA_NO_CHANGE
        reason = "NO_MEMBER_DELTA"
    elif actual_s25v["transition_kind"] == NEXT_SEQUENCE:
        if not changed:
            return _blocked(
                "NEXT_SEQUENCE_WITHOUT_DELTA",
                classification=PROJECTION_DELTA_CONFLICT,
                transition_kind=NEXT_SEQUENCE,
                changed_member_ids=changed,
                unchanged_member_ids=unchanged,
                allowed_changed_member_ids=allowed,
                changed_member_count=0,
                before_set_digest=actual_s25v["before_projection_set_digest"],
                after_set_digest=actual_s25v["after_projection_set_digest"],
                before_order_digest=actual_s25v["before_projection_order_digest"],
                after_order_digest=actual_s25v["after_projection_order_digest"],
                delta_digest=delta_digest,
                s25v_case_digest=bindings["s25v_case_digest"],
                s25v_result_digest=bindings["s25v_result_digest"],
            )
        forbidden = [member_id for member_id in changed if member_id not in allowed]
        if forbidden:
            return _blocked(
                "FORBIDDEN_MEMBER_DELTA",
                classification=PROJECTION_DELTA_CONFLICT,
                transition_kind=NEXT_SEQUENCE,
                changed_member_ids=changed,
                unchanged_member_ids=unchanged,
                allowed_changed_member_ids=allowed,
                changed_member_count=len(changed),
                before_set_digest=actual_s25v["before_projection_set_digest"],
                after_set_digest=actual_s25v["after_projection_set_digest"],
                before_order_digest=actual_s25v["before_projection_order_digest"],
                after_order_digest=actual_s25v["after_projection_order_digest"],
                delta_digest=delta_digest,
                s25v_case_digest=bindings["s25v_case_digest"],
                s25v_result_digest=bindings["s25v_result_digest"],
            )
        classification = PROJECTION_DELTA_NEXT_SEQUENCE
        reason = "ALLOWED_SUCCESSOR_DELTA"
    else:
        return _blocked("EVIDENCE_DEGRADED_NOT_POSITIVE", classification=PROJECTION_DELTA_PARTIAL)

    return _result(
        classification,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        reason,
        transition_kind=actual_s25v["transition_kind"],
        changed_member_ids=changed,
        unchanged_member_ids=unchanged,
        allowed_changed_member_ids=allowed,
        changed_member_count=len(changed),
        before_set_digest=actual_s25v["before_projection_set_digest"],
        after_set_digest=actual_s25v["after_projection_set_digest"],
        before_order_digest=actual_s25v["before_projection_order_digest"],
        after_order_digest=actual_s25v["after_projection_order_digest"],
        delta_digest=delta_digest,
        s25v_case_digest=bindings["s25v_case_digest"],
        s25v_result_digest=bindings["s25v_result_digest"],
    )


def evaluate_projection_delta(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Return a deterministic member-delta witness over a public S25V case."""

    try:
        return _evaluate(case)
    except _Failure as failure:
        return _blocked(failure.reason, classification=failure.classification)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


def input_digest(case: Mapping[str, Any]) -> str:
    snapshot = _snapshot(case)
    if not isinstance(snapshot, Mapping):
        raise ValueError("case must be a mapping")
    return _digest({key: value for key, value in snapshot.items() if key != "input_digest"})


__all__ = [
    "ALLOWED_MEMBER_IDS",
    "CANONICALIZATION",
    "CONTEXT_KEYS",
    "DELTA_SCHEMA",
    "FALSE_FLAGS",
    "HARNESS_SCHEMA",
    "INPUT_INVALID",
    "MEMBER_DIGEST_FIELDS",
    "MEMBER_KEYS",
    "NEXT_SEQUENCE_ALLOWED_MEMBER_IDS",
    "NO_CHANGE_ALLOWED_MEMBER_IDS",
    "PROJECTION_DELTA_CONFLICT",
    "PROJECTION_DELTA_NEXT_SEQUENCE",
    "PROJECTION_DELTA_NO_CHANGE",
    "PROJECTION_DELTA_PARTIAL",
    "PROJECTION_OUT_OF_WINDOW",
    "PROJECTION_SET_SCHEMA",
    "PROJECTION_STALE",
    "RESULT_KEYS",
    "S25V_REJECTED",
    "evaluate_projection_delta",
    "input_digest",
    "member_digest",
]
