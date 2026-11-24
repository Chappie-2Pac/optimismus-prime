"""Pure S25X claim-containment witness over the public S25W delta contract."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from support.w5_s25w_projection_delta import (
        ALLOWED_MEMBER_IDS,
        CANONICALIZATION as S25W_CANONICALIZATION,
        CONTEXT_KEYS,
        DELTA_SCHEMA as S25W_DELTA_SCHEMA,
        FALSE_FLAGS,
        HARNESS_SCHEMA as S25W_SCHEMA,
        MEMBER_DIGEST_FIELDS,
        MEMBER_KEYS,
        NEXT_SEQUENCE_ALLOWED_MEMBER_IDS,
        NO_CHANGE_ALLOWED_MEMBER_IDS,
        PROJECTION_DELTA_NEXT_SEQUENCE,
        PROJECTION_DELTA_NO_CHANGE,
        PROJECTION_SET_SCHEMA,
        RESULT_KEYS as S25W_RESULT_KEYS,
        evaluate_projection_delta,
        input_digest as s25w_input_digest,
        member_digest as s25w_member_digest,
    )
except ImportError:  # pragma: no cover - direct support-module execution
    from w5_s25w_projection_delta import (
        ALLOWED_MEMBER_IDS,
        CANONICALIZATION as S25W_CANONICALIZATION,
        CONTEXT_KEYS,
        DELTA_SCHEMA as S25W_DELTA_SCHEMA,
        FALSE_FLAGS,
        HARNESS_SCHEMA as S25W_SCHEMA,
        MEMBER_DIGEST_FIELDS,
        MEMBER_KEYS,
        NEXT_SEQUENCE_ALLOWED_MEMBER_IDS,
        NO_CHANGE_ALLOWED_MEMBER_IDS,
        PROJECTION_DELTA_NEXT_SEQUENCE,
        PROJECTION_DELTA_NO_CHANGE,
        PROJECTION_SET_SCHEMA,
        RESULT_KEYS as S25W_RESULT_KEYS,
        evaluate_projection_delta,
        input_digest as s25w_input_digest,
        member_digest as s25w_member_digest,
    )


HARNESS_SCHEMA = "s25x.delta-claim-containment.v1"
CANONICALIZATION = S25W_CANONICALIZATION
TEST_ONLY = "TEST_ONLY"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

CLAIM_SCOPE = "S25W_MEMBER_DELTA_ONLY"
UNSUPPORTED_SCOPE = "UNSUPPORTED"
DELTA_CLAIM_CONTAINED = "DELTA_CLAIM_CONTAINED"
CLAIM_NOT_CONTAINED = "CLAIM_NOT_CONTAINED"
CLAIM_SCOPE_UNSUPPORTED = "CLAIM_SCOPE_UNSUPPORTED"
S25W_REJECTED = "S25W_REJECTED"
INPUT_INVALID = "INPUT_INVALID"

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
        "s25w_case",
        "s25w_output",
        "claim",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset({"s25w_case_digest", "s25w_result_digest", "claim_digest", "required_member_count"})
_CLAIM_KEYS = frozenset(
    {
        "claim_scope",
        "s25w_case_digest",
        "s25w_result_digest",
        "classification",
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
        "production_status",
        "authority_claim",
        *FALSE_FLAGS,
    }
)
_WITNESS_KEYS = frozenset(
    {"s25t_output", "s25r_output", "context", "members", "projection_set_digest", "projection_order_digest"}
)
_PROVENANCE_KEYS = frozenset(
    {
        "member_id",
        "before_member_digest",
        "after_member_digest",
        "before_value_digest",
        "after_value_digest",
        "before_context_digest",
        "after_context_digest",
        "changed",
    }
)
_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "claim_scope",
        "transition_kind",
        "member_provenance",
        "changed_member_ids",
        "unchanged_member_ids",
        "changed_member_count",
        "s25w_case_digest",
        "s25w_result_digest",
        "claim_digest",
        "production_status",
        "authority_claim",
        *FALSE_FLAGS,
    }
)
_ZERO_HASH = "0" * 64
_POSITIVE_S25W_CLASSES = {PROJECTION_DELTA_NO_CHANGE, PROJECTION_DELTA_NEXT_SEQUENCE}
CLAIM_KEYS = tuple(sorted(_CLAIM_KEYS))
PROVENANCE_KEYS = tuple(sorted(_PROVENANCE_KEYS))
RESULT_KEYS = tuple(sorted(_OUTPUT_KEYS))


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
            if len(value) > _MAX_CONTAINER_ITEMS:
                raise ValueError("mapping too large")
            result: dict[str, Any] = {}
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
        return len(value) <= _MAX_STRING and not any("\ud800" <= char <= "\udfff" for char in value) and not _ABSOLUTE_PATH.match(value) and not value.startswith("\\\\") and not _URI_SCHEME.match(value)
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
            return all(isinstance(key, str) and len(key) <= _MAX_KEY_LENGTH and _safe_value(item, depth=depth + 1, active=active) for key, item in value.items())
        if isinstance(value, (list, tuple)):
            return len(value) <= _MAX_CONTAINER_ITEMS and all(_safe_value(item, depth=depth + 1, active=active) for item in value)
        return False
    except Exception:
        return False
    finally:
        active.remove(marker)


def _exact(value: Any, keys: frozenset[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == set(keys)


def _strict_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping):
        return set(left) == set(right) and all(_strict_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_strict_equal(item, other) for item, other in zip(left, right))
    return left == right


def _hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_HASH64.fullmatch(value))


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= _MAX_INTEGER


def _result(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    claim_scope: str = CLAIM_SCOPE,
    transition_kind: str = "UNKNOWN",
    member_provenance: list[dict[str, Any]] | None = None,
    changed_member_ids: list[str] | None = None,
    unchanged_member_ids: list[str] | None = None,
    changed_member_count: int = 0,
    s25w_case_digest: str = _ZERO_HASH,
    s25w_result_digest: str = _ZERO_HASH,
    claim_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": TEST_ONLY,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "claim_scope": claim_scope,
        "transition_kind": transition_kind,
        "member_provenance": list(member_provenance or []),
        "changed_member_ids": list(changed_member_ids or []),
        "unchanged_member_ids": list(unchanged_member_ids or []),
        "changed_member_count": changed_member_count,
        "s25w_case_digest": s25w_case_digest,
        "s25w_result_digest": s25w_result_digest,
        "claim_digest": claim_digest,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
        **{field: False for field in FALSE_FLAGS},
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _result(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(reason: str, *, classification: str = S25W_REJECTED, **kwargs: Any) -> dict[str, Any]:
    if classification == CLAIM_SCOPE_UNSUPPORTED:
        kwargs.setdefault("claim_scope", UNSUPPORTED_SCOPE)
    return _result(classification, TEST_BLOCKED, HOLD, reason, **kwargs)


def _claim_from_output(
    output: Mapping[str, Any], *, s25w_case_digest: str, s25w_result_digest: str
) -> dict[str, Any]:
    fields = (
        "classification",
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
        "production_status",
        "authority_claim",
    )
    return {
        "claim_scope": CLAIM_SCOPE,
        "s25w_case_digest": s25w_case_digest,
        "s25w_result_digest": s25w_result_digest,
        **{field: output[field] for field in fields},
        **{field: output[field] for field in FALSE_FLAGS},
    }


def _valid_s25w_result(output: Any) -> bool:
    if not isinstance(output, Mapping) or not _exact(output, frozenset(S25W_RESULT_KEYS)) or not _safe_value(output):
        return False
    if output.get("schema_version") != S25W_SCHEMA or output.get("observation_mode") != TEST_ONLY:
        return False
    if output.get("classification") not in _POSITIVE_S25W_CLASSES or output.get("status") != PROPOSAL_ONLY or output.get("decision") != DESIGN_ONLY:
        return False
    if output.get("production_status") != PRODUCTION_NOT_AUTHORIZED or output.get("authority_claim") != NOT_CLAIMED:
        return False
    if not _hash(output.get("s25v_case_digest")) or not _hash(output.get("s25v_result_digest")) or not _hash(output.get("delta_digest")):
        return False
    if output.get("transition_kind") not in {"NO_CHANGE", "NEXT_SEQUENCE"} or not _integer(output.get("changed_member_count")) or output.get("changed_member_count") < 0:
        return False
    if not isinstance(output.get("changed_member_ids"), list) or not isinstance(output.get("unchanged_member_ids"), list) or not isinstance(output.get("allowed_changed_member_ids"), list):
        return False
    return all(output.get(field) is False for field in FALSE_FLAGS)


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    for field in ("s25w_case_digest", "s25w_result_digest", "claim_digest"):
        if not _hash(expected.get(field)):
            return "EXPECTED_DIGEST_INVALID"
    if not _integer(expected.get("required_member_count")) or expected["required_member_count"] != len(ALLOWED_MEMBER_IDS):
        return "EXPECTED_MEMBER_COUNT_INVALID"
    return None


def _member_provenance(s25w_case: Mapping[str, Any], output: Mapping[str, Any]) -> list[dict[str, Any]]:
    s25v_case = s25w_case.get("s25v_case")
    if not isinstance(s25v_case, Mapping):
        raise _Failure(S25W_REJECTED, "S25V_CASE_INVALID")
    sides: list[dict[str, Mapping[str, Any]]] = []
    for side in ("before_witness", "after_witness"):
        witness = s25v_case.get(side)
        if not isinstance(witness, Mapping) or not _exact(witness, _WITNESS_KEYS) or not _safe_value(witness):
            raise _Failure(S25W_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
        context = witness.get("context")
        if not isinstance(context, Mapping) or not _exact(context, frozenset(CONTEXT_KEYS)) or not _safe_value(context):
            raise _Failure(S25W_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
        context_digest = _digest(context)
        members = witness.get("members")
        if not isinstance(members, list) or len(members) != len(ALLOWED_MEMBER_IDS):
            raise _Failure(S25W_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
        by_id: dict[str, Mapping[str, Any]] = {}
        ids: list[str] = []
        for member in members:
            if not isinstance(member, Mapping) or not _exact(member, frozenset(MEMBER_KEYS)) or not _safe_value(member):
                raise _Failure(S25W_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
            member_id = member.get("member_id")
            if (
                not isinstance(member_id, str)
                or member_id not in ALLOWED_MEMBER_IDS
                or member_id in by_id
                or member.get("observation_state") != "PRESENT"
                or member.get("context_digest") != context_digest
                or not _hash(member.get("value_digest"))
                or not _hash(member.get("context_digest"))
                or not _hash(member.get("member_digest"))
            ):
                raise _Failure(S25W_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
            try:
                if s25w_member_digest(member) != member["member_digest"]:
                    raise _Failure(S25W_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
            except Exception as exc:
                raise _Failure(S25W_REJECTED, "S25V_MEMBER_WITNESS_INVALID") from exc
            ids.append(member_id)
            by_id[member_id] = member
        if ids != list(ALLOWED_MEMBER_IDS):
            raise _Failure(S25W_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
        digests = [by_id[member_id]["member_digest"] for member_id in ALLOWED_MEMBER_IDS]
        expected_set = _digest({"schema": PROJECTION_SET_SCHEMA, "member_digests": sorted(digests)})
        expected_order = _digest({"schema": PROJECTION_SET_SCHEMA, "member_digests": digests})
        if witness.get("projection_set_digest") != expected_set or witness.get("projection_order_digest") != expected_order:
            raise _Failure(S25W_REJECTED, "S25V_MEMBER_WITNESS_INVALID")
        sides.append(by_id)
    before, after = sides
    provenance: list[dict[str, Any]] = []
    changed: list[str] = []
    unchanged: list[str] = []
    for member_id in ALLOWED_MEMBER_IDS:
        before_member = before[member_id]
        after_member = after[member_id]
        changed_value = before_member["member_digest"] != after_member["member_digest"]
        item = {
            "member_id": member_id,
            "before_member_digest": before_member["member_digest"],
            "after_member_digest": after_member["member_digest"],
            "before_value_digest": before_member["value_digest"],
            "after_value_digest": after_member["value_digest"],
            "before_context_digest": before_member["context_digest"],
            "after_context_digest": after_member["context_digest"],
            "changed": changed_value,
        }
        provenance.append(item)
        (changed if changed_value else unchanged).append(member_id)
    if changed != output.get("changed_member_ids") or unchanged != output.get("unchanged_member_ids") or len(changed) != output.get("changed_member_count"):
        raise _Failure(S25W_REJECTED, "S25W_MEMBER_DELTA_MISMATCH")
    before_digests = [before[member_id]["member_digest"] for member_id in ALLOWED_MEMBER_IDS]
    after_digests = [after[member_id]["member_digest"] for member_id in ALLOWED_MEMBER_IDS]
    expected_before_set = _digest({"schema": PROJECTION_SET_SCHEMA, "member_digests": sorted(before_digests)})
    expected_after_set = _digest({"schema": PROJECTION_SET_SCHEMA, "member_digests": sorted(after_digests)})
    expected_before_order = _digest({"schema": PROJECTION_SET_SCHEMA, "member_digests": before_digests})
    expected_after_order = _digest({"schema": PROJECTION_SET_SCHEMA, "member_digests": after_digests})
    delta_members = [
        {
            "member_id": member_id,
            "before_member_digest": before[member_id]["member_digest"],
            "after_member_digest": after[member_id]["member_digest"],
            "changed": before[member_id]["member_digest"] != after[member_id]["member_digest"],
        }
        for member_id in ALLOWED_MEMBER_IDS
    ]
    expected_delta = _digest(
        {"schema": S25W_DELTA_SCHEMA, "transition_kind": output["transition_kind"], "members": delta_members}
    )
    if output["transition_kind"] == "NO_CHANGE":
        expected_classification = PROJECTION_DELTA_NO_CHANGE
        expected_allowed = list(NO_CHANGE_ALLOWED_MEMBER_IDS)
        transition_valid = not changed
    elif output["transition_kind"] == "NEXT_SEQUENCE":
        expected_classification = PROJECTION_DELTA_NEXT_SEQUENCE
        expected_allowed = list(NEXT_SEQUENCE_ALLOWED_MEMBER_IDS)
        transition_valid = bool(changed) and all(member_id in expected_allowed for member_id in changed)
    else:  # pragma: no cover - guarded by _valid_s25w_result
        transition_valid = False
        expected_classification = ""
        expected_allowed = []
    if (
        not transition_valid
        or output["classification"] != expected_classification
        or output["allowed_changed_member_ids"] != expected_allowed
        or output["before_projection_set_digest"] != expected_before_set
        or output["after_projection_set_digest"] != expected_after_set
        or output["before_projection_order_digest"] != expected_before_order
        or output["after_projection_order_digest"] != expected_after_order
        or output["delta_digest"] != expected_delta
    ):
        raise _Failure(S25W_REJECTED, "S25W_DELTA_SEMANTIC_MISMATCH")
    return provenance


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
        return _invalid(expected_error)
    s25w_case = snapshot["s25w_case"]
    if not isinstance(s25w_case, Mapping) or not _safe_value(s25w_case):
        return _blocked("S25W_CASE_INVALID")
    try:
        if not _hash(s25w_case.get("input_digest")) or s25w_case["input_digest"] != s25w_input_digest(s25w_case):
            return _blocked("S25W_CASE_DIGEST_DRIFT")
        actual_s25w = _snapshot(evaluate_projection_delta(s25w_case))
    except Exception:
        return _blocked("S25W_RESULT_UNREADABLE")
    if not _strict_equal(snapshot["s25w_output"], actual_s25w):
        return _blocked("S25W_RESULT_MISMATCH")
    if not _valid_s25w_result(actual_s25w):
        return _blocked("S25W_NOT_POSITIVE", classification=CLAIM_NOT_CONTAINED)
    bindings = {
        "s25w_case_digest": s25w_input_digest(s25w_case),
        "s25w_result_digest": _digest(actual_s25w),
        "required_member_count": len(ALLOWED_MEMBER_IDS),
    }
    if any(snapshot["expected"][field] != value for field, value in bindings.items()):
        return _blocked("EXPECTED_BINDING_MISMATCH", classification=CLAIM_NOT_CONTAINED)
    claim = snapshot["claim"]
    if not isinstance(claim, Mapping) or not _exact(claim, _CLAIM_KEYS) or not _safe_value(claim):
        return _invalid("CLAIM_SCHEMA_NOT_EXACT")
    if claim.get("claim_scope") != CLAIM_SCOPE:
        return _blocked("CLAIM_SCOPE_UNSUPPORTED", classification=CLAIM_SCOPE_UNSUPPORTED)
    expected_claim = _claim_from_output(
        actual_s25w,
        s25w_case_digest=bindings["s25w_case_digest"],
        s25w_result_digest=bindings["s25w_result_digest"],
    )
    if not _strict_equal(claim, expected_claim):
        return _blocked("CLAIM_NOT_BOUND", classification=CLAIM_NOT_CONTAINED)
    claim_digest = _digest(claim)
    if snapshot["expected"]["claim_digest"] != claim_digest:
        return _blocked("CLAIM_DIGEST_MISMATCH", classification=CLAIM_NOT_CONTAINED)
    try:
        provenance = _member_provenance(s25w_case, actual_s25w)
    except _Failure as failure:
        return _blocked(failure.reason, classification=failure.classification)
    return _result(
        DELTA_CLAIM_CONTAINED,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        "S25W_MEMBER_DELTA_ONLY",
        transition_kind=actual_s25w["transition_kind"],
        member_provenance=provenance,
        changed_member_ids=actual_s25w["changed_member_ids"],
        unchanged_member_ids=actual_s25w["unchanged_member_ids"],
        changed_member_count=actual_s25w["changed_member_count"],
        s25w_case_digest=bindings["s25w_case_digest"],
        s25w_result_digest=bindings["s25w_result_digest"],
        claim_digest=claim_digest,
    )


def evaluate_delta_claim_containment(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Contain a downstream claim to the public S25W member-delta evidence."""

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
    "CANONICALIZATION",
    "CLAIM_KEYS",
    "CLAIM_NOT_CONTAINED",
    "CLAIM_SCOPE",
    "CLAIM_SCOPE_UNSUPPORTED",
    "DELTA_CLAIM_CONTAINED",
    "FALSE_FLAGS",
    "HARNESS_SCHEMA",
    "INPUT_INVALID",
    "ALLOWED_MEMBER_IDS",
    "MEMBER_DIGEST_FIELDS",
    "NEXT_SEQUENCE_ALLOWED_MEMBER_IDS",
    "NO_CHANGE_ALLOWED_MEMBER_IDS",
    "PROVENANCE_KEYS",
    "RESULT_KEYS",
    "S25W_REJECTED",
    "UNSUPPORTED_SCOPE",
    "evaluate_delta_claim_containment",
    "input_digest",
]
