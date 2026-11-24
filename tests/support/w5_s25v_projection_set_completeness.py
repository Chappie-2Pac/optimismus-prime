"""Pure S25V completeness gate for public S25U/T/R provenance witnesses."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from support.w5_s25r_receipt_reconciliation import (
        CANONICALIZATION as S25R_CANONICALIZATION,
        HARNESS_SCHEMA as S25R_SCHEMA,
        evaluate_receipt_reconciliation,
        input_digest as s25r_input_digest,
    )
    from support.w5_s25t_receipt_provenance import (
        CANONICALIZATION as S25T_CANONICALIZATION,
        HARNESS_SCHEMA as S25T_SCHEMA,
        evaluate_receipt_provenance,
        input_digest as s25t_input_digest,
    )
    from support.w5_s25u_provenance_monotonicity import (
        CANONICALIZATION as S25U_CANONICALIZATION,
        HARNESS_SCHEMA as S25U_SCHEMA,
        evaluate_provenance_monotonicity,
        input_digest as s25u_input_digest,
    )
except ImportError:  # pragma: no cover - direct support-module execution
    from w5_s25r_receipt_reconciliation import (
        CANONICALIZATION as S25R_CANONICALIZATION,
        HARNESS_SCHEMA as S25R_SCHEMA,
        evaluate_receipt_reconciliation,
        input_digest as s25r_input_digest,
    )
    from w5_s25t_receipt_provenance import (
        CANONICALIZATION as S25T_CANONICALIZATION,
        HARNESS_SCHEMA as S25T_SCHEMA,
        evaluate_receipt_provenance,
        input_digest as s25t_input_digest,
    )
    from w5_s25u_provenance_monotonicity import (
        CANONICALIZATION as S25U_CANONICALIZATION,
        HARNESS_SCHEMA as S25U_SCHEMA,
        evaluate_provenance_monotonicity,
        input_digest as s25u_input_digest,
    )


HARNESS_SCHEMA = "s25v.projection-set-completeness.v1"
CANONICALIZATION = S25U_CANONICALIZATION
TEST_ONLY = "TEST_ONLY"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
HOLD = "HOLD"
DESIGN_ONLY = "DESIGN_ONLY"
MANUAL_REVIEW = "MANUAL_REVIEW"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

PROJECTION_SET_COMPLETE = "PROJECTION_SET_COMPLETE"
PROJECTION_PARTIAL = "PROJECTION_PARTIAL"
PROJECTION_REJECTED = "PROJECTION_REJECTED"
PROJECTION_CONFLICT = "PROJECTION_CONFLICT"
PROJECTION_STALE = "PROJECTION_STALE"
PROJECTION_OUT_OF_WINDOW = "PROJECTION_OUT_OF_WINDOW"
INPUT_INVALID = "INPUT_INVALID"
S25U_REJECTED = "S25U_REJECTED"
S25T_REJECTED = "S25T_REJECTED"
S25R_REJECTED = "S25R_REJECTED"

_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_MAX_DEPTH = 64
_MAX_STRING = 4096
_MAX_INTEGER = 2**63 - 1

_STATUS_DECISIONS = {PROPOSAL_ONLY: DESIGN_ONLY, TEST_BLOCKED: HOLD, RECOVERY_REQUIRED: MANUAL_REVIEW}
_TRANSITIONS = {"NO_CHANGE", "NEXT_SEQUENCE", "EVIDENCE_DEGRADED"}
_FALSE_FLAGS = (
    "capability_issued",
    "write_authorized",
    "mutation_allowed",
    "persistence_performed",
    "cas_attempted",
    "fence_issued",
    "resume_allowed",
    "receipt_emitted",
    "receipt_committed",
    "commit_authorized",
    "floor_advanced",
)

_CONTEXT_KEYS = frozenset(
    {
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "previous_sequence",
        "current_sequence",
        "observation_id",
        "idempotency_key",
        "observer_id",
        "comparison_group",
        "s25t_case_digest",
        "s25t_result_digest",
        "s25r_case_digest",
        "s25r_result_digest",
        "s25r_projection_digest",
        "source_set_digest",
        "window_digest",
        "observation_set_digest",
    }
)

# This tuple is the authority of the test-only completeness contract. The
# caller may echo it, but may not define or extend it.
_MEMBER_FIELDS = (
    ("S25T_CASE_DIGEST", ("s25t_case_digest",)),
    ("S25T_RESULT_DIGEST", ("s25t_result_digest",)),
    ("S25R_CASE_DIGEST", ("s25r_case_digest",)),
    ("S25R_RESULT_DIGEST", ("s25r_result_digest",)),
    ("S25R_PROJECTION_DIGEST", ("s25r_projection_digest",)),
    ("SOURCE_SET_DIGEST", ("source_set_digest",)),
    ("WINDOW_DIGEST", ("window_digest",)),
    ("OBSERVATION_SET_DIGEST", ("observation_set_digest",)),
    ("IDENTITY", ("subject_digest", "scope_digest", "baseline_digest", "observer_id", "comparison_group")),
    ("EPOCH_SEQUENCE", ("epoch", "previous_sequence", "current_sequence")),
    ("OBSERVATION_KEYS", ("observation_id", "idempotency_key")),
    (
        "QUALITY",
        (
            "classification",
            "status",
            "decision",
            "reason",
            "provenance_status",
            "coverage_status",
            "freshness_status",
            "comparison_status",
            "source_count",
            "observation_count",
            "witness_only",
            "source_witnessed",
            "s25r_classification",
            "s25r_status",
            "s25r_reconciliation_status",
        ),
    ),
    ("SECURITY", ("production_status", "authority_claim", *_FALSE_FLAGS)),
)
ALLOWED_MEMBER_IDS = tuple(member_id for member_id, _ in _MEMBER_FIELDS)
FALSE_FLAGS = _FALSE_FLAGS
CONTEXT_KEYS = tuple(sorted(_CONTEXT_KEYS))
MEMBER_FIELDS = _MEMBER_FIELDS

_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "s25u_case",
        "s25u_output",
        "allowed_member_ids",
        "before_witness",
        "after_witness",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "s25u_case_digest",
        "s25u_result_digest",
        "before_s25t_case_digest",
        "after_s25t_case_digest",
        "before_s25t_result_digest",
        "after_s25t_result_digest",
        "before_s25r_case_digest",
        "after_s25r_case_digest",
        "before_s25r_result_digest",
        "after_s25r_result_digest",
        "before_s25r_projection_digest",
        "after_s25r_projection_digest",
        "before_context_digest",
        "after_context_digest",
        "before_projection_set_digest",
        "after_projection_set_digest",
        "before_projection_order_digest",
        "after_projection_order_digest",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "observer_id",
        "comparison_group",
        "epoch",
        "before_sequence",
        "after_sequence",
        "transition_kind",
        "required_member_count",
    }
)
_WITNESS_KEYS = frozenset({"s25t_output", "s25r_output", "context", "members", "projection_set_digest", "projection_order_digest"})
PROJECTION_SET_SCHEMA = "s25v.projection-set.v1"
MEMBER_KEYS = ("member_id", "observation_state", "value_digest", "context_digest", "member_digest")
MEMBER_DIGEST_FIELDS = ("member_id", "observation_state", "value_digest", "context_digest")
RESULT_KEYS = (
    "schema_version",
    "observation_mode",
    "classification",
    "status",
    "decision",
    "reason",
    "transition_kind",
    "completeness_status",
    "before_member_count",
    "after_member_count",
    "required_member_count",
    "before_projection_set_digest",
    "after_projection_set_digest",
    "before_projection_order_digest",
    "after_projection_order_digest",
    "production_status",
    "authority_claim",
    *_FALSE_FLAGS,
)
_MEMBER_KEYS = frozenset(MEMBER_KEYS)
_RESULT_KEYS = frozenset(RESULT_KEYS)
_S25U_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "transition_kind",
        "monotonicity_status",
        "before_status",
        "after_status",
        "before_provenance_status",
        "after_provenance_status",
        "before_sequence",
        "after_sequence",
        "production_status",
        "authority_claim",
        *_FALSE_FLAGS,
    }
)
_S25T_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "provenance_status",
        "coverage_status",
        "freshness_status",
        "comparison_status",
        "source_count",
        "observation_count",
        "witness_only",
        "source_witnessed",
        "s25r_classification",
        "s25r_status",
        "s25r_reconciliation_status",
        "production_status",
        "authority_claim",
        *_FALSE_FLAGS,
    }
)
_S25R_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "reconciliation_status",
        "receipt_count",
        "receipt_witnessed",
        "witness_only",
        "s25q_classification",
        "s25q_status",
        "production_status",
        "authority_claim",
        *_FALSE_FLAGS,
    }
)


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
        return json.loads(value.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_constant)
    if isinstance(value, str):
        return json.loads(value, object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_constant)
    raise TypeError("case must be a mapping, bytes or JSON string")


def _snapshot(value: Any, *, depth: int = 0, active: set[int] | None = None) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("value too deep")
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
            for key, item in value.items():
                if not isinstance(key, str) or key in result:
                    raise ValueError("invalid mapping key")
                result[key] = _snapshot(item, depth=depth + 1, active=active)
            return result
        if isinstance(value, (list, tuple)):
            return [_snapshot(item, depth=depth + 1, active=active) for item in value]
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


def _text(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= _MAX_STRING and not _ABSOLUTE_PATH.match(value) and not value.startswith("\\\\") and not _URI_SCHEME.match(value)


def _integer(value: Any, *, positive: bool = False) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= _MAX_INTEGER and (not positive or value > 0)


def _output(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    transition_kind: str = "UNKNOWN",
    before_member_count: int = 0,
    after_member_count: int = 0,
    before_set_digest: str = "0" * 64,
    after_set_digest: str = "0" * 64,
    before_order_digest: str = "0" * 64,
    after_order_digest: str = "0" * 64,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": TEST_ONLY,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "transition_kind": transition_kind,
        "completeness_status": "COMPLETE" if classification == PROJECTION_SET_COMPLETE else ("PARTIAL" if classification == PROJECTION_PARTIAL else "NOT_CLAIMED"),
        "before_member_count": before_member_count,
        "after_member_count": after_member_count,
        "required_member_count": len(ALLOWED_MEMBER_IDS),
        "before_projection_set_digest": before_set_digest,
        "after_projection_set_digest": after_set_digest,
        "before_projection_order_digest": before_order_digest,
        "after_projection_order_digest": after_order_digest,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
        **{field: False for field in _FALSE_FLAGS},
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _output(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(reason: str, *, classification: str = PROJECTION_REJECTED, **kwargs: Any) -> dict[str, Any]:
    return _output(classification, TEST_BLOCKED, HOLD, reason, **kwargs)


def _review(reason: str, *, classification: str = PROJECTION_CONFLICT, **kwargs: Any) -> dict[str, Any]:
    return _output(classification, RECOVERY_REQUIRED, MANUAL_REVIEW, reason, **kwargs)


def _valid_s25u_result(result: Any) -> bool:
    if not isinstance(result, Mapping) or not _exact(result, _S25U_RESULT_KEYS) or not _safe_value(result):
        return False
    if result.get("schema_version") != S25U_SCHEMA or result.get("observation_mode") != TEST_ONLY:
        return False
    if result.get("classification") != "PROVENANCE_PROJECTION_MONOTONIC" or result.get("status") != PROPOSAL_ONLY or result.get("decision") != DESIGN_ONLY:
        return False
    if result.get("transition_kind") not in {"NO_CHANGE", "NEXT_SEQUENCE", "EVIDENCE_DEGRADED"} or result.get("production_status") != PRODUCTION_NOT_AUTHORIZED or result.get("authority_claim") != NOT_CLAIMED:
        return False
    expected_monotonicity = "SAFE_DOWNGRADE" if result.get("transition_kind") == "EVIDENCE_DEGRADED" else "UNCHANGED_OR_NEXT"
    if result.get("monotonicity_status") != expected_monotonicity:
        return False
    if not all(result.get(field) is False for field in _FALSE_FLAGS):
        return False
    return all(_integer(result.get(field)) for field in ("before_sequence", "after_sequence")) and _text(result.get("reason"))


def _valid_s25t_result(result: Any) -> bool:
    if not isinstance(result, Mapping) or not _exact(result, _S25T_RESULT_KEYS) or not _safe_value(result):
        return False
    return (
        result.get("schema_version") == S25T_SCHEMA
        and result.get("observation_mode") == TEST_ONLY
        and result.get("classification") == "PROVENANCE_WITNESS_RECONCILED"
        and result.get("status") == PROPOSAL_ONLY
        and result.get("decision") == DESIGN_ONLY
        and result.get("reason") == "READ_ONLY_PROVENANCE_WITNESS"
        and result.get("provenance_status") == "COMPLETE"
        and result.get("coverage_status") == "COMPLETE"
        and result.get("freshness_status") == "FRESH"
        and result.get("comparison_status") == "COMPARABLE"
        and result.get("source_count") == 6
        and result.get("observation_count") == 6
        and result.get("witness_only") is True
        and result.get("source_witnessed") is True
        and result.get("s25r_classification") == "RECEIPT_BUNDLE_RECONCILED"
        and result.get("s25r_status") == PROPOSAL_ONLY
        and result.get("s25r_reconciliation_status") == "CONSISTENT"
        and result.get("production_status") == PRODUCTION_NOT_AUTHORIZED
        and result.get("authority_claim") == NOT_CLAIMED
        and all(result.get(field) is False for field in _FALSE_FLAGS)
    )


def _valid_s25r_result(result: Any) -> bool:
    if not isinstance(result, Mapping) or not _exact(result, _S25R_RESULT_KEYS) or not _safe_value(result):
        return False
    return (
        result.get("schema_version") == S25R_SCHEMA
        and result.get("observation_mode") == TEST_ONLY
        and result.get("classification") == "RECEIPT_BUNDLE_RECONCILED"
        and result.get("status") == PROPOSAL_ONLY
        and result.get("decision") == DESIGN_ONLY
        and result.get("reason") == "READ_ONLY_WITNESS_ONLY"
        and result.get("reconciliation_status") == "CONSISTENT"
        and result.get("receipt_count") == 6
        and result.get("receipt_witnessed") is True
        and result.get("witness_only") is True
        and result.get("s25q_classification") == "FLOOR_ADVANCE_ELIGIBLE"
        and result.get("s25q_status") == "LOCKED_TEST_PASS"
        and result.get("production_status") == PRODUCTION_NOT_AUTHORIZED
        and result.get("authority_claim") == NOT_CLAIMED
        and all(result.get(field) is False for field in _FALSE_FLAGS)
    )


def _projection_from_s25t(case: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any] | None:
    expected = case.get("expected")
    if not isinstance(expected, Mapping):
        return None
    try:
        projection: dict[str, Any] = {
            "schema": "s25u.s25t-projection.v1",
            "s25t_case_digest": s25t_input_digest(case),
            "s25t_result_digest": _digest(result),
            "s25r_case_digest": expected["s25r_case_digest"],
            "s25r_result_digest": expected["s25r_result_digest"],
            "s25r_projection_digest": expected["s25r_projection_digest"],
            "source_set_digest": expected["source_set_digest"],
            "window_digest": expected["window_digest"],
            "observation_set_digest": expected["observation_set_digest"],
            "classification": result["classification"],
            "status": result["status"],
            "decision": result["decision"],
            "reason": result["reason"],
            "provenance_status": result["provenance_status"],
            "coverage_status": result["coverage_status"],
            "freshness_status": result["freshness_status"],
            "comparison_status": result["comparison_status"],
            "source_count": result["source_count"],
            "observation_count": result["observation_count"],
            "witness_only": result["witness_only"],
            "source_witnessed": result["source_witnessed"],
            "s25r_classification": result["s25r_classification"],
            "s25r_status": result["s25r_status"],
            "s25r_reconciliation_status": result["s25r_reconciliation_status"],
            "production_status": result["production_status"],
            "authority_claim": result["authority_claim"],
            **{field: result[field] for field in _FALSE_FLAGS},
            "subject_digest": expected["subject_digest"],
            "scope_digest": expected["scope_digest"],
            "baseline_digest": expected["baseline_digest"],
            "epoch": expected["epoch"],
            "previous_sequence": expected["previous_sequence"],
            "current_sequence": expected["current_sequence"],
            "observation_id": expected["observation_id"],
            "idempotency_key": expected["idempotency_key"],
            "observer_id": expected["observer_id"],
            "comparison_group": expected["comparison_group"],
        }
        projection["projection_digest"] = _digest(projection)
        return projection
    except (KeyError, TypeError, ValueError):
        return None


def _context(projection: Mapping[str, Any]) -> dict[str, Any]:
    return {key: projection[key] for key in sorted(_CONTEXT_KEYS)}


def _member_value(projection: Mapping[str, Any], fields: tuple[str, ...]) -> str:
    return _digest({field: projection[field] for field in fields})


def _member_digest(member: Mapping[str, Any]) -> str:
    return _digest({key: member[key] for key in MEMBER_DIGEST_FIELDS})


def _set_digest(member_digests: list[str]) -> str:
    return _digest({"schema": PROJECTION_SET_SCHEMA, "member_digests": sorted(member_digests)})


def _order_digest(member_digests: list[str]) -> str:
    return _digest({"schema": PROJECTION_SET_SCHEMA, "member_digests": member_digests})


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    for field in (
        "s25u_case_digest",
        "s25u_result_digest",
        "before_s25t_case_digest",
        "after_s25t_case_digest",
        "before_s25t_result_digest",
        "after_s25t_result_digest",
        "before_s25r_case_digest",
        "after_s25r_case_digest",
        "before_s25r_result_digest",
        "after_s25r_result_digest",
        "before_s25r_projection_digest",
        "after_s25r_projection_digest",
        "before_context_digest",
        "after_context_digest",
        "before_projection_set_digest",
        "after_projection_set_digest",
        "before_projection_order_digest",
        "after_projection_order_digest",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
    ):
        if not _hash(expected.get(field)):
            return "EXPECTED_DIGEST_INVALID"
    for field in ("epoch", "before_sequence", "after_sequence", "required_member_count"):
        if not _integer(expected.get(field), positive=True):
            return "EXPECTED_COUNTER_INVALID"
    if expected["required_member_count"] != len(ALLOWED_MEMBER_IDS):
        return "EXPECTED_MEMBER_COUNT_INVALID"
    if expected["transition_kind"] not in _TRANSITIONS:
        return "TRANSITION_KIND_INVALID"
    for field in ("observer_id", "comparison_group"):
        if not _text(expected.get(field)):
            return "EXPECTED_TEXT_INVALID"
    return None


def _validated_side(nested: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not isinstance(nested, Mapping) or not _safe_value(nested):
        raise _Failure(S25T_REJECTED, "S25T_CASE_INVALID")
    try:
        t_result = _snapshot(evaluate_receipt_provenance(nested))
    except Exception as exc:
        raise _Failure(S25T_REJECTED, "S25T_RESULT_UNREADABLE") from exc
    if not _valid_s25t_result(t_result):
        classification = t_result.get("classification") if isinstance(t_result, Mapping) else None
        if classification == "PROVENANCE_STALE":
            raise _Failure(PROJECTION_STALE, "S25T_STALE")
        if classification == "PROVENANCE_OUT_OF_WINDOW":
            raise _Failure(PROJECTION_OUT_OF_WINDOW, "S25T_OUT_OF_WINDOW")
        if classification == "PROVENANCE_CONFLICT":
            raise _Failure(PROJECTION_CONFLICT, "S25T_CONTEXT_CONFLICT")
        if classification == "PROVENANCE_PARTIAL":
            raise _Failure(PROJECTION_PARTIAL, "S25T_NOT_COMPLETE")
        raise _Failure(S25T_REJECTED, "S25T_RESULT_INVALID")
    r_case = nested.get("s25r_case")
    if not isinstance(r_case, Mapping) or not _safe_value(r_case):
        raise _Failure(S25R_REJECTED, "S25R_CASE_INVALID")
    try:
        r_result = _snapshot(evaluate_receipt_reconciliation(r_case))
    except Exception as exc:
        raise _Failure(S25R_REJECTED, "S25R_RESULT_UNREADABLE") from exc
    if not _valid_s25r_result(r_result):
        raise _Failure(S25R_REJECTED, "S25R_NOT_RECONCILIABLE")
    projection = _projection_from_s25t(nested, t_result)
    if projection is None:
        raise _Failure(S25T_REJECTED, "S25T_PROJECTION_INVALID")
    try:
        r_case_digest = s25r_input_digest(r_case)
    except Exception as exc:
        raise _Failure(S25R_REJECTED, "S25R_CASE_DIGEST_INVALID") from exc
    if projection["s25r_case_digest"] != r_case_digest or projection["s25r_result_digest"] != _digest(r_result):
        raise _Failure(S25R_REJECTED, "S25R_DIGEST_MISMATCH")
    if t_result["s25r_classification"] != r_result["classification"] or t_result["s25r_status"] != r_result["status"] or t_result["s25r_reconciliation_status"] != r_result["reconciliation_status"]:
        raise _Failure(S25R_REJECTED, "S25R_RESULT_BINDING_MISMATCH")
    return t_result, r_result, projection


def _validate_witness(
    witness: Any,
    projection: Mapping[str, Any],
    t_result: Mapping[str, Any],
    r_result: Mapping[str, Any],
) -> tuple[str, str, str, int]:
    if not isinstance(witness, Mapping) or not _exact(witness, _WITNESS_KEYS) or not _safe_value(witness):
        raise _Failure(INPUT_INVALID, "WITNESS_SCHEMA_NOT_EXACT")
    if witness["s25t_output"] != t_result or witness["s25r_output"] != r_result:
        raise _Failure(PROJECTION_REJECTED, "PUBLIC_WITNESS_OUTPUT_MISMATCH")
    context = witness["context"]
    if not isinstance(context, Mapping) or not _exact(context, _CONTEXT_KEYS) or not _safe_value(context):
        raise _Failure(PROJECTION_REJECTED, "WITNESS_CONTEXT_SCHEMA_INVALID")
    expected_context = _context(projection)
    if context != expected_context:
        raise _Failure(PROJECTION_CONFLICT, "WITNESS_CONTEXT_DRIFT")
    context_digest = _digest(expected_context)
    members = witness["members"]
    if not isinstance(members, list):
        raise _Failure(INPUT_INVALID, "MEMBERS_NOT_LIST")
    member_ids = [member.get("member_id") if isinstance(member, Mapping) else None for member in members]
    if len(member_ids) != len(set(member_ids)):
        raise _Failure(PROJECTION_REJECTED, "MEMBER_DUPLICATE")
    if len(member_ids) > len(ALLOWED_MEMBER_IDS):
        raise _Failure(PROJECTION_REJECTED, "MEMBER_EXTRA")
    if any(member_id not in ALLOWED_MEMBER_IDS for member_id in member_ids):
        raise _Failure(PROJECTION_REJECTED, "MEMBER_UNKNOWN")
    if len(member_ids) < len(ALLOWED_MEMBER_IDS):
        raise _Failure(PROJECTION_PARTIAL, "MEMBER_MISSING")
    if member_ids != list(ALLOWED_MEMBER_IDS):
        raise _Failure(PROJECTION_REJECTED, "MEMBER_ORDER_DRIFT")
    digests: list[str] = []
    for member, (member_id, fields) in zip(members, _MEMBER_FIELDS):
        if not isinstance(member, Mapping) or not _exact(member, _MEMBER_KEYS) or not _safe_value(member):
            raise _Failure(INPUT_INVALID, "MEMBER_SCHEMA_INVALID")
        if member["member_id"] != member_id or member["observation_state"] != "PRESENT":
            raise _Failure(PROJECTION_REJECTED, "MEMBER_PROFILE_INVALID")
        if member["context_digest"] != context_digest:
            raise _Failure(PROJECTION_CONFLICT, "MEMBER_CONTEXT_DRIFT")
        if member["value_digest"] != _member_value(projection, fields):
            raise _Failure(PROJECTION_REJECTED, "MEMBER_VALUE_MISMATCH")
        if not _hash(member["member_digest"]) or member["member_digest"] != _member_digest(member):
            raise _Failure(PROJECTION_REJECTED, "MEMBER_DIGEST_MISMATCH")
        digests.append(member["member_digest"])
    set_digest = _set_digest(digests)
    order_digest = _order_digest(digests)
    if witness["projection_set_digest"] != set_digest:
        raise _Failure(PROJECTION_REJECTED, "PROJECTION_SET_DIGEST_MISMATCH")
    if witness["projection_order_digest"] != order_digest:
        raise _Failure(PROJECTION_REJECTED, "PROJECTION_ORDER_DIGEST_MISMATCH")
    return context_digest, set_digest, order_digest, len(members)


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
        return _blocked(expected_error)
    if snapshot["allowed_member_ids"] != list(ALLOWED_MEMBER_IDS):
        return _blocked("ALLOWED_MEMBER_IDS_MISMATCH")

    s25u_case = snapshot["s25u_case"]
    if not isinstance(s25u_case, Mapping) or not _safe_value(s25u_case):
        return _blocked("S25U_CASE_INVALID", classification=S25U_REJECTED)
    try:
        actual_u_result = _snapshot(evaluate_provenance_monotonicity(s25u_case))
    except Exception as exc:
        raise _Failure(S25U_REJECTED, "S25U_RESULT_UNREADABLE") from exc
    if not isinstance(snapshot["s25u_output"], Mapping) or snapshot["s25u_output"] != actual_u_result:
        return _blocked("S25U_RESULT_MISMATCH", classification=S25U_REJECTED)
    if not _valid_s25u_result(actual_u_result):
        if isinstance(actual_u_result, Mapping) and actual_u_result.get("classification") == "PROVENANCE_PROJECTION_MONOTONIC" and actual_u_result.get("transition_kind") == "EVIDENCE_DEGRADED":
            return _blocked("S25U_DEGRADED_NOT_COMPLETE", classification=PROJECTION_PARTIAL)
        return _blocked("S25U_NOT_MONOTONIC", classification=S25U_REJECTED)

    try:
        before_t, before_r, before_projection = _validated_side(s25u_case["before_case"])
        after_t, after_r, after_projection = _validated_side(s25u_case["after_case"])
    except _Failure as failure:
        return _blocked(failure.reason, classification=failure.classification)

    if s25u_case.get("before_projection") != before_projection or s25u_case.get("after_projection") != after_projection:
        return _blocked("S25U_PROJECTION_MISMATCH", classification=S25U_REJECTED)
    transition = actual_u_result["transition_kind"]
    if transition == "EVIDENCE_DEGRADED":
        return _blocked("S25U_DEGRADED_NOT_COMPLETE", classification=PROJECTION_PARTIAL)
    if snapshot["expected"]["transition_kind"] != transition:
        return _blocked("TRANSITION_BINDING_MISMATCH")
    expected_u_semantics = {
        "before_status": before_projection["status"],
        "after_status": after_projection["status"],
        "before_provenance_status": before_projection["provenance_status"],
        "after_provenance_status": after_projection["provenance_status"],
        "before_sequence": before_projection["current_sequence"],
        "after_sequence": after_projection["current_sequence"],
    }
    if any(actual_u_result[field] != value for field, value in expected_u_semantics.items()):
        return _blocked("S25U_RESULT_SEMANTIC_MISMATCH", classification=S25U_REJECTED)

    try:
        before_context, before_set, before_order, before_count = _validate_witness(snapshot["before_witness"], before_projection, before_t, before_r)
        after_context, after_set, after_order, after_count = _validate_witness(snapshot["after_witness"], after_projection, after_t, after_r)
    except _Failure as failure:
        return _blocked(failure.reason, classification=failure.classification)

    expected = snapshot["expected"]
    bindings = {
        "s25u_case_digest": s25u_input_digest(s25u_case),
        "s25u_result_digest": _digest(actual_u_result),
        "before_s25t_case_digest": before_projection["s25t_case_digest"],
        "after_s25t_case_digest": after_projection["s25t_case_digest"],
        "before_s25t_result_digest": before_projection["s25t_result_digest"],
        "after_s25t_result_digest": after_projection["s25t_result_digest"],
        "before_s25r_case_digest": before_projection["s25r_case_digest"],
        "after_s25r_case_digest": after_projection["s25r_case_digest"],
        "before_s25r_result_digest": before_projection["s25r_result_digest"],
        "after_s25r_result_digest": after_projection["s25r_result_digest"],
        "before_s25r_projection_digest": before_projection["s25r_projection_digest"],
        "after_s25r_projection_digest": after_projection["s25r_projection_digest"],
        "before_context_digest": before_context,
        "after_context_digest": after_context,
        "before_projection_set_digest": before_set,
        "after_projection_set_digest": after_set,
        "before_projection_order_digest": before_order,
        "after_projection_order_digest": after_order,
        "subject_digest": before_projection["subject_digest"],
        "scope_digest": before_projection["scope_digest"],
        "baseline_digest": before_projection["baseline_digest"],
        "epoch": before_projection["epoch"],
        "before_sequence": before_projection["current_sequence"],
        "after_sequence": after_projection["current_sequence"],
        "observer_id": before_projection["observer_id"],
        "comparison_group": before_projection["comparison_group"],
        "required_member_count": len(ALLOWED_MEMBER_IDS),
    }
    for field, actual in bindings.items():
        if expected[field] != actual:
            if field in {"subject_digest", "scope_digest", "baseline_digest", "observer_id", "comparison_group"}:
                return _review("EXPECTED_IDENTITY_DRIFT")
            if field == "epoch":
                return _review("EXPECTED_EPOCH_DRIFT", classification=PROJECTION_OUT_OF_WINDOW)
            return _blocked("EXPECTED_BINDING_MISMATCH")
    common_fields = ("subject_digest", "scope_digest", "baseline_digest", "observer_id", "comparison_group", "epoch")
    if any(before_projection[field] != after_projection[field] for field in common_fields if field != "epoch"):
        return _review("IDENTITY_OR_CONTEXT_DRIFT")
    if before_projection["epoch"] != after_projection["epoch"]:
        return _review("EPOCH_DRIFT", classification=PROJECTION_OUT_OF_WINDOW)
    if transition == "NO_CHANGE":
        if before_projection != after_projection or before_context != after_context or before_set != after_set or before_order != after_order:
            return _review("NO_CHANGE_PROJECTION_SET_DRIFT")
    elif transition == "NEXT_SEQUENCE":
        if after_projection["previous_sequence"] != before_projection["current_sequence"] or after_projection["current_sequence"] != before_projection["current_sequence"] + 1:
            return _review("SEQUENCE_GAP_OR_ROLLBACK", classification=PROJECTION_OUT_OF_WINDOW)
        if before_t["status"] != PROPOSAL_ONLY or after_t["status"] != PROPOSAL_ONLY:
            return _blocked("NEXT_SEQUENCE_STATUS_NOT_POSITIVE")
        mutable_fields = {
            "s25t_case_digest",
            "s25t_result_digest",
            "s25r_case_digest",
            "s25r_result_digest",
            "s25r_projection_digest",
            "source_set_digest",
            "window_digest",
            "observation_set_digest",
            "previous_sequence",
            "current_sequence",
            "observation_id",
            "idempotency_key",
        }
        fixed_fields = set(_CONTEXT_KEYS) - mutable_fields
        if any(before_projection[field] != after_projection[field] for field in fixed_fields):
            return _review("NEXT_SEQUENCE_CONTEXT_DRIFT")
        quality_fields = (
            "classification",
            "status",
            "decision",
            "reason",
            "provenance_status",
            "coverage_status",
            "freshness_status",
            "comparison_status",
            "source_count",
            "observation_count",
            "witness_only",
            "source_witnessed",
            "s25r_classification",
            "s25r_status",
            "s25r_reconciliation_status",
            "production_status",
            "authority_claim",
            *_FALSE_FLAGS,
        )
        if any(before_projection[field] != after_projection[field] for field in quality_fields):
            return _review("NEXT_SEQUENCE_QUALITY_DRIFT")
    else:
        return _blocked("TRANSITION_NOT_COMPLETE", classification=PROJECTION_PARTIAL)
    return _output(
        PROJECTION_SET_COMPLETE,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        "COMPLETE_PROJECTION_SET",
        transition_kind=transition,
        before_member_count=int(before_count),
        after_member_count=int(after_count),
        before_set_digest=before_set,
        after_set_digest=after_set,
        before_order_digest=before_order,
        after_order_digest=after_order,
    )


def evaluate_projection_set_completeness(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Validate a fixed public S25U/T/R projection member set without state."""

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
    "FALSE_FLAGS",
    "HARNESS_SCHEMA",
    "INPUT_INVALID",
    "MEMBER_DIGEST_FIELDS",
    "MEMBER_KEYS",
    "MEMBER_FIELDS",
    "PROJECTION_CONFLICT",
    "PROJECTION_OUT_OF_WINDOW",
    "PROJECTION_PARTIAL",
    "PROJECTION_REJECTED",
    "PROJECTION_SET_COMPLETE",
    "PROJECTION_SET_SCHEMA",
    "PROJECTION_STALE",
    "RESULT_KEYS",
    "S25R_REJECTED",
    "S25R_SCHEMA",
    "S25T_REJECTED",
    "S25T_SCHEMA",
    "S25U_REJECTED",
    "evaluate_projection_set_completeness",
    "input_digest",
]
