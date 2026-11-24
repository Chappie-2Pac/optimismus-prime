"""Pure S25U monotonicity gate for public S25T provenance projections."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from support.w5_s25t_receipt_provenance import (
        CANONICALIZATION as S25T_CANONICALIZATION,
        HARNESS_SCHEMA as S25T_SCHEMA,
        evaluate_receipt_provenance,
        input_digest as s25t_input_digest,
    )
except ImportError:  # pragma: no cover - direct support-module execution
    from w5_s25t_receipt_provenance import (
        CANONICALIZATION as S25T_CANONICALIZATION,
        HARNESS_SCHEMA as S25T_SCHEMA,
        evaluate_receipt_provenance,
        input_digest as s25t_input_digest,
    )


HARNESS_SCHEMA = "s25u.provenance-projection-monotonicity.v1"
CANONICALIZATION = "s25m-canonical-json-v1"
TEST_ONLY = "TEST_ONLY"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
HOLD = "HOLD"
DESIGN_ONLY = "DESIGN_ONLY"
MANUAL_REVIEW = "MANUAL_REVIEW"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

PROVENANCE_PROJECTION_MONOTONIC = "PROVENANCE_PROJECTION_MONOTONIC"
PROJECTION_REJECTED = "PROJECTION_REJECTED"
PROJECTION_CONFLICT = "PROJECTION_CONFLICT"
PROJECTION_PARTIAL = "PROJECTION_PARTIAL"
PROJECTION_STALE = "PROJECTION_STALE"
PROJECTION_OUT_OF_WINDOW = "PROJECTION_OUT_OF_WINDOW"
S25T_REJECTED = "S25T_REJECTED"

_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_MAX_DEPTH = 64
_MAX_STRING = 4096
_MAX_INTEGER = 2**63 - 1

_STATUS_DECISIONS = {
    PROPOSAL_ONLY: DESIGN_ONLY,
    TEST_BLOCKED: HOLD,
    RECOVERY_REQUIRED: MANUAL_REVIEW,
}
_STATUS_RANK = {PROPOSAL_ONLY: 2, TEST_BLOCKED: 1, RECOVERY_REQUIRED: 1}
_TRANSITIONS = {"NO_CHANGE", "NEXT_SEQUENCE", "EVIDENCE_DEGRADED"}
_S25T_CLASSIFICATIONS = {
    "PROVENANCE_WITNESS_RECONCILED",
    "PROVENANCE_REJECTED",
    "PROVENANCE_PARTIAL",
    "PROVENANCE_UNKNOWN",
    "PROVENANCE_STALE",
    "PROVENANCE_OUT_OF_WINDOW",
    "PROVENANCE_CONFLICT",
    "S25R_REJECTED",
    "INPUT_INVALID",
}
_S25T_COVERAGE = {"COMPLETE", "PARTIAL", "UNKNOWN"}
_S25T_FRESHNESS = {"FRESH", "STALE", "FUTURE", "UNKNOWN"}
_S25T_COMPARISON = {"COMPARABLE", "NOT_COMPARABLE", "CONFLICT"}
_S25T_PROVENANCE = {"COMPLETE", "NOT_CLAIMED", "UNKNOWN", "PARTIAL", "STALE", "CONFLICT"}
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
    }
)
_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "before_case",
        "after_case",
        "before_projection",
        "after_projection",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "before_case_digest",
        "after_case_digest",
        "before_result_digest",
        "after_result_digest",
        "before_projection_digest",
        "after_projection_digest",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "observer_id",
        "comparison_group",
        "epoch",
        "before_sequence",
        "after_sequence",
        "before_observation_id",
        "after_observation_id",
        "before_idempotency_key",
        "after_idempotency_key",
        "transition_kind",
        "required_source_count",
        "required_observation_count",
    }
)
_PROJECTION_KEYS = frozenset(
    {
        "schema",
        "s25t_case_digest",
        "s25t_result_digest",
        "s25r_case_digest",
        "s25r_result_digest",
        "s25r_projection_digest",
        "source_set_digest",
        "window_digest",
        "observation_set_digest",
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
        "projection_digest",
    }
)
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


class _DuplicateKey(ValueError):
    pass


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


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _input_digest_snapshot(case: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in case.items() if key != "input_digest"})


def input_digest(case: Mapping[str, Any]) -> str:
    snapshot = _snapshot(case)
    if not isinstance(snapshot, Mapping):
        raise ValueError("case must be a mapping")
    return _input_digest_snapshot(snapshot)


def _output(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    transition_kind: str = "UNKNOWN",
    before_projection: Mapping[str, Any] | None = None,
    after_projection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    before_status = before_projection.get("status", "UNKNOWN") if before_projection is not None else "UNKNOWN"
    after_status = after_projection.get("status", "UNKNOWN") if after_projection is not None else "UNKNOWN"
    before_provenance = before_projection.get("provenance_status", "UNKNOWN") if before_projection is not None else "UNKNOWN"
    after_provenance = after_projection.get("provenance_status", "UNKNOWN") if after_projection is not None else "UNKNOWN"
    before_sequence = before_projection.get("current_sequence", 0) if before_projection is not None else 0
    after_sequence = after_projection.get("current_sequence", 0) if after_projection is not None else 0
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": TEST_ONLY,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "transition_kind": transition_kind,
        "monotonicity_status": "NOT_CLAIMED" if status != PROPOSAL_ONLY else ("SAFE_DOWNGRADE" if transition_kind == "EVIDENCE_DEGRADED" else "UNCHANGED_OR_NEXT"),
        "before_status": before_status,
        "after_status": after_status,
        "before_provenance_status": before_provenance,
        "after_provenance_status": after_provenance,
        "before_sequence": before_sequence,
        "after_sequence": after_sequence,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
        "capability_issued": False,
        "write_authorized": False,
        "mutation_allowed": False,
        "persistence_performed": False,
        "cas_attempted": False,
        "fence_issued": False,
        "resume_allowed": False,
        "receipt_emitted": False,
        "receipt_committed": False,
        "commit_authorized": False,
        "floor_advanced": False,
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _output("INPUT_INVALID", TEST_BLOCKED, HOLD, reason)


def _blocked(reason: str, *, classification: str = PROJECTION_REJECTED, **kwargs: Any) -> dict[str, Any]:
    return _output(classification, TEST_BLOCKED, HOLD, reason, **kwargs)


def _review(reason: str, *, classification: str = PROJECTION_CONFLICT, **kwargs: Any) -> dict[str, Any]:
    return _output(classification, RECOVERY_REQUIRED, MANUAL_REVIEW, reason, **kwargs)


def _valid_s25t_result(result: Any) -> bool:
    if not isinstance(result, Mapping) or not _safe_value(result) or set(result) != set(_S25T_RESULT_KEYS):
        return False
    if result.get("schema_version") != S25T_SCHEMA or result.get("observation_mode") != TEST_ONLY:
        return False
    if result.get("classification") not in _S25T_CLASSIFICATIONS or result.get("status") not in _STATUS_DECISIONS:
        return False
    if result.get("classification") == "INPUT_INVALID":
        return False
    status = result["status"]
    if result.get("decision") != _STATUS_DECISIONS[status] or not _text(result.get("reason")):
        return False
    if result.get("provenance_status") not in _S25T_PROVENANCE or result.get("coverage_status") not in _S25T_COVERAGE or result.get("freshness_status") not in _S25T_FRESHNESS or result.get("comparison_status") not in _S25T_COMPARISON:
        return False
    for field in ("source_count", "observation_count"):
        if not _integer(result.get(field)) or result[field] < 0:
            return False
    for field in ("witness_only", "source_witnessed", *_FALSE_FLAGS):
        if not isinstance(result.get(field), bool):
            return False
    if result.get("production_status") != PRODUCTION_NOT_AUTHORIZED or result.get("authority_claim") != NOT_CLAIMED:
        return False
    if not all(result.get(field) is False for field in _FALSE_FLAGS):
        return False
    if result["classification"] == "PROVENANCE_WITNESS_RECONCILED":
        return (
            status == PROPOSAL_ONLY
            and result["decision"] == DESIGN_ONLY
            and result["reason"] == "READ_ONLY_PROVENANCE_WITNESS"
            and result["provenance_status"] == "COMPLETE"
            and result["coverage_status"] == "COMPLETE"
            and result["freshness_status"] == "FRESH"
            and result["comparison_status"] == "COMPARABLE"
            and result["witness_only"] is True
            and result["source_witnessed"] is True
            and result["source_count"] == 6
            and result["observation_count"] == 6
        )
    return not (status == PROPOSAL_ONLY or result["witness_only"] or result["source_witnessed"])


def _projection_from_case(case: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any] | None:
    expected = case.get("expected")
    if not isinstance(expected, Mapping):
        return None
    try:
        case_digest = s25t_input_digest(case)
        projection: dict[str, Any] = {
            "schema": "s25u.s25t-projection.v1",
            "s25t_case_digest": case_digest,
            "s25t_result_digest": _digest(result),
            "s25r_case_digest": expected["s25r_case_digest"],
            "s25r_result_digest": expected["s25r_result_digest"],
            "s25r_projection_digest": expected["s25r_projection_digest"],
            "source_set_digest": expected.get("source_set_digest", ""),
            "window_digest": expected.get("window_digest", ""),
            "observation_set_digest": expected.get("observation_set_digest", ""),
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


def _valid_projection(projection: Any) -> bool:
    if not isinstance(projection, Mapping) or not _exact(projection, _PROJECTION_KEYS) or not _safe_value(projection):
        return False
    for field in ("s25t_case_digest", "s25t_result_digest", "s25r_case_digest", "s25r_result_digest", "s25r_projection_digest", "source_set_digest", "window_digest", "observation_set_digest", "subject_digest", "scope_digest", "baseline_digest", "projection_digest"):
        if not _hash(projection.get(field)):
            return False
    for field in ("schema", "classification", "status", "decision", "reason", "provenance_status", "coverage_status", "freshness_status", "comparison_status", "s25r_classification", "s25r_status", "s25r_reconciliation_status", "production_status", "authority_claim", "observation_id", "idempotency_key", "observer_id", "comparison_group"):
        if not _text(projection.get(field)):
            return False
    if projection.get("schema") != "s25u.s25t-projection.v1" or projection.get("status") not in _STATUS_DECISIONS or projection.get("decision") != _STATUS_DECISIONS[projection["status"]]:
        return False
    if projection.get("provenance_status") not in _S25T_PROVENANCE or projection.get("coverage_status") not in _S25T_COVERAGE or projection.get("freshness_status") not in _S25T_FRESHNESS or projection.get("comparison_status") not in _S25T_COMPARISON:
        return False
    if not _integer(projection.get("epoch"), positive=True) or not _integer(projection.get("previous_sequence"), positive=True) or not _integer(projection.get("current_sequence"), positive=True) or projection["current_sequence"] != projection["previous_sequence"] + 1:
        return False
    if not _integer(projection.get("source_count")) or not _integer(projection.get("observation_count")) or projection["source_count"] < 0 or projection["observation_count"] < 0:
        return False
    for field in ("witness_only", "source_witnessed", *_FALSE_FLAGS):
        if not isinstance(projection.get(field), bool):
            return False
    if projection["production_status"] != PRODUCTION_NOT_AUTHORIZED or projection["authority_claim"] != NOT_CLAIMED or any(projection[field] is not False for field in _FALSE_FLAGS):
        return False
    return projection["projection_digest"] == _digest({key: value for key, value in projection.items() if key != "projection_digest"})


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    for field in ("before_case_digest", "after_case_digest", "before_result_digest", "after_result_digest", "before_projection_digest", "after_projection_digest", "subject_digest", "scope_digest", "baseline_digest"):
        if not _hash(expected.get(field)):
            return "EXPECTED_DIGEST_INVALID"
    for field in ("epoch", "before_sequence", "after_sequence", "required_source_count", "required_observation_count"):
        if not _integer(expected.get(field), positive=True):
            return "EXPECTED_COUNTER_INVALID"
    if expected["required_source_count"] != 6 or expected["required_observation_count"] != 6:
        return "EXPECTED_COVERAGE_INVALID"
    if expected["transition_kind"] not in _TRANSITIONS:
        return "TRANSITION_KIND_INVALID"
    for field in ("observer_id", "comparison_group", "before_observation_id", "after_observation_id", "before_idempotency_key", "after_idempotency_key"):
        if not _text(expected.get(field)):
            return "EXPECTED_TEXT_INVALID"
    return None


def _same_context(before: Mapping[str, Any], after: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    fields = ("subject_digest", "scope_digest", "baseline_digest", "epoch", "observer_id", "comparison_group")
    return all(before[field] == after[field] == expected[field] for field in fields)


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
    if not _hash(snapshot.get("input_digest")) or snapshot["input_digest"] != _input_digest_snapshot(snapshot):
        return _invalid("CASE_DIGEST_DRIFT")
    expected = snapshot["expected"]
    expected_error = _validate_expected(expected)
    if expected_error:
        return _blocked(expected_error)
    projections: list[dict[str, Any]] = []
    for side in ("before_case", "after_case"):
        nested = snapshot[side]
        if not isinstance(nested, Mapping) or not _safe_value(nested):
            return _blocked("S25T_CASE_INVALID", classification=S25T_REJECTED)
        try:
            result = _snapshot(evaluate_receipt_provenance(nested))
        except Exception:
            return _blocked("S25T_RESULT_UNREADABLE", classification=S25T_REJECTED)
        if not _valid_s25t_result(result):
            return _blocked("S25T_RESULT_INVALID", classification=S25T_REJECTED)
        projection = _projection_from_case(nested, result)
        if projection is None or not _valid_projection(projection):
            return _blocked("S25T_PROJECTION_INVALID", classification=S25T_REJECTED)
        projections.append(projection)
    before, after = projections
    if snapshot["before_projection"] != before or snapshot["after_projection"] != after:
        return _blocked("S25T_PROJECTION_MISMATCH", before_projection=before, after_projection=after)
    if not _same_context(before, after, expected):
        return _review("IDENTITY_OR_CONTEXT_DRIFT", before_projection=before, after_projection=after)
    bindings = {
        "before_case_digest": before["s25t_case_digest"],
        "after_case_digest": after["s25t_case_digest"],
        "before_result_digest": before["s25t_result_digest"],
        "after_result_digest": after["s25t_result_digest"],
        "before_projection_digest": before["projection_digest"],
        "after_projection_digest": after["projection_digest"],
        "subject_digest": before["subject_digest"],
        "scope_digest": before["scope_digest"],
        "baseline_digest": before["baseline_digest"],
        "epoch": before["epoch"],
        "before_sequence": before["current_sequence"],
        "after_sequence": after["current_sequence"],
        "before_observation_id": before["observation_id"],
        "after_observation_id": after["observation_id"],
        "before_idempotency_key": before["idempotency_key"],
        "after_idempotency_key": after["idempotency_key"],
    }
    for field, actual in bindings.items():
        if expected[field] != actual:
            return _blocked("EXPECTED_BINDING_MISMATCH", before_projection=before, after_projection=after)
    if expected["transition_kind"] == "NO_CHANGE":
        if before != after:
            return _review("NO_CHANGE_PROJECTION_DRIFT", before_projection=before, after_projection=after)
        return _output(PROVENANCE_PROJECTION_MONOTONIC, PROPOSAL_ONLY, DESIGN_ONLY, "MONOTONIC_NO_CHANGE", transition_kind="NO_CHANGE", before_projection=before, after_projection=after)
    if expected["transition_kind"] == "NEXT_SEQUENCE":
        if before["status"] != PROPOSAL_ONLY or after["status"] != PROPOSAL_ONLY:
            return _blocked("NEXT_SEQUENCE_STATUS_NOT_POSITIVE", before_projection=before, after_projection=after)
        if after["previous_sequence"] != before["current_sequence"] or after["current_sequence"] != before["current_sequence"] + 1:
            return _review("SEQUENCE_GAP_OR_ROLLBACK", classification=PROJECTION_OUT_OF_WINDOW, before_projection=before, after_projection=after)
        if any(before[field] != after[field] for field in ("provenance_status", "coverage_status", "freshness_status", "comparison_status", "status", "decision")):
            return _review("NEXT_SEQUENCE_STATUS_DRIFT", before_projection=before, after_projection=after)
        return _output(PROVENANCE_PROJECTION_MONOTONIC, PROPOSAL_ONLY, DESIGN_ONLY, "MONOTONIC_NEXT_SEQUENCE", transition_kind="NEXT_SEQUENCE", before_projection=before, after_projection=after)
    before_rank = _STATUS_RANK.get(before["status"], -1)
    after_rank = _STATUS_RANK.get(after["status"], -1)
    if after_rank > before_rank:
        return _blocked("STATUS_ESCALATION_OR_INVALID_DEGRADATION", before_projection=before, after_projection=after)
    if after_rank == before_rank:
        return _review("STATUS_SIDEWAYS_OR_UNKNOWN", before_projection=before, after_projection=after)
    if before["status"] != PROPOSAL_ONLY or after["status"] == PROPOSAL_ONLY:
        return _blocked("STATUS_ESCALATION_OR_INVALID_DEGRADATION", before_projection=before, after_projection=after)
    if after["current_sequence"] != before["current_sequence"] or after["previous_sequence"] != before["previous_sequence"]:
        return _review("DEGRADATION_SEQUENCE_DRIFT", classification=PROJECTION_OUT_OF_WINDOW, before_projection=before, after_projection=after)
    return _output(PROVENANCE_PROJECTION_MONOTONIC, PROPOSAL_ONLY, DESIGN_ONLY, "SAFE_NON_ESCALATING_DOWNGRADE", transition_kind="EVIDENCE_DEGRADED", before_projection=before, after_projection=after)


def evaluate_provenance_monotonicity(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Compare two public S25T evaluations without persistence or hidden state."""

    try:
        return _evaluate(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


__all__ = [
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "PROVENANCE_PROJECTION_MONOTONIC",
    "PROJECTION_REJECTED",
    "PROJECTION_CONFLICT",
    "PROJECTION_PARTIAL",
    "PROJECTION_STALE",
    "PROJECTION_OUT_OF_WINDOW",
    "S25T_REJECTED",
    "evaluate_provenance_monotonicity",
    "input_digest",
]
