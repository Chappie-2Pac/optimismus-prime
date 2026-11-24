"""Pure S25Z coverage-verdict partition over the public S25Y contract."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:  # pragma: no cover - import path depends on the test runner
    from support.w5_s25y_claim_evidence_closure import (
        ATOM_IDS,
        CANONICALIZATION as S25Y_CANONICALIZATION,
        COVERAGE_COMPLETE as S25Y_COVERAGE_COMPLETE,
        COVERAGE_INCOMPLETE as S25Y_COVERAGE_INCOMPLETE,
        COVERAGE_SCOPE as S25Y_COVERAGE_SCOPE,
        HARNESS_SCHEMA as S25Y_SCHEMA,
        INPUT_INVALID as S25Y_INPUT_INVALID,
        RESULT_KEYS as S25Y_RESULT_KEYS,
        SCOPE_UNSUPPORTED as S25Y_SCOPE_UNSUPPORTED,
        X_REJECTED as S25Y_X_REJECTED,
        evaluate_claim_evidence_closure,
        input_digest as s25y_input_digest,
    )
except ImportError:  # pragma: no cover
    from w5_s25y_claim_evidence_closure import (  # type: ignore[no-redef]
        ATOM_IDS,
        CANONICALIZATION as S25Y_CANONICALIZATION,
        COVERAGE_COMPLETE as S25Y_COVERAGE_COMPLETE,
        COVERAGE_INCOMPLETE as S25Y_COVERAGE_INCOMPLETE,
        COVERAGE_SCOPE as S25Y_COVERAGE_SCOPE,
        HARNESS_SCHEMA as S25Y_SCHEMA,
        INPUT_INVALID as S25Y_INPUT_INVALID,
        RESULT_KEYS as S25Y_RESULT_KEYS,
        SCOPE_UNSUPPORTED as S25Y_SCOPE_UNSUPPORTED,
        X_REJECTED as S25Y_X_REJECTED,
        evaluate_claim_evidence_closure,
        input_digest as s25y_input_digest,
    )


HARNESS_SCHEMA = "s25z.coverage-verdict-partition.v1"
OBSERVATION_MODE = "TEST_ONLY"
CANONICALIZATION = S25Y_CANONICALIZATION
VERDICT_SCHEMA = "s25z.coverage-verdict.v1"
VERDICT_SCOPE = "S25Y_COVERAGE_VERDICT_PARTITION_ONLY"
EXPECTED_Y_CLAIM_SCOPE = "S25W_MEMBER_DELTA_ONLY"
EXPECTED_Y_UNSUPPORTED_SCOPE = "UNSUPPORTED"

VERDICT_COMPLETE = "VERDICT_COMPLETE"
VERDICT_INCOMPLETE = "VERDICT_INCOMPLETE"
S25Y_REJECTED = "S25Y_REJECTED"
S25Y_NOT_COMPLETE = "S25Y_NOT_COMPLETE"
INPUT_INVALID = "INPUT_INVALID"

PROPOSAL_ONLY = "PROPOSAL_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

_HASH64 = re.compile(r"[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\/])")
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
        "s25y_case",
        "s25y_output",
        "verdict",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset({"y_case_digest", "y_result_digest", "verdict_digest", "required_atom_count"})
_PARTITION_KEYS = frozenset({"atom_id", "state"})
_VERDICT_KEYS = frozenset(
    {
        "coverage_digest",
        "classification",
        "covered_atom_ids",
        "uncovered_atom_ids",
        "required_atom_count",
        "partition",
    }
)
_Y_CORE_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "coverage_scope",
        "claim_scope",
        "covered_atom_ids",
        "uncovered_atom_ids",
        "required_atom_count",
        "x_case_digest",
        "x_result_digest",
        "claim_digest",
        "coverage_digest",
        "production_status",
        "authority_claim",
    }
)
Y_FLAG_KEYS = (
    "capability_issued",
    "cas_attempted",
    "commit_authorized",
    "fence_issued",
    "floor_advanced",
    "mutation_allowed",
    "persistence_performed",
    "receipt_committed",
    "receipt_emitted",
    "resume_allowed",
    "write_authorized",
)
_Y_REASON_PROFILES = {
    S25Y_COVERAGE_COMPLETE: frozenset({"ALL_CLAIM_ATOMS_COVERED"}),
    S25Y_COVERAGE_INCOMPLETE: frozenset(
        {
            "EXPECTED_BINDING_MISMATCH",
            "ATOM_SET_INCOMPLETE",
            "ATOM_SCHEMA_INVALID",
            "ATOM_DUPLICATE",
            "ATOM_UNKNOWN",
            "ATOM_ORDER_OR_MISSING",
            "ATOM_BINDING_MISMATCH",
            "COVERAGE_DIGEST_MISMATCH",
        }
    ),
    S25Y_X_REJECTED: frozenset(
        {
            "S25X_CASE_INVALID",
            "S25X_CASE_DIGEST_DRIFT",
            "S25X_RESULT_UNREADABLE",
            "S25X_RESULT_MISMATCH",
            "S25X_NOT_POSITIVE",
            "S25X_PROVENANCE_INVALID",
            "S25X_CLAIM_DIGEST_MISMATCH",
        }
    ),
    S25Y_SCOPE_UNSUPPORTED: frozenset({"CLAIM_SCOPE_UNSUPPORTED"}),
    S25Y_INPUT_INVALID: frozenset(
        {
            "CASE_UNREADABLE_OR_TOO_DEEP",
            "CASE_SCHEMA_NOT_EXACT",
            "CASE_VALUE_NOT_SAFE",
            "CASE_PROFILE_INVALID",
            "CASE_DIGEST_DRIFT",
            "EXPECTED_SCHEMA_NOT_EXACT",
            "EXPECTED_DIGEST_INVALID",
            "EXPECTED_ATOM_COUNT_INVALID",
            "EXPECTED_MEMBER_COUNT_INVALID",
        }
    ),
}

_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "verdict_scope",
        "y_coverage_scope",
        "y_claim_scope",
        "y_case_digest",
        "y_result_digest",
        "coverage_digest",
        "verdict_digest",
        "covered_atom_ids",
        "uncovered_atom_ids",
        "required_atom_count",
        "partition",
        "production_status",
        "authority_claim",
        *Y_FLAG_KEYS,
    }
)
RESULT_KEYS = tuple(sorted(_OUTPUT_KEYS))
_ZERO_HASH = "0" * 64


class _DuplicateKey(ValueError):
    pass


class _Failure(ValueError):
    def __init__(self, classification: str, reason: str, **kwargs: Any) -> None:
        super().__init__(reason)
        self.classification = classification
        self.reason = reason
        self.kwargs = kwargs


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
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


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
    if isinstance(value, (float, bytes, bytearray)):
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
        return (
            len(value) <= _MAX_STRING
            and not any("\ud800" <= char <= "\udfff" for char in value)
            and not _ABSOLUTE_PATH.match(value)
            and not value.startswith("\\\\")
            and not _URI_SCHEME.match(value)
        )
    if isinstance(value, (float, bytes, bytearray)):
        return False
    if active is None:
        active = set()
    marker = id(value)
    if marker in active:
        return False
    active.add(marker)
    try:
        if isinstance(value, Mapping):
            return len(value) <= _MAX_CONTAINER_ITEMS and all(
                isinstance(key, str)
                and len(key) <= _MAX_KEY_LENGTH
                and _safe_value(item, depth=depth + 1, active=active)
                for key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return len(value) <= _MAX_CONTAINER_ITEMS and all(
                _safe_value(item, depth=depth + 1, active=active) for item in value
            )
        return False
    except Exception:
        return False
    finally:
        active.remove(marker)


def _exact(value: Any, keys: frozenset[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == set(keys)


def _hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_HASH64.fullmatch(value))


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= _MAX_INTEGER


def _strict_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping):
        return set(left) == set(right) and all(_strict_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_strict_equal(item, other) for item, other in zip(left, right))
    return left == right


def _result(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    verdict_scope: str = VERDICT_SCOPE,
    y_coverage_scope: str = S25Y_COVERAGE_SCOPE,
    y_claim_scope: str = EXPECTED_Y_CLAIM_SCOPE,
    y_case_digest: str = _ZERO_HASH,
    y_result_digest: str = _ZERO_HASH,
    coverage_digest: str = _ZERO_HASH,
    verdict_digest: str = _ZERO_HASH,
    covered_atom_ids: list[str] | None = None,
    uncovered_atom_ids: list[str] | None = None,
    required_atom_count: int | None = None,
    partition: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVATION_MODE,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "verdict_scope": verdict_scope,
        "y_coverage_scope": y_coverage_scope,
        "y_claim_scope": y_claim_scope,
        "y_case_digest": y_case_digest,
        "y_result_digest": y_result_digest,
        "coverage_digest": coverage_digest,
        "verdict_digest": verdict_digest,
        "covered_atom_ids": list(covered_atom_ids or []),
        "uncovered_atom_ids": list(uncovered_atom_ids or []),
        "required_atom_count": len(ATOM_IDS) if required_atom_count is None else required_atom_count,
        "partition": [dict(item) for item in (partition or [])],
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
        **{field: False for field in Y_FLAG_KEYS},
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _result(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(reason: str, *, classification: str = S25Y_REJECTED, **kwargs: Any) -> dict[str, Any]:
    return _result(classification, TEST_BLOCKED, HOLD, reason, **kwargs)


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    for field in ("y_case_digest", "y_result_digest", "verdict_digest"):
        if not _hash(expected.get(field)):
            return "EXPECTED_DIGEST_INVALID"
    if not _integer(expected.get("required_atom_count")) or expected["required_atom_count"] != len(ATOM_IDS):
        return "EXPECTED_ATOM_COUNT_INVALID"
    return None


def _valid_y_result(output: Any) -> bool:
    if not isinstance(output, Mapping) or not _exact(output, frozenset(S25Y_RESULT_KEYS)) or not _safe_value(output):
        return False
    if output.get("schema_version") != S25Y_SCHEMA or output.get("observation_mode") != OBSERVATION_MODE:
        return False
    classification = output.get("classification")
    profiles = {
        S25Y_COVERAGE_COMPLETE: (PROPOSAL_ONLY, DESIGN_ONLY, S25Y_COVERAGE_SCOPE, EXPECTED_Y_CLAIM_SCOPE),
        S25Y_COVERAGE_INCOMPLETE: (TEST_BLOCKED, HOLD, S25Y_COVERAGE_SCOPE, EXPECTED_Y_CLAIM_SCOPE),
        S25Y_X_REJECTED: (TEST_BLOCKED, HOLD, S25Y_COVERAGE_SCOPE, EXPECTED_Y_CLAIM_SCOPE),
        S25Y_SCOPE_UNSUPPORTED: (TEST_BLOCKED, HOLD, EXPECTED_Y_UNSUPPORTED_SCOPE, EXPECTED_Y_UNSUPPORTED_SCOPE),
        S25Y_INPUT_INVALID: (TEST_BLOCKED, HOLD, S25Y_COVERAGE_SCOPE, EXPECTED_Y_CLAIM_SCOPE),
    }
    if classification not in profiles:
        return False
    expected_status, expected_decision, expected_coverage_scope, expected_claim_scope = profiles[classification]
    if output.get("status") != expected_status or output.get("decision") != expected_decision:
        return False
    if output.get("coverage_scope") != expected_coverage_scope or output.get("claim_scope") != expected_claim_scope:
        return False
    if output.get("production_status") != PRODUCTION_NOT_AUTHORIZED or output.get("authority_claim") != NOT_CLAIMED:
        return False
    if not all(_hash(output.get(field)) for field in ("x_case_digest", "x_result_digest", "claim_digest", "coverage_digest")):
        return False
    if output.get("reason") not in _Y_REASON_PROFILES[classification]:
        return False
    return all(output.get(field) is False for field in Y_FLAG_KEYS)


def _valid_partition(verdict: Mapping[str, Any]) -> str | None:
    if not _exact(verdict, _VERDICT_KEYS) or not _safe_value(verdict):
        return "VERDICT_SCHEMA_INVALID"
    if not _hash(verdict.get("coverage_digest")):
        return "VERDICT_DIGEST_INVALID"
    if not isinstance(verdict.get("classification"), str):
        return "VERDICT_CLASSIFICATION_INVALID"
    if not _integer(verdict.get("required_atom_count")) or verdict["required_atom_count"] != len(ATOM_IDS):
        return "VERDICT_ATOM_COUNT_INVALID"
    covered = verdict.get("covered_atom_ids")
    uncovered = verdict.get("uncovered_atom_ids")
    partition = verdict.get("partition")
    if not isinstance(covered, list) or not isinstance(uncovered, list):
        return "VERDICT_PARTITION_INVALID"
    if not isinstance(partition, list) or len(partition) != len(ATOM_IDS):
        return "VERDICT_PARTITION_SCHEMA_INVALID"
    if any(not isinstance(item, str) for item in [*covered, *uncovered]):
        return "VERDICT_PARTITION_INVALID"
    if len(covered) != len(set(covered)) or len(uncovered) != len(set(uncovered)):
        return "VERDICT_ATOM_DUPLICATE"
    if any(item not in ATOM_IDS for item in [*covered, *uncovered]):
        return "VERDICT_ATOM_UNKNOWN"
    if set(covered) & set(uncovered):
        return "VERDICT_PARTITION_OVERLAP"
    positions = {atom_id: index for index, atom_id in enumerate(ATOM_IDS)}
    if covered != sorted(covered, key=positions.__getitem__) or uncovered != sorted(uncovered, key=positions.__getitem__):
        return "VERDICT_ATOM_ORDER_DRIFT"
    partition_rows: list[dict[str, str]] = []
    for item in partition:
        if not isinstance(item, Mapping) or not _exact(item, _PARTITION_KEYS) or not _safe_value(item):
            return "VERDICT_PARTITION_SCHEMA_INVALID"
        if not isinstance(item.get("atom_id"), str) or item["atom_id"] not in ATOM_IDS:
            return "VERDICT_PARTITION_ATOM_UNKNOWN"
        if item.get("state") not in {"COVERED", "UNCOVERED", "UNOBSERVED"}:
            return "VERDICT_PARTITION_STATE_INVALID"
        partition_rows.append({"atom_id": item["atom_id"], "state": item["state"]})
    if [item["atom_id"] for item in partition_rows] != list(ATOM_IDS):
        return "VERDICT_PARTITION_ORDER_DRIFT"
    if len({item["atom_id"] for item in partition_rows}) != len(ATOM_IDS):
        return "VERDICT_PARTITION_ATOM_DUPLICATE"
    expected_states = {
        atom_id: ("COVERED" if atom_id in covered else "UNCOVERED" if atom_id in uncovered else "UNOBSERVED")
        for atom_id in ATOM_IDS
    }
    if any(item["state"] != expected_states[item["atom_id"]] for item in partition_rows):
        return "VERDICT_PARTITION_REWIRE"
    return None


def _partition_from_y(output: Mapping[str, Any]) -> list[dict[str, str]]:
    covered = set(output["covered_atom_ids"])
    uncovered = set(output["uncovered_atom_ids"])
    return [
        {
            "atom_id": atom_id,
            "state": "COVERED" if atom_id in covered else "UNCOVERED" if atom_id in uncovered else "UNOBSERVED",
        }
        for atom_id in ATOM_IDS
    ]


def _verdict_from_y(output: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "coverage_digest": output["coverage_digest"],
        "classification": output["classification"],
        "covered_atom_ids": output["covered_atom_ids"],
        "uncovered_atom_ids": output["uncovered_atom_ids"],
        "required_atom_count": output["required_atom_count"],
        "partition": _partition_from_y(output),
    }


def _verdict_digest(y_result_digest: str, verdict: Mapping[str, Any]) -> str:
    return _digest(
        {
            "schema": VERDICT_SCHEMA,
            "verdict_scope": VERDICT_SCOPE,
            "y_result_digest": y_result_digest,
            "verdict": verdict,
        }
    )


def _evaluate(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    try:
        snapshot = _snapshot(_parse(case))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")
    if not isinstance(snapshot, Mapping) or not _exact(snapshot, _TOP_LEVEL):
        return _invalid("CASE_SCHEMA_NOT_EXACT")
    if not _safe_value(snapshot):
        return _invalid("CASE_VALUE_NOT_SAFE")
    if snapshot.get("schema_version") != HARNESS_SCHEMA or snapshot.get("observation_mode") != OBSERVATION_MODE or snapshot.get("canonicalization") != CANONICALIZATION:
        return _invalid("CASE_PROFILE_INVALID")
    if not _hash(snapshot.get("input_digest")) or snapshot["input_digest"] != input_digest(snapshot):
        return _invalid("CASE_DIGEST_DRIFT")
    expected_error = _validate_expected(snapshot["expected"])
    if expected_error:
        return _invalid(expected_error)
    y_case = snapshot["s25y_case"]
    if not isinstance(y_case, Mapping) or not _safe_value(y_case):
        return _blocked("S25Y_CASE_INVALID")
    try:
        if not _hash(y_case.get("input_digest")) or y_case["input_digest"] != s25y_input_digest(y_case):
            return _blocked("S25Y_CASE_DIGEST_DRIFT")
        actual_y = _snapshot(evaluate_claim_evidence_closure(y_case))
    except Exception:
        return _blocked("S25Y_RESULT_UNREADABLE")
    if not _strict_equal(snapshot["s25y_output"], actual_y):
        return _blocked("S25Y_RESULT_MISMATCH")
    if not _valid_y_result(actual_y):
        return _blocked("S25Y_RESULT_INVALID")
    y_case_digest = s25y_input_digest(y_case)
    y_result_digest = _digest(actual_y)
    if snapshot["expected"]["y_case_digest"] != y_case_digest or snapshot["expected"]["y_result_digest"] != y_result_digest:
        return _blocked(
            "EXPECTED_BINDING_MISMATCH",
            classification=VERDICT_INCOMPLETE,
            y_case_digest=y_case_digest,
            y_result_digest=y_result_digest,
        )
    actual_verdict = _verdict_from_y(actual_y)
    supplied_verdict = snapshot["verdict"]
    verdict_error = _valid_partition(supplied_verdict)
    if verdict_error:
        return _blocked(verdict_error, classification=VERDICT_INCOMPLETE, y_case_digest=y_case_digest, y_result_digest=y_result_digest)
    if not _strict_equal(supplied_verdict, actual_verdict):
        return _blocked(
            "VERDICT_PARTITION_MISMATCH",
            classification=VERDICT_INCOMPLETE,
            y_case_digest=y_case_digest,
            y_result_digest=y_result_digest,
            coverage_digest=actual_verdict["coverage_digest"],
        )
    verdict_digest = _verdict_digest(y_result_digest, actual_verdict)
    if snapshot["expected"]["verdict_digest"] != verdict_digest:
        return _blocked(
            "VERDICT_DIGEST_MISMATCH",
            classification=VERDICT_INCOMPLETE,
            y_case_digest=y_case_digest,
            y_result_digest=y_result_digest,
            coverage_digest=actual_verdict["coverage_digest"],
            verdict_digest=verdict_digest,
        )
    if actual_y["classification"] != S25Y_COVERAGE_COMPLETE:
        return _blocked(
            "S25Y_NOT_COMPLETE",
            classification=S25Y_NOT_COMPLETE,
            y_case_digest=y_case_digest,
            y_result_digest=y_result_digest,
            coverage_digest=actual_verdict["coverage_digest"],
            verdict_digest=verdict_digest,
            covered_atom_ids=list(actual_verdict["covered_atom_ids"]),
            uncovered_atom_ids=list(actual_verdict["uncovered_atom_ids"]),
        )
    if actual_verdict["covered_atom_ids"] != list(ATOM_IDS) or actual_verdict["uncovered_atom_ids"] != [] or actual_verdict["required_atom_count"] != len(ATOM_IDS):
        return _blocked(
            "VERDICT_PARTITION_MISMATCH",
            classification=VERDICT_INCOMPLETE,
            y_case_digest=y_case_digest,
            y_result_digest=y_result_digest,
            coverage_digest=actual_verdict["coverage_digest"],
            verdict_digest=verdict_digest,
            covered_atom_ids=list(actual_verdict["covered_atom_ids"]),
            uncovered_atom_ids=list(actual_verdict["uncovered_atom_ids"]),
        )
    return _result(
        VERDICT_COMPLETE,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        "COVERAGE_VERDICT_PARTITION_CLOSED",
        y_case_digest=y_case_digest,
        y_result_digest=y_result_digest,
        y_coverage_scope=actual_y["coverage_scope"],
        y_claim_scope=actual_y["claim_scope"],
        coverage_digest=actual_verdict["coverage_digest"],
        verdict_digest=verdict_digest,
        covered_atom_ids=list(actual_verdict["covered_atom_ids"]),
        uncovered_atom_ids=list(actual_verdict["uncovered_atom_ids"]),
        required_atom_count=actual_verdict["required_atom_count"],
        partition=actual_verdict["partition"],
    )


def evaluate_coverage_verdict_partition(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Return a deterministic verdict-partition witness over public S25Y."""

    try:
        return _evaluate(case)
    except _Failure as failure:
        return _blocked(failure.reason, classification=failure.classification, **failure.kwargs)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


def verdict_digest(y_result_digest: str, verdict: Mapping[str, Any]) -> str:
    """Return the canonical digest for the shaped verdict witness."""

    return _verdict_digest(y_result_digest, verdict)


def input_digest(case: Mapping[str, Any]) -> str:
    snapshot = _snapshot(case)
    if not isinstance(snapshot, Mapping):
        raise ValueError("case must be a mapping")
    return _digest({key: value for key, value in snapshot.items() if key != "input_digest"})


__all__ = [
    "ATOM_IDS",
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "INPUT_INVALID",
    "RESULT_KEYS",
    "S25Y_NOT_COMPLETE",
    "S25Y_REJECTED",
    "VERDICT_COMPLETE",
    "VERDICT_INCOMPLETE",
    "VERDICT_SCHEMA",
    "VERDICT_SCOPE",
    "Y_FLAG_KEYS",
    "evaluate_coverage_verdict_partition",
    "input_digest",
    "verdict_digest",
]
