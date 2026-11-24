"""Pure second-order endpoint incidence over the public S25AA boundary.

S25AB compares two independently re-evaluated, positive S25AA edges.  It
only classifies the exact equality structure of their complete opaque
identity endpoints.  It does not interpret any endpoint as a real-world
entity and does not make temporal, replay, causal, truth, or authority
claims.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:  # pragma: no cover - import path depends on the test runner
    from support.w5_s25aa_pairwise_identity import (
        CANONICALIZATION as S25AA_CANONICALIZATION,
        HARNESS_SCHEMA as S25AA_SCHEMA,
        IDENTITY_FIELDS,
        INPUT_INVALID as S25AA_INPUT_INVALID,
        PAIR_IDENTITY_INCONSISTENT,
        PAIR_NOT_SEPARATED,
        PAIR_SCOPE as S25AA_PAIR_SCOPE,
        PAIR_SEPARATED,
        PRODUCTION_NOT_AUTHORIZED,
        RESULT_KEYS as S25AA_RESULT_KEYS,
        S25Z_NOT_COMPLETE,
        S25Z_REJECTED,
        evaluate_pairwise_identity,
        input_digest as s25aa_input_digest,
        pair_digest as s25aa_pair_digest,
    )
except ImportError:  # pragma: no cover
    from w5_s25aa_pairwise_identity import (  # type: ignore[no-redef]
        CANONICALIZATION as S25AA_CANONICALIZATION,
        HARNESS_SCHEMA as S25AA_SCHEMA,
        IDENTITY_FIELDS,
        INPUT_INVALID as S25AA_INPUT_INVALID,
        PAIR_IDENTITY_INCONSISTENT,
        PAIR_NOT_SEPARATED,
        PAIR_SCOPE as S25AA_PAIR_SCOPE,
        PAIR_SEPARATED,
        PRODUCTION_NOT_AUTHORIZED,
        RESULT_KEYS as S25AA_RESULT_KEYS,
        S25Z_NOT_COMPLETE,
        S25Z_REJECTED,
        evaluate_pairwise_identity,
        input_digest as s25aa_input_digest,
        pair_digest as s25aa_pair_digest,
    )


HARNESS_SCHEMA = "s25ab.endpoint-incidence.v1"
OBSERVATION_MODE = "TEST_ONLY"
CANONICALIZATION = S25AA_CANONICALIZATION
INCIDENCE_SCHEMA = "s25ab.endpoint-incidence-witness.v1"
INCIDENCE_SCOPE = "S25AA_EDGE_ENDPOINT_INCIDENCE_ONLY"

AA_ONE_ENDPOINT_SHARED = "AA_ONE_ENDPOINT_SHARED"
AA_ENDPOINTS_DISJOINT = "AA_ENDPOINTS_DISJOINT"
AA_EDGE_SAME = "AA_EDGE_SAME"
AA_EDGE_REVERSED = "AA_EDGE_REVERSED"
S25AA_NOT_POSITIVE = "S25AA_NOT_POSITIVE"
S25AA_REJECTED = "S25AA_REJECTED"
AA_ENDPOINT_WITNESS_MISMATCH = "AA_ENDPOINT_WITNESS_MISMATCH"
INPUT_INVALID = "INPUT_INVALID"

PROPOSAL_ONLY = "PROPOSAL_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
NOT_CLAIMED = "NOT_CLAIMED"

MATRIX_FIELDS = (
    "left_left",
    "left_right",
    "right_left",
    "right_right",
)
RELATION_CLASSES = frozenset(
    {
        AA_ONE_ENDPOINT_SHARED,
        AA_ENDPOINTS_DISJOINT,
        AA_EDGE_SAME,
        AA_EDGE_REVERSED,
    }
)
NON_POSITIVE_AA_CLASSES = frozenset({PAIR_NOT_SEPARATED, PAIR_IDENTITY_INCONSISTENT})
VALID_AA_CLASSES = frozenset(
    {
        PAIR_SEPARATED,
        PAIR_NOT_SEPARATED,
        PAIR_IDENTITY_INCONSISTENT,
        S25Z_NOT_COMPLETE,
        S25Z_REJECTED,
        S25AA_INPUT_INVALID,
    }
)

# These are the fixed public operation flags carried by S25AA.  AB verifies
# them but never assigns meaning to them beyond the required false profile.
AA_FALSE_FLAG_KEYS = (
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

_HASH64 = re.compile(r"[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_MAX_DEPTH = 64
_MAX_STRING = 4096
_MAX_INTEGER = 2**63 - 1
_MAX_INPUT_BYTES = 2 * 1024 * 1024
# The envelope contains two complete public S25AA cases.  Keep a bounded
# budget, but do not reuse S25AA's single-case budget for this two-edge shell.
_MAX_NODES = 50000
_MAX_CONTAINER_ITEMS = 2048
_MAX_KEY_LENGTH = 256
_ZERO_HASH = "0" * 64

_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "left_case",
        "left_output",
        "right_case",
        "right_output",
        "endpoint_witness",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "left_aa_case_digest",
        "right_aa_case_digest",
        "left_aa_result_digest",
        "right_aa_result_digest",
        "endpoint_relation_digest",
    }
)
_ENDPOINT_KEYS = frozenset(IDENTITY_FIELDS)
_EDGE_KEYS = frozenset({"left_endpoint", "right_endpoint"})
_MATRIX_KEYS = frozenset(MATRIX_FIELDS)
_WITNESS_KEYS = frozenset({"left_edge", "right_edge", "match_matrix", "relation"})
_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "incidence_scope",
        "left_edge",
        "right_edge",
        "match_matrix",
        "endpoint_relation_digest",
        "production_status",
        "authority_claim",
    }
)
RESULT_KEYS = tuple(sorted(_OUTPUT_KEYS))


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


def _strict_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping):
        return set(left) == set(right) and all(_strict_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_strict_equal(item, other) for item, other in zip(left, right))
    return left == right


def _zero_endpoint() -> dict[str, str]:
    return {field: _ZERO_HASH for field in IDENTITY_FIELDS}


def _zero_edge() -> dict[str, dict[str, str]]:
    return {"left_endpoint": _zero_endpoint(), "right_endpoint": _zero_endpoint()}


def _zero_matrix() -> dict[str, bool]:
    return {field: False for field in MATRIX_FIELDS}


def _result(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    left_edge: Mapping[str, Any] | None = None,
    right_edge: Mapping[str, Any] | None = None,
    match_matrix: Mapping[str, Any] | None = None,
    endpoint_relation_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVATION_MODE,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "incidence_scope": INCIDENCE_SCOPE,
        "left_edge": deepcopy_edge(left_edge),
        "right_edge": deepcopy_edge(right_edge),
        "match_matrix": dict(match_matrix or _zero_matrix()),
        "endpoint_relation_digest": endpoint_relation_digest,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
    }


def deepcopy_edge(edge: Mapping[str, Any] | None) -> dict[str, dict[str, str]]:
    if edge is None:
        return _zero_edge()
    return {
        "left_endpoint": dict(edge["left_endpoint"]),
        "right_endpoint": dict(edge["right_endpoint"]),
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _result(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(
    reason: str,
    *,
    classification: str = INPUT_INVALID,
    left_edge: Mapping[str, Any] | None = None,
    right_edge: Mapping[str, Any] | None = None,
    match_matrix: Mapping[str, Any] | None = None,
    endpoint_relation_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return _result(
        classification,
        TEST_BLOCKED,
        HOLD,
        reason,
        left_edge=left_edge,
        right_edge=right_edge,
        match_matrix=match_matrix,
        endpoint_relation_digest=endpoint_relation_digest,
    )


def _valid_expected(expected: Any) -> bool:
    return isinstance(expected, Mapping) and _exact(expected, _EXPECTED_KEYS) and all(
        _hash(expected.get(field)) for field in _EXPECTED_KEYS
    )


def _valid_endpoint(endpoint: Any) -> bool:
    return (
        isinstance(endpoint, Mapping)
        and _exact(endpoint, _ENDPOINT_KEYS)
        and _safe_value(endpoint)
        and all(_hash(endpoint.get(field)) for field in IDENTITY_FIELDS)
    )


def _valid_edge(edge: Any) -> bool:
    return (
        isinstance(edge, Mapping)
        and _exact(edge, _EDGE_KEYS)
        and _safe_value(edge)
        and _valid_endpoint(edge.get("left_endpoint"))
        and _valid_endpoint(edge.get("right_endpoint"))
    )


def _valid_matrix(matrix: Any) -> bool:
    return (
        isinstance(matrix, Mapping)
        and _exact(matrix, _MATRIX_KEYS)
        and _safe_value(matrix)
        and all(type(matrix.get(field)) is bool for field in MATRIX_FIELDS)
    )


def _valid_witness(witness: Any) -> bool:
    return (
        isinstance(witness, Mapping)
        and _exact(witness, _WITNESS_KEYS)
        and _safe_value(witness)
        and _valid_edge(witness.get("left_edge"))
        and _valid_edge(witness.get("right_edge"))
        and _valid_matrix(witness.get("match_matrix"))
        and witness.get("relation") in RELATION_CLASSES
    )


def _valid_aa_output(output: Any) -> bool:
    if not isinstance(output, Mapping) or not _exact(output, frozenset(S25AA_RESULT_KEYS)) or not _safe_value(output):
        return False
    if output.get("schema_version") != S25AA_SCHEMA or output.get("observation_mode") != OBSERVATION_MODE:
        return False
    if output.get("pair_scope") != S25AA_PAIR_SCOPE:
        return False
    if output.get("production_status") != PRODUCTION_NOT_AUTHORIZED or output.get("authority_claim") != NOT_CLAIMED:
        return False
    if any(output.get(field) is not False for field in AA_FALSE_FLAG_KEYS):
        return False
    if output.get("classification") not in VALID_AA_CLASSES:
        return False
    if not _valid_endpoint(output.get("left_identity")) or not _valid_endpoint(output.get("right_identity")):
        return False
    equal_fields = output.get("equal_fields")
    if (
        not isinstance(equal_fields, Mapping)
        or not _exact(equal_fields, frozenset(IDENTITY_FIELDS))
        or not _safe_value(equal_fields)
        or any(type(equal_fields.get(field)) is not bool for field in IDENTITY_FIELDS)
        or not _hash(output.get("pair_digest"))
    ):
        return False
    if output.get("classification") == PAIR_SEPARATED:
        if output["left_identity"]["z_case_digest"] == output["right_identity"]["z_case_digest"]:
            return False
        expected_equal_fields = {
            field: output["left_identity"][field] == output["right_identity"][field]
            for field in IDENTITY_FIELDS
        }
        return (
            output.get("status") == PROPOSAL_ONLY
            and output.get("decision") == DESIGN_ONLY
            and output.get("reason") == "PAIR_IDENTITY_SEPARATED"
            and dict(equal_fields) == expected_equal_fields
            and output.get("pair_digest")
            == s25aa_pair_digest(output["left_identity"], output["right_identity"], expected_equal_fields, PAIR_SEPARATED)
        )
    if output.get("classification") in NON_POSITIVE_AA_CLASSES:
        expected_equal_fields = {
            field: output["left_identity"][field] == output["right_identity"][field]
            for field in IDENTITY_FIELDS
        }
        if dict(equal_fields) != expected_equal_fields:
            return False
        if output.get("pair_digest") != s25aa_pair_digest(
            output["left_identity"], output["right_identity"], expected_equal_fields, output["classification"]
        ):
            return False
        if output.get("classification") == PAIR_NOT_SEPARATED and not all(expected_equal_fields.values()):
            return False
        if output.get("classification") == PAIR_IDENTITY_INCONSISTENT and (
            output["left_identity"]["z_case_digest"] != output["right_identity"]["z_case_digest"]
            or all(expected_equal_fields.values())
        ):
            return False
    return output.get("status") == TEST_BLOCKED and output.get("decision") == HOLD and isinstance(output.get("reason"), str)


def _edge_from_output(output: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    return {
        "left_endpoint": dict(output["left_identity"]),
        "right_endpoint": dict(output["right_identity"]),
    }


def _evaluate_side(
    case: Any, supplied_output: Any
) -> tuple[str, dict[str, Any] | None, dict[str, dict[str, str]] | None, str | None]:
    if not isinstance(case, Mapping) or not _safe_value(case):
        return "S25AA_CASE_INVALID", None, None, None
    try:
        case_digest = s25aa_input_digest(case)
        if not _hash(case.get("input_digest")) or case["input_digest"] != case_digest:
            return "S25AA_CASE_DIGEST_DRIFT", None, None, None
        actual_output = _snapshot(evaluate_pairwise_identity(case))
    except Exception:
        return "S25AA_RESULT_UNREADABLE", None, None, None
    if not _strict_equal(supplied_output, actual_output):
        return "S25AA_RESULT_MISMATCH", None, None, None
    if not _valid_aa_output(actual_output):
        return "S25AA_RESULT_INVALID", actual_output if isinstance(actual_output, dict) else None, None, None
    edge = _edge_from_output(actual_output)
    if actual_output["classification"] != PAIR_SEPARATED:
        return "S25AA_NOT_POSITIVE", actual_output, edge, None
    return "", actual_output, edge, _digest(actual_output)


def _matrix(left_edge: Mapping[str, Any], right_edge: Mapping[str, Any]) -> dict[str, bool]:
    return {
        "left_left": _strict_equal(left_edge["left_endpoint"], right_edge["left_endpoint"]),
        "left_right": _strict_equal(left_edge["left_endpoint"], right_edge["right_endpoint"]),
        "right_left": _strict_equal(left_edge["right_endpoint"], right_edge["left_endpoint"]),
        "right_right": _strict_equal(left_edge["right_endpoint"], right_edge["right_endpoint"]),
    }


def _relation(match_matrix: Mapping[str, bool]) -> str | None:
    values = tuple(match_matrix[field] for field in MATRIX_FIELDS)
    if values == (True, False, False, True):
        return AA_EDGE_SAME
    if values == (False, True, True, False):
        return AA_EDGE_REVERSED
    if sum(values) == 1:
        return AA_ONE_ENDPOINT_SHARED
    if sum(values) == 0:
        return AA_ENDPOINTS_DISJOINT
    return None


def _endpoint_relation_digest(
    left_edge: Mapping[str, Any], right_edge: Mapping[str, Any], match_matrix: Mapping[str, bool], relation: str
) -> str:
    return _digest(
        {
            "schema": INCIDENCE_SCHEMA,
            "incidence_scope": INCIDENCE_SCOPE,
            "left_edge": deepcopy_edge(left_edge),
            "right_edge": deepcopy_edge(right_edge),
            "match_matrix": dict(match_matrix),
            "relation": relation,
        }
    )


def _side_failure_classification(reason: str) -> str:
    if reason == "S25AA_NOT_POSITIVE":
        return S25AA_NOT_POSITIVE
    return S25AA_REJECTED


def _evaluate(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    try:
        snapshot = _snapshot(_parse(case))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")
    if not isinstance(snapshot, Mapping) or not _exact(snapshot, _TOP_LEVEL):
        return _invalid("CASE_SCHEMA_NOT_EXACT")
    if not _safe_value(snapshot):
        return _invalid("CASE_VALUE_NOT_SAFE")
    if (
        snapshot.get("schema_version") != HARNESS_SCHEMA
        or snapshot.get("observation_mode") != OBSERVATION_MODE
        or snapshot.get("canonicalization") != CANONICALIZATION
    ):
        return _invalid("CASE_PROFILE_INVALID")
    if not _hash(snapshot.get("input_digest")) or snapshot["input_digest"] != input_digest(snapshot):
        return _invalid("CASE_DIGEST_DRIFT")
    if not _valid_expected(snapshot["expected"]):
        return _invalid("EXPECTED_SCHEMA_OR_DIGEST_INVALID")
    if not _valid_witness(snapshot["endpoint_witness"]):
        return _invalid("ENDPOINT_WITNESS_SCHEMA_INVALID")

    left_reason, left_output, left_edge, left_result_digest = _evaluate_side(
        snapshot["left_case"], snapshot["left_output"]
    )
    right_reason, right_output, right_edge, right_result_digest = _evaluate_side(
        snapshot["right_case"], snapshot["right_output"]
    )
    if left_reason:
        return _blocked(
            left_reason,
            classification=_side_failure_classification(left_reason),
            left_edge=left_edge,
            right_edge=right_edge,
        )
    if right_reason:
        return _blocked(
            right_reason,
            classification=_side_failure_classification(right_reason),
            left_edge=left_edge,
            right_edge=right_edge,
        )
    assert left_output is not None and right_output is not None
    assert left_edge is not None and right_edge is not None
    assert left_result_digest is not None and right_result_digest is not None

    expected = snapshot["expected"]
    if (
        expected["left_aa_case_digest"] != s25aa_input_digest(snapshot["left_case"])
        or expected["right_aa_case_digest"] != s25aa_input_digest(snapshot["right_case"])
        or expected["left_aa_result_digest"] != left_result_digest
        or expected["right_aa_result_digest"] != right_result_digest
    ):
        return _blocked(
            "EXPECTED_AA_BINDING_MISMATCH",
            classification=AA_ENDPOINT_WITNESS_MISMATCH,
            left_edge=left_edge,
            right_edge=right_edge,
        )

    match_matrix = _matrix(left_edge, right_edge)
    relation = _relation(match_matrix)
    if relation is None:
        return _blocked(
            "ENDPOINT_MATRIX_IMPOSSIBLE",
            classification=AA_ENDPOINT_WITNESS_MISMATCH,
            left_edge=left_edge,
            right_edge=right_edge,
            match_matrix=match_matrix,
        )
    for left_endpoint in (left_edge["left_endpoint"], left_edge["right_endpoint"]):
        for right_endpoint in (right_edge["left_endpoint"], right_edge["right_endpoint"]):
            if (
                left_endpoint["z_case_digest"] == right_endpoint["z_case_digest"]
                and not _strict_equal(left_endpoint, right_endpoint)
            ):
                return _blocked(
                    "ENDPOINT_IDENTITY_CONFLICT",
                    classification=AA_ENDPOINT_WITNESS_MISMATCH,
                    left_edge=left_edge,
                    right_edge=right_edge,
                    match_matrix=match_matrix,
                )
    witness = snapshot["endpoint_witness"]
    if (
        not _strict_equal(witness["left_edge"], left_edge)
        or not _strict_equal(witness["right_edge"], right_edge)
        or not _strict_equal(witness["match_matrix"], match_matrix)
        or witness["relation"] != relation
    ):
        return _blocked(
            "ENDPOINT_WITNESS_MISMATCH",
            classification=AA_ENDPOINT_WITNESS_MISMATCH,
            left_edge=left_edge,
            right_edge=right_edge,
            match_matrix=match_matrix,
        )
    endpoint_digest = _endpoint_relation_digest(left_edge, right_edge, match_matrix, relation)
    if expected["endpoint_relation_digest"] != endpoint_digest:
        return _blocked(
            "ENDPOINT_RELATION_DIGEST_MISMATCH",
            classification=AA_ENDPOINT_WITNESS_MISMATCH,
            left_edge=left_edge,
            right_edge=right_edge,
            match_matrix=match_matrix,
        )
    if relation == AA_EDGE_SAME:
        return _blocked(
            "AA_EDGE_IDENTICAL_NOT_NEW",
            classification=AA_EDGE_SAME,
            left_edge=left_edge,
            right_edge=right_edge,
            match_matrix=match_matrix,
            endpoint_relation_digest=endpoint_digest,
        )
    if relation == AA_EDGE_REVERSED:
        return _blocked(
            "AA_EDGE_REVERSED_NOT_NEW",
            classification=AA_EDGE_REVERSED,
            left_edge=left_edge,
            right_edge=right_edge,
            match_matrix=match_matrix,
            endpoint_relation_digest=endpoint_digest,
        )
    if relation == AA_ONE_ENDPOINT_SHARED:
        return _result(
            AA_ONE_ENDPOINT_SHARED,
            PROPOSAL_ONLY,
            DESIGN_ONLY,
            "AA_ENDPOINT_INCIDENCE_ONE_SHARED",
            left_edge=left_edge,
            right_edge=right_edge,
            match_matrix=match_matrix,
            endpoint_relation_digest=endpoint_digest,
        )
    return _result(
        AA_ENDPOINTS_DISJOINT,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        "AA_ENDPOINT_INCIDENCE_DISJOINT",
        left_edge=left_edge,
        right_edge=right_edge,
        match_matrix=match_matrix,
        endpoint_relation_digest=endpoint_digest,
    )


def evaluate_endpoint_incidence(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Return a deterministic, non-temporal relation over two AA edges."""

    try:
        return _evaluate(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


def endpoint_relation_digest(
    left_edge: Mapping[str, Any], right_edge: Mapping[str, Any], match_matrix: Mapping[str, bool], relation: str
) -> str:
    """Return the canonical digest for the endpoint-incidence witness."""

    return _endpoint_relation_digest(left_edge, right_edge, match_matrix, relation)


def input_digest(case: Mapping[str, Any]) -> str:
    snapshot = _snapshot(case)
    if not isinstance(snapshot, Mapping):
        raise ValueError("case must be a mapping")
    return _digest({key: value for key, value in snapshot.items() if key != "input_digest"})


__all__ = [
    "AA_EDGE_REVERSED",
    "AA_EDGE_SAME",
    "AA_ENDPOINTS_DISJOINT",
    "AA_ENDPOINT_WITNESS_MISMATCH",
    "AA_FALSE_FLAG_KEYS",
    "AA_ONE_ENDPOINT_SHARED",
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "INCIDENCE_SCOPE",
    "INCIDENCE_SCHEMA",
    "INPUT_INVALID",
    "RESULT_KEYS",
    "S25AA_NOT_POSITIVE",
    "S25AA_REJECTED",
    "endpoint_relation_digest",
    "evaluate_endpoint_incidence",
    "input_digest",
]

