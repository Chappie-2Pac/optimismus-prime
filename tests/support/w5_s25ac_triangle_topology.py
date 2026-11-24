"""Pure directed triangle closure over the public S25AB boundary.

S25AC consumes three independently re-evaluated positive S25AB observations.
Each observation is treated as one directed pairing of two complete opaque
S25AA edge vectors.  The only new relation is whether those three pairings
form a closed directed three-cycle.  No endpoint is interpreted as a
real-world entity and no temporal, replay, causal, truth, authority, or
production claim is made.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Mapping

try:  # pragma: no cover - import path depends on the test runner
    from support.w5_s25ab_endpoint_incidence import (
        AA_EDGE_REVERSED,
        AA_EDGE_SAME,
        AA_ENDPOINTS_DISJOINT,
        AA_ENDPOINT_WITNESS_MISMATCH,
        AA_ONE_ENDPOINT_SHARED,
        CANONICALIZATION as S25AB_CANONICALIZATION,
        HARNESS_SCHEMA as S25AB_SCHEMA,
        INCIDENCE_SCOPE as S25AB_SCOPE,
        INPUT_INVALID as S25AB_INPUT_INVALID,
        RESULT_KEYS as S25AB_RESULT_KEYS,
        S25AA_NOT_POSITIVE,
        S25AA_REJECTED,
        endpoint_relation_digest as s25ab_endpoint_relation_digest,
        evaluate_endpoint_incidence,
        input_digest as s25ab_input_digest,
    )
except ImportError:  # pragma: no cover
    from w5_s25ab_endpoint_incidence import (  # type: ignore[no-redef]
        AA_EDGE_REVERSED,
        AA_EDGE_SAME,
        AA_ENDPOINTS_DISJOINT,
        AA_ENDPOINT_WITNESS_MISMATCH,
        AA_ONE_ENDPOINT_SHARED,
        CANONICALIZATION as S25AB_CANONICALIZATION,
        HARNESS_SCHEMA as S25AB_SCHEMA,
        INCIDENCE_SCOPE as S25AB_SCOPE,
        INPUT_INVALID as S25AB_INPUT_INVALID,
        RESULT_KEYS as S25AB_RESULT_KEYS,
        S25AA_NOT_POSITIVE,
        S25AA_REJECTED,
        endpoint_relation_digest as s25ab_endpoint_relation_digest,
        evaluate_endpoint_incidence,
        input_digest as s25ab_input_digest,
    )


HARNESS_SCHEMA = "s25ac.ordered-aa-edge-triangle.v1"
OBSERVATION_MODE = "TEST_ONLY"
CANONICALIZATION = S25AB_CANONICALIZATION
TRIANGLE_SCHEMA = "s25ac.ordered-aa-edge-triangle-witness.v1"
TRIANGLE_SCOPE = "S25AB_ORDERED_AA_EDGE_TRIANGLE_CLOSURE_ONLY"

AC_TRIANGLE_CLOSED = "AC_TRIANGLE_CLOSED"
AC_NOT_TRIANGLE = "AC_NOT_TRIANGLE"
AC_REJECTED = "AC_REJECTED"
S25AB_NOT_POSITIVE = "S25AB_NOT_POSITIVE"
S25AB_REJECTED = "S25AB_REJECTED"
INPUT_INVALID = "INPUT_INVALID"

PROPOSAL_ONLY = "PROPOSAL_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

AA_EDGE_FIELDS = ("left_endpoint", "right_endpoint")
IDENTITY_FIELDS = (
    "z_case_digest",
    "y_case_digest",
    "y_result_digest",
    "verdict_digest",
)
TOPOLOGY_RELATIONS = frozenset({AC_TRIANGLE_CLOSED, AC_NOT_TRIANGLE, AC_REJECTED})
AB_RELATION_CLASSES = frozenset(
    {
        AA_ONE_ENDPOINT_SHARED,
        AA_ENDPOINTS_DISJOINT,
        AA_EDGE_SAME,
        AA_EDGE_REVERSED,
        AA_ENDPOINT_WITNESS_MISMATCH,
        S25AA_NOT_POSITIVE,
        S25AA_REJECTED,
        S25AB_INPUT_INVALID,
    }
)
NON_POSITIVE_AB_CLASSES = frozenset({AA_ENDPOINTS_DISJOINT, AA_EDGE_SAME, AA_EDGE_REVERSED})

_HASH64 = re.compile(r"[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_MAX_DEPTH = 64
_MAX_STRING = 4096
_MAX_INTEGER = 2**63 - 1
_MAX_INPUT_BYTES = 8 * 1024 * 1024
# Three complete AB envelopes are nested below one AC envelope.
_MAX_NODES = 150000
_MAX_CONTAINER_ITEMS = 2048
_MAX_KEY_LENGTH = 256
_ZERO_HASH = "0" * 64

_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "first_ab_case",
        "first_ab_output",
        "second_ab_case",
        "second_ab_output",
        "third_ab_case",
        "third_ab_output",
        "topology_witness",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "first_ab_case_digest",
        "second_ab_case_digest",
        "third_ab_case_digest",
        "first_ab_result_digest",
        "second_ab_result_digest",
        "third_ab_result_digest",
        "triangle_digest",
    }
)
_EDGE_KEYS = frozenset(AA_EDGE_FIELDS)
_DIRECTED_EDGE_KEYS = frozenset({"from_edge", "to_edge"})
_WITNESS_KEYS = frozenset({"ordered_edges", "vertex_catalog", "relation"})
_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "topology_scope",
        "ordered_edges",
        "vertex_catalog",
        "triangle_digest",
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
        return json.loads(
            value.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_constant
        )
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_INPUT_BYTES:
            raise ValueError("input too large")
        return json.loads(
            value, object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_constant
        )
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
            and not any("\\ud800" <= char <= "\\udfff" for char in value)
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


def _zero_directed_edge() -> dict[str, dict[str, dict[str, str]]]:
    return {"from_edge": _zero_edge(), "to_edge": _zero_edge()}


def _deepcopy_edge(edge: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    return {
        "left_endpoint": dict(edge["left_endpoint"]),
        "right_endpoint": dict(edge["right_endpoint"]),
    }


def _deepcopy_directed_edge(edge: Mapping[str, Any]) -> dict[str, dict[str, dict[str, str]]]:
    return {"from_edge": _deepcopy_edge(edge["from_edge"]), "to_edge": _deepcopy_edge(edge["to_edge"])}


def _edge_key(edge: Mapping[str, Any]) -> bytes:
    return _canonical_json(_deepcopy_edge(edge))


def _directed_edge_equal(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return _strict_equal(left["from_edge"], right["from_edge"]) and _strict_equal(
        left["to_edge"], right["to_edge"]
    )


def _unique_edges(edges: list[Mapping[str, Any]]) -> list[dict[str, dict[str, str]]]:
    result: list[dict[str, dict[str, str]]] = []
    for edge in edges:
        if not any(_strict_equal(edge, existing) for existing in result):
            result.append(_deepcopy_edge(edge))
    return result


def _topology_digest(
    ordered_edges: list[Mapping[str, Any]], vertex_catalog: list[Mapping[str, Any]], relation: str
) -> str:
    return _digest(
        {
            "schema": TRIANGLE_SCHEMA,
            "topology_scope": TRIANGLE_SCOPE,
            "ordered_edges": [_deepcopy_directed_edge(edge) for edge in ordered_edges],
            "vertex_catalog": [_deepcopy_edge(edge) for edge in vertex_catalog],
            "relation": relation,
        }
    )


def _result(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    ordered_edges: list[Mapping[str, Any]] | None = None,
    vertex_catalog: list[Mapping[str, Any]] | None = None,
    triangle_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVATION_MODE,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "topology_scope": TRIANGLE_SCOPE,
        "ordered_edges": [_deepcopy_directed_edge(edge) for edge in (ordered_edges or [])],
        "vertex_catalog": [_deepcopy_edge(edge) for edge in (vertex_catalog or [])],
        "triangle_digest": triangle_digest,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _result(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(
    reason: str,
    *,
    classification: str = AC_REJECTED,
    ordered_edges: list[Mapping[str, Any]] | None = None,
    vertex_catalog: list[Mapping[str, Any]] | None = None,
    triangle_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return _result(
        classification,
        TEST_BLOCKED,
        HOLD,
        reason,
        ordered_edges=ordered_edges,
        vertex_catalog=vertex_catalog,
        triangle_digest=triangle_digest,
    )


def _valid_endpoint(endpoint: Any) -> bool:
    return (
        isinstance(endpoint, Mapping)
        and _exact(endpoint, frozenset(IDENTITY_FIELDS))
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


def _valid_directed_edge(edge: Any) -> bool:
    return (
        isinstance(edge, Mapping)
        and _exact(edge, _DIRECTED_EDGE_KEYS)
        and _safe_value(edge)
        and _valid_edge(edge.get("from_edge"))
        and _valid_edge(edge.get("to_edge"))
    )


def _aa_edge_identity_consistent(edge: Mapping[str, Any]) -> bool:
    return edge["left_endpoint"]["z_case_digest"] != edge["right_endpoint"]["z_case_digest"]


def _cross_edge_identity_consistent(left_edge: Mapping[str, Any], right_edge: Mapping[str, Any]) -> bool:
    endpoints = (
        left_edge["left_endpoint"],
        left_edge["right_endpoint"],
        right_edge["left_endpoint"],
        right_edge["right_endpoint"],
    )
    return all(
        not any(
            first["z_case_digest"] == second["z_case_digest"] and not _strict_equal(first, second)
            for second in endpoints[index + 1 :]
        )
        for index, first in enumerate(endpoints)
    )


def _valid_witness(witness: Any) -> bool:
    if not isinstance(witness, Mapping) or not _exact(witness, _WITNESS_KEYS) or not _safe_value(witness):
        return False
    ordered_edges = witness.get("ordered_edges")
    vertex_catalog = witness.get("vertex_catalog")
    return (
        isinstance(ordered_edges, list)
        and len(ordered_edges) == 3
        and all(_valid_directed_edge(edge) for edge in ordered_edges)
        and isinstance(vertex_catalog, list)
        and 1 <= len(vertex_catalog) <= 6
        and all(_valid_edge(edge) for edge in vertex_catalog)
        and witness.get("relation") in TOPOLOGY_RELATIONS
    )


def _valid_ab_output(output: Any) -> bool:
    if not isinstance(output, Mapping) or not _exact(output, frozenset(S25AB_RESULT_KEYS)) or not _safe_value(output):
        return False
    if output.get("schema_version") != S25AB_SCHEMA or output.get("observation_mode") != OBSERVATION_MODE:
        return False
    if output.get("incidence_scope") != S25AB_SCOPE:
        return False
    if output.get("production_status") != PRODUCTION_NOT_AUTHORIZED or output.get("authority_claim") != NOT_CLAIMED:
        return False
    if output.get("classification") not in AB_RELATION_CLASSES:
        return False
    if not _valid_edge(output.get("left_edge")) or not _valid_edge(output.get("right_edge")):
        return False
    matrix = output.get("match_matrix")
    if (
        not isinstance(matrix, Mapping)
        or set(matrix) != {"left_left", "left_right", "right_left", "right_right"}
        or any(type(matrix.get(field)) is not bool for field in matrix)
        or not _safe_value(matrix)
        or not _hash(output.get("endpoint_relation_digest"))
    ):
        return False
    if output.get("classification") in {AA_ONE_ENDPOINT_SHARED, AA_ENDPOINTS_DISJOINT}:
        expected_matrix = {
            "left_left": _strict_equal(output["left_edge"]["left_endpoint"], output["right_edge"]["left_endpoint"]),
            "left_right": _strict_equal(output["left_edge"]["left_endpoint"], output["right_edge"]["right_endpoint"]),
            "right_left": _strict_equal(output["left_edge"]["right_endpoint"], output["right_edge"]["left_endpoint"]),
            "right_right": _strict_equal(output["left_edge"]["right_endpoint"], output["right_edge"]["right_endpoint"]),
        }
        relation = (
            AA_ONE_ENDPOINT_SHARED if output["classification"] == AA_ONE_ENDPOINT_SHARED else AA_ENDPOINTS_DISJOINT
        )
        expected_status = PROPOSAL_ONLY
        expected_decision = DESIGN_ONLY
        expected_reason = (
            "AA_ENDPOINT_INCIDENCE_ONE_SHARED"
            if relation == AA_ONE_ENDPOINT_SHARED
            else "AA_ENDPOINT_INCIDENCE_DISJOINT"
        )
        expected_count = 1 if relation == AA_ONE_ENDPOINT_SHARED else 0
        return (
            output.get("status") == expected_status
            and output.get("decision") == expected_decision
            and output.get("reason") == expected_reason
            and dict(matrix) == expected_matrix
            and sum(expected_matrix.values()) == expected_count
            and (
                relation != AA_ONE_ENDPOINT_SHARED
                or (
                    _aa_edge_identity_consistent(output["left_edge"])
                    and _aa_edge_identity_consistent(output["right_edge"])
                    and _cross_edge_identity_consistent(output["left_edge"], output["right_edge"])
                )
            )
            and output.get("endpoint_relation_digest")
            == s25ab_endpoint_relation_digest(
                output["left_edge"],
                output["right_edge"],
                expected_matrix,
                relation,
            )
        )
    return output.get("status") == TEST_BLOCKED and output.get("decision") == HOLD and isinstance(
        output.get("reason"), str
    )


def _evaluate_side(
    case: Any, supplied_output: Any
) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None, str | None]:
    if not isinstance(case, Mapping) or not _safe_value(case):
        return "S25AB_CASE_INVALID", None, None, None
    try:
        case_digest = s25ab_input_digest(case)
        if not _hash(case.get("input_digest")) or case["input_digest"] != case_digest:
            return "S25AB_CASE_DIGEST_DRIFT", None, None, None
        actual_output = _snapshot(evaluate_endpoint_incidence(case))
    except Exception:
        return "S25AB_RESULT_UNREADABLE", None, None, None
    if not _strict_equal(supplied_output, actual_output):
        return "S25AB_RESULT_MISMATCH", None, None, None
    if not _valid_ab_output(actual_output):
        return "S25AB_RESULT_INVALID", actual_output if isinstance(actual_output, dict) else None, None, None
    result_digest = _digest(actual_output)
    if actual_output["classification"] in NON_POSITIVE_AB_CLASSES:
        return S25AB_NOT_POSITIVE, actual_output, None, result_digest
    if actual_output["classification"] != AA_ONE_ENDPOINT_SHARED:
        return S25AB_REJECTED, actual_output, None, result_digest
    return "", actual_output, {
        "from_edge": _deepcopy_edge(actual_output["left_edge"]),
        "to_edge": _deepcopy_edge(actual_output["right_edge"]),
    }, result_digest


def _topology(
    directed_edges: list[Mapping[str, Any]],
) -> tuple[str, list[dict[str, Any]], list[dict[str, dict[str, str]]], str]:
    observed = [_deepcopy_directed_edge(edge) for edge in directed_edges]
    vertices = _unique_edges(
        [edge["from_edge"] for edge in observed] + [edge["to_edge"] for edge in observed]
    )
    catalog = sorted(vertices, key=_edge_key)

    if any(_strict_equal(edge["from_edge"], edge["to_edge"]) for edge in observed):
        relation = AC_REJECTED
        return relation, observed, catalog, _topology_digest(observed, catalog, relation)
    for index, edge in enumerate(observed):
        for other in observed[index + 1 :]:
            if _directed_edge_equal(edge, other):
                relation = AC_REJECTED
                return relation, observed, catalog, _topology_digest(observed, catalog, relation)
            if _strict_equal(edge["from_edge"], other["to_edge"]) and _strict_equal(
                edge["to_edge"], other["from_edge"]
            ):
                relation = AC_REJECTED
                return relation, observed, catalog, _topology_digest(observed, catalog, relation)

    if len(vertices) != 3:
        relation = AC_NOT_TRIANGLE
        return relation, observed, catalog, _topology_digest(observed, catalog, relation)

    outgoing: dict[bytes, tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]] = {}
    incoming: dict[bytes, int] = {}
    for edge in observed:
        source = edge["from_edge"]
        target = edge["to_edge"]
        source_key = _edge_key(source)
        target_key = _edge_key(target)
        if source_key in outgoing:
            relation = AC_NOT_TRIANGLE
            return relation, observed, catalog, _topology_digest(observed, catalog, relation)
        outgoing[source_key] = (_deepcopy_edge(source), _deepcopy_edge(target))
        incoming[target_key] = incoming.get(target_key, 0) + 1
    if len(outgoing) != 3 or set(incoming) != {_edge_key(vertex) for vertex in vertices} or any(
        count != 1 for count in incoming.values()
    ):
        relation = AC_NOT_TRIANGLE
        return relation, observed, catalog, _topology_digest(observed, catalog, relation)

    start = catalog[0]
    ordered: list[dict[str, Any]] = []
    current = start
    for _ in range(3):
        pair = outgoing.get(_edge_key(current))
        if pair is None:
            relation = AC_NOT_TRIANGLE
            return relation, observed, catalog, _topology_digest(observed, catalog, relation)
        source, target = pair
        ordered.append({"from_edge": source, "to_edge": target})
        current = target
    if not _strict_equal(current, start):
        relation = AC_NOT_TRIANGLE
        return relation, observed, catalog, _topology_digest(observed, catalog, relation)
    relation = AC_TRIANGLE_CLOSED
    return relation, ordered, catalog, _topology_digest(ordered, catalog, relation)


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
    if not _valid_witness(snapshot["topology_witness"]):
        return _invalid("TOPOLOGY_WITNESS_SCHEMA_INVALID")

    sides = (
        (snapshot["first_ab_case"], snapshot["first_ab_output"]),
        (snapshot["second_ab_case"], snapshot["second_ab_output"]),
        (snapshot["third_ab_case"], snapshot["third_ab_output"]),
    )
    evaluations = [_evaluate_side(ab_case, ab_output) for ab_case, ab_output in sides]
    for reason, _output, _edge, _digest_value in evaluations:
        if reason:
            if reason == S25AB_NOT_POSITIVE:
                return _blocked(reason, classification=S25AB_NOT_POSITIVE)
            return _blocked(reason, classification=S25AB_REJECTED)
    if any(edge is None or result_digest is None for _reason, _output, edge, result_digest in evaluations):
        return _blocked("S25AB_RESULT_UNREADABLE", classification=S25AB_REJECTED)

    expected = snapshot["expected"]
    case_digest_fields = (
        "first_ab_case_digest",
        "second_ab_case_digest",
        "third_ab_case_digest",
    )
    result_digest_fields = (
        "first_ab_result_digest",
        "second_ab_result_digest",
        "third_ab_result_digest",
    )
    for (ab_case, _ab_output), case_field, result_field, (_reason, _output, _edge, result_digest) in zip(
        sides, case_digest_fields, result_digest_fields, evaluations
    ):
        if expected[case_field] != s25ab_input_digest(ab_case) or expected[result_field] != result_digest:
            return _blocked("EXPECTED_AB_BINDING_MISMATCH", classification=AC_REJECTED)

    directed_edges = [evaluation[2] for evaluation in evaluations]
    assert all(edge is not None for edge in directed_edges)
    relation, ordered_edges, vertex_catalog, triangle_digest = _topology(directed_edges)  # type: ignore[arg-type]
    witness = snapshot["topology_witness"]
    witness_edges = [_deepcopy_directed_edge(edge) for edge in witness["ordered_edges"]]
    witness_catalog = [_deepcopy_edge(edge) for edge in witness["vertex_catalog"]]
    if (
        not _strict_equal(witness_edges, ordered_edges)
        or not _strict_equal(witness_catalog, vertex_catalog)
        or witness["relation"] != relation
    ):
        return _blocked(
            "TOPOLOGY_WITNESS_MISMATCH",
            classification=AC_REJECTED,
            ordered_edges=ordered_edges,
            vertex_catalog=vertex_catalog,
        )
    if expected["triangle_digest"] != triangle_digest:
        return _blocked(
            "TRIANGLE_DIGEST_MISMATCH",
            classification=AC_REJECTED,
            ordered_edges=ordered_edges,
            vertex_catalog=vertex_catalog,
        )
    if relation == AC_TRIANGLE_CLOSED:
        return _result(
            AC_TRIANGLE_CLOSED,
            PROPOSAL_ONLY,
            DESIGN_ONLY,
            "AC_ORDERED_AA_EDGE_TRIANGLE_CLOSED",
            ordered_edges=ordered_edges,
            vertex_catalog=vertex_catalog,
            triangle_digest=triangle_digest,
        )
    if relation == AC_REJECTED:
        return _blocked(
            "AC_TOPOLOGY_REJECTED",
            classification=AC_REJECTED,
            ordered_edges=ordered_edges,
            vertex_catalog=vertex_catalog,
            triangle_digest=triangle_digest,
        )
    return _blocked(
        "AC_TRIANGLE_NOT_CLOSED",
        classification=AC_NOT_TRIANGLE,
        ordered_edges=ordered_edges,
        vertex_catalog=vertex_catalog,
        triangle_digest=triangle_digest,
    )


def _valid_expected(expected: Any) -> bool:
    return isinstance(expected, Mapping) and _exact(expected, _EXPECTED_KEYS) and all(
        _hash(expected.get(field)) for field in _EXPECTED_KEYS
    )


def evaluate_triangle_topology(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Return a deterministic, non-temporal relation over three AB observations."""

    try:
        return _evaluate(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


def input_digest(case: Mapping[str, Any]) -> str:
    snapshot = _snapshot(case)
    if not isinstance(snapshot, Mapping):
        raise ValueError("case must be a mapping")
    return _digest({key: value for key, value in snapshot.items() if key != "input_digest"})


def topology_digest(
    ordered_edges: list[Mapping[str, Any]], vertex_catalog: list[Mapping[str, Any]], relation: str
) -> str:
    """Return the canonical digest for a complete AC topology witness."""

    return _topology_digest(ordered_edges, vertex_catalog, relation)


__all__ = [
    "AC_NOT_TRIANGLE",
    "AC_REJECTED",
    "AC_TRIANGLE_CLOSED",
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "INPUT_INVALID",
    "RESULT_KEYS",
    "S25AB_NOT_POSITIVE",
    "S25AB_REJECTED",
    "TRIANGLE_SCOPE",
    "evaluate_triangle_topology",
    "input_digest",
    "topology_digest",
]
