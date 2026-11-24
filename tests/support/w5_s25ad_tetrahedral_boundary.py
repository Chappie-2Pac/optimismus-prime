"""Pure signed tetrahedral boundary closure over the public S25AC boundary.

S25AD consumes four independently re-evaluated positive S25AC triangle
observations.  It checks only a formal signed 2-chain invariant: the four
oriented triangular faces must be the boundary of one abstract 3-simplex.
The complete AA-edge vertices remain opaque values.  No geometric,
real-world, temporal, causal, truth, authority, or production meaning is
inferred.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any, Mapping

try:  # pragma: no cover - import path depends on the test runner
    from support.w5_s25ac_triangle_topology import (
        AC_NOT_TRIANGLE,
        AC_REJECTED as S25AC_REJECTED,
        AC_TRIANGLE_CLOSED,
        CANONICALIZATION as S25AC_CANONICALIZATION,
        HARNESS_SCHEMA as S25AC_SCHEMA,
        INPUT_INVALID as S25AC_INPUT_INVALID,
        RESULT_KEYS as S25AC_RESULT_KEYS,
        TRIANGLE_SCOPE as S25AC_SCOPE,
        evaluate_triangle_topology,
        input_digest as s25ac_input_digest,
        topology_digest as s25ac_topology_digest,
    )
except ImportError:  # pragma: no cover
    from w5_s25ac_triangle_topology import (  # type: ignore[no-redef]
        AC_NOT_TRIANGLE,
        AC_REJECTED as S25AC_REJECTED,
        AC_TRIANGLE_CLOSED,
        CANONICALIZATION as S25AC_CANONICALIZATION,
        HARNESS_SCHEMA as S25AC_SCHEMA,
        INPUT_INVALID as S25AC_INPUT_INVALID,
        RESULT_KEYS as S25AC_RESULT_KEYS,
        TRIANGLE_SCOPE as S25AC_SCOPE,
        evaluate_triangle_topology,
        input_digest as s25ac_input_digest,
        topology_digest as s25ac_topology_digest,
    )


HARNESS_SCHEMA = "s25ad.signed-tetrahedral-boundary.v1"
OBSERVATION_MODE = "TEST_ONLY"
CANONICALIZATION = S25AC_CANONICALIZATION
BOUNDARY_SCHEMA = "s25ad.signed-tetrahedral-boundary-witness.v1"
BOUNDARY_SCOPE = "S25AC_SIGNED_TETRAHEDRAL_BOUNDARY_ONLY"

AD_TETRAHEDRAL_BOUNDARY_CLOSED = "AD_TETRAHEDRAL_BOUNDARY_CLOSED"
AD_NOT_TETRAHEDRAL = "AD_NOT_TETRAHEDRAL"
AD_REJECTED = "AD_REJECTED"
AC_NOT_POSITIVE = "AC_NOT_POSITIVE"
AC_REJECTED = "AC_REJECTED"
INPUT_INVALID = "INPUT_INVALID"

PROPOSAL_ONLY = "PROPOSAL_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

IDENTITY_FIELDS = (
    "z_case_digest",
    "y_case_digest",
    "y_result_digest",
    "verdict_digest",
)
EDGE_FIELDS = ("left_endpoint", "right_endpoint")
BASE_CYCLES = (
    (1, 2, 3),
    (0, 2, 3),
    (0, 1, 3),
    (0, 1, 2),
)
BASE_SIGNS = (1, -1, 1, -1)
AC_CLASSES = frozenset({AC_TRIANGLE_CLOSED, AC_NOT_TRIANGLE, S25AC_REJECTED, S25AC_INPUT_INVALID})

_HASH64 = re.compile(r"[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_MAX_DEPTH = 64
_MAX_STRING = 4096
_MAX_INTEGER = 2**63 - 1
_MAX_INPUT_BYTES = 16 * 1024 * 1024
# Four AC envelopes contain twelve AB observations and their lower cases.
_MAX_NODES = 300000
_MAX_CONTAINER_ITEMS = 2048
_MAX_KEY_LENGTH = 256
_ZERO_HASH = "0" * 64

_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "first_ac_case",
        "first_ac_output",
        "second_ac_case",
        "second_ac_output",
        "third_ac_case",
        "third_ac_output",
        "fourth_ac_case",
        "fourth_ac_output",
        "boundary_witness",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "first_ac_case_digest",
        "second_ac_case_digest",
        "third_ac_case_digest",
        "fourth_ac_case_digest",
        "first_ac_result_digest",
        "second_ac_result_digest",
        "third_ac_result_digest",
        "fourth_ac_result_digest",
        "boundary_digest",
    }
)
_EDGE_KEYS = frozenset(EDGE_FIELDS)
_DIRECTED_EDGE_KEYS = frozenset({"from_edge", "to_edge"})
_FACE_KEYS = frozenset({"opposite_index", "ordered_edges", "orientation"})
_WITNESS_KEYS = frozenset({"ordered_faces", "vertex_catalog", "orientation_pattern", "relation"})
_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "boundary_scope",
        "ordered_faces",
        "vertex_catalog",
        "orientation_pattern",
        "boundary_digest",
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


def _deepcopy_edge(edge: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    return {"left_endpoint": dict(edge["left_endpoint"]), "right_endpoint": dict(edge["right_endpoint"])}


def _deepcopy_directed_edge(edge: Mapping[str, Any]) -> dict[str, dict[str, dict[str, str]]]:
    return {"from_edge": _deepcopy_edge(edge["from_edge"]), "to_edge": _deepcopy_edge(edge["to_edge"])}


def _deepcopy_face(face: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "opposite_index": face["opposite_index"],
        "ordered_edges": [_deepcopy_directed_edge(edge) for edge in face["ordered_edges"]],
        "orientation": face["orientation"],
    }


def _edge_key(edge: Mapping[str, Any]) -> bytes:
    return _canonical_json(_deepcopy_edge(edge))


def _unique_edges(edges: list[Mapping[str, Any]]) -> list[dict[str, dict[str, str]]]:
    result: list[dict[str, dict[str, str]]] = []
    for edge in edges:
        if not any(_strict_equal(edge, existing) for existing in result):
            result.append(_deepcopy_edge(edge))
    return result


def _boundary_digest(
    ordered_faces: list[Mapping[str, Any]],
    vertex_catalog: list[Mapping[str, Any]],
    orientation_pattern: list[int],
    relation: str,
) -> str:
    return _digest(
        {
            "schema": BOUNDARY_SCHEMA,
            "boundary_scope": BOUNDARY_SCOPE,
            "ordered_faces": [_deepcopy_face(face) for face in ordered_faces],
            "vertex_catalog": [_deepcopy_edge(edge) for edge in vertex_catalog],
            "orientation_pattern": list(orientation_pattern),
            "relation": relation,
        }
    )


def _result(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    ordered_faces: list[Mapping[str, Any]] | None = None,
    vertex_catalog: list[Mapping[str, Any]] | None = None,
    orientation_pattern: list[int] | None = None,
    boundary_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVATION_MODE,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "boundary_scope": BOUNDARY_SCOPE,
        "ordered_faces": [_deepcopy_face(face) for face in (ordered_faces or [])],
        "vertex_catalog": [_deepcopy_edge(edge) for edge in (vertex_catalog or [])],
        "orientation_pattern": list(orientation_pattern or []),
        "boundary_digest": boundary_digest,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _result(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(
    reason: str,
    *,
    classification: str = AD_REJECTED,
    ordered_faces: list[Mapping[str, Any]] | None = None,
    vertex_catalog: list[Mapping[str, Any]] | None = None,
    orientation_pattern: list[int] | None = None,
    boundary_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return _result(
        classification,
        TEST_BLOCKED,
        HOLD,
        reason,
        ordered_faces=ordered_faces,
        vertex_catalog=vertex_catalog,
        orientation_pattern=orientation_pattern,
        boundary_digest=boundary_digest,
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


def _valid_face(face: Any) -> bool:
    if not isinstance(face, Mapping) or not _exact(face, _FACE_KEYS) or not _safe_value(face):
        return False
    return (
        type(face.get("opposite_index")) is int
        and 0 <= face["opposite_index"] < 4
        and type(face.get("orientation")) is int
        and face["orientation"] in {-1, 1}
        and isinstance(face.get("ordered_edges"), list)
        and len(face["ordered_edges"]) == 3
        and all(_valid_directed_edge(edge) for edge in face["ordered_edges"])
    )


def _valid_witness(witness: Any) -> bool:
    if not isinstance(witness, Mapping) or not _exact(witness, _WITNESS_KEYS) or not _safe_value(witness):
        return False
    relation = witness.get("relation")
    if relation == AD_TETRAHEDRAL_BOUNDARY_CLOSED:
        return (
            isinstance(witness.get("ordered_faces"), list)
            and len(witness["ordered_faces"]) == 4
            and all(_valid_face(face) for face in witness["ordered_faces"])
            and isinstance(witness.get("vertex_catalog"), list)
            and len(witness["vertex_catalog"]) == 4
            and all(_valid_edge(edge) for edge in witness["vertex_catalog"])
            and isinstance(witness.get("orientation_pattern"), list)
            and witness["orientation_pattern"] == list(BASE_SIGNS)
        )
    return (
        relation == AD_NOT_TETRAHEDRAL
        and witness.get("ordered_faces") == []
        and witness.get("vertex_catalog") == []
        and witness.get("orientation_pattern") == []
    )


def _valid_expected(expected: Any) -> bool:
    return isinstance(expected, Mapping) and _exact(expected, _EXPECTED_KEYS) and all(
        _hash(expected.get(field)) for field in _EXPECTED_KEYS
    )


def _cycle_from_output(output: Mapping[str, Any]) -> list[dict[str, dict[str, str]]]:
    return [_deepcopy_edge(edge["from_edge"]) for edge in output["ordered_edges"]]


def _valid_positive_ac_output(output: Mapping[str, Any]) -> bool:
    ordered_edges = output.get("ordered_edges")
    catalog = output.get("vertex_catalog")
    if (
        not isinstance(ordered_edges, list)
        or len(ordered_edges) != 3
        or not all(_valid_directed_edge(edge) for edge in ordered_edges)
        or not isinstance(catalog, list)
        or len(catalog) != 3
        or not all(_valid_edge(edge) for edge in catalog)
    ):
        return False
    sources = [edge["from_edge"] for edge in ordered_edges]
    targets = [edge["to_edge"] for edge in ordered_edges]
    if len(_unique_edges(sources)) != 3 or any(_strict_equal(source, target) for source, target in zip(sources, targets)):
        return False
    if any(
        not _strict_equal(ordered_edges[index]["to_edge"], ordered_edges[(index + 1) % 3]["from_edge"])
        for index in range(3)
    ):
        return False
    expected_catalog = sorted(_unique_edges(sources), key=_edge_key)
    return (
        _strict_equal(catalog, expected_catalog)
        and output.get("triangle_digest")
        == s25ac_topology_digest(ordered_edges, expected_catalog, AC_TRIANGLE_CLOSED)
    )


def _valid_ac_output(output: Any) -> bool:
    if not isinstance(output, Mapping) or not _exact(output, frozenset(S25AC_RESULT_KEYS)) or not _safe_value(output):
        return False
    if output.get("schema_version") != S25AC_SCHEMA or output.get("observation_mode") != OBSERVATION_MODE:
        return False
    if output.get("topology_scope") != S25AC_SCOPE:
        return False
    if output.get("production_status") != PRODUCTION_NOT_AUTHORIZED or output.get("authority_claim") != NOT_CLAIMED:
        return False
    if output.get("classification") not in AC_CLASSES or not _hash(output.get("triangle_digest")):
        return False
    if output.get("classification") == AC_TRIANGLE_CLOSED:
        return (
            output.get("status") == PROPOSAL_ONLY
            and output.get("decision") == DESIGN_ONLY
            and output.get("reason") == "AC_ORDERED_AA_EDGE_TRIANGLE_CLOSED"
            and _valid_positive_ac_output(output)
        )
    ordered_edges = output.get("ordered_edges")
    catalog = output.get("vertex_catalog")
    return (
        output.get("status") == TEST_BLOCKED
        and output.get("decision") == HOLD
        and isinstance(output.get("reason"), str)
        and isinstance(ordered_edges, list)
        and len(ordered_edges) in {0, 3}
        and all(_valid_directed_edge(edge) for edge in ordered_edges)
        and isinstance(catalog, list)
        and len(catalog) <= 6
        and all(_valid_edge(edge) for edge in catalog)
    )


def _evaluate_side(
    case: Any, supplied_output: Any
) -> tuple[str, dict[str, Any] | None, list[dict[str, dict[str, str]]] | None, str | None]:
    if not isinstance(case, Mapping) or not _safe_value(case):
        return "S25AC_CASE_INVALID", None, None, None
    try:
        case_digest = s25ac_input_digest(case)
        if not _hash(case.get("input_digest")) or case["input_digest"] != case_digest:
            return "S25AC_CASE_DIGEST_DRIFT", None, None, None
        actual_output = _snapshot(evaluate_triangle_topology(case))
    except Exception:
        return "S25AC_RESULT_UNREADABLE", None, None, None
    if not _strict_equal(supplied_output, actual_output):
        return "S25AC_RESULT_MISMATCH", None, None, None
    if not _valid_ac_output(actual_output):
        return "S25AC_RESULT_INVALID", actual_output if isinstance(actual_output, dict) else None, None, None
    result_digest = _digest(actual_output)
    if actual_output["classification"] == AC_TRIANGLE_CLOSED:
        return "", actual_output, _cycle_from_output(actual_output), result_digest
    if actual_output["classification"] == AC_NOT_TRIANGLE:
        return AC_NOT_POSITIVE, actual_output, None, result_digest
    return AC_REJECTED, actual_output, None, result_digest


def _rotate_equal(actual: list[int], expected: tuple[int, int, int]) -> int:
    expected_list = list(expected)
    for offset in range(3):
        if actual == expected_list[offset:] + expected_list[:offset]:
            return 1
    reversed_expected = list(reversed(expected_list))
    for offset in range(3):
        if actual == reversed_expected[offset:] + reversed_expected[:offset]:
            return -1
    return 0


def _make_face(vertex_catalog: list[Mapping[str, Any]], opposite_index: int) -> dict[str, Any]:
    cycle = BASE_CYCLES[opposite_index]
    ordered_edges = [
        {
            "from_edge": _deepcopy_edge(vertex_catalog[source]),
            "to_edge": _deepcopy_edge(vertex_catalog[target]),
        }
        for source, target in zip(cycle, cycle[1:] + cycle[:1])
    ]
    return {"opposite_index": opposite_index, "ordered_edges": ordered_edges, "orientation": BASE_SIGNS[opposite_index]}


def _analyze(
    cycles: list[list[dict[str, dict[str, str]]]],
) -> tuple[list[dict[str, Any]], list[dict[str, dict[str, str]]], list[int], str] | None:
    vertices = _unique_edges([edge for cycle in cycles for edge in cycle])
    catalog = sorted(vertices, key=_edge_key)
    if len(catalog) != 4:
        return None
    id_by_key = {_edge_key(edge): index for index, edge in enumerate(catalog)}
    face_ids: list[list[int]] = []
    for cycle in cycles:
        ids = [id_by_key[_edge_key(edge)] for edge in cycle]
        if len(set(ids)) != 3:
            return None
        face_ids.append(ids)
    face_sets = [frozenset(ids) for ids in face_ids]
    expected_sets = {frozenset(set(range(4)) - {missing}) for missing in range(4)}
    if len(set(face_sets)) != 4 or set(face_sets) != expected_sets:
        return None

    actual_signs: list[int] = [0, 0, 0, 0]
    for ids in face_ids:
        missing = next(index for index in range(4) if index not in ids)
        relative_sign = _rotate_equal(ids, BASE_CYCLES[missing])
        if relative_sign == 0:
            return None
        actual_signs[missing] = relative_sign
    if actual_signs not in (list(BASE_SIGNS), [-sign for sign in BASE_SIGNS]):
        return None

    boundary_edges: dict[tuple[int, int], list[tuple[int, int]]] = {}
    for ids in face_ids:
        for source, target in zip(ids, ids[1:] + ids[:1]):
            key = tuple(sorted((source, target)))
            boundary_edges.setdefault(key, []).append((source, target))
    if len(boundary_edges) != 6 or any(
        len(directions) != 2 or directions[0] == directions[1] for directions in boundary_edges.values()
    ):
        return None

    ordered_faces = [_make_face(catalog, missing) for missing in range(4)]
    orientation_pattern = list(BASE_SIGNS)
    relation = AD_TETRAHEDRAL_BOUNDARY_CLOSED
    digest = _boundary_digest(ordered_faces, catalog, orientation_pattern, relation)
    return ordered_faces, catalog, orientation_pattern, digest


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
    if not _valid_witness(snapshot["boundary_witness"]):
        return _invalid("BOUNDARY_WITNESS_SCHEMA_INVALID")

    sides = (
        (snapshot["first_ac_case"], snapshot["first_ac_output"]),
        (snapshot["second_ac_case"], snapshot["second_ac_output"]),
        (snapshot["third_ac_case"], snapshot["third_ac_output"]),
        (snapshot["fourth_ac_case"], snapshot["fourth_ac_output"]),
    )
    evaluations = [_evaluate_side(ac_case, ac_output) for ac_case, ac_output in sides]
    for reason, _output, _cycle, _result_digest in evaluations:
        if reason:
            if reason == AC_NOT_POSITIVE:
                return _blocked(reason, classification=AC_NOT_POSITIVE)
            return _blocked(reason, classification=AC_REJECTED)
    if any(cycle is None or result_digest is None for _reason, _output, cycle, result_digest in evaluations):
        return _blocked("S25AC_RESULT_UNREADABLE", classification=AC_REJECTED)

    expected = snapshot["expected"]
    case_digest_fields = (
        "first_ac_case_digest",
        "second_ac_case_digest",
        "third_ac_case_digest",
        "fourth_ac_case_digest",
    )
    result_digest_fields = (
        "first_ac_result_digest",
        "second_ac_result_digest",
        "third_ac_result_digest",
        "fourth_ac_result_digest",
    )
    for (ac_case, _ac_output), case_field, result_field, (_reason, _output, _cycle, result_digest) in zip(
        sides, case_digest_fields, result_digest_fields, evaluations
    ):
        if expected[case_field] != s25ac_input_digest(ac_case) or expected[result_field] != result_digest:
            return _blocked("EXPECTED_AC_BINDING_MISMATCH", classification=AC_REJECTED)

    cycles = [evaluation[2] for evaluation in evaluations]
    assert all(cycle is not None for cycle in cycles)
    analysis = _analyze(cycles)  # type: ignore[arg-type]
    witness = snapshot["boundary_witness"]
    if analysis is None:
        if (
            witness["relation"] != AD_NOT_TETRAHEDRAL
            or witness["ordered_faces"] != []
            or witness["vertex_catalog"] != []
            or witness["orientation_pattern"] != []
        ):
            return _blocked("BOUNDARY_WITNESS_MISMATCH", classification=AD_REJECTED)
        if expected["boundary_digest"] != _ZERO_HASH:
            return _blocked("BOUNDARY_DIGEST_MISMATCH", classification=AD_REJECTED)
        return _blocked("AD_BOUNDARY_NOT_CLOSED", classification=AD_NOT_TETRAHEDRAL)

    ordered_faces, vertex_catalog, orientation_pattern, boundary_digest = analysis
    if (
        witness["relation"] != AD_TETRAHEDRAL_BOUNDARY_CLOSED
        or not _strict_equal(witness["ordered_faces"], ordered_faces)
        or not _strict_equal(witness["vertex_catalog"], vertex_catalog)
        or witness["orientation_pattern"] != orientation_pattern
    ):
        return _blocked("BOUNDARY_WITNESS_MISMATCH", classification=AD_REJECTED)
    if expected["boundary_digest"] != boundary_digest:
        return _blocked("BOUNDARY_DIGEST_MISMATCH", classification=AD_REJECTED)
    return _result(
        AD_TETRAHEDRAL_BOUNDARY_CLOSED,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        "AD_SIGNED_TETRAHEDRAL_BOUNDARY_CLOSED",
        ordered_faces=ordered_faces,
        vertex_catalog=vertex_catalog,
        orientation_pattern=orientation_pattern,
        boundary_digest=boundary_digest,
    )


def evaluate_tetrahedral_boundary(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Return a deterministic formal signed-boundary relation over four AC faces."""

    try:
        return _evaluate(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


def input_digest(case: Mapping[str, Any]) -> str:
    snapshot = _snapshot(case)
    if not isinstance(snapshot, Mapping):
        raise ValueError("case must be a mapping")
    return _digest({key: value for key, value in snapshot.items() if key != "input_digest"})


def boundary_digest(
    ordered_faces: list[Mapping[str, Any]],
    vertex_catalog: list[Mapping[str, Any]],
    orientation_pattern: list[int],
    relation: str,
) -> str:
    """Return the canonical digest for a complete AD boundary witness."""

    return _boundary_digest(ordered_faces, vertex_catalog, orientation_pattern, relation)


__all__ = [
    "AC_NOT_POSITIVE",
    "AC_REJECTED",
    "AD_NOT_TETRAHEDRAL",
    "AD_REJECTED",
    "AD_TETRAHEDRAL_BOUNDARY_CLOSED",
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "INPUT_INVALID",
    "RESULT_KEYS",
    "BOUNDARY_SCOPE",
    "boundary_digest",
    "evaluate_tetrahedral_boundary",
    "input_digest",
]
