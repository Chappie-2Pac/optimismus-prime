"""Pure S25AA pairwise identity separation over the public S25Z contract.

This module compares two independently re-evaluated S25Z cases.  Its relation
is deliberately positional and non-temporal: it can say that the two
identity vectors are separated, equal, or inconsistent for the same Z case.
It does not infer replay, freshness, causality, hand-off, truth, or authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:  # pragma: no cover - import path depends on the test runner
    from support.w5_s25z_coverage_verdict_partition import (
        ATOM_IDS as S25Z_ATOM_IDS,
        CANONICALIZATION as S25Z_CANONICALIZATION,
        HARNESS_SCHEMA as S25Z_SCHEMA,
        INPUT_INVALID as S25Z_INPUT_INVALID,
        RESULT_KEYS as S25Z_RESULT_KEYS,
        S25Y_NOT_COMPLETE as S25Z_NOT_COMPLETE,
        S25Y_REJECTED as S25Z_REJECTED,
        VERDICT_COMPLETE as S25Z_VERDICT_COMPLETE,
        VERDICT_SCOPE as S25Z_VERDICT_SCOPE,
        Y_FLAG_KEYS as S25Z_FLAG_KEYS,
        evaluate_coverage_verdict_partition,
        input_digest as s25z_input_digest,
    )
except ImportError:  # pragma: no cover
    from w5_s25z_coverage_verdict_partition import (  # type: ignore[no-redef]
        ATOM_IDS as S25Z_ATOM_IDS,
        CANONICALIZATION as S25Z_CANONICALIZATION,
        HARNESS_SCHEMA as S25Z_SCHEMA,
        INPUT_INVALID as S25Z_INPUT_INVALID,
        RESULT_KEYS as S25Z_RESULT_KEYS,
        S25Y_NOT_COMPLETE as S25Z_NOT_COMPLETE,
        S25Y_REJECTED as S25Z_REJECTED,
        VERDICT_COMPLETE as S25Z_VERDICT_COMPLETE,
        VERDICT_SCOPE as S25Z_VERDICT_SCOPE,
        Y_FLAG_KEYS as S25Z_FLAG_KEYS,
        evaluate_coverage_verdict_partition,
        input_digest as s25z_input_digest,
    )


HARNESS_SCHEMA = "s25aa.pairwise-identity-separation.v1"
OBSERVATION_MODE = "TEST_ONLY"
CANONICALIZATION = S25Z_CANONICALIZATION
PAIR_SCHEMA = "s25aa.pairwise-identity.v1"
PAIR_SCOPE = "S25Z_PAIRWISE_IDENTITY_SEPARATION_ONLY"

PAIR_SEPARATED = "PAIR_SEPARATED"
PAIR_NOT_SEPARATED = "PAIR_NOT_SEPARATED"
PAIR_IDENTITY_INCONSISTENT = "PAIR_IDENTITY_INCONSISTENT"
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
        "pair_witness",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "left_z_case_digest",
        "right_z_case_digest",
        "left_result_digest",
        "right_result_digest",
        "pair_digest",
    }
)
_IDENTITY_KEYS = frozenset(IDENTITY_FIELDS)
_WITNESS_KEYS = frozenset({"left_identity", "right_identity", "equal_fields", "relation"})
_OUTPUT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "pair_scope",
        "left_identity",
        "right_identity",
        "equal_fields",
        "pair_digest",
        "production_status",
        "authority_claim",
        *S25Z_FLAG_KEYS,
    }
)
RESULT_KEYS = tuple(sorted(_OUTPUT_KEYS))
_POSITIVE_REASON = "PAIR_IDENTITY_SEPARATED"
_NON_SEPARATED_REASON = "PAIR_IDENTICAL_NOT_SEPARATED"
_INCONSISTENT_REASON = "PAIR_IDENTITY_DRIFT"
_S25Z_Y_COVERAGE_SCOPE = "S25X_CLAIM_EVIDENCE_ONLY"
_S25Z_Y_CLAIM_SCOPE = "S25W_MEMBER_DELTA_ONLY"
_PARTITION_KEYS = frozenset({"atom_id", "state"})
_VALID_Z_CLASSIFICATIONS = frozenset(
    {
        S25Z_VERDICT_COMPLETE,
        "VERDICT_INCOMPLETE",
        S25Z_REJECTED,
        S25Z_NOT_COMPLETE,
        S25Z_INPUT_INVALID,
    }
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


def _empty_identity() -> dict[str, str]:
    return {field: _ZERO_HASH for field in IDENTITY_FIELDS}


def _empty_equal_fields() -> dict[str, bool]:
    return {field: False for field in IDENTITY_FIELDS}


def _result(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    left_identity: Mapping[str, Any] | None = None,
    right_identity: Mapping[str, Any] | None = None,
    equal_fields: Mapping[str, Any] | None = None,
    pair_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVATION_MODE,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "pair_scope": PAIR_SCOPE,
        "left_identity": dict(left_identity or _empty_identity()),
        "right_identity": dict(right_identity or _empty_identity()),
        "equal_fields": dict(equal_fields or _empty_equal_fields()),
        "pair_digest": pair_digest,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
        **{field: False for field in S25Z_FLAG_KEYS},
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _result(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(
    reason: str,
    *,
    classification: str = INPUT_INVALID,
    left_identity: Mapping[str, Any] | None = None,
    right_identity: Mapping[str, Any] | None = None,
    equal_fields: Mapping[str, Any] | None = None,
    pair_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return _result(
        classification,
        TEST_BLOCKED,
        HOLD,
        reason,
        left_identity=left_identity,
        right_identity=right_identity,
        equal_fields=equal_fields,
        pair_digest=pair_digest,
    )


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    if any(not _hash(expected.get(field)) for field in _EXPECTED_KEYS):
        return "EXPECTED_DIGEST_INVALID"
    return None


def _valid_identity(identity: Any) -> bool:
    return (
        isinstance(identity, Mapping)
        and _exact(identity, _IDENTITY_KEYS)
        and _safe_value(identity)
        and all(_hash(identity.get(field)) for field in IDENTITY_FIELDS)
    )


def _valid_equal_fields(equal_fields: Any) -> bool:
    return (
        isinstance(equal_fields, Mapping)
        and _exact(equal_fields, _IDENTITY_KEYS)
        and _safe_value(equal_fields)
        and all(type(equal_fields.get(field)) is bool for field in IDENTITY_FIELDS)
    )


def _valid_z_partition_shape(output: Mapping[str, Any]) -> bool:
    covered = output.get("covered_atom_ids")
    uncovered = output.get("uncovered_atom_ids")
    partition = output.get("partition")
    if not isinstance(covered, list) or not isinstance(uncovered, list) or not isinstance(partition, list):
        return False
    if any(not isinstance(atom_id, str) for atom_id in [*covered, *uncovered]):
        return False
    if len(covered) != len(set(covered)) or len(uncovered) != len(set(uncovered)):
        return False
    if any(atom_id not in S25Z_ATOM_IDS for atom_id in [*covered, *uncovered]):
        return False
    positions = {atom_id: index for index, atom_id in enumerate(S25Z_ATOM_IDS)}
    if covered != sorted(covered, key=positions.__getitem__) or uncovered != sorted(uncovered, key=positions.__getitem__):
        return False
    if set(covered) & set(uncovered):
        return False
    rows: list[dict[str, str]] = []
    for item in partition:
        if not isinstance(item, Mapping) or not _exact(item, _PARTITION_KEYS) or not _safe_value(item):
            return False
        if item.get("atom_id") not in S25Z_ATOM_IDS or item.get("state") not in {
            "COVERED",
            "UNCOVERED",
            "UNOBSERVED",
        }:
            return False
        rows.append({"atom_id": item["atom_id"], "state": item["state"]})
    if len({row["atom_id"] for row in rows}) != len(rows):
        return False
    if [row["atom_id"] for row in rows] != sorted(
        [row["atom_id"] for row in rows], key=positions.__getitem__
    ):
        return False
    expected_states = {
        atom_id: "COVERED" if atom_id in covered else "UNCOVERED" if atom_id in uncovered else "UNOBSERVED"
        for atom_id in S25Z_ATOM_IDS
    }
    return all(row["state"] == expected_states[row["atom_id"]] for row in rows)


def _valid_z_output(output: Any) -> bool:
    if not isinstance(output, Mapping) or not _exact(output, frozenset(S25Z_RESULT_KEYS)) or not _safe_value(output):
        return False
    if output.get("schema_version") != S25Z_SCHEMA or output.get("observation_mode") != OBSERVATION_MODE:
        return False
    if output.get("production_status") != PRODUCTION_NOT_AUTHORIZED or output.get("authority_claim") != NOT_CLAIMED:
        return False
    if not all(output.get(field) is False for field in S25Z_FLAG_KEYS):
        return False
    if output.get("classification") not in _VALID_Z_CLASSIFICATIONS:
        return False
    if (
        output.get("verdict_scope") != S25Z_VERDICT_SCOPE
        or output.get("y_coverage_scope") != _S25Z_Y_COVERAGE_SCOPE
        or output.get("y_claim_scope") != _S25Z_Y_CLAIM_SCOPE
        or not isinstance(output.get("reason"), str)
        or not _valid_z_partition_shape(output)
        or output.get("required_atom_count") != len(S25Z_ATOM_IDS)
    ):
        return False
    if not all(
        _hash(output.get(field))
        for field in ("y_case_digest", "y_result_digest", "coverage_digest", "verdict_digest")
    ):
        return False
    if output.get("classification") == S25Z_VERDICT_COMPLETE:
        covered = output.get("covered_atom_ids")
        uncovered = output.get("uncovered_atom_ids")
        partition = output.get("partition")
        expected_partition = [{"atom_id": atom_id, "state": "COVERED"} for atom_id in S25Z_ATOM_IDS]
        return (
            output.get("status") == PROPOSAL_ONLY
            and output.get("decision") == DESIGN_ONLY
            and output.get("reason") == "COVERAGE_VERDICT_PARTITION_CLOSED"
            and covered == list(S25Z_ATOM_IDS)
            and uncovered == []
            and output.get("required_atom_count") == len(S25Z_ATOM_IDS)
            and isinstance(partition, list)
            and len(partition) == len(expected_partition)
            and all(isinstance(item, Mapping) and _exact(item, _PARTITION_KEYS) for item in partition)
            and partition == expected_partition
        )
    return output.get("status") == TEST_BLOCKED and output.get("decision") == HOLD


def _identity(z_case: Mapping[str, Any], z_output: Mapping[str, Any]) -> dict[str, str]:
    return {
        "z_case_digest": s25z_input_digest(z_case),
        "y_case_digest": z_output["y_case_digest"],
        "y_result_digest": z_output["y_result_digest"],
        "verdict_digest": z_output["verdict_digest"],
    }


def _relation(left: Mapping[str, str], right: Mapping[str, str]) -> tuple[str, dict[str, bool]]:
    equal_fields = {field: left[field] == right[field] for field in IDENTITY_FIELDS}
    if left["z_case_digest"] != right["z_case_digest"]:
        return PAIR_SEPARATED, equal_fields
    if all(equal_fields.values()):
        return PAIR_NOT_SEPARATED, equal_fields
    return PAIR_IDENTITY_INCONSISTENT, equal_fields


def _pair_digest(
    left_identity: Mapping[str, str],
    right_identity: Mapping[str, str],
    equal_fields: Mapping[str, bool],
    relation: str,
) -> str:
    return _digest(
        {
            "schema": PAIR_SCHEMA,
            "pair_scope": PAIR_SCOPE,
            "left_identity": dict(left_identity),
            "right_identity": dict(right_identity),
            "equal_fields": dict(equal_fields),
            "relation": relation,
        }
    )


def _validate_witness(witness: Any) -> str | None:
    if not isinstance(witness, Mapping) or not _exact(witness, _WITNESS_KEYS) or not _safe_value(witness):
        return "PAIR_WITNESS_SCHEMA_INVALID"
    if not _valid_identity(witness.get("left_identity")) or not _valid_identity(witness.get("right_identity")):
        return "PAIR_IDENTITY_INVALID"
    if not _valid_equal_fields(witness.get("equal_fields")):
        return "PAIR_EQUAL_FIELDS_INVALID"
    if witness.get("relation") not in {PAIR_SEPARATED, PAIR_NOT_SEPARATED, PAIR_IDENTITY_INCONSISTENT}:
        return "PAIR_RELATION_INVALID"
    return None


def _evaluate_side(case: Any, supplied_output: Any) -> tuple[str, dict[str, Any] | None, dict[str, str] | None, str | None]:
    if not isinstance(case, Mapping) or not _safe_value(case):
        return "S25Z_CASE_INVALID", None, None, None
    try:
        case_digest = s25z_input_digest(case)
        if not _hash(case.get("input_digest")) or case["input_digest"] != case_digest:
            return "S25Z_CASE_DIGEST_DRIFT", None, None, None
        actual_output = _snapshot(evaluate_coverage_verdict_partition(case))
    except Exception:
        return "S25Z_RESULT_UNREADABLE", None, None, None
    if not _strict_equal(supplied_output, actual_output):
        return "S25Z_RESULT_MISMATCH", None, None, None
    if not _valid_z_output(actual_output):
        return "S25Z_RESULT_INVALID", actual_output if isinstance(actual_output, dict) else None, None, None
    identity = _identity(case, actual_output)
    if actual_output["classification"] != S25Z_VERDICT_COMPLETE:
        return "S25Z_NOT_COMPLETE", actual_output, identity, None
    return "", actual_output, identity, _digest(actual_output)


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
    expected_error = _validate_expected(snapshot["expected"])
    if expected_error:
        return _invalid(expected_error)
    witness_error = _validate_witness(snapshot["pair_witness"])
    if witness_error:
        return _invalid(witness_error)

    left_reason, left_output, left_identity, left_result_digest = _evaluate_side(
        snapshot["left_case"], snapshot["left_output"]
    )
    right_reason, right_output, right_identity, right_result_digest = _evaluate_side(
        snapshot["right_case"], snapshot["right_output"]
    )
    if left_reason:
        side_classification = S25Z_NOT_COMPLETE if left_reason == "S25Z_NOT_COMPLETE" else S25Z_REJECTED
        return _blocked(
            left_reason,
            classification=side_classification,
            left_identity=left_identity,
            right_identity=right_identity,
        )
    if right_reason:
        side_classification = S25Z_NOT_COMPLETE if right_reason == "S25Z_NOT_COMPLETE" else S25Z_REJECTED
        return _blocked(
            right_reason,
            classification=side_classification,
            left_identity=left_identity,
            right_identity=right_identity,
        )
    assert left_output is not None and right_output is not None
    assert left_identity is not None and right_identity is not None
    assert left_result_digest is not None and right_result_digest is not None

    expected = snapshot["expected"]
    if (
        expected["left_z_case_digest"] != left_identity["z_case_digest"]
        or expected["right_z_case_digest"] != right_identity["z_case_digest"]
        or expected["left_result_digest"] != left_result_digest
        or expected["right_result_digest"] != right_result_digest
    ):
        return _blocked(
            "EXPECTED_BINDING_MISMATCH",
            classification=PAIR_IDENTITY_INCONSISTENT,
            left_identity=left_identity,
            right_identity=right_identity,
        )
    relation, equal_fields = _relation(left_identity, right_identity)
    witness = snapshot["pair_witness"]
    if not _strict_equal(witness["left_identity"], left_identity) or not _strict_equal(
        witness["right_identity"], right_identity
    ):
        return _blocked(
            "PAIR_IDENTITY_MISMATCH",
            classification=PAIR_IDENTITY_INCONSISTENT,
            left_identity=left_identity,
            right_identity=right_identity,
            equal_fields=equal_fields,
        )
    if not _strict_equal(witness["equal_fields"], equal_fields) or witness["relation"] != relation:
        return _blocked(
            "PAIR_RELATION_MISMATCH",
            classification=PAIR_IDENTITY_INCONSISTENT,
            left_identity=left_identity,
            right_identity=right_identity,
            equal_fields=equal_fields,
        )
    pair_digest = _pair_digest(left_identity, right_identity, equal_fields, relation)
    if expected["pair_digest"] != pair_digest:
        return _blocked(
            "PAIR_DIGEST_MISMATCH",
            classification=PAIR_IDENTITY_INCONSISTENT,
            left_identity=left_identity,
            right_identity=right_identity,
            equal_fields=equal_fields,
        )
    if witness["relation"] != relation:
        return _blocked(
            "PAIR_RELATION_MISMATCH",
            classification=PAIR_IDENTITY_INCONSISTENT,
            left_identity=left_identity,
            right_identity=right_identity,
            equal_fields=equal_fields,
            pair_digest=pair_digest,
        )
    if relation == PAIR_SEPARATED:
        return _result(
            PAIR_SEPARATED,
            PROPOSAL_ONLY,
            DESIGN_ONLY,
            _POSITIVE_REASON,
            left_identity=left_identity,
            right_identity=right_identity,
            equal_fields=equal_fields,
            pair_digest=pair_digest,
        )
    if relation == PAIR_NOT_SEPARATED:
        return _result(
            PAIR_NOT_SEPARATED,
            TEST_BLOCKED,
            HOLD,
            _NON_SEPARATED_REASON,
            left_identity=left_identity,
            right_identity=right_identity,
            equal_fields=equal_fields,
            pair_digest=pair_digest,
        )
    return _result(
        PAIR_IDENTITY_INCONSISTENT,
        TEST_BLOCKED,
        HOLD,
        _INCONSISTENT_REASON,
        left_identity=left_identity,
        right_identity=right_identity,
        equal_fields=equal_fields,
        pair_digest=pair_digest,
    )


def evaluate_pairwise_identity(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Return a deterministic, non-temporal relation over two S25Z cases."""

    try:
        return _evaluate(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


def pair_digest(
    left_identity: Mapping[str, str],
    right_identity: Mapping[str, str],
    equal_fields: Mapping[str, bool],
    relation: str,
) -> str:
    """Return the canonical digest for the independent pair witness."""

    return _pair_digest(left_identity, right_identity, equal_fields, relation)


def input_digest(case: Mapping[str, Any]) -> str:
    snapshot = _snapshot(case)
    if not isinstance(snapshot, Mapping):
        raise ValueError("case must be a mapping")
    return _digest({key: value for key, value in snapshot.items() if key != "input_digest"})


__all__ = [
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "IDENTITY_FIELDS",
    "INPUT_INVALID",
    "PAIR_IDENTITY_INCONSISTENT",
    "PAIR_NOT_SEPARATED",
    "PAIR_SCHEMA",
    "PAIR_SCOPE",
    "PAIR_SEPARATED",
    "PRODUCTION_NOT_AUTHORIZED",
    "RESULT_KEYS",
    "S25Z_NOT_COMPLETE",
    "S25Z_REJECTED",
    "S25Z_VERDICT_COMPLETE",
    "evaluate_pairwise_identity",
    "input_digest",
    "pair_digest",
]
