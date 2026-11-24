"""Pure S25Y claim-evidence coverage over the public S25X contract."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from support.w5_s25x_delta_claim_containment import (
        ALLOWED_MEMBER_IDS,
        CANONICALIZATION as S25X_CANONICALIZATION,
        CLAIM_SCOPE as S25X_CLAIM_SCOPE,
        DELTA_CLAIM_CONTAINED,
        FALSE_FLAGS,
        HARNESS_SCHEMA as S25X_SCHEMA,
        MEMBER_DIGEST_FIELDS,
        NEXT_SEQUENCE_ALLOWED_MEMBER_IDS,
        PROVENANCE_KEYS,
        RESULT_KEYS as S25X_RESULT_KEYS,
        evaluate_delta_claim_containment,
        input_digest as s25x_input_digest,
    )
except ImportError:  # pragma: no cover - direct support-module execution
    from w5_s25x_delta_claim_containment import (
        ALLOWED_MEMBER_IDS,
        CANONICALIZATION as S25X_CANONICALIZATION,
        CLAIM_SCOPE as S25X_CLAIM_SCOPE,
        DELTA_CLAIM_CONTAINED,
        FALSE_FLAGS,
        HARNESS_SCHEMA as S25X_SCHEMA,
        MEMBER_DIGEST_FIELDS,
        NEXT_SEQUENCE_ALLOWED_MEMBER_IDS,
        PROVENANCE_KEYS,
        RESULT_KEYS as S25X_RESULT_KEYS,
        evaluate_delta_claim_containment,
        input_digest as s25x_input_digest,
    )


HARNESS_SCHEMA = "s25y.claim-evidence-closure.v1"
CANONICALIZATION = S25X_CANONICALIZATION
TEST_ONLY = "TEST_ONLY"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

COVERAGE_SCOPE = "S25X_CLAIM_EVIDENCE_ONLY"
UNSUPPORTED_SCOPE = "UNSUPPORTED"
COVERAGE_SCHEMA = "s25y.claim-evidence-coverage.v1"
COVERAGE_COMPLETE = "COVERAGE_COMPLETE"
COVERAGE_INCOMPLETE = "COVERAGE_INCOMPLETE"
X_REJECTED = "S25X_REJECTED"
SCOPE_UNSUPPORTED = "SCOPE_UNSUPPORTED"
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

_ATOM_DEFINITIONS = (
    ("X_CASE_BINDING", "X_BINDING", ()),
    ("X_RESULT_BINDING", "X_BINDING", ()),
    ("CLAIM_SCOPE", "X_RESULT_FIELD", ()),
    ("TRANSITION", "X_TRANSITION", tuple(ALLOWED_MEMBER_IDS)),
    ("MEMBER_DELTA", "MEMBER_PROVENANCE", tuple(ALLOWED_MEMBER_IDS)),
    ("MEMBER_PROVENANCE", "MEMBER_PROVENANCE", tuple(ALLOWED_MEMBER_IDS)),
    ("AUTHORITY_BOUNDARY", "AUTHORITY_BOUNDARY", ("SECURITY",)),
)
ATOM_COVERAGE_MAP = tuple(_ATOM_DEFINITIONS)
ATOM_IDS = tuple(item[0] for item in _ATOM_DEFINITIONS)
ATOM_KEYS = ("atom_id", "claim_scope", "evidence_kind", "evidence_member_ids", "value_digest")
_ATOM_KEY_SET = frozenset(ATOM_KEYS)

_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "s25x_case",
        "s25x_output",
        "claim_atoms",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {"x_case_digest", "x_result_digest", "claim_digest", "coverage_digest", "required_atom_count", "required_member_count"}
)
_OUTPUT_KEYS = frozenset(
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
        *FALSE_FLAGS,
    }
)
RESULT_KEYS = tuple(sorted(_OUTPUT_KEYS))
ATOM_SCHEMA = "s25y.claim-atom.v1"
_ZERO_HASH = "0" * 64
_X_RESULT_CLASSES = {DELTA_CLAIM_CONTAINED}


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
            return len(value) <= _MAX_CONTAINER_ITEMS and all(isinstance(key, str) and len(key) <= _MAX_KEY_LENGTH and _safe_value(item, depth=depth + 1, active=active) for key, item in value.items())
        if isinstance(value, (list, tuple)):
            return len(value) <= _MAX_CONTAINER_ITEMS and all(_safe_value(item, depth=depth + 1, active=active) for item in value)
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
    coverage_scope: str = COVERAGE_SCOPE,
    claim_scope: str = S25X_CLAIM_SCOPE,
    covered_atom_ids: list[str] | None = None,
    uncovered_atom_ids: list[str] | None = None,
    x_case_digest: str = _ZERO_HASH,
    x_result_digest: str = _ZERO_HASH,
    claim_digest: str = _ZERO_HASH,
    coverage_digest: str = _ZERO_HASH,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": TEST_ONLY,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "coverage_scope": coverage_scope,
        "claim_scope": claim_scope,
        "covered_atom_ids": list(covered_atom_ids or []),
        "uncovered_atom_ids": list(uncovered_atom_ids or []),
        "required_atom_count": len(ATOM_IDS),
        "x_case_digest": x_case_digest,
        "x_result_digest": x_result_digest,
        "claim_digest": claim_digest,
        "coverage_digest": coverage_digest,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
        **{field: False for field in FALSE_FLAGS},
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _result(INPUT_INVALID, TEST_BLOCKED, HOLD, reason)


def _blocked(reason: str, *, classification: str = X_REJECTED, **kwargs: Any) -> dict[str, Any]:
    if classification == SCOPE_UNSUPPORTED:
        kwargs.setdefault("coverage_scope", UNSUPPORTED_SCOPE)
        kwargs.setdefault("claim_scope", UNSUPPORTED_SCOPE)
    if classification in {COVERAGE_INCOMPLETE, SCOPE_UNSUPPORTED} and "uncovered_atom_ids" not in kwargs:
        kwargs.setdefault("uncovered_atom_ids", list(ATOM_IDS))
    return _result(classification, TEST_BLOCKED, HOLD, reason, **kwargs)


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    for field in ("x_case_digest", "x_result_digest", "claim_digest", "coverage_digest"):
        if not _hash(expected.get(field)):
            return "EXPECTED_DIGEST_INVALID"
    if not _integer(expected.get("required_atom_count")) or expected["required_atom_count"] != len(ATOM_IDS):
        return "EXPECTED_ATOM_COUNT_INVALID"
    if not _integer(expected.get("required_member_count")) or expected["required_member_count"] != len(ALLOWED_MEMBER_IDS):
        return "EXPECTED_MEMBER_COUNT_INVALID"
    return None


def _valid_x_result(output: Any) -> bool:
    if not isinstance(output, Mapping) or not _exact(output, frozenset(S25X_RESULT_KEYS)) or not _safe_value(output):
        return False
    if output.get("schema_version") != S25X_SCHEMA or output.get("observation_mode") != TEST_ONLY:
        return False
    if output.get("classification") not in _X_RESULT_CLASSES or output.get("status") != PROPOSAL_ONLY or output.get("decision") != DESIGN_ONLY:
        return False
    if output.get("claim_scope") != S25X_CLAIM_SCOPE or output.get("production_status") != PRODUCTION_NOT_AUTHORIZED or output.get("authority_claim") != NOT_CLAIMED:
        return False
    if not all(_hash(output.get(field)) for field in ("s25w_case_digest", "s25w_result_digest", "claim_digest")):
        return False
    if output.get("transition_kind") not in {"NO_CHANGE", "NEXT_SEQUENCE"} or not _integer(output.get("changed_member_count")):
        return False
    if not isinstance(output.get("changed_member_ids"), list) or not isinstance(output.get("unchanged_member_ids"), list) or not isinstance(output.get("member_provenance"), list):
        return False
    return all(output.get(field) is False for field in FALSE_FLAGS)


def _valid_provenance(output: Mapping[str, Any]) -> bool:
    provenance = output.get("member_provenance")
    if not isinstance(provenance, list) or len(provenance) != len(ALLOWED_MEMBER_IDS):
        return False
    ids: list[str] = []
    changed: list[str] = []
    unchanged: list[str] = []
    for item in provenance:
        if not isinstance(item, Mapping) or not _exact(item, frozenset(PROVENANCE_KEYS)) or not _safe_value(item):
            return False
        member_id = item.get("member_id")
        if not isinstance(member_id, str) or member_id not in ALLOWED_MEMBER_IDS or member_id in ids:
            return False
        if not all(_hash(item.get(field)) for field in ("before_member_digest", "after_member_digest", "before_value_digest", "after_value_digest", "before_context_digest", "after_context_digest")):
            return False
        if type(item.get("changed")) is not bool:
            return False
        expected_changed = item["before_member_digest"] != item["after_member_digest"]
        if item["changed"] != expected_changed:
            return False
        for prefix in ("before", "after"):
            expected_member_digest = _digest(
                {
                    MEMBER_DIGEST_FIELDS[0]: member_id,
                    MEMBER_DIGEST_FIELDS[1]: "PRESENT",
                    MEMBER_DIGEST_FIELDS[2]: item[f"{prefix}_value_digest"],
                    MEMBER_DIGEST_FIELDS[3]: item[f"{prefix}_context_digest"],
                }
            )
            if item[f"{prefix}_member_digest"] != expected_member_digest:
                return False
        ids.append(member_id)
        (changed if expected_changed else unchanged).append(member_id)
    if ids != list(ALLOWED_MEMBER_IDS) or changed != output.get("changed_member_ids") or unchanged != output.get("unchanged_member_ids") or len(changed) != output.get("changed_member_count"):
        return False
    if output.get("transition_kind") == "NO_CHANGE":
        return not changed
    if output.get("transition_kind") == "NEXT_SEQUENCE":
        return bool(changed) and all(member_id in NEXT_SEQUENCE_ALLOWED_MEMBER_IDS for member_id in changed)
    return False


def _atom_payloads(x_case_digest: str, x_result_digest: str, output: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    provenance = output["member_provenance"]
    return {
        "X_CASE_BINDING": {"x_case_digest": x_case_digest},
        "X_RESULT_BINDING": {"x_result_digest": x_result_digest, "claim_digest": output["claim_digest"]},
        "CLAIM_SCOPE": {"claim_scope": output["claim_scope"]},
        "TRANSITION": {
            "transition_kind": output["transition_kind"],
            "changed_member_ids": output["changed_member_ids"],
            "unchanged_member_ids": output["unchanged_member_ids"],
            "changed_member_count": output["changed_member_count"],
        },
        "MEMBER_DELTA": {
            "changed_member_ids": output["changed_member_ids"],
            "unchanged_member_ids": output["unchanged_member_ids"],
            "changed_member_count": output["changed_member_count"],
            "changed": [item["changed"] for item in provenance],
        },
        "MEMBER_PROVENANCE": {"member_provenance": provenance},
        "AUTHORITY_BOUNDARY": {
            "production_status": output["production_status"],
            "authority_claim": output["authority_claim"],
            **{field: output[field] for field in FALSE_FLAGS},
        },
    }


def _expected_atoms(x_case_digest: str, x_result_digest: str, output: Mapping[str, Any]) -> list[dict[str, Any]]:
    payloads = _atom_payloads(x_case_digest, x_result_digest, output)
    atoms: list[dict[str, Any]] = []
    for atom_id, evidence_kind, evidence_member_ids in _ATOM_DEFINITIONS:
        atoms.append(
            {
                "atom_id": atom_id,
                "claim_scope": S25X_CLAIM_SCOPE,
                "evidence_kind": evidence_kind,
                "evidence_member_ids": list(evidence_member_ids),
                "value_digest": _digest({"schema": ATOM_SCHEMA, "atom_id": atom_id, "payload": payloads[atom_id]}),
            }
        )
    return atoms


def _coverage_digest(x_case_digest: str, x_result_digest: str, atoms: list[dict[str, Any]]) -> str:
    return _digest(
        {
            "schema": COVERAGE_SCHEMA,
            "coverage_scope": COVERAGE_SCOPE,
            "claim_scope": S25X_CLAIM_SCOPE,
            "x_case_digest": x_case_digest,
            "x_result_digest": x_result_digest,
            "atoms": atoms,
        }
    )


def _validate_atoms(atoms: Any, expected_atoms: list[dict[str, Any]]) -> str | None:
    if not isinstance(atoms, list) or len(atoms) != len(expected_atoms):
        return "ATOM_SET_INCOMPLETE"
    ids: list[Any] = []
    for atom in atoms:
        if not isinstance(atom, Mapping) or not _exact(atom, _ATOM_KEY_SET) or not _safe_value(atom):
            return "ATOM_SCHEMA_INVALID"
        ids.append(atom.get("atom_id"))
    if len(ids) != len(set(ids)):
        return "ATOM_DUPLICATE"
    if any(atom_id not in ATOM_IDS for atom_id in ids):
        return "ATOM_UNKNOWN"
    if ids != list(ATOM_IDS):
        return "ATOM_ORDER_OR_MISSING"
    for supplied, expected in zip(atoms, expected_atoms):
        if supplied.get("claim_scope") != S25X_CLAIM_SCOPE:
            raise _Failure(SCOPE_UNSUPPORTED, "CLAIM_SCOPE_UNSUPPORTED", claim_scope=UNSUPPORTED_SCOPE, coverage_scope=UNSUPPORTED_SCOPE)
        if not _strict_equal(supplied, expected):
            return "ATOM_BINDING_MISMATCH"
    return None


def _affected_atom_ids(atoms: Any, expected_atoms: list[dict[str, Any]], reason: str) -> list[str]:
    if reason == "ATOM_BINDING_MISMATCH" and isinstance(atoms, list):
        return [
            expected["atom_id"]
            for supplied, expected in zip(atoms, expected_atoms)
            if not isinstance(supplied, Mapping) or not _strict_equal(supplied, expected)
        ]
    if reason in {"ATOM_UNKNOWN", "ATOM_DUPLICATE"} and isinstance(atoms, list):
        ids = [item.get("atom_id") for item in atoms if isinstance(item, Mapping)]
        known_ids = {atom_id for atom_id in ids if atom_id in ATOM_IDS}
        affected = {atom_id for atom_id in ATOM_IDS if atom_id not in known_ids}
        seen: set[str] = set()
        for atom_id in ids:
            if isinstance(atom_id, str) and atom_id in seen and atom_id in ATOM_IDS:
                affected.add(atom_id)
            if isinstance(atom_id, str):
                seen.add(atom_id)
        return [atom_id for atom_id in ATOM_IDS if atom_id in affected]
    return list(ATOM_IDS)


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
    x_case = snapshot["s25x_case"]
    if not isinstance(x_case, Mapping) or not _safe_value(x_case):
        return _blocked("S25X_CASE_INVALID")
    try:
        if not _hash(x_case.get("input_digest")) or x_case["input_digest"] != s25x_input_digest(x_case):
            return _blocked("S25X_CASE_DIGEST_DRIFT")
        actual_x = _snapshot(evaluate_delta_claim_containment(x_case))
    except Exception:
        return _blocked("S25X_RESULT_UNREADABLE")
    if not _strict_equal(snapshot["s25x_output"], actual_x):
        return _blocked("S25X_RESULT_MISMATCH")
    if not _valid_x_result(actual_x):
        return _blocked("S25X_NOT_POSITIVE")
    if not _valid_provenance(actual_x):
        return _blocked("S25X_PROVENANCE_INVALID")
    if not isinstance(x_case.get("claim"), Mapping) or actual_x["claim_digest"] != _digest(x_case["claim"]):
        return _blocked("S25X_CLAIM_DIGEST_MISMATCH")
    bindings = {
        "x_case_digest": s25x_input_digest(x_case),
        "x_result_digest": _digest(actual_x),
        "claim_digest": actual_x["claim_digest"],
        "required_atom_count": len(ATOM_IDS),
        "required_member_count": len(ALLOWED_MEMBER_IDS),
    }
    if any(snapshot["expected"][field] != value for field, value in bindings.items()):
        affected = []
        if snapshot["expected"]["x_case_digest"] != bindings["x_case_digest"]:
            affected.append("X_CASE_BINDING")
        if snapshot["expected"]["x_result_digest"] != bindings["x_result_digest"]:
            affected.append("X_RESULT_BINDING")
        if snapshot["expected"]["claim_digest"] != bindings["claim_digest"]:
            affected.append("X_RESULT_BINDING")
        return _blocked("EXPECTED_BINDING_MISMATCH", classification=COVERAGE_INCOMPLETE, uncovered_atom_ids=sorted(set(affected)))
    expected_atoms = _expected_atoms(bindings["x_case_digest"], bindings["x_result_digest"], actual_x)
    try:
        atom_error = _validate_atoms(snapshot["claim_atoms"], expected_atoms)
    except _Failure as failure:
        return _blocked(failure.reason, classification=failure.classification, **failure.kwargs)
    if atom_error:
        return _blocked(
            atom_error,
            classification=COVERAGE_INCOMPLETE,
            uncovered_atom_ids=_affected_atom_ids(snapshot["claim_atoms"], expected_atoms, atom_error),
        )
    supplied_atoms = snapshot["claim_atoms"]
    coverage_digest = _coverage_digest(bindings["x_case_digest"], bindings["x_result_digest"], supplied_atoms)
    if snapshot["expected"]["coverage_digest"] != coverage_digest:
        return _blocked("COVERAGE_DIGEST_MISMATCH", classification=COVERAGE_INCOMPLETE, uncovered_atom_ids=[])
    return _result(
        COVERAGE_COMPLETE,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        "ALL_CLAIM_ATOMS_COVERED",
        covered_atom_ids=list(ATOM_IDS),
        uncovered_atom_ids=[],
        x_case_digest=bindings["x_case_digest"],
        x_result_digest=bindings["x_result_digest"],
        claim_digest=bindings["claim_digest"],
        coverage_digest=coverage_digest,
    )


def evaluate_claim_evidence_closure(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Return a deterministic claim-atom coverage witness over public S25X."""

    try:
        return _evaluate(case)
    except _Failure as failure:
        return _blocked(failure.reason, classification=failure.classification, **failure.kwargs)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


def build_claim_atoms(x_case_digest: str, x_result_digest: str, output: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Build the fixed test-only atom catalog for a public S25X result."""

    return _expected_atoms(x_case_digest, x_result_digest, output)


def coverage_digest(x_case_digest: str, x_result_digest: str, atoms: list[Mapping[str, Any]]) -> str:
    """Return the canonical digest for an already-shaped atom catalog."""

    return _coverage_digest(x_case_digest, x_result_digest, atoms)


def input_digest(case: Mapping[str, Any]) -> str:
    snapshot = _snapshot(case)
    if not isinstance(snapshot, Mapping):
        raise ValueError("case must be a mapping")
    return _digest({key: value for key, value in snapshot.items() if key != "input_digest"})


__all__ = [
    "ATOM_IDS",
    "ATOM_KEYS",
    "ATOM_SCHEMA",
    "ATOM_COVERAGE_MAP",
    "CANONICALIZATION",
    "build_claim_atoms",
    "COVERAGE_COMPLETE",
    "COVERAGE_INCOMPLETE",
    "COVERAGE_SCHEMA",
    "COVERAGE_SCOPE",
    "HARNESS_SCHEMA",
    "INPUT_INVALID",
    "RESULT_KEYS",
    "SCOPE_UNSUPPORTED",
    "UNSUPPORTED_SCOPE",
    "X_REJECTED",
    "coverage_digest",
    "evaluate_claim_evidence_closure",
    "input_digest",
]
