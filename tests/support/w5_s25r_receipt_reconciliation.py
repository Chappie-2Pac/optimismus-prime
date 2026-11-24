"""Pure S25R read-only receipt/reconciliation witness behind S25Q."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from support.w5_s25q_replay_floor_fork import evaluate_replay_floor_fork
except ImportError:  # pragma: no cover - direct support-module execution
    from w5_s25q_replay_floor_fork import evaluate_replay_floor_fork


HARNESS_SCHEMA = "s25r.receipt-reconciliation-witness.v1"
CANONICALIZATION = "s25m-canonical-json-v1"
TEST_ONLY = "TEST_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
HOLD = "HOLD"
DESIGN_ONLY = "DESIGN_ONLY"
MANUAL_REVIEW = "MANUAL_REVIEW"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

RECEIPT_BUNDLE_RECONCILED = "RECEIPT_BUNDLE_RECONCILED"
RECEIPT_REJECTED = "RECEIPT_REJECTED"
RECEIPT_CONFLICT = "RECEIPT_CONFLICT"
RECEIPT_REPLAY = "RECEIPT_REPLAY"
FORK_CONFLICT = "FORK_CONFLICT"
S25Q_REJECTED = "S25Q_REJECTED"

_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_MAX_DEPTH = 64
_MAX_STRING = 4096
_MAX_INTEGER = 2**63 - 1

_STATUS_DECISIONS = {
    "LOCKED_TEST_PASS": "TEST_ONLY_PASS",
    "PROPOSAL_ONLY": DESIGN_ONLY,
    TEST_BLOCKED: HOLD,
    RECOVERY_REQUIRED: MANUAL_REVIEW,
}
_Q_CLASSIFICATIONS = {
    "FLOOR_ADVANCE_ELIGIBLE",
    "FLOOR_BLOCKED",
    "FORK_CONFLICT",
    "FLOOR_REJECTED",
    "S25P_REJECTED",
    "INPUT_INVALID",
}
_S25P_CLASSIFICATIONS = {
    "FRESH_REVALIDATION_ACCEPTED",
    "PRECEDENCE_REJECTED",
    "FRESHNESS_REJECTED",
    "FRESHNESS_BLOCKED",
    "INPUT_INVALID",
}
_S25P_FRESHNESS_REVIEW_REASONS = {
    "STATUS_ESCALATION_AFTER_PRIOR_PASS",
    "PREVIOUS_PASS_ANCHOR_MISMATCH",
    "SUBJECT_BINDING_MISMATCH",
    "SCOPE_BINDING_MISMATCH",
    "BASELINE_DIGEST_MISMATCH",
    "CURRENT_BASELINE_MISMATCH",
    "REVALIDATION_DIGEST_REUSED",
    "REPLAY_FLOOR_SEQUENCE_MISMATCH",
    "REVALIDATION_PASS_REPLAY",
    "OBSERVATION_EPOCH_ROLLBACK",
    "OBSERVATION_EPOCH_CHANGED",
    "OBSERVATION_SEQUENCE_ROLLBACK",
    "OBSERVATION_SEQUENCE_GAP",
}
_S25P_BLOCKED_REASONS = {
    "CASE_JSON_INVALID",
    "CASE_NOT_MAPPING",
    "CASE_SCHEMA_NOT_EXACT",
    "CASE_VALUE_NOT_SAFE",
    "CASE_PROFILE_INVALID",
    "CASE_CANONICALIZATION_INVALID",
    "CASE_DIGEST_INVALID",
    "CASE_DIGEST_DRIFT",
    "CASE_NOT_CANONICAL",
    "PRECEDENCE_CASE_NOT_MAPPING",
    "PRECEDENCE_CASE_UNREADABLE",
    "PRECEDENCE_REPORTS_NOT_MAPPING",
    "PRECEDENCE_DIGEST_INVALID",
    "DERIVED_DIGEST_NOT_CANONICAL",
    "FRESHNESS_ANCHOR_MISMATCH",
    "CANDIDATE_DIGEST_DRIFT",
    "EVIDENCE_DIGEST_DRIFT",
    "PRECEDENCE_RESULT_INVALID",
    "EXPECTED_SCHEMA_NOT_EXACT",
    "CURRENT_SCHEMA_NOT_EXACT",
    "PREVIOUS_SCHEMA_NOT_EXACT",
    "EXPECTED_DIGEST_INVALID",
    "CURRENT_DIGEST_INVALID",
    "PREVIOUS_DIGEST_INVALID",
    "PREVIOUS_STATUS_INVALID",
    "CURRENT_COUNTER_INVALID",
    "PREVIOUS_COUNTER_INVALID",
    "CURRENT_SNAPSHOT_NOT_FRESH",
}

_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "previous",
        "current",
        "floor_transition",
        "successor_index",
        "s25q_case",
        "receipt_set",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "previous_sequence",
        "previous_pass_digest",
        "previous_observation_digest",
        "current_sequence",
        "current_pass_digest",
        "current_observation_digest",
        "parent_key",
        "candidate_key",
        "transition_digest",
        "before_state_version",
        "after_state_version",
        "before_head_digest",
        "after_head_digest",
        "before_history_digest",
        "after_history_digest",
        "before_successor_index_digest",
        "after_successor_index_digest",
        "successor_index_digest",
        "s25q_case_digest",
        "s25q_result_digest",
        "s25q_classification",
        "s25q_status",
        "s25q_decision",
        "s25p_classification",
        "observation_id",
        "idempotency_key",
        "receipt_set_digest",
    }
)
_PREVIOUS_KEYS = frozenset(
    {
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "observation_sequence",
        "pass_digest",
        "status",
        "decision",
        "candidate_digest",
        "evidence_digest",
        "observation_digest",
    }
)
_CURRENT_KEYS = frozenset(
    {
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "observation_sequence",
        "previous_pass_digest",
        "candidate_digest",
        "evidence_digest",
        "pass_digest",
        "status",
        "decision",
        "observation_digest",
        "s25p_result_digest",
    }
)
_NODE_KEYS = frozenset(
    {
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "floor_sequence",
        "floor_pass_digest",
        "state_version",
        "head_digest",
        "successor_index_digest",
        "used_pass_digests",
        "used_observation_digests",
    }
)
_TRANSITION_KEYS = frozenset(
    {
        "schema",
        "source",
        "observation_id",
        "idempotency_key",
        "before",
        "after",
        "cas_status",
        "transition_digest",
    }
)
_SUCCESSOR_KEYS = frozenset(
    {
        "parent_key",
        "candidate_key",
        "entry_status",
        "existing_successor_pass_digest",
        "candidate_count",
        "candidate_pass_digests",
        "candidate_keys",
        "lineage",
        "registry_state_version",
        "registry_head_digest",
    }
)
_RECEIPT_SET_KEYS = frozenset({"schema", "required_kinds", "receipt_count", "receipts", "receipt_digests", "set_digest"})
_RECEIPT_KEYS = frozenset(
    {
        "kind",
        "receipt_digest",
        "observation_id",
        "idempotency_key",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "previous_sequence",
        "previous_pass_digest",
        "previous_observation_digest",
        "current_sequence",
        "current_pass_digest",
        "current_observation_digest",
        "parent_key",
        "candidate_key",
        "transition_digest",
        "before_state_version",
        "after_state_version",
        "before_head_digest",
        "after_head_digest",
        "before_history_digest",
        "after_history_digest",
        "index_digest",
        "payload",
    }
)
_REQUIRED_KINDS = (
    "S25Q_RESULT",
    "PARENT_CANDIDATE",
    "TRANSITION",
    "HEAD",
    "HISTORY",
    "INDEX",
)
_PAYLOAD_KEYS = {
    "S25Q_RESULT": frozenset({"s25q_result_digest", "classification", "status", "decision", "s25p_classification", "reason", "floor_advanced"}),
    "PARENT_CANDIDATE": frozenset({"previous_sequence", "current_sequence", "previous_pass_digest", "current_pass_digest", "parent_key", "candidate_key"}),
    "TRANSITION": frozenset({"schema", "source", "observation_id", "idempotency_key", "cas_status"}),
    "HEAD": frozenset({"before_head_digest", "after_head_digest", "transition_digest"}),
    "HISTORY": frozenset({"before_history_digest", "after_history_digest", "appended_pass_digest", "appended_observation_digest"}),
    "INDEX": frozenset({"successor_index_digest", "registry_state_version", "registry_head_digest", "candidate_count", "candidate_pass_digests", "candidate_keys", "lineage", "entry_status"}),
}


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
    raise ValueError(f"non-finite JSON constant: {value}")


def _snapshot(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("receipt value is too deep")
    if value is None or isinstance(value, (bool, int, str, float)):
        return value
    if isinstance(value, list):
        return [_snapshot(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            if key in result:
                raise _DuplicateKey(str(key))
            result[key] = _snapshot(item, depth=depth + 1)
        return result
    return value


def _safe_value(value: Any, *, depth: int = 0) -> bool:
    if depth > _MAX_DEPTH:
        return False
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, int) and not isinstance(value, bool):
            return abs(value) <= _MAX_INTEGER
        if not isinstance(value, str):
            return True
        stripped = value.lstrip()
        if len(value) > _MAX_STRING or _ABSOLUTE_PATH.match(stripped) is not None:
            return False
        if _URI_SCHEME.match(stripped.lower()) is not None or stripped.startswith("\\\\"):
            return False
        return not any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    if isinstance(value, float):
        return False
    if isinstance(value, list):
        return all(_safe_value(item, depth=depth + 1) for item in value)
    if isinstance(value, Mapping):
        return all(
            isinstance(key, str)
            and len(key) <= _MAX_STRING
            and key not in {"hostname", "host_path", "timestamp", "secret", "private_key", "seed"}
            and _safe_value(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def _exact(mapping: Mapping[str, Any], expected: frozenset[str]) -> bool:
    return set(mapping) == set(expected)


def _hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH64.fullmatch(value) is not None


def _integer(value: Any, *, positive: bool = False) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and (value > 0 if positive else value >= 0) and value <= _MAX_INTEGER


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value


def _parse(value: Mapping[str, Any] | bytes | str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        parsed = _snapshot(value)
        if isinstance(parsed, Mapping):
            return parsed
        raise TypeError("receipt case must be a mapping")
    if isinstance(value, (bytes, str)):
        raw = value.decode("utf-8") if isinstance(value, bytes) else value
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_constant)
        if isinstance(parsed, Mapping):
            snapshot = _snapshot(parsed)
            if isinstance(snapshot, Mapping):
                return snapshot
    raise TypeError("receipt case must be a mapping or JSON object")


def _canonical_json(value: Any) -> bytes:
    if not _safe_value(value):
        raise ValueError("receipt case contains unsafe value")
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def input_digest(case: Mapping[str, Any]) -> str:
    try:
        if not isinstance(case, Mapping):
            raise TypeError("receipt case must be a mapping")
        snapshot = _snapshot(case)
        if not isinstance(snapshot, Mapping):
            raise TypeError("receipt case must be a mapping")
        unsigned = {key: value for key, value in snapshot.items() if key != "input_digest"}
        return hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    except Exception:
        raise ValueError("receipt case cannot be canonicalized") from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _history_digest(node: Mapping[str, Any]) -> str:
    return _digest({"used_pass_digests": node["used_pass_digests"], "used_observation_digests": node["used_observation_digests"]})


def _receipt_digest(receipt: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in receipt.items() if key != "receipt_digest"})


def _set_digest(receipt_set: Mapping[str, Any]) -> str:
    return _digest(
        {
            "schema": receipt_set["schema"],
            "required_kinds": receipt_set["required_kinds"],
            "receipt_digests": sorted(receipt_set["receipt_digests"]),
        }
    )


def _output(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    q_result: Mapping[str, Any] | None = None,
    reconciliation_status: str = "NOT_CLAIMED",
    witness_only: bool = False,
    receipt_count: int = 0,
    receipt_witnessed: bool = False,
) -> dict[str, Any]:
    result = {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": TEST_ONLY,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "reconciliation_status": reconciliation_status,
        "witness_only": witness_only,
        "receipt_count": receipt_count,
        "receipt_witnessed": receipt_witnessed,
        "s25q_classification": "UNKNOWN",
        "s25q_status": "UNKNOWN",
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
    if q_result is not None:
        result["s25q_classification"] = q_result.get("classification", "UNKNOWN")
        result["s25q_status"] = q_result.get("status", "UNKNOWN")
    return result


def _invalid(reason: str) -> dict[str, Any]:
    return _output("INPUT_INVALID", TEST_BLOCKED, HOLD, reason)


def _blocked(reason: str, **kwargs: Any) -> dict[str, Any]:
    return _output("RECEIPT_REJECTED", TEST_BLOCKED, HOLD, reason, **kwargs)


def _review(reason: str, *, classification: str = RECEIPT_CONFLICT, **kwargs: Any) -> dict[str, Any]:
    return _output(classification, RECOVERY_REQUIRED, MANUAL_REVIEW, reason, **kwargs)


_Q_BASE_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "baseline_status",
        "candidate_status",
        "sequence_status",
        "floor_status",
        "binding_status",
        "replay_status",
        "floor_advanced",
        "production_status",
        "authority_claim",
        "capability_issued",
        "write_authorized",
        "mutation_allowed",
        "persistence_performed",
        "cas_attempted",
        "fence_issued",
        "resume_allowed",
    }
)
_Q_OPTIONAL_RESULT_KEYS = frozenset({"s25p_classification", "s25p_reason"})


def _validate_hashes(mapping: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    return all(_hash(mapping.get(field)) for field in fields)


def _validate_summary(previous: Any, current: Any) -> str | None:
    if not isinstance(previous, Mapping) or not _exact(previous, _PREVIOUS_KEYS):
        return "PREVIOUS_SCHEMA_NOT_EXACT"
    if not isinstance(current, Mapping) or not _exact(current, _CURRENT_KEYS):
        return "CURRENT_SCHEMA_NOT_EXACT"
    if not _validate_hashes(
        previous,
        ("subject_digest", "scope_digest", "baseline_digest", "pass_digest", "candidate_digest", "evidence_digest", "observation_digest"),
    ):
        return "PREVIOUS_DIGEST_INVALID"
    if not _validate_hashes(
        current,
        ("subject_digest", "scope_digest", "baseline_digest", "previous_pass_digest", "candidate_digest", "evidence_digest", "pass_digest", "observation_digest", "s25p_result_digest"),
    ):
        return "CURRENT_DIGEST_INVALID"
    for node in (previous, current):
        if not _integer(node.get("epoch"), positive=True) or not _integer(node.get("observation_sequence"), positive=True):
            return "SUMMARY_COUNTER_INVALID"
        if node.get("status") not in _STATUS_DECISIONS or node.get("decision") != _STATUS_DECISIONS[node["status"]]:
            return "SUMMARY_STATUS_INVALID"
    return None


def _validate_node(node: Any) -> str | None:
    if not isinstance(node, Mapping) or not _exact(node, _NODE_KEYS):
        return "FLOOR_NODE_SCHEMA_NOT_EXACT"
    if not _validate_hashes(node, ("subject_digest", "scope_digest", "baseline_digest", "floor_pass_digest", "head_digest", "successor_index_digest")):
        return "FLOOR_NODE_DIGEST_INVALID"
    if not _integer(node.get("epoch"), positive=True) or not _integer(node.get("floor_sequence"), positive=True) or not _integer(node.get("state_version"), positive=True):
        return "FLOOR_NODE_COUNTER_INVALID"
    used_pass = node.get("used_pass_digests")
    used_observation = node.get("used_observation_digests")
    if not isinstance(used_pass, list) or not isinstance(used_observation, list) or not used_pass or not used_observation:
        return "FLOOR_NODE_HISTORY_INVALID"
    if len(used_pass) != len(set(used_pass)) or len(used_observation) != len(set(used_observation)):
        return "FLOOR_NODE_HISTORY_DUPLICATE"
    if not all(_hash(item) for item in used_pass + used_observation):
        return "FLOOR_NODE_HISTORY_DIGEST_INVALID"
    return None


def _validate_transition(transition: Any) -> str | None:
    if not isinstance(transition, Mapping) or not _exact(transition, _TRANSITION_KEYS):
        return "TRANSITION_SCHEMA_NOT_EXACT"
    if transition.get("schema") != "s25q.external-floor-transition.v1" or transition.get("source") != "EXTERNAL_TEST_ONLY":
        return "TRANSITION_PROFILE_INVALID"
    if not _text(transition.get("observation_id")) or not _text(transition.get("idempotency_key")):
        return "TRANSITION_ID_INVALID"
    if transition.get("cas_status") not in {"WOULD_ADVANCE", "IDEMPOTENT_MATCH", "CONFLICT"} or not _hash(transition.get("transition_digest")):
        return "TRANSITION_STATUS_INVALID"
    before_error = _validate_node(transition.get("before"))
    after_error = _validate_node(transition.get("after"))
    return f"BEFORE_{before_error}" if before_error else (f"AFTER_{after_error}" if after_error else None)


def _validate_successor(index: Any) -> str | None:
    if not isinstance(index, Mapping) or not _exact(index, _SUCCESSOR_KEYS):
        return "SUCCESSOR_SCHEMA_NOT_EXACT"
    if not _validate_hashes(index, ("parent_key", "candidate_key", "registry_head_digest")):
        return "SUCCESSOR_DIGEST_INVALID"
    if not _integer(index.get("candidate_count"), positive=True) or not _integer(index.get("registry_state_version"), positive=True):
        return "SUCCESSOR_COUNTER_INVALID"
    candidates = index.get("candidate_pass_digests")
    keys = index.get("candidate_keys")
    if not isinstance(candidates, list) or not isinstance(keys, list) or len(candidates) != index["candidate_count"] or len(keys) != index["candidate_count"]:
        return "SUCCESSOR_CANDIDATES_INVALID"
    if not all(_hash(item) for item in candidates + keys) or len(candidates) != len(set(candidates)) or len(keys) != len(set(keys)):
        return "SUCCESSOR_CANDIDATES_INVALID"
    if index.get("lineage") not in {"SINGLE", "FORK", "MERGE"} or index.get("entry_status") not in {"ABSENT", "EXACT_MATCH", "CONFLICT", "MERGE_UNRESOLVED"}:
        return "SUCCESSOR_PROFILE_INVALID"
    if index.get("existing_successor_pass_digest") is not None and not _hash(index["existing_successor_pass_digest"]):
        return "SUCCESSOR_EXISTING_DIGEST_INVALID"
    return None


def _q_status_projection(q_case: Mapping[str, Any]) -> tuple[str, str, str, str] | None:
    current = q_case.get("current")
    if not isinstance(current, Mapping):
        return None
    s25p_case = current.get("s25p_case")
    if not isinstance(s25p_case, Mapping):
        return None
    precedence_case = s25p_case.get("precedence_case")
    if not isinstance(precedence_case, Mapping):
        return None
    baseline = precedence_case.get("baseline")
    candidate = precedence_case.get("candidate")
    if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
        return None
    baseline_status = baseline.get("status")
    candidate_status = candidate.get("status")
    current_status = current.get("status")
    current_decision = current.get("decision")
    if baseline_status not in _STATUS_DECISIONS or candidate_status not in _STATUS_DECISIONS or current_status not in _STATUS_DECISIONS:
        return None
    if current_decision != _STATUS_DECISIONS[current_status]:
        return None
    return baseline_status, candidate_status, current_status, current_decision


def _valid_q_result(result: Any, q_case: Mapping[str, Any] | None = None) -> bool:
    if not isinstance(result, Mapping) or not _safe_value(result):
        return False
    keys = set(result)
    if keys not in (set(_Q_BASE_RESULT_KEYS), set(_Q_BASE_RESULT_KEYS | _Q_OPTIONAL_RESULT_KEYS)):
        return False
    if result.get("schema_version") != "s25q.external-replay-floor.v1" or result.get("observation_mode") != TEST_ONLY:
        return False
    if result.get("classification") not in _Q_CLASSIFICATIONS or result.get("status") not in _STATUS_DECISIONS:
        return False
    if result.get("decision") != _STATUS_DECISIONS[result["status"]] or not isinstance(result.get("reason"), str) or not result["reason"]:
        return False
    if result.get("floor_advanced") is not False or result.get("production_status") != PRODUCTION_NOT_AUTHORIZED or result.get("authority_claim") != NOT_CLAIMED:
        return False
    if result.get("baseline_status") not in set(_STATUS_DECISIONS) | {"UNKNOWN"} or result.get("candidate_status") not in set(_STATUS_DECISIONS) | {"UNKNOWN"}:
        return False
    if not all(result.get(field) is False for field in ("capability_issued", "write_authorized", "mutation_allowed", "persistence_performed", "cas_attempted", "fence_issued", "resume_allowed")):
        return False
    if q_case is not None:
        projection = _q_status_projection(q_case)
        if projection is None:
            return False
        baseline_status, candidate_status, current_status, current_decision = projection
        if result.get("baseline_status") != baseline_status or result.get("candidate_status") != candidate_status:
            return False
    else:
        projection = None
    if result["classification"] == "FLOOR_ADVANCE_ELIGIBLE":
        if result["status"] not in {"LOCKED_TEST_PASS", "PROPOSAL_ONLY"}:
            return False
        if projection is not None and (result["status"] != current_status or result["decision"] != current_decision):
            return False
        if result.get("s25p_classification") != "FRESH_REVALIDATION_ACCEPTED" or result.get("s25p_reason") != "FRESHNESS_BOUND_TO_S25O":
            return False
        return (
            result["reason"] == "FLOOR_ADVANCE_PROPOSAL_ONLY"
            and result["sequence_status"] == "NEXT"
            and result["floor_status"] == "PROPOSED"
            and result["binding_status"] == "MATCH"
            and result["replay_status"] == "NEW"
        )
    if result["status"] not in {TEST_BLOCKED, RECOVERY_REQUIRED}:
        return False
    if "s25p_classification" in result:
        s25p_classification = result.get("s25p_classification")
        s25p_reason = result.get("s25p_reason")
        if s25p_classification not in _S25P_CLASSIFICATIONS or not isinstance(s25p_reason, str) or not s25p_reason:
            return False
        valid_reasons = {
            "FRESH_REVALIDATION_ACCEPTED": {"FRESHNESS_BOUND_TO_S25O"},
            "PRECEDENCE_REJECTED": {"S25O_PRECEDENCE_REJECTED"},
            "FRESHNESS_REJECTED": _S25P_FRESHNESS_REVIEW_REASONS,
            "FRESHNESS_BLOCKED": _S25P_BLOCKED_REASONS,
            "INPUT_INVALID": _S25P_BLOCKED_REASONS | {"CASE_UNREADABLE_OR_TOO_DEEP"},
        }
        if s25p_reason not in valid_reasons[s25p_classification]:
            return False
    if result["classification"] == "FORK_CONFLICT":
        return result["status"] == RECOVERY_REQUIRED and result["decision"] == MANUAL_REVIEW and result["floor_status"] == "NOT_ADVANCED" and result["binding_status"] == "MATCH" and result["replay_status"] == "CONFLICT"
    if result["classification"] == "S25P_REJECTED":
        return result["reason"] == "S25P_RESULT_NOT_ACCEPTABLE" and result["sequence_status"] == "NEXT" and result["floor_status"] == "NOT_ADVANCED" and result["binding_status"] == "MATCH" and result["replay_status"] == "NEW"
    if result["classification"] == "FLOOR_BLOCKED" and result["reason"] == "FLOOR_IDEMPOTENT_REPLAY":
        return result["status"] == TEST_BLOCKED and result["sequence_status"] == "NEXT" and result["floor_status"] == "UNCHANGED" and result["binding_status"] == "MATCH" and result["replay_status"] == "REPLAY"
    return True


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    if not _validate_hashes(
        expected,
        (
            "subject_digest",
            "scope_digest",
            "baseline_digest",
            "previous_pass_digest",
            "previous_observation_digest",
            "current_pass_digest",
            "current_observation_digest",
            "parent_key",
            "candidate_key",
            "transition_digest",
            "before_head_digest",
            "after_head_digest",
            "before_history_digest",
            "after_history_digest",
            "before_successor_index_digest",
            "after_successor_index_digest",
            "successor_index_digest",
            "s25q_case_digest",
            "s25q_result_digest",
            "receipt_set_digest",
        ),
    ):
        return "EXPECTED_DIGEST_INVALID"
    for field in ("epoch", "previous_sequence", "current_sequence", "before_state_version", "after_state_version"):
        if not _integer(expected.get(field), positive=True):
            return "EXPECTED_COUNTER_INVALID"
    if expected.get("s25q_classification") not in _Q_CLASSIFICATIONS or expected.get("s25q_status") not in _STATUS_DECISIONS:
        return "EXPECTED_Q_STATUS_INVALID"
    if expected.get("s25q_decision") != _STATUS_DECISIONS[expected["s25q_status"]] or expected.get("s25p_classification") not in _S25P_CLASSIFICATIONS:
        return "EXPECTED_Q_BINDING_INVALID"
    if not _text(expected.get("observation_id")) or not _text(expected.get("idempotency_key")):
        return "EXPECTED_OBSERVATION_ID_INVALID"
    return None


def _validate_receipt(receipt: Any) -> str | None:
    if not isinstance(receipt, Mapping) or not _exact(receipt, _RECEIPT_KEYS):
        return "RECEIPT_SCHEMA_NOT_EXACT"
    kind = receipt.get("kind")
    if kind not in _PAYLOAD_KEYS:
        return "RECEIPT_KIND_INVALID"
    if not _hash(receipt.get("receipt_digest")) or receipt["receipt_digest"] != _receipt_digest(receipt):
        return "RECEIPT_DIGEST_INVALID"
    if not _text(receipt.get("observation_id")) or not _text(receipt.get("idempotency_key")):
        return "RECEIPT_IDENTIFIER_INVALID"
    if not _validate_hashes(
        receipt,
        (
            "subject_digest",
            "scope_digest",
            "baseline_digest",
            "previous_pass_digest",
            "previous_observation_digest",
            "current_pass_digest",
            "current_observation_digest",
            "parent_key",
            "candidate_key",
            "transition_digest",
            "before_head_digest",
            "after_head_digest",
            "before_history_digest",
            "after_history_digest",
            "index_digest",
        ),
    ):
        return "RECEIPT_BINDING_DIGEST_INVALID"
    if not _integer(receipt.get("epoch"), positive=True) or not _integer(receipt.get("previous_sequence"), positive=True) or not _integer(receipt.get("current_sequence"), positive=True) or not _integer(receipt.get("before_state_version"), positive=True) or not _integer(receipt.get("after_state_version"), positive=True):
        return "RECEIPT_COUNTER_INVALID"
    payload = receipt.get("payload")
    if not isinstance(payload, Mapping) or not _exact(payload, _PAYLOAD_KEYS[kind]):
        return "RECEIPT_PAYLOAD_SCHEMA_INVALID"
    if kind == "S25Q_RESULT":
        if not _hash(payload.get("s25q_result_digest")) or payload.get("classification") not in _Q_CLASSIFICATIONS or payload.get("status") not in _STATUS_DECISIONS or payload.get("decision") != _STATUS_DECISIONS[payload["status"]] or payload.get("s25p_classification") not in _S25P_CLASSIFICATIONS or payload.get("floor_advanced") is not False or not _text(payload.get("reason")):
            return "RECEIPT_Q_PAYLOAD_INVALID"
    elif kind == "PARENT_CANDIDATE":
        if not _integer(payload.get("previous_sequence"), positive=True) or not _integer(payload.get("current_sequence"), positive=True) or not _validate_hashes(payload, ("previous_pass_digest", "current_pass_digest", "parent_key", "candidate_key")):
            return "RECEIPT_PARENT_PAYLOAD_INVALID"
    elif kind == "TRANSITION":
        if payload.get("schema") != "s25q.external-floor-transition.v1" or payload.get("source") != "EXTERNAL_TEST_ONLY" or not _text(payload.get("observation_id")) or not _text(payload.get("idempotency_key")) or payload.get("cas_status") not in {"WOULD_ADVANCE", "IDEMPOTENT_MATCH", "CONFLICT"}:
            return "RECEIPT_TRANSITION_PAYLOAD_INVALID"
    elif kind == "HEAD":
        if not _validate_hashes(payload, ("before_head_digest", "after_head_digest", "transition_digest")):
            return "RECEIPT_HEAD_PAYLOAD_INVALID"
    elif kind == "HISTORY":
        if not _validate_hashes(payload, ("before_history_digest", "after_history_digest", "appended_pass_digest", "appended_observation_digest")):
            return "RECEIPT_HISTORY_PAYLOAD_INVALID"
    elif kind == "INDEX":
        if not _hash(payload.get("successor_index_digest")) or not _integer(payload.get("registry_state_version"), positive=True) or not _hash(payload.get("registry_head_digest")) or not _integer(payload.get("candidate_count"), positive=True) or not isinstance(payload.get("candidate_pass_digests"), list) or not isinstance(payload.get("candidate_keys"), list) or not all(_hash(item) for item in payload["candidate_pass_digests"] + payload["candidate_keys"]) or payload.get("lineage") not in {"SINGLE", "FORK", "MERGE"} or payload.get("entry_status") not in {"ABSENT", "EXACT_MATCH", "CONFLICT", "MERGE_UNRESOLVED"}:
            return "RECEIPT_INDEX_PAYLOAD_INVALID"
    return None


def _validate_receipt_set(receipt_set: Any) -> str | None:
    if not isinstance(receipt_set, Mapping) or not _exact(receipt_set, _RECEIPT_SET_KEYS):
        return "RECEIPT_SET_SCHEMA_NOT_EXACT"
    if receipt_set.get("schema") != "s25r.receipt-set.v1" or receipt_set.get("required_kinds") != list(_REQUIRED_KINDS):
        return "RECEIPT_SET_PROFILE_INVALID"
    receipts = receipt_set.get("receipts")
    digests = receipt_set.get("receipt_digests")
    if not isinstance(receipts, list) or not isinstance(digests, list) or not _integer(receipt_set.get("receipt_count")) or receipt_set["receipt_count"] != len(receipts) or len(digests) != len(receipts) or not _hash(receipt_set.get("set_digest")):
        return "RECEIPT_SET_SHAPE_INVALID"
    if len(digests) != len(set(digests)):
        return "RECEIPTS_DUPLICATE"
    for receipt, digest in zip(receipts, digests):
        error = _validate_receipt(receipt)
        if error:
            return error
        if receipt["receipt_digest"] != digest:
            return "RECEIPT_SET_DIGEST_MISMATCH"
    try:
        if receipt_set["set_digest"] != _set_digest(receipt_set):
            return "RECEIPT_SET_DIGEST_DRIFT"
    except (TypeError, ValueError, UnicodeError):
        return "RECEIPT_SET_NOT_CANONICAL"
    kinds = [receipt.get("kind") for receipt in receipts]
    if len(kinds) != len(set(kinds)):
        return "RECEIPTS_DUPLICATE"
    if len(kinds) != len(_REQUIRED_KINDS) or set(kinds) != set(_REQUIRED_KINDS):
        return "RECEIPTS_PARTIAL"
    return None


def _summary_without_nested(current: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in current.items() if key != "s25p_case"}


def _same_common_receipt(receipt: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    fields = (
        "subject_digest",
        "scope_digest",
        "observation_id",
        "idempotency_key",
        "baseline_digest",
        "epoch",
        "previous_sequence",
        "previous_pass_digest",
        "previous_observation_digest",
        "current_sequence",
        "current_pass_digest",
        "current_observation_digest",
        "parent_key",
        "candidate_key",
        "transition_digest",
        "before_state_version",
        "after_state_version",
        "before_head_digest",
        "after_head_digest",
        "before_history_digest",
        "after_history_digest",
        "index_digest",
    )
    return all(receipt.get(field) == (expected["successor_index_digest"] if field == "index_digest" else expected.get(field)) for field in fields)


def _expected_receipt_payloads(
    q_result: Mapping[str, Any],
    q_case: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    transition = q_case["floor_transition"]
    before = transition["before"]
    after = transition["after"]
    index = q_case["successor_index"]
    return {
        "S25Q_RESULT": {
            "s25q_result_digest": expected["s25q_result_digest"],
            "classification": q_result["classification"],
            "status": q_result["status"],
            "decision": q_result["decision"],
            "s25p_classification": q_result["s25p_classification"],
            "reason": q_result["reason"],
            "floor_advanced": False,
        },
        "PARENT_CANDIDATE": {
            "previous_sequence": expected["previous_sequence"],
            "current_sequence": expected["current_sequence"],
            "previous_pass_digest": expected["previous_pass_digest"],
            "current_pass_digest": expected["current_pass_digest"],
            "parent_key": expected["parent_key"],
            "candidate_key": expected["candidate_key"],
        },
        "TRANSITION": {
            "schema": transition["schema"],
            "source": transition["source"],
            "observation_id": transition["observation_id"],
            "idempotency_key": transition["idempotency_key"],
            "cas_status": transition["cas_status"],
        },
        "HEAD": {
            "before_head_digest": expected["before_head_digest"],
            "after_head_digest": expected["after_head_digest"],
            "transition_digest": expected["transition_digest"],
        },
        "HISTORY": {
            "before_history_digest": expected["before_history_digest"],
            "after_history_digest": expected["after_history_digest"],
            "appended_pass_digest": after["used_pass_digests"][-1],
            "appended_observation_digest": after["used_observation_digests"][-1],
        },
        "INDEX": {
            "successor_index_digest": expected["successor_index_digest"],
            "registry_state_version": index["registry_state_version"],
            "registry_head_digest": index["registry_head_digest"],
            "candidate_count": index["candidate_count"],
            "candidate_pass_digests": index["candidate_pass_digests"],
            "candidate_keys": index["candidate_keys"],
            "lineage": index["lineage"],
            "entry_status": index["entry_status"],
        },
    }


def _q_observation_digest(node: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in node.items() if key != "observation_digest"})


def _q_pass_digest(current: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in current.items() if key not in {"pass_digest", "observation_digest"}}
    return _digest({"current": unsigned, "s25p_result_digest": current["s25p_result_digest"]})


def _q_parent_key(previous: Mapping[str, Any]) -> str:
    return _digest(
        {
            "subject_digest": previous["subject_digest"],
            "scope_digest": previous["scope_digest"],
            "baseline_digest": previous["baseline_digest"],
            "epoch": previous["epoch"],
            "observation_sequence": previous["observation_sequence"],
            "pass_digest": previous["pass_digest"],
        }
    )


def _q_candidate_key(parent_key: str, current: Mapping[str, Any]) -> str:
    return _digest(
        {
            "parent_key": parent_key,
            "observation_sequence": current["observation_sequence"],
            "pass_digest": current["pass_digest"],
        }
    )


def _q_transition_digest(transition: Mapping[str, Any]) -> str:
    after = {key: value for key, value in transition["after"].items() if key != "head_digest"}
    return _digest(
        {
            "schema": transition["schema"],
            "source": transition["source"],
            "observation_id": transition["observation_id"],
            "idempotency_key": transition["idempotency_key"],
            "before": transition["before"],
            "after": after,
            "cas_status": transition["cas_status"],
        }
    )


def _valid_positive_q_case(q_case: Mapping[str, Any]) -> bool:
    previous = q_case.get("previous")
    current = q_case.get("current")
    transition = q_case.get("floor_transition")
    index = q_case.get("successor_index")
    if not isinstance(previous, Mapping) or not isinstance(current, Mapping) or not isinstance(transition, Mapping) or not isinstance(index, Mapping):
        return False
    before = transition.get("before")
    after = transition.get("after")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return False
    if transition.get("cas_status") != "WOULD_ADVANCE" or index.get("lineage") != "SINGLE" or index.get("entry_status") != "ABSENT" or index.get("candidate_count") != 1 or index.get("existing_successor_pass_digest") is not None:
        return False
    if current.get("previous_pass_digest") != previous.get("pass_digest") or current.get("observation_sequence") != previous.get("observation_sequence") + 1:
        return False
    if current.get("pass_digest") != _q_pass_digest(current) or current.get("observation_digest") != _q_observation_digest(current):
        return False
    parent_key = _q_parent_key(previous)
    candidate_key = _q_candidate_key(parent_key, current)
    if index.get("parent_key") != parent_key or index.get("candidate_key") != candidate_key or index.get("candidate_pass_digests") != [current.get("pass_digest")] or index.get("candidate_keys") != [candidate_key]:
        return False
    if index.get("registry_state_version") != before.get("state_version") or index.get("registry_head_digest") != before.get("head_digest"):
        return False
    if before.get("subject_digest") != previous.get("subject_digest") or before.get("scope_digest") != previous.get("scope_digest") or before.get("baseline_digest") != previous.get("baseline_digest") or before.get("epoch") != previous.get("epoch") or before.get("floor_sequence") != previous.get("observation_sequence") or before.get("floor_pass_digest") != previous.get("pass_digest") or before.get("used_pass_digests", [])[-1] != previous.get("pass_digest") or before.get("used_observation_digests", [])[-1] != previous.get("observation_digest"):
        return False
    if after.get("subject_digest") != current.get("subject_digest") or after.get("scope_digest") != current.get("scope_digest") or after.get("baseline_digest") != current.get("baseline_digest") or after.get("epoch") != current.get("epoch") or after.get("floor_sequence") != current.get("observation_sequence") or after.get("floor_pass_digest") != current.get("pass_digest") or after.get("state_version") != before.get("state_version") + 1:
        return False
    if after.get("used_pass_digests") != before.get("used_pass_digests") + [current.get("pass_digest")] or after.get("used_observation_digests") != before.get("used_observation_digests") + [current.get("observation_digest")]:
        return False
    if after.get("successor_index_digest") != _digest(index) or transition.get("transition_digest") != _q_transition_digest(transition):
        return False
    return after.get("head_digest") == _digest({"before_head_digest": before.get("head_digest"), "transition_digest": transition.get("transition_digest")})


def _evaluate(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    try:
        case = _parse(case)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _invalid("CASE_JSON_INVALID")
    except TypeError:
        return _invalid("CASE_NOT_MAPPING")
    if not _exact(case, _TOP_LEVEL):
        return _invalid("CASE_SCHEMA_NOT_EXACT")
    if not _safe_value(case):
        return _invalid("CASE_VALUE_NOT_SAFE")
    if case.get("schema_version") != HARNESS_SCHEMA or case.get("observation_mode") != TEST_ONLY:
        return _invalid("CASE_PROFILE_INVALID")
    if case.get("canonicalization") != CANONICALIZATION or not _hash(case.get("input_digest")):
        return _invalid("CASE_CANONICALIZATION_OR_DIGEST_INVALID")
    try:
        if case["input_digest"] != input_digest(case):
            return _invalid("CASE_DIGEST_DRIFT")
    except (TypeError, ValueError, UnicodeError):
        return _invalid("CASE_NOT_CANONICAL")

    expected = case["expected"]
    previous = case["previous"]
    current = case["current"]
    transition = case["floor_transition"]
    index = case["successor_index"]
    for validator, value in (
        (_validate_expected, expected),
        (lambda item: _validate_summary(item, current), previous),
        (lambda item: _validate_transition(item), transition),
        (lambda item: _validate_successor(item), index),
        (lambda item: _validate_receipt_set(item), case["receipt_set"]),
    ):
        error = validator(value)
        if error:
            if error in {"RECEIPTS_DUPLICATE", "RECEIPTS_PARTIAL"}:
                return _blocked(error)
            return _blocked(error)
    if not isinstance(case.get("s25q_case"), Mapping) or not _safe_value(case["s25q_case"]):
        return _blocked("S25Q_CASE_INVALID")
    q_case = case["s25q_case"]
    q_previous = q_case.get("previous")
    q_current = q_case.get("current")
    q_transition = q_case.get("floor_transition")
    q_index = q_case.get("successor_index")
    if not isinstance(q_previous, Mapping) or not isinstance(q_current, Mapping) or not isinstance(q_transition, Mapping) or not isinstance(q_index, Mapping):
        return _blocked("S25Q_CASE_SCHEMA_INVALID")
    try:
        q_result_raw = evaluate_replay_floor_fork(q_case)
        q_result = _snapshot(q_result_raw)
    except Exception:
        return _blocked("S25Q_CASE_UNREADABLE")
    if not _valid_q_result(q_result, q_case):
        return _blocked("S25Q_RESULT_INVALID")
    try:
        q_result_digest = _digest(q_result)
    except (TypeError, ValueError, UnicodeError):
        return _blocked("S25Q_RESULT_NOT_CANONICAL")
    if not _hash(q_case.get("input_digest")) or q_case.get("input_digest") != expected["s25q_case_digest"]:
        return _review("S25Q_CASE_DIGEST_MISMATCH", classification=S25Q_REJECTED, q_result=q_result)
    if previous != q_previous or current != _summary_without_nested(q_current) or transition != q_transition or index != q_index:
        return _review("S25Q_CASE_PROJECTION_MISMATCH", classification=S25Q_REJECTED, q_result=q_result)

    before = transition["before"]
    after = transition["after"]
    expected_bindings = {
        "subject_digest": q_previous.get("subject_digest"),
        "scope_digest": q_previous.get("scope_digest"),
        "baseline_digest": q_previous.get("baseline_digest"),
        "epoch": q_previous.get("epoch"),
        "previous_sequence": q_previous.get("observation_sequence"),
        "previous_pass_digest": q_previous.get("pass_digest"),
        "previous_observation_digest": q_previous.get("observation_digest"),
        "current_sequence": q_current.get("observation_sequence"),
        "current_pass_digest": q_current.get("pass_digest"),
        "current_observation_digest": q_current.get("observation_digest"),
        "parent_key": q_index.get("parent_key"),
        "candidate_key": q_index.get("candidate_key"),
        "transition_digest": transition.get("transition_digest"),
        "before_state_version": before.get("state_version"),
        "after_state_version": after.get("state_version"),
        "before_head_digest": before.get("head_digest"),
        "after_head_digest": after.get("head_digest"),
        "before_history_digest": _history_digest(before),
        "after_history_digest": _history_digest(after),
        "before_successor_index_digest": before.get("successor_index_digest"),
        "after_successor_index_digest": after.get("successor_index_digest"),
        "successor_index_digest": _digest(index),
        "s25q_result_digest": q_result_digest,
        "s25q_classification": q_result.get("classification"),
        "s25q_status": q_result.get("status"),
        "s25q_decision": q_result.get("decision"),
        "s25p_classification": q_result.get("s25p_classification"),
        "observation_id": transition.get("observation_id"),
        "idempotency_key": transition.get("idempotency_key"),
    }
    for field, value in expected_bindings.items():
        if expected.get(field) != value:
            return _review("EXPECTED_BINDING_MISMATCH", classification=S25Q_REJECTED, q_result=q_result)
    if expected["current_sequence"] != expected["previous_sequence"] + 1:
        return _review("EXPECTED_SEQUENCE_NOT_NEXT", classification=S25Q_REJECTED, q_result=q_result)
    if expected["after_state_version"] != expected["before_state_version"] + 1:
        return _review("EXPECTED_STATE_VERSION_NOT_MONOTONE", classification=S25Q_REJECTED, q_result=q_result)

    if q_result["classification"] != "FLOOR_ADVANCE_ELIGIBLE":
        if q_result["classification"] == "FORK_CONFLICT":
            return _review("S25Q_FORK_CONFLICT", classification=FORK_CONFLICT, q_result=q_result)
        if q_result["classification"] == "FLOOR_BLOCKED" and q_result.get("replay_status") == "REPLAY":
            return _output(RECEIPT_REPLAY, TEST_BLOCKED, HOLD, "S25Q_REPLAY_OBSERVED", q_result=q_result)
        if q_result["status"] == RECOVERY_REQUIRED:
            return _review("S25Q_NOT_ELIGIBLE", classification=S25Q_REJECTED, q_result=q_result)
        return _output(S25Q_REJECTED, q_result["status"], q_result["decision"], "S25Q_NOT_ELIGIBLE", q_result=q_result)
    if q_result.get("reason") != "FLOOR_ADVANCE_PROPOSAL_ONLY" or q_result.get("floor_advanced") is not False or q_result.get("s25p_classification") != "FRESH_REVALIDATION_ACCEPTED":
        return _blocked("S25Q_POSITIVE_SEMANTICS_INVALID", q_result=q_result)
    if not _valid_positive_q_case(q_case):
        return _review("S25Q_CASE_NOT_RECONCILIABLE", classification=S25Q_REJECTED, q_result=q_result)
    if transition.get("cas_status") != "WOULD_ADVANCE" or index.get("lineage") != "SINGLE" or index.get("entry_status") != "ABSENT" or index.get("candidate_count") != 1:
        return _review("S25Q_PROPOSAL_NOT_SINGLE", classification=RECEIPT_CONFLICT, q_result=q_result)

    receipt_set = case["receipt_set"]
    receipts = receipt_set["receipts"]
    kinds = [receipt["kind"] for receipt in receipts]
    if set(kinds) != set(_REQUIRED_KINDS):
        return _blocked("RECEIPTS_PARTIAL", q_result=q_result, receipt_count=len(receipts))
    if receipt_set["set_digest"] != expected["receipt_set_digest"]:
        return _blocked("RECEIPT_SET_BINDING_MISMATCH", q_result=q_result, receipt_count=len(receipts))
    common_expected = dict(expected)
    payloads = _expected_receipt_payloads(q_result, q_case, expected)
    for receipt in receipts:
        if not _same_common_receipt(receipt, common_expected):
            identity_fields = ("subject_digest", "scope_digest", "baseline_digest", "epoch")
            if any(receipt.get(field) != expected.get(field) for field in identity_fields):
                return _review("RECEIPT_IDENTITY_MISMATCH", classification=RECEIPT_CONFLICT, q_result=q_result, receipt_count=len(receipts))
            replay_fields = (
                "previous_sequence",
                "previous_pass_digest",
                "previous_observation_digest",
                "current_sequence",
                "current_pass_digest",
                "current_observation_digest",
            )
            if any(receipt.get(field) != expected.get(field) for field in replay_fields):
                return _review("RECEIPT_REPLAY", classification=RECEIPT_REPLAY, q_result=q_result, receipt_count=len(receipts))
            return _review("RECEIPT_STALE_OR_CONFLICTING", classification=RECEIPT_CONFLICT, q_result=q_result, receipt_count=len(receipts))
        if receipt["payload"] != payloads[receipt["kind"]]:
            if receipt["kind"] == "S25Q_RESULT":
                return _blocked("RECEIPT_Q_RESULT_MISMATCH", q_result=q_result, receipt_count=len(receipts))
            return _review("RECEIPT_PAYLOAD_CONFLICT", classification=RECEIPT_CONFLICT, q_result=q_result, receipt_count=len(receipts))
    return _output(
        RECEIPT_BUNDLE_RECONCILED,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        "READ_ONLY_WITNESS_ONLY",
        q_result=q_result,
        reconciliation_status="CONSISTENT",
        witness_only=True,
        receipt_count=len(receipts),
        receipt_witnessed=True,
    )


def evaluate_receipt_reconciliation(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Fail closed for hostile mappings, malformed receipts and deep values."""

    try:
        return _evaluate(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


__all__ = [
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "RECEIPT_BUNDLE_RECONCILED",
    "RECEIPT_CONFLICT",
    "RECEIPT_REJECTED",
    "RECEIPT_REPLAY",
    "FORK_CONFLICT",
    "S25Q_REJECTED",
    "evaluate_receipt_reconciliation",
    "input_digest",
]

