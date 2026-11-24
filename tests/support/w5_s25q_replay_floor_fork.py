"""Pure S25Q replay-floor and fork-conflict gate behind S25P."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from support.w5_s25p_fresh_revalidation import evaluate_fresh_revalidation
except ImportError:  # pragma: no cover - direct support-module execution
    from w5_s25p_fresh_revalidation import evaluate_fresh_revalidation


HARNESS_SCHEMA = "s25q.external-replay-floor.v1"
CANONICALIZATION = "s25m-canonical-json-v1"
TEST_ONLY = "TEST_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
HOLD = "HOLD"
MANUAL_REVIEW = "MANUAL_REVIEW"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

FLOOR_ADVANCE_ELIGIBLE = "FLOOR_ADVANCE_ELIGIBLE"
FLOOR_IDEMPOTENT_REPLAY = "FLOOR_IDEMPOTENT_REPLAY"
FORK_CONFLICT = "FORK_CONFLICT"
FLOOR_REJECTED = "FLOOR_REJECTED"
S25P_REJECTED = "S25P_REJECTED"

_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_MAX_DEPTH = 64
_MAX_STRING = 4096
_MAX_INTEGER = 2**63 - 1

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
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "predecessor_sequence",
        "predecessor_pass_digest",
        "successor_sequence",
        "successor_pass_digest",
        "current_case_digest",
        "floor_before_state_version",
        "floor_before_head_digest",
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
        "s25p_case",
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
_FLOOR_TRANSITION_KEYS = frozenset(
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
_STATUS_DECISIONS = {
    "LOCKED_TEST_PASS": "TEST_ONLY_PASS",
    "PROPOSAL_ONLY": "DESIGN_ONLY",
    "TEST_BLOCKED": "HOLD",
    "RECOVERY_REQUIRED": "MANUAL_REVIEW",
}
_CLAIM_LEVEL = {"LOCKED_TEST_PASS": 3, "PROPOSAL_ONLY": 2, "TEST_BLOCKED": 1, "RECOVERY_REQUIRED": 1}
_S25P_CLASSIFICATIONS = frozenset(
    {"FRESH_REVALIDATION_ACCEPTED", "PRECEDENCE_REJECTED", "FRESHNESS_REJECTED", "FRESHNESS_BLOCKED", "INPUT_INVALID"}
)
_S25P_CORE_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "baseline_status",
        "candidate_status",
        "digest_status",
        "freshness_status",
        "sequence_status",
        "binding_status",
        "replay_status",
        "production_status",
        "authority_claim",
        "capability_issued",
        "write_authorized",
        "mutation_allowed",
        "persistence_performed",
        "cas_attempted",
        "fence_issued",
        "resume_allowed",
        "assurance_rank",
    }
)
_S25P_OPTIONAL_KEYS = frozenset(
    {"precedence_classification", "precedence_reason", "precedence_digest_status"}
)
_S25P_ASSURANCE_RANK = {
    "LOCKED_TEST_PASS": 2,
    "PROPOSAL_ONLY": 1,
    "TEST_BLOCKED": 0,
    "RECOVERY_REQUIRED": 0,
}
_S25P_PRECEDENCE_CLASSIFICATIONS = frozenset(
    {"NO_ESCALATION", "SAFE_NON_ESCALATING_DOWNGRADE", "INPUT_INVALID", "STATUS_ESCALATION_REJECTED"}
)
_S25P_RESULT_CLASSIFICATIONS = frozenset(
    {"FRESH_REVALIDATION_ACCEPTED", "PRECEDENCE_REJECTED", "FRESHNESS_REJECTED", "FRESHNESS_BLOCKED", "INPUT_INVALID"}
)
_S25P_FRESHNESS_REVIEW_REASONS = frozenset(
    {
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
        "STATUS_ESCALATION_AFTER_PRIOR_PASS",
    }
)
_S25P_FRESHNESS_BLOCKED_REASONS = frozenset(
    {
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
        "FRESHNESS_ANCHOR_SCHEMA_NOT_EXACT",
        "FRESHNESS_ANCHOR_SOURCE_INVALID",
        "FRESHNESS_ANCHOR_NOT_CURRENT",
        "FRESHNESS_ANCHOR_COUNTER_INVALID",
        "FRESHNESS_ANCHOR_DIGEST_INVALID",
        "REPLAY_GUARD_SCHEMA_NOT_EXACT",
        "REPLAY_GUARD_SCHEMA_INVALID",
        "REPLAY_GUARD_SEQUENCE_INVALID",
        "REPLAY_GUARD_LIST_INVALID",
        "REPLAY_GUARD_DUPLICATE_DIGEST",
        "PRECEDENCE_CASE_NOT_MAPPING",
        "PRECEDENCE_CASE_UNREADABLE",
        "PRECEDENCE_REPORTS_NOT_MAPPING",
        "PRECEDENCE_DIGEST_INVALID",
        "DERIVED_DIGEST_NOT_CANONICAL",
        "FRESHNESS_ANCHOR_MISMATCH",
        "CANDIDATE_DIGEST_DRIFT",
        "EVIDENCE_DIGEST_DRIFT",
        "PRECEDENCE_RESULT_INVALID",
    }
)
_S25O_REPORT_KEYS = frozenset(
    {
        "status",
        "decision",
        "evidence_state",
        "seal_status",
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
_S25O_EVENT_KEYS = frozenset({"kind", "field", "baseline_evidence_state", "candidate_evidence_state"})
_S25O_EVENT_STATES = {
    "EVIDENCE_REMOVED": "MISSING",
    "EVIDENCE_DOWNGRADED": "PROPOSED",
    "EVIDENCE_UNKNOWN": "UNKNOWN",
    "EVIDENCE_STALE": "STALE",
    "EVIDENCE_DRIFT": "DRIFT",
    "EVIDENCE_MALFORMED": "MALFORMED",
}
_S25O_ALLOWED_EVENT_FIELDS = frozenset(
    {
        "oracle.result",
        "oracle",
        "sbom.includes_native",
        "sbom",
        "lockfile.hash_mode",
        "lockfile",
        "provider",
        "provider.native",
        "fips.provider_binding",
        "graph.edge",
        "projection_digests",
        "subject",
        "source_tree_sha256",
        "root_digest",
        "schema",
        "dependency_graph",
        "artifacts",
        "fips",
    }
)
_S25O_EVIDENCE_STATES = frozenset({"COMPLETE", "PROPOSED", "MISSING", "UNKNOWN", "STALE", "DRIFT", "MALFORMED"})
_S25O_FAIL_CLOSED_STATES = frozenset({"MISSING", "UNKNOWN", "STALE", "DRIFT", "MALFORMED"})


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
    """Materialize one stable, plain snapshot before any validation or digest."""

    if depth > _MAX_DEPTH:
        raise ValueError("replay-floor value is too deep")
    if value is None or isinstance(value, (bool, int, str, float)):
        return value
    if isinstance(value, list):
        return [_snapshot(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        snapshot: dict[Any, Any] = {}
        for key, item in value.items():
            if key in snapshot:
                raise _DuplicateKey(str(key))
            snapshot[key] = _snapshot(item, depth=depth + 1)
        return snapshot
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
        normalized = stripped.lower()
        if len(value) > _MAX_STRING or _ABSOLUTE_PATH.match(stripped) is not None:
            return False
        if _URI_SCHEME.match(normalized) is not None or stripped.startswith("\\\\"):
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
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (value > 0 if positive else value >= 0)
        and value <= _MAX_INTEGER
    )


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value


def _parse(value: Mapping[str, Any] | bytes | str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        parsed = _snapshot(value)
        if isinstance(parsed, Mapping):
            return parsed
        raise TypeError("replay-floor case must be a mapping")
    if isinstance(value, (bytes, str)):
        raw = value.decode("utf-8") if isinstance(value, bytes) else value
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs, parse_constant=_reject_constant)
        if isinstance(parsed, Mapping):
            return _snapshot(parsed)
    raise TypeError("replay-floor case must be a mapping or JSON object")


def _canonical_json(value: Any) -> bytes:
    if not _safe_value(value):
        raise ValueError("replay-floor case contains unsafe value")
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def input_digest(case: Mapping[str, Any]) -> str:
    try:
        if not isinstance(case, Mapping):
            raise TypeError("replay-floor case must be a mapping")
        snapshot = _snapshot(case)
        if not isinstance(snapshot, Mapping):
            raise TypeError("replay-floor case must be a mapping")
        unsigned = {key: value for key, value in snapshot.items() if key != "input_digest"}
        return hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    except Exception:
        raise ValueError("replay-floor case cannot be canonicalized") from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _observation_digest(node: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in node.items() if key != "observation_digest"}
    return _digest(unsigned)


def _pass_digest(current: Mapping[str, Any], s25p_result_digest: str) -> str:
    unsigned = {
        key: value
        for key, value in current.items()
        if key not in {"pass_digest", "observation_digest"}
    }
    return _digest({"current": unsigned, "s25p_result_digest": s25p_result_digest})


def _parent_key(previous: Mapping[str, Any]) -> str:
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


def _candidate_key(parent_key: str, current: Mapping[str, Any]) -> str:
    return _digest(
        {
            "parent_key": parent_key,
            "observation_sequence": current["observation_sequence"],
            "pass_digest": current["pass_digest"],
        }
    )


def _transition_digest(transition: Mapping[str, Any]) -> str:
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


def _output(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    s25p_result: Mapping[str, Any] | None = None,
    sequence_status: str = "NOT_CLAIMED",
    floor_status: str = "NOT_CLAIMED",
    binding_status: str = "NOT_CLAIMED",
    replay_status: str = "NOT_CLAIMED",
) -> dict[str, Any]:
    result = {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": TEST_ONLY,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "baseline_status": "UNKNOWN",
        "candidate_status": "UNKNOWN",
        "sequence_status": sequence_status,
        "floor_status": floor_status,
        "binding_status": binding_status,
        "replay_status": replay_status,
        "floor_advanced": False,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
        "capability_issued": False,
        "write_authorized": False,
        "mutation_allowed": False,
        "persistence_performed": False,
        "cas_attempted": False,
        "fence_issued": False,
        "resume_allowed": False,
    }
    if s25p_result is not None:
        result["baseline_status"] = s25p_result.get("baseline_status", "UNKNOWN")
        result["candidate_status"] = s25p_result.get("candidate_status", "UNKNOWN")
        result["s25p_classification"] = s25p_result.get("classification", "UNKNOWN")
        result["s25p_reason"] = s25p_result.get("reason", "UNKNOWN")
    return result


def _invalid(reason: str) -> dict[str, Any]:
    return _output("INPUT_INVALID", TEST_BLOCKED, HOLD, reason)


def _blocked(reason: str, **kwargs: Any) -> dict[str, Any]:
    return _output("FLOOR_BLOCKED", TEST_BLOCKED, HOLD, reason, **kwargs)


def _review(reason: str, *, classification: str = FLOOR_REJECTED, **kwargs: Any) -> dict[str, Any]:
    return _output(classification, RECOVERY_REQUIRED, MANUAL_REVIEW, reason, **kwargs)


def _validate_hashes(mapping: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    return all(_hash(mapping.get(field)) for field in fields)


def _validate_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_hash(item) for item in value) and len(set(value)) == len(value)


def _validate_previous(previous: Any) -> str | None:
    if not isinstance(previous, Mapping) or not _exact(previous, _PREVIOUS_KEYS):
        return "PREVIOUS_SCHEMA_NOT_EXACT"
    if not _validate_hashes(
        previous,
        (
            "subject_digest",
            "scope_digest",
            "baseline_digest",
            "pass_digest",
            "candidate_digest",
            "evidence_digest",
            "observation_digest",
        ),
    ):
        return "PREVIOUS_DIGEST_INVALID"
    if not _integer(previous.get("epoch"), positive=True) or not _integer(previous.get("observation_sequence"), positive=True):
        return "PREVIOUS_COUNTER_INVALID"
    if previous.get("status") not in _STATUS_DECISIONS or previous.get("decision") != _STATUS_DECISIONS[previous["status"]]:
        return "PREVIOUS_STATUS_INVALID"
    if previous["observation_digest"] != _observation_digest(previous):
        return "PREVIOUS_OBSERVATION_DIGEST_DRIFT"
    return None


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    if not _validate_hashes(
        expected,
        (
            "subject_digest",
            "scope_digest",
            "baseline_digest",
            "predecessor_pass_digest",
            "successor_pass_digest",
            "current_case_digest",
            "floor_before_head_digest",
        ),
    ):
        return "EXPECTED_DIGEST_INVALID"
    if not _integer(expected.get("epoch"), positive=True):
        return "EXPECTED_EPOCH_INVALID"
    if not _integer(expected.get("predecessor_sequence"), positive=True) or not _integer(expected.get("successor_sequence"), positive=True):
        return "EXPECTED_SEQUENCE_INVALID"
    if not _integer(expected.get("floor_before_state_version"), positive=True):
        return "EXPECTED_STATE_VERSION_INVALID"
    return None


def _validate_current(current: Any) -> str | None:
    if not isinstance(current, Mapping) or not _exact(current, _CURRENT_KEYS):
        return "CURRENT_SCHEMA_NOT_EXACT"
    if not _validate_hashes(
        current,
        (
            "subject_digest",
            "scope_digest",
            "baseline_digest",
            "previous_pass_digest",
            "candidate_digest",
            "evidence_digest",
            "pass_digest",
            "observation_digest",
            "s25p_result_digest",
        ),
    ):
        return "CURRENT_DIGEST_INVALID"
    if not _integer(current.get("epoch"), positive=True) or not _integer(current.get("observation_sequence"), positive=True):
        return "CURRENT_COUNTER_INVALID"
    if current.get("status") not in _STATUS_DECISIONS or current.get("decision") != _STATUS_DECISIONS[current["status"]]:
        return "CURRENT_STATUS_INVALID"
    if not isinstance(current.get("s25p_case"), Mapping):
        return "S25P_CASE_NOT_MAPPING"
    return None


def _validate_floor_node(node: Any) -> str | None:
    if not isinstance(node, Mapping) or not _exact(node, _NODE_KEYS):
        return "FLOOR_NODE_SCHEMA_NOT_EXACT"
    if not _validate_hashes(
        node,
        (
            "subject_digest",
            "scope_digest",
            "baseline_digest",
            "floor_pass_digest",
            "head_digest",
            "successor_index_digest",
        ),
    ):
        return "FLOOR_NODE_DIGEST_INVALID"
    if not _integer(node.get("epoch"), positive=True) or not _integer(node.get("floor_sequence"), positive=True):
        return "FLOOR_NODE_COUNTER_INVALID"
    if not _integer(node.get("state_version"), positive=True):
        return "FLOOR_NODE_STATE_VERSION_INVALID"
    if not _validate_list(node.get("used_pass_digests")) or not _validate_list(node.get("used_observation_digests")):
        return "FLOOR_NODE_HISTORY_INVALID"
    return None


def _validate_transition(transition: Any) -> str | None:
    if not isinstance(transition, Mapping) or not _exact(transition, _FLOOR_TRANSITION_KEYS):
        return "FLOOR_TRANSITION_SCHEMA_NOT_EXACT"
    if transition.get("schema") != "s25q.external-floor-transition.v1" or transition.get("source") != "EXTERNAL_TEST_ONLY":
        return "FLOOR_TRANSITION_PROFILE_INVALID"
    if not _text(transition.get("observation_id")) or not _text(transition.get("idempotency_key")):
        return "FLOOR_TRANSITION_ID_INVALID"
    if not _hash(transition.get("transition_digest")):
        return "FLOOR_TRANSITION_DIGEST_INVALID"
    if transition.get("cas_status") not in {"WOULD_ADVANCE", "IDEMPOTENT_MATCH", "CONFLICT"}:
        return "FLOOR_TRANSITION_CAS_INVALID"
    before_error = _validate_floor_node(transition.get("before"))
    if before_error:
        return f"BEFORE_{before_error}"
    after_error = _validate_floor_node(transition.get("after"))
    if after_error:
        return f"AFTER_{after_error}"
    return None


def _validate_successor(index: Any) -> str | None:
    if not isinstance(index, Mapping) or not _exact(index, _SUCCESSOR_KEYS):
        return "SUCCESSOR_INDEX_SCHEMA_NOT_EXACT"
    if not _validate_hashes(index, ("parent_key", "candidate_key", "registry_head_digest")):
        return "SUCCESSOR_INDEX_DIGEST_INVALID"
    existing = index.get("existing_successor_pass_digest")
    if existing is not None and not _hash(existing):
        return "SUCCESSOR_EXISTING_DIGEST_INVALID"
    if not _integer(index.get("candidate_count"), positive=True):
        return "SUCCESSOR_COUNT_INVALID"
    candidates = index.get("candidate_pass_digests")
    keys = index.get("candidate_keys")
    if not isinstance(candidates, list) or not isinstance(keys, list) or len(candidates) != index["candidate_count"] or len(keys) != index["candidate_count"]:
        return "SUCCESSOR_CANDIDATE_LIST_INVALID"
    if not all(_hash(item) for item in candidates) or not all(_hash(item) for item in keys):
        return "SUCCESSOR_CANDIDATE_DIGEST_INVALID"
    if len(set(candidates)) != len(candidates) or len(set(keys)) != len(keys):
        return "SUCCESSOR_CANDIDATE_DUPLICATE"
    if index.get("lineage") not in {"SINGLE", "FORK", "MERGE"}:
        return "SUCCESSOR_LINEAGE_INVALID"
    if index.get("entry_status") not in {"ABSENT", "EXACT_MATCH", "CONFLICT", "MERGE_UNRESOLVED"}:
        return "SUCCESSOR_ENTRY_STATUS_INVALID"
    if not _integer(index.get("registry_state_version"), positive=True):
        return "SUCCESSOR_REGISTRY_VERSION_INVALID"
    return None


def _valid_s25o_report(report: Any) -> bool:
    if not isinstance(report, Mapping) or not _exact(report, _S25O_REPORT_KEYS):
        return False
    status = report.get("status")
    if status not in _STATUS_DECISIONS or report.get("decision") != _STATUS_DECISIONS[status]:
        return False
    if report.get("evidence_state") not in _S25O_EVIDENCE_STATES:
        return False
    if report.get("seal_status") not in {"SEALED_TEST_ONLY", "UNSEALED"}:
        return False
    if report.get("production_status") != PRODUCTION_NOT_AUTHORIZED or report.get("authority_claim") != NOT_CLAIMED:
        return False
    if any(report.get(field) is not False for field in ("capability_issued", "write_authorized", "mutation_allowed", "persistence_performed", "cas_attempted", "fence_issued", "resume_allowed")):
        return False
    if status == "LOCKED_TEST_PASS":
        return report["evidence_state"] == "COMPLETE" and report["seal_status"] == "SEALED_TEST_ONLY"
    if status == "PROPOSAL_ONLY":
        return report["evidence_state"] == "PROPOSED" and report["seal_status"] == "UNSEALED"
    return report["evidence_state"] in _S25O_FAIL_CLOSED_STATES


def _valid_s25o_case(precedence_case: Any) -> bool:
    if not isinstance(precedence_case, Mapping) or not _exact(
        precedence_case,
        frozenset({"schema_version", "observation_mode", "baseline", "candidate", "event", "canonicalization", "input_digest"}),
    ):
        return False
    if (
        precedence_case.get("schema_version") != "s25o.status-precedence.v1"
        or precedence_case.get("observation_mode") != "OBSERVE_ONLY"
        or precedence_case.get("canonicalization") != CANONICALIZATION
        or not _hash(precedence_case.get("input_digest"))
    ):
        return False
    try:
        if precedence_case["input_digest"] != _digest(
            {key: value for key, value in precedence_case.items() if key != "input_digest"}
        ):
            return False
    except (TypeError, ValueError, UnicodeError):
        return False
    baseline = precedence_case.get("baseline")
    candidate = precedence_case.get("candidate")
    event = precedence_case.get("event")
    if not _valid_s25o_report(baseline) or not _valid_s25o_report(candidate):
        return False
    if not isinstance(event, Mapping) or not _exact(event, _S25O_EVENT_KEYS):
        return False
    if (
        not isinstance(event.get("kind"), str)
        or not isinstance(event.get("field"), str)
        or event.get("field") not in _S25O_ALLOWED_EVENT_FIELDS
        or event.get("baseline_evidence_state") not in _S25O_EVIDENCE_STATES
        or event.get("candidate_evidence_state") not in _S25O_EVIDENCE_STATES
        or event.get("baseline_evidence_state") != baseline.get("evidence_state")
        or event.get("candidate_evidence_state") != candidate.get("evidence_state")
    ):
        return False
    if event["kind"] == "NO_CHANGE":
        return baseline == candidate and event["baseline_evidence_state"] == event["candidate_evidence_state"]
    if event["kind"] not in _S25O_EVENT_STATES:
        return False
    return event["candidate_evidence_state"] == _S25O_EVENT_STATES[event["kind"]]


def _valid_s25p_result(result: Any, s25p_case: Any) -> bool:
    if not isinstance(result, Mapping) or not _safe_value(result):
        return False
    keys = set(result)
    classification = result.get("classification")
    if keys == set(_S25P_CORE_KEYS | _S25P_OPTIONAL_KEYS):
        has_precedence_details = True
    elif keys == set(_S25P_CORE_KEYS):
        has_precedence_details = False
    else:
        return False
    if result.get("schema_version") != "s25p.fresh-revalidation.v1" or result.get("observation_mode") != "TEST_ONLY":
        return False
    status = result.get("status")
    if status not in _STATUS_DECISIONS or result.get("decision") != _STATUS_DECISIONS[status]:
        return False
    if classification not in _S25P_RESULT_CLASSIFICATIONS:
        return False
    if result.get("production_status") != PRODUCTION_NOT_AUTHORIZED or result.get("authority_claim") != NOT_CLAIMED:
        return False
    if result.get("assurance_rank") != _S25P_ASSURANCE_RANK[status] or not isinstance(result.get("reason"), str) or not result["reason"]:
        return False
    valid_statuses = set(_STATUS_DECISIONS) | {"UNKNOWN"}
    if result.get("baseline_status") not in valid_statuses or result.get("candidate_status") not in valid_statuses:
        return False
    if result.get("digest_status") not in {"MATCH", "MISMATCH", "NOT_CLAIMED"}:
        return False
    if result.get("freshness_status") not in {"FRESH", "MISMATCH", "NOT_CLAIMED"}:
        return False
    if result.get("sequence_status") not in {"NEXT", "ROLLBACK", "GAP", "EPOCH_CHANGED", "NOT_CLAIMED"}:
        return False
    if result.get("binding_status") not in {"MATCH", "MISMATCH", "NOT_CLAIMED"}:
        return False
    if result.get("replay_status") not in {"NEW", "REPLAY", "MISMATCH", "NOT_CLAIMED"}:
        return False
    if classification == "FRESH_REVALIDATION_ACCEPTED":
        if (
            not has_precedence_details
            or result.get("precedence_classification") not in {"NO_ESCALATION", "SAFE_NON_ESCALATING_DOWNGRADE"}
            or result.get("reason") != "FRESHNESS_BOUND_TO_S25O"
            or result.get("digest_status") != "MATCH"
            or result.get("freshness_status") != "FRESH"
            or result.get("sequence_status") != "NEXT"
            or result.get("binding_status") != "MATCH"
            or result.get("replay_status") != "NEW"
            or result.get("candidate_status") != status
        ):
            return False
        if result.get("precedence_digest_status") != "MATCH":
            return False
        expected_reason = {
            "NO_ESCALATION": "STATUS_UNCHANGED",
            "SAFE_NON_ESCALATING_DOWNGRADE": "STATUS_NON_ESCALATING",
        }[result["precedence_classification"]]
        if result.get("precedence_reason") != expected_reason:
            return False
        if not isinstance(s25p_case, Mapping) or not _valid_s25o_case(s25p_case.get("precedence_case")):
            return False
        precedence_case = s25p_case["precedence_case"]
        baseline = precedence_case.get("baseline")
        candidate = precedence_case.get("candidate")
        event = precedence_case.get("event")
        if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping) or not isinstance(event, Mapping):
            return False
        if result.get("baseline_status") != baseline.get("status") or result.get("candidate_status") != candidate.get("status"):
            return False
        if result["precedence_classification"] == "NO_ESCALATION":
            if event.get("kind") != "NO_CHANGE" or baseline != candidate:
                return False
        elif (
            event.get("kind") == "NO_CHANGE"
            or result.get("candidate_status") == "LOCKED_TEST_PASS"
            or _CLAIM_LEVEL.get(result.get("candidate_status"), -1) > _CLAIM_LEVEL.get(result.get("baseline_status"), -1)
        ):
            return False
    elif classification == "PRECEDENCE_REJECTED":
        if (
            not has_precedence_details
            or result.get("precedence_classification") not in {"INPUT_INVALID", "STATUS_ESCALATION_REJECTED"}
            or result.get("reason") != "S25O_PRECEDENCE_REJECTED"
            or result.get("digest_status") != "MATCH"
            or result.get("freshness_status") != "FRESH"
            or result.get("sequence_status") != "NEXT"
            or result.get("binding_status") != "MATCH"
            or result.get("replay_status") != "NEW"
        ):
            return False
        if result.get("precedence_classification") == "INPUT_INVALID":
            if status != TEST_BLOCKED or result.get("precedence_digest_status") != "NOT_CLAIMED":
                return False
        elif status != RECOVERY_REQUIRED or result.get("precedence_digest_status") != "MATCH":
            return False
    elif classification == "FRESHNESS_REJECTED":
        if status != RECOVERY_REQUIRED or result.get("decision") != MANUAL_REVIEW:
            return False
        if has_precedence_details:
            if (
                result.get("reason") != "STATUS_ESCALATION_AFTER_PRIOR_PASS"
                or result.get("precedence_classification") not in {"NO_ESCALATION", "SAFE_NON_ESCALATING_DOWNGRADE"}
                or result.get("precedence_digest_status") != "MATCH"
                or result.get("digest_status") != "MATCH"
                or result.get("freshness_status") != "FRESH"
                or result.get("sequence_status") != "NEXT"
                or result.get("binding_status") != "MATCH"
                or result.get("replay_status") != "NEW"
            ):
                return False
            expected_reason = {
                "NO_ESCALATION": "STATUS_UNCHANGED",
                "SAFE_NON_ESCALATING_DOWNGRADE": "STATUS_NON_ESCALATING",
            }[result["precedence_classification"]]
            if result.get("precedence_reason") != expected_reason:
                return False
        else:
            if result.get("reason") not in _S25P_FRESHNESS_REVIEW_REASONS - {"STATUS_ESCALATION_AFTER_PRIOR_PASS"}:
                return False
            expected_fields = {
                "PREVIOUS_PASS_ANCHOR_MISMATCH": ("NOT_CLAIMED", "NOT_CLAIMED", "MISMATCH", "NOT_CLAIMED", "NOT_CLAIMED"),
                "SUBJECT_BINDING_MISMATCH": ("NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "MISMATCH", "NOT_CLAIMED"),
                "SCOPE_BINDING_MISMATCH": ("NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "MISMATCH", "NOT_CLAIMED"),
                "BASELINE_DIGEST_MISMATCH": ("NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "MISMATCH", "NOT_CLAIMED"),
                "CURRENT_BASELINE_MISMATCH": ("NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "MISMATCH", "NOT_CLAIMED"),
                "REVALIDATION_DIGEST_REUSED": ("NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "REPLAY"),
                "REPLAY_FLOOR_SEQUENCE_MISMATCH": ("NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "MISMATCH"),
                "REVALIDATION_PASS_REPLAY": ("NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "REPLAY"),
                "OBSERVATION_EPOCH_ROLLBACK": ("NOT_CLAIMED", "ROLLBACK", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED"),
                "OBSERVATION_EPOCH_CHANGED": ("NOT_CLAIMED", "EPOCH_CHANGED", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED"),
                "OBSERVATION_SEQUENCE_ROLLBACK": ("NOT_CLAIMED", "ROLLBACK", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED"),
                "OBSERVATION_SEQUENCE_GAP": ("NOT_CLAIMED", "GAP", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED"),
            }[result["reason"]]
            if (
                result.get("digest_status"),
                result.get("sequence_status"),
                result.get("freshness_status"),
                result.get("binding_status"),
                result.get("replay_status"),
            ) != expected_fields:
                return False
    elif classification in {"FRESHNESS_BLOCKED", "INPUT_INVALID"}:
        if has_precedence_details or status != TEST_BLOCKED:
            return False
        if result.get("baseline_status") != "UNKNOWN" or result.get("candidate_status") != "UNKNOWN":
            return False
        if classification == "INPUT_INVALID":
            if result.get("digest_status") != "NOT_CLAIMED" or result.get("freshness_status") != "NOT_CLAIMED" or result.get("sequence_status") != "NOT_CLAIMED" or result.get("binding_status") != "NOT_CLAIMED" or result.get("replay_status") != "NOT_CLAIMED":
                return False
        else:
            if result.get("reason") not in _S25P_FRESHNESS_BLOCKED_REASONS:
                return False
            expected_fields = {
                "FRESHNESS_ANCHOR_MISMATCH": ("NOT_CLAIMED", "NOT_CLAIMED", "MISMATCH", "NOT_CLAIMED", "NOT_CLAIMED"),
                "CANDIDATE_DIGEST_DRIFT": ("MISMATCH", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED"),
                "EVIDENCE_DIGEST_DRIFT": ("MISMATCH", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED"),
            }.get(result["reason"], ("NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED", "NOT_CLAIMED"))
            if (
                result.get("digest_status"),
                result.get("sequence_status"),
                result.get("freshness_status"),
                result.get("binding_status"),
                result.get("replay_status"),
            ) != expected_fields:
                return False
    return all(
        result.get(field) is False
        for field in (
            "capability_issued",
            "write_authorized",
            "mutation_allowed",
            "persistence_performed",
            "cas_attempted",
            "fence_issued",
            "resume_allowed",
        )
    )


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
    if case.get("canonicalization") != CANONICALIZATION:
        return _invalid("CASE_CANONICALIZATION_INVALID")
    if not _hash(case.get("input_digest")):
        return _invalid("CASE_DIGEST_INVALID")
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
        (_validate_previous, previous),
        (_validate_current, current),
        (_validate_transition, transition),
        (_validate_successor, index),
    ):
        error = validator(value)
        if error:
            return _blocked(error)

    if (
        expected["subject_digest"] != previous["subject_digest"]
        or expected["scope_digest"] != previous["scope_digest"]
        or expected["baseline_digest"] != previous["baseline_digest"]
        or expected["epoch"] != previous["epoch"]
        or expected["predecessor_sequence"] != previous["observation_sequence"]
        or expected["predecessor_pass_digest"] != previous["pass_digest"]
        or expected["subject_digest"] != current["subject_digest"]
        or expected["scope_digest"] != current["scope_digest"]
        or expected["baseline_digest"] != current["baseline_digest"]
        or expected["epoch"] != current["epoch"]
        or expected["successor_sequence"] != current["observation_sequence"]
        or expected["successor_pass_digest"] != current["pass_digest"]
        or expected["current_case_digest"] != current["s25p_case"]["input_digest"]
    ):
        return _review("EXPECTED_BINDING_MISMATCH", binding_status="MISMATCH")
    if current["previous_pass_digest"] != previous["pass_digest"]:
        return _review("PARENT_PASS_MISMATCH", binding_status="MISMATCH")
    if current["observation_digest"] != _observation_digest(current):
        return _blocked("CURRENT_OBSERVATION_DIGEST_DRIFT")

    before = transition["before"]
    after = transition["after"]
    for node in (before, after):
        if (
            node["subject_digest"] != expected["subject_digest"]
            or node["scope_digest"] != expected["scope_digest"]
            or node["baseline_digest"] != expected["baseline_digest"]
            or node["epoch"] != expected["epoch"]
        ):
            return _review("FLOOR_IDENTITY_MISMATCH", binding_status="MISMATCH")
    if (
        before["floor_sequence"] != previous["observation_sequence"]
        or before["floor_pass_digest"] != previous["pass_digest"]
        or before["state_version"] != expected["floor_before_state_version"]
        or before["head_digest"] != expected["floor_before_head_digest"]
        or before["used_pass_digests"][-1] != previous["pass_digest"]
        or before["used_observation_digests"][-1] != previous["observation_digest"]
    ):
        return _review("FLOOR_BEFORE_MISMATCH", floor_status="MISMATCH")
    if index["registry_state_version"] != before["state_version"] or index["registry_head_digest"] != before["head_digest"]:
        return _review("SUCCESSOR_REGISTRY_HEAD_MISMATCH", floor_status="MISMATCH")
    parent_key = _parent_key(previous)
    candidate_key = _candidate_key(parent_key, current)
    if index["parent_key"] != parent_key or index["candidate_key"] != candidate_key:
        return _review("SUCCESSOR_KEY_MISMATCH", binding_status="MISMATCH")
    if current["pass_digest"] != _pass_digest(current, current["s25p_result_digest"]):
        return _blocked("CURRENT_PASS_DIGEST_DRIFT")
    if current["observation_digest"] != _observation_digest(current):
        return _blocked("CURRENT_OBSERVATION_DIGEST_DRIFT")

    try:
        raw_s25p_result = evaluate_fresh_revalidation(current["s25p_case"])
        s25p_result = _snapshot(raw_s25p_result)
    except Exception:
        return _blocked("S25P_CASE_UNREADABLE")
    if not _valid_s25p_result(s25p_result, current["s25p_case"]):
        return _blocked("S25P_RESULT_INVALID")
    if current["s25p_result_digest"] != _digest(s25p_result):
        return _blocked("S25P_RESULT_DIGEST_DRIFT")
    if current["status"] != s25p_result["status"] or current["decision"] != s25p_result["decision"]:
        return _review("S25P_STATUS_BINDING_MISMATCH", binding_status="MISMATCH")
    nested_current = current["s25p_case"].get("current")
    if not isinstance(nested_current, Mapping) or (
        current["subject_digest"] != nested_current.get("subject_digest")
        or current["scope_digest"] != nested_current.get("scope_digest")
        or current["baseline_digest"] != nested_current.get("baseline_digest")
        or current["epoch"] != nested_current.get("observation_epoch")
        or current["observation_sequence"] != nested_current.get("observation_sequence")
        or current["candidate_digest"] != nested_current.get("candidate_digest")
        or current["evidence_digest"] != nested_current.get("evidence_digest")
    ):
        return _review("S25P_CASE_BINDING_MISMATCH", binding_status="MISMATCH")
    if _CLAIM_LEVEL[current["status"]] > _CLAIM_LEVEL[previous["status"]]:
        return _review("STATUS_ESCALATION_AFTER_PREVIOUS_PASS", s25p_result=s25p_result, binding_status="MATCH")
    if s25p_result["status"] in {TEST_BLOCKED, RECOVERY_REQUIRED}:
        return _output(
            S25P_REJECTED,
            s25p_result["status"],
            s25p_result["decision"],
            "S25P_RESULT_NOT_ACCEPTABLE",
            s25p_result=s25p_result,
            sequence_status="NEXT",
            floor_status="NOT_ADVANCED",
            binding_status="MATCH",
            replay_status="NEW",
        )

    if index["lineage"] != "SINGLE" or index["entry_status"] in {"CONFLICT", "MERGE_UNRESOLVED"} or transition["cas_status"] == "CONFLICT":
        return _review("FORK_OR_MERGE_CONFLICT", classification=FORK_CONFLICT, s25p_result=s25p_result, sequence_status="NEXT", floor_status="NOT_ADVANCED", binding_status="MATCH", replay_status="CONFLICT")
    if index["candidate_count"] != 1 or index["candidate_pass_digests"] != [current["pass_digest"]] or index["candidate_keys"] != [candidate_key]:
        return _review("SUCCESSOR_CANDIDATE_SET_INVALID", s25p_result=s25p_result, sequence_status="NEXT", floor_status="NOT_ADVANCED", binding_status="MATCH", replay_status="CONFLICT")

    if index["entry_status"] == "EXACT_MATCH":
        if (
            index["existing_successor_pass_digest"] != current["pass_digest"]
            or transition["cas_status"] != "IDEMPOTENT_MATCH"
            or after != before
        ):
            return _review("IDEMPOTENT_ENTRY_INCONSISTENT", s25p_result=s25p_result, sequence_status="NEXT", floor_status="MISMATCH", binding_status="MATCH", replay_status="REPLAY")
        return _blocked("FLOOR_IDEMPOTENT_REPLAY", s25p_result=s25p_result, sequence_status="NEXT", floor_status="UNCHANGED", binding_status="MATCH", replay_status="REPLAY")

    if index["entry_status"] != "ABSENT" or transition["cas_status"] != "WOULD_ADVANCE":
        return _review("SUCCESSOR_ENTRY_NOT_ABSENT", s25p_result=s25p_result, sequence_status="NEXT", floor_status="MISMATCH", binding_status="MATCH", replay_status="CONFLICT")
    if current["pass_digest"] in before["used_pass_digests"] or current["observation_digest"] in before["used_observation_digests"]:
        return _review("SUCCESSOR_REPLAY", s25p_result=s25p_result, sequence_status="NEXT", floor_status="REPLAY", binding_status="MATCH", replay_status="REPLAY")
    if current["observation_sequence"] != previous["observation_sequence"] + 1:
        return _review("SUCCESSOR_SEQUENCE_NOT_NEXT", s25p_result=s25p_result, sequence_status="GAP_OR_ROLLBACK", floor_status="MISMATCH", binding_status="MATCH", replay_status="NEW")
    if after["floor_sequence"] != current["observation_sequence"] or after["floor_pass_digest"] != current["pass_digest"]:
        return _review("FLOOR_AFTER_NOT_SUCCESSOR", s25p_result=s25p_result, sequence_status="NEXT", floor_status="MISMATCH", binding_status="MATCH", replay_status="NEW")
    if after["state_version"] != before["state_version"] + 1:
        return _review("FLOOR_STATE_VERSION_NOT_MONOTONE", s25p_result=s25p_result, sequence_status="NEXT", floor_status="MISMATCH", binding_status="MATCH", replay_status="NEW")
    if after["used_pass_digests"] != before["used_pass_digests"] + [current["pass_digest"]] or after["used_observation_digests"] != before["used_observation_digests"] + [current["observation_digest"]]:
        return _review("FLOOR_HISTORY_NOT_APPEND_ONLY", s25p_result=s25p_result, sequence_status="NEXT", floor_status="MISMATCH", binding_status="MATCH", replay_status="NEW")
    if after["successor_index_digest"] != _digest(index):
        return _review("SUCCESSOR_INDEX_DIGEST_MISMATCH", s25p_result=s25p_result, sequence_status="NEXT", floor_status="MISMATCH", binding_status="MATCH", replay_status="NEW")
    if transition["transition_digest"] != _transition_digest(transition):
        return _blocked("FLOOR_TRANSITION_DIGEST_DRIFT")
    expected_head = _digest({"before_head_digest": before["head_digest"], "transition_digest": transition["transition_digest"]})
    if after["head_digest"] != expected_head:
        return _review("FLOOR_HEAD_NOT_DERIVED", s25p_result=s25p_result, sequence_status="NEXT", floor_status="MISMATCH", binding_status="MATCH", replay_status="NEW")
    return _output(
        FLOOR_ADVANCE_ELIGIBLE,
        current["status"],
        current["decision"],
        "FLOOR_ADVANCE_PROPOSAL_ONLY",
        s25p_result=s25p_result,
        sequence_status="NEXT",
        floor_status="PROPOSED",
        binding_status="MATCH",
        replay_status="NEW",
    )


def evaluate_replay_floor_fork(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Fail closed for hostile mappings, parser failures and deep values."""

    try:
        return _evaluate(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


__all__ = [
    "CANONICALIZATION",
    "FLOOR_ADVANCE_ELIGIBLE",
    "FLOOR_IDEMPOTENT_REPLAY",
    "FORK_CONFLICT",
    "HARNESS_SCHEMA",
    "RECOVERY_REQUIRED",
    "TEST_BLOCKED",
    "evaluate_replay_floor_fork",
    "input_digest",
]
