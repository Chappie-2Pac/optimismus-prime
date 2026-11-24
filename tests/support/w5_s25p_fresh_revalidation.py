"""Pure S25P freshness gate delegating status precedence to S25O."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from support.w5_s25o_status_precedence import evaluate_status_precedence
except ImportError:  # pragma: no cover - direct support-module execution
    from w5_s25o_status_precedence import evaluate_status_precedence


HARNESS_SCHEMA = "s25p.fresh-revalidation.v1"
CANONICALIZATION = "s25m-canonical-json-v1"
TEST_ONLY = "TEST_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
HOLD = "HOLD"
MANUAL_REVIEW = "MANUAL_REVIEW"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

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
        "expected",
        "current",
        "previous",
        "precedence_case",
        "freshness_anchor",
        "replay_guard",
        "canonicalization",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset({"subject_digest", "scope_digest", "baseline_digest", "previous_pass_digest"})
_CURRENT_KEYS = frozenset(
    {
        "subject_digest",
        "scope_digest",
        "observation_epoch",
        "observation_sequence",
        "snapshot_state",
        "revalidation_performed",
        "baseline_digest",
        "candidate_digest",
        "evidence_digest",
    }
)
_PREVIOUS_KEYS = frozenset(
    {
        "subject_digest",
        "scope_digest",
        "observation_epoch",
        "observation_sequence",
        "status",
        "baseline_digest",
        "candidate_digest",
        "evidence_digest",
        "pass_digest",
    }
)
_ANCHOR_KEYS = frozenset(
    {
        "source",
        "snapshot_state",
        "revalidation_performed",
        "observation_epoch",
        "observation_sequence",
        "anchor_digest",
    }
)
_REPLAY_KEYS = frozenset({"schema", "floor_sequence", "used_pass_digests"})
_VALID_PRECEDENCE_CLASSIFICATIONS = frozenset(
    {"NO_ESCALATION", "SAFE_NON_ESCALATING_DOWNGRADE", "INPUT_INVALID", "STATUS_ESCALATION_REJECTED"}
)
_PRECEDENCE_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "baseline_status",
        "candidate_status",
        "degradation",
        "digest_status",
        "assurance_rank",
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
_STATUS_DECISIONS = {
    "LOCKED_TEST_PASS": "TEST_ONLY_PASS",
    "PROPOSAL_ONLY": "DESIGN_ONLY",
    "TEST_BLOCKED": "HOLD",
    "RECOVERY_REQUIRED": "MANUAL_REVIEW",
}
_CLAIM_LEVEL = {"LOCKED_TEST_PASS": 3, "PROPOSAL_ONLY": 2, "TEST_BLOCKED": 1, "RECOVERY_REQUIRED": 1}
_ASSURANCE_RANK = {"LOCKED_TEST_PASS": 2, "PROPOSAL_ONLY": 1, "TEST_BLOCKED": 0, "RECOVERY_REQUIRED": 0}


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


def _parse(value: Mapping[str, Any] | bytes | str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, (bytes, str)):
        raw = value.decode("utf-8") if isinstance(value, bytes) else value
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
        if isinstance(parsed, Mapping):
            return parsed
    raise TypeError("fresh revalidation case must be a mapping or JSON object")


def _canonical_json(value: Any) -> bytes:
    if not _safe_value(value):
        raise ValueError("fresh revalidation case contains unsafe value")
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def input_digest(case: Mapping[str, Any]) -> str:
    try:
        if not isinstance(case, Mapping):
            raise TypeError("fresh revalidation case must be a mapping")
        unsigned = {key: value for key, value in case.items() if key != "input_digest"}
        return hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    except Exception:
        raise ValueError("fresh revalidation case cannot be canonicalized") from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _report_digest(report: Mapping[str, Any]) -> str:
    return _digest(report)


def _candidate_digest(
    subject_digest: str,
    scope_digest: str,
    baseline_digest: str,
    report: Mapping[str, Any],
    epoch: int,
    sequence: int,
) -> str:
    return _digest(
        {
            "subject_digest": subject_digest,
            "scope_digest": scope_digest,
            "baseline_digest": baseline_digest,
            "report": report,
            "observation_epoch": epoch,
            "observation_sequence": sequence,
        }
    )


def _evidence_digest(
    subject_digest: str,
    scope_digest: str,
    precedence_case: Mapping[str, Any],
) -> str:
    return _digest(
        {
            "subject_digest": subject_digest,
            "scope_digest": scope_digest,
            "precedence_digest": precedence_case["input_digest"],
            "baseline_report": precedence_case["baseline"],
            "candidate_report": precedence_case["candidate"],
            "event": precedence_case["event"],
        }
    )


def _previous_pass_digest(previous: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in previous.items() if key != "pass_digest"}
    return _digest(unsigned)


def _freshness_anchor_digest(
    expected: Mapping[str, Any],
    current: Mapping[str, Any],
    precedence_case: Mapping[str, Any],
) -> str:
    return _digest(
        {
            "subject_digest": expected["subject_digest"],
            "scope_digest": expected["scope_digest"],
            "baseline_digest": expected["baseline_digest"],
            "snapshot_state": current["snapshot_state"],
            "revalidation_performed": current["revalidation_performed"],
            "observation_epoch": current["observation_epoch"],
            "observation_sequence": current["observation_sequence"],
            "precedence_digest": precedence_case["input_digest"],
        }
    )


def _revalidation_pass_digest(case: Mapping[str, Any]) -> str:
    return _digest(
        {
            "schema_version": case["schema_version"],
            "observation_mode": case["observation_mode"],
            "expected": case["expected"],
            "current": case["current"],
            "previous": case["previous"],
            "precedence_digest": case["precedence_case"]["input_digest"],
            "freshness_anchor": case["freshness_anchor"],
        }
    )


def _output(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    baseline_status: str = "UNKNOWN",
    candidate_status: str = "UNKNOWN",
    digest_status: str = "NOT_CLAIMED",
    freshness_status: str = "NOT_CLAIMED",
    sequence_status: str = "NOT_CLAIMED",
    binding_status: str = "NOT_CLAIMED",
    replay_status: str = "NOT_CLAIMED",
    precedence_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": TEST_ONLY,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "baseline_status": baseline_status,
        "candidate_status": candidate_status,
        "digest_status": digest_status,
        "freshness_status": freshness_status,
        "sequence_status": sequence_status,
        "binding_status": binding_status,
        "replay_status": replay_status,
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
    if precedence_result is not None:
        result["precedence_classification"] = precedence_result.get("classification", "UNKNOWN")
        result["precedence_reason"] = precedence_result.get("reason", "UNKNOWN")
        result["precedence_digest_status"] = precedence_result.get("digest_status", "NOT_CLAIMED")
        result["assurance_rank"] = precedence_result.get("assurance_rank", 0)
    else:
        result["assurance_rank"] = 0
    return result


def _invalid(reason: str, **kwargs: str) -> dict[str, Any]:
    return _output("INPUT_INVALID", TEST_BLOCKED, HOLD, reason, **kwargs)


def _review(reason: str, **kwargs: str) -> dict[str, Any]:
    return _output("FRESHNESS_REJECTED", RECOVERY_REQUIRED, MANUAL_REVIEW, reason, **kwargs)


def _blocked(reason: str, **kwargs: str) -> dict[str, Any]:
    return _output("FRESHNESS_BLOCKED", TEST_BLOCKED, HOLD, reason, **kwargs)


def _validate_hash_fields(mapping: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    return all(_hash(mapping.get(field)) for field in fields)


def _validate_metadata(case: Mapping[str, Any]) -> str | None:
    expected = case.get("expected")
    current = case.get("current")
    previous = case.get("previous")
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    if not isinstance(current, Mapping) or not _exact(current, _CURRENT_KEYS):
        return "CURRENT_SCHEMA_NOT_EXACT"
    if not isinstance(previous, Mapping) or not _exact(previous, _PREVIOUS_KEYS):
        return "PREVIOUS_SCHEMA_NOT_EXACT"
    if not _validate_hash_fields(expected, ("subject_digest", "scope_digest", "baseline_digest", "previous_pass_digest")):
        return "EXPECTED_DIGEST_INVALID"
    if not _validate_hash_fields(current, ("subject_digest", "scope_digest", "baseline_digest", "candidate_digest", "evidence_digest")):
        return "CURRENT_DIGEST_INVALID"
    if not _validate_hash_fields(previous, ("subject_digest", "scope_digest", "baseline_digest", "candidate_digest", "evidence_digest", "pass_digest")):
        return "PREVIOUS_DIGEST_INVALID"
    if previous.get("status") not in _STATUS_DECISIONS:
        return "PREVIOUS_STATUS_INVALID"
    if not _integer(current.get("observation_epoch"), positive=True) or not _integer(current.get("observation_sequence"), positive=True):
        return "CURRENT_COUNTER_INVALID"
    if not _integer(previous.get("observation_epoch"), positive=True) or not _integer(previous.get("observation_sequence"), positive=True):
        return "PREVIOUS_COUNTER_INVALID"
    if current.get("snapshot_state") != "CURRENT" or current.get("revalidation_performed") is not True:
        return "CURRENT_SNAPSHOT_NOT_FRESH"
    return None


def _validate_anchor(anchor: Any) -> str | None:
    if not isinstance(anchor, Mapping) or not _exact(anchor, _ANCHOR_KEYS):
        return "FRESHNESS_ANCHOR_SCHEMA_NOT_EXACT"
    if anchor.get("source") != "EXTERNAL_TEST_ONLY":
        return "FRESHNESS_ANCHOR_SOURCE_INVALID"
    if anchor.get("snapshot_state") != "CURRENT" or anchor.get("revalidation_performed") is not True:
        return "FRESHNESS_ANCHOR_NOT_CURRENT"
    if not _integer(anchor.get("observation_epoch"), positive=True) or not _integer(anchor.get("observation_sequence"), positive=True):
        return "FRESHNESS_ANCHOR_COUNTER_INVALID"
    if not _hash(anchor.get("anchor_digest")):
        return "FRESHNESS_ANCHOR_DIGEST_INVALID"
    return None


def _validate_replay_guard(guard: Any) -> str | None:
    if not isinstance(guard, Mapping) or not _exact(guard, _REPLAY_KEYS):
        return "REPLAY_GUARD_SCHEMA_NOT_EXACT"
    if guard.get("schema") != "s25p.external-replay-floor.v1":
        return "REPLAY_GUARD_SCHEMA_INVALID"
    if not _integer(guard.get("floor_sequence"), positive=True):
        return "REPLAY_GUARD_SEQUENCE_INVALID"
    used = guard.get("used_pass_digests")
    if not isinstance(used, list) or not used or not all(_hash(value) for value in used):
        return "REPLAY_GUARD_LIST_INVALID"
    if len(set(used)) != len(used):
        return "REPLAY_GUARD_DUPLICATE_DIGEST"
    return None


def _valid_precedence_result(result: Any, precedence_case: Mapping[str, Any]) -> bool:
    if not isinstance(result, Mapping):
        return False
    if not _safe_value(result) or not _exact(result, _PRECEDENCE_RESULT_KEYS):
        return False
    if result.get("schema_version") != "s25o.status-precedence.v1" or result.get("observation_mode") != "OBSERVE_ONLY":
        return False
    classification = result.get("classification")
    status = result.get("status")
    if classification not in _VALID_PRECEDENCE_CLASSIFICATIONS or status not in _STATUS_DECISIONS:
        return False
    if result.get("decision") != _STATUS_DECISIONS[status]:
        return False
    if result.get("production_status") != PRODUCTION_NOT_AUTHORIZED or result.get("authority_claim") != NOT_CLAIMED:
        return False
    if result.get("assurance_rank") != _ASSURANCE_RANK[status]:
        return False
    if not all(
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
    ):
        return False
    classification = result["classification"]
    if classification == "INPUT_INVALID":
        return result.get("digest_status") == "NOT_CLAIMED" and status == "TEST_BLOCKED" and result["decision"] == "HOLD"
    baseline = precedence_case.get("baseline")
    candidate = precedence_case.get("candidate")
    event = precedence_case.get("event")
    if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping) or not isinstance(event, Mapping):
        return False
    if result.get("baseline_status") != baseline.get("status") or result.get("candidate_status") != candidate.get("status"):
        return False
    if result.get("digest_status") != "MATCH":
        return False
    if classification == "NO_ESCALATION":
        return (
            event.get("kind") == "NO_CHANGE"
            and baseline == candidate
            and result.get("degradation") == "NO_CHANGE"
            and status == candidate.get("status")
            and result.get("decision") == candidate.get("decision")
        )
    if classification == "SAFE_NON_ESCALATING_DOWNGRADE":
        return (
            event.get("kind") != "NO_CHANGE"
            and result.get("degradation") == event.get("kind")
            and candidate.get("status") != "LOCKED_TEST_PASS"
            and _CLAIM_LEVEL.get(candidate.get("status"), -1) <= _CLAIM_LEVEL.get(baseline.get("status"), -1)
            and not (
                event.get("kind") in {"EVIDENCE_STALE", "EVIDENCE_DRIFT"}
                and candidate.get("status") not in {"TEST_BLOCKED", "RECOVERY_REQUIRED"}
            )
            and not (
                event.get("kind") == "EVIDENCE_MALFORMED"
                and candidate.get("status") != "TEST_BLOCKED"
            )
            and status == candidate.get("status")
            and result.get("decision") == candidate.get("decision")
        )
    if classification == "STATUS_ESCALATION_REJECTED":
        return (
            event.get("kind") != "NO_CHANGE"
            and result.get("degradation") == event.get("kind")
            and status == "RECOVERY_REQUIRED"
            and result.get("decision") == "MANUAL_REVIEW"
        )
    return False


def _evaluate_fresh_revalidation(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
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

    metadata_error = _validate_metadata(case)
    if metadata_error:
        return _blocked(metadata_error)
    expected = case["expected"]
    current = case["current"]
    previous = case["previous"]
    anchor_error = _validate_anchor(case.get("freshness_anchor"))
    if anchor_error:
        return _blocked(anchor_error)
    replay_error = _validate_replay_guard(case.get("replay_guard"))
    if replay_error:
        return _blocked(replay_error)
    precedence_case = case.get("precedence_case")
    if not isinstance(precedence_case, Mapping):
        return _blocked("PRECEDENCE_CASE_NOT_MAPPING")
    try:
        precedence_result = evaluate_status_precedence(precedence_case)
    except Exception:
        return _blocked("PRECEDENCE_CASE_UNREADABLE")

    baseline_report = precedence_case.get("baseline")
    candidate_report = precedence_case.get("candidate")
    if not isinstance(baseline_report, Mapping) or not isinstance(candidate_report, Mapping):
        return _blocked("PRECEDENCE_REPORTS_NOT_MAPPING")
    if not _hash(precedence_case.get("input_digest")):
        return _blocked("PRECEDENCE_DIGEST_INVALID")
    try:
        computed_baseline_digest = _report_digest(baseline_report)
        computed_candidate_digest = _candidate_digest(
            current["subject_digest"],
            current["scope_digest"],
            computed_baseline_digest,
            candidate_report,
            current["observation_epoch"],
            current["observation_sequence"],
        )
        computed_evidence_digest = _evidence_digest(
            current["subject_digest"],
            current["scope_digest"],
            precedence_case,
        )
        computed_previous_pass = _previous_pass_digest(previous)
        computed_anchor = _freshness_anchor_digest(expected, current, precedence_case)
        computed_pass = _revalidation_pass_digest(case)
    except (TypeError, ValueError, UnicodeError):
        return _blocked("DERIVED_DIGEST_NOT_CANONICAL")

    if previous["pass_digest"] != computed_previous_pass or expected["previous_pass_digest"] != computed_previous_pass:
        return _review("PREVIOUS_PASS_ANCHOR_MISMATCH", binding_status="MISMATCH")
    anchor = case["freshness_anchor"]
    if (
        anchor["snapshot_state"] != current["snapshot_state"]
        or anchor["revalidation_performed"] is not current["revalidation_performed"]
        or anchor["observation_epoch"] != current["observation_epoch"]
        or anchor["observation_sequence"] != current["observation_sequence"]
        or anchor["anchor_digest"] != computed_anchor
    ):
        return _blocked("FRESHNESS_ANCHOR_MISMATCH", freshness_status="MISMATCH")
    if expected["subject_digest"] != current["subject_digest"] or expected["subject_digest"] != previous["subject_digest"]:
        return _review("SUBJECT_BINDING_MISMATCH", binding_status="MISMATCH")
    if expected["scope_digest"] != current["scope_digest"] or expected["scope_digest"] != previous["scope_digest"]:
        return _review("SCOPE_BINDING_MISMATCH", binding_status="MISMATCH")
    if expected["baseline_digest"] != computed_baseline_digest:
        return _review("BASELINE_DIGEST_MISMATCH", binding_status="MISMATCH")
    if current["baseline_digest"] != expected["baseline_digest"] or previous["baseline_digest"] != expected["baseline_digest"]:
        return _review("CURRENT_BASELINE_MISMATCH", binding_status="MISMATCH")
    if current["candidate_digest"] != computed_candidate_digest:
        return _blocked("CANDIDATE_DIGEST_DRIFT", digest_status="MISMATCH")
    if current["evidence_digest"] != computed_evidence_digest:
        return _blocked("EVIDENCE_DIGEST_DRIFT", digest_status="MISMATCH")
    if current["candidate_digest"] == previous["candidate_digest"] or current["evidence_digest"] == previous["evidence_digest"]:
        return _review("REVALIDATION_DIGEST_REUSED", replay_status="REPLAY")
    replay_guard = case["replay_guard"]
    if replay_guard["floor_sequence"] != previous["observation_sequence"]:
        return _review("REPLAY_FLOOR_SEQUENCE_MISMATCH", replay_status="MISMATCH")
    if computed_pass in replay_guard["used_pass_digests"]:
        return _review("REVALIDATION_PASS_REPLAY", replay_status="REPLAY")
    if current["observation_epoch"] < previous["observation_epoch"]:
        return _review("OBSERVATION_EPOCH_ROLLBACK", sequence_status="ROLLBACK")
    if current["observation_epoch"] != previous["observation_epoch"]:
        return _review("OBSERVATION_EPOCH_CHANGED", sequence_status="EPOCH_CHANGED")
    if current["observation_sequence"] <= previous["observation_sequence"]:
        return _review("OBSERVATION_SEQUENCE_ROLLBACK", sequence_status="ROLLBACK")
    if current["observation_sequence"] != previous["observation_sequence"] + 1:
        return _review("OBSERVATION_SEQUENCE_GAP", sequence_status="GAP")

    precedence_status = precedence_result.get("status", TEST_BLOCKED)
    precedence_decision = precedence_result.get("decision", HOLD)
    if not _valid_precedence_result(precedence_result, precedence_case):
        return _blocked("PRECEDENCE_RESULT_INVALID")
    if _CLAIM_LEVEL.get(precedence_status, -1) > _CLAIM_LEVEL.get(previous["status"], -1):
        return _output(
            "FRESHNESS_REJECTED",
            RECOVERY_REQUIRED,
            MANUAL_REVIEW,
            "STATUS_ESCALATION_AFTER_PRIOR_PASS",
            baseline_status=precedence_result.get("baseline_status", "UNKNOWN"),
            candidate_status=precedence_result.get("candidate_status", "UNKNOWN"),
            digest_status="MATCH",
            freshness_status="FRESH",
            sequence_status="NEXT",
            binding_status="MATCH",
            replay_status="NEW",
            precedence_result=precedence_result,
        )
    if precedence_result.get("classification") in {"INPUT_INVALID", "STATUS_ESCALATION_REJECTED"}:
        return _output(
            "PRECEDENCE_REJECTED",
            precedence_status if precedence_status in {TEST_BLOCKED, RECOVERY_REQUIRED} else TEST_BLOCKED,
            precedence_decision if precedence_decision in {HOLD, MANUAL_REVIEW} else HOLD,
            "S25O_PRECEDENCE_REJECTED",
            baseline_status=precedence_result.get("baseline_status", "UNKNOWN"),
            candidate_status=precedence_result.get("candidate_status", "UNKNOWN"),
            digest_status="MATCH",
            freshness_status="FRESH",
            sequence_status="NEXT",
            binding_status="MATCH",
            replay_status="NEW",
            precedence_result=precedence_result,
        )
    return _output(
        "FRESH_REVALIDATION_ACCEPTED",
        precedence_status if precedence_status in {"LOCKED_TEST_PASS", "PROPOSAL_ONLY", TEST_BLOCKED, RECOVERY_REQUIRED} else TEST_BLOCKED,
        precedence_decision if precedence_decision in {"TEST_ONLY_PASS", "DESIGN_ONLY", HOLD, MANUAL_REVIEW} else HOLD,
        "FRESHNESS_BOUND_TO_S25O",
        baseline_status=precedence_result.get("baseline_status", "UNKNOWN"),
        candidate_status=precedence_result.get("candidate_status", "UNKNOWN"),
        digest_status="MATCH",
        freshness_status="FRESH",
        sequence_status="NEXT",
        binding_status="MATCH",
        replay_status="NEW",
        precedence_result=precedence_result,
    )


def evaluate_fresh_revalidation(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Fail closed for hostile mappings, recursion and parser failures."""

    try:
        return _evaluate_fresh_revalidation(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


__all__ = [
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "TEST_BLOCKED",
    "RECOVERY_REQUIRED",
    "evaluate_fresh_revalidation",
    "input_digest",
]
