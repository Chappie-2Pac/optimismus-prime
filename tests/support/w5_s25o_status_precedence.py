"""Pure S25O status-precedence checks for negative evidence transitions."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


HARNESS_SCHEMA = "s25o.status-precedence.v1"
CANONICALIZATION = "s25m-canonical-json-v1"
LOCKED_TEST_PASS = "LOCKED_TEST_PASS"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"
DESIGN_ONLY = "DESIGN_ONLY"
HOLD = "HOLD"
MANUAL_REVIEW = "MANUAL_REVIEW"

_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "baseline",
        "candidate",
        "event",
        "canonicalization",
        "input_digest",
    }
)
_REPORT_KEYS = frozenset(
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
_EVENT_KEYS = frozenset({"kind", "field", "baseline_evidence_state", "candidate_evidence_state"})
_EVENT_STATES = {
    "EVIDENCE_REMOVED": "MISSING",
    "EVIDENCE_DOWNGRADED": "PROPOSED",
    "EVIDENCE_UNKNOWN": "UNKNOWN",
    "EVIDENCE_STALE": "STALE",
    "EVIDENCE_DRIFT": "DRIFT",
    "EVIDENCE_MALFORMED": "MALFORMED",
}
_ALLOWED_EVENT_FIELDS = frozenset(
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
_EVIDENCE_STATES = frozenset(
    {"COMPLETE", "PROPOSED", "MISSING", "UNKNOWN", "STALE", "DRIFT", "MALFORMED"}
)
_STATUS_DECISIONS = {
    LOCKED_TEST_PASS: "TEST_ONLY_PASS",
    PROPOSAL_ONLY: DESIGN_ONLY,
    TEST_BLOCKED: HOLD,
    RECOVERY_REQUIRED: MANUAL_REVIEW,
}
_CLAIM_LEVEL = {LOCKED_TEST_PASS: 3, PROPOSAL_ONLY: 2, TEST_BLOCKED: 1, RECOVERY_REQUIRED: 1}
_ASSURANCE_RANK = {LOCKED_TEST_PASS: 2, PROPOSAL_ONLY: 1, TEST_BLOCKED: 0, RECOVERY_REQUIRED: 0}
_FAIL_CLOSED_STATES = frozenset({"MISSING", "UNKNOWN", "STALE", "DRIFT", "MALFORMED"})


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


def _safe_value(value: Any) -> bool:
    if value is None or isinstance(value, (bool, int, str)):
        if not isinstance(value, str):
            return True
        normalized = value.lstrip().lower()
        if (
            _ABSOLUTE_PATH.match(value.lstrip()) is not None
            or _URI_SCHEME.match(normalized) is not None
            or value.lstrip().startswith("\\\\")
        ):
            return False
        return not any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    if isinstance(value, float):
        return False
    if isinstance(value, list):
        return all(_safe_value(item) for item in value)
    if isinstance(value, Mapping):
        return all(
            isinstance(key, str)
            and key not in {"hostname", "host_path", "timestamp", "secret", "private_key", "seed"}
            and _safe_value(item)
            for key, item in value.items()
        )
    return False


def _exact(mapping: Mapping[str, Any], expected: frozenset[str]) -> bool:
    return set(mapping) == set(expected)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value


def _hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH64.fullmatch(value) is not None


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
    raise TypeError("precedence case must be a mapping or JSON object")


def _canonical_json(value: Any) -> bytes:
    if not _safe_value(value):
        raise ValueError("precedence case contains unsafe value")
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
            raise TypeError("precedence case must be a mapping")
        unsigned = {key: value for key, value in case.items() if key != "input_digest"}
        return hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    except Exception as exc:
        raise ValueError("precedence case cannot be canonicalized") from None


def _output(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    baseline_status: str = "UNKNOWN",
    candidate_status: str = "UNKNOWN",
    degradation: str = "UNKNOWN",
    digest_status: str = "NOT_CLAIMED",
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": "OBSERVE_ONLY",
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "baseline_status": baseline_status,
        "candidate_status": candidate_status,
        "degradation": degradation,
        "digest_status": digest_status,
        "assurance_rank": _ASSURANCE_RANK.get(status, 0),
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


def _invalid(reason: str, *, baseline_status: str = "UNKNOWN", candidate_status: str = "UNKNOWN") -> dict[str, Any]:
    return _output(
        "INPUT_INVALID",
        TEST_BLOCKED,
        HOLD,
        reason,
        baseline_status=baseline_status,
        candidate_status=candidate_status,
    )


def _validate_report(report: Any) -> str | None:
    if not isinstance(report, Mapping) or not _exact(report, _REPORT_KEYS):
        return "REPORT_SCHEMA_NOT_EXACT"
    if not all(_text(report.get(key)) for key in ("status", "decision", "evidence_state", "seal_status", "production_status", "authority_claim")):
        return "REPORT_TEXT_INVALID"
    status = report["status"]
    if status not in _STATUS_DECISIONS or report["decision"] != _STATUS_DECISIONS[status]:
        return "STATUS_DECISION_MISMATCH"
    if report["evidence_state"] not in _EVIDENCE_STATES:
        return "EVIDENCE_STATE_UNKNOWN"
    if report["seal_status"] not in {"SEALED_TEST_ONLY", "UNSEALED"}:
        return "SEAL_STATUS_UNKNOWN"
    if report["production_status"] != PRODUCTION_NOT_AUTHORIZED or report["authority_claim"] != NOT_CLAIMED:
        return "NEGATIVE_AUTHORITY_FLAGS_INVALID"
    for field in (
        "capability_issued",
        "write_authorized",
        "mutation_allowed",
        "persistence_performed",
        "cas_attempted",
        "fence_issued",
        "resume_allowed",
    ):
        if report[field] is not False:
            return "NEGATIVE_MUTATION_FLAGS_INVALID"
    if status == LOCKED_TEST_PASS and (report["evidence_state"] != "COMPLETE" or report["seal_status"] != "SEALED_TEST_ONLY"):
        return "LOCKED_REPORT_NOT_COMPLETE"
    if status == PROPOSAL_ONLY and (report["evidence_state"] != "PROPOSED" or report["seal_status"] != "UNSEALED"):
        return "PROPOSAL_REPORT_NOT_UNSEALED"
    if status == TEST_BLOCKED and report["evidence_state"] not in _FAIL_CLOSED_STATES:
        return "BLOCKED_REPORT_NOT_FAIL_CLOSED"
    if status == RECOVERY_REQUIRED and report["evidence_state"] not in _FAIL_CLOSED_STATES:
        return "RECOVERY_REPORT_NOT_FAIL_CLOSED"
    return None


def _evaluate_status_precedence(
    case: Mapping[str, Any] | bytes | str,
) -> dict[str, Any]:
    """Reject any upward claim after a declared negative evidence event."""

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
    if case.get("schema_version") != HARNESS_SCHEMA or case.get("observation_mode") != "OBSERVE_ONLY":
        return _invalid("CASE_PROFILE_INVALID")
    if case.get("canonicalization") != CANONICALIZATION:
        return _invalid("CASE_CANONICALIZATION_INVALID")
    if not _hash(case.get("input_digest")):
        return _invalid("CASE_DIGEST_INVALID")
    try:
        computed = input_digest(case)
    except (TypeError, ValueError, UnicodeError):
        return _invalid("CASE_NOT_CANONICAL")
    if case["input_digest"] != computed:
        return _invalid("CASE_DIGEST_DRIFT")

    baseline = case.get("baseline")
    candidate = case.get("candidate")
    event = case.get("event")
    baseline_error = _validate_report(baseline)
    candidate_error = _validate_report(candidate)
    if baseline_error:
        return _invalid(baseline_error)
    if candidate_error:
        return _invalid(
            candidate_error,
            baseline_status=baseline["status"],
            candidate_status="UNKNOWN",
        )
    if not isinstance(event, Mapping) or not _exact(event, _EVENT_KEYS):
        return _invalid("EVENT_SCHEMA_NOT_EXACT", baseline_status=baseline["status"], candidate_status=candidate["status"])
    if not _text(event["kind"]) or not _text(event["field"]):
        return _invalid("EVENT_TEXT_INVALID", baseline_status=baseline["status"], candidate_status=candidate["status"])
    if event["field"] not in _ALLOWED_EVENT_FIELDS:
        return _invalid("EVENT_FIELD_INVALID", baseline_status=baseline["status"], candidate_status=candidate["status"])
    if event["kind"] != "NO_CHANGE" and event["kind"] not in _EVENT_STATES:
        return _invalid("EVENT_KIND_UNKNOWN", baseline_status=baseline["status"], candidate_status=candidate["status"])
    if event["baseline_evidence_state"] != baseline["evidence_state"] or event["candidate_evidence_state"] != candidate["evidence_state"]:
        return _invalid("EVENT_EVIDENCE_STATE_MISMATCH", baseline_status=baseline["status"], candidate_status=candidate["status"])

    if event["kind"] == "NO_CHANGE":
        if baseline != candidate or event["baseline_evidence_state"] != event["candidate_evidence_state"]:
            return _invalid("NO_CHANGE_EVENT_MUTATED_REPORT", baseline_status=baseline["status"], candidate_status=candidate["status"])
        return _output(
            "NO_ESCALATION",
            candidate["status"],
            candidate["decision"],
            "STATUS_UNCHANGED",
            baseline_status=baseline["status"],
            candidate_status=candidate["status"],
            degradation="NO_CHANGE",
            digest_status="MATCH",
        )

    expected_state = _EVENT_STATES[event["kind"]]
    if candidate["evidence_state"] != expected_state:
        return _invalid("EVENT_KIND_STATE_MISMATCH", baseline_status=baseline["status"], candidate_status=candidate["status"])
    if candidate["status"] == LOCKED_TEST_PASS:
        return _output(
            "STATUS_ESCALATION_REJECTED",
            RECOVERY_REQUIRED,
            MANUAL_REVIEW,
            "LOCKED_PASS_AFTER_NEGATIVE_EVIDENCE",
            baseline_status=baseline["status"],
            candidate_status=candidate["status"],
            degradation=event["kind"],
            digest_status="MATCH",
        )
    if _CLAIM_LEVEL[candidate["status"]] > _CLAIM_LEVEL[baseline["status"]]:
        return _output(
            "STATUS_ESCALATION_REJECTED",
            RECOVERY_REQUIRED,
            MANUAL_REVIEW,
            "CLAIM_LEVEL_INCREASED",
            baseline_status=baseline["status"],
            candidate_status=candidate["status"],
            degradation=event["kind"],
            digest_status="MATCH",
        )
    if event["kind"] in {"EVIDENCE_STALE", "EVIDENCE_DRIFT"} and candidate["status"] not in {TEST_BLOCKED, RECOVERY_REQUIRED}:
        return _output(
            "STATUS_ESCALATION_REJECTED",
            RECOVERY_REQUIRED,
            MANUAL_REVIEW,
            "DRIFT_NOT_FAIL_CLOSED",
            baseline_status=baseline["status"],
            candidate_status=candidate["status"],
            degradation=event["kind"],
            digest_status="MATCH",
        )
    if event["kind"] == "EVIDENCE_MALFORMED" and candidate["status"] != TEST_BLOCKED:
        return _output(
            "STATUS_ESCALATION_REJECTED",
            RECOVERY_REQUIRED,
            MANUAL_REVIEW,
            "MALFORMED_NOT_BLOCKED",
            baseline_status=baseline["status"],
            candidate_status=candidate["status"],
            degradation=event["kind"],
            digest_status="MATCH",
        )
    return _output(
        "SAFE_NON_ESCALATING_DOWNGRADE",
        candidate["status"],
        candidate["decision"],
        "STATUS_NON_ESCALATING",
        baseline_status=baseline["status"],
        candidate_status=candidate["status"],
        degradation=event["kind"],
        digest_status="MATCH",
    )


def evaluate_status_precedence(
    case: Mapping[str, Any] | bytes | str,
) -> dict[str, Any]:
    """Fail closed even for hostile/custom Mapping implementations."""

    try:
        return _evaluate_status_precedence(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


__all__ = [
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "LOCKED_TEST_PASS",
    "MANUAL_REVIEW",
    "NOT_CLAIMED",
    "PRODUCTION_NOT_AUTHORIZED",
    "PROPOSAL_ONLY",
    "RECOVERY_REQUIRED",
    "TEST_BLOCKED",
    "evaluate_status_precedence",
    "input_digest",
]
