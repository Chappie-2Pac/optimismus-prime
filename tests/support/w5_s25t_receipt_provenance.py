"""Pure S25T receipt provenance and partial-observation gate behind S25R."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from support.w5_s25r_receipt_reconciliation import (
        CANONICALIZATION as S25R_CANONICALIZATION,
        HARNESS_SCHEMA as S25R_SCHEMA,
        evaluate_receipt_reconciliation,
        input_digest as s25r_input_digest,
    )
except ImportError:  # pragma: no cover - direct support-module execution
    from w5_s25r_receipt_reconciliation import (
        CANONICALIZATION as S25R_CANONICALIZATION,
        HARNESS_SCHEMA as S25R_SCHEMA,
        evaluate_receipt_reconciliation,
        input_digest as s25r_input_digest,
    )


HARNESS_SCHEMA = "s25t.receipt-provenance-partial-observation.v1"
CANONICALIZATION = "s25m-canonical-json-v1"
TEST_ONLY = "TEST_ONLY"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
HOLD = "HOLD"
DESIGN_ONLY = "DESIGN_ONLY"
MANUAL_REVIEW = "MANUAL_REVIEW"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

PROVENANCE_WITNESS_RECONCILED = "PROVENANCE_WITNESS_RECONCILED"
PROVENANCE_REJECTED = "PROVENANCE_REJECTED"
PROVENANCE_PARTIAL = "PROVENANCE_PARTIAL"
PROVENANCE_UNKNOWN = "PROVENANCE_UNKNOWN"
PROVENANCE_STALE = "PROVENANCE_STALE"
PROVENANCE_OUT_OF_WINDOW = "PROVENANCE_OUT_OF_WINDOW"
PROVENANCE_CONFLICT = "PROVENANCE_CONFLICT"
S25R_REJECTED = "S25R_REJECTED"

_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\\\/])")
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.IGNORECASE)
_MAX_DEPTH = 64
_MAX_STRING = 4096
_MAX_INTEGER = 2**63 - 1

_REQUIRED_KINDS = (
    "S25Q_RESULT",
    "PARENT_CANDIDATE",
    "TRANSITION",
    "HEAD",
    "HISTORY",
    "INDEX",
)
_SOURCE_IDS = tuple(f"s25r-source-{kind.lower()}" for kind in _REQUIRED_KINDS)
_SOURCE_ID_BY_KIND = dict(zip(_REQUIRED_KINDS, _SOURCE_IDS))
_STATUS_DECISIONS = {
    "LOCKED_TEST_PASS": "TEST_ONLY_PASS",
    PROPOSAL_ONLY: DESIGN_ONLY,
    TEST_BLOCKED: HOLD,
    RECOVERY_REQUIRED: MANUAL_REVIEW,
}
_S25R_CLASSIFICATIONS = {
    "RECEIPT_BUNDLE_RECONCILED",
    "RECEIPT_REJECTED",
    "RECEIPT_CONFLICT",
    "RECEIPT_REPLAY",
    "FORK_CONFLICT",
    "S25Q_REJECTED",
    "INPUT_INVALID",
}
_OBSERVATION_STATES = {
    "PRESENT",
    "ABSENT",
    "UNKNOWN",
    "UNREADABLE",
    "STALE",
    "FUTURE",
    "CONTRADICTORY",
    "NOT_COMPARABLE",
}
_COMPARISON_STATES = {"COMPARABLE", "NOT_COMPARABLE", "CONFLICT"}
_FRESHNESS_STATES = {"FRESH", "STALE", "FUTURE", "UNKNOWN"}
_COVERAGE_STATES = {"COMPLETE", "PARTIAL", "UNKNOWN"}

_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "observation_mode",
        "canonicalization",
        "expected",
        "s25r_case",
        "s25r_projection",
        "sources",
        "window",
        "observations",
        "input_digest",
    }
)
_EXPECTED_KEYS = frozenset(
    {
        "s25r_case_digest",
        "s25r_result_digest",
        "s25r_projection_digest",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "previous_sequence",
        "current_sequence",
        "previous_pass_digest",
        "current_pass_digest",
        "previous_observation_digest",
        "current_observation_digest",
        "observation_id",
        "idempotency_key",
        "observer_id",
        "comparison_group",
        "window_digest",
        "source_set_digest",
        "observation_set_digest",
        "required_source_count",
        "required_observation_count",
    }
)
_SOURCE_SET_KEYS = frozenset({"schema", "required_source_ids", "source_count", "sources", "source_digests", "set_digest"})
_SOURCE_KEYS = frozenset(
    {
        "schema",
        "source_id",
        "observer_id",
        "comparison_group",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "source_digest",
    }
)
_WINDOW_KEYS = frozenset(
    {
        "schema",
        "window_id",
        "observer_id",
        "comparison_group",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "start_sequence",
        "target_sequence",
        "end_sequence",
        "start_observation_digest",
        "end_observation_digest",
        "required_receipt_kinds",
        "expected_cells",
        "required_cell_count",
        "coverage_status",
        "freshness_status",
        "comparison_status",
        "window_digest",
    }
)
_CELL_KEYS = frozenset({"source_id", "observer_id", "receipt_kind", "epoch", "observation_sequence", "cell_digest"})
_OBSERVATION_KEYS = frozenset(
    {
        "schema",
        "cell_digest",
        "source_id",
        "source_digest",
        "observer_id",
        "comparison_group",
        "receipt_kind",
        "observation_id",
        "idempotency_key",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "observation_sequence",
        "observation_state",
        "comparison_status",
        "freshness_status",
        "coverage_status",
        "receipt_digest",
        "s25r_projection_digest",
        "observation_digest",
    }
)
_PROJECTION_KEYS = frozenset(
    {
        "schema",
        "s25r_case_digest",
        "s25r_result_digest",
        "classification",
        "status",
        "decision",
        "reason",
        "reconciliation_status",
        "witness_only",
        "receipt_count",
        "receipt_witnessed",
        "s25q_classification",
        "s25q_status",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "epoch",
        "observation_id",
        "idempotency_key",
        "previous_sequence",
        "current_sequence",
        "previous_pass_digest",
        "current_pass_digest",
        "previous_observation_digest",
        "current_observation_digest",
        "receipt_set_digest",
        "receipt_digests",
        "production_status",
        "authority_claim",
        "write_authorized",
        "mutation_allowed",
        "persistence_performed",
        "cas_attempted",
        "fence_issued",
        "resume_allowed",
        "receipt_emitted",
        "receipt_committed",
        "commit_authorized",
        "floor_advanced",
        "projection_digest",
    }
)
_RECEIPT_DIGEST_KEYS = frozenset({"kind", "receipt_digest"})
_S25R_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "observation_mode",
        "classification",
        "status",
        "decision",
        "reason",
        "reconciliation_status",
        "witness_only",
        "receipt_count",
        "receipt_witnessed",
        "s25q_classification",
        "s25q_status",
        "production_status",
        "authority_claim",
        "capability_issued",
        "write_authorized",
        "mutation_allowed",
        "persistence_performed",
        "cas_attempted",
        "fence_issued",
        "resume_allowed",
        "receipt_emitted",
        "receipt_committed",
        "commit_authorized",
        "floor_advanced",
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


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse(value: Mapping[str, Any] | bytes | str) -> Any:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, bytes):
        return json.loads(value.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    if isinstance(value, str):
        return json.loads(value, object_pairs_hook=_reject_duplicate_pairs)
    raise TypeError("case must be a mapping, bytes or JSON string")


def _snapshot(value: Any, *, depth: int = 0, active: set[int] | None = None) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("value too deep")
    if active is None:
        active = set()
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, int) and not isinstance(value, bool) and abs(value) > _MAX_INTEGER:
            raise ValueError("integer out of range")
        if isinstance(value, str) and len(value) > _MAX_STRING:
            raise ValueError("string too long")
        return value
    if isinstance(value, float):
        raise ValueError("float is not allowed")
    if isinstance(value, (bytes, bytearray)):
        raise ValueError("bytes are not allowed inside a case")
    marker = id(value)
    if marker in active:
        raise ValueError("recursive value")
    active.add(marker)
    try:
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("mapping keys must be strings")
                if key in result:
                    raise _DuplicateKey(key)
                result[key] = _snapshot(item, depth=depth + 1, active=active)
            return result
        if isinstance(value, (list, tuple)):
            return [_snapshot(item, depth=depth + 1, active=active) for item in value]
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
            return all(isinstance(key, str) and _safe_value(item, depth=depth + 1, active=active) for key, item in value.items())
        if isinstance(value, (list, tuple)):
            return all(_safe_value(item, depth=depth + 1, active=active) for item in value)
        return False
    except Exception:
        return False
    finally:
        active.remove(marker)


def _exact(value: Any, keys: frozenset[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == set(keys)


def _hash(value: Any) -> bool:
    return isinstance(value, str) and bool(_HASH64.fullmatch(value))


def _validate_hashes(mapping: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    return all(_hash(mapping.get(field)) for field in fields)


def _text(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= _MAX_STRING and not _ABSOLUTE_PATH.match(value) and not value.startswith("\\\\") and not _URI_SCHEME.match(value)


def _integer(value: Any, *, positive: bool = False) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= _MAX_INTEGER and (not positive or value > 0)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _input_digest_snapshot(case: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in case.items() if key != "input_digest"}
    return _digest(unsigned)


def input_digest(case: Mapping[str, Any]) -> str:
    """Return the outer S25T digest without reading or mutating anything."""

    try:
        snapshot = _snapshot(case)
        if not isinstance(snapshot, Mapping):
            raise ValueError("case must be a mapping")
        return _input_digest_snapshot(snapshot)
    except Exception:
        raise ValueError("case cannot be canonicalized") from None


def _source_digest(source: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in source.items() if key != "source_digest"})


def _source_set_digest(source_set: Mapping[str, Any]) -> str:
    return _digest({"schema": source_set["schema"], "required_source_ids": source_set["required_source_ids"], "source_digests": sorted(source_set["source_digests"])})


def _window_id(window: Mapping[str, Any]) -> str:
    return _digest(
        {
            "schema": window["schema"],
            "observer_id": window["observer_id"],
            "comparison_group": window["comparison_group"],
            "subject_digest": window["subject_digest"],
            "scope_digest": window["scope_digest"],
            "baseline_digest": window["baseline_digest"],
            "epoch": window["epoch"],
            "start_sequence": window["start_sequence"],
            "target_sequence": window["target_sequence"],
            "end_sequence": window["end_sequence"],
        }
    )


def _cell_digest(cell: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in cell.items() if key != "cell_digest"})


def _window_digest(window: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in window.items() if key not in {"window_id", "window_digest"}}
    unsigned["expected_cells"] = sorted(unsigned["expected_cells"], key=lambda item: item["cell_digest"])
    unsigned["window_id"] = window["window_id"]
    return _digest(unsigned)


def _observation_digest(observation: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in observation.items() if key != "observation_digest"})


def _observation_set_digest(observations: list[Mapping[str, Any]]) -> str:
    return _digest({"schema": "s25t.observation-set.v1", "observation_digests": sorted(item["observation_digest"] for item in observations)})


def _output(
    classification: str,
    status: str,
    decision: str,
    reason: str,
    *,
    s25r_result: Mapping[str, Any] | None = None,
    provenance_status: str = "NOT_CLAIMED",
    coverage_status: str = "UNKNOWN",
    freshness_status: str = "UNKNOWN",
    comparison_status: str = "NOT_COMPARABLE",
    source_count: int = 0,
    observation_count: int = 0,
    witness_only: bool = False,
    source_witnessed: bool = False,
) -> dict[str, Any]:
    result = {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": TEST_ONLY,
        "classification": classification,
        "status": status,
        "decision": decision,
        "reason": reason,
        "provenance_status": provenance_status,
        "coverage_status": coverage_status,
        "freshness_status": freshness_status,
        "comparison_status": comparison_status,
        "source_count": source_count,
        "observation_count": observation_count,
        "witness_only": witness_only,
        "source_witnessed": source_witnessed,
        "s25r_classification": "UNKNOWN",
        "s25r_status": "UNKNOWN",
        "s25r_reconciliation_status": "UNKNOWN",
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
    if s25r_result is not None:
        classification_value = s25r_result.get("classification")
        status_value = s25r_result.get("status")
        reconciliation_value = s25r_result.get("reconciliation_status")
        result["s25r_classification"] = classification_value if classification_value in _S25R_CLASSIFICATIONS else "UNKNOWN"
        result["s25r_status"] = status_value if status_value in _STATUS_DECISIONS else "UNKNOWN"
        result["s25r_reconciliation_status"] = reconciliation_value if reconciliation_value in {"CONSISTENT", "NOT_CLAIMED"} else "UNKNOWN"
    return result


def _invalid(reason: str) -> dict[str, Any]:
    return _output("INPUT_INVALID", TEST_BLOCKED, HOLD, reason)


def _blocked(reason: str, *, classification: str = PROVENANCE_REJECTED, **kwargs: Any) -> dict[str, Any]:
    return _output(classification, TEST_BLOCKED, HOLD, reason, **kwargs)


def _review(reason: str, *, classification: str = PROVENANCE_CONFLICT, **kwargs: Any) -> dict[str, Any]:
    return _output(classification, RECOVERY_REQUIRED, MANUAL_REVIEW, reason, **kwargs)


def _valid_s25r_result(result: Any) -> bool:
    if not isinstance(result, Mapping) or not _safe_value(result) or set(result) != set(_S25R_RESULT_KEYS):
        return False
    if result.get("schema_version") != S25R_SCHEMA or result.get("observation_mode") != TEST_ONLY:
        return False
    if result.get("classification") not in _S25R_CLASSIFICATIONS or result.get("status") not in _STATUS_DECISIONS:
        return False
    if result.get("decision") != _STATUS_DECISIONS[result["status"]] or not _text(result.get("reason")):
        return False
    if result.get("reconciliation_status") not in {"CONSISTENT", "NOT_CLAIMED"} or not isinstance(result.get("witness_only"), bool) or not isinstance(result.get("receipt_witnessed"), bool):
        return False
    if not _integer(result.get("receipt_count")) or result.get("receipt_count") < 0:
        return False
    if result.get("s25q_classification") not in {"FLOOR_ADVANCE_ELIGIBLE", "FLOOR_BLOCKED", "FORK_CONFLICT", "FLOOR_REJECTED", "S25P_REJECTED", "INPUT_INVALID", "UNKNOWN"}:
        return False
    if result.get("s25q_status") not in set(_STATUS_DECISIONS) | {"UNKNOWN"}:
        return False
    if result.get("production_status") != PRODUCTION_NOT_AUTHORIZED or result.get("authority_claim") != NOT_CLAIMED:
        return False
    if result.get("floor_advanced") is not False:
        return False
    if not all(result.get(field) is False for field in ("capability_issued", "write_authorized", "mutation_allowed", "persistence_performed", "cas_attempted", "fence_issued", "resume_allowed", "receipt_emitted", "receipt_committed", "commit_authorized")):
        return False
    if result["classification"] == "RECEIPT_BUNDLE_RECONCILED":
        return (
            result["status"] == PROPOSAL_ONLY
            and result["decision"] == DESIGN_ONLY
            and result["reason"] == "READ_ONLY_WITNESS_ONLY"
            and result["reconciliation_status"] == "CONSISTENT"
            and result["witness_only"] is True
            and result["receipt_count"] == len(_REQUIRED_KINDS)
            and result["receipt_witnessed"] is True
            and result["s25q_classification"] == "FLOOR_ADVANCE_ELIGIBLE"
            and result["s25q_status"] in {"LOCKED_TEST_PASS", PROPOSAL_ONLY}
        )
    return result["witness_only"] is False and result["receipt_witnessed"] is False and result["reconciliation_status"] == "NOT_CLAIMED"


def _validate_expected(expected: Any) -> str | None:
    if not isinstance(expected, Mapping) or not _exact(expected, _EXPECTED_KEYS):
        return "EXPECTED_SCHEMA_NOT_EXACT"
    for field in (
        "s25r_case_digest",
        "s25r_result_digest",
        "s25r_projection_digest",
        "subject_digest",
        "scope_digest",
        "baseline_digest",
        "previous_pass_digest",
        "current_pass_digest",
        "previous_observation_digest",
        "current_observation_digest",
        "window_digest",
        "source_set_digest",
        "observation_set_digest",
    ):
        if not _hash(expected.get(field)):
            return "EXPECTED_DIGEST_INVALID"
    for field in ("epoch", "previous_sequence", "current_sequence", "required_source_count", "required_observation_count"):
        if not _integer(expected.get(field), positive=True):
            return "EXPECTED_COUNTER_INVALID"
    if expected["current_sequence"] != expected["previous_sequence"] + 1:
        return "EXPECTED_SEQUENCE_NOT_NEXT"
    if expected["required_source_count"] != len(_REQUIRED_KINDS) or expected["required_observation_count"] != len(_REQUIRED_KINDS):
        return "EXPECTED_COVERAGE_INVALID"
    for field in ("observation_id", "idempotency_key", "observer_id", "comparison_group"):
        if not _text(expected.get(field)):
            return "EXPECTED_TEXT_INVALID"
    return None


def _validate_source(source: Any) -> str | None:
    if not isinstance(source, Mapping) or not _exact(source, _SOURCE_KEYS):
        return "SOURCE_SCHEMA_NOT_EXACT"
    for field in ("source_id", "observer_id", "comparison_group"):
        if not _text(source.get(field)):
            return "SOURCE_TEXT_INVALID"
    if not _validate_hashes(source, ("subject_digest", "scope_digest", "baseline_digest", "source_digest")):
        return "SOURCE_DIGEST_INVALID"
    if not _integer(source.get("epoch"), positive=True):
        return "SOURCE_EPOCH_INVALID"
    if source["source_digest"] != _source_digest(source):
        return "SOURCE_DIGEST_DRIFT"
    return None


def _validate_source_set(source_set: Any) -> str | None:
    if not isinstance(source_set, Mapping) or not _exact(source_set, _SOURCE_SET_KEYS):
        return "SOURCE_SET_SCHEMA_NOT_EXACT"
    if source_set.get("schema") != "s25t.source-set.v1" or source_set.get("required_source_ids") != list(_SOURCE_IDS):
        return "SOURCE_SET_PROFILE_INVALID"
    sources = source_set.get("sources")
    digests = source_set.get("source_digests")
    if not isinstance(sources, list) or not isinstance(digests, list) or not _integer(source_set.get("source_count")) or source_set["source_count"] != len(sources) or len(digests) != len(sources) or not _hash(source_set.get("set_digest")):
        return "SOURCE_SET_SHAPE_INVALID"
    if len(digests) != len(set(digests)):
        return "SOURCES_DUPLICATE"
    for source, digest in zip(sources, digests):
        error = _validate_source(source)
        if error:
            return error
        if source["source_digest"] != digest:
            return "SOURCE_SET_DIGEST_MISMATCH"
    if source_set["set_digest"] != _source_set_digest(source_set):
        return "SOURCE_SET_DIGEST_DRIFT"
    ids = [source["source_id"] for source in sources]
    if len(ids) != len(set(ids)):
        return "SOURCES_DUPLICATE"
    if len(ids) != len(_SOURCE_IDS) or set(ids) != set(_SOURCE_IDS):
        return "SOURCES_PARTIAL_OR_UNKNOWN"
    return None


def _validate_window(window: Any) -> str | None:
    if not isinstance(window, Mapping) or not _exact(window, _WINDOW_KEYS):
        return "WINDOW_SCHEMA_NOT_EXACT"
    if window.get("schema") != "s25t.observation-window.v1" or not _hash(window.get("window_id")) or not _hash(window.get("window_digest")):
        return "WINDOW_PROFILE_INVALID"
    for field in ("observer_id", "comparison_group"):
        if not _text(window.get(field)):
            return "WINDOW_TEXT_INVALID"
    if not _validate_hashes(window, ("subject_digest", "scope_digest", "baseline_digest", "start_observation_digest", "end_observation_digest")):
        return "WINDOW_DIGEST_INVALID"
    for field in ("epoch", "start_sequence", "target_sequence", "end_sequence", "required_cell_count"):
        if not _integer(window.get(field), positive=True):
            return "WINDOW_COUNTER_INVALID"
    if window.get("target_sequence") != window.get("start_sequence") + 1 or window.get("end_sequence") != window.get("target_sequence"):
        return "WINDOW_SEQUENCE_INVALID"
    if window.get("required_receipt_kinds") != list(_REQUIRED_KINDS) or window.get("required_cell_count") != len(_REQUIRED_KINDS):
        return "WINDOW_COVERAGE_INVALID"
    if window.get("coverage_status") not in _COVERAGE_STATES or window.get("freshness_status") not in _FRESHNESS_STATES or window.get("comparison_status") not in _COMPARISON_STATES:
        return "WINDOW_STATUS_INVALID"
    if window["coverage_status"] != "COMPLETE":
        return "WINDOW_PARTIAL"
    if window["freshness_status"] == "STALE":
        return "WINDOW_STALE"
    if window["freshness_status"] == "FUTURE":
        return "WINDOW_OUT_OF_WINDOW"
    if window["freshness_status"] != "FRESH":
        return "WINDOW_FRESHNESS_UNKNOWN"
    if window["comparison_status"] != "COMPARABLE":
        return "WINDOW_NOT_COMPARABLE"
    cells = window.get("expected_cells")
    if not isinstance(cells, list) or len(cells) != window["required_cell_count"]:
        return "WINDOW_CELLS_INVALID"
    cell_digests: list[str] = []
    for cell in cells:
        if not isinstance(cell, Mapping) or not _exact(cell, _CELL_KEYS):
            return "WINDOW_CELL_SCHEMA_INVALID"
        if not _text(cell.get("source_id")) or not _text(cell.get("observer_id")) or cell.get("receipt_kind") not in _REQUIRED_KINDS or not _integer(cell.get("epoch"), positive=True) or not _integer(cell.get("observation_sequence"), positive=True) or not _hash(cell.get("cell_digest")):
            return "WINDOW_CELL_INVALID"
        if cell["source_id"] != _SOURCE_ID_BY_KIND[cell["receipt_kind"]]:
            return "WINDOW_SOURCE_KIND_MISMATCH"
        if cell["cell_digest"] != _cell_digest(cell):
            return "WINDOW_CELL_DIGEST_DRIFT"
        cell_digests.append(cell["cell_digest"])
    if len(cell_digests) != len(set(cell_digests)) or {cell["receipt_kind"] for cell in cells} != set(_REQUIRED_KINDS):
        return "WINDOW_CELLS_DUPLICATE_OR_PARTIAL"
    if window["window_id"] != _window_id(window) or window["window_digest"] != _window_digest(window):
        return "WINDOW_DIGEST_DRIFT"
    return None


def _validate_observation(observation: Any) -> str | None:
    if not isinstance(observation, Mapping) or not _exact(observation, _OBSERVATION_KEYS):
        return "OBSERVATION_SCHEMA_NOT_EXACT"
    if observation.get("schema") != "s25t.receipt-observation.v1":
        return "OBSERVATION_PROFILE_INVALID"
    for field in ("cell_digest", "source_digest", "s25r_projection_digest", "observation_digest"):
        if not _hash(observation.get(field)):
            return "OBSERVATION_DIGEST_INVALID"
    for field in ("source_id", "observer_id", "comparison_group", "observation_id", "idempotency_key"):
        if not _text(observation.get(field)):
            return "OBSERVATION_TEXT_INVALID"
    for field in ("subject_digest", "scope_digest", "baseline_digest"):
        if not _hash(observation.get(field)):
            return "OBSERVATION_IDENTITY_INVALID"
    if not _integer(observation.get("epoch"), positive=True) or not _integer(observation.get("observation_sequence"), positive=True):
        return "OBSERVATION_COUNTER_INVALID"
    if observation.get("receipt_kind") not in _REQUIRED_KINDS or observation.get("observation_state") not in _OBSERVATION_STATES or observation.get("comparison_status") not in _COMPARISON_STATES or observation.get("freshness_status") not in _FRESHNESS_STATES or observation.get("coverage_status") not in _COVERAGE_STATES:
        return "OBSERVATION_STATUS_INVALID"
    receipt_digest = observation.get("receipt_digest")
    if observation["observation_state"] == "PRESENT":
        if not _hash(receipt_digest):
            return "OBSERVATION_RECEIPT_MISSING"
    elif receipt_digest is not None:
        return "OBSERVATION_NONPRESENT_RECEIPT_LEAK"
    if observation["observation_digest"] != _observation_digest(observation):
        return "OBSERVATION_DIGEST_DRIFT"
    return None


def _valid_projection(projection: Any) -> bool:
    if not isinstance(projection, Mapping) or not _exact(projection, _PROJECTION_KEYS) or not _safe_value(projection):
        return False
    if projection.get("schema") != "s25t.s25r-projection.v1" or not _hash(projection.get("s25r_case_digest")) or not _hash(projection.get("s25r_result_digest")) or not _hash(projection.get("projection_digest")):
        return False
    for field in ("subject_digest", "scope_digest", "baseline_digest", "previous_pass_digest", "current_pass_digest", "previous_observation_digest", "current_observation_digest", "receipt_set_digest"):
        if not _hash(projection.get(field)):
            return False
    for field in ("epoch", "previous_sequence", "current_sequence", "receipt_count"):
        if not _integer(projection.get(field), positive=True):
            return False
    if projection["current_sequence"] != projection["previous_sequence"] + 1 or projection["receipt_count"] != len(_REQUIRED_KINDS):
        return False
    if projection.get("classification") not in _S25R_CLASSIFICATIONS or projection.get("status") not in _STATUS_DECISIONS or projection.get("decision") != _STATUS_DECISIONS[projection["status"]] or not _text(projection.get("reason")):
        return False
    if projection.get("s25q_classification") not in {"FLOOR_ADVANCE_ELIGIBLE", "FLOOR_BLOCKED", "FORK_CONFLICT", "FLOOR_REJECTED", "S25P_REJECTED", "INPUT_INVALID", "UNKNOWN"} or projection.get("s25q_status") not in set(_STATUS_DECISIONS) | {"UNKNOWN"}:
        return False
    if projection.get("production_status") != PRODUCTION_NOT_AUTHORIZED or projection.get("authority_claim") != NOT_CLAIMED or projection.get("floor_advanced") is not False:
        return False
    if not all(projection.get(field) is False for field in ("witness_only", "receipt_witnessed", "write_authorized", "mutation_allowed", "persistence_performed", "cas_attempted", "fence_issued", "resume_allowed", "receipt_emitted", "receipt_committed", "commit_authorized")) and projection.get("classification") != "RECEIPT_BUNDLE_RECONCILED":
        return False
    if projection.get("classification") == "RECEIPT_BUNDLE_RECONCILED" and (projection.get("witness_only") is not True or projection.get("receipt_witnessed") is not True):
        return False
    digests = projection.get("receipt_digests")
    if not isinstance(digests, list) or len(digests) != len(_REQUIRED_KINDS):
        return False
    kinds: list[str] = []
    for item in digests:
        if not isinstance(item, Mapping) or set(item) != set(_RECEIPT_DIGEST_KEYS) or item.get("kind") not in _REQUIRED_KINDS or not _hash(item.get("receipt_digest")):
            return False
        kinds.append(item["kind"])
    if kinds != list(_REQUIRED_KINDS) or projection["projection_digest"] != _digest({key: value for key, value in projection.items() if key != "projection_digest"}):
        return False
    return True


def _r_context(case: Mapping[str, Any]) -> dict[str, Any] | None:
    expected = case.get("expected")
    previous = case.get("previous")
    current = case.get("current")
    transition = case.get("floor_transition")
    receipt_set = case.get("receipt_set")
    if not all(isinstance(item, Mapping) for item in (expected, previous, current, transition, receipt_set)):
        return None
    before_after = transition.get("before"), transition.get("after")
    if not all(isinstance(item, Mapping) for item in before_after):
        return None
    receipts = receipt_set.get("receipts")
    if not isinstance(receipts, list):
        return None
    by_kind = {item.get("kind"): item for item in receipts if isinstance(item, Mapping)}
    if set(by_kind) != set(_REQUIRED_KINDS) or len(by_kind) != len(_REQUIRED_KINDS):
        return None
    try:
        case_digest = s25r_input_digest(case)
    except Exception:
        return None
    result_digest = ""
    return {"expected": expected, "previous": previous, "current": current, "transition": transition, "receipt_set": receipt_set, "by_kind": by_kind, "case_digest": case_digest, "result_digest": result_digest}


def _projection_from_context(context: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any] | None:
    expected = context["expected"]
    receipt_set = context["receipt_set"]
    try:
        receipt_digests = [{"kind": kind, "receipt_digest": context["by_kind"][kind]["receipt_digest"]} for kind in _REQUIRED_KINDS]
        projection: dict[str, Any] = {
            "schema": "s25t.s25r-projection.v1",
            "s25r_case_digest": context["case_digest"],
            "s25r_result_digest": _digest(result),
            "classification": result["classification"],
            "status": result["status"],
            "decision": result["decision"],
            "reason": result["reason"],
            "reconciliation_status": result["reconciliation_status"],
            "witness_only": result["witness_only"],
            "receipt_count": result["receipt_count"],
            "receipt_witnessed": result["receipt_witnessed"],
            "s25q_classification": result["s25q_classification"],
            "s25q_status": result["s25q_status"],
            "subject_digest": expected["subject_digest"],
            "scope_digest": expected["scope_digest"],
            "baseline_digest": expected["baseline_digest"],
            "epoch": expected["epoch"],
            "observation_id": expected["observation_id"],
            "idempotency_key": expected["idempotency_key"],
            "previous_sequence": expected["previous_sequence"],
            "current_sequence": expected["current_sequence"],
            "previous_pass_digest": expected["previous_pass_digest"],
            "current_pass_digest": expected["current_pass_digest"],
            "previous_observation_digest": expected["previous_observation_digest"],
            "current_observation_digest": expected["current_observation_digest"],
            "receipt_set_digest": receipt_set["set_digest"],
            "receipt_digests": receipt_digests,
            "production_status": result["production_status"],
            "authority_claim": result["authority_claim"],
            "write_authorized": result["write_authorized"],
            "mutation_allowed": result["mutation_allowed"],
            "persistence_performed": result["persistence_performed"],
            "cas_attempted": result["cas_attempted"],
            "fence_issued": result["fence_issued"],
            "resume_allowed": result["resume_allowed"],
            "receipt_emitted": result["receipt_emitted"],
            "receipt_committed": result["receipt_committed"],
            "commit_authorized": result["commit_authorized"],
            "floor_advanced": result["floor_advanced"],
        }
        projection["projection_digest"] = _digest(projection)
        return projection
    except (KeyError, TypeError, ValueError):
        return None


def _evaluate(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    try:
        parsed = _parse(case)
        snapshot = _snapshot(parsed)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")
    if not isinstance(snapshot, Mapping) or not _exact(snapshot, _TOP_LEVEL):
        return _invalid("CASE_SCHEMA_NOT_EXACT")
    if not _safe_value(snapshot):
        return _invalid("CASE_VALUE_NOT_SAFE")
    if snapshot.get("schema_version") != HARNESS_SCHEMA or snapshot.get("observation_mode") != TEST_ONLY or snapshot.get("canonicalization") != CANONICALIZATION:
        return _invalid("CASE_PROFILE_INVALID")
    if not _hash(snapshot.get("input_digest")) or snapshot["input_digest"] != _input_digest_snapshot(snapshot):
        return _invalid("CASE_DIGEST_DRIFT")
    expected = snapshot["expected"]
    error = _validate_expected(expected)
    if error:
        return _blocked(error)
    s25r_case = snapshot["s25r_case"]
    if not isinstance(s25r_case, Mapping) or not _safe_value(s25r_case):
        return _blocked("S25R_CASE_INVALID")
    try:
        raw_result = evaluate_receipt_reconciliation(s25r_case)
        s25r_result = _snapshot(raw_result)
    except Exception:
        return _blocked("S25R_CASE_UNREADABLE")
    if not _valid_s25r_result(s25r_result):
        return _blocked("S25R_RESULT_INVALID")
    if s25r_result["classification"] != "RECEIPT_BUNDLE_RECONCILED":
        return _output(S25R_REJECTED, TEST_BLOCKED, HOLD, "S25R_NOT_RECONCILIABLE", s25r_result=s25r_result)
    context = _r_context(s25r_case)
    if context is None:
        return _blocked("S25R_CONTEXT_INVALID", s25r_result=s25r_result)
    actual_projection = _projection_from_context(context, s25r_result)
    if actual_projection is None or not _valid_projection(actual_projection):
        return _blocked("S25R_PROJECTION_INVALID", s25r_result=s25r_result)
    if snapshot["s25r_projection"] != actual_projection:
        return _blocked("S25R_PROJECTION_MISMATCH", s25r_result=s25r_result)
    if expected["s25r_case_digest"] != actual_projection["s25r_case_digest"] or expected["s25r_result_digest"] != actual_projection["s25r_result_digest"] or expected["s25r_projection_digest"] != actual_projection["projection_digest"]:
        return _blocked("EXPECTED_S25R_BINDING_MISMATCH", s25r_result=s25r_result)
    for field in ("subject_digest", "scope_digest", "baseline_digest", "epoch", "previous_sequence", "current_sequence", "previous_pass_digest", "current_pass_digest", "previous_observation_digest", "current_observation_digest", "observation_id", "idempotency_key"):
        if expected[field] != actual_projection[field]:
            return _review("EXPECTED_S25R_CONTEXT_MISMATCH", s25r_result=s25r_result)
    source_set = snapshot["sources"]
    source_error = _validate_source_set(source_set)
    if source_error:
        if source_error in {"SOURCES_PARTIAL_OR_UNKNOWN", "SOURCES_DUPLICATE"}:
            return _blocked(source_error, classification=PROVENANCE_PARTIAL if source_error == "SOURCES_PARTIAL_OR_UNKNOWN" else PROVENANCE_REJECTED, s25r_result=s25r_result)
        return _blocked(source_error, s25r_result=s25r_result)
    if source_set["set_digest"] != expected["source_set_digest"]:
        return _blocked("SOURCE_SET_BINDING_MISMATCH", s25r_result=s25r_result)
    source_by_id = {source["source_id"]: source for source in source_set["sources"]}
    for kind, source_id in _SOURCE_ID_BY_KIND.items():
        source = source_by_id[source_id]
        if source["observer_id"] != expected["observer_id"] or source["comparison_group"] != expected["comparison_group"]:
            return _review("SOURCE_OBSERVER_IDENTITY_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]))
        if any(source[field] != expected[field] for field in ("subject_digest", "scope_digest", "baseline_digest", "epoch")):
            return _review("SOURCE_CROSS_IDENTITY_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]))
    window = snapshot["window"]
    window_error = _validate_window(window)
    if window_error:
        if window_error in {"WINDOW_STALE"}:
            return _review("WINDOW_STALE", classification=PROVENANCE_STALE, s25r_result=s25r_result, source_count=len(source_set["sources"]))
        if window_error in {"WINDOW_OUT_OF_WINDOW"}:
            return _review("WINDOW_OUT_OF_WINDOW", classification=PROVENANCE_OUT_OF_WINDOW, s25r_result=s25r_result, source_count=len(source_set["sources"]))
        if window_error in {"WINDOW_PARTIAL", "WINDOW_FRESHNESS_UNKNOWN", "WINDOW_NOT_COMPARABLE"}:
            return _blocked(window_error, classification=PROVENANCE_PARTIAL, s25r_result=s25r_result, source_count=len(source_set["sources"]))
        if window_error in {"WINDOW_SEQUENCE_INVALID", "WINDOW_DIGEST_DRIFT", "WINDOW_SOURCE_KIND_MISMATCH"}:
            return _review("WINDOW_DRIFT", classification=PROVENANCE_OUT_OF_WINDOW, s25r_result=s25r_result, source_count=len(source_set["sources"]))
        return _blocked(window_error, s25r_result=s25r_result, source_count=len(source_set["sources"]))
    if window["window_digest"] != expected["window_digest"]:
        return _review("WINDOW_BINDING_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]))
    if any(window[field] != expected[field] for field in ("observer_id", "comparison_group", "subject_digest", "scope_digest", "baseline_digest", "epoch")):
        return _review("WINDOW_CONTEXT_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]))
    if window["start_sequence"] != expected["previous_sequence"] or window["target_sequence"] != expected["current_sequence"] or window["end_sequence"] != expected["current_sequence"]:
        return _review("WINDOW_SEQUENCE_MISMATCH", classification=PROVENANCE_OUT_OF_WINDOW, s25r_result=s25r_result, source_count=len(source_set["sources"]))
    if window["start_observation_digest"] != expected["previous_observation_digest"] or window["end_observation_digest"] != expected["current_observation_digest"]:
        return _review("WINDOW_OBSERVATION_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]))
    observations = snapshot["observations"]
    if not isinstance(observations, list):
        return _blocked("OBSERVATIONS_NOT_LIST", s25r_result=s25r_result, source_count=len(source_set["sources"]))
    if len(observations) != len(_REQUIRED_KINDS):
        return _blocked("PARTIAL_OBSERVATION", classification=PROVENANCE_PARTIAL, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
    observation_digests: list[str] = []
    by_kind: dict[str, Mapping[str, Any]] = {}
    cells = {cell["receipt_kind"]: cell for cell in window["expected_cells"]}
    receipt_digests = {item["kind"]: item["receipt_digest"] for item in actual_projection["receipt_digests"]}
    for observation in observations:
        observation_error = _validate_observation(observation)
        if observation_error:
            return _blocked(observation_error, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
        kind = observation["receipt_kind"]
        if kind in by_kind:
            return _blocked("OBSERVATIONS_DUPLICATE", classification=PROVENANCE_REJECTED, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
        by_kind[kind] = observation
        observation_digests.append(observation["observation_digest"])
        source = source_by_id.get(observation["source_id"])
        cell = cells.get(kind)
        if source is None or cell is None:
            return _blocked("OBSERVATION_UNKNOWN_SOURCE_OR_KIND", classification=PROVENANCE_UNKNOWN, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
        if observation["source_digest"] != source["source_digest"] or observation["observer_id"] != expected["observer_id"] or observation["comparison_group"] != expected["comparison_group"]:
            return _review("OBSERVATION_SOURCE_IDENTITY_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
        if observation["cell_digest"] != cell["cell_digest"] or observation["source_id"] != cell["source_id"] or observation["observer_id"] != cell["observer_id"] or observation["epoch"] != cell["epoch"] or observation["observation_sequence"] != cell["observation_sequence"]:
            return _review("OBSERVATION_WINDOW_CELL_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
        if any(observation[field] != expected[field] for field in ("observation_id", "idempotency_key", "subject_digest", "scope_digest", "baseline_digest", "epoch")):
            return _review("OBSERVATION_CONTEXT_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
        if observation["s25r_projection_digest"] != actual_projection["projection_digest"]:
            return _review("OBSERVATION_PROJECTION_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
        if observation["observation_state"] == "PRESENT":
            if observation["freshness_status"] == "STALE":
                return _review("FRESHNESS_STALE", classification=PROVENANCE_STALE, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
            if observation["freshness_status"] == "FUTURE":
                return _review("FRESHNESS_FUTURE", classification=PROVENANCE_OUT_OF_WINDOW, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
            if observation["observation_sequence"] != expected["current_sequence"] or observation["receipt_digest"] != receipt_digests[kind] or observation["comparison_status"] != "COMPARABLE" or observation["freshness_status"] != "FRESH" or observation["coverage_status"] != "COMPLETE":
                return _review("RECEIPT_BINDING_MISMATCH", classification=PROVENANCE_CONFLICT, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
        else:
            if observation["receipt_digest"] is not None or observation["comparison_status"] == "COMPARABLE" or observation["coverage_status"] == "COMPLETE":
                return _blocked("PARTIAL_OBSERVATION_STATUS_INCONSISTENT", classification=PROVENANCE_PARTIAL, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
            if observation["observation_state"] in {"STALE", "FUTURE"} or observation["freshness_status"] in {"STALE", "FUTURE"}:
                return _review("FRESHNESS_STALE_OR_FUTURE", classification=PROVENANCE_STALE if observation["observation_state"] == "STALE" else PROVENANCE_OUT_OF_WINDOW, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
            return _blocked("PARTIAL_OBSERVATION", classification=PROVENANCE_PARTIAL, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
    if set(by_kind) != set(_REQUIRED_KINDS):
        return _blocked("PARTIAL_OBSERVATION", classification=PROVENANCE_PARTIAL, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
    if _observation_set_digest(observations) != expected["observation_set_digest"]:
        return _blocked("OBSERVATION_SET_BINDING_MISMATCH", s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
    if not all(observation["observation_state"] == "PRESENT" for observation in observations):
        return _blocked("PARTIAL_OBSERVATION", classification=PROVENANCE_PARTIAL, s25r_result=s25r_result, source_count=len(source_set["sources"]), observation_count=len(observations))
    return _output(
        PROVENANCE_WITNESS_RECONCILED,
        PROPOSAL_ONLY,
        DESIGN_ONLY,
        "READ_ONLY_PROVENANCE_WITNESS",
        s25r_result=s25r_result,
        provenance_status="COMPLETE",
        coverage_status="COMPLETE",
        freshness_status="FRESH",
        comparison_status="COMPARABLE",
        source_count=len(source_set["sources"]),
        observation_count=len(observations),
        witness_only=True,
        source_witnessed=True,
    )


def evaluate_receipt_provenance(case: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Evaluate provenance metadata fail-closed without external I/O or mutation."""

    try:
        return _evaluate(case)
    except Exception:
        return _invalid("CASE_UNREADABLE_OR_TOO_DEEP")


__all__ = [
    "CANONICALIZATION",
    "HARNESS_SCHEMA",
    "PROVENANCE_WITNESS_RECONCILED",
    "PROVENANCE_REJECTED",
    "PROVENANCE_PARTIAL",
    "PROVENANCE_UNKNOWN",
    "PROVENANCE_STALE",
    "PROVENANCE_OUT_OF_WINDOW",
    "PROVENANCE_CONFLICT",
    "S25R_REJECTED",
    "evaluate_receipt_provenance",
    "input_digest",
]
