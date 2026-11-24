"""Pure S25AI knowledge-order closure.

This module evaluates only the bounded token/score/order projection of the
public local knowledge retrieval relation.  It intentionally does not import
the retrieval implementation and never performs I/O, persistence, or source
attestation.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any


HARNESS_SCHEMA = "s25ai.knowledge-order.v1"
CANONICALIZATION = "NFKC_CASEFOLD_WORD_STOPWORD_V1"

KNOWLEDGE_ORDER_CLOSED = "KNOWLEDGE_ORDER_CLOSED"
BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
INPUT_INVALID = "INPUT_INVALID"
QUERY_EMPTY = "QUERY_EMPTY"
ENTRY_INVALID = "ENTRY_INVALID"
OBSERVATION_INVALID = "OBSERVATION_INVALID"
HIT_SET_DRIFT = "HIT_SET_DRIFT"
SCORE_DRIFT = "SCORE_DRIFT"
ORDER_DRIFT = "ORDER_DRIFT"

PASS = "PASS"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

MAX_INPUT_BYTES = 64 * 1024
MAX_JSON_DEPTH = 8
MAX_CONTAINER_ITEMS = 256
MAX_NODES = 4096
MAX_ENTRIES = 128
MAX_TAGS = 32
MAX_HITS = 3
MAX_STRING_BYTES = 16 * 1024
MAX_TOTAL_STRING_BYTES = 64 * 1024
MAX_SCORE = (MAX_STRING_BYTES // 3) * 5 + 10

RESULT_KEYS = (
    "schema_version",
    "canonicalization",
    "classification",
    "status",
    "decision",
    "reason",
    "expected_hit_count",
    "observed_hit_count",
    "top_k",
    "production_status",
    "authority_claim",
)

_ROOT_KEYS = frozenset({"query", "entries"})
_ENTRY_KEYS = frozenset({"id", "title", "tags", "selected_text"})
_OBSERVATION_KEYS = frozenset({"id", "score"})
_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_TOKEN_RE = re.compile(r"[\w]+")
_STOP = frozenset(
    "der die das und oder mit von fuer für eine einen einer ein den dem des "
    "ist sind im in als auf aus zu zur zum nur nicht nach vor dieser diese "
    "dieses werden wird kann bitte karte task lokal plan build".split()
)

_REASON = {
    KNOWLEDGE_ORDER_CLOSED: "knowledge_order_closed",
    BUDGET_EXCEEDED: "budget_exceeded",
    INPUT_INVALID: "input_invalid",
    QUERY_EMPTY: "query_empty",
    ENTRY_INVALID: "entry_invalid",
    OBSERVATION_INVALID: "observation_invalid",
    HIT_SET_DRIFT: "hit_set_drift",
    SCORE_DRIFT: "score_drift",
    ORDER_DRIFT: "order_drift",
}


class _Failure(Exception):
    def __init__(self, classification: str) -> None:
        super().__init__(classification)
        self.classification = classification


def _fail_input() -> None:
    raise _Failure(INPUT_INVALID)


def _fail_budget() -> None:
    raise _Failure(BUDGET_EXCEEDED)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail_input()
        result[key] = value
    return result


def _reject_json_number(_value: str) -> None:
    _fail_input()


def _has_surrogate(value: str) -> bool:
    return any("\ud800" <= char <= "\udfff" for char in value)


def _string_bytes(value: str) -> int:
    if _has_surrogate(value):
        _fail_input()
    try:
        return len(value.encode("utf-8", "strict"))
    except UnicodeEncodeError:
        _fail_input()
    raise AssertionError("unreachable")


def _check_json_depth(value: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in value:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail_budget()
        elif char in "]}":
            depth -= 1
            if depth < 0:
                _fail_input()


def _parse_case(case: dict[str, Any] | bytes | str) -> Any:
    if type(case) is dict:
        return case

    if type(case) is bytes:
        if len(case) > MAX_INPUT_BYTES:
            _fail_budget()
        try:
            text = case.decode("utf-8", "strict")
        except UnicodeDecodeError:
            _fail_input()
    elif type(case) is str:
        if _has_surrogate(case):
            _fail_input()
        if _string_bytes(case) > MAX_INPUT_BYTES:
            _fail_budget()
        text = case
    else:
        _fail_input()

    if text.startswith("\ufeff"):
        _fail_input()
    _check_json_depth(text)
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
    except _Failure:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        _fail_input()
    raise AssertionError("unreachable")


class _SnapshotBudget:
    def __init__(self) -> None:
        self.nodes = 0
        self.string_bytes = 0
        self.container_ids: set[int] = set()

    def node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            _fail_budget()

    def string(self, value: str) -> str:
        size = _string_bytes(value)
        if size > MAX_STRING_BYTES:
            _fail_budget()
        self.string_bytes += size
        if self.string_bytes > MAX_TOTAL_STRING_BYTES:
            _fail_budget()
        return value

    def container(self, value: dict[Any, Any] | list[Any]) -> None:
        identity = id(value)
        if identity in self.container_ids:
            _fail_input()
        self.container_ids.add(identity)


def _snapshot(value: Any, state: _SnapshotBudget, depth: int) -> Any:
    if type(value) is dict:
        if depth > MAX_JSON_DEPTH:
            _fail_budget()
        if len(value) > MAX_CONTAINER_ITEMS:
            _fail_budget()
        state.node()
        state.container(value)
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                _fail_input()
            state.node()
            key_copy = state.string(key)
            if key_copy in result:
                _fail_input()
            result[key_copy] = _snapshot(item, state, depth + 1)
        return result

    if type(value) is list:
        if depth > MAX_JSON_DEPTH:
            _fail_budget()
        if len(value) > MAX_CONTAINER_ITEMS:
            _fail_budget()
        state.node()
        state.container(value)
        return [_snapshot(item, state, depth + 1) for item in value]

    if type(value) is str:
        state.node()
        return state.string(value)

    if type(value) is int:
        state.node()
        return value

    _fail_input()
    raise AssertionError("unreachable")


def _tokens(text: str) -> set[str]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return {token for token in _TOKEN_RE.findall(normalized) if len(token) > 2 and token not in _STOP}


def _validate_case_structure(root: Any) -> tuple[str, list[dict[str, Any]]]:
    if type(root) is not dict or len(root) != len(_ROOT_KEYS) or frozenset(root) != _ROOT_KEYS:
        _fail_input()
    query = root["query"]
    entries = root["entries"]
    if type(query) is not str or type(entries) is not list:
        _fail_input()
    if len(entries) > MAX_ENTRIES:
        _fail_budget()

    for entry in entries:
        if type(entry) is not dict or len(entry) != len(_ENTRY_KEYS) or frozenset(entry) != _ENTRY_KEYS:
            _fail_input()
        if type(entry["id"]) is not str or type(entry["title"]) is not str:
            _fail_input()
        if type(entry["tags"]) is not list:
            _fail_input()
        if type(entry["selected_text"]) is not str:
            _fail_input()
        if any(type(tag) is not str for tag in entry["tags"]):
            _fail_input()
    return query, entries


def _validate_entry_semantics(entries: list[dict[str, Any]]) -> set[str]:
    if not entries:
        raise _Failure(ENTRY_INVALID)
    known_ids: set[str] = set()
    for entry in entries:
        entry_id = entry["id"]
        title = entry["title"]
        tags = entry["tags"]
        if not _ID_RE.fullmatch(entry_id) or entry_id in known_ids:
            raise _Failure(ENTRY_INVALID)
        known_ids.add(entry_id)
        if _string_bytes(title) > 120 or any(ord(char) < 0x20 for char in title):
            raise _Failure(ENTRY_INVALID)
        if len(tags) > MAX_TAGS:
            raise _Failure(ENTRY_INVALID)
        if any(_string_bytes(tag) > 64 for tag in tags):
            raise _Failure(ENTRY_INVALID)
    return known_ids


def _oracle(query: str, entries: list[dict[str, Any]]) -> list[dict[str, int | str]]:
    wanted = _tokens(query)
    candidates: list[dict[str, int | str]] = []
    for entry in entries:
        tag_title_tokens = _tokens(" ".join(entry["tags"]) + " " + entry["title"])
        tag_title_score = len(wanted & tag_title_tokens) * 5
        if not tag_title_score:
            continue
        content_score = len(wanted & _tokens(entry["selected_text"]))
        candidates.append(
            {
                "id": entry["id"],
                "score": tag_title_score + min(content_score, 10),
            }
        )
    candidates.sort(key=lambda hit: (-int(hit["score"]), str(hit["id"])))
    return candidates[:MAX_HITS]


def _validate_observed(
    observed_hits: Any,
    known_ids: set[str],
) -> list[dict[str, int | str]]:
    if type(observed_hits) is not list:
        _fail_input()
    if len(observed_hits) > MAX_HITS:
        _fail_budget()
    result: list[dict[str, int | str]] = []
    seen: set[str] = set()
    for hit in observed_hits:
        if type(hit) is not dict or len(hit) != len(_OBSERVATION_KEYS) or frozenset(hit) != _OBSERVATION_KEYS:
            raise _Failure(OBSERVATION_INVALID)
        hit_id = hit["id"]
        score = hit["score"]
        if type(hit_id) is not str or not _ID_RE.fullmatch(hit_id):
            raise _Failure(OBSERVATION_INVALID)
        if hit_id not in known_ids or hit_id in seen:
            raise _Failure(OBSERVATION_INVALID)
        if type(score) is not int or score < 0 or score > MAX_SCORE:
            raise _Failure(OBSERVATION_INVALID)
        seen.add(hit_id)
        result.append({"id": hit_id, "score": score})
    return result


def _result(
    classification: str,
    *,
    expected_hit_count: int = 0,
    observed_hit_count: int = 0,
) -> dict[str, Any]:
    positive = classification == KNOWLEDGE_ORDER_CLOSED
    return {
        "schema_version": HARNESS_SCHEMA,
        "canonicalization": CANONICALIZATION,
        "classification": classification,
        "status": PASS if positive else TEST_BLOCKED,
        "decision": PROPOSAL_ONLY if positive else HOLD,
        "reason": _REASON[classification],
        "expected_hit_count": expected_hit_count if positive else 0,
        "observed_hit_count": observed_hit_count if positive else 0,
        "top_k": MAX_HITS,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
    }


def evaluate_knowledge_order_case(
    case: dict[str, Any] | bytes | str,
    *,
    observed_hits: list[dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate the bounded, actionless knowledge-order relation."""

    try:
        # A hit-list overflow is a budget error before any lower-priority
        # semantic or observation diagnosis, including malformed case input.
        if type(observed_hits) is list and len(observed_hits) > MAX_HITS:
            _fail_budget()

        parsed_case = _parse_case(case)
        budget = _SnapshotBudget()
        case_snapshot = _snapshot(parsed_case, budget, 1)
        observed_snapshot = _snapshot(observed_hits, budget, 1)

        query, entries = _validate_case_structure(case_snapshot)
        if not _tokens(query):
            raise _Failure(QUERY_EMPTY)
        known_ids = _validate_entry_semantics(entries)
        expected = _oracle(query, entries)
        observed = _validate_observed(observed_snapshot, known_ids)

        expected_ids = [str(hit["id"]) for hit in expected]
        observed_ids = [str(hit["id"]) for hit in observed]
        if set(expected_ids) != set(observed_ids):
            raise _Failure(HIT_SET_DRIFT)

        expected_by_id = {str(hit["id"]): int(hit["score"]) for hit in expected}
        observed_by_id = {str(hit["id"]): int(hit["score"]) for hit in observed}
        if any(expected_by_id[entry_id] != observed_by_id[entry_id] for entry_id in expected_by_id):
            raise _Failure(SCORE_DRIFT)
        if expected_ids != observed_ids:
            raise _Failure(ORDER_DRIFT)

        return _result(
            KNOWLEDGE_ORDER_CLOSED,
            expected_hit_count=len(expected),
            observed_hit_count=len(observed),
        )
    except _Failure as failure:
        return _result(failure.classification)
    except Exception:
        # The public boundary is fail-closed even if an unexpected built-in
        # parser/type edge case is introduced later.
        return _result(INPUT_INVALID)

