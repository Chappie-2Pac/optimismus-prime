"""Pure S25AJ training-record field closure.

The boundary checks only four already-materialized fields from the public
Chappie training-record contract.  Optional metadata is bounded and opaque;
no validator, formatter, trainer, model, file, or network is imported.
"""

from __future__ import annotations

import json
import math
from typing import Any


HARNESS_SCHEMA = "s25aj.training-record.v1"
TRAINING_RECORD_CLOSED = "TRAINING_RECORD_CLOSED"
BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
INPUT_INVALID = "INPUT_INVALID"
TRAINING_MODE_INVALID = "TRAINING_MODE_INVALID"
OUTPUT_INVALID = "OUTPUT_INVALID"
INSTRUCTION_INVALID = "INSTRUCTION_INVALID"
INPUT_TEXT_INVALID = "INPUT_TEXT_INVALID"

PASS = "PASS"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

MAX_INPUT_BYTES = 64 * 1024
MAX_JSON_DEPTH = 8
MAX_CONTAINER_ITEMS = 256
MAX_CONTAINERS = 1024
MAX_NODES = 4096
MAX_STRING_BYTES = 16 * 1024
MAX_TOTAL_STRING_BYTES = 64 * 1024

RESULT_KEYS = (
    "schema_version",
    "classification",
    "status",
    "decision",
    "reason",
    "production_status",
    "authority_claim",
)

_REQUIRED_KEYS = frozenset({"training_mode", "instruction", "input", "output"})
_TRAINING_MODE = "self_supervised_continuation"
_REASONS = {
    TRAINING_RECORD_CLOSED: "training_record_closed",
    BUDGET_EXCEEDED: "budget_exceeded",
    INPUT_INVALID: "input_invalid",
    TRAINING_MODE_INVALID: "training_mode_invalid",
    OUTPUT_INVALID: "output_invalid",
    INSTRUCTION_INVALID: "instruction_invalid",
    INPUT_TEXT_INVALID: "input_text_invalid",
}


class _Failure(Exception):
    def __init__(self, classification: str) -> None:
        super().__init__(classification)
        self.classification = classification


def _input_failure() -> None:
    raise _Failure(INPUT_INVALID)


def _budget_failure() -> None:
    raise _Failure(BUDGET_EXCEEDED)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _input_failure()
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    _input_failure()


def _parse_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        _input_failure()
    return parsed


def _bounded_utf8_size(value: str, limit: int) -> tuple[int, bool]:
    size = 0
    for char in value:
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            return size, True
        if codepoint <= 0x7F:
            size += 1
        elif codepoint <= 0x7FF:
            size += 2
        elif codepoint <= 0xFFFF:
            size += 3
        else:
            size += 4
        if size > limit:
            return size, False
    return size, False


def _string_bytes(value: str) -> int:
    size, invalid = _bounded_utf8_size(value, MAX_INPUT_BYTES)
    if invalid:
        _input_failure()
    if size > MAX_INPUT_BYTES:
        _budget_failure()
    return size


def _check_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
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
                _budget_failure()
        elif char in "]}":
            depth -= 1
            if depth < 0:
                _input_failure()
    if in_string or escaped or depth != 0:
        _input_failure()


def _parse_record(record: dict[str, Any] | bytes | str) -> Any:
    if type(record) is dict:
        return record
    if type(record) is bytes:
        if len(record) > MAX_INPUT_BYTES:
            _budget_failure()
        try:
            text = record.decode("utf-8", "strict")
        except UnicodeDecodeError:
            _input_failure()
    elif type(record) is str:
        _string_bytes(record)
        text = record
    else:
        _input_failure()

    if text.startswith("\ufeff"):
        _input_failure()
    _check_json_depth(text)
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
    except _Failure:
        raise
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        _input_failure()
    raise AssertionError("unreachable")


class _SnapshotBudget:
    def __init__(self) -> None:
        self.nodes = 0
        self.containers = 0
        self.string_bytes = 0
        self.container_ids: set[int] = set()
        self.invalid = False

    def node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            _budget_failure()

    def invalid_input(self) -> None:
        self.invalid = True

    def container(self, value: dict[Any, Any] | list[Any]) -> bool:
        identity = id(value)
        if identity in self.container_ids:
            self.invalid_input()
            return False
        self.container_ids.add(identity)
        self.containers += 1
        if self.containers > MAX_CONTAINERS:
            _budget_failure()
        return True

    def string(self, value: str) -> str:
        size, invalid = _bounded_utf8_size(value, MAX_STRING_BYTES)
        if size > MAX_STRING_BYTES:
            _budget_failure()
        if invalid:
            self.invalid_input()
            return ""
        self.string_bytes += size
        if self.string_bytes > MAX_TOTAL_STRING_BYTES:
            _budget_failure()
        return value


def _snapshot(value: Any, state: _SnapshotBudget, depth: int) -> Any:
    if type(value) is dict:
        if depth > MAX_JSON_DEPTH:
            _budget_failure()
        if len(value) > MAX_CONTAINER_ITEMS:
            _budget_failure()
        state.node()
        if not state.container(value):
            return {}
        result: dict[str, Any] = {}
        for key, item in value.items():
            state.node()
            if type(key) is not str:
                state.invalid_input()
                _snapshot(item, state, depth + 1)
                continue
            key_copy = state.string(key)
            if key_copy in result:
                state.invalid_input()
                _snapshot(item, state, depth + 1)
                continue
            result[key_copy] = _snapshot(item, state, depth + 1)
        return result

    if type(value) is list:
        if depth > MAX_JSON_DEPTH:
            _budget_failure()
        if len(value) > MAX_CONTAINER_ITEMS:
            _budget_failure()
        state.node()
        if not state.container(value):
            return []
        return [_snapshot(item, state, depth + 1) for item in value]

    if type(value) is str:
        state.node()
        return state.string(value)

    if type(value) is int or type(value) is bool or value is None:
        state.node()
        return value

    if type(value) is float:
        state.node()
        if not math.isfinite(value):
            state.invalid_input()
            return 0.0
        return value

    state.node()
    state.invalid_input()
    return None


def _validate_record_structure(value: Any) -> dict[str, Any]:
    if type(value) is not dict or not _REQUIRED_KEYS.issubset(value):
        _input_failure()
    for key in _REQUIRED_KEYS:
        if type(value[key]) is not str:
            _input_failure()
    return value


def _result(classification: str) -> dict[str, str]:
    positive = classification == TRAINING_RECORD_CLOSED
    return {
        "schema_version": HARNESS_SCHEMA,
        "classification": classification,
        "status": PASS if positive else TEST_BLOCKED,
        "decision": PROPOSAL_ONLY if positive else HOLD,
        "reason": _REASONS[classification],
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
    }


def evaluate_training_record_case(record: dict[str, Any] | bytes | str) -> dict[str, str]:
    """Evaluate the bounded, actionless four-field training contract."""

    try:
        parsed = _parse_record(record)
        state = _SnapshotBudget()
        snapshot = _snapshot(parsed, state, 1)
        if state.invalid:
            _input_failure()
        value = _validate_record_structure(snapshot)
        if value["training_mode"] != _TRAINING_MODE:
            raise _Failure(TRAINING_MODE_INVALID)
        if value["output"] != "":
            raise _Failure(OUTPUT_INVALID)
        if not value["instruction"].strip():
            raise _Failure(INSTRUCTION_INVALID)
        if not value["input"].strip():
            raise _Failure(INPUT_TEXT_INVALID)
        return _result(TRAINING_RECORD_CLOSED)
    except _Failure as failure:
        return _result(failure.classification)

