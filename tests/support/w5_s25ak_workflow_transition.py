"""Pure, bounded S25AK workflow-lifecycle transition relation."""

from __future__ import annotations

from typing import Any


SCHEMA_VERSION = "s25ak.workflow-transition.v1"
VALID_TRANSITION = "VALID_TRANSITION"
IDEMPOTENT_NOOP = "IDEMPOTENT_NOOP"
INVALID_TRANSITION = "INVALID_TRANSITION"
INPUT_INVALID = "INPUT_INVALID"

PASS = "PASS"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

MAX_STRING_BYTES = 64

RESULT_KEYS = (
    "schema_version",
    "classification",
    "status",
    "decision",
    "reason",
    "next_state",
    "production_status",
    "authority_claim",
)

_VALID_STATES = frozenset({"created", "running", "paused", "completed", "failed", "cancelled"})
_VALID_OPERATIONS = frozenset({"start", "pause", "resume", "cancel", "fail", "complete"})

_MATRIX: dict[str, dict[str, tuple[str, str]]] = {
    "created": {
        "start": (VALID_TRANSITION, "running"),
        "pause": (INVALID_TRANSITION, ""),
        "resume": (INVALID_TRANSITION, ""),
        "cancel": (VALID_TRANSITION, "cancelled"),
        "fail": (VALID_TRANSITION, "failed"),
        "complete": (INVALID_TRANSITION, ""),
    },
    "running": {
        "start": (INVALID_TRANSITION, ""),
        "pause": (VALID_TRANSITION, "paused"),
        "resume": (INVALID_TRANSITION, ""),
        "cancel": (VALID_TRANSITION, "cancelled"),
        "fail": (VALID_TRANSITION, "failed"),
        "complete": (VALID_TRANSITION, "completed"),
    },
    "paused": {
        "start": (INVALID_TRANSITION, ""),
        "pause": (INVALID_TRANSITION, ""),
        "resume": (VALID_TRANSITION, "running"),
        "cancel": (VALID_TRANSITION, "cancelled"),
        "fail": (VALID_TRANSITION, "failed"),
        "complete": (INVALID_TRANSITION, ""),
    },
    "completed": {
        "start": (INVALID_TRANSITION, ""),
        "pause": (INVALID_TRANSITION, ""),
        "resume": (INVALID_TRANSITION, ""),
        "cancel": (IDEMPOTENT_NOOP, "completed"),
        "fail": (VALID_TRANSITION, "failed"),
        "complete": (INVALID_TRANSITION, ""),
    },
    "failed": {
        "start": (INVALID_TRANSITION, ""),
        "pause": (INVALID_TRANSITION, ""),
        "resume": (INVALID_TRANSITION, ""),
        "cancel": (VALID_TRANSITION, "cancelled"),
        "fail": (VALID_TRANSITION, "failed"),
        "complete": (INVALID_TRANSITION, ""),
    },
    "cancelled": {
        "start": (INVALID_TRANSITION, ""),
        "pause": (INVALID_TRANSITION, ""),
        "resume": (INVALID_TRANSITION, ""),
        "cancel": (IDEMPOTENT_NOOP, "cancelled"),
        "fail": (VALID_TRANSITION, "failed"),
        "complete": (INVALID_TRANSITION, ""),
    },
}

_REASONS = {
    VALID_TRANSITION: "valid_transition",
    IDEMPOTENT_NOOP: "idempotent_noop",
    INVALID_TRANSITION: "invalid_transition",
    INPUT_INVALID: "input_invalid",
}


def _bounded_utf8_ok(value: str) -> bool:
    size = 0
    for char in value:
        codepoint = ord(char)
        if 0xD800 <= codepoint <= 0xDFFF:
            return False
        if codepoint <= 0x7F:
            size += 1
        elif codepoint <= 0x7FF:
            size += 2
        elif codepoint <= 0xFFFF:
            size += 3
        else:
            size += 4
        if size > MAX_STRING_BYTES:
            return False
    return True


def _result(classification: str, next_state: str = "") -> dict[str, str]:
    positive = classification in {VALID_TRANSITION, IDEMPOTENT_NOOP}
    return {
        "schema_version": SCHEMA_VERSION,
        "classification": classification,
        "status": PASS if positive else TEST_BLOCKED,
        "decision": PROPOSAL_ONLY if positive else HOLD,
        "reason": _REASONS[classification],
        "next_state": next_state,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
    }


def evaluate_workflow_transition_case(state: Any, operation: Any) -> dict[str, str]:
    """Evaluate only the bounded Chappie state/operation relation."""

    if type(state) is not str or type(operation) is not str:
        return _result(INPUT_INVALID)
    if not _bounded_utf8_ok(state) or not _bounded_utf8_ok(operation):
        return _result(INPUT_INVALID)
    if state not in _VALID_STATES or operation not in _VALID_OPERATIONS:
        return _result(INVALID_TRANSITION)
    classification, next_state = _MATRIX[state][operation]
    return _result(classification, next_state)
