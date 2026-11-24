"""Pure, bounded S25AL memory-layer first-match relation."""

from __future__ import annotations


SCHEMA_VERSION = "s25al.memory-layer-first-match.v1"
MEMORY_LAYER_FIRST_MATCH_CLOSED = "MEMORY_LAYER_FIRST_MATCH_CLOSED"
INPUT_INVALID = "INPUT_INVALID"

PASS = "PASS"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

RESULT_KEYS = (
    "schema_version",
    "classification",
    "status",
    "decision",
    "reason",
    "selected_layer",
    "production_status",
    "authority_claim",
)

_STM_KEY = "stm_present"
_MTM_KEY = "mtm_present"
_LTM_KEY = "ltm_present"


def _result(classification: str, selected_layer: str = "") -> dict[str, str]:
    is_valid = classification == MEMORY_LAYER_FIRST_MATCH_CLOSED
    return {
        "schema_version": SCHEMA_VERSION,
        "classification": classification,
        "status": PASS if is_valid else TEST_BLOCKED,
        "decision": PROPOSAL_ONLY if is_valid else HOLD,
        "reason": "first_match_resolved" if is_valid else "input_invalid",
        "selected_layer": selected_layer if is_valid else "",
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
    }


def evaluate_memory_layer_first_match_case(case: object) -> dict[str, str]:
    """Evaluate only a bounded, already-materialized layer-presence snapshot."""

    # Reject subclasses before invoking any user-overridable container method.
    if type(case) is not dict:
        return _result(INPUT_INVALID)
    if len(case) != 3:
        return _result(INPUT_INVALID)

    # Validate every key before any membership comparison or fixed lookup.
    # A non-builtin key can carry hostile __hash__/__eq__ behavior.
    for key in case:
        if type(key) is not str:
            return _result(INPUT_INVALID)
        if key != _STM_KEY and key != _MTM_KEY and key != _LTM_KEY:
            return _result(INPUT_INVALID)

    # With exactly three distinct builtin string keys, the checks above imply
    # that all three required keys are present exactly once.
    stm_present = case[_STM_KEY]
    mtm_present = case[_MTM_KEY]
    ltm_present = case[_LTM_KEY]
    if type(stm_present) is not bool:
        return _result(INPUT_INVALID)
    if type(mtm_present) is not bool:
        return _result(INPUT_INVALID)
    if type(ltm_present) is not bool:
        return _result(INPUT_INVALID)

    if stm_present:
        selected_layer = "stm"
    elif mtm_present:
        selected_layer = "mtm"
    elif ltm_present:
        selected_layer = "ltm"
    else:
        selected_layer = "none"
    return _result(MEMORY_LAYER_FIRST_MATCH_CLOSED, selected_layer)
