"""Pure S25AG dual-renderer projection closure.

The boundary evaluates two already-materialized renderer observations against
an independent, deliberately small in-memory oracle.  It does not import or
execute either Chappie trainer, tokenizer, model, backend, or validator.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any


HARNESS_SCHEMA = "s25ag.dual-render.v1"
RECORD_FORMAT = HARNESS_SCHEMA

DUAL_RENDER_CLOSED = "DUAL_RENDER_CLOSED"
INPUT_INVALID = "INPUT_INVALID"
BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
RENDERER_OUTPUT_INVALID = "RENDERER_OUTPUT_INVALID"
BACKEND_DIVERGENCE = "BACKEND_DIVERGENCE"
FIELD_LOSS = "FIELD_LOSS"
WHITESPACE_DRIFT = "WHITESPACE_DRIFT"
UNICODE_DRIFT = "UNICODE_DRIFT"
TEMPLATE_DRIFT = "TEMPLATE_DRIFT"
SHARED_RENDER_DRIFT = "SHARED_RENDER_DRIFT"
FIELD_DRIFT = "FIELD_DRIFT"

PASS = "PASS"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
HOLD = "HOLD"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
NOT_CLAIMED = "NOT_CLAIMED"

MAX_INPUT_BYTES = 64 * 1024
MAX_JSON_DEPTH = 8
MAX_RECORD_STRING_BYTES = 16 * 1024
MAX_PROJECTION_BYTES = 64 * 1024

_RECORD_KEYS = frozenset({"format", "instruction", "input", "output"})
RESULT_KEYS = (
    "schema_version",
    "classification",
    "status",
    "decision",
    "reason",
    "transformers_match",
    "unsloth_match",
    "projections_equal",
    "production_status",
    "authority_claim",
)


class _DuplicateKey(ValueError):
    pass


class _InputInvalid(ValueError):
    pass


class _BudgetExceeded(ValueError):
    pass


class _RendererOutputInvalid(ValueError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise _InputInvalid(value)


def _has_surrogate(value: str) -> bool:
    return any("\ud800" <= char <= "\udfff" for char in value)


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
                raise _InputInvalid("json_depth")
        elif char in "]}":
            depth -= 1


def _parse(case: dict[str, Any] | bytes | str) -> Any:
    if type(case) is dict:
        return case
    if type(case) is bytes:
        if len(case) > MAX_INPUT_BYTES:
            raise _BudgetExceeded("input_bytes")
        try:
            text = case.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise _InputInvalid("utf8") from exc
        if text.startswith("\ufeff"):
            raise _InputInvalid("bom")
        _check_json_depth(text)
        try:
            return json.loads(
                text,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
            raise _InputInvalid("json") from exc
    if type(case) is str:
        if _has_surrogate(case):
            raise _InputInvalid("surrogate")
        try:
            encoded_size = len(case.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise _InputInvalid("utf8") from exc
        if encoded_size > MAX_INPUT_BYTES:
            raise _BudgetExceeded("input_bytes")
        if case.startswith("\ufeff"):
            raise _InputInvalid("bom")
        _check_json_depth(case)
        try:
            return json.loads(
                case,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
            raise _InputInvalid("json") from exc
    raise _InputInvalid("case_type")


def _text_size(value: str) -> int:
    if _has_surrogate(value):
        raise _InputInvalid("surrogate")
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise _InputInvalid("utf8") from exc


def _validate_record(value: Any) -> dict[str, str]:
    if type(value) is not dict or len(value) != len(_RECORD_KEYS):
        raise _InputInvalid("record_shape")

    keys: list[str] = []
    for key in value:
        if type(key) is not str:
            raise _InputInvalid("record_key_type")
        keys.append(key)
    if frozenset(keys) != _RECORD_KEYS:
        raise _InputInvalid("record_keys")

    record: dict[str, str] = {}
    total_bytes = 0
    for key in ("format", "instruction", "input", "output"):
        item = value[key]
        if type(item) is not str:
            raise _InputInvalid("record_value_type")
        size = _text_size(item)
        if size > MAX_RECORD_STRING_BYTES:
            raise _BudgetExceeded("record_string")
        total_bytes += size
        record[key] = item
    if total_bytes > MAX_INPUT_BYTES:
        raise _BudgetExceeded("record_bytes")

    if record["format"] != RECORD_FORMAT:
        raise _InputInvalid("format")
    instruction = record["instruction"]
    if not instruction or instruction[0].isspace() or instruction[-1].isspace():
        raise _InputInvalid("instruction_boundary")
    input_text = record["input"]
    if input_text and (input_text[0].isspace() or input_text[-1].isspace()):
        raise _InputInvalid("input_boundary")
    output = record["output"]
    if output and (output[0].isspace() or output[-1].isspace()):
        raise _InputInvalid("output_boundary")
    return record


def _validate_projection(value: Any) -> str:
    if type(value) is not str or value == "":
        raise _RendererOutputInvalid("projection_type_or_empty")
    size = _text_size(value)
    if size > MAX_PROJECTION_BYTES:
        raise _BudgetExceeded("projection_bytes")
    return value


def _render_values(instruction: str, input_text: str, output: str) -> str:
    rendered = "<s>[INST]\n" + instruction
    if input_text:
        rendered += "\n\n" + input_text
    rendered += "\n[/INST]"
    if output:
        rendered += output
    return rendered


def _oracle(record: dict[str, str]) -> str:
    """Return the independent raw projection for a validated record."""

    return _render_values(record["instruction"], record["input"], record["output"])


def _same_whitespace_shape(expected: str, actual: str) -> bool:
    def shape(value: str) -> str:
        value = value.replace("\r\n", "\n").replace("\r", "\n")
        return "".join("\x00" if char.isspace() else char for char in value)

    return shape(expected) == shape(actual)


def _unicode_equivalent(expected: str, actual: str) -> bool:
    try:
        return (
            unicodedata.normalize("NFC", expected) == unicodedata.normalize("NFC", actual)
            or unicodedata.normalize("NFD", expected) == unicodedata.normalize("NFD", actual)
        )
    except (TypeError, ValueError):
        return False


def _diagnose_shared_drift(expected: str, actual: str, record: dict[str, str]) -> tuple[str, str]:
    if _same_whitespace_shape(expected, actual):
        return WHITESPACE_DRIFT, "shared_projection_changed_whitespace"
    if _unicode_equivalent(expected, actual):
        return UNICODE_DRIFT, "shared_projection_changed_unicode_form"

    omitted_variants = (
        ("instruction", _render_values("", record["input"], record["output"])),
        ("input", _render_values(record["instruction"], "", record["output"])),
        ("output", _render_values(record["instruction"], record["input"], "")),
    )
    for field, omitted in omitted_variants:
        if record[field] and actual == omitted:
            return FIELD_LOSS, f"shared_projection_lost_{field}_field"
    if expected.startswith(actual):
        return FIELD_LOSS, "shared_projection_truncated_record_field"

    expected_without_output = _render_values(record["instruction"], record["input"], "")
    if actual.startswith(expected_without_output):
        return FIELD_DRIFT, "shared_projection_changed_output_field"

    prefix = "<s>[INST]\n"
    suffix = "\n[/INST]"
    expected_body = record["instruction"] + ("\n\n" + record["input"] if record["input"] else "")
    if actual.startswith(prefix) and actual.endswith(suffix + record["output"]):
        body_end = len(actual) - len(suffix + record["output"])
        actual_body = actual[len(prefix) : body_end]
        if record["input"] and actual_body == record["input"] + "\n\n" + record["instruction"]:
            return TEMPLATE_DRIFT, "shared_projection_reordered_record_fields"
        if actual_body != expected_body:
            return FIELD_DRIFT, "shared_projection_changed_record_field"

    if "[INST]" in actual or "[/INST]" in actual or actual.startswith("<s>"):
        return TEMPLATE_DRIFT, "shared_projection_changed_template"
    return SHARED_RENDER_DRIFT, "shared_projection_changed_render"


def _result(
    classification: str,
    reason: str,
    *,
    transformers_match: bool = False,
    unsloth_match: bool = False,
    projections_equal: bool = False,
) -> dict[str, Any]:
    positive = classification == DUAL_RENDER_CLOSED
    result = {
        "schema_version": HARNESS_SCHEMA,
        "classification": classification,
        "status": PASS if positive else TEST_BLOCKED,
        "decision": PROPOSAL_ONLY if positive else HOLD,
        "reason": reason,
        "transformers_match": transformers_match,
        "unsloth_match": unsloth_match,
        "projections_equal": projections_equal,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
    }
    assert tuple(result) == RESULT_KEYS
    return result


def evaluate_dual_renderer_case(
    case: dict[str, Any] | bytes | str,
    *,
    transformers_projection: Any,
    unsloth_projection: Any,
) -> dict[str, Any]:
    """Evaluate two supplied projections without importing or executing them."""

    try:
        parsed = _parse(case)
        record = _validate_record(parsed)
    except _BudgetExceeded:
        return _result(BUDGET_EXCEEDED, "input_budget_exceeded")
    except (_InputInvalid, TypeError, ValueError):
        return _result(INPUT_INVALID, "record_or_json_invalid")

    projection_errors: list[str] = []
    transformers: str | None = None
    unsloth: str | None = None
    try:
        transformers = _validate_projection(transformers_projection)
    except _BudgetExceeded:
        projection_errors.append("budget")
    except (_RendererOutputInvalid, TypeError, ValueError):
        projection_errors.append("invalid")
    try:
        unsloth = _validate_projection(unsloth_projection)
    except _BudgetExceeded:
        projection_errors.append("budget")
    except (_RendererOutputInvalid, TypeError, ValueError):
        projection_errors.append("invalid")
    if "budget" in projection_errors:
        return _result(BUDGET_EXCEEDED, "projection_budget_exceeded")
    if projection_errors:
        return _result(RENDERER_OUTPUT_INVALID, "renderer_projection_invalid")
    assert transformers is not None and unsloth is not None

    expected = _oracle(record)
    transformers_match = transformers == expected
    unsloth_match = unsloth == expected
    projections_equal = transformers == unsloth
    if not projections_equal:
        return _result(
            BACKEND_DIVERGENCE,
            "renderer_projections_differ",
            transformers_match=transformers_match,
            unsloth_match=unsloth_match,
            projections_equal=False,
        )
    if transformers_match:
        return _result(
            DUAL_RENDER_CLOSED,
            "both_projections_equal_independent_oracle",
            transformers_match=True,
            unsloth_match=True,
            projections_equal=True,
        )
    classification, reason = _diagnose_shared_drift(expected, transformers, record)
    return _result(
        classification,
        reason,
        transformers_match=False,
        unsloth_match=False,
        projections_equal=True,
    )

