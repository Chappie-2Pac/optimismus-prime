"""Pure verification of a bounded W4 tool-failure circuit.

The verifier consumes a sealed trace. It never reads ``tool-failures.jsonl``,
creates a gate, aborts a session, or starts a command. A future adapter may
translate the existing local guard's records into this explicit trace format.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .models import W4EvidenceError
from .w25_compat import _exact_int, _hash64, _mapping, _text


TRACE_SCHEMA = "w4-tool-trace.v1"
FAILURE_LIMIT = 2
CONSECUTIVE_FAILURE_LIMIT = 6


def _allowed_tools(value: Any) -> set[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64 or any(not isinstance(item, str) or not item for item in value):
        raise W4EvidenceError("loop_policy.allowed_tools: bounded string list required")
    if len(set(value)) != len(value):
        raise W4EvidenceError("loop_policy.allowed_tools: duplicate tool")
    return set(value)


def _failure_record(value: Any, label: str) -> dict[str, Any]:
    record = _mapping(value, label)
    call_seq = _exact_int(record.get("call_seq"), f"{label}.call_seq", minimum=1)
    turn_no = _exact_int(record.get("turn_no"), f"{label}.turn_no", minimum=1)
    tool = _text(record.get("tool"), f"{label}.tool")
    command_hash = _hash64(record.get("command_sha256"), f"{label}.command_sha256")
    error_class = _text(record.get("error_class"), f"{label}.error_class")
    count = _exact_int(record.get("count"), f"{label}.count", minimum=1)
    consecutive = _exact_int(record.get("consecutive"), f"{label}.consecutive", minimum=1)
    return {
        "call_seq": call_seq,
        "turn_no": turn_no,
        "tool": tool,
        "command_sha256": command_hash,
        "error_class": error_class,
        "count": count,
        "consecutive": consecutive,
    }


def verify_tool_trace(
    trace: Mapping[str, Any],
    *,
    identity: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify a W4 tool trace and return ``CLOSED`` or valid ``OPEN`` state.

    A circuit is validly open only when the trace contains the exact failure
    that reached either threshold and proves that no call followed the gate.
    A malformed or incomplete gate is evidence failure, not a safe stop.
    """

    trace = _mapping(trace, "tool_trace")
    if trace.get("schema") != TRACE_SCHEMA:
        raise W4EvidenceError("TOOL_TRACE_SCHEMA_UNSUPPORTED")
    identity = _mapping(identity, "identity")
    policy = _mapping(policy, "loop_policy")
    for field in ("run_id", "attempt_id", "capability_set_hash", "policy_hash", "budget_hash"):
        if trace.get(field) != identity.get(field):
            raise W4EvidenceError(f"tool_trace.{field}: binding drift")
    max_turns = _exact_int(policy.get("max_turns"), "loop_policy.max_turns", minimum=1)
    max_tool_calls = _exact_int(policy.get("max_tool_calls"), "loop_policy.max_tool_calls", minimum=0)
    allowed = _allowed_tools(policy.get("allowed_tools"))
    same_failure_limit = _exact_int(policy.get("same_failure_limit"), "loop_policy.same_failure_limit", minimum=1)
    consecutive_failure_limit = _exact_int(policy.get("consecutive_failure_limit"), "loop_policy.consecutive_failure_limit", minimum=1)
    if same_failure_limit != FAILURE_LIMIT or consecutive_failure_limit != CONSECUTIVE_FAILURE_LIMIT:
        raise W4EvidenceError("W4-S0 failure thresholds are immutable")
    calls = trace.get("calls")
    failures = trace.get("failures")
    if not isinstance(calls, list) or not isinstance(failures, list):
        raise W4EvidenceError("tool_trace.calls/failures: lists required")
    if len(calls) > max_tool_calls:
        raise W4EvidenceError("TOOL_BUDGET_EXCEEDED")
    parsed_failures = [_failure_record(item, f"tool_trace.failures[{index}]") for index, item in enumerate(failures)]
    by_call: dict[int, dict[str, Any]] = {}
    for item in parsed_failures:
        if item["call_seq"] in by_call:
            raise W4EvidenceError("duplicate tool failure call_seq")
        by_call[item["call_seq"]] = item
    per_fingerprint: dict[tuple[str, str], int] = {}
    consecutive = 0
    matched_failures: set[int] = set()
    trigger: dict[str, Any] | None = None
    normalized_calls: list[dict[str, Any]] = []
    for expected_seq, raw_call in enumerate(calls, 1):
        call = _mapping(raw_call, f"tool_trace.calls[{expected_seq - 1}]")
        call_seq = _exact_int(call.get("call_seq"), f"tool_trace.calls[{expected_seq - 1}].call_seq", minimum=1)
        if call_seq != expected_seq:
            raise W4EvidenceError("tool call sequence is not contiguous")
        turn_no = _exact_int(call.get("turn_no"), f"tool_trace.calls[{expected_seq - 1}].turn_no", minimum=1)
        if turn_no > max_turns:
            raise W4EvidenceError("TOOL_TURN_BUDGET_EXCEEDED")
        tool = _text(call.get("tool"), f"tool_trace.calls[{expected_seq - 1}].tool")
        if tool not in allowed:
            raise W4EvidenceError("TOOL_NOT_ALLOWLISTED")
        command_hash = _hash64(call.get("command_sha256"), f"tool_trace.calls[{expected_seq - 1}].command_sha256")
        outcome = call.get("outcome")
        if outcome not in {"success", "failure"}:
            raise W4EvidenceError("tool call outcome must be success or failure")
        if trigger is not None:
            raise W4EvidenceError("TOOL_CALL_AFTER_CIRCUIT_GATE")
        if outcome == "success":
            consecutive = 0
            # This mirrors the existing Prime guard's explicit successful
            # write/edit reset without treating arbitrary model text as proof.
            if tool in {"write", "edit"}:
                per_fingerprint.clear()
        else:
            failure = by_call.get(call_seq)
            if failure is None:
                raise W4EvidenceError("tool failure has no bound failure record")
            if failure["turn_no"] != turn_no or failure["tool"] != tool or failure["command_sha256"] != command_hash:
                raise W4EvidenceError("tool failure record binding drift")
            fingerprint = (command_hash, failure["error_class"])
            count = per_fingerprint.get(fingerprint, 0) + 1
            consecutive += 1
            if failure["count"] != count or failure["consecutive"] != consecutive:
                raise W4EvidenceError("tool failure threshold counters drift")
            per_fingerprint[fingerprint] = count
            matched_failures.add(call_seq)
            if count >= same_failure_limit or consecutive >= consecutive_failure_limit:
                trigger = {
                    "call_seq": call_seq,
                    "turn_no": turn_no,
                    "tool": tool,
                    "command_sha256": command_hash,
                    "error_class": failure["error_class"],
                    "count": count,
                    "consecutive": consecutive,
                }
        normalized_calls.append({"call_seq": call_seq, "turn_no": turn_no, "tool": tool, "command_sha256": command_hash, "outcome": outcome})
    if matched_failures != set(by_call):
        raise W4EvidenceError("unbound or missing tool failure record")
    gate = trace.get("gate")
    if trigger is None:
        if gate is not None:
            raise W4EvidenceError("tool circuit gate without threshold-triggering failure")
        status = "CLOSED"
    else:
        gate = _mapping(gate, "tool_trace.gate")
        for field in ("call_seq", "turn_no", "tool", "command_sha256", "error_class", "count", "consecutive"):
            if gate.get(field) != trigger[field]:
                raise W4EvidenceError(f"tool_trace.gate.{field}: trigger drift")
        _text(gate.get("reason"), "tool_trace.gate.reason")
        if len(calls) != trigger["call_seq"]:
            raise W4EvidenceError("tool calls exist after circuit gate")
        status = "OPEN"
    return {
        "status": status,
        "call_count": len(normalized_calls),
        "failure_count": len(parsed_failures),
        "last_consecutive": consecutive,
        "trigger": dict(trigger) if trigger is not None else None,
    }
