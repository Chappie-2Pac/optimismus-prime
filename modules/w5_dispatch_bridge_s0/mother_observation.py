"""Pure W5-S1 to Mother-session observation projection.

This module consumes an already verified W5 result and emits only bounded,
read-only context.  It does not verify a raw bridge bundle and it never
decides whether a run may continue.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

try:
    from .models import DispatchBridgeResult
except ImportError:  # Direct pinned-reader loading has no package context.
    DispatchBridgeResult = None  # type: ignore[assignment,misc]


OBSERVATION_SCHEMA = "w5-local-mother-observation-v1"
OBSERVATION_STATUSES = frozenset(
    {"BRIDGE_VERIFIED", "BLOCKED", "INCOMPATIBLE_SOURCE", "INVALID_EVIDENCE"}
)
RESULT_KEYS = frozenset({"status", "findings", "bridge", "replay", "accepted"})
OBSERVATION_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "identity",
        "state",
        "findings",
        "upstream_result_sha256",
        "source_attestation_hash",
        "permission",
        "acceptance_status",
        "external_action",
        "execution",
    }
)
EXECUTION_KEYS = frozenset({"process_start", "network", "acceptance", "next_card"})
IDENTITY_KEYS = frozenset({"run_id", "card_id", "attempt_id", "dispatch_id"})
STATE_KEYS = frozenset({"run", "card", "attempt", "dispatch"})
IDENTITY_ORDER = ("run_id", "card_id", "attempt_id", "dispatch_id")
STATE_ORDER = ("run", "card", "attempt", "dispatch")
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED_SOURCE_ATTESTATION_HASH = "d4d62852319ef50bfbc7090d57e8dea7d0252f02941412b855e89cd877a9db21"
MAX_STRING_LENGTH = 256
MAX_FINDINGS = 8

VERIFIED_STATE = {
    "run": "DISPATCHING",
    "card": "CLAIMED",
    "attempt": "STARTING",
    "dispatch": "EXECUTOR_ACKED",
}
BLOCKED_STATE = {
    "run": "DISPATCHING",
    "card": "CLAIMED",
    "attempt": "ADMITTED",
    "dispatch": "SPAWN_REQUESTED",
}
FALSE_EXECUTION = {
    "process_start": False,
    "network": False,
    "acceptance": False,
    "next_card": False,
}


class MotherObservationError(ValueError):
    """The bounded Mother observation is malformed or contradictory."""


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MotherObservationError(f"{label}: object required")
    return value


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    keys = set(value)
    if any(not isinstance(key, str) for key in keys):
        raise MotherObservationError(f"{label}: field names must be strings")
    missing = expected - keys
    extra = keys - expected
    if missing or extra:
        raise MotherObservationError(
            f"{label}: schema drift; missing={sorted(missing)} extra={sorted(extra)}"
        )


def _require_string(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > MAX_STRING_LENGTH
        or any(ord(char) < 32 for char in value)
    ):
        raise MotherObservationError(f"{label}: non-empty string required")
    return value


def _require_findings(value: Any, label: str) -> list[str]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_FINDINGS:
        raise MotherObservationError(f"{label}: list of strings required")
    return [_require_string(item, f"{label}[{index}]") for index, item in enumerate(value)]


def _require_sha256(value: Any, label: str) -> str:
    value = _require_string(value, label)
    if SHA256_HEX.fullmatch(value) is None:
        raise MotherObservationError(f"{label}: lowercase SHA256 hex required")
    return value


def _require_source_attestation_hash(value: Any, label: str) -> str:
    value = _require_sha256(value, label)
    if value != EXPECTED_SOURCE_ATTESTATION_HASH:
        raise MotherObservationError(f"{label}: W5-S1 source contract hash drift")
    return value


def _identity(bridge: Mapping[str, Any], label: str) -> dict[str, str]:
    result = {}
    for key in IDENTITY_ORDER:
        result[key] = _require_string(bridge.get(key), f"{label}.{key}")
    return result


def _state(value: Any, expected: Mapping[str, str], label: str) -> dict[str, str]:
    value = _require_mapping(value, label)
    _require_exact_keys(value, STATE_KEYS, label)
    result = {key: _require_string(value[key], f"{label}.{key}") for key in STATE_ORDER}
    if result != dict(expected):
        raise MotherObservationError(f"{label}: state does not match the W5 contract")
    return result


def _result_mapping(result: Any) -> dict[str, Any]:
    if DispatchBridgeResult is not None and type(result) is DispatchBridgeResult:
        result = {
            "status": result.status,
            "findings": list(result.findings),
            "bridge": result.bridge,
            "replay": result.replay,
            "accepted": result.accepted,
        }
    result = _require_mapping(result, "result")
    _require_exact_keys(result, RESULT_KEYS, "result")
    if type(result["accepted"]) is not bool or result["accepted"] is not False:
        raise MotherObservationError("result.accepted must be exactly false")
    if not isinstance(result["status"], str) or result["status"] not in OBSERVATION_STATUSES:
        raise MotherObservationError("result.status is unsupported")
    findings = _require_findings(result["findings"], "result.findings")
    bridge = result["bridge"]
    replay = result["replay"]
    if result["status"] in {"INCOMPATIBLE_SOURCE", "INVALID_EVIDENCE"}:
        if bridge is not None or replay is not None or not findings:
            raise MotherObservationError(
                "invalid/incompatible result must contain findings and no bridge/replay"
            )
    else:
        _require_mapping(bridge, "result.bridge")
        if result["status"] == "BRIDGE_VERIFIED" and not isinstance(replay, Mapping):
            raise MotherObservationError("verified result requires replay evidence")
        if result["status"] == "BLOCKED" and replay is not None:
            raise MotherObservationError("blocked result must not carry replay evidence")
    return {
        "status": result["status"],
        "findings": findings,
        "bridge": bridge,
        "replay": replay,
        "accepted": False,
    }


def _project_result(result: Any) -> dict[str, Any]:
    result = _result_mapping(result)
    status = result["status"]
    findings = result["findings"]
    upstream_result_sha256 = _canonical_hash(result)
    if status in {"INCOMPATIBLE_SOURCE", "INVALID_EVIDENCE"}:
        return {
            "schema_version": OBSERVATION_SCHEMA,
            "status": status,
            "identity": None,
            "state": None,
            "findings": findings,
            "upstream_result_sha256": upstream_result_sha256,
            "source_attestation_hash": None,
            "permission": "read_only",
            "acceptance_status": "pending",
            "external_action": False,
            "execution": dict(FALSE_EXECUTION),
        }

    bridge = _require_mapping(result["bridge"], "result.bridge")
    if status == "BRIDGE_VERIFIED":
        expected_bridge = frozenset(
            {
                "run_id",
                "card_id",
                "attempt_id",
                "dispatch_id",
                "controller_claim",
                "worker_claim",
                "process_ack",
                "state",
                "source_attestation_hash",
            }
        )
        _require_exact_keys(bridge, expected_bridge, "result.bridge")
        if bridge["controller_claim"] != "C2_DISPATCH_CLAIMED":
            raise MotherObservationError("result.bridge.controller_claim is not C2")
        _require_string(bridge["worker_claim"], "result.bridge.worker_claim")
        _require_string(bridge["process_ack"], "result.bridge.process_ack")
        state = _state(bridge["state"], VERIFIED_STATE, "result.bridge.state")
    else:
        expected_bridge = frozenset(
            {"run_id", "card_id", "attempt_id", "dispatch_id", "state", "source_attestation_hash"}
        )
        _require_exact_keys(bridge, expected_bridge, "result.bridge")
        if findings != ["ACK_NOT_CONFIRMED"]:
            raise MotherObservationError("blocked result findings must be exactly ACK_NOT_CONFIRMED")
        state = _state(bridge["state"], BLOCKED_STATE, "result.bridge.state")

    return {
        "schema_version": OBSERVATION_SCHEMA,
        "status": status,
        "identity": _identity(bridge, "result.bridge"),
        "state": state,
        "findings": findings,
        "upstream_result_sha256": upstream_result_sha256,
        "source_attestation_hash": _require_source_attestation_hash(
            bridge["source_attestation_hash"], "result.bridge.source_attestation_hash"
        ),
        "permission": "read_only",
        "acceptance_status": "pending",
        "external_action": False,
        "execution": dict(FALSE_EXECUTION),
    }


def build_mother_observation(result: Any) -> dict[str, Any]:
    """Project a verified W5-S1 result into bounded Mother context."""

    return verify_mother_observation(_project_result(result))


def verify_mother_observation(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and copy one serialized Mother observation."""

    value = _require_mapping(value, "observation")
    _require_exact_keys(value, OBSERVATION_KEYS, "observation")
    if value["schema_version"] != OBSERVATION_SCHEMA:
        raise MotherObservationError("observation schema unsupported")
    status = value["status"]
    if not isinstance(status, str) or status not in OBSERVATION_STATUSES:
        raise MotherObservationError("observation.status is unsupported")
    findings = _require_findings(value["findings"], "observation.findings")
    upstream_result_sha256 = _require_sha256(
        value["upstream_result_sha256"], "observation.upstream_result_sha256"
    )
    if value["permission"] != "read_only":
        raise MotherObservationError("observation.permission must be read_only")
    if value["acceptance_status"] != "pending":
        raise MotherObservationError("observation.acceptance_status must be pending")
    if type(value["external_action"]) is not bool or value["external_action"] is not False:
        raise MotherObservationError("observation.external_action must be exactly false")
    execution = _require_mapping(value["execution"], "observation.execution")
    _require_exact_keys(execution, EXECUTION_KEYS, "observation.execution")
    if any(type(execution[key]) is not bool or execution[key] is not False for key in EXECUTION_KEYS):
        raise MotherObservationError("observation.execution must be all false")

    identity = value["identity"]
    state = value["state"]
    source_hash = value["source_attestation_hash"]
    if status in {"INCOMPATIBLE_SOURCE", "INVALID_EVIDENCE"}:
        if identity is not None or state is not None or source_hash is not None or not findings:
            raise MotherObservationError("invalid/incompatible observation has unsafe context")
        identity_copy = None
        state_copy = None
        source_copy = None
    else:
        identity = _require_mapping(identity, "observation.identity")
        _require_exact_keys(identity, IDENTITY_KEYS, "observation.identity")
        identity_copy = {key: _require_string(identity[key], f"observation.identity.{key}") for key in IDENTITY_ORDER}
        expected = VERIFIED_STATE if status == "BRIDGE_VERIFIED" else BLOCKED_STATE
        state_copy = _state(state, expected, "observation.state")
        source_copy = _require_source_attestation_hash(source_hash, "observation.source_attestation_hash")
        if status == "BRIDGE_VERIFIED" and findings:
            raise MotherObservationError("verified observation must not contain findings")
        if status == "BLOCKED" and findings != ["ACK_NOT_CONFIRMED"]:
            raise MotherObservationError("blocked observation findings must be exactly ACK_NOT_CONFIRMED")

    return {
        "schema_version": OBSERVATION_SCHEMA,
        "status": status,
        "identity": identity_copy,
        "state": state_copy,
        "findings": findings,
        "upstream_result_sha256": upstream_result_sha256,
        "source_attestation_hash": source_copy,
        "permission": "read_only",
        "acceptance_status": "pending",
        "external_action": False,
        "execution": dict(FALSE_EXECUTION),
    }


__all__ = [
    "BLOCKED_STATE",
    "FALSE_EXECUTION",
    "MotherObservationError",
    "OBSERVATION_SCHEMA",
    "OBSERVATION_STATUSES",
    "VERIFIED_STATE",
    "build_mother_observation",
    "verify_mother_observation",
]
