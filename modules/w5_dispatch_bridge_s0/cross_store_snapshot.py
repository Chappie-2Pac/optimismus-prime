"""W5-S13 pure adapter for independently frozen Cross-Store observations.

S13 is an envelope gate, not a live reader.  A separately reviewed capture
layer may read SQLite, Queue or Prime files, but this module accepts only its
serialised frozen result.  It verifies source identity, a common capture
barrier, two samples per participant, source cursors, full S11 contract
semantics, replay metadata, independent fencing and actionless safety before
projecting the observations into the W5-S12 fixture classifier.

No SQLite, filesystem, Queue, Prime, process, network, lock, recovery or
mutation API is imported or called here.  A successful result proves only
that the submitted envelope is internally coherent and bound to S12; it
never proves live truth or Cross-Store atomicity.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Mapping

from modules.w4_small_loop_s0 import canonical_hash

from .cross_store_fixture import (
    CROSS_STORE_PARTICIPANT_IDS,
    CrossStoreFixtureError,
    build_cross_store_fixture,
    classify_cross_store_fixture,
)
from .prime_transaction_authority import (
    PrimeTransactionAuthorityError,
    verify_authoritative_transaction_contract,
)


CROSS_STORE_SNAPSHOT_SCHEMA = "prime-cross-store-observation-v1"
CROSS_STORE_SNAPSHOT_VERIFICATION_SCHEMA = "prime-cross-store-adapter-verification-v1"
CROSS_STORE_SNAPSHOT_ROLE = "cross_store_snapshot_adapter_read_only"
SNAPSHOT_PARTICIPANT_IDS = CROSS_STORE_PARTICIPANT_IDS

OBSERVER_KEYS = frozenset({"observer_id", "observer_instance_id", "implementation_id", "mode"})
SOURCE_KEYS = frozenset(
    {
        "participant_id",
        "source_kind",
        "source_id",
        "source_instance_id",
        "source_schema",
        "snapshot_id",
        "snapshot_mode",
        "source_identity_sha256",
    }
)
CURSOR_KEYS = frozenset({"cursor_id", "version", "generation", "generation_id", "journal_sha256"})
S12_LEASE_KEYS = frozenset({"owner_id", "token_sha256", "issued_at", "observed_at", "expires_at", "fencing_epoch"})
SAMPLE_KEYS = frozenset({"participant_id", "source_identity_sha256", "snapshot_id", "source_cursor", "projection"})
EVENT_KEYS = frozenset(
    {"ordinal", "participant_id", "pass", "source_identity_sha256", "observation_sha256", "clock_sample_id"}
)
CAPTURE_KEYS = frozenset(
    {
        "capture_id",
        "sequence_domain",
        "sequence_no",
        "barrier_id",
        "clock_domain_id",
        "clock_sample_id",
        "clock_before",
        "clock_after",
        "source_set_sha256",
        "events",
        "stable",
        "read_only",
        "external_action",
        "execution",
    }
)
OBSERVATION_KEYS = frozenset(
    {
        "source_id",
        "snapshot_id",
        "source_identity_sha256",
        "sample_a",
        "sample_b",
        "source_cursor",
        "source_cursor_sha256",
        "observed",
        "observed_sha256",
        "content_sha256",
        "read_only",
    }
)
MANIFEST_PARTICIPANT_KEYS = frozenset({"before", "after", "target_id"})
MANIFEST_KEYS = frozenset(
    {"schema_version", "contract_digest", "precondition_plan_sha256", "participants", "manifest_sha256"}
)
REPLAY_KEYS = frozenset(
    {
        "registry_source_id",
        "idempotency_key",
        "transaction_id",
        "contract_digest",
        "subject_binding_digest",
        "status",
        "conflict",
        "observation_sha256",
    }
)
FENCE_KEYS = frozenset(
    {
        "owner_id",
        "worker_id",
        "token_sha256",
        "fencing_epoch",
        "issued_at",
        "expires_at",
        "clock_domain_id",
        "fence_cursor",
        "fence_observation_sha256",
    }
)
S12_INPUT_KEYS = frozenset(
    {
        "contract_material",
        "subject_binding_material",
        "effect_set",
        "marker_material",
        "lease",
        "hook_trace",
        "fault_hook_or_null",
    }
)
SAFETY_KEYS = frozenset(
    {
        "read_only",
        "lock_acquired",
        "lock_held",
        "reservation",
        "mutation_performed",
        "authoritative_commit",
        "recovery_invoked",
        "process_started",
        "process_stopped",
        "network_used",
        "external_action",
    }
)
SNAPSHOT_KEYS = frozenset(
    {
        "schema_version",
        "contract_role",
        "transaction_id",
        "observer",
        "sources",
        "source_set",
        "source_set_sha256",
        "expected_projection_manifest",
        "capture",
        "observations",
        "fence",
        "replay",
        "s12_input",
        "safety",
    }
)
BUILDER_CAPTURE_KEYS = frozenset(
    {
        "capture_id",
        "sequence_domain",
        "sequence_no",
        "barrier_id",
        "clock_domain_id",
        "clock_sample_id",
        "clock_before",
        "clock_after",
    }
)
BUILDER_SAMPLE_KEYS = frozenset(
    {"source_id", "snapshot_id", "source_identity_sha256", "source_cursor", "projection", "read_only"}
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EXECUTION_KEYS = frozenset({"resume", "reconcile", "mutation", "network"})
_RECOVERY_CODES = frozenset(
    {
        "SNAPSHOT_SOURCE_DRIFT",
        "SNAPSHOT_TOCTOU_DETECTED",
        "SNAPSHOT_FENCE_DRIFT",
        "SNAPSHOT_LEASE_EXPIRED",
        "SNAPSHOT_CAPTURE_COHORT_INVALID",
    }
)
SNAPSHOT_ERROR_CODES = frozenset(
    {
        "SNAPSHOT_NOT_OBSERVED",
        "SNAPSHOT_JSON_INVALID",
        "SNAPSHOT_JSON_DUPLICATE_KEY",
        "SNAPSHOT_SCHEMA_INVALID",
        "SNAPSHOT_SOURCE_DRIFT",
        "SNAPSHOT_TOCTOU_DETECTED",
        "SNAPSHOT_CAPTURE_COHORT_INVALID",
        "SNAPSHOT_FENCE_DRIFT",
        "SNAPSHOT_LEASE_EXPIRED",
        "SNAPSHOT_UNSAFE_REQUEST",
        "SNAPSHOT_S12_BINDING_INVALID",
        "SNAPSHOT_S12_FIXTURE_INVALID",
    }
)


class CrossStoreSnapshotError(ValueError):
    """A frozen S13 observation envelope failed closed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in SNAPSHOT_ERROR_CODES:
            raise ValueError(f"unknown S13 snapshot code: {code}")
        self.code = code
        super().__init__(f"{code}: {message}")


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"{label} must be an integer >= 0")
    return value


def _copy_json(value: Any, label: str) -> Any:
    try:
        copied = copy.deepcopy(value)
        canonical_hash(copied)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"{label} is not canonical JSON") from exc
    return copied


def _canonical_digest(value: Any, label: str) -> str:
    try:
        return canonical_hash(value)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"{label} is not canonical JSON") from exc


def parse_cross_store_snapshot(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Copy an envelope and reject duplicate JSON keys."""

    if value is None:
        raise CrossStoreSnapshotError("SNAPSHOT_NOT_OBSERVED", "snapshot envelope is missing")
    if isinstance(value, Mapping):
        try:
            return copy.deepcopy(dict(value))
        except (TypeError, ValueError, copy.Error) as exc:
            raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "snapshot envelope could not be isolated") from exc
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CrossStoreSnapshotError("SNAPSHOT_JSON_INVALID", "snapshot envelope is not UTF-8") from exc
    if not isinstance(value, str):
        raise CrossStoreSnapshotError("SNAPSHOT_JSON_INVALID", "snapshot object or JSON text required")
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except _DuplicateJsonKey as exc:
        raise CrossStoreSnapshotError("SNAPSHOT_JSON_DUPLICATE_KEY", f"duplicate key: {exc}") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CrossStoreSnapshotError("SNAPSHOT_JSON_INVALID", "snapshot JSON is invalid") from exc
    if not isinstance(parsed, dict):
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "snapshot JSON object required")
    return parsed


def _actionless_result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    result = {
        "schema_version": CROSS_STORE_SNAPSHOT_VERIFICATION_SCHEMA,
        "contract_role": CROSS_STORE_SNAPSHOT_ROLE,
        "status": status,
        "classification_role": "READ_ONLY_ADAPTER_CLASSIFICATION",
        "reason": reason,
        "permission": "read_only",
        "external_action": False,
        "mutation_allowed": False,
        "authoritative_decision": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "execution": {key: False for key in sorted(_EXECUTION_KEYS)},
    }
    result.update(extra)
    return result


def _validate_observer(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != OBSERVER_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "observer keys are not exact")
    normalized = {key: _safe_id(value[key], f"observer.{key}") for key in sorted(OBSERVER_KEYS - {"mode"})}
    if value["mode"] != "READ_ONLY_IMPORT":
        raise CrossStoreSnapshotError("SNAPSHOT_UNSAFE_REQUEST", "observer mode is not read-only import")
    normalized["mode"] = "READ_ONLY_IMPORT"
    return normalized


def _validate_source_identities(value: Any) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if not isinstance(value, Mapping) or set(value) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "source participant set is not exact")
    normalized: dict[str, dict[str, Any]] = {}
    source_ids: set[str] = set()
    instances: set[str] = set()
    snapshots: set[str] = set()
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        item = value[participant_id]
        if not isinstance(item, Mapping) or set(item) != SOURCE_KEYS:
            raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"sources.{participant_id} keys are not exact")
        if item["participant_id"] != participant_id:
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"source participant mismatch: {participant_id}")
        source_id = _safe_id(item["source_id"], f"sources.{participant_id}.source_id")
        source_instance_id = _safe_id(item["source_instance_id"], f"sources.{participant_id}.source_instance_id")
        snapshot_id = _safe_id(item["snapshot_id"], f"sources.{participant_id}.snapshot_id")
        if source_id in source_ids or source_instance_id in instances or snapshot_id in snapshots:
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", "source identity is duplicated")
        source_ids.add(source_id)
        instances.add(source_instance_id)
        snapshots.add(snapshot_id)
        identity = {
            "participant_id": participant_id,
            "source_kind": _safe_id(item["source_kind"], f"sources.{participant_id}.source_kind"),
            "source_id": source_id,
            "source_instance_id": source_instance_id,
            "source_schema": _safe_id(item["source_schema"], f"sources.{participant_id}.source_schema"),
            "snapshot_id": snapshot_id,
            "snapshot_mode": _safe_id(item["snapshot_mode"], f"sources.{participant_id}.snapshot_mode"),
        }
        if identity["snapshot_mode"] != "FROZEN_EXPORT":
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"{participant_id} is not a frozen export")
        declared = _hash64(item["source_identity_sha256"], f"sources.{participant_id}.source_identity_sha256")
        if declared != _canonical_digest(identity, f"sources.{participant_id}.identity"):
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"{participant_id} source identity digest mismatch")
        normalized[participant_id] = {**identity, "source_identity_sha256": declared}
    return normalized, sorted(source_ids)


def _validate_cursor(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != CURSOR_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"{label} keys are not exact")
    return {
        "cursor_id": _safe_id(value["cursor_id"], f"{label}.cursor_id"),
        "version": _integer(value["version"], f"{label}.version"),
        "generation": _integer(value["generation"], f"{label}.generation"),
        "generation_id": _hash64(value["generation_id"], f"{label}.generation_id"),
        "journal_sha256": _hash64(value["journal_sha256"], f"{label}.journal_sha256"),
    }


def _validate_safety(value: Any) -> dict[str, bool]:
    if not isinstance(value, Mapping) or set(value) != SAFETY_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "safety keys are not exact")
    if value["read_only"] is not True or any(
        value[key] is not False
        for key in (
            "lock_acquired",
            "lock_held",
            "reservation",
            "mutation_performed",
            "authoritative_commit",
            "recovery_invoked",
            "process_started",
            "process_stopped",
            "network_used",
            "external_action",
        )
    ):
        raise CrossStoreSnapshotError("SNAPSHOT_UNSAFE_REQUEST", "safety envelope is not actionless")
    return {key: (key == "read_only") for key in sorted(SAFETY_KEYS)}


def _validate_capture(value: Any, *, source_set_digest: str, source_identities: Mapping[str, Mapping[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != CAPTURE_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "capture keys are not exact")
    capture_id = _safe_id(value["capture_id"], "capture.capture_id")
    sequence_domain = _safe_id(value["sequence_domain"], "capture.sequence_domain")
    sequence_no = _integer(value["sequence_no"], "capture.sequence_no")
    barrier_id = _safe_id(value["barrier_id"], "capture.barrier_id")
    clock_domain = _safe_id(value["clock_domain_id"], "capture.clock_domain_id")
    clock_sample = _safe_id(value["clock_sample_id"], "capture.clock_sample_id")
    clock_before = _integer(value["clock_before"], "capture.clock_before")
    clock_after = _integer(value["clock_after"], "capture.clock_after")
    if clock_after < clock_before:
        raise CrossStoreSnapshotError("SNAPSHOT_TOCTOU_DETECTED", "capture clock moved backwards")
    if value["stable"] is not True or value["read_only"] is not True or value["external_action"] is not False:
        raise CrossStoreSnapshotError("SNAPSHOT_UNSAFE_REQUEST", "capture is not stable read-only")
    execution = value["execution"]
    if not isinstance(execution, Mapping) or set(execution) != _EXECUTION_KEYS or any(execution[key] is not False for key in _EXECUTION_KEYS):
        raise CrossStoreSnapshotError("SNAPSHOT_UNSAFE_REQUEST", "capture execution flags are not all false")
    events = value["events"]
    if not isinstance(events, list) or len(events) != 10:
        raise CrossStoreSnapshotError("SNAPSHOT_CAPTURE_COHORT_INVALID", "capture requires exactly ten events")
    normalized_events: list[dict[str, Any]] = []
    seen_passes: set[tuple[str, str]] = set()
    for index, event in enumerate(events):
        if not isinstance(event, Mapping) or set(event) != EVENT_KEYS:
            raise CrossStoreSnapshotError("SNAPSHOT_CAPTURE_COHORT_INVALID", f"capture.events[{index}] keys are not exact")
        ordinal = _integer(event["ordinal"], f"capture.events[{index}].ordinal")
        participant_id = event["participant_id"]
        if participant_id not in SNAPSHOT_PARTICIPANT_IDS or ordinal != index + 1:
            raise CrossStoreSnapshotError("SNAPSHOT_CAPTURE_COHORT_INVALID", "capture ordinals or participant is invalid")
        pass_name = event["pass"]
        if pass_name not in {"before", "after"} or (participant_id, pass_name) in seen_passes:
            raise CrossStoreSnapshotError("SNAPSHOT_CAPTURE_COHORT_INVALID", "capture before/after cohort is incomplete")
        seen_passes.add((participant_id, pass_name))
        if event["source_identity_sha256"] != source_identities[participant_id]["source_identity_sha256"]:
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", "capture event source identity mismatch")
        if event["clock_sample_id"] != clock_sample:
            raise CrossStoreSnapshotError("SNAPSHOT_CAPTURE_COHORT_INVALID", "capture event clock sample mismatch")
        normalized_events.append({
            "ordinal": ordinal,
            "participant_id": participant_id,
            "pass": pass_name,
            "source_identity_sha256": event["source_identity_sha256"],
            "observation_sha256": _hash64(event["observation_sha256"], f"capture.events[{index}].observation_sha256"),
            "clock_sample_id": clock_sample,
        })
    if seen_passes != {(participant_id, pass_name) for participant_id in SNAPSHOT_PARTICIPANT_IDS for pass_name in ("before", "after")}:
        raise CrossStoreSnapshotError("SNAPSHOT_CAPTURE_COHORT_INVALID", "capture does not cover every participant twice")
    normalized = {
        "capture_id": capture_id,
        "sequence_domain": sequence_domain,
        "sequence_no": sequence_no,
        "barrier_id": barrier_id,
        "clock_domain_id": clock_domain,
        "clock_sample_id": clock_sample,
        "clock_before": clock_before,
        "clock_after": clock_after,
        "source_set_sha256": source_set_digest,
        "events": normalized_events,
        "stable": True,
        "read_only": True,
        "external_action": False,
        "execution": {key: False for key in sorted(_EXECUTION_KEYS)},
    }
    if _hash64(value.get("source_set_sha256", source_set_digest), "capture.source_set_sha256") != source_set_digest:
        raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", "capture source-set digest mismatch")
    return normalized, {"capture_id": capture_id, "sequence_no": sequence_no, "barrier_id": barrier_id, "clock_domain_id": clock_domain, "clock_before": clock_before, "clock_after": clock_after, "clock_sample_id": clock_sample}


def _validate_fence(
    value: Any,
    *,
    transaction_id: str,
    capture: Mapping[str, Any],
    observer_instance_id: str,
) -> tuple[dict[str, Any], bool]:
    if not isinstance(value, Mapping) or set(value) != FENCE_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "fence keys are not exact")
    normalized = {
        "owner_id": _safe_id(value["owner_id"], "fence.owner_id"),
        "worker_id": _safe_id(value["worker_id"], "fence.worker_id"),
        "token_sha256": _hash64(value["token_sha256"], "fence.token_sha256"),
        "fencing_epoch": _integer(value["fencing_epoch"], "fence.fencing_epoch"),
        "issued_at": _integer(value["issued_at"], "fence.issued_at"),
        "expires_at": _integer(value["expires_at"], "fence.expires_at"),
        "clock_domain_id": _safe_id(value["clock_domain_id"], "fence.clock_domain_id"),
        "fence_cursor": _safe_id(value["fence_cursor"], "fence.fence_cursor"),
        "fence_observation_sha256": _hash64(value["fence_observation_sha256"], "fence.fence_observation_sha256"),
    }
    if normalized["clock_domain_id"] != capture["clock_domain_id"]:
        raise CrossStoreSnapshotError("SNAPSHOT_FENCE_DRIFT", "fence clock domain differs")
    if normalized["worker_id"] != observer_instance_id:
        raise CrossStoreSnapshotError("SNAPSHOT_FENCE_DRIFT", "fence worker is not the observing instance")
    expected_token = _canonical_digest({"transaction_id": transaction_id, "owner": normalized["owner_id"]}, "fence.token_binding")
    if normalized["token_sha256"] != expected_token:
        raise CrossStoreSnapshotError("SNAPSHOT_FENCE_DRIFT", "fence token is not bound to transaction and owner")
    fence_material = {key: normalized[key] for key in sorted(FENCE_KEYS - {"fence_observation_sha256"})}
    if normalized["fence_observation_sha256"] != _canonical_digest(fence_material, "fence"):
        raise CrossStoreSnapshotError("SNAPSHOT_FENCE_DRIFT", "fence observation digest mismatch")
    if normalized["issued_at"] > capture["clock_before"]:
        raise CrossStoreSnapshotError("SNAPSHOT_FENCE_DRIFT", "fence was issued after capture started")
    live = capture["clock_after"] < normalized["expires_at"]
    return normalized, live


def _validate_s12_lease(value: Any, *, transaction_id: str, fencing_epoch: int, capture: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != S12_LEASE_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "S12 lease keys are not exact")
    normalized = {
        "owner_id": _safe_id(value["owner_id"], "s12_input.lease.owner_id"),
        "token_sha256": _hash64(value["token_sha256"], "s12_input.lease.token_sha256"),
        "issued_at": _integer(value["issued_at"], "s12_input.lease.issued_at"),
        "observed_at": _integer(value["observed_at"], "s12_input.lease.observed_at"),
        "expires_at": _integer(value["expires_at"], "s12_input.lease.expires_at"),
        "fencing_epoch": _integer(value["fencing_epoch"], "s12_input.lease.fencing_epoch"),
    }
    expected_token = _canonical_digest(
        {"transaction_id": transaction_id, "owner": normalized["owner_id"]}, "s12_input.lease.token_binding"
    )
    if normalized["token_sha256"] != expected_token:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "S12 lease token is not transaction-bound")
    if normalized["fencing_epoch"] != fencing_epoch:
        raise CrossStoreSnapshotError("SNAPSHOT_FENCE_DRIFT", "S12 lease epoch differs from S13 fence")
    if not (
        normalized["issued_at"] <= capture["clock_before"] <= normalized["observed_at"] <= capture["clock_after"] < normalized["expires_at"]
    ):
        raise CrossStoreSnapshotError("SNAPSHOT_LEASE_EXPIRED", "S12 lease does not cover the frozen capture")
    return normalized


def _validate_manifest(value: Any, *, contract_digest: str, contract: Mapping[str, Any], observations: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != MANIFEST_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "projection manifest keys are not exact")
    if value["schema_version"] != "prime-cross-store-projection-manifest-v1":
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "projection manifest schema is invalid")
    if _hash64(value["contract_digest"], "manifest.contract_digest") != contract_digest:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "projection manifest contract mismatch")
    plan_hash = _hash64(value["precondition_plan_sha256"], "manifest.precondition_plan_sha256")
    if plan_hash != contract.get("precondition_plan_sha256"):
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "projection manifest plan mismatch")
    participants = value["participants"]
    if not isinstance(participants, Mapping) or set(participants) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "projection manifest participants are incomplete")
    normalized_participants: dict[str, Any] = {}
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        entry = participants[participant_id]
        if not isinstance(entry, Mapping) or set(entry) != MANIFEST_PARTICIPANT_KEYS:
            raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", f"manifest.{participant_id} keys are not exact")
        if entry["target_id"] != participant_id:
            raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", f"manifest.{participant_id} target is not source-bound")
        observed_bundle = observations[participant_id]["observed"]
        if entry["before"] != observed_bundle["expected_before"] or entry["after"] != observed_bundle["expected_after"]:
            raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", f"manifest.{participant_id} expected projection drift")
        normalized_participants[participant_id] = {
            "before": _copy_json(entry["before"], f"manifest.{participant_id}.before"),
            "after": _copy_json(entry["after"], f"manifest.{participant_id}.after"),
            "target_id": _safe_id(entry["target_id"], f"manifest.{participant_id}.target_id"),
        }
    normalized = {
        "schema_version": value["schema_version"],
        "contract_digest": contract_digest,
        "precondition_plan_sha256": plan_hash,
        "participants": normalized_participants,
    }
    if _hash64(value["manifest_sha256"], "manifest.manifest_sha256") != _canonical_digest(normalized, "projection manifest"):
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "projection manifest digest mismatch")
    return {**normalized, "manifest_sha256": _canonical_digest(normalized, "projection manifest")}


def _validate_observations(
    value: Any,
    *,
    sources: Mapping[str, Mapping[str, Any]],
    capture: Mapping[str, Any],
    fence_epoch: int,
) -> tuple[dict[str, dict[str, Any]], bool]:
    if not isinstance(value, Mapping) or set(value) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "observation participant set is not exact")
    normalized: dict[str, dict[str, Any]] = {}
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        item = value[participant_id]
        if not isinstance(item, Mapping) or set(item) != OBSERVATION_KEYS:
            raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"observations.{participant_id} keys are not exact")
        source = sources[participant_id]
        source_id = _safe_id(item["source_id"], f"observations.{participant_id}.source_id")
        if source_id != source["source_id"] or item["snapshot_id"] != source["snapshot_id"] or item["source_identity_sha256"] != source["source_identity_sha256"]:
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"{participant_id} observation identity mismatch")
        cursor = _validate_cursor(item["source_cursor"], f"observations.{participant_id}.source_cursor")
        cursor_digest = _hash64(item["source_cursor_sha256"], f"observations.{participant_id}.source_cursor_sha256")
        if cursor_digest != _canonical_digest(cursor, f"observations.{participant_id}.source_cursor"):
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"{participant_id} cursor digest mismatch")
        sample_a = _copy_json(item["sample_a"], f"observations.{participant_id}.sample_a")
        sample_b = _copy_json(item["sample_b"], f"observations.{participant_id}.sample_b")
        observed = _copy_json(item["observed"], f"observations.{participant_id}.observed")
        observed_projection = observed.get("observed") if isinstance(observed, Mapping) else None
        if not isinstance(observed_projection, Mapping):
            raise CrossStoreSnapshotError("SNAPSHOT_S12_FIXTURE_INVALID", f"{participant_id} observed bundle is incomplete")
        if (
            cursor["version"] != observed_projection.get("version")
            or cursor["generation"] != observed_projection.get("generation")
            or cursor["generation_id"] != observed_projection.get("generation_id")
            or cursor["journal_sha256"] != observed_projection.get("journal_sha256")
        ):
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"{participant_id} cursor does not bind observed projection")
        for sample_name, sample in (("sample_a", sample_a), ("sample_b", sample_b)):
            if not isinstance(sample, Mapping) or set(sample) != SAMPLE_KEYS:
                raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"{participant_id}.{sample_name} keys are not exact")
            if sample["participant_id"] != participant_id or sample["source_identity_sha256"] != source["source_identity_sha256"] or sample["snapshot_id"] != source["snapshot_id"]:
                raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"{participant_id}.{sample_name} identity mismatch")
            if sample["source_cursor"] != cursor or sample["projection"] != observed:
                raise CrossStoreSnapshotError("SNAPSHOT_TOCTOU_DETECTED", f"{participant_id}.{sample_name} differs from observed projection")
            _validate_cursor(sample["source_cursor"], f"observations.{participant_id}.{sample_name}.source_cursor")
        if sample_a != sample_b:
            raise CrossStoreSnapshotError("SNAPSHOT_TOCTOU_DETECTED", f"{participant_id} before/after samples differ")
        observed_digest = _hash64(item["observed_sha256"], f"observations.{participant_id}.observed_sha256")
        if observed_digest != _canonical_digest(observed, f"observations.{participant_id}.observed"):
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"{participant_id} observed digest mismatch")
        content = {
            "participant_id": participant_id,
            "source_identity_sha256": source["source_identity_sha256"],
            "snapshot_id": source["snapshot_id"],
            "source_cursor": cursor,
            "observed": observed,
        }
        content_digest = _hash64(item["content_sha256"], f"observations.{participant_id}.content_sha256")
        if content_digest != _canonical_digest(content, f"observations.{participant_id}.content"):
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"{participant_id} content digest mismatch")
        if item["read_only"] is not True:
            raise CrossStoreSnapshotError("SNAPSHOT_UNSAFE_REQUEST", f"{participant_id} is not read-only")
        normalized[participant_id] = {
            "source_id": source_id,
            "snapshot_id": source["snapshot_id"],
            "source_identity_sha256": source["source_identity_sha256"],
            "sample_a": sample_a,
            "sample_b": sample_b,
            "source_cursor": cursor,
            "source_cursor_sha256": cursor_digest,
            "observed": observed,
            "observed_sha256": observed_digest,
            "content_sha256": content_digest,
            "read_only": True,
        }
    # The event validation is separate because it binds the common barrier to each source twice.
    events = capture["events"]
    for event in events:
        participant_id = event["participant_id"]
        observation = normalized[participant_id]
        event_material = {
            "capture_id": capture["capture_id"],
            "sequence_domain": capture["sequence_domain"],
            "sequence_no": capture["sequence_no"],
            "barrier_id": capture["barrier_id"],
            "ordinal": event["ordinal"],
            "participant_id": participant_id,
            "pass": event["pass"],
            "source_identity_sha256": event["source_identity_sha256"],
            "content_sha256": observation["content_sha256"],
            "clock_sample_id": event["clock_sample_id"],
        }
        if event["observation_sha256"] != _canonical_digest(event_material, f"capture event {event['ordinal']}"):
            raise CrossStoreSnapshotError("SNAPSHOT_CAPTURE_COHORT_INVALID", "capture event digest mismatch")
    return normalized, True


def _validate_replay(value: Any, *, contract: Mapping[str, Any], transaction_id: str, contract_digest: str, subject_digest: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != REPLAY_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "replay observation keys are not exact")
    normalized = {
        "registry_source_id": _safe_id(value["registry_source_id"], "replay.registry_source_id"),
        "idempotency_key": _safe_id(value["idempotency_key"], "replay.idempotency_key"),
        "transaction_id": _safe_id(value["transaction_id"], "replay.transaction_id"),
        "contract_digest": _hash64(value["contract_digest"], "replay.contract_digest"),
        "subject_binding_digest": _hash64(value["subject_binding_digest"], "replay.subject_binding_digest"),
        "status": _text(value["status"], "replay.status"),
        "conflict": value["conflict"],
        "observation_sha256": _hash64(value["observation_sha256"], "replay.observation_sha256"),
    }
    if normalized["idempotency_key"] != contract["idempotency_key"] or normalized["transaction_id"] != transaction_id or normalized["contract_digest"] != contract_digest or normalized["subject_binding_digest"] != subject_digest:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "replay observation is not bound to S11 contract")
    if normalized["status"] != "UNIQUE_OBSERVED" or normalized["conflict"] is not False:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "replay observation is not unique and conflict-free")
    material = {key: normalized[key] for key in sorted(REPLAY_KEYS - {"observation_sha256"})}
    if normalized["observation_sha256"] != _canonical_digest(material, "replay observation"):
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "replay observation digest mismatch")
    return normalized


def _validate_s12_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != S12_INPUT_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "s12_input keys are not exact")
    return {
        "contract_material": _copy_json(value["contract_material"], "s12_input.contract_material"),
        "subject_binding_material": _copy_json(value["subject_binding_material"], "s12_input.subject_binding_material"),
        "effect_set": _copy_json(value["effect_set"], "s12_input.effect_set"),
        "marker_material": _copy_json(value["marker_material"], "s12_input.marker_material"),
        "lease": _copy_json(value["lease"], "s12_input.lease"),
        "hook_trace": _copy_json(value["hook_trace"], "s12_input.hook_trace"),
        "fault_hook_or_null": None if value["fault_hook_or_null"] is None else _safe_id(value["fault_hook_or_null"], "s12_input.fault_hook_or_null"),
    }


def _build_observation_from_sample(
    participant_id: str,
    source: Mapping[str, Any],
    sample_a: Mapping[str, Any],
    sample_b: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(sample_a, Mapping) or set(sample_a) != BUILDER_SAMPLE_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"builder sample {participant_id} keys are not exact")
    if not isinstance(sample_b, Mapping) or set(sample_b) != BUILDER_SAMPLE_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"builder second sample {participant_id} keys are not exact")
    if sample_a["read_only"] is not True or sample_b["read_only"] is not True:
        raise CrossStoreSnapshotError("SNAPSHOT_UNSAFE_REQUEST", f"builder sample {participant_id} is not read-only")
    for sample_name, sample in (("first", sample_a), ("second", sample_b)):
        if (
            sample["source_id"] != source["source_id"]
            or sample["snapshot_id"] != source["snapshot_id"]
            or sample["source_identity_sha256"] != source["source_identity_sha256"]
        ):
            raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"builder {sample_name} sample {participant_id} identity mismatch")
    cursor_a = _copy_json(sample_a["source_cursor"], f"builder.{participant_id}.source_cursor_a")
    projection_a = _copy_json(sample_a["projection"], f"builder.{participant_id}.projection_a")
    cursor_b = _copy_json(sample_b["source_cursor"], f"builder.{participant_id}.source_cursor_b")
    projection_b = _copy_json(sample_b["projection"], f"builder.{participant_id}.projection_b")
    if not isinstance(cursor_a, Mapping) or not isinstance(projection_a, Mapping) or not isinstance(cursor_b, Mapping) or not isinstance(projection_b, Mapping):
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"builder sample {participant_id} cursor/projection must be objects")
    if cursor_a != cursor_b or projection_a != projection_b:
        raise CrossStoreSnapshotError("SNAPSHOT_TOCTOU_DETECTED", f"builder samples {participant_id} differ")
    if sample_a["source_id"] != sample_b["source_id"] or sample_a["snapshot_id"] != sample_b["snapshot_id"] or sample_a["source_identity_sha256"] != sample_b["source_identity_sha256"]:
        raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", f"builder samples {participant_id} identity drifted")
    observation_sample_a = {
        "participant_id": participant_id,
        "source_identity_sha256": source["source_identity_sha256"],
        "snapshot_id": source["snapshot_id"],
        "source_cursor": cursor_a,
        "projection": projection_a,
    }
    observation_sample_b = {
        "participant_id": participant_id,
        "source_identity_sha256": source["source_identity_sha256"],
        "snapshot_id": source["snapshot_id"],
        "source_cursor": cursor_b,
        "projection": projection_b,
    }
    content = {
        "participant_id": participant_id,
        "source_identity_sha256": source["source_identity_sha256"],
        "snapshot_id": source["snapshot_id"],
        "source_cursor": copy.deepcopy(cursor_a),
        "observed": copy.deepcopy(projection_a),
    }
    return {
        "source_id": source["source_id"],
        "snapshot_id": source["snapshot_id"],
        "source_identity_sha256": source["source_identity_sha256"],
        "sample_a": observation_sample_a,
        "sample_b": observation_sample_b,
        "source_cursor": cursor_a,
        "source_cursor_sha256": _canonical_digest(cursor_a, f"builder.{participant_id}.source_cursor"),
        "observed": projection_a,
        "observed_sha256": _canonical_digest(projection_a, f"builder.{participant_id}.observed"),
        "content_sha256": _canonical_digest(content, f"builder.{participant_id}.content"),
        "read_only": True,
    }


def _build_capture_from_observations(
    context: Mapping[str, Any],
    source_set: list[str],
    sources: Mapping[str, Mapping[str, Any]],
    observations: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(context, Mapping) or set(context) != BUILDER_CAPTURE_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "builder capture context keys are not exact")
    normalized_context = {
        "capture_id": _safe_id(context["capture_id"], "builder.capture.capture_id"),
        "sequence_domain": _safe_id(context["sequence_domain"], "builder.capture.sequence_domain"),
        "sequence_no": _integer(context["sequence_no"], "builder.capture.sequence_no"),
        "barrier_id": _safe_id(context["barrier_id"], "builder.capture.barrier_id"),
        "clock_domain_id": _safe_id(context["clock_domain_id"], "builder.capture.clock_domain_id"),
        "clock_sample_id": _safe_id(context["clock_sample_id"], "builder.capture.clock_sample_id"),
        "clock_before": _integer(context["clock_before"], "builder.capture.clock_before"),
        "clock_after": _integer(context["clock_after"], "builder.capture.clock_after"),
    }
    if normalized_context["clock_after"] < normalized_context["clock_before"]:
        raise CrossStoreSnapshotError("SNAPSHOT_TOCTOU_DETECTED", "builder capture clock moved backwards")
    events: list[dict[str, Any]] = []
    for ordinal, (participant_id, pass_name) in enumerate(
        ((participant_id, pass_name) for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS) for pass_name in ("before", "after")),
        start=1,
    ):
        event = {
            "ordinal": ordinal,
            "participant_id": participant_id,
            "pass": pass_name,
            "source_identity_sha256": sources[participant_id]["source_identity_sha256"],
            "observation_sha256": "",
            "clock_sample_id": normalized_context["clock_sample_id"],
        }
        material = {
            "capture_id": normalized_context["capture_id"],
            "sequence_domain": normalized_context["sequence_domain"],
            "sequence_no": normalized_context["sequence_no"],
            "barrier_id": normalized_context["barrier_id"],
            "ordinal": ordinal,
            "participant_id": participant_id,
            "pass": pass_name,
            "source_identity_sha256": event["source_identity_sha256"],
            "content_sha256": observations[participant_id]["content_sha256"],
            "clock_sample_id": event["clock_sample_id"],
        }
        event["observation_sha256"] = _canonical_digest(material, f"builder.capture.events[{ordinal}]")
        events.append(event)
    return {
        **normalized_context,
        "source_set_sha256": _canonical_digest(source_set, "builder.source_set"),
        "events": events,
        "stable": True,
        "read_only": True,
        "external_action": False,
        "execution": {key: False for key in sorted(_EXECUTION_KEYS)},
    }


def build_cross_store_snapshot_envelope(
    *,
    transaction_id: str,
    observer: Mapping[str, Any],
    sources: Mapping[str, Mapping[str, Any]],
    source_samples: Mapping[str, Mapping[str, Any]],
    source_samples_after: Mapping[str, Mapping[str, Any]] | None = None,
    capture_context: Mapping[str, Any],
    expected_projection_manifest: Mapping[str, Any],
    fence: Mapping[str, Any],
    replay: Mapping[str, Any],
    s12_input: Mapping[str, Any],
) -> dict[str, Any]:
    """Build and S13-validate an envelope from already stable source samples.

    The function is deliberately pure: ``source_samples`` are supplied by an
    approved producer after its own two-pass read.  S14 uses this builder so
    the event/content digest formulas have one canonical implementation.
    """

    transaction_id = _safe_id(transaction_id, "transaction_id")
    if not isinstance(sources, Mapping) or set(sources) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "builder source participant set is not exact")
    if not isinstance(source_samples, Mapping) or set(source_samples) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "builder sample participant set is not exact")
    if source_samples_after is None:
        source_samples_after = source_samples
    if not isinstance(source_samples_after, Mapping) or set(source_samples_after) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "builder second sample participant set is not exact")
    normalized_sources = {participant_id: _copy_json(sources[participant_id], f"builder.sources.{participant_id}") for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS)}
    source_ids = []
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        source = normalized_sources[participant_id]
        if not isinstance(source, Mapping) or set(source) != SOURCE_KEYS:
            raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", f"builder source {participant_id} keys are not exact")
        source_ids.append(_safe_id(source["source_id"], f"builder.sources.{participant_id}.source_id"))
    if len(set(source_ids)) != len(source_ids):
        raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", "builder source IDs are not unique")
    source_set = sorted(source_ids)
    observations = {
        participant_id: _build_observation_from_sample(
            participant_id,
            normalized_sources[participant_id],
            source_samples[participant_id],
            source_samples_after[participant_id],
        )
        for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS)
    }
    envelope = {
        "schema_version": CROSS_STORE_SNAPSHOT_SCHEMA,
        "contract_role": CROSS_STORE_SNAPSHOT_ROLE,
        "transaction_id": transaction_id,
        "observer": _copy_json(observer, "builder.observer"),
        "sources": normalized_sources,
        "source_set": source_set,
        "source_set_sha256": _canonical_digest(source_set, "builder.source_set"),
        "expected_projection_manifest": _copy_json(expected_projection_manifest, "builder.expected_projection_manifest"),
        "capture": _build_capture_from_observations(capture_context, source_set, normalized_sources, observations),
        "observations": observations,
        "fence": _copy_json(fence, "builder.fence"),
        "replay": _copy_json(replay, "builder.replay"),
        "s12_input": _copy_json(s12_input, "builder.s12_input"),
        "safety": {key: (key == "read_only") for key in sorted(SAFETY_KEYS)},
    }
    try:
        adapt_cross_store_snapshot(envelope)
    except CrossStoreSnapshotError:
        raise
    return envelope


def _validate_envelope(value: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    if set(value) != SNAPSHOT_KEYS:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "snapshot envelope keys are not exact")
    if value["schema_version"] != CROSS_STORE_SNAPSHOT_SCHEMA or value["contract_role"] != CROSS_STORE_SNAPSHOT_ROLE:
        raise CrossStoreSnapshotError("SNAPSHOT_SCHEMA_INVALID", "unsupported S13 schema or role")
    transaction_id = _safe_id(value["transaction_id"], "transaction_id")
    observer = _validate_observer(value["observer"])
    sources, source_ids = _validate_source_identities(value["sources"])
    source_set = value["source_set"]
    if (
        not isinstance(source_set, list)
        or len(source_set) != len(source_ids)
        or sorted(source_set) != source_set
        or set(source_set) != set(source_ids)
    ):
        raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", "source_set is not the exact sorted source identity set")
    source_set_digest = _hash64(value["source_set_sha256"], "source_set_sha256")
    if source_set_digest != _canonical_digest(source_set, "source_set"):
        raise CrossStoreSnapshotError("SNAPSHOT_SOURCE_DRIFT", "source_set digest mismatch")
    s12_input = _validate_s12_input(value["s12_input"])
    contract = s12_input["contract_material"]
    try:
        verified_contract = verify_authoritative_transaction_contract(contract)
    except (PrimeTransactionAuthorityError, TypeError, ValueError) as exc:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "full S11 contract did not verify") from exc
    if verified_contract.get("transaction_id") != transaction_id or verified_contract.get("status") != "CONTRACT_VALIDATED_READ_ONLY":
        raise CrossStoreSnapshotError("SNAPSHOT_S12_BINDING_INVALID", "S11 contract result is not bound/read-only")
    contract_digest = _canonical_digest(contract, "s12 contract")
    subject_digest = _canonical_digest(s12_input["subject_binding_material"], "s12 subject material")
    capture, capture_context = _validate_capture(
        value["capture"], source_set_digest=source_set_digest, source_identities=sources
    )
    fence, fence_live = _validate_fence(
        value["fence"],
        transaction_id=transaction_id,
        capture=capture_context,
        observer_instance_id=observer["observer_instance_id"],
    )
    if not fence_live:
        raise CrossStoreSnapshotError("SNAPSHOT_LEASE_EXPIRED", "S13 fence expired during the frozen capture")
    if fence["fencing_epoch"] != contract["lease"]["fencing_epoch"]:
        raise CrossStoreSnapshotError("SNAPSHOT_FENCE_DRIFT", "S13 fence differs from S11 lease epoch")
    s12_lease = _validate_s12_lease(
        s12_input["lease"],
        transaction_id=transaction_id,
        fencing_epoch=fence["fencing_epoch"],
        capture=capture_context,
    )
    observations, observations_verified = _validate_observations(
        value["observations"], sources=sources, capture=capture, fence_epoch=fence["fencing_epoch"]
    )
    # Re-check the manifest against the actual observed bundles after source parsing.
    manifest = _validate_manifest(value["expected_projection_manifest"], contract_digest=contract_digest, contract=contract, observations=observations)
    replay = _validate_replay(
        value["replay"],
        contract=contract,
        transaction_id=transaction_id,
        contract_digest=contract_digest,
        subject_digest=subject_digest,
    )
    safety = _validate_safety(value["safety"])
    return (
        {
            "schema_version": CROSS_STORE_SNAPSHOT_SCHEMA,
            "contract_role": CROSS_STORE_SNAPSHOT_ROLE,
            "transaction_id": transaction_id,
            "observer": observer,
            "sources": sources,
            "source_set": list(source_set),
            "source_set_sha256": source_set_digest,
            "expected_projection_manifest": manifest,
            "capture": capture,
            "observations": observations,
            "fence": fence,
            "replay": replay,
            "s12_input": s12_input,
            "safety": safety,
        },
        {"source_set_verified": True, "observations_verified": observations_verified, "capture_stable": True, "toctou_verified": True, "fence_live": fence_live, "fencing_epoch": fence["fencing_epoch"]},
        {**s12_input, "lease": s12_lease},
        manifest,
    )


def adapt_cross_store_snapshot(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Validate a frozen envelope and classify its S12 projection."""

    envelope = parse_cross_store_snapshot(value)
    normalized, gates, s12_input, _manifest = _validate_envelope(envelope)
    participants = {participant_id: item["observed"] for participant_id, item in normalized["observations"].items()}
    try:
        fixture = build_cross_store_fixture(
            transaction_id=normalized["transaction_id"],
            fencing_epoch=normalized["fence"]["fencing_epoch"],
            participants=participants,
            hook_trace=s12_input["hook_trace"],
            contract_material=s12_input["contract_material"],
            subject_binding_material=s12_input["subject_binding_material"],
            effect_set=s12_input["effect_set"],
            marker_material=s12_input["marker_material"],
            lease=s12_input["lease"],
        )
    except CrossStoreFixtureError as exc:
        raise CrossStoreSnapshotError("SNAPSHOT_S12_FIXTURE_INVALID", str(exc)) from exc
    if s12_input["fault_hook_or_null"] is not None:
        fixture["fault_hook_or_null"] = s12_input["fault_hook_or_null"]
    classification = classify_cross_store_fixture(fixture)
    return _actionless_result(
        "ADAPTED_READ_ONLY",
        "SOURCE_GATES_PASSED",
        transaction_id=normalized["transaction_id"],
        classification_status=classification["status"],
        classification_reason=classification["reason"],
        source_gates={"source_set": gates["source_set_verified"], "capture": gates["capture_stable"], "safety": True},
        toctou_gate={"verified": gates["toctou_verified"], "barrier_id": normalized["capture"]["barrier_id"], "sequence_no": normalized["capture"]["sequence_no"]},
        fence_gate={"verified": classification.get("fencing_verified", False), "live": gates["fence_live"], "fencing_epoch": gates["fencing_epoch"]},
        live_binding="BOUNDED_FROZEN_SNAPSHOT",
        fixture_sha256=_canonical_digest(fixture, "s12 fixture"),
        snapshot_envelope_sha256=_canonical_digest(normalized, "snapshot envelope"),
        classification=classification,
        fixture=fixture,
    )


def evaluate_cross_store_snapshot(value: Mapping[str, Any] | bytes | str | None) -> dict[str, Any]:
    """Return actionless HOLD or RECOVERY_REQUIRED for invalid envelopes."""

    try:
        return adapt_cross_store_snapshot(value)
    except CrossStoreSnapshotError as exc:
        status = "RECOVERY_REQUIRED" if exc.code in _RECOVERY_CODES else "HOLD"
        return _actionless_result(status, exc.code)
    except (AttributeError, KeyError, TypeError, ValueError):
        return _actionless_result("HOLD", "SNAPSHOT_SCHEMA_INVALID")


__all__ = [
    "CROSS_STORE_SNAPSHOT_ROLE",
    "CROSS_STORE_SNAPSHOT_SCHEMA",
    "CROSS_STORE_SNAPSHOT_VERIFICATION_SCHEMA",
    "CrossStoreSnapshotError",
    "SNAPSHOT_ERROR_CODES",
    "SNAPSHOT_PARTICIPANT_IDS",
    "build_cross_store_snapshot_envelope",
    "adapt_cross_store_snapshot",
    "evaluate_cross_store_snapshot",
    "parse_cross_store_snapshot",
]
