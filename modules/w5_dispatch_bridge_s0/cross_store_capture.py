"""W5-S14 read-only producer for a common Cross-Store capture cohort.

This module owns the *orchestration* boundary only.  It never opens a source,
path, database or transport itself.  A separately reviewed source adapter must
implement ``read_snapshot()`` and return one frozen, canonical source record.
S14 calls every approved reader twice, compares both passes, binds the common
clock/capture cohort and asks W5-S13 to validate the resulting envelope.

The producer therefore detects drift between two observations, but cannot
prove that a malicious or incorrect reader reported the real live source.  It
also never acquires a lock, invokes recovery, writes a replay record, starts a
process or grants execution authority.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Mapping, Protocol

from modules.w4_small_loop_s0 import canonical_hash

from .cross_store_snapshot import (
    SNAPSHOT_PARTICIPANT_IDS,
    CrossStoreSnapshotError,
    build_cross_store_snapshot_envelope,
)


CROSS_STORE_CAPTURE_SCHEMA = "prime-cross-store-capture-v1"
CROSS_STORE_CAPTURE_VERIFICATION_SCHEMA = "prime-cross-store-capture-verification-v1"
CROSS_STORE_CAPTURE_ROLE = "cross_store_capture_producer_read_only"

SOURCE_IDENTITY_KEYS = frozenset(
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
READER_RESULT_KEYS = frozenset(
    {"source_id", "snapshot_id", "source_identity_sha256", "source_cursor", "projection", "read_only"}
)
SOURCE_CAPABILITY_KEYS = frozenset(
    {
        "adapter_id",
        "allowed_root_or_binding",
        "read_only_capability",
        "write_capability",
        "lock_capability",
        "network_capability",
        "process_capability",
    }
)
CAPTURE_CONTEXT_KEYS = frozenset(
    {"capture_id", "sequence_domain", "sequence_no", "barrier_id", "clock_domain_id", "clock_sample_id"}
)
COHORT_RESULT_KEYS = frozenset({"fence", "lease", "generation"})
COHORT_GENERATION_KEYS = frozenset({"generation", "generation_id"})
EXECUTION_KEYS = frozenset({"resume", "reconcile", "mutation", "network"})
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_RECOVERY_CODES = frozenset(
    {
        "CAPTURE_SOURCE_DRIFT",
        "CAPTURE_TOCTOU_DETECTED",
        "CAPTURE_CLOCK_DRIFT",
        "CAPTURE_FENCE_DRIFT",
        "CAPTURE_LEASE_DRIFT",
        "CAPTURE_GENERATION_DRIFT",
        "CAPTURE_LEASE_EXPIRED",
        "SNAPSHOT_SOURCE_DRIFT",
        "SNAPSHOT_TOCTOU_DETECTED",
        "SNAPSHOT_CAPTURE_COHORT_INVALID",
        "SNAPSHOT_FENCE_DRIFT",
        "SNAPSHOT_LEASE_EXPIRED",
    }
)
CAPTURE_ERROR_CODES = frozenset(
    {
        "CAPTURE_NOT_OBSERVED",
        "CAPTURE_SCHEMA_INVALID",
        "CAPTURE_SOURCE_DRIFT",
        "CAPTURE_TOCTOU_DETECTED",
        "CAPTURE_CLOCK_UNOBSERVABLE",
        "CAPTURE_CLOCK_DRIFT",
        "CAPTURE_SOURCE_UNOBSERVABLE",
        "CAPTURE_UNSAFE_SOURCE",
        "CAPTURE_S13_REJECTED",
        "CAPTURE_FENCE_DRIFT",
        "CAPTURE_LEASE_DRIFT",
        "CAPTURE_GENERATION_DRIFT",
        "CAPTURE_LEASE_EXPIRED",
    }
)


class ReadOnlySnapshotReader(Protocol):
    """Approved source boundary; implementation must perform read-only work."""

    adapter_id: str

    def read_snapshot(self) -> Mapping[str, Any]:
        ...


class ReadOnlyClock(Protocol):
    """Injected monotonic clock boundary used for deterministic tests."""

    def sample(self) -> int:
        ...


class ReadOnlyCohort(Protocol):
    """Read-only observation of the existing lease/fence cohort."""

    def read_cohort(self) -> Mapping[str, Any]:
        ...


class CrossStoreCaptureError(ValueError):
    """A source capture failed closed without a side effect."""

    def __init__(self, code: str, message: str, *, source_code: str | None = None) -> None:
        if code not in CAPTURE_ERROR_CODES:
            raise ValueError(f"unknown S14 capture code: {code}")
        self.code = code
        self.source_code = source_code
        suffix = f" ({source_code})" if source_code else ""
        super().__init__(f"{code}{suffix}: {message}")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"{label} must be non-empty text")
    return value


def _safe_id(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SAFE_ID.fullmatch(value) is None:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"{label} is not a safe identifier")
    return value


def _hash64(value: Any, label: str) -> str:
    value = _text(value, label)
    if _HEX64.fullmatch(value) is None:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"{label} must be an integer >= 0")
    return value


def _copy_json(value: Any, label: str) -> Any:
    try:
        copied = copy.deepcopy(value)
        canonical_hash(copied)
    except Exception as exc:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"{label} is not canonical JSON") from exc
    return copied


def _digest(value: Any, label: str) -> str:
    try:
        return canonical_hash(value)
    except Exception as exc:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"{label} is not canonical JSON") from exc


def _validate_observer(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"observer_id", "observer_instance_id", "implementation_id", "mode"}:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", "observer keys are not exact")
    result = {
        "observer_id": _safe_id(value["observer_id"], "observer.observer_id"),
        "observer_instance_id": _safe_id(value["observer_instance_id"], "observer.observer_instance_id"),
        "implementation_id": _safe_id(value["implementation_id"], "observer.implementation_id"),
        "mode": value["mode"],
    }
    if result["mode"] != "READ_ONLY_IMPORT":
        raise CrossStoreCaptureError("CAPTURE_UNSAFE_SOURCE", "observer is not a read-only import")
    return result


def _validate_source_identity(participant_id: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != SOURCE_IDENTITY_KEYS:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"source {participant_id} keys are not exact")
    if value["participant_id"] != participant_id:
        raise CrossStoreCaptureError("CAPTURE_SOURCE_DRIFT", f"source participant mismatch: {participant_id}")
    identity = {
        "participant_id": participant_id,
        "source_kind": _safe_id(value["source_kind"], f"source.{participant_id}.source_kind"),
        "source_id": _safe_id(value["source_id"], f"source.{participant_id}.source_id"),
        "source_instance_id": _safe_id(value["source_instance_id"], f"source.{participant_id}.source_instance_id"),
        "source_schema": _safe_id(value["source_schema"], f"source.{participant_id}.source_schema"),
        "snapshot_id": _safe_id(value["snapshot_id"], f"source.{participant_id}.snapshot_id"),
        "snapshot_mode": _safe_id(value["snapshot_mode"], f"source.{participant_id}.snapshot_mode"),
    }
    if identity["snapshot_mode"] != "FROZEN_EXPORT":
        raise CrossStoreCaptureError("CAPTURE_SOURCE_DRIFT", f"source {participant_id} is not frozen")
    declared = _hash64(value["source_identity_sha256"], f"source.{participant_id}.source_identity_sha256")
    if declared != _digest(identity, f"source.{participant_id}.identity"):
        raise CrossStoreCaptureError("CAPTURE_SOURCE_DRIFT", f"source {participant_id} identity digest mismatch")
    return {**identity, "source_identity_sha256": declared}


def _validate_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != CAPTURE_CONTEXT_KEYS:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", "capture context keys are not exact")
    return {
        "capture_id": _safe_id(value["capture_id"], "capture.capture_id"),
        "sequence_domain": _safe_id(value["sequence_domain"], "capture.sequence_domain"),
        "sequence_no": _integer(value["sequence_no"], "capture.sequence_no"),
        "barrier_id": _safe_id(value["barrier_id"], "capture.barrier_id"),
        "clock_domain_id": _safe_id(value["clock_domain_id"], "capture.clock_domain_id"),
        "clock_sample_id": _safe_id(value["clock_sample_id"], "capture.clock_sample_id"),
    }


def _validate_capabilities(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", "source capability participant set is not exact")
    normalized: dict[str, dict[str, Any]] = {}
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        profile = value[participant_id]
        if not isinstance(profile, Mapping) or set(profile) != SOURCE_CAPABILITY_KEYS:
            raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"capability {participant_id} keys are not exact")
        normalized[participant_id] = {
            "adapter_id": _safe_id(profile["adapter_id"], f"capability.{participant_id}.adapter_id"),
            "allowed_root_or_binding": _safe_id(profile["allowed_root_or_binding"], f"capability.{participant_id}.allowed_root_or_binding"),
            "read_only_capability": profile["read_only_capability"],
            "write_capability": profile["write_capability"],
            "lock_capability": profile["lock_capability"],
            "network_capability": profile["network_capability"],
            "process_capability": profile["process_capability"],
        }
        if (
            normalized[participant_id]["read_only_capability"] is not True
            or any(normalized[participant_id][key] is not False for key in SOURCE_CAPABILITY_KEYS - {"adapter_id", "allowed_root_or_binding", "read_only_capability"})
        ):
            raise CrossStoreCaptureError("CAPTURE_UNSAFE_SOURCE", f"capability {participant_id} is not read-only")
    return normalized


def _validate_reader_result(participant_id: str, value: Any, source: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != READER_RESULT_KEYS:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"reader result {participant_id} keys are not exact")
    if value["read_only"] is not True:
        raise CrossStoreCaptureError("CAPTURE_UNSAFE_SOURCE", f"reader {participant_id} did not declare read-only")
    source_id = _safe_id(value["source_id"], f"reader.{participant_id}.source_id")
    snapshot_id = _safe_id(value["snapshot_id"], f"reader.{participant_id}.snapshot_id")
    identity_digest = _hash64(value["source_identity_sha256"], f"reader.{participant_id}.source_identity_sha256")
    if source_id != source["source_id"] or snapshot_id != source["snapshot_id"] or identity_digest != source["source_identity_sha256"]:
        raise CrossStoreCaptureError("CAPTURE_SOURCE_DRIFT", f"reader {participant_id} identity differs from approved source")
    cursor = _copy_json(value["source_cursor"], f"reader.{participant_id}.source_cursor")
    projection = _copy_json(value["projection"], f"reader.{participant_id}.projection")
    if not isinstance(cursor, Mapping) or not isinstance(projection, Mapping):
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"reader {participant_id} cursor/projection must be objects")
    return {
        "source_id": source_id,
        "snapshot_id": snapshot_id,
        "source_identity_sha256": identity_digest,
        "source_cursor": cursor,
        "projection": projection,
        "read_only": True,
    }


def _read_pass(
    readers: Mapping[str, ReadOnlySnapshotReader],
    sources: Mapping[str, Mapping[str, Any]],
    capabilities: Mapping[str, Mapping[str, Any]],
    participant_ids: tuple[str, ...],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for participant_id in participant_ids:
        reader = readers[participant_id]
        method = getattr(reader, "read_snapshot", None)
        if not callable(method):
            raise CrossStoreCaptureError("CAPTURE_SOURCE_UNOBSERVABLE", f"reader {participant_id} lacks read_snapshot()")
        if getattr(reader, "adapter_id", None) != capabilities[participant_id]["adapter_id"]:
            raise CrossStoreCaptureError("CAPTURE_SOURCE_UNOBSERVABLE", f"reader {participant_id} is not the approved adapter")
        try:
            raw = method()
        except CrossStoreCaptureError:
            raise
        except Exception as exc:
            raise CrossStoreCaptureError("CAPTURE_SOURCE_UNOBSERVABLE", f"reader {participant_id} failed") from exc
        result[participant_id] = _validate_reader_result(participant_id, raw, sources[participant_id])
    return result


def _sample_clock(clock: ReadOnlyClock, label: str) -> int:
    method = getattr(clock, "sample", None)
    if not callable(method):
        raise CrossStoreCaptureError("CAPTURE_CLOCK_UNOBSERVABLE", "clock lacks sample()")
    try:
        value = method()
    except Exception as exc:
        raise CrossStoreCaptureError("CAPTURE_CLOCK_UNOBSERVABLE", f"clock sample failed at {label}") from exc
    return _integer(value, f"clock.{label}")


def _read_cohort(cohort: ReadOnlyCohort, label: str) -> dict[str, Any]:
    method = getattr(cohort, "read_cohort", None)
    if not callable(method):
        raise CrossStoreCaptureError("CAPTURE_SOURCE_UNOBSERVABLE", "cohort lacks read_cohort()")
    try:
        raw = method()
    except CrossStoreCaptureError:
        raise
    except Exception as exc:
        raise CrossStoreCaptureError("CAPTURE_SOURCE_UNOBSERVABLE", f"cohort failed at {label}") from exc
    if not isinstance(raw, Mapping) or set(raw) != COHORT_RESULT_KEYS:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"cohort {label} keys are not exact")
    generation = raw["generation"]
    if not isinstance(generation, Mapping) or set(generation) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", f"cohort {label} generation participant set is not exact")
    normalized_generation: dict[str, dict[str, Any]] = {}
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        item = generation[participant_id]
        if not isinstance(item, Mapping) or set(item) != COHORT_GENERATION_KEYS:
            raise CrossStoreCaptureError(
                "CAPTURE_SCHEMA_INVALID", f"cohort {label} generation {participant_id} keys are not exact"
            )
        normalized_generation[participant_id] = {
            "generation": _integer(item["generation"], f"cohort.{label}.generation.{participant_id}.generation"),
            "generation_id": _hash64(
                item["generation_id"], f"cohort.{label}.generation.{participant_id}.generation_id"
            ),
        }
    return {
        "fence": _copy_json(raw["fence"], f"cohort.{label}.fence"),
        "lease": _copy_json(raw["lease"], f"cohort.{label}.lease"),
        "generation": normalized_generation,
    }


def _validate_generation_binding(
    cohort_generation: Mapping[str, Mapping[str, Any]],
    samples: Mapping[str, Mapping[str, Any]],
    label: str,
) -> None:
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        cursor = samples[participant_id]["source_cursor"]
        generation = cohort_generation[participant_id]
        if not isinstance(cursor, Mapping) or cursor.get("generation") != generation["generation"] or cursor.get("generation_id") != generation["generation_id"]:
            raise CrossStoreCaptureError(
                "CAPTURE_GENERATION_DRIFT", f"source {participant_id} does not match the {label} generation cohort"
            )


def _actionless_result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    result = {
        "schema_version": CROSS_STORE_CAPTURE_VERIFICATION_SCHEMA,
        "contract_role": CROSS_STORE_CAPTURE_ROLE,
        "status": status,
        "reason": reason,
        "permission": "read_only",
        "external_action": False,
        "mutation_allowed": False,
        "authoritative_decision": False,
        "resume_allowed": False,
        "consume_allowed": False,
        "cas_authorized": False,
        "execution": {key: False for key in sorted(EXECUTION_KEYS)},
    }
    result.update(extra)
    return result


def capture_cross_store_snapshot(
    *,
    transaction_id: str,
    observer: Mapping[str, Any],
    source_identities: Mapping[str, Mapping[str, Any]],
    readers: Mapping[str, ReadOnlySnapshotReader],
    source_capabilities: Mapping[str, Mapping[str, Any]],
    capture_context: Mapping[str, Any],
    clock: ReadOnlyClock,
    cohort: ReadOnlyCohort,
    expected_projection_manifest: Mapping[str, Any],
    fence: Mapping[str, Any],
    replay: Mapping[str, Any],
    s12_input: Mapping[str, Any],
) -> dict[str, Any]:
    """Capture five approved readers twice and return a validated S13 envelope."""

    transaction_id = _safe_id(transaction_id, "transaction_id")
    normalized_observer = _validate_observer(observer)
    if not isinstance(source_identities, Mapping) or set(source_identities) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", "source identity participant set is not exact")
    if not isinstance(readers, Mapping) or set(readers) != SNAPSHOT_PARTICIPANT_IDS:
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", "reader participant set is not exact")
    normalized_sources = {
        participant_id: _validate_source_identity(participant_id, source_identities[participant_id])
        for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS)
    }
    normalized_capabilities = _validate_capabilities(source_capabilities)
    source_ids = [normalized_sources[participant_id]["source_id"] for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS)]
    if len(set(source_ids)) != len(source_ids):
        raise CrossStoreCaptureError("CAPTURE_SOURCE_DRIFT", "source IDs are not unique")
    context = _validate_context(capture_context)
    expected_fence = _copy_json(fence, "fence")
    if not isinstance(s12_input, Mapping):
        raise CrossStoreCaptureError("CAPTURE_SCHEMA_INVALID", "s12_input must be an object")
    expected_lease = _copy_json(s12_input.get("lease"), "s12_input.lease")
    clock_before = _sample_clock(clock, "before")
    cohort_before = _read_cohort(cohort, "before")
    participant_ids = tuple(sorted(SNAPSHOT_PARTICIPANT_IDS))
    first = _read_pass(readers, normalized_sources, normalized_capabilities, participant_ids)
    second = _read_pass(readers, normalized_sources, normalized_capabilities, participant_ids)
    cohort_after = _read_cohort(cohort, "after")
    clock_after = _sample_clock(clock, "after")
    if clock_after < clock_before:
        raise CrossStoreCaptureError("CAPTURE_CLOCK_DRIFT", "capture clock moved backwards")
    if cohort_before["fence"] != cohort_after["fence"]:
        raise CrossStoreCaptureError("CAPTURE_FENCE_DRIFT", "fence changed during capture")
    if cohort_before["lease"] != cohort_after["lease"]:
        raise CrossStoreCaptureError("CAPTURE_LEASE_DRIFT", "lease changed during capture")
    if cohort_before["fence"] != expected_fence:
        raise CrossStoreCaptureError("CAPTURE_FENCE_DRIFT", "capture fence differs from the observed cohort")
    if cohort_before["lease"] != expected_lease:
        raise CrossStoreCaptureError("CAPTURE_LEASE_DRIFT", "capture lease differs from the observed cohort")
    _validate_generation_binding(cohort_before["generation"], first, "first-pass")
    _validate_generation_binding(cohort_after["generation"], second, "second-pass")
    if cohort_before["generation"] != cohort_after["generation"]:
        raise CrossStoreCaptureError("CAPTURE_GENERATION_DRIFT", "source generation cohort changed during capture")
    for participant_id in sorted(SNAPSHOT_PARTICIPANT_IDS):
        first_item = first[participant_id]
        second_item = second[participant_id]
        identity_keys = ("source_id", "snapshot_id", "source_identity_sha256")
        if any(first_item[key] != second_item[key] for key in identity_keys):
            raise CrossStoreCaptureError("CAPTURE_SOURCE_DRIFT", f"source {participant_id} changed identity during capture")
        if first_item["source_cursor"] != second_item["source_cursor"] or first_item["projection"] != second_item["projection"]:
            raise CrossStoreCaptureError("CAPTURE_TOCTOU_DETECTED", f"source {participant_id} changed during capture")
    builder_context = {
        **context,
        "clock_before": clock_before,
        "clock_after": clock_after,
    }
    try:
        envelope = build_cross_store_snapshot_envelope(
            transaction_id=transaction_id,
            observer=normalized_observer,
            sources=normalized_sources,
            source_samples=first,
            capture_context=builder_context,
            expected_projection_manifest=expected_projection_manifest,
            fence=fence,
            replay=replay,
            s12_input=s12_input,
            source_samples_after=second,
        )
    except CrossStoreSnapshotError as exc:
        raise CrossStoreCaptureError("CAPTURE_S13_REJECTED", str(exc), source_code=exc.code) from exc
    return envelope


def evaluate_cross_store_capture(**kwargs: Any) -> dict[str, Any]:
    """Return an actionless capture result, mapping drift to recovery-required."""

    try:
        envelope = capture_cross_store_snapshot(**kwargs)
        return _actionless_result(
            "CAPTURED_READ_ONLY",
            "S13_ENVELOPE_VALIDATED",
            transaction_id=envelope["transaction_id"],
            envelope_sha256=_digest(envelope, "capture envelope"),
            envelope=envelope,
        )
    except CrossStoreCaptureError as exc:
        source_reason = exc.source_code or exc.code
        status = "RECOVERY_REQUIRED" if source_reason in _RECOVERY_CODES else "HOLD"
        return _actionless_result(status, source_reason)
    except Exception:
        return _actionless_result("HOLD", "CAPTURE_SCHEMA_INVALID")


__all__ = [
    "CROSS_STORE_CAPTURE_ROLE",
    "CROSS_STORE_CAPTURE_SCHEMA",
    "CROSS_STORE_CAPTURE_VERIFICATION_SCHEMA",
    "CAPTURE_ERROR_CODES",
    "CrossStoreCaptureError",
    "ReadOnlyClock",
    "ReadOnlyCohort",
    "ReadOnlySnapshotReader",
    "capture_cross_store_snapshot",
    "evaluate_cross_store_capture",
]
