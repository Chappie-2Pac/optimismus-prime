"""S17-to-S18 validation bridge.

The persistent store intentionally exposes only a private low-level CAS
method.  This adapter is the production entrypoint: it re-runs the complete
S16/S17 verification, derives every candidate value from the signed proof and
then passes only that derived candidate to the owner store.
"""

from __future__ import annotations

from typing import Any, Mapping

from .cross_store_owner import (
    CrossStoreOwnerError,
    OWNER_OPERATION as S17_OWNER_OPERATION,
    OWNER_PREFLIGHT_SCHEMA,
    parse_owner_observation,
    verify_replay_owner_preflight,
)
from .replay_owner_store import OWNER_OPERATION, ReplayOwnerStore


class ReplayOwnerAdapterError(ValueError):
    """S17 proof was invalid or did not describe a writable candidate."""


def advance_from_s17_preflight(
    store: ReplayOwnerStore,
    *,
    worker_attestations: Mapping[str, Mapping[str, Any]],
    replay_observation: Mapping[str, Any],
    replay_floor: Mapping[str, Any],
    host_runtime_attestation: Mapping[str, Any],
    s15_input: Mapping[str, Any],
    owner_observation: Mapping[str, Any] | bytes | str | None,
    request: Mapping[str, Any],
    lease_token: str,
) -> dict[str, Any]:
    """Verify S16/S17 and atomically apply only the derived owner candidate."""

    try:
        proof = verify_replay_owner_preflight(
            worker_attestations=worker_attestations,
            replay_observation=replay_observation,
            replay_floor=replay_floor,
            host_runtime_attestation=host_runtime_attestation,
            s15_input=s15_input,
            owner_observation=owner_observation,
            request=request,
        )
        parsed_owner = parse_owner_observation(owner_observation)
    except (CrossStoreOwnerError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ReplayOwnerAdapterError("S16/S17 proof could not be verified") from exc

    if (
        proof.get("schema_version") != OWNER_PREFLIGHT_SCHEMA
        or proof.get("status") != "OWNER_PREVIEW_ONLY"
        or proof.get("decision") != "CAS_RECHECK_REQUIRED"
        or proof.get("authoritative_decision") is not False
        or proof.get("owner_state_advanced") is not False
        or proof.get("idempotency_reserved") is not False
        or proof.get("cas_authorized") is not False
        or proof.get("consume_allowed") is not False
        or proof.get("owner_cas_required") is not True
    ):
        raise ReplayOwnerAdapterError("S17 result is not the exact read-only owner preview")

    candidate = proof.get("candidate")
    owner = parsed_owner.get("payload")
    if not isinstance(candidate, Mapping) or not isinstance(owner, Mapping):
        raise ReplayOwnerAdapterError("S17 candidate or owner payload is incomplete")
    if candidate.get("operation") != S17_OWNER_OPERATION or candidate.get("operation") != OWNER_OPERATION:
        raise ReplayOwnerAdapterError("S17 operation is not ADVANCE_REPLAY")
    if candidate.get("owner_id") != owner.get("owner_id") or candidate.get("owner_instance_id") != owner.get("owner_instance_id"):
        raise ReplayOwnerAdapterError("S17 owner identity differs from the signed observation")

    scope_binding = {
        key: candidate[key] if key in candidate else owner[key]
        for key in (
            "replay_namespace",
            "registry_id",
            "registry_version",
            "registry_epoch",
            "registry_sha256",
            "profile_set_sha256",
            "source_set_sha256",
            "cohort_binding_sha256",
            "host_id",
            "host_instance_id",
            "worker_epoch",
        )
    }
    intent = {
        "schema_version": "prime-cross-store-replay-owner-s17-intent-v1",
        "s17_preflight_sha256": proof["preflight_sha256"],
        "owner_observation_sha256": proof["owner_observation_sha256"],
        "worker_authorization_sha256": proof["worker_authorization_sha256"],
        "s16_replay_observation_sha256": proof["s16_replay_observation_sha256"],
        "s16_replay_floor_sha256": proof["s16_replay_floor_sha256"],
        "candidate": dict(candidate),
    }
    return store._advance_validated(
        scope_id=store.scope_id,
        scope_binding=scope_binding,
        owner_id=candidate["owner_id"],
        owner_instance_id=candidate["owner_instance_id"],
        owner_epoch=owner["owner_epoch"],
        fencing_epoch=candidate["owner_fencing_epoch"],
        lease_token=lease_token,
        idempotency_key=candidate["idempotency_key"],
        transaction_id=candidate["transaction_id"],
        operation=OWNER_OPERATION,
        intent=intent,
        expected_state_version=candidate["expected_state_version"],
        expected_head_sha256=candidate["parent_owner_head_sha256"],
        expected_sequence=candidate["expected_sequence"],
        next_sequence=candidate["next_sequence"],
        next_attestation_set_sha256=candidate["next_attestation_set_sha256"],
        next_nonce_sha256=candidate["next_nonce_sha256"],
    )


__all__ = ["ReplayOwnerAdapterError", "advance_from_s17_preflight"]
