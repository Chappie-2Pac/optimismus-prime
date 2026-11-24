"""Pure S25K policy matrix for a proposed asymmetric Authority contract.

This module deliberately does not implement Ed25519, JCS, a trust store, a
revocation service, a replay floor, a clock, a lock, a CAS or a writer.  It
classifies already supplied *synthetic* layer observations so the architecture
and its fail-closed oracles can be tested before a production dependency is
chosen and sealed.

The only positive result is ``NOT_CLAIMED / DESIGN_ONLY``.  A complete
observation therefore describes a reproducible design contract; it never
becomes a capability or a permission to mutate a subject.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


HARNESS_SCHEMA = "prime-queue-asymmetric-authority-contract-v1"
OBSERVE_ONLY = "OBSERVE_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
MANUAL_REVIEW = "MANUAL_REVIEW"
NOT_CLAIMED = "NOT_CLAIMED"
HOLD = "HOLD"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
TEST_BLOCKED = "TEST_BLOCKED"

_FORMAT = "s25k.quarantine-grant.v1"
_ALGORITHM = "Ed25519-v1"
_CANONICALIZATION = "RFC8785-JCS-v1"
_DOMAIN_SEPARATOR = "S25K/QUARANTINE-GRANT/v1\x00"
_VECTOR_ID = "RFC8032-ED25519-1"
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$\Z")

_SECTIONS = (
    "architecture",
    "dependency",
    "vector",
    "trust",
    "revocation",
    "replay",
    "binding",
    "lease",
    "generation",
    "clock",
    "faults",
)
_DANGEROUS_CLAIMS = (
    "authorized",
    "capability_issued",
    "write_authorized",
    "cas_committed",
    "fence_issued",
    "resume_allowed",
    "mutation_allowed",
    "production_ready",
)
_BINDING_FIELDS = (
    "root",
    "authority_store",
    "scope",
    "store",
    "transaction",
    "idempotency",
    "evidence",
    "generation",
    "fence",
)


def _output(
    status: str,
    decision: str,
    reason: str,
    *,
    gaps: list[str],
    case_id: str = "unknown",
    dependency_status: str = NOT_CLAIMED,
    crypto_status: str = NOT_CLAIMED,
) -> dict[str, Any]:
    """Build the immutable no-write result shared by every oracle branch."""

    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVE_ONLY,
        "case_id": case_id,
        "status": status,
        "decision": decision,
        "reason": reason,
        "audit_gaps": list(gaps),
        "dependency_status": dependency_status,
        "cryptographic_status": crypto_status,
        "architecture_claim": NOT_CLAIMED,
        "authority_claim": NOT_CLAIMED,
        "capability_issued": False,
        "write_authorized": False,
        "cas_attempted": False,
        "cas_committed": False,
        "fence_issued": False,
        "persistence_performed": False,
        "quarantine_persisted": False,
        "mutation_allowed": False,
        "resume_allowed": False,
        "recovery_authority": False,
        "cross_store_atomicity": NOT_CLAIMED,
        "exactly_once_claim": NOT_CLAIMED,
    }


def _manual(reason: str, gaps: list[str], case_id: str) -> dict[str, Any]:
    return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, reason, gaps=gaps, case_id=case_id)


def _hold(reason: str, gaps: list[str], case_id: str) -> dict[str, Any]:
    return _output(HOLD, HOLD, reason, gaps=gaps, case_id=case_id)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value


def _integer(value: Any) -> bool:
    return type(value) is int


def _section(observation: Mapping[str, Any], name: str) -> Mapping[str, Any] | None:
    value = observation.get(name)
    return value if isinstance(value, Mapping) else None


def evaluate_asymmetric_contract(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Classify a synthetic S25K observation without executing any authority.

    Every layer is supplied by the test fixture.  No value is discovered from
    the host, verified by a cryptographic backend, read from a store, or
    written back to one.  This is intentionally a policy oracle, not a
    signature verifier.
    """

    if not isinstance(observation, Mapping):
        return _manual("OBSERVATION_NOT_MAPPING", ["OBSERVATION_TYPE"], "unknown")

    case_id = observation.get("case_id", "unknown")
    case_id = case_id if _text(case_id) else "unknown"

    dangerous = [key for key in _DANGEROUS_CLAIMS if observation.get(key) is True]
    if dangerous:
        return _manual("UNTRUSTED_AUTHORITY_CLAIM", dangerous, case_id)

    missing = [name for name in _SECTIONS if not isinstance(observation.get(name), Mapping)]
    if missing:
        return _manual(
            "OBSERVATION_INCOMPLETE",
            [f"MISSING_{name.upper()}" for name in missing],
            case_id,
        )

    architecture = _section(observation, "architecture")
    dependency = _section(observation, "dependency")
    vector = _section(observation, "vector")
    trust = _section(observation, "trust")
    revocation = _section(observation, "revocation")
    replay = _section(observation, "replay")
    binding = _section(observation, "binding")
    lease = _section(observation, "lease")
    generation = _section(observation, "generation")
    clock = _section(observation, "clock")
    faults = _section(observation, "faults")

    # The explicit architecture IDs prevent algorithm, canonicalization and
    # domain-separator downgrade.  A legacy canonicalizer is not silently
    # treated as RFC 8785/JCS.
    assert architecture is not None
    if architecture.get("format") != _FORMAT:
        return _hold("FORMAT_NOT_ALLOWLISTED", ["FORMAT"], case_id)
    if architecture.get("algorithm") != _ALGORITHM:
        return _hold("ALGORITHM_NOT_ALLOWLISTED", ["ALGORITHM"], case_id)
    if architecture.get("canonicalization") != _CANONICALIZATION:
        return _hold("CANONICALIZATION_NOT_LOCKED", ["CANONICALIZATION"], case_id)
    if architecture.get("domain_separator") != _DOMAIN_SEPARATOR:
        return _manual("DOMAIN_SEPARATOR_MISMATCH", ["DOMAIN_SEPARATOR"], case_id)
    if architecture.get("fallback") != "NONE":
        return _hold("ALGORITHM_FALLBACK_FORBIDDEN", ["FALLBACK_POLICY"], case_id)
    if architecture.get("private_key_policy") != "EXTERNAL_ONLY":
        return _manual("PRIVATE_KEY_BOUNDARY_INVALID", ["PRIVATE_KEY_POLICY"], case_id)
    if architecture.get("trust_root_source") != "EXTERNAL_PINNED_BUNDLE":
        return _manual("TRUST_ROOT_SOURCE_INVALID", ["TRUST_ROOT_SOURCE"], case_id)
    if architecture.get("revocation_source") != "EXTERNAL_SIGNED_SNAPSHOT":
        return _manual("REVOCATION_SOURCE_INVALID", ["REVOCATION_SOURCE"], case_id)

    # Dependency data is a proposed, hash-pinned decision record.  It is not
    # an import or an environment probe; missing/ambiguous data blocks the
    # test contract instead of being counted as a green architecture test.
    assert dependency is not None
    required_dependency = (
        "lock_status",
        "package",
        "package_version",
        "package_hash",
        "backend",
        "backend_version",
        "python_version",
        "fallback",
    )
    if any(not _text(dependency.get(key)) for key in required_dependency):
        return _output(
            TEST_BLOCKED,
            HOLD,
            "DEPENDENCY_DECISION_INCOMPLETE",
            gaps=[f"DEPENDENCY_{key.upper()}" for key in required_dependency if not _text(dependency.get(key))],
            case_id=case_id,
            dependency_status="TEST_BLOCKED",
        )
    if dependency.get("lock_status") != "PROPOSED_HASH_PINNED":
        return _output(
            TEST_BLOCKED,
            HOLD,
            "DEPENDENCY_LOCK_NOT_SEALED",
            gaps=["HASH_PINNED_LOCK"],
            case_id=case_id,
            dependency_status="TEST_BLOCKED",
        )
    if dependency.get("package") != "cryptography" or dependency.get("backend") != "OpenSSL":
        return _output(
            TEST_BLOCKED,
            HOLD,
            "DEPENDENCY_BACKEND_NOT_SELECTED",
            gaps=["SUPPORTED_BACKEND"],
            case_id=case_id,
            dependency_status="TEST_BLOCKED",
        )
    if _HASH.fullmatch(str(dependency.get("package_hash"))) is None:
        return _output(
            TEST_BLOCKED,
            HOLD,
            "DEPENDENCY_HASH_INVALID",
            gaps=["PACKAGE_HASH"],
            case_id=case_id,
            dependency_status="TEST_BLOCKED",
        )
    if dependency.get("fallback") != "NONE":
        return _hold("DEPENDENCY_FALLBACK_FORBIDDEN", ["DEPENDENCY_FALLBACK"], case_id)

    # The vector is deliberately only a declared external fixture.  This
    # module does not verify it and therefore never returns cryptographic
    # authority evidence.
    assert vector is not None
    if vector.get("vector_id") != _VECTOR_ID or vector.get("status") != "DECLARED_EXTERNAL_FIXTURE":
        return _hold("GOLDEN_VECTOR_NOT_DECLARED", ["EXTERNAL_GOLDEN_VECTOR"], case_id)
    if vector.get("private_key_source") != "ISOLATED_FIXTURE" or vector.get("signature_source") != "EXTERNAL_ORACLE":
        return _manual("TEST_KEY_BOUNDARY_INVALID", ["TEST_KEY_ORACLE"], case_id)

    assert trust is not None
    if trust.get("root_status") == "UNKNOWN" or trust.get("authority_status") == "UNKNOWN":
        return _hold("TRUST_SNAPSHOT_UNKNOWN", ["TRUST_SNAPSHOT"], case_id)
    if trust.get("root_status") != "PINNED" or trust.get("authority_status") != "ACTIVE":
        return _manual("TRUST_ROOT_OR_KEY_REJECTED", ["TRUST_STATUS"], case_id)
    if not all(_text(trust.get(key)) for key in ("root_id", "root_fingerprint", "authority_id", "key_id")):
        return _manual("TRUST_IDENTITY_INCOMPLETE", ["TRUST_IDENTITY"], case_id)
    if not _integer(trust.get("authority_sequence")) or trust["authority_sequence"] <= 0:
        return _manual("AUTHORITY_SEQUENCE_INVALID", ["AUTHORITY_SEQUENCE"], case_id)

    assert revocation is not None
    if revocation.get("snapshot_status") in {"MISSING", "STALE", "UNAUTHENTICATED"}:
        return _hold("REVOCATION_SNAPSHOT_UNKNOWN", ["REVOCATION_SNAPSHOT"], case_id)
    if revocation.get("snapshot_status") != "CLEAR":
        return _manual("REVOCATION_REJECTED", ["REVOCATION_STATUS"], case_id)
    if revocation.get("key_revoked") is True or revocation.get("grant_revoked") is True:
        return _manual("KEY_OR_GRANT_REVOKED", ["REVOCATION"], case_id)
    if not _integer(revocation.get("sequence_floor")):
        return _hold("REVOCATION_FLOOR_UNKNOWN", ["SEQUENCE_FLOOR"], case_id)
    if trust["authority_sequence"] <= revocation["sequence_floor"]:
        return _manual("AUTHORITY_SEQUENCE_REVOKED", ["SEQUENCE_FLOOR"], case_id)

    assert lease is not None
    if lease.get("status") in {"NOT_YET_VALID", "EXPIRED", "TIME_UNKNOWN"}:
        return _hold("LEASE_NOT_CURRENT", ["LEASE_FRESHNESS"], case_id)
    if lease.get("status") != "FRESH":
        return _manual("LEASE_STATUS_INVALID", ["LEASE_STATUS"], case_id)
    if not all(_integer(lease.get(key)) for key in ("now", "not_before", "expires_at")):
        return _manual("LEASE_WINDOW_INVALID", ["LEASE_WINDOW"], case_id)
    if lease["expires_at"] <= lease["not_before"] or not (
        lease["not_before"] <= lease["now"] < lease["expires_at"]
    ):
        return _hold("LEASE_NOT_CURRENT", ["LEASE_FRESHNESS"], case_id)

    assert replay is not None
    if replay.get("snapshot_status") in {"MISSING", "STALE", "UNAUTHENTICATED"}:
        return _hold("REPLAY_SNAPSHOT_UNKNOWN", ["REPLAY_SNAPSHOT"], case_id)
    if replay.get("snapshot_status") != "PRESENT":
        return _manual("REPLAY_SNAPSHOT_REJECTED", ["REPLAY_SNAPSHOT"], case_id)
    if replay.get("grant_status") != "UNUSED" or replay.get("sequence_status") != "ABOVE_FLOOR":
        return _manual("REPLAY_DETECTED", ["REPLAY"], case_id)
    if replay.get("incarnation_status") != "PROVEN":
        return _manual("INCARNATION_PROOF_MISSING", ["INCARNATION"], case_id)

    assert binding is not None
    if binding.get("authority_store_independent") is not True:
        return _manual("AUTHORITY_NOT_INDEPENDENT", ["AUTHORITY_STORE"], case_id)
    unknown_bindings = [field for field in _BINDING_FIELDS if binding.get(field) == "UNKNOWN"]
    if unknown_bindings:
        return _hold("LOCAL_BINDING_UNKNOWN", unknown_bindings, case_id)
    mismatches = [field for field in _BINDING_FIELDS if binding.get(field) != "MATCH"]
    if mismatches:
        return _manual("LOCAL_BINDING_MISMATCH", mismatches, case_id)

    assert generation is not None
    if generation.get("aba") is True or generation.get("reused") is True or generation.get("foreign_writer") is True:
        return _manual("GENERATION_OR_FOREIGN_DRIFT", ["GENERATION_DRIFT"], case_id)
    if generation.get("status") != "MATCH" or generation.get("incarnation") != "PROVEN":
        return _manual("GENERATION_PROOF_INVALID", ["GENERATION"], case_id)

    assert clock is not None
    if clock.get("status") in {"UNKNOWN", "NON_MONOTONIC"}:
        return _manual("CLOCK_PROOF_INVALID", ["CLOCK"], case_id)
    if clock.get("status") != "FRESH" or clock.get("monotonic") is not True:
        return _hold("CLOCK_NOT_FRESH", ["CLOCK"], case_id)

    assert faults is not None
    crash_phase = faults.get("crash_phase")
    if crash_phase in {"AFTER_UNKNOWN_CAS", "AFTER_EXTERNAL_COMMIT"}:
        return _manual("UNKNOWN_OUTCOME_REQUIRES_REVIEW", ["CRASH_OUTCOME"], case_id)
    if crash_phase in {"BEFORE_VERIFICATION", "AFTER_VERIFICATION", "AFTER_DESIGN_ONLY"}:
        return _output(
            NOT_CLAIMED,
            DESIGN_ONLY,
            "EPHEMERAL_TEST_RESULT_REQUIRES_RECHECK",
            gaps=["PROCESS_RESTART"],
            case_id=case_id,
            dependency_status="PROPOSED_HASH_PINNED",
            crypto_status="NOT_VERIFIED",
        )
    if crash_phase != "NONE":
        return _manual("CRASH_PHASE_UNKNOWN", ["CRASH_PHASE"], case_id)
    if faults.get("cas_outcome") != "NOT_ATTEMPTED" or faults.get("foreign_writer") != "NONE":
        return _manual("MUTATION_OR_FOREIGN_WRITER_CLAIM", ["NO_WRITE_BOUNDARY"], case_id)

    return _output(
        NOT_CLAIMED,
        DESIGN_ONLY,
        "ASYMMETRIC_CONTRACT_DESIGN_ONLY",
        gaps=["CRYPTOGRAPHIC_BACKEND_NOT_VERIFIED", "PRODUCTION_AUTHORITY_NOT_IMPLEMENTED"],
        case_id=case_id,
        dependency_status="PROPOSED_HASH_PINNED",
        crypto_status="NOT_VERIFIED",
    )


__all__ = [
    "DESIGN_ONLY",
    "HARNESS_SCHEMA",
    "HOLD",
    "MANUAL_REVIEW",
    "NOT_CLAIMED",
    "OBSERVE_ONLY",
    "RECOVERY_REQUIRED",
    "TEST_BLOCKED",
    "evaluate_asymmetric_contract",
]
