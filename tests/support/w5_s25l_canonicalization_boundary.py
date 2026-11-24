"""Pure S25L metadata gates for canonicalization and RFC-8032 vectors.

S25L does not implement JCS or Ed25519.  It checks exact, public
RFC-8032-known-answer metadata, the proposed S25K preimage contract and the
boundary between the existing legacy serializer and the unimplemented JCS
profile.  A metadata match is evidence about a fixture only; it is never a
signature verification or a production capability.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


HARNESS_SCHEMA = "prime-queue-canonicalization-golden-vector-v1"
OBSERVE_ONLY = "OBSERVE_ONLY"
DESIGN_ONLY = "DESIGN_ONLY"
LEGACY_REGRESSION_ONLY = "LEGACY_REGRESSION_ONLY"
HOLD = "HOLD"
MANUAL_REVIEW = "MANUAL_REVIEW"
NOT_CLAIMED = "NOT_CLAIMED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
TEST_BLOCKED = "TEST_BLOCKED"

LEGACY_CANONICALIZATION = "json-sortkeys-v1"
JCS_CANONICALIZATION = "RFC8785-JCS-v1"
ED25519_ALGORITHM = "Ed25519"
ED25519_ALGORITHM_ID = "Ed25519-v1"
S25K_FORMAT = "s25k.quarantine-grant.v1"
S25K_DOMAIN_SEPARATOR_HEX = "5332354b2f51554152414e54494e452d4752414e542f763100"
RFC8032_SOURCE = "RFC8032_SECTION_7_1"

_HEX = re.compile(r"^[0-9a-f]*\Z")
_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_DANGEROUS_CLAIMS = (
    "signature_valid",
    "verified",
    "authorized",
    "capability_issued",
    "write_authorized",
)
_PREIMAGE_FIELDS = (
    "algorithm",
    "canonicalization",
    "format",
    "authority_id",
    "key_id",
    "payload",
)

# RFC 8032 public keys and signatures are public verification material.  The
# private seeds are intentionally not stored in this project.  TEST 1024 is
# represented by its required length/digest metadata until a complete external
# message fixture and an independent locked backend exist.
_VECTORS: dict[str, dict[str, Any]] = {
    "RFC8032-ED25519-1": {
        "message_hex": "",
        "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "signature_hex": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    "RFC8032-ED25519-2": {
        "message_hex": "72",
        "public_key_hex": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "signature_hex": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    "RFC8032-ED25519-3": {
        "message_hex": "af82",
        "public_key_hex": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "signature_hex": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
    "RFC8032-ED25519-1024": {
        "message_length": 1023,
        "message_sha256": "358c67baee6b3e0265787951d1840a8468b9e9044852f1c67229a892b2cc0d22",
        "public_key_hex": "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "signature_hex": "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    },
    "RFC8032-ED25519-SHA-ABC": {
        "message_hex": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "public_key_hex": "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "signature_hex": "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    },
}


def _output(
    status: str,
    decision: str,
    reason: str,
    *,
    case_id: str,
    gaps: list[str],
    vector_status: str = NOT_CLAIMED,
    canonicalization_status: str = NOT_CLAIMED,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": OBSERVE_ONLY,
        "case_id": case_id,
        "status": status,
        "decision": decision,
        "reason": reason,
        "audit_gaps": list(gaps),
        "vector_status": vector_status,
        "canonicalization_status": canonicalization_status,
        "signature_verification": NOT_CLAIMED,
        "authority_claim": NOT_CLAIMED,
        "capability_issued": False,
        "write_authorized": False,
        "persistence_performed": False,
        "cas_attempted": False,
        "fence_issued": False,
        "resume_allowed": False,
        "mutation_allowed": False,
        "cross_store_atomicity": NOT_CLAIMED,
        "exactly_once_claim": NOT_CLAIMED,
    }


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value


def _hex(value: Any, *, length: int | None = None) -> bool:
    if not isinstance(value, str) or not _HEX.fullmatch(value) or len(value) % 2:
        return False
    return length is None or len(value) == length


def evaluate_rfc8032_vector(vector: Mapping[str, Any]) -> dict[str, Any]:
    """Check public RFC-8032 fixture metadata without running crypto."""

    if not isinstance(vector, Mapping):
        return _output(TEST_BLOCKED, HOLD, "VECTOR_NOT_MAPPING", case_id="unknown", gaps=["VECTOR_TYPE"])
    case_id = vector.get("vector_id", "unknown")
    case_id = case_id if _text(case_id) else "unknown"
    dangerous = [field for field in _DANGEROUS_CLAIMS if vector.get(field) is True]
    if dangerous:
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "UNTRUSTED_VECTOR_CLAIM", case_id=case_id, gaps=dangerous)
    expected = _VECTORS.get(case_id)
    if expected is None:
        return _output(HOLD, HOLD, "VECTOR_NOT_ALLOWLISTED", case_id=case_id, gaps=["VECTOR_ID"])
    if vector.get("algorithm") != ED25519_ALGORITHM:
        return _output(HOLD, HOLD, "ALGORITHM_NOT_ALLOWLISTED", case_id=case_id, gaps=["ALGORITHM"])
    if vector.get("source") != RFC8032_SOURCE:
        return _output(TEST_BLOCKED, HOLD, "VECTOR_SOURCE_UNVERIFIED", case_id=case_id, gaps=["VECTOR_SOURCE"])
    if vector.get("private_key_material") != "NOT_INCLUDED":
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "PRIVATE_KEY_MATERIAL_PRESENT", case_id=case_id, gaps=["PRIVATE_KEY"])
    if vector.get("verification_status") != "NOT_RUN":
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "VERIFICATION_OVERCLAIM", case_id=case_id, gaps=["VERIFICATION_STATUS"])

    if vector.get("public_key_hex") != expected["public_key_hex"] or vector.get("signature_hex") != expected["signature_hex"]:
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "VECTOR_BYTES_MISMATCH", case_id=case_id, gaps=["PUBLIC_OR_SIGNATURE"])
    if not _hex(vector.get("public_key_hex"), length=64) or not _hex(vector.get("signature_hex"), length=128):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "VECTOR_LENGTH_INVALID", case_id=case_id, gaps=["VECTOR_LENGTH"])

    if "message_hex" in expected:
        if vector.get("message_hex") != expected["message_hex"] or not _hex(vector.get("message_hex")):
            return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "MESSAGE_BYTES_MISMATCH", case_id=case_id, gaps=["MESSAGE"])
    else:
        if vector.get("message_length") != expected["message_length"] or vector.get("message_sha256") != expected["message_sha256"]:
            return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "LONG_MESSAGE_METADATA_MISMATCH", case_id=case_id, gaps=["MESSAGE_DIGEST"])
        return _output(TEST_BLOCKED, HOLD, "FULL_MESSAGE_FIXTURE_REQUIRED", case_id=case_id, gaps=["FULL_MESSAGE_BYTES"], vector_status="METADATA_EXACT")

    return _output(
        NOT_CLAIMED,
        DESIGN_ONLY,
        "RFC8032_METADATA_EXACT_CRYPTO_NOT_RUN",
        case_id=case_id,
        gaps=["CRYPTOGRAPHIC_BACKEND_NOT_VERIFIED"],
        vector_status="METADATA_EXACT",
    )


def evaluate_preimage_contract(preimage: Mapping[str, Any]) -> dict[str, Any]:
    """Check S25K preimage metadata and refuse an unimplemented JCS claim."""

    if not isinstance(preimage, Mapping):
        return _output(TEST_BLOCKED, HOLD, "PREIMAGE_NOT_MAPPING", case_id="unknown", gaps=["PREIMAGE_TYPE"])
    case_id = preimage.get("case_id", "preimage")
    case_id = case_id if _text(case_id) else "preimage"
    dangerous = [field for field in _DANGEROUS_CLAIMS if preimage.get(field) is True]
    if dangerous:
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "UNTRUSTED_PREIMAGE_CLAIM", case_id=case_id, gaps=dangerous)
    required = (
        "format",
        "algorithm",
        "canonicalization",
        "domain_separator_hex",
        "preimage_fields",
        "authority_id_bound",
        "key_id_bound",
        "payload_bound",
        "jcs_execution",
    )
    missing = [field for field in required if field not in preimage]
    if missing:
        return _output(TEST_BLOCKED, HOLD, "PREIMAGE_CONTRACT_INCOMPLETE", case_id=case_id, gaps=missing)
    expected = {
        "format": S25K_FORMAT,
        "algorithm": ED25519_ALGORITHM_ID,
        "canonicalization": JCS_CANONICALIZATION,
        "domain_separator_hex": S25K_DOMAIN_SEPARATOR_HEX,
    }
    drift = [field for field, value in expected.items() if preimage.get(field) != value]
    if drift:
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "PREIMAGE_CONTRACT_DRIFT", case_id=case_id, gaps=drift)
    if preimage.get("preimage_fields") != list(_PREIMAGE_FIELDS):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "PREIMAGE_FIELD_ORDER_DRIFT", case_id=case_id, gaps=["PREIMAGE_FIELDS"])
    if not all(preimage.get(field) is True for field in ("authority_id_bound", "key_id_bound", "payload_bound")):
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "PREIMAGE_BINDING_INCOMPLETE", case_id=case_id, gaps=["PREIMAGE_BINDINGS"])
    if preimage.get("jcs_execution") == "INDEPENDENT_MATCH":
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "JCS_EXECUTION_OVERCLAIM", case_id=case_id, gaps=["JCS_NOT_IMPLEMENTED"])
    if preimage.get("jcs_execution") == "UNKNOWN":
        return _output(HOLD, HOLD, "JCS_EXECUTION_UNKNOWN", case_id=case_id, gaps=["JCS_EXECUTION"])
    if preimage.get("jcs_execution") != "NOT_IMPLEMENTED":
        return _output(TEST_BLOCKED, HOLD, "JCS_EXECUTION_NOT_LOCKED", case_id=case_id, gaps=["JCS_EXECUTION"])
    return _output(
        TEST_BLOCKED,
        HOLD,
        "JCS_NOT_IMPLEMENTED",
        case_id=case_id,
        gaps=["JCS_REFERENCE_IMPLEMENTATION", "LOCKED_CRYPTO_BACKEND"],
        canonicalization_status="NOT_IMPLEMENTED",
    )


def evaluate_legacy_boundary(boundary: Mapping[str, Any]) -> dict[str, Any]:
    """Keep the existing legacy format separate from the unimplemented JCS."""

    if not isinstance(boundary, Mapping):
        return _output(TEST_BLOCKED, HOLD, "BOUNDARY_NOT_MAPPING", case_id="legacy", gaps=["BOUNDARY_TYPE"])
    case_id = boundary.get("case_id", "legacy")
    case_id = case_id if _text(case_id) else "legacy"
    if boundary.get("labeled_as_jcs") is True:
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "LEGACY_LABELLED_AS_JCS", case_id=case_id, gaps=["CANONICALIZATION_LABEL"])
    if boundary.get("legacy_id") != LEGACY_CANONICALIZATION:
        return _output(HOLD, HOLD, "LEGACY_ID_UNKNOWN", case_id=case_id, gaps=["LEGACY_ID"])
    if boundary.get("legacy_status") != "REGRESSION_ONLY":
        return _output(TEST_BLOCKED, HOLD, "LEGACY_REGRESSION_NOT_DECLARED", case_id=case_id, gaps=["LEGACY_STATUS"])
    if boundary.get("jcs_status") == "UNKNOWN":
        return _output(HOLD, HOLD, "JCS_STATUS_UNKNOWN", case_id=case_id, gaps=["JCS_STATUS"])
    if boundary.get("jcs_status") != "NOT_IMPLEMENTED":
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "JCS_STATUS_OVERCLAIMED", case_id=case_id, gaps=["JCS_STATUS"])
    return _output(
        NOT_CLAIMED,
        LEGACY_REGRESSION_ONLY,
        "LEGACY_BYTES_NOT_JCS",
        case_id=case_id,
        gaps=["JCS_NOT_IMPLEMENTED"],
        canonicalization_status="LEGACY_ONLY",
    )


def evaluate_canonicalization_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Classify JCS policy metadata without implementing its serializer."""

    if not isinstance(policy, Mapping):
        return _output(TEST_BLOCKED, HOLD, "POLICY_NOT_MAPPING", case_id="policy", gaps=["POLICY_TYPE"])
    case_id = policy.get("case_id", "policy")
    case_id = case_id if _text(case_id) else "policy"
    required = (
        "canonicalization",
        "sort_order",
        "unicode_normalization",
        "duplicate_keys",
        "float_policy",
        "array_order",
        "utf8",
        "implementation_status",
    )
    missing = [field for field in required if field not in policy]
    if missing:
        return _output(TEST_BLOCKED, HOLD, "POLICY_INCOMPLETE", case_id=case_id, gaps=missing)
    expected = {
        "canonicalization": JCS_CANONICALIZATION,
        "sort_order": "UTF16_CODE_UNITS",
        "unicode_normalization": "PRESERVE_NO_NORMALIZATION",
        "duplicate_keys": "REJECT",
        "float_policy": "ECMASCRIPT_FINITE",
        "array_order": "PRESERVE",
        "utf8": "UTF8",
    }
    drift = [field for field, value in expected.items() if policy.get(field) != value]
    if drift:
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "JCS_POLICY_DRIFT", case_id=case_id, gaps=drift)
    if policy.get("implementation_status") == "INDEPENDENT_MATCH":
        return _output(RECOVERY_REQUIRED, MANUAL_REVIEW, "JCS_IMPLEMENTATION_OVERCLAIM", case_id=case_id, gaps=["JCS_NOT_IMPLEMENTED"])
    if policy.get("implementation_status") == "UNKNOWN":
        return _output(HOLD, HOLD, "JCS_IMPLEMENTATION_UNKNOWN", case_id=case_id, gaps=["IMPLEMENTATION_STATUS"])
    if policy.get("implementation_status") != "NOT_IMPLEMENTED":
        return _output(TEST_BLOCKED, HOLD, "JCS_IMPLEMENTATION_NOT_LOCKED", case_id=case_id, gaps=["IMPLEMENTATION_STATUS"])
    return _output(
        TEST_BLOCKED,
        HOLD,
        "JCS_NOT_IMPLEMENTED",
        case_id=case_id,
        gaps=["JCS_REFERENCE_IMPLEMENTATION"],
        canonicalization_status="NOT_IMPLEMENTED",
    )


__all__ = [
    "DESIGN_ONLY",
    "ED25519_ALGORITHM",
    "ED25519_ALGORITHM_ID",
    "HARNESS_SCHEMA",
    "HOLD",
    "JCS_CANONICALIZATION",
    "LEGACY_CANONICALIZATION",
    "LEGACY_REGRESSION_ONLY",
    "MANUAL_REVIEW",
    "NOT_CLAIMED",
    "RECOVERY_REQUIRED",
    "RFC8032_SOURCE",
    "S25K_DOMAIN_SEPARATOR_HEX",
    "S25K_FORMAT",
    "TEST_BLOCKED",
    "evaluate_canonicalization_policy",
    "evaluate_legacy_boundary",
    "evaluate_preimage_contract",
    "evaluate_rfc8032_vector",
]
