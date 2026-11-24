"""Pure S25M validator for a synthetic reproducibility manifest.

The manifest is an evidence contract, not an environment probe.  This module
does not install packages, import a crypto backend, inspect the host, read
files, verify signatures, or authorize production.  It only validates the
shape, hashes, canonical digest and explicitly supplied status claims of a
test-only manifest.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


HARNESS_SCHEMA = "s25m.reproducibility-manifest.v1"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
LOCKED_TEST_PASS = "LOCKED_TEST_PASS"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
DESIGN_ONLY = "DESIGN_ONLY"
HOLD = "HOLD"
MANUAL_REVIEW = "MANUAL_REVIEW"
NOT_CLAIMED = "NOT_CLAIMED"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
CANONICALIZATION = "s25m-canonical-json-v1"
_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\\\/])")
_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "profile",
        "source",
        "runtime",
        "lock",
        "artifacts",
        "provider",
        "fips",
        "sbom",
        "oracle",
        "digest_algorithm",
        "canonicalization",
        "seal_status",
        "manifest_digest",
    }
)
_SOURCE_KEYS = frozenset({"repository_id", "commit", "tree_sha256"})
_RUNTIME_KEYS = frozenset(
    {
        "python_implementation",
        "python_version",
        "python_abi",
        "platform_tag",
        "os_id",
        "architecture",
        "libc_id",
        "runtime_image_sha256",
    }
)
_LOCK_KEYS = frozenset(
    {
        "lock_status",
        "lockfile_sha256",
        "lock_format",
        "resolver_name",
        "resolver_version",
        "hash_mode",
        "dependency_graph_sha256",
        "artifact_set_sha256",
    }
)
_ARTIFACT_KEYS = frozenset(
    {
        "name",
        "normalized_name",
        "version",
        "dependency_role",
        "artifact_type",
        "filename",
        "sha256",
        "source_reference",
        "platform_tag",
        "abi_tag",
        "parent_purls",
    }
)
_PROVIDER_KEYS = frozenset(
    {
        "algorithm",
        "package_purl",
        "package_version",
        "package_artifact_sha256",
        "effective_provider",
        "provider_version",
        "provider_build_id",
        "native_artifact_sha256",
        "provider_config_sha256",
        "signature_encoding",
        "canonicalization_profile",
    }
)
_FIPS_KEYS = frozenset(
    {
        "required",
        "status",
        "module_id",
        "module_version",
        "module_sha256",
        "self_test_id",
        "self_test_result",
        "validation_reference",
    }
)
_SBOM_KEYS = frozenset(
    {
        "format",
        "version",
        "document_sha256",
        "closure_sha256",
        "generator_name",
        "generator_version",
        "component_count",
        "includes_transitive",
        "includes_native",
        "unresolved_component_count",
    }
)
_ORACLE_KEYS = frozenset(
    {
        "oracle_id",
        "oracle_type",
        "oracle_artifact_sha256",
        "implementation_id",
        "implementation_version",
        "provider_id",
        "vector_set_sha256",
        "input_digest",
        "output_digest",
        "independence",
        "result",
    }
)
_FORBIDDEN_RUNTIME_KEYS = frozenset(
    {
        "evaluated_at",
        "hostname",
        "host_path",
        "absolute_path",
        "secret",
        "private_key",
        "seed",
    }
)


def _base(
    status: str,
    decision: str,
    reason: str,
    *,
    gaps: list[str],
    manifest_id: str = "unknown",
    digest_status: str = NOT_CLAIMED,
    dependency_status: str = NOT_CLAIMED,
    provider_status: str = NOT_CLAIMED,
    sbom_status: str = NOT_CLAIMED,
    oracle_status: str = NOT_CLAIMED,
    fips_status: str = NOT_CLAIMED,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": "OBSERVE_ONLY",
        "manifest_id": manifest_id,
        "status": status,
        "decision": decision,
        "reason": reason,
        "audit_gaps": list(gaps),
        "digest_status": digest_status,
        "dependency_status": dependency_status,
        "provider_status": provider_status,
        "sbom_status": sbom_status,
        "oracle_status": oracle_status,
        "fips_status": fips_status,
        "environment_probe": NOT_CLAIMED,
        "production_status": PRODUCTION_NOT_AUTHORIZED,
        "authority_claim": NOT_CLAIMED,
        "capability_issued": False,
        "write_authorized": False,
        "persistence_performed": False,
        "cas_attempted": False,
        "fence_issued": False,
        "mutation_allowed": False,
        "resume_allowed": False,
        "cross_store_atomicity": NOT_CLAIMED,
        "exactly_once_claim": NOT_CLAIMED,
    }


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value


def _hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH64.fullmatch(value) is not None


def _exact(mapping: Mapping[str, Any], expected: frozenset[str]) -> bool:
    return set(mapping) == set(expected)


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _parse_manifest(value: Mapping[str, Any] | bytes | str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, (bytes, str)):
        text = value.decode("utf-8") if isinstance(value, bytes) else value
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
        if isinstance(parsed, Mapping):
            return parsed
    raise TypeError("manifest must be a mapping or JSON object")


def _safe_value(value: Any) -> bool:
    if value is None or isinstance(value, (bool, int, str)):
        return not (isinstance(value, str) and _ABSOLUTE_PATH.match(value) is not None)
    if isinstance(value, float):
        return False
    if isinstance(value, list):
        return all(_safe_value(item) for item in value)
    if isinstance(value, Mapping):
        return all(
            isinstance(key, str)
            and key not in _FORBIDDEN_RUNTIME_KEYS
            and _safe_value(item)
            for key, item in value.items()
        )
    return False


def _canonical_json(value: Any) -> bytes:
    if not _safe_value(value):
        raise ValueError("manifest contains unsupported or host-bound value")
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Return the S25M digest over the manifest without ``manifest_digest``."""

    if not isinstance(manifest, Mapping):
        raise TypeError("manifest must be a mapping")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def _blocked(reason: str, gaps: list[str], manifest_id: str, **status: str) -> dict[str, Any]:
    return _base(TEST_BLOCKED, HOLD, reason, gaps=gaps, manifest_id=manifest_id, **status)


def evaluate_reproducibility_manifest(manifest: Mapping[str, Any] | bytes | str) -> dict[str, Any]:
    """Validate a supplied S25M manifest without probing or changing reality."""

    try:
        manifest = _parse_manifest(manifest)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _blocked("MANIFEST_JSON_INVALID", ["MANIFEST_JSON"], "unknown")
    except TypeError:
        return _blocked("MANIFEST_NOT_MAPPING", ["MANIFEST_TYPE"], "unknown")
    manifest_id = manifest.get("source", {}).get("repository_id", "unknown") if isinstance(manifest.get("source"), Mapping) else "unknown"
    if not _text(manifest_id):
        manifest_id = "unknown"
    if not _exact(manifest, _TOP_LEVEL):
        unknown = sorted(set(manifest) - set(_TOP_LEVEL))
        missing = sorted(set(_TOP_LEVEL) - set(manifest))
        return _blocked(
            "MANIFEST_SCHEMA_NOT_EXACT",
            [*(f"UNKNOWN_{key.upper()}" for key in unknown), *(f"MISSING_{key.upper()}" for key in missing)],
            manifest_id,
        )
    if not _safe_value(manifest):
        return _blocked("MANIFEST_VALUE_NOT_SAFE", ["HOST_PATH_OR_UNSUPPORTED_VALUE"], manifest_id)
    if manifest.get("schema_version") != HARNESS_SCHEMA:
        return _blocked("MANIFEST_SCHEMA_VERSION_UNKNOWN", ["SCHEMA_VERSION"], manifest_id)
    if manifest.get("profile") not in {"TEST", "PREPROD"}:
        return _blocked("MANIFEST_PROFILE_UNKNOWN", ["PROFILE"], manifest_id)
    if manifest.get("digest_algorithm") != "SHA-256" or manifest.get("canonicalization") != CANONICALIZATION:
        return _blocked("MANIFEST_DIGEST_PROFILE_INVALID", ["DIGEST_PROFILE"], manifest_id)
    if manifest.get("seal_status") not in {"UNSEALED", "SEALED_TEST_ONLY"}:
        return _blocked("MANIFEST_SEAL_STATUS_UNKNOWN", ["SEAL_STATUS"], manifest_id)

    sections = {
        "source": _SOURCE_KEYS,
        "runtime": _RUNTIME_KEYS,
        "lock": _LOCK_KEYS,
        "provider": _PROVIDER_KEYS,
        "fips": _FIPS_KEYS,
        "sbom": _SBOM_KEYS,
        "oracle": _ORACLE_KEYS,
    }
    for name, keys in sections.items():
        section = manifest.get(name)
        if not isinstance(section, Mapping) or not _exact(section, keys):
            return _blocked("MANIFEST_SECTION_NOT_EXACT", [f"SECTION_{name.upper()}"], manifest_id)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return _blocked("ARTIFACT_SET_MISSING", ["ARTIFACTS"], manifest_id)
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, Mapping) or not _exact(artifact, _ARTIFACT_KEYS):
            return _blocked("ARTIFACT_SCHEMA_NOT_EXACT", [f"ARTIFACT_{index}"], manifest_id)

    source = manifest["source"]
    runtime = manifest["runtime"]
    lock = manifest["lock"]
    provider = manifest["provider"]
    fips = manifest["fips"]
    sbom = manifest["sbom"]
    oracle = manifest["oracle"]

    required_texts = (
        (source, ("repository_id", "commit", "tree_sha256")),
        (runtime, ("python_implementation", "python_version", "python_abi", "platform_tag", "os_id", "architecture", "libc_id")),
        (lock, ("lockfile_sha256", "lock_format", "resolver_name", "resolver_version", "dependency_graph_sha256", "artifact_set_sha256")),
        (provider, ("algorithm", "package_purl", "package_version", "package_artifact_sha256", "effective_provider", "provider_version", "provider_build_id", "native_artifact_sha256", "provider_config_sha256", "signature_encoding", "canonicalization_profile")),
        (oracle, ("oracle_id", "oracle_type", "oracle_artifact_sha256", "implementation_id", "implementation_version", "provider_id", "vector_set_sha256", "input_digest", "output_digest", "independence", "result")),
    )
    for section, keys in required_texts:
        if any(not _text(section.get(key)) for key in keys):
            return _blocked("MANIFEST_TEXT_FIELD_INVALID", ["TEXT_FIELD"], manifest_id)
    if not all(_hash(source.get(key)) for key in ("tree_sha256",)):
        return _blocked("SOURCE_DIGEST_INVALID", ["SOURCE_TREE_SHA256"], manifest_id)
    if not all(_hash(lock.get(key)) for key in ("lockfile_sha256", "dependency_graph_sha256", "artifact_set_sha256")):
        return _blocked("LOCK_DIGEST_INVALID", ["LOCK_DIGEST"], manifest_id, dependency_status="TEST_BLOCKED")
    if not all(_hash(provider.get(key)) for key in ("package_artifact_sha256", "native_artifact_sha256", "provider_config_sha256")):
        return _blocked("PROVIDER_DIGEST_INVALID", ["PROVIDER_DIGEST"], manifest_id, provider_status="TEST_BLOCKED")
    if not all(_hash(oracle.get(key)) for key in ("oracle_artifact_sha256", "vector_set_sha256", "input_digest", "output_digest")):
        return _blocked("ORACLE_DIGEST_INVALID", ["ORACLE_DIGEST"], manifest_id, oracle_status="TEST_BLOCKED")

    for index, artifact in enumerate(artifacts):
        if not all(_text(artifact.get(key)) for key in ("name", "normalized_name", "version", "filename", "source_reference", "platform_tag", "abi_tag")):
            return _blocked("ARTIFACT_TEXT_INVALID", [f"ARTIFACT_{index}_TEXT"], manifest_id, dependency_status="TEST_BLOCKED")
        if not _hash(artifact.get("sha256")):
            return _blocked("ARTIFACT_HASH_INVALID", [f"ARTIFACT_{index}_HASH"], manifest_id, dependency_status="TEST_BLOCKED")
        if artifact.get("dependency_role") not in {"DIRECT", "TRANSITIVE", "BUILD"} or artifact.get("artifact_type") not in {"WHEEL", "SDIST", "NATIVE"}:
            return _blocked("ARTIFACT_ROLE_INVALID", [f"ARTIFACT_{index}_ROLE"], manifest_id, dependency_status="TEST_BLOCKED")
        if not isinstance(artifact.get("parent_purls"), list) or any(not _text(item) for item in artifact["parent_purls"]):
            return _blocked("ARTIFACT_PARENTS_INVALID", [f"ARTIFACT_{index}_PARENTS"], manifest_id, dependency_status="TEST_BLOCKED")
    roles = {artifact.get("dependency_role") for artifact in artifacts}
    types = {artifact.get("artifact_type") for artifact in artifacts}
    if not {"DIRECT", "TRANSITIVE"}.issubset(roles) or "NATIVE" not in types:
        return _blocked("ARTIFACT_CLOSURE_INCOMPLETE", ["DIRECT_TRANSITIVE_NATIVE"], manifest_id, dependency_status="TEST_BLOCKED")

    if not isinstance(fips.get("required"), bool) or fips.get("status") not in {"VERIFIED", "NOT_REQUIRED", "UNKNOWN", "FAILED"}:
        return _blocked("FIPS_STATUS_INVALID", ["FIPS"], manifest_id, fips_status="TEST_BLOCKED")
    if not all(_text(fips.get(key)) for key in ("module_id", "module_version", "self_test_id", "self_test_result", "validation_reference")) or not _hash(fips.get("module_sha256")):
        return _blocked("FIPS_EVIDENCE_INCOMPLETE", ["FIPS_EVIDENCE"], manifest_id, fips_status="TEST_BLOCKED")
    if not isinstance(sbom.get("component_count"), int) or sbom.get("component_count") < 1 or not isinstance(sbom.get("unresolved_component_count"), int) or sbom.get("unresolved_component_count") < 0:
        return _blocked("SBOM_COUNT_INVALID", ["SBOM_COUNTS"], manifest_id, sbom_status="TEST_BLOCKED")
    if not all(_text(sbom.get(key)) for key in ("format", "version", "generator_name", "generator_version")) or not all(_hash(sbom.get(key)) for key in ("document_sha256", "closure_sha256")):
        return _blocked("SBOM_EVIDENCE_INCOMPLETE", ["SBOM_EVIDENCE"], manifest_id, sbom_status="TEST_BLOCKED")
    if sbom.get("format") not in {"SPDX", "CycloneDX"} or not isinstance(sbom.get("includes_transitive"), bool) or not isinstance(sbom.get("includes_native"), bool):
        return _blocked("SBOM_SCHEMA_INVALID", ["SBOM_SCHEMA"], manifest_id, sbom_status="TEST_BLOCKED")
    if oracle.get("oracle_type") not in {"KAT", "CROSS_PROVIDER"} or oracle.get("independence") not in {"INDEPENDENT", "SELF_CHECK_ONLY", "UNKNOWN"} or oracle.get("result") not in {"PASS", "FAIL", "UNKNOWN"}:
        return _blocked("ORACLE_STATUS_INVALID", ["ORACLE_STATUS"], manifest_id, oracle_status="TEST_BLOCKED")

    try:
        computed_digest = manifest_digest(manifest)
    except (TypeError, ValueError):
        return _blocked("MANIFEST_CANONICALIZATION_INVALID", ["CANONICAL_MANIFEST"], manifest_id, digest_status="TEST_BLOCKED")
    if not _hash(manifest.get("manifest_digest")) or manifest.get("manifest_digest") != computed_digest:
        return _blocked("MANIFEST_DIGEST_MISMATCH", ["MANIFEST_DIGEST"], manifest_id, digest_status="TEST_BLOCKED")

    if manifest.get("seal_status") == "UNSEALED":
        return _base(
            PROPOSAL_ONLY,
            DESIGN_ONLY,
            "REPRODUCIBILITY_MANIFEST_PROPOSAL_ONLY",
            gaps=["EXTERNAL_LOCK_AND_ENVIRONMENT_NOT_ATTESTED"],
            manifest_id=manifest_id,
            digest_status="MATCH",
            dependency_status="PROPOSED",
            provider_status="PROPOSED",
            sbom_status="PROPOSED",
            oracle_status="PROPOSED",
            fips_status="PROPOSED",
        )

    if lock.get("lock_status") != "LOCKED" or lock.get("hash_mode") != "REQUIRED":
        return _blocked("LOCK_NOT_SEALED", ["LOCK_STATUS"], manifest_id, digest_status="MATCH", dependency_status="TEST_BLOCKED")
    if provider.get("algorithm") != "Ed25519" or provider.get("canonicalization_profile") != "RFC8785-JCS-v1":
        return _blocked("PROVIDER_PROFILE_MISMATCH", ["PROVIDER_PROFILE"], manifest_id, digest_status="MATCH", provider_status="TEST_BLOCKED")
    if fips.get("required") and fips.get("status") != "VERIFIED":
        return _blocked("FIPS_REQUIRED_NOT_VERIFIED", ["FIPS_STATUS"], manifest_id, digest_status="MATCH", fips_status="TEST_BLOCKED")
    if not fips.get("required") and fips.get("status") != "NOT_REQUIRED":
        return _blocked("FIPS_OPTIONAL_STATUS_UNKNOWN", ["FIPS_STATUS"], manifest_id, digest_status="MATCH", fips_status="TEST_BLOCKED")
    if not sbom.get("includes_transitive") or not sbom.get("includes_native") or sbom.get("unresolved_component_count") != 0:
        return _blocked("SBOM_CLOSURE_INCOMPLETE", ["SBOM_CLOSURE"], manifest_id, digest_status="MATCH", sbom_status="TEST_BLOCKED")
    if oracle.get("independence") != "INDEPENDENT" or oracle.get("result") != "PASS":
        return _blocked("INDEPENDENT_ORACLE_NOT_PASSED", ["ORACLE_INDEPENDENCE"], manifest_id, digest_status="MATCH", oracle_status="TEST_BLOCKED")
    return _base(
        LOCKED_TEST_PASS,
        "TEST_ONLY_PASS",
        "REPRODUCIBILITY_CONTRACT_PASS_NO_PRODUCTION_AUTHORITY",
        gaps=["ENVIRONMENT_NOT_PROBED", "PRODUCTION_NOT_AUTHORIZED"],
        manifest_id=manifest_id,
        digest_status="MATCH",
        dependency_status="LOCKED",
        provider_status="IDENTIFIED",
        sbom_status="COMPLETE",
        oracle_status="INDEPENDENT_PASS",
        fips_status="VERIFIED" if fips.get("required") else "NOT_REQUIRED",
    )


__all__ = [
    "CANONICALIZATION",
    "DESIGN_ONLY",
    "HARNESS_SCHEMA",
    "HOLD",
    "LOCKED_TEST_PASS",
    "MANUAL_REVIEW",
    "NOT_CLAIMED",
    "PRODUCTION_NOT_AUTHORIZED",
    "PROPOSAL_ONLY",
    "RECOVERY_REQUIRED",
    "TEST_BLOCKED",
    "evaluate_reproducibility_manifest",
    "manifest_digest",
]
