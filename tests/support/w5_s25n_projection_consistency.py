"""Pure S25N consistency checks for synthetic evidence projections.

The validator compares separately supplied lockfile, dependency-graph,
artifact, runtime, provider/FIPS, SBOM and oracle projections.  It never
resolves, imports, probes, writes or repairs anything.  A coherent fixture is
only a test result; it is never production authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


HARNESS_SCHEMA = "s25n.projection-consistency.v1"
CANONICALIZATION = "s25m-canonical-json-v1"
PROPOSAL_ONLY = "PROPOSAL_ONLY"
TEST_BLOCKED = "TEST_BLOCKED"
LOCKED_TEST_PASS = "LOCKED_TEST_PASS"
RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
PRODUCTION_NOT_AUTHORIZED = "PRODUCTION_NOT_AUTHORIZED"
DESIGN_ONLY = "DESIGN_ONLY"
HOLD = "HOLD"
MANUAL_REVIEW = "MANUAL_REVIEW"
NOT_CLAIMED = "NOT_CLAIMED"

_HASH64 = re.compile(r"^[0-9a-f]{64}\Z")
_ABSOLUTE_PATH = re.compile(r"^(?:/|~/|[A-Za-z]:[\\\\/])")
_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "profile",
        "observation_mode",
        "seal_status",
        "subject",
        "anchors",
        "runtime",
        "lockfile",
        "dependency_graph",
        "artifacts",
        "provider",
        "fips",
        "sbom",
        "oracle",
        "projection_digests",
        "canonicalization",
        "projection_set_digest",
    }
)
_SUBJECT_KEYS = frozenset({"s25m_manifest_digest", "source_tree_sha256"})
_ANCHOR_KEYS = frozenset(
    {
        "lockfile_sha256",
        "dependency_graph_sha256",
        "artifact_set_sha256",
        "provider_config_sha256",
        "fips_module_sha256",
        "sbom_document_sha256",
        "sbom_closure_sha256",
        "oracle_artifact_sha256",
        "oracle_vector_set_sha256",
    }
)
_RUNTIME_KEYS = frozenset({"python_abi", "platform_tag", "architecture", "os_id"})
_LOCKFILE_KEYS = frozenset(
    {
        "status",
        "hash_mode",
        "lockfile_sha256",
        "resolver_name",
        "resolver_version",
        "dependency_graph_sha256",
        "artifact_set_sha256",
        "component_ids",
    }
)
_GRAPH_KEYS = frozenset(
    {
        "graph_sha256",
        "resolver_name",
        "resolver_version",
        "runtime_python_abi",
        "platform_tag",
        "nodes",
        "edges",
    }
)
_GRAPH_NODE_KEYS = frozenset(
    {"component_id", "purl", "version", "role", "artifact_sha256"}
)
_GRAPH_EDGE_KEYS = frozenset(
    {"parent_component_id", "child_component_id", "child_digest"}
)
_ARTIFACTS_KEYS = frozenset({"artifact_set_sha256", "items"})
_ARTIFACT_KEYS = frozenset(
    {
        "component_id",
        "purl",
        "name",
        "normalized_name",
        "version",
        "role",
        "artifact_type",
        "filename",
        "sha256",
        "platform_tag",
        "abi_tag",
        "parent_component_ids",
    }
)
_PROVIDER_KEYS = frozenset(
    {
        "package_component_id",
        "package_artifact_sha256",
        "provider_id",
        "provider_version",
        "native_component_id",
        "native_artifact_sha256",
        "provider_config_sha256",
        "algorithm",
        "canonicalization_profile",
    }
)
_FIPS_KEYS = frozenset(
    {
        "required",
        "status",
        "provider_id",
        "module_component_id",
        "module_sha256",
        "config_sha256",
        "self_test_result",
        "validation_reference",
    }
)
_SBOM_KEYS = frozenset(
    {
        "document_sha256",
        "closure_sha256",
        "dependency_graph_sha256",
        "artifact_set_sha256",
        "component_count",
        "component_ids",
        "native_component_ids",
        "includes_transitive",
        "includes_native",
        "unresolved_count",
    }
)
_ORACLE_KEYS = frozenset(
    {
        "oracle_id",
        "result",
        "independence",
        "input_digest",
        "output_digest",
        "artifact_set_sha256",
        "provider_id",
        "provider_version",
        "native_artifact_sha256",
        "subject_manifest_digest",
        "target_provider_id",
        "target_provider_version",
        "target_native_artifact_sha256",
        "vector_set_sha256",
    }
)
_PROJECTION_NAMES = (
    "runtime",
    "lockfile",
    "dependency_graph",
    "artifacts",
    "provider",
    "fips",
    "sbom",
    "oracle",
)
_FORBIDDEN_KEYS = frozenset(
    {
        "absolute_path",
        "captured_at",
        "cwd",
        "evaluated_at",
        "environment",
        "hostname",
        "host_path",
        "private_key",
        "repo_root",
        "secret",
        "seed",
        "timestamp",
    }
)


def _base(
    status: str,
    decision: str,
    reason: str,
    gaps: list[str],
    *,
    digest_status: str = NOT_CLAIMED,
    dependency_status: str = NOT_CLAIMED,
    provider_status: str = NOT_CLAIMED,
    sbom_status: str = NOT_CLAIMED,
    oracle_status: str = NOT_CLAIMED,
    fips_status: str = NOT_CLAIMED,
    projection_status: str = NOT_CLAIMED,
) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_SCHEMA,
        "observation_mode": "OBSERVE_ONLY",
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
        "projection_status": projection_status,
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


def _blocked(reason: str, gaps: list[str], **status: str) -> dict[str, Any]:
    return _base(TEST_BLOCKED, HOLD, reason, gaps, **status)


def _recovery(reason: str, gaps: list[str], **status: str) -> dict[str, Any]:
    return _base(RECOVERY_REQUIRED, MANUAL_REVIEW, reason, gaps, **status)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value


def _hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH64.fullmatch(value) is not None


def _exact(mapping: Mapping[str, Any], expected: frozenset[str]) -> bool:
    return set(mapping) == set(expected)


def _unique_text_list(value: Any) -> bool:
    return isinstance(value, list) and all(_text(item) for item in value) and len(value) == len(set(value))


def _safe_value(value: Any) -> bool:
    if value is None or isinstance(value, (bool, int, str)):
        if not isinstance(value, str):
            return True
        normalized = value.lstrip().lower()
        if (
            _ABSOLUTE_PATH.match(value.lstrip()) is not None
            or normalized.startswith("file:")
            or value.lstrip().startswith("\\\\")
        ):
            return False
        return not any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    if isinstance(value, float):
        return False
    if isinstance(value, list):
        return all(_safe_value(item) for item in value)
    if isinstance(value, Mapping):
        return all(
            isinstance(key, str)
            and key not in _FORBIDDEN_KEYS
            and _safe_value(item)
            for key, item in value.items()
        )
    return False


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


def _parse_projection(value: Mapping[str, Any] | bytes | str) -> Mapping[str, Any]:
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
    raise TypeError("projection set must be a mapping or JSON object")


def _canonical_json(value: Any) -> bytes:
    if not _safe_value(value):
        raise ValueError("projection set contains unsupported or host-bound value")
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def projection_set_digest(projections: Mapping[str, Any]) -> str:
    """Return the digest over all projections without the self field."""

    if not isinstance(projections, Mapping):
        raise TypeError("projection set must be a mapping")
    unsigned = {
        key: value for key, value in projections.items() if key != "projection_set_digest"
    }
    return hashlib.sha256(_canonical_json(unsigned)).hexdigest()


def projection_digest(projection: Mapping[str, Any]) -> str:
    """Return the canonical digest for one supplied projection payload."""

    if not isinstance(projection, Mapping):
        raise TypeError("projection must be a mapping")
    return hashlib.sha256(_canonical_json(projection)).hexdigest()


def _section_text(section: Mapping[str, Any], keys: tuple[str, ...]) -> bool:
    return all(_text(section.get(key)) for key in keys)


def _artifact_name_is_bound(artifact: Mapping[str, Any]) -> bool:
    expected = re.sub(r"[-_.]+", "-", artifact["name"]).lower()
    return artifact["normalized_name"] == expected and artifact["version"] in artifact["filename"]


def evaluate_projection_consistency(
    projections: Mapping[str, Any] | bytes | str,
    *,
    expected_subject: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare supplied projections without resolving or mutating reality."""

    try:
        projections = _parse_projection(projections)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _blocked("PROJECTION_JSON_INVALID", ["PROJECTION_JSON"])
    except TypeError:
        return _blocked("PROJECTION_NOT_MAPPING", ["PROJECTION_TYPE"])

    if not _exact(projections, _TOP_LEVEL):
        unknown = sorted(set(projections) - set(_TOP_LEVEL))
        missing = sorted(set(_TOP_LEVEL) - set(projections))
        return _blocked(
            "PROJECTION_SCHEMA_NOT_EXACT",
            [*(f"UNKNOWN_{key.upper()}" for key in unknown), *(f"MISSING_{key.upper()}" for key in missing)],
        )
    if not _safe_value(projections):
        return _blocked("PROJECTION_VALUE_NOT_SAFE", ["HOST_PATH_OR_UNSUPPORTED_VALUE"])
    if projections.get("schema_version") != HARNESS_SCHEMA:
        return _blocked("PROJECTION_SCHEMA_VERSION_UNKNOWN", ["SCHEMA_VERSION"])
    if not _text(projections.get("profile")) or projections.get("profile") not in {"TEST", "PREPROD"}:
        return _blocked("PROJECTION_PROFILE_UNKNOWN", ["PROFILE"])
    if not _text(projections.get("observation_mode")) or projections.get("observation_mode") != "OBSERVE_ONLY":
        return _blocked("OBSERVATION_MODE_NOT_READ_ONLY", ["OBSERVATION_MODE"])
    if not _text(projections.get("seal_status")) or projections.get("seal_status") not in {"UNSEALED", "SEALED_TEST_ONLY"}:
        return _blocked("PROJECTION_SEAL_STATUS_UNKNOWN", ["SEAL_STATUS"])
    if not _text(projections.get("canonicalization")) or projections.get("canonicalization") != CANONICALIZATION:
        return _blocked("PROJECTION_CANONICALIZATION_INVALID", ["CANONICALIZATION"])

    subject = projections.get("subject")
    anchors = projections.get("anchors")
    if not isinstance(subject, Mapping) or not _exact(subject, _SUBJECT_KEYS):
        return _blocked("SUBJECT_SCHEMA_NOT_EXACT", ["SUBJECT"])
    if not isinstance(anchors, Mapping) or not _exact(anchors, _ANCHOR_KEYS):
        return _blocked("ANCHOR_SCHEMA_NOT_EXACT", ["ANCHORS"])
    if not _hash(subject["s25m_manifest_digest"]) or not _hash(subject["source_tree_sha256"]):
        return _blocked("SUBJECT_ANCHOR_INVALID", ["SUBJECT_HASHES"])
    if not all(_hash(anchors.get(key)) for key in _ANCHOR_KEYS):
        return _blocked("ANCHOR_DIGEST_INVALID", ["ANCHOR_HASHES"])
    if expected_subject is not None:
        if (
            not isinstance(expected_subject, Mapping)
            or not _exact(expected_subject, _SUBJECT_KEYS)
            or not _safe_value(expected_subject)
            or not all(_hash(expected_subject.get(key)) for key in _SUBJECT_KEYS)
        ):
            return _blocked("EXPECTED_SUBJECT_INVALID", ["EXPECTED_SUBJECT"])

    sections = {
        "runtime": _RUNTIME_KEYS,
        "lockfile": _LOCKFILE_KEYS,
        "dependency_graph": _GRAPH_KEYS,
        "artifacts": _ARTIFACTS_KEYS,
        "provider": _PROVIDER_KEYS,
        "fips": _FIPS_KEYS,
        "sbom": _SBOM_KEYS,
        "oracle": _ORACLE_KEYS,
    }
    for name, keys in sections.items():
        section = projections.get(name)
        if not isinstance(section, Mapping) or not _exact(section, keys):
            return _blocked("PROJECTION_SECTION_NOT_EXACT", [f"SECTION_{name.upper()}"])
    projection_digests = projections.get("projection_digests")
    if not isinstance(projection_digests, Mapping) or set(projection_digests) != set(_PROJECTION_NAMES):
        return _blocked("PROJECTION_DIGEST_SCHEMA_INVALID", ["PROJECTION_DIGESTS"], digest_status="TEST_BLOCKED")
    if not all(_hash(projection_digests.get(name)) for name in _PROJECTION_NAMES):
        return _blocked("PROJECTION_DIGEST_INVALID", ["PROJECTION_DIGESTS"], digest_status="TEST_BLOCKED")
    runtime = projections["runtime"]
    lockfile = projections["lockfile"]
    graph = projections["dependency_graph"]
    artifacts = projections["artifacts"]
    provider = projections["provider"]
    fips = projections["fips"]
    sbom = projections["sbom"]
    oracle = projections["oracle"]

    if not _section_text(runtime, ("python_abi", "platform_tag", "architecture", "os_id")):
        return _blocked("RUNTIME_PROFILE_INCOMPLETE", ["RUNTIME_PROFILE"])
    if not _section_text(lockfile, ("resolver_name", "resolver_version")):
        return _blocked("LOCKFILE_RESOLVER_INCOMPLETE", ["RESOLVER"])
    if lockfile["resolver_name"].upper() == "UNKNOWN" or lockfile["resolver_version"].upper() == "UNKNOWN":
        return _blocked("RESOLVER_NOT_BOUND", ["RESOLVER"], dependency_status="HOLD")
    if not _text(lockfile["status"]) or lockfile["status"] not in {"LOCKED", "PROPOSED", "UNKNOWN"}:
        return _blocked("LOCKFILE_STATUS_INVALID", ["LOCK_STATUS"])
    if lockfile["status"] == "UNKNOWN":
        return _blocked("LOCKFILE_STATUS_UNKNOWN", ["LOCK_STATUS"], dependency_status="HOLD")
    if not _text(lockfile["hash_mode"]) or lockfile["hash_mode"] not in {"REQUIRED", "OPTIONAL", "UNKNOWN"}:
        return _blocked("LOCKFILE_HASH_MODE_INVALID", ["HASH_MODE"])
    if lockfile["hash_mode"] != "REQUIRED":
        return _blocked("LOCKFILE_HASH_MODE_NOT_REQUIRED", ["HASH_MODE"], dependency_status="TEST_BLOCKED")
    if not all(
        _hash(lockfile.get(key))
        for key in ("lockfile_sha256", "dependency_graph_sha256", "artifact_set_sha256")
    ):
        return _blocked("LOCKFILE_DIGEST_INVALID", ["LOCKFILE_DIGEST"], dependency_status="TEST_BLOCKED")
    if not _unique_text_list(lockfile["component_ids"]):
        return _blocked("LOCKFILE_COMPONENT_IDS_INVALID", ["LOCKFILE_COMPONENT_IDS"], dependency_status="TEST_BLOCKED")
    if not _hash(graph.get("graph_sha256")) or not _hash(artifacts.get("artifact_set_sha256")):
        return _blocked("PROJECTION_DIGEST_INVALID", ["GRAPH_OR_ARTIFACT_DIGEST"], dependency_status="TEST_BLOCKED")
    if not _hash(projections.get("projection_set_digest")):
        return _blocked("PROJECTION_SET_DIGEST_INVALID", ["PROJECTION_SET_DIGEST"], digest_status="TEST_BLOCKED")

    items = artifacts["items"]
    nodes = graph["nodes"]
    edges = graph["edges"]
    if not isinstance(items, list) or not items:
        return _blocked("ARTIFACT_PROJECTION_MISSING", ["ARTIFACT_ITEMS"], dependency_status="TEST_BLOCKED")
    if not isinstance(nodes, list) or not nodes:
        return _blocked("GRAPH_NODE_PROJECTION_MISSING", ["GRAPH_NODES"], dependency_status="TEST_BLOCKED")
    if not isinstance(edges, list):
        return _blocked("GRAPH_EDGE_PROJECTION_INVALID", ["GRAPH_EDGES"], dependency_status="TEST_BLOCKED")

    item_map: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, Mapping) or not _exact(item, _ARTIFACT_KEYS):
            return _blocked("ARTIFACT_SCHEMA_NOT_EXACT", [f"ARTIFACT_{index}"], dependency_status="TEST_BLOCKED")
        if not _section_text(
            item,
            (
                "component_id",
                "purl",
                "name",
                "normalized_name",
                "version",
                "filename",
                "platform_tag",
                "abi_tag",
                "role",
                "artifact_type",
            ),
        ) or not _hash(item["sha256"]):
            return _blocked("ARTIFACT_IDENTITY_INVALID", [f"ARTIFACT_{index}"], dependency_status="TEST_BLOCKED")
        if item["component_id"] in item_map:
            return _recovery("DUPLICATE_COMPONENT_ID", [f"ARTIFACT_{index}_COMPONENT_ID"], dependency_status="RECOVERY_REQUIRED")
        item_map[item["component_id"]] = item
        if not _artifact_name_is_bound(item):
            return _recovery("ARTIFACT_NAME_VERSION_DRIFT", [f"ARTIFACT_{index}_IDENTITY"], dependency_status="RECOVERY_REQUIRED")
        if item["role"] not in {"DIRECT", "TRANSITIVE", "BUILD"} or item["artifact_type"] not in {"WHEEL", "SDIST", "NATIVE"}:
            return _blocked("ARTIFACT_ROLE_INVALID", [f"ARTIFACT_{index}_ROLE"], dependency_status="TEST_BLOCKED")
        if not _unique_text_list(item["parent_component_ids"]):
            return _blocked("ARTIFACT_PARENTS_INVALID", [f"ARTIFACT_{index}_PARENTS"], dependency_status="TEST_BLOCKED")
        if item["artifact_type"] == "WHEEL" and (
            item["platform_tag"] != runtime["platform_tag"] or item["abi_tag"] != runtime["python_abi"]
        ):
            return _recovery("ARTIFACT_RUNTIME_TAG_DRIFT", [f"ARTIFACT_{index}_RUNTIME"], dependency_status="RECOVERY_REQUIRED")
        if item["artifact_type"] == "NATIVE" and item["platform_tag"] != runtime["platform_tag"]:
            return _recovery("NATIVE_PLATFORM_DRIFT", [f"ARTIFACT_{index}_PLATFORM"], dependency_status="RECOVERY_REQUIRED")

    roles = {item["role"] for item in item_map.values()}
    types = {item["artifact_type"] for item in item_map.values()}
    if not {"DIRECT", "TRANSITIVE"}.issubset(roles) or "NATIVE" not in types:
        return _blocked("ARTIFACT_CLOSURE_INCOMPLETE", ["DIRECT_TRANSITIVE_NATIVE"], dependency_status="TEST_BLOCKED")
    if set(lockfile["component_ids"]) != set(item_map):
        return _recovery("LOCKFILE_COMPONENT_SET_DRIFT", ["LOCKFILE_COMPONENTS"], dependency_status="RECOVERY_REQUIRED")

    if graph["resolver_name"] != lockfile["resolver_name"] or graph["resolver_version"] != lockfile["resolver_version"]:
        return _recovery("RESOLVER_PROJECTION_DRIFT", ["RESOLVER"], dependency_status="RECOVERY_REQUIRED")
    if graph["runtime_python_abi"] != runtime["python_abi"] or graph["platform_tag"] != runtime["platform_tag"]:
        return _recovery("GRAPH_RUNTIME_PROJECTION_DRIFT", ["GRAPH_RUNTIME"], dependency_status="RECOVERY_REQUIRED")
    if graph["graph_sha256"] != lockfile["dependency_graph_sha256"]:
        return _recovery("DEPENDENCY_GRAPH_DIGEST_DRIFT", ["GRAPH_DIGEST"], dependency_status="RECOVERY_REQUIRED")
    if artifacts["artifact_set_sha256"] != lockfile["artifact_set_sha256"]:
        return _recovery("ARTIFACT_SET_DIGEST_DRIFT", ["ARTIFACT_SET_DIGEST"], dependency_status="RECOVERY_REQUIRED")

    node_map: dict[str, Mapping[str, Any]] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, Mapping) or not _exact(node, _GRAPH_NODE_KEYS):
            return _blocked("GRAPH_NODE_SCHEMA_NOT_EXACT", [f"GRAPH_NODE_{index}"], dependency_status="TEST_BLOCKED")
        if not _section_text(node, ("component_id", "purl", "version", "role")) or not _hash(node["artifact_sha256"]):
            return _blocked("GRAPH_NODE_IDENTITY_INVALID", [f"GRAPH_NODE_{index}"], dependency_status="TEST_BLOCKED")
        if node["component_id"] in node_map:
            return _recovery("DUPLICATE_GRAPH_NODE", [f"GRAPH_NODE_{index}"], dependency_status="RECOVERY_REQUIRED")
        node_map[node["component_id"]] = node
        item = item_map.get(node["component_id"])
        if item is None or any(
            node[key] != item["sha256"] if key == "artifact_sha256" else node[key] != item[key]
            for key in ("purl", "version", "role", "artifact_sha256")
        ):
            return _recovery("GRAPH_NODE_ARTIFACT_DRIFT", [f"GRAPH_NODE_{index}"], dependency_status="RECOVERY_REQUIRED")
    if set(node_map) != set(item_map):
        return _recovery("GRAPH_ARTIFACT_COMPONENT_SET_DRIFT", ["COMPONENT_SET"], dependency_status="RECOVERY_REQUIRED")

    expected_edges: set[tuple[str, str]] = set()
    for item in item_map.values():
        for parent in item["parent_component_ids"]:
            expected_edges.add((parent, item["component_id"]))
            if parent not in item_map:
                return _recovery("ARTIFACT_PARENT_MISSING", ["PARENT_COMPONENT"], dependency_status="RECOVERY_REQUIRED")
    seen_edges: set[tuple[str, str]] = set()
    for index, edge in enumerate(edges):
        if not isinstance(edge, Mapping) or not _exact(edge, _GRAPH_EDGE_KEYS):
            return _blocked("GRAPH_EDGE_SCHEMA_NOT_EXACT", [f"GRAPH_EDGE_{index}"], dependency_status="TEST_BLOCKED")
        if not _text(edge["parent_component_id"]) or not _text(edge["child_component_id"]) or not _hash(edge["child_digest"]):
            return _blocked("GRAPH_EDGE_INVALID", [f"GRAPH_EDGE_{index}"], dependency_status="TEST_BLOCKED")
        pair = (edge["parent_component_id"], edge["child_component_id"])
        if pair in seen_edges or pair[0] == pair[1]:
            return _recovery("DUPLICATE_OR_SELF_GRAPH_EDGE", [f"GRAPH_EDGE_{index}"], dependency_status="RECOVERY_REQUIRED")
        seen_edges.add(pair)
        child = item_map.get(edge["child_component_id"])
        if child is None or edge["child_digest"] != child["sha256"]:
            return _recovery("GRAPH_CHILD_DIGEST_DRIFT", [f"GRAPH_EDGE_{index}"], dependency_status="RECOVERY_REQUIRED")
    if seen_edges != expected_edges:
        return _recovery("GRAPH_EDGE_SET_DRIFT", ["GRAPH_EDGES"], dependency_status="RECOVERY_REQUIRED")

    if not _section_text(
        provider,
        (
            "package_component_id",
            "provider_id",
            "provider_version",
            "native_component_id",
            "algorithm",
            "canonicalization_profile",
        ),
    ) or not all(
        _hash(provider.get(key))
        for key in ("package_artifact_sha256", "native_artifact_sha256", "provider_config_sha256")
    ):
        return _blocked("PROVIDER_EVIDENCE_INCOMPLETE", ["PROVIDER"], provider_status="TEST_BLOCKED")
    package = item_map.get(provider["package_component_id"])
    native = item_map.get(provider["native_component_id"])
    if package is None or native is None or native["artifact_type"] != "NATIVE":
        return _recovery("PROVIDER_COMPONENT_BINDING_DRIFT", ["PROVIDER_COMPONENTS"], provider_status="RECOVERY_REQUIRED")
    if provider["package_artifact_sha256"] != package["sha256"] or provider["native_artifact_sha256"] != native["sha256"]:
        return _recovery("PROVIDER_ARTIFACT_BINDING_DRIFT", ["PROVIDER_ARTIFACTS"], provider_status="RECOVERY_REQUIRED")
    if provider["algorithm"] != "Ed25519" or provider["canonicalization_profile"] != "RFC8785-JCS-v1":
        return _recovery("PROVIDER_PROFILE_DRIFT", ["PROVIDER_PROFILE"], provider_status="RECOVERY_REQUIRED")

    if not isinstance(fips["required"], bool) or not _text(fips["status"]) or fips["status"] not in {"VERIFIED", "NOT_REQUIRED", "UNKNOWN", "FAILED"}:
        return _blocked("FIPS_STATUS_INVALID", ["FIPS_STATUS"], fips_status="TEST_BLOCKED")
    if not _section_text(fips, ("provider_id", "module_component_id", "self_test_result", "validation_reference")) or not all(
        _hash(fips.get(key)) for key in ("module_sha256", "config_sha256")
    ):
        return _blocked("FIPS_EVIDENCE_INCOMPLETE", ["FIPS_EVIDENCE"], fips_status="TEST_BLOCKED")
    if fips["provider_id"] != provider["provider_id"] or fips["config_sha256"] != provider["provider_config_sha256"]:
        return _recovery("FIPS_PROVIDER_BINDING_DRIFT", ["FIPS_PROVIDER"], fips_status="RECOVERY_REQUIRED")
    if fips["required"]:
        module = item_map.get(fips["module_component_id"])
        if module is None or module["artifact_type"] != "NATIVE" or fips["module_sha256"] != module["sha256"]:
            return _recovery("FIPS_MODULE_BINDING_DRIFT", ["FIPS_MODULE"], fips_status="RECOVERY_REQUIRED")
        if fips["status"] == "UNKNOWN" or fips["self_test_result"] == "UNKNOWN":
            return _blocked("FIPS_EVIDENCE_UNKNOWN", ["FIPS_STATUS"], fips_status="HOLD")
        if fips["status"] == "FAILED" or fips["self_test_result"] == "FAIL":
            return _recovery("FIPS_NEGATIVE_RESULT", ["FIPS_STATUS"], fips_status="RECOVERY_REQUIRED")
        if fips["status"] != "VERIFIED" or fips["self_test_result"] != "PASS":
            return _blocked("FIPS_REQUIRED_NOT_VERIFIED", ["FIPS_STATUS"], fips_status="TEST_BLOCKED")
    elif fips["status"] != "NOT_REQUIRED" or fips["self_test_result"] != "NOT_REQUIRED":
        return _blocked("FIPS_OPTIONAL_STATUS_UNKNOWN", ["FIPS_STATUS"], fips_status="TEST_BLOCKED")

    if not all(_hash(sbom.get(key)) for key in ("document_sha256", "closure_sha256", "dependency_graph_sha256", "artifact_set_sha256")):
        return _blocked("SBOM_EVIDENCE_INCOMPLETE", ["SBOM_DIGESTS"], sbom_status="TEST_BLOCKED")
    if not isinstance(sbom["component_count"], int) or isinstance(sbom["component_count"], bool) or sbom["component_count"] < 1 or not isinstance(sbom["unresolved_count"], int) or isinstance(sbom["unresolved_count"], bool) or sbom["unresolved_count"] < 0:
        return _blocked("SBOM_COUNTS_INVALID", ["SBOM_COUNTS"], sbom_status="TEST_BLOCKED")
    if not _unique_text_list(sbom["component_ids"]) or not _unique_text_list(sbom["native_component_ids"]):
        return _blocked("SBOM_COMPONENT_IDS_INVALID", ["SBOM_COMPONENT_IDS"], sbom_status="TEST_BLOCKED")
    if sbom["component_count"] != len(sbom["component_ids"]):
        return _recovery("SBOM_COMPONENT_COUNT_DRIFT", ["SBOM_COUNT"], sbom_status="RECOVERY_REQUIRED")
    if set(sbom["component_ids"]) != set(item_map) or set(sbom["native_component_ids"]) != {
        item["component_id"] for item in item_map.values() if item["artifact_type"] == "NATIVE"
    }:
        return _recovery("SBOM_COMPONENT_SET_DRIFT", ["SBOM_CLOSURE"], sbom_status="RECOVERY_REQUIRED")
    if sbom["dependency_graph_sha256"] != graph["graph_sha256"] or sbom["artifact_set_sha256"] != artifacts["artifact_set_sha256"]:
        return _recovery("SBOM_DIGEST_BINDING_DRIFT", ["SBOM_DIGESTS"], sbom_status="RECOVERY_REQUIRED")
    if not isinstance(sbom["includes_transitive"], bool) or not isinstance(sbom["includes_native"], bool):
        return _blocked("SBOM_CLOSURE_FLAGS_INVALID", ["SBOM_CLOSURE_FLAGS"], sbom_status="TEST_BLOCKED")
    if sbom["unresolved_count"] != 0 or not sbom["includes_transitive"] or not sbom["includes_native"]:
        return _blocked("SBOM_CLOSURE_INCOMPLETE", ["SBOM_CLOSURE"], sbom_status="TEST_BLOCKED")

    if not _section_text(
        oracle,
        (
            "oracle_id",
            "result",
            "independence",
            "provider_id",
            "provider_version",
            "target_provider_id",
            "target_provider_version",
        ),
    ) or not all(
        _hash(oracle.get(key))
        for key in (
            "input_digest",
            "output_digest",
            "artifact_set_sha256",
            "native_artifact_sha256",
            "subject_manifest_digest",
            "target_native_artifact_sha256",
            "vector_set_sha256",
        )
    ):
        return _blocked("ORACLE_EVIDENCE_INCOMPLETE", ["ORACLE"], oracle_status="TEST_BLOCKED")
    try:
        for name in _PROJECTION_NAMES:
            if projection_digests[name] != projection_digest(projections[name]):
                return _recovery("PROJECTION_PAYLOAD_DIGEST_DRIFT", [f"PROJECTION_{name.upper()}"], digest_status="RECOVERY_REQUIRED")
    except (TypeError, ValueError, UnicodeError):
        return _blocked("PROJECTION_PAYLOAD_NOT_CANONICAL", ["PROJECTION_DIGESTS"], digest_status="TEST_BLOCKED")
    if oracle["artifact_set_sha256"] != artifacts["artifact_set_sha256"]:
        return _recovery("ORACLE_SCOPE_DRIFT", ["ORACLE_SCOPE"], oracle_status="RECOVERY_REQUIRED")
    if oracle["input_digest"] != artifacts["artifact_set_sha256"] or oracle["output_digest"] != provider["provider_config_sha256"]:
        return _recovery("ORACLE_INPUT_OUTPUT_DRIFT", ["ORACLE_DIGESTS"], oracle_status="RECOVERY_REQUIRED")
    if (
        oracle["target_provider_id"] != provider["provider_id"]
        or oracle["target_provider_version"] != provider["provider_version"]
        or oracle["target_native_artifact_sha256"] != provider["native_artifact_sha256"]
        or oracle["subject_manifest_digest"] != subject["s25m_manifest_digest"]
    ):
        return _recovery("ORACLE_TARGET_IDENTITY_DRIFT", ["ORACLE_TARGET"], oracle_status="RECOVERY_REQUIRED")
    if oracle["independence"] not in {"INDEPENDENT", "SELF_CHECK_ONLY", "UNKNOWN"} or oracle["result"] not in {"PASS", "FAIL", "UNKNOWN"}:
        return _blocked("ORACLE_STATUS_INVALID", ["ORACLE_STATUS"], oracle_status="TEST_BLOCKED")
    if oracle["independence"] == "UNKNOWN" or oracle["result"] == "UNKNOWN":
        return _blocked("ORACLE_NOT_BOUND", ["ORACLE_INDEPENDENCE"], oracle_status="HOLD")
    if oracle["result"] == "FAIL":
        return _recovery("ORACLE_NEGATIVE_RESULT", ["ORACLE_RESULT"], oracle_status="RECOVERY_REQUIRED")
    if oracle["independence"] != "INDEPENDENT":
        return _blocked("ORACLE_NOT_INDEPENDENT", ["ORACLE_INDEPENDENCE"], oracle_status="TEST_BLOCKED")
    if (
        oracle["provider_id"],
        oracle["provider_version"],
        oracle["native_artifact_sha256"],
    ) == (
        provider["provider_id"],
        provider["provider_version"],
        provider["native_artifact_sha256"],
    ):
        return _blocked("ORACLE_NOT_INDEPENDENT", ["ORACLE_IDENTITY"], oracle_status="TEST_BLOCKED")

    if expected_subject is not None and dict(expected_subject) != dict(subject):
        return _recovery("SUBJECT_BINDING_DRIFT", ["SUBJECT"], dependency_status="RECOVERY_REQUIRED")

    if anchors["lockfile_sha256"] != lockfile["lockfile_sha256"]:
        return _recovery("LOCKFILE_ANCHOR_DRIFT", ["LOCKFILE_ANCHOR"], dependency_status="RECOVERY_REQUIRED")
    if anchors["dependency_graph_sha256"] != graph["graph_sha256"]:
        return _recovery("GRAPH_ANCHOR_DRIFT", ["GRAPH_ANCHOR"], dependency_status="RECOVERY_REQUIRED")
    if anchors["artifact_set_sha256"] != artifacts["artifact_set_sha256"]:
        return _recovery("ARTIFACT_ANCHOR_DRIFT", ["ARTIFACT_ANCHOR"], dependency_status="RECOVERY_REQUIRED")
    if anchors["provider_config_sha256"] != provider["provider_config_sha256"]:
        return _recovery("PROVIDER_ANCHOR_DRIFT", ["PROVIDER_ANCHOR"], provider_status="RECOVERY_REQUIRED")
    if anchors["fips_module_sha256"] != fips["module_sha256"]:
        return _recovery("FIPS_ANCHOR_DRIFT", ["FIPS_ANCHOR"], fips_status="RECOVERY_REQUIRED")
    if anchors["sbom_document_sha256"] != sbom["document_sha256"] or anchors["sbom_closure_sha256"] != sbom["closure_sha256"]:
        return _recovery("SBOM_ANCHOR_DRIFT", ["SBOM_ANCHOR"], sbom_status="RECOVERY_REQUIRED")
    if anchors["oracle_artifact_sha256"] != oracle["artifact_set_sha256"] or anchors["oracle_vector_set_sha256"] != oracle["vector_set_sha256"]:
        return _recovery("ORACLE_ANCHOR_DRIFT", ["ORACLE_ANCHOR"], oracle_status="RECOVERY_REQUIRED")

    try:
        computed_digest = projection_set_digest(projections)
    except (TypeError, ValueError, UnicodeError):
        return _blocked("PROJECTION_CANONICALIZATION_INVALID", ["PROJECTION_SET"], digest_status="TEST_BLOCKED")
    if projections["projection_set_digest"] != computed_digest:
        return _recovery("PROJECTION_SET_DIGEST_DRIFT", ["PROJECTION_SET_DIGEST"], digest_status="RECOVERY_REQUIRED")

    if projections["seal_status"] == "UNSEALED":
        return _base(
            PROPOSAL_ONLY,
            DESIGN_ONLY,
            "PROJECTION_CONSISTENCY_PROPOSAL_ONLY",
            ["EXTERNAL_PROVENANCE_NOT_ATTESTED"],
            digest_status="MATCH",
            dependency_status="CONSISTENT_PROPOSED",
            provider_status="CONSISTENT_PROPOSED",
            sbom_status="CONSISTENT_PROPOSED",
            oracle_status="INDEPENDENT_PASS_PROPOSED",
            fips_status="NOT_REQUIRED_PROPOSED" if not fips["required"] else "VERIFIED_PROPOSED",
            projection_status="CONSISTENT",
        )
    if expected_subject is None:
        return _blocked(
            "SUBJECT_EXPECTATION_MISSING",
            ["EXPECTED_SUBJECT"],
            digest_status="MATCH",
            dependency_status="HOLD",
        )
    if lockfile["status"] != "LOCKED":
        return _blocked("LOCKFILE_NOT_SEALED", ["LOCK_STATUS"], dependency_status="TEST_BLOCKED")
    return _base(
        LOCKED_TEST_PASS,
        "TEST_ONLY_PASS",
        "PROJECTION_CONSISTENCY_PASS_NO_PRODUCTION_AUTHORITY",
        ["EXTERNAL_PROVENANCE_NOT_ATTESTED", "PRODUCTION_NOT_AUTHORIZED"],
        digest_status="MATCH",
        dependency_status="CONSISTENT_LOCKED",
        provider_status="CONSISTENT_IDENTIFIED",
        sbom_status="COMPLETE",
        oracle_status="INDEPENDENT_PASS",
        fips_status="VERIFIED" if fips["required"] else "NOT_REQUIRED",
        projection_status="CONSISTENT",
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
    "evaluate_projection_consistency",
    "projection_digest",
    "projection_set_digest",
]
