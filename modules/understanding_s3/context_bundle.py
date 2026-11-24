"""W3-S3 semantic binding of sealed streams to manifest evidence.

W3-S2 proves that a stream is internally ordered and bound to a scope.  This
module adds the missing semantic edge: every stream event must resolve to a
source manifest, and the existing W3-S1 bundle verifier must accept that
event/manifest pair.  S2 sequence fields are not silently reinterpreted;
they are projected into a temporary singleton event solely for W3-S1's
singleton-order contract, while S2 independently verifies the original
sequence and event hash.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from modules.understanding_s0.model import canonical_json_bytes, sha256_json
from modules.understanding_s1.verifier import (
    Finding,
    VerificationResult,
    verify_bundle,
)
from modules.understanding_s2.event_stream import (
    EventStreamArtifact,
    EventStreamError,
    verify_event_stream_artifact,
)
from modules.understanding_s2.scope import (
    ScopeArtifact,
    ScopeArtifactError,
)


MAX_MANIFESTS = 4096
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 64


class ContextBundleError(ValueError):
    """The semantic context bundle is malformed or exceeds its limits."""


@dataclass(frozen=True)
class ContextBundle:
    """Immutable input view for the S3 verifier; it does not materialize data."""

    stream: EventStreamArtifact
    scope: ScopeArtifact
    profile: Mapping[str, Any]
    source: Mapping[str, Any]
    manifests: Tuple[Mapping[str, Any], ...]


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ContextBundleError("JSON nesting exceeds the depth limit")
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _check_depth(item, depth + 1)


def _plain_object(value: Any, field: str) -> Dict[str, Any]:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if not isinstance(value, dict):
        raise ContextBundleError(f"{field} must be an object")
    try:
        _check_depth(value)
        data = json.loads(canonical_json_bytes(value).decode("utf-8"))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ContextBundleError(f"{field} is not canonical JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ContextBundleError(f"{field} must be an object")
    return data


def _result(findings: list[Finding], checked_hash: Optional[str]) -> VerificationResult:
    return VerificationResult(
        accepted=not findings,
        artifact="context-bundle",
        checked_hash=checked_hash,
        findings=tuple(findings),
    )


def _parse_stream(value: Any) -> EventStreamArtifact:
    if isinstance(value, EventStreamArtifact):
        return value
    return EventStreamArtifact.from_dict(value)


def _parse_scope(value: Any) -> ScopeArtifact:
    if isinstance(value, ScopeArtifact):
        return value
    return ScopeArtifact.from_dict(value)


def _parse_manifests(value: Any, findings: list[Finding]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        findings.append(Finding("MANIFEST_CATALOG_SCHEMA", "manifests must be a list", "context-bundle"))
        return {}
    if len(value) > MAX_MANIFESTS:
        findings.append(Finding("MANIFEST_CATALOG_LIMIT", "manifest catalog exceeds the item limit", "context-bundle"))
        return {}
    catalog: Dict[str, Dict[str, Any]] = {}
    for index, item in enumerate(value):
        try:
            manifest = _plain_object(item, f"manifest[{index}]")
        except ContextBundleError as exc:
            findings.append(Finding("MANIFEST_SCHEMA", str(exc)[:300], "context-bundle"))
            continue
        if len(canonical_json_bytes(manifest)) > MAX_MANIFEST_BYTES:
            findings.append(Finding("MANIFEST_SIZE_LIMIT", f"manifest[{index}] exceeds the size limit", "context-bundle"))
            continue
        manifest_hash = manifest.get("manifest_hash")
        if not isinstance(manifest_hash, str) or not manifest_hash:
            findings.append(Finding("MANIFEST_HASH_MISSING", f"manifest[{index}] has no manifest_hash", "context-bundle"))
            continue
        if manifest_hash in catalog:
            findings.append(Finding("MANIFEST_DUPLICATE", "manifest_hash occurs more than once", "context-bundle"))
            continue
        if manifest.get("schema_version") != "source-manifest.v1":
            findings.append(
                Finding(
                    "MANIFEST_SCHEMA_UNSUPPORTED",
                    "context bundle requires source-manifest.v1",
                    "context-bundle",
                )
            )
        catalog[manifest_hash] = manifest
    return catalog


def _project_singleton(event: Mapping[str, Any]) -> Dict[str, Any]:
    """Project one S2 event into the S1 singleton contract without mutation."""

    projected = dict(event)
    projected["sequence_no"] = 1
    projected["previous_event_hash"] = None
    projected["event_hash"] = sha256_json(
        {key: value for key, value in projected.items() if key != "event_hash"}
    )
    return projected


def verify_contextual_stream_bundle(
    stream: Any,
    scope: Any,
    profile: Mapping[str, Any] | Any,
    source: Mapping[str, Any] | Any,
    manifests: Sequence[Mapping[str, Any] | Any],
    *,
    authority: Any = None,
) -> VerificationResult:
    """Verify S2 ordering plus S1 semantics for every referenced manifest."""

    findings: list[Finding] = []
    parsed_stream: Optional[EventStreamArtifact] = None
    parsed_scope: Optional[ScopeArtifact] = None
    checked_hash: Optional[str] = None
    try:
        parsed_stream = _parse_stream(stream)
        checked_hash = parsed_stream.stream_hash
        parsed_scope = _parse_scope(scope)
        profile_data = _plain_object(profile, "profile")
        source_data = _plain_object(source, "source")
    except (ContextBundleError, EventStreamError, ScopeArtifactError, TypeError, ValueError, RecursionError) as exc:
        findings.append(Finding("CONTEXT_BUNDLE_SCHEMA", str(exc)[:300], "context-bundle"))
        return _result(findings, checked_hash)

    source_ids = profile_data.get("source_ids")
    selected_source_id = source_data.get("source_id")
    if source_ids != [selected_source_id]:
        findings.append(
            Finding(
                "CONTEXT_MULTI_SOURCE_UNSUPPORTED",
                "W3-S3 v1 requires a profile containing exactly the selected source",
                "context-bundle",
            )
        )

    stream_result = verify_event_stream_artifact(
        parsed_stream,
        parsed_scope,
        profile_data,
        source_data,
        authority=authority,
    )
    findings.extend(stream_result.findings)
    if authority is None:
        findings.append(
            Finding(
                "AUTHORITY_REQUIRED",
                "W3-S3 acceptance requires a live UnderstandingRegistry authority",
                "context-bundle",
            )
        )

    catalog = _parse_manifests(manifests, findings)
    events = parsed_stream.to_dict()["events"]
    referenced_hashes = {
        event.get("manifest_hash")
        for event in events
        if isinstance(event, dict) and isinstance(event.get("manifest_hash"), str)
    }
    for missing in sorted(referenced_hashes - set(catalog)):
        findings.append(Finding("MANIFEST_MISSING", f"stream references missing manifest {missing}", "context-bundle"))
    for extra in sorted(set(catalog) - referenced_hashes):
        findings.append(Finding("MANIFEST_UNREFERENCED", f"catalog contains unreferenced manifest {extra}", "context-bundle"))

    scope_data = parsed_scope.scope.to_dict()
    for event in events:
        if not isinstance(event, dict):
            continue
        manifest_hash = event.get("manifest_hash")
        if not isinstance(manifest_hash, str) or manifest_hash not in catalog:
            continue
        projected = _project_singleton(event)
        bundle_result = verify_bundle(
            profile_data,
            source_data,
            catalog[manifest_hash],
            projected,
            scope_data,
        )
        findings.extend(bundle_result.findings)

    return _result(findings, checked_hash)


__all__ = ["ContextBundle", "ContextBundleError", "verify_contextual_stream_bundle"]
