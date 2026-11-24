"""Fail-closed, read-only verification for W3-S0 artifacts.

The verifier treats every JSON value as untrusted data. It never imports a
project module, starts a process, uses a network API, or writes a receipt. A
positive result requires an explicit expected scan scope; merely repeating the
scope hash from an untrusted manifest is not sufficient evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
import re
import stat
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from modules.understanding_s0.model import sha256_json
from modules.understanding_s0.path_policy import (
    PathPolicyError,
    absolute_path,
    is_same_or_under,
    open_directory_nofollow,
    overlaps_protected_root,
    relative_parts,
    validate_id,
)


HEX64 = re.compile(r"^[0-9a-f]{64}$")
PROFILE_KEYS = {
    "schema_version", "project_id", "canonical_root", "allowed_roots",
    "root_device", "root_inode", "path_policy_hash", "registry_snapshot_hash",
    "status", "version", "source_ids",
}
SOURCE_KEYS = {
    "schema_version", "project_id", "source_id", "relative_root",
    "root_device", "root_inode", "kind", "trust", "approval", "status",
}
SCOPE_KEYS = {
    "scope_version", "project_id", "source_id", "root_relative",
    "include_rules", "exclude_rules", "file_types", "follow_symlinks",
    "cross_device", "max_files", "max_bytes",
}
FILE_KEYS = {"relative_path", "size", "mtime_ns", "mode", "device", "inode", "link_count", "sha256"}
DENIED_KEYS = {"relative_path", "entry_kind", "reason_code", "detail"}
COVERAGE_KEYS = {
    "requested_scope", "directories_seen", "entries_seen", "files_indexed",
    "bytes_indexed", "denied_entries", "complete", "unknown_remainder",
    "absence_claims", "reason_codes", "eligible_entries", "lower_bound_only",
}
MANIFEST_KEYS = {
    "schema_version", "project_id", "source_id", "relative_root",
    "path_policy_hash", "registry_snapshot_hash", "scope_hash", "status",
    "state", "coverage", "files", "denied_entries", "source_device",
    "observed_at", "manifest_hash",
}
EVENT_KEYS = {
    "schema_version", "scan_id", "project_id", "source_id",
    "registry_snapshot_hash", "scope_hash", "sequence_no", "kind",
    "previous_event_hash", "status", "started_at", "finished_at",
    "manifest_hash", "coverage", "reason_codes", "read_only", "source_writes",
    "network_access", "process_starts", "event_hash",
}
TRUST_VALUES = {"trusted", "reviewed", "untrusted", "tainted", "historical", "hypothesis"}
SENSITIVE_COMPONENTS = {
    ".env", ".git", ".gnupg", ".netrc", ".network-pki", ".ssh",
    "credentials", "id_rsa", "secrets", "token", "tokens",
}
SENSITIVE_SUFFIXES = (".key", ".pem", ".p12", ".pfx")
STATUS_VALUES = {"REGISTERED", "READY"}
SCAN_STATUS_VALUES = {"COMPLETE", "PARTIAL", "DENIED"}


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str
    artifact: str

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "detail": self.detail, "artifact": self.artifact}


@dataclass(frozen=True)
class VerificationResult:
    accepted: bool
    artifact: str
    checked_hash: Optional[str]
    findings: Tuple[Finding, ...]

    @property
    def status(self) -> str:
        return "ACCEPTED" if self.accepted else "REJECTED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "status": self.status,
            "artifact": self.artifact,
            "checked_hash": self.checked_hash,
            "findings": [item.to_dict() for item in self.findings],
        }


class _Collector:
    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def add(self, code: str, detail: str, artifact: str) -> None:
        self.findings.append(Finding(code, detail[:300], artifact))

    def merge(self, result: VerificationResult) -> None:
        self.findings.extend(result.findings)

    def result(self, artifact: str, checked_hash: Optional[str] = None) -> VerificationResult:
        return VerificationResult(
            accepted=not self.findings,
            artifact=artifact,
            checked_hash=checked_hash,
            findings=tuple(self.findings),
        )


def _dict(value: Any, artifact: str, collector: _Collector, keys: set[str]) -> bool:
    if not isinstance(value, dict):
        collector.add("SCHEMA_NOT_OBJECT", "artifact must be a JSON object", artifact)
        return False
    missing = sorted(keys - set(value))
    unknown = sorted(set(value) - keys)
    if missing:
        collector.add("SCHEMA_MISSING_FIELDS", ", ".join(missing), artifact)
    if unknown:
        collector.add("SCHEMA_UNKNOWN_FIELDS", ", ".join(unknown), artifact)
    return not missing and not unknown


def _text(value: Any, field: str, collector: _Collector, artifact: str, *, nonempty: bool = True) -> bool:
    if not isinstance(value, str) or (nonempty and not value):
        collector.add("SCHEMA_TYPE", f"{field} must be non-empty text", artifact)
        return False
    return True


def _integer(value: Any, field: str, collector: _Collector, artifact: str, *, nonnegative: bool = True) -> bool:
    if isinstance(value, bool) or not isinstance(value, int) or (nonnegative and value < 0):
        collector.add("SCHEMA_TYPE", f"{field} must be a {'non-negative ' if nonnegative else ''}integer", artifact)
        return False
    return True


def _boolean(value: Any, field: str, collector: _Collector, artifact: str) -> bool:
    if not isinstance(value, bool):
        collector.add("SCHEMA_TYPE", f"{field} must be boolean", artifact)
        return False
    return True


def _hex(value: Any, field: str, collector: _Collector, artifact: str) -> bool:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        collector.add("HASH_FORMAT", f"{field} must be lowercase SHA-256", artifact)
        return False
    return True


def _list(value: Any, field: str, collector: _Collector, artifact: str) -> bool:
    if not isinstance(value, list):
        collector.add("SCHEMA_TYPE", f"{field} must be a list", artifact)
        return False
    return True


def _canonical_hash(value: Any, collector: _Collector, artifact: str, code: str) -> Optional[str]:
    try:
        return sha256_json(value)
    except (TypeError, ValueError, OverflowError) as exc:
        collector.add(code, f"canonical JSON/hash failed: {exc}", artifact)
        return None


def _relative(value: Any, field: str, collector: _Collector, artifact: str, *, allow_empty: bool = False) -> bool:
    if not isinstance(value, str):
        collector.add("PATH_INVALID", f"{field} must be text", artifact)
        return False
    if not allow_empty and value in ("", "."):
        collector.add("PATH_INVALID", f"{field} must not be empty", artifact)
        return False
    try:
        parts = relative_parts(value, field)
        if not allow_empty and not parts:
            raise PathPolicyError("empty relative path")
    except (PathPolicyError, TypeError) as exc:
        collector.add("PATH_INVALID", str(exc), artifact)
        return False
    return True


def _absolute(value: Any, field: str, collector: _Collector, artifact: str) -> bool:
    if not isinstance(value, str):
        collector.add("PATH_INVALID", f"{field} must be text", artifact)
        return False
    try:
        absolute_path(value, field)
    except (PathPolicyError, TypeError) as exc:
        collector.add("PATH_INVALID", str(exc), artifact)
        return False
    return True


def _timestamp(value: Any, field: str, collector: _Collector, artifact: str) -> Optional[datetime]:
    if not _text(value, field, collector, artifact):
        return None
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return parsed
    except ValueError as exc:
        collector.add("TIMESTAMP_INVALID", f"{field}: {exc}", artifact)
        return None


def _sensitive(relative_path: Any) -> bool:
    if not isinstance(relative_path, str):
        return False
    for component in relative_path.split("/"):
        lowered = component.lower()
        if lowered in SENSITIVE_COMPONENTS or lowered.startswith(".env.") or lowered.endswith(SENSITIVE_SUFFIXES):
            return True
    return False


def _sorted_unique(values: Any, field: str, collector: _Collector, artifact: str) -> bool:
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        collector.add("SCHEMA_TYPE", f"{field} must be a list of strings", artifact)
        return False
    if values != sorted(set(values)):
        collector.add("ORDER_INVALID", f"{field} must be sorted and unique", artifact)
        return False
    return True


def _validate_profile_shape(profile: Any, collector: _Collector) -> bool:
    artifact = "project-profile"
    if not _dict(profile, artifact, collector, PROFILE_KEYS):
        return False
    if profile.get("schema_version") != "project-profile.v1":
        collector.add("SCHEMA_VERSION", "unsupported project profile schema", artifact)
    try:
        validate_id(profile["project_id"], "project_id")
    except PathPolicyError as exc:
        collector.add("ID_INVALID", str(exc), artifact)
    _absolute(profile.get("canonical_root"), "canonical_root", collector, artifact)
    if _list(profile.get("allowed_roots"), "allowed_roots", collector, artifact):
        if not profile["allowed_roots"]:
            collector.add("PATH_INVALID", "allowed_roots must not be empty", artifact)
        for item in profile["allowed_roots"]:
            _absolute(item, "allowed_root", collector, artifact)
        if (all(isinstance(item, str) for item in profile["allowed_roots"])
                and profile["allowed_roots"] != sorted(set(profile["allowed_roots"]))):
            collector.add("ORDER_INVALID", "allowed_roots must be sorted and unique", artifact)
    _integer(profile.get("root_device"), "root_device", collector, artifact)
    _integer(profile.get("root_inode"), "root_inode", collector, artifact)
    _hex(profile.get("path_policy_hash"), "path_policy_hash", collector, artifact)
    _hex(profile.get("registry_snapshot_hash"), "registry_snapshot_hash", collector, artifact)
    profile_status = profile.get("status")
    if not isinstance(profile_status, str) or profile_status not in STATUS_VALUES:
        collector.add("STATUS_INVALID", "unknown project status", artifact)
    _integer(profile.get("version"), "version", collector, artifact)
    if isinstance(profile.get("version"), int) and not isinstance(profile.get("version"), bool) and profile["version"] < 1:
        collector.add("STATUS_INVALID", "project version must be positive", artifact)
    if _list(profile.get("source_ids"), "source_ids", collector, artifact):
        try:
            for source_id in profile["source_ids"]:
                validate_id(source_id, "source_id")
        except PathPolicyError as exc:
            collector.add("ID_INVALID", str(exc), artifact)
        _sorted_unique(profile["source_ids"], "source_ids", collector, artifact)
        if profile.get("status") == "REGISTERED" and profile["source_ids"]:
            collector.add("STATUS_INVALID", "REGISTERED profile must not contain sources", artifact)
        if profile.get("status") == "READY" and not profile["source_ids"]:
            collector.add("STATUS_INVALID", "READY profile must contain a source", artifact)
    if isinstance(profile.get("canonical_root"), str) and isinstance(profile.get("allowed_roots"), list):
        if not any(is_same_or_under(profile["canonical_root"], root) for root in profile["allowed_roots"] if isinstance(root, str)):
            collector.add("PATH_INVALID", "canonical_root is outside allowed_roots", artifact)
        if overlaps_protected_root(profile["canonical_root"]):
            collector.add("PATH_INVALID", "canonical_root overlaps a protected system root", artifact)
    return True


def _validate_source_shape(source: Any, collector: _Collector) -> bool:
    artifact = "source-spec"
    if not _dict(source, artifact, collector, SOURCE_KEYS):
        return False
    if source.get("schema_version") != "source-spec.v1":
        collector.add("SCHEMA_VERSION", "unsupported source schema", artifact)
    for field in ("project_id", "source_id"):
        try:
            validate_id(source[field], field)
        except PathPolicyError as exc:
            collector.add("ID_INVALID", str(exc), artifact)
    _relative(source.get("relative_root"), "relative_root", collector, artifact, allow_empty=True)
    if isinstance(source.get("relative_root"), str):
        try:
            normalized = "/".join(relative_parts(source["relative_root"], "relative_root"))
            if source["relative_root"] != normalized:
                collector.add("PATH_INVALID", "relative_root is not normalized", artifact)
        except PathPolicyError:
            pass
    _integer(source.get("root_device"), "root_device", collector, artifact)
    _integer(source.get("root_inode"), "root_inode", collector, artifact)
    _text(source.get("kind"), "kind", collector, artifact)
    source_trust = source.get("trust")
    if not isinstance(source_trust, str) or source_trust not in TRUST_VALUES:
        collector.add("TRUST_INVALID", "unknown source trust", artifact)
    if source.get("approval") != "explicit":
        collector.add("APPROVAL_INVALID", "source approval is not explicit", artifact)
    if source.get("status") != "REGISTERED":
        collector.add("STATUS_INVALID", "unknown source status", artifact)
    return True


def _validate_profile_sources(profile: Mapping[str, Any], sources: Sequence[Mapping[str, Any]], collector: _Collector) -> None:
    seen = set()
    for source in sources:
        if not _validate_source_shape(source, collector):
            continue
        source_id = source.get("source_id")
        source_key = source_id if isinstance(source_id, str) else repr(source_id)
        if source_key in seen:
            collector.add("SOURCE_DUPLICATE", f"duplicate source: {source_id}", "source-spec")
        seen.add(source_key)
        if source.get("project_id") != profile.get("project_id"):
            collector.add("PROJECT_MISMATCH", "source belongs to another project", "source-spec")
        if source_id not in profile.get("source_ids", []):
            collector.add("REGISTRY_BINDING", "source is absent from profile source_ids", "source-spec")
        if source.get("root_device") != profile.get("root_device"):
            collector.add("DEVICE_MISMATCH", "source device differs from project device", "source-spec")
    expected_ids = profile.get("source_ids", [])
    comparable_seen = sorted(item for item in seen if isinstance(item, str))
    if sorted(item for item in expected_ids if isinstance(item, str)) != comparable_seen or len(comparable_seen) != len(expected_ids):
        collector.add("REGISTRY_BINDING", "profile source_ids do not match supplied source specs", "project-profile")


def verify_profile(profile: Any, sources: Sequence[Mapping[str, Any]] = ()) -> VerificationResult:
    collector = _Collector()
    if not _validate_profile_shape(profile, collector):
        return collector.result("project-profile")
    if not isinstance(sources, (list, tuple)):
        collector.add("SCHEMA_TYPE", "sources must be a list or tuple", "project-profile")
        sources = ()
    _validate_profile_sources(profile, sources, collector)
    body = dict(profile)
    expected = dict(body)
    expected.pop("registry_snapshot_hash", None)
    source_payloads = sorted(
        (dict(item) for item in sources if isinstance(item, dict)),
        key=lambda item: item.get("source_id", "") if isinstance(item.get("source_id", ""), str) else repr(item.get("source_id")),
    )
    computed = _canonical_hash({"profile": expected, "sources": source_payloads}, collector, "project-profile", "REGISTRY_HASH_INVALID")
    if computed is not None and profile.get("registry_snapshot_hash") != computed:
        collector.add("REGISTRY_HASH_MISMATCH", "registry_snapshot_hash does not match profile and source specs", "project-profile")
    return collector.result("project-profile", profile.get("registry_snapshot_hash"))


def verify_source(source: Any, profile: Mapping[str, Any]) -> VerificationResult:
    collector = _Collector()
    profile = profile if isinstance(profile, dict) else {}
    if not _validate_source_shape(source, collector):
        return collector.result("source-spec")
    if not _validate_profile_shape(profile, collector):
        return collector.result("source-spec")
    collector.merge(verify_profile(profile, [source]))
    if source.get("project_id") != profile.get("project_id"):
        collector.add("PROJECT_MISMATCH", "source project_id differs from profile", "source-spec")
    if source.get("source_id") not in profile.get("source_ids", []):
        collector.add("REGISTRY_BINDING", "source_id is not registered in profile", "source-spec")
    if source.get("root_device") != profile.get("root_device"):
        collector.add("DEVICE_MISMATCH", "source device differs from profile", "source-spec")
    return collector.result("source-spec")


def _validate_scope(scope: Any, profile: Mapping[str, Any], source: Mapping[str, Any], collector: _Collector) -> Optional[str]:
    artifact = "scan-scope"
    if not _dict(scope, artifact, collector, SCOPE_KEYS):
        return None
    if scope.get("scope_version") != "scan-scope.v1":
        collector.add("SCHEMA_VERSION", "unsupported scan scope schema", artifact)
    if scope.get("project_id") != profile.get("project_id"):
        collector.add("PROJECT_MISMATCH", "scope project_id differs from profile", artifact)
    if scope.get("source_id") != source.get("source_id"):
        collector.add("SOURCE_MISMATCH", "scope source_id differs from source", artifact)
    if scope.get("root_relative") != source.get("relative_root"):
        collector.add("SCOPE_MISMATCH", "scope root differs from registered source", artifact)
    if isinstance(scope.get("root_relative"), str):
        try:
            if scope["root_relative"] != "/".join(relative_parts(scope["root_relative"], "root_relative")):
                collector.add("PATH_INVALID", "scope root_relative is not normalized", artifact)
        except PathPolicyError:
            collector.add("PATH_INVALID", "scope root_relative is invalid", artifact)
    if scope.get("include_rules") != ["regular-files"]:
        collector.add("SCOPE_MISMATCH", "unexpected include rules", artifact)
    if scope.get("exclude_rules") != []:
        collector.add("SCOPE_MISMATCH", "unexpected exclude rules", artifact)
    if scope.get("file_types") != ["regular"]:
        collector.add("SCOPE_MISMATCH", "unexpected file types", artifact)
    if scope.get("follow_symlinks") is not False:
        collector.add("POLICY_MISMATCH", "scope permits symlink following", artifact)
    if scope.get("cross_device") is not False:
        collector.add("POLICY_MISMATCH", "scope permits device crossing", artifact)
    for field in ("max_files", "max_bytes"):
        value = scope.get(field)
        if value is not None:
            _integer(value, field, collector, artifact)
    return _canonical_hash(scope, collector, artifact, "SCOPE_HASH_INVALID")


def verify_scope(scope: Any, profile: Mapping[str, Any], source: Mapping[str, Any]) -> VerificationResult:
    collector = _Collector()
    profile = profile if isinstance(profile, dict) else {}
    source = source if isinstance(source, dict) else {}
    expected = _validate_scope(scope, profile, source, collector)
    return collector.result("scan-scope", expected)


def _validate_file_records(files: Any, collector: _Collector) -> None:
    artifact = "source-manifest"
    if not _list(files, "files", collector, artifact):
        return
    paths = []
    for item in files:
        if not _dict(item, "file-record", collector, FILE_KEYS):
            continue
        relative_path = item.get("relative_path")
        _relative(relative_path, "relative_path", collector, "file-record")
        if isinstance(relative_path, str):
            try:
                normalized = "/".join(relative_parts(relative_path, "relative_path"))
                if relative_path != normalized:
                    collector.add("PATH_INVALID", "file relative_path is not normalized", "file-record")
            except PathPolicyError:
                pass
        if _sensitive(relative_path):
            collector.add("SENSITIVE_PATH_IN_MANIFEST", "sensitive path must not appear as indexed content", "file-record")
        for field in ("size", "mtime_ns", "mode", "device", "inode", "link_count"):
            _integer(item.get(field), field, collector, "file-record")
        _hex(item.get("sha256"), "sha256", collector, "file-record")
        path = item.get("relative_path")
        paths.append(path if isinstance(path, str) else repr(path))
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        collector.add("ORDER_INVALID", "files must be sorted by unique relative_path", artifact)


def _validate_denied_records(entries: Any, collector: _Collector) -> None:
    artifact = "source-manifest"
    if not _list(entries, "denied_entries", collector, artifact):
        return
    keys = []
    for item in entries:
        if not _dict(item, "denied-entry", collector, DENIED_KEYS):
            continue
        relative_path = item.get("relative_path")
        _relative(relative_path, "relative_path", collector, "denied-entry", allow_empty=True)
        if isinstance(relative_path, str) and relative_path not in ("", "."):
            try:
                normalized = "/".join(relative_parts(relative_path, "relative_path"))
                if relative_path != normalized:
                    collector.add("PATH_INVALID", "denied relative_path is not normalized", "denied-entry")
            except PathPolicyError:
                pass
        _text(item.get("entry_kind"), "entry_kind", collector, "denied-entry")
        _text(item.get("reason_code"), "reason_code", collector, "denied-entry")
        _text(item.get("detail"), "detail", collector, "denied-entry", nonempty=False)
        path = item.get("relative_path")
        reason = item.get("reason_code")
        keys.append((path if isinstance(path, str) else repr(path), reason if isinstance(reason, str) else repr(reason)))
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        collector.add("ORDER_INVALID", "denied_entries must be sorted and unique", artifact)


def _validate_coverage(
    coverage: Any,
    files: Sequence[Mapping[str, Any]],
    denied: Sequence[Mapping[str, Any]],
    status: Any,
    collector: _Collector,
) -> None:
    artifact = "source-manifest"
    if not _dict(coverage, "coverage", collector, COVERAGE_KEYS):
        return
    if coverage.get("requested_scope") != "registered-source-root":
        collector.add("SCOPE_MISMATCH", "unexpected requested_scope", artifact)
    for field in ("directories_seen", "entries_seen", "files_indexed", "bytes_indexed", "denied_entries"):
        _integer(coverage.get(field), field, collector, artifact)
    for field in ("complete", "unknown_remainder", "lower_bound_only"):
        _boolean(coverage.get(field), field, collector, artifact)
    absence_claims = coverage.get("absence_claims")
    if not isinstance(absence_claims, str) or absence_claims not in {"allowed", "forbidden"}:
        collector.add("COVERAGE_INVALID", "unknown absence_claims value", artifact)
    if _list(coverage.get("reason_codes"), "reason_codes", collector, artifact):
        all_reason_text = all(isinstance(item, str) and bool(item) for item in coverage["reason_codes"])
        if not all_reason_text:
            collector.add("COVERAGE_INVALID", "reason_codes must contain text", artifact)
        if all_reason_text and coverage["reason_codes"] != sorted(set(coverage["reason_codes"])):
            collector.add("ORDER_INVALID", "reason_codes must be sorted and unique", artifact)
    if coverage.get("eligible_entries") is not None:
        _integer(coverage.get("eligible_entries"), "eligible_entries", collector, artifact)
    if coverage.get("files_indexed") != len(files):
        collector.add("COVERAGE_INVALID", "files_indexed does not equal file records", artifact)
    if coverage.get("denied_entries") != len(denied):
        collector.add("COVERAGE_INVALID", "denied_entries does not equal denied records", artifact)
    indexed_size = sum(
        item.get("size", 0)
        for item in files
        if isinstance(item, dict) and isinstance(item.get("size"), int) and not isinstance(item.get("size"), bool)
    )
    if coverage.get("bytes_indexed") != indexed_size:
        collector.add("COVERAGE_INVALID", "bytes_indexed does not equal indexed file sizes", artifact)
    denied_reasons = {
        item.get("reason_code")
        for item in denied
        if isinstance(item, dict) and isinstance(item.get("reason_code"), str)
    }
    reasons = coverage.get("reason_codes", [])
    if not isinstance(reasons, list):
        reasons = []
    if not all(isinstance(item, str) for item in reasons):
        reasons = [item for item in reasons if isinstance(item, str)]
    if not denied_reasons.issubset(set(reasons)):
        collector.add("COVERAGE_INVALID", "coverage omits a denied-entry reason", artifact)
    derived_complete = coverage.get("denied_entries") == 0 and coverage.get("unknown_remainder") is False
    if coverage.get("complete") != derived_complete:
        collector.add("COVERAGE_INVALID", "complete does not match denial/unknown semantics", artifact)
    if coverage.get("complete"):
        if status != "COMPLETE" or coverage.get("unknown_remainder") or coverage.get("denied_entries"):
            collector.add("COVERAGE_INVALID", "complete coverage contradicts status or exclusions", artifact)
        if coverage.get("directories_seen") == 0:
            collector.add("COVERAGE_INVALID", "complete coverage has no observed directory", artifact)
        if coverage.get("absence_claims") != "allowed" or coverage.get("lower_bound_only"):
            collector.add("COVERAGE_INVALID", "complete coverage has partial semantics", artifact)
        if coverage.get("reason_codes"):
            collector.add("COVERAGE_INVALID", "complete coverage has reason codes", artifact)
    else:
        if not isinstance(status, str) or status not in {"PARTIAL", "DENIED"}:
            collector.add("COVERAGE_INVALID", "incomplete coverage has invalid status", artifact)
        if coverage.get("absence_claims") != "forbidden" or not coverage.get("lower_bound_only"):
            collector.add("COVERAGE_INVALID", "incomplete coverage permits negative claims", artifact)
        if not coverage.get("reason_codes"):
            collector.add("COVERAGE_INVALID", "incomplete coverage has no reason", artifact)
        if status == "PARTIAL" and coverage.get("directories_seen") == 0:
            collector.add("COVERAGE_INVALID", "PARTIAL scan has no observed directory", artifact)
        if status == "DENIED" and (coverage.get("directories_seen") or coverage.get("files_indexed") or coverage.get("bytes_indexed")):
            collector.add("COVERAGE_INVALID", "denied scan contains observed content", artifact)
    counters = [coverage.get(field) for field in ("entries_seen", "files_indexed", "denied_entries")]
    if all(isinstance(value, int) and not isinstance(value, bool) for value in counters):
        if coverage["entries_seen"] < coverage["files_indexed"] + coverage["denied_entries"]:
            collector.add("COVERAGE_INVALID", "entries_seen is below observed records", artifact)


def verify_manifest(
    manifest: Any,
    profile: Mapping[str, Any],
    source: Mapping[str, Any],
    scope: Any,
) -> VerificationResult:
    collector = _Collector()
    artifact = "source-manifest"
    profile = profile if isinstance(profile, dict) else {}
    source = source if isinstance(source, dict) else {}
    if not _dict(manifest, artifact, collector, MANIFEST_KEYS):
        return collector.result(artifact)
    if not _validate_profile_shape(profile, collector):
        return collector.result(artifact, manifest.get("manifest_hash"))
    if not _validate_source_shape(source, collector):
        return collector.result(artifact, manifest.get("manifest_hash"))
    collector.merge(verify_source(source, profile))
    scope_result = verify_scope(scope, profile, source)
    collector.merge(scope_result)
    for field in ("project_id", "source_id"):
        expected = profile.get("project_id") if field == "project_id" else source.get("source_id")
        if manifest.get(field) != expected:
            collector.add("REGISTRY_BINDING", f"manifest {field} is not bound to registry", artifact)
    if manifest.get("relative_root") != source.get("relative_root"):
        collector.add("SCOPE_MISMATCH", "manifest relative_root differs from source", artifact)
    if manifest.get("path_policy_hash") != profile.get("path_policy_hash"):
        collector.add("POLICY_MISMATCH", "manifest path policy differs from profile", artifact)
    if manifest.get("registry_snapshot_hash") != profile.get("registry_snapshot_hash"):
        collector.add("REGISTRY_BINDING", "manifest registry snapshot differs from profile", artifact)
    if manifest.get("scope_hash") != scope_result.checked_hash:
        collector.add("SCOPE_MISMATCH", "manifest scope hash differs from supplied scope", artifact)
    manifest_status = manifest.get("status")
    if not isinstance(manifest_status, str) or manifest_status not in SCAN_STATUS_VALUES:
        collector.add("STATUS_INVALID", "unknown manifest status", artifact)
    if manifest.get("state") != "SEALED":
        collector.add("STATE_INVALID", "manifest is not sealed", artifact)
    _validate_file_records(manifest.get("files"), collector)
    _validate_denied_records(manifest.get("denied_entries"), collector)
    files = manifest.get("files") if isinstance(manifest.get("files"), list) else []
    denied = manifest.get("denied_entries") if isinstance(manifest.get("denied_entries"), list) else []
    _validate_coverage(manifest.get("coverage"), files, denied, manifest.get("status"), collector)
    source_device = source.get("root_device")
    if isinstance(source_device, int) and not isinstance(source_device, bool):
        for item in files:
            if isinstance(item, dict) and item.get("device") != source_device:
                collector.add("DEVICE_MISMATCH", "file device differs from source device", artifact)
    coverage_value = manifest.get("coverage") if isinstance(manifest.get("coverage"), dict) else {}
    if manifest.get("source_device") is not None:
        _integer(manifest.get("source_device"), "source_device", collector, artifact)
        if manifest.get("source_device") != source.get("root_device"):
            collector.add("DEVICE_MISMATCH", "manifest source_device differs from source", artifact)
    else:
        if manifest.get("status") != "DENIED" or coverage_value.get("directories_seen", 0) != 0:
            collector.add("DEVICE_MISMATCH", "observed scan must bind a source device", artifact)
    _timestamp(manifest.get("observed_at"), "observed_at", collector, artifact)
    _hex(manifest.get("manifest_hash"), "manifest_hash", collector, artifact)
    hash_payload = {key: manifest.get(key) for key in MANIFEST_KEYS if key not in {"observed_at", "manifest_hash"}}
    computed_hash = _canonical_hash(hash_payload, collector, artifact, "MANIFEST_HASH_INVALID")
    if computed_hash is not None and manifest.get("manifest_hash") != computed_hash:
        collector.add("MANIFEST_HASH_MISMATCH", "manifest hash does not match canonical payload", artifact)
    return collector.result(artifact, manifest.get("manifest_hash"))


def verify_event(
    event: Any,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    source: Mapping[str, Any],
    scope: Any,
) -> VerificationResult:
    collector = _Collector()
    artifact = "scan-event"
    manifest = manifest if isinstance(manifest, dict) else {}
    profile = profile if isinstance(profile, dict) else {}
    source = source if isinstance(source, dict) else {}
    if not _dict(event, artifact, collector, EVENT_KEYS):
        return collector.result(artifact)
    collector.merge(verify_manifest(manifest, profile, source, scope))
    scope_result = verify_scope(scope, profile, source)
    collector.merge(scope_result)
    if event.get("schema_version") != "scan-event.v1":
        collector.add("SCHEMA_VERSION", "unsupported scan event schema", artifact)
    try:
        validate_id(event.get("scan_id"), "scan_id")
    except PathPolicyError as exc:
        collector.add("ID_INVALID", str(exc), artifact)
    if event.get("project_id") != profile.get("project_id") or event.get("source_id") != source.get("source_id"):
        collector.add("REGISTRY_BINDING", "event is not bound to profile/source", artifact)
    if event.get("registry_snapshot_hash") != profile.get("registry_snapshot_hash"):
        collector.add("REGISTRY_BINDING", "event registry snapshot differs from profile", artifact)
    if event.get("scope_hash") != scope_result.checked_hash:
        collector.add("SCOPE_MISMATCH", "event scope hash differs from supplied scope", artifact)
    if event.get("manifest_hash") != manifest.get("manifest_hash"):
        collector.add("MANIFEST_BINDING", "event does not point to supplied manifest", artifact)
    if event.get("sequence_no") != 1 or event.get("previous_event_hash") is not None:
        collector.add("EVENT_ORDER_INVALID", "W3-S0 requires one first event with no predecessor", artifact)
    _integer(event.get("sequence_no"), "sequence_no", collector, artifact)
    status = event.get("status")
    if not isinstance(status, str) or status not in SCAN_STATUS_VALUES or status != manifest.get("status"):
        collector.add("STATUS_INVALID", "event status differs from manifest", artifact)
    expected_kind = ({"COMPLETE": "SCAN_COMPLETED", "PARTIAL": "SCAN_PARTIAL", "DENIED": "SCAN_BLOCKED"}.get(status)
                     if isinstance(status, str) else None)
    if event.get("kind") != expected_kind:
        collector.add("EVENT_KIND_INVALID", "event kind does not match status", artifact)
    started = _timestamp(event.get("started_at"), "started_at", collector, artifact)
    finished = _timestamp(event.get("finished_at"), "finished_at", collector, artifact)
    if started is not None and finished is not None:
        try:
            if finished < started:
                collector.add("TIMESTAMP_INVALID", "finished_at precedes started_at", artifact)
        except TypeError:
            collector.add("TIMESTAMP_INVALID", "timestamps have incompatible timezone information", artifact)
    if event.get("coverage") != manifest.get("coverage"):
        collector.add("COVERAGE_INVALID", "event coverage differs from manifest", artifact)
    manifest_coverage = manifest.get("coverage") if isinstance(manifest.get("coverage"), dict) else {}
    if event.get("reason_codes") != manifest_coverage.get("reason_codes"):
        collector.add("COVERAGE_INVALID", "event reason_codes differ from coverage", artifact)
    if event.get("read_only") is not True:
        collector.add("CAPABILITY_VIOLATION", "event is not marked read-only", artifact)
    if event.get("source_writes") != 0 or event.get("network_access") is not False or event.get("process_starts") != 0:
        collector.add("CAPABILITY_VIOLATION", "event records a forbidden side effect", artifact)
    _integer(event.get("source_writes"), "source_writes", collector, artifact)
    _integer(event.get("process_starts"), "process_starts", collector, artifact)
    body = {key: event.get(key) for key in EVENT_KEYS if key != "event_hash"}
    _hex(event.get("event_hash"), "event_hash", collector, artifact)
    computed_hash = _canonical_hash(body, collector, artifact, "EVENT_HASH_INVALID")
    if computed_hash is not None and event.get("event_hash") != computed_hash:
        collector.add("EVENT_HASH_MISMATCH", "event hash does not match canonical body", artifact)
    return collector.result(artifact, event.get("event_hash"))


def verify_bundle(
    profile: Any,
    source: Any,
    manifest: Any,
    event: Any,
    scope: Any,
) -> VerificationResult:
    collector = _Collector()
    profile_result = verify_profile(profile, [source])
    collector.merge(profile_result)
    source_result = verify_source(source, profile if isinstance(profile, dict) else {})
    collector.merge(source_result)
    manifest_result = verify_manifest(manifest, profile if isinstance(profile, dict) else {}, source if isinstance(source, dict) else {}, scope)
    collector.merge(manifest_result)
    event_result = verify_event(event, manifest if isinstance(manifest, dict) else {}, profile if isinstance(profile, dict) else {}, source if isinstance(source, dict) else {}, scope)
    collector.merge(event_result)
    if (isinstance(manifest, dict) and isinstance(event, dict)
            and manifest.get("observed_at") != event.get("finished_at")):
        collector.add("TIMESTAMP_MISMATCH", "manifest observed_at differs from event finished_at", "scan-bundle")
    checked_hash = manifest.get("manifest_hash") if isinstance(manifest, dict) else None
    return collector.result("scan-bundle", checked_hash)


def verify_event_stream(events: Any) -> VerificationResult:
    """Verify append-only sequence links when a future stream has >1 event."""

    collector = _Collector()
    artifact = "event-stream"
    if not isinstance(events, list) or not events:
        collector.add("EVENT_STREAM_INVALID", "event stream must be a non-empty list", artifact)
        return collector.result(artifact)
    seen_hashes = set()
    previous_hash = None
    for expected_sequence, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            collector.add("SCHEMA_NOT_OBJECT", "event stream member must be an object", artifact)
            continue
        if not _dict(event, "scan-event", collector, EVENT_KEYS):
            continue
        if not isinstance(event.get("sequence_no"), int) or isinstance(event.get("sequence_no"), bool):
            collector.add("SCHEMA_TYPE", "sequence_no must be an integer", artifact)
        elif event.get("sequence_no") != expected_sequence:
            collector.add("EVENT_SEQUENCE_GAP", f"expected sequence {expected_sequence}", artifact)
        if event.get("previous_event_hash") != previous_hash:
            collector.add("EVENT_CHAIN_MISMATCH", "previous_event_hash does not point to the preceding event", artifact)
        status = event.get("status")
        if not isinstance(status, str) or status not in SCAN_STATUS_VALUES:
            collector.add("STATUS_INVALID", "event stream status is invalid", artifact)
        else:
            expected_kind = {"COMPLETE": "SCAN_COMPLETED", "PARTIAL": "SCAN_PARTIAL", "DENIED": "SCAN_BLOCKED"}[status]
            if event.get("kind") != expected_kind:
                collector.add("EVENT_KIND_INVALID", "event stream kind does not match status", artifact)
        started = _timestamp(event.get("started_at"), "started_at", collector, artifact)
        finished = _timestamp(event.get("finished_at"), "finished_at", collector, artifact)
        if started is not None and finished is not None and finished < started:
            collector.add("TIMESTAMP_INVALID", "finished_at precedes started_at", artifact)
        if event.get("read_only") is not True or event.get("network_access") is not False:
            collector.add("CAPABILITY_VIOLATION", "event stream contains a forbidden capability marker", artifact)
        _integer(event.get("source_writes"), "source_writes", collector, artifact)
        _integer(event.get("process_starts"), "process_starts", collector, artifact)
        if event.get("source_writes") != 0 or event.get("process_starts") != 0:
            collector.add("CAPABILITY_VIOLATION", "event stream contains a side effect marker", artifact)
        _dict(event.get("coverage"), "coverage", collector, COVERAGE_KEYS)
        _list(event.get("reason_codes"), "reason_codes", collector, artifact)
        event_hash = event.get("event_hash")
        hash_key = event_hash if isinstance(event_hash, str) else repr(event_hash)
        if hash_key in seen_hashes:
            collector.add("DUPLICATE_EVENT", "event hash occurs more than once", artifact)
        seen_hashes.add(hash_key)
        body = {key: event.get(key) for key in EVENT_KEYS if key != "event_hash"}
        computed_hash = _canonical_hash(body, collector, artifact, "EVENT_HASH_INVALID")
        if (not isinstance(event_hash, str) or not HEX64.fullmatch(event_hash)
                or (computed_hash is not None and event_hash != computed_hash)):
            collector.add("EVENT_HASH_MISMATCH", "event hash does not match canonical body", artifact)
        previous_hash = event_hash
    return collector.result(artifact)


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json_bytes(data: bytes) -> Any:
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid JSON constant: {value}")),
    )


def _read_relative_json(root_fd: int, relative: str) -> Any:
    parts = relative_parts(relative, "artifact path")
    if not parts:
        raise PathPolicyError("artifact path must not be empty")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        try:
            st = os.fstat(file_fd)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise PathPolicyError("artifact is not a regular file")
            with os.fdopen(file_fd, "rb") as handle:
                data = handle.read()
            file_fd = None
            return _parse_json_bytes(data)
        finally:
            if file_fd is not None:
                os.close(file_fd)
    finally:
        os.close(directory_fd)


def verify_output_bundle(
    output_root: os.PathLike[str] | str,
    profile_path: str,
    source_path: str,
    manifest_path: str,
    event_path: str,
    scope: Any,
) -> VerificationResult:
    """Read four explicit artifacts without writing or following symlinks."""

    collector = _Collector()
    try:
        root = absolute_path(output_root, "output root")
        if overlaps_protected_root(root):
            raise PathPolicyError("output root overlaps a protected system root")
        root_fd = open_directory_nofollow(root)
    except (OSError, PathPolicyError) as exc:
        collector.add("OUTPUT_ROOT_REJECTED", str(exc), "scan-bundle")
        return collector.result("scan-bundle")
    try:
        try:
            profile = _read_relative_json(root_fd, profile_path)
            source = _read_relative_json(root_fd, source_path)
            manifest = _read_relative_json(root_fd, manifest_path)
            event = _read_relative_json(root_fd, event_path)
        except (OSError, PathPolicyError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            collector.add("OUTPUT_READ_FAILED", str(exc), "scan-bundle")
            return collector.result("scan-bundle")
    finally:
        os.close(root_fd)
    result = verify_bundle(profile, source, manifest, event, scope)
    collector.merge(result)

    def check_path(path: str, expected: Tuple[str, ...], code: str) -> None:
        try:
            actual = relative_parts(path, "artifact path")
        except PathPolicyError as exc:
            collector.add("OUTPUT_PATH_REJECTED", str(exc), "scan-bundle")
            return
        if actual != expected:
            collector.add(code, f"expected {'/'.join(expected)}", "scan-bundle")

    if isinstance(profile, dict) and isinstance(profile.get("project_id"), str) and isinstance(profile.get("version"), int):
        check_path(
            profile_path,
            ("registry", "projects", profile["project_id"], f"v{profile['version']:04d}.json"),
            "PROFILE_PATH_MISMATCH",
        )
    if isinstance(source, dict) and isinstance(source.get("project_id"), str) and isinstance(source.get("source_id"), str):
        check_path(
            source_path,
            ("registry", "sources", source["project_id"], f"{source['source_id']}.json"),
            "SOURCE_PATH_MISMATCH",
        )
    if isinstance(manifest, dict) and isinstance(manifest.get("manifest_hash"), str):
        check_path(
            manifest_path,
            ("manifests", f"{manifest['manifest_hash']}.json"),
            "MANIFEST_PATH_HASH_MISMATCH",
        )
    if isinstance(event, dict) and isinstance(event.get("scan_id"), str):
        check_path(event_path, ("events", f"{event['scan_id']}.json"), "EVENT_PATH_ID_MISMATCH")
    return collector.result("scan-bundle", manifest.get("manifest_hash") if isinstance(manifest, dict) else None)

