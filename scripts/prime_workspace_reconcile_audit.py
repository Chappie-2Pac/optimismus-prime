#!/usr/bin/env python3
"""Read-only Werkstatt registry audit with conservative proposals.

Only the registry TSV and immediate directory metadata are read.  The tool
never opens project contents and never edits Werkstatt Core.  Its output is a
proposal, not an authorization to apply changes.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


SENSITIVE_NAMES = {"private-workspace", "credentials", ".network-pki", "private-data", "hosting-provider"}
WEBSITE_NAMES = {"project-site", "portfolio-site", "documentation-site"}
KNOWN_PROPOSALS = {
    "local-ai": ("meta-tooling", "active", "safe_metadata_candidate"),
    "system-build-lab": ("system-build", "manual-review", "reference_candidate"),
    "reference-library": ("archive", "manual-review", "archive_candidate"),
}


def load_registry(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def classify_unregistered(entry: Path) -> dict[str, str]:
    name = entry.name
    if name in SENSITIVE_NAMES:
        return {"decision": "manual_only", "proposed_class": "sensitive-private", "reason": "sensitive_name"}
    if name in WEBSITE_NAMES or "portfolio" in name.casefold():
        return {"decision": "manual_only", "proposed_class": "website-or-portfolio", "reason": "website_or_portfolio_scope"}
    if name in KNOWN_PROPOSALS:
        project_class, state, reason = KNOWN_PROPOSALS[name]
        return {"decision": "propose_only", "proposed_class": project_class, "proposed_state": state, "reason": reason}
    return {"decision": "manual_only", "proposed_class": "unknown", "reason": "no_conservative_classifier"}


def audit(workspace_root: Path, registry_path: Path) -> dict:
    rows = load_registry(registry_path)
    registered = {row.get("abs_path", ""): row for row in rows if row.get("abs_path")}
    entries = sorted(workspace_root.iterdir(), key=lambda path: path.name.casefold())
    proposals = []
    for entry in entries:
        if entry.is_symlink():
            proposals.append({"name": entry.name, "path": str(entry), "kind": "symlink", "decision": "manual_only", "proposed_class": "unknown", "reason": "symlink_entry"})
            continue
        if entry.is_dir() and str(entry) not in registered:
            proposal = {"name": entry.name, "path": str(entry), "kind": "directory" if entry.is_dir() else "file"}
            proposal.update(classify_unregistered(entry))
            proposals.append(proposal)
    missing_registered = []
    external_registered = []
    for row in rows:
        path = Path(row["abs_path"])
        if workspace_root not in path.parents and path != workspace_root:
            external_registered.append({"project_id": row.get("project_id", ""), "path": str(path), "decision": "manual_only", "reason": "registered_path_outside_workspace"})
            continue
        if not path.exists():
            missing_registered.append({"project_id": row.get("project_id", ""), "path": str(path), "decision": "manual_only", "reason": "registered_path_missing"})
    return {
        "schema": 1,
        "scope": "registry plus immediate entry metadata; no project contents read",
        "read_only": True,
        "apply_supported": False,
        "workspace_root": str(workspace_root),
        "registry_path": str(registry_path),
        "unregistered_entries": proposals,
        "missing_registered_paths": missing_registered,
        "external_registered_paths": external_registered,
        "summary": {
            "top_level_entries": len(entries),
            "top_level_directories": sum(entry.is_dir() for entry in entries),
            "top_level_files_ignored": sum(entry.is_file() for entry in entries),
            "registry_rows": len(rows),
            "unregistered_count": len(proposals),
            "missing_registered_count": len(missing_registered),
            "external_registered_count": len(external_registered),
            "manual_only_count": sum(item["decision"] == "manual_only" for item in proposals) + len(missing_registered),
            "propose_only_count": sum(item["decision"] == "propose_only" for item in proposals),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.workspace_root.resolve(), args.registry.resolve()), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
