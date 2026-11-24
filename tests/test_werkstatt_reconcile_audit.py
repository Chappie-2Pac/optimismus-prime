import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from prime_workspace_reconcile_audit import audit


def write_registry(path: Path, rows: list[dict[str, str]]) -> None:
    fields = ["project_id", "abs_path", "state"]
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)


def test_audit_is_conservative_and_metadata_only(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "local-ai").mkdir()
    (root / "private-workspace").mkdir()
    (root / "unknown").mkdir()
    (root / "AGENTS.md").write_text("metadata\n", encoding="utf-8")
    (root / "linked").symlink_to(root / "unknown", target_is_directory=True)
    registry = tmp_path / "projects.tsv"
    write_registry(registry, [
        {"project_id": "missing", "abs_path": str(root / "gone"), "state": "parked"},
        {"project_id": "external", "abs_path": "/tmp/external-project", "state": "reference"},
    ])

    result = audit(root, registry)
    by_name = {item["name"]: item for item in result["unregistered_entries"]}
    assert by_name["local-ai"]["decision"] == "propose_only"
    assert by_name["private-workspace"]["decision"] == "manual_only"
    assert by_name["unknown"]["reason"] == "no_conservative_classifier"
    assert "AGENTS.md" not in by_name
    assert by_name["linked"]["reason"] == "symlink_entry"
    assert result["summary"]["top_level_files_ignored"] == 1
    assert result["missing_registered_paths"][0]["reason"] == "registered_path_missing"
    assert result["external_registered_paths"][0]["reason"] == "registered_path_outside_workspace"
    assert result["read_only"] is True
    assert result["apply_supported"] is False


def test_cli_output_is_json(tmp_path, capsys):
    root = tmp_path / "workspace"
    root.mkdir()
    registry = tmp_path / "projects.tsv"
    write_registry(registry, [])
    result = audit(root, registry)
    assert json.dumps(result)
