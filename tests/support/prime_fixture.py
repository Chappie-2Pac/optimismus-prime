"""Synthetic project fixture shared by the standalone Prime tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def make_project(tmp_path: Path) -> Path:
    """Build a self-contained project with no host-specific data."""

    root = tmp_path / "prime-project"
    card_root = root / "Plan" / "local-ai"
    run = root / "runtime" / "runs" / "20260101T000000Z-public-fixture"
    card_root.mkdir(parents=True)
    (run / "out" / "evidence" / "artifact-receipts").mkdir(parents=True)

    (card_root / "QUEUE.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "updated": "2026-01-01T00:00:00Z",
                "tasks": [
                    {
                        "id": "card-1",
                        "owner": "Plan",
                        "status": "READY",
                        "card": "card-1.md",
                        "depends_on": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (card_root / "card-1.md").write_text(
        "# card-1 — Test\n\nRead-only fixture.\n", encoding="utf-8"
    )
    (run / "assignment.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "project": str(root),
                "run_id": run.name,
                "phase": "coordinate",
                "task_id": None,
            }
        ),
        encoding="utf-8",
    )
    (run / "session_state.json").write_text(
        json.dumps(
            {
                "run_id": run.name,
                "status": "done",
                "role": "mother-session",
                "writer_authority": "lease-v1-required",
            }
        ),
        encoding="utf-8",
    )
    (run / "tasks.json").write_text(json.dumps({"tasks": []}), encoding="utf-8")
    (run / "summary.md").write_text("# Summary\n", encoding="utf-8")

    artifact = run / "out" / "handoff.md"
    artifact.write_text("handoff\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    receipt = run / "out" / "evidence" / "artifact-receipts" / "artifact-001.json"
    receipt.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact_id": "artifact-001",
                "run_id": run.name,
                "run_dir": str(run),
                "path": str(artifact),
                "realpath": str(artifact),
                "sha256": digest,
                "size": artifact.stat().st_size,
                "verification_method": "sha256-file-integrity",
                "integrity_verified": True,
            }
        ),
        encoding="utf-8",
    )
    (run / "artifacts.jsonl").write_text(
        json.dumps(
            {
                "artifact_id": "artifact-001",
                "verification_receipt": str(receipt),
                "path": str(artifact),
                "sha256": digest,
                "size": artifact.stat().st_size,
                "integrity_verified": True,
                "verified": False,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return root
