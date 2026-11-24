"""Independent S25AM oracle for the local JSON plan-shape contract."""

from __future__ import annotations

from pathlib import Path


PLAN_FIELDS = ("goal", "files", "steps", "tests", "risks", "open_questions")


def evaluate_local_plan_shape_case(
    plan: dict[str, object],
) -> dict[str, object]:
    """Mirror the public plan-shape relation for a JSON-built-in snapshot."""

    missing = [field for field in PLAN_FIELDS if not plan.get(field)]
    if missing:
        raise ValueError("Plan unvollständig: " + ", ".join(missing))
    if (
        not isinstance(plan["files"], list)
        or not isinstance(plan["steps"], list)
        or not isinstance(plan["tests"], list)
    ):
        raise ValueError("files, steps und tests müssen Listen sein")
    if any(
        Path(item).is_absolute() or ".." in Path(item).parts
        for item in plan["files"]
    ):
        raise ValueError("Plan enthält einen unzulässigen Dateipfad")
    return {"valid": True, "fields": list(PLAN_FIELDS)}
