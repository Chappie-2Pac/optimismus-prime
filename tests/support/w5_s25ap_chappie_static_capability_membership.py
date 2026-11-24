"""Independent oracle for Chappie's static capability membership relation."""


def evaluate_chappie_static_capability_membership(capability: str) -> bool:
    """Return the existing static allowlist result for an exact str value."""

    forbidden = {
        "self_modify",
        "set_goals",
        "self_preservation",
        "autonomous_action",
        "replicate",
        "override_constraints",
    }
    allowed = {
        "analyze",
        "compare",
        "document",
        "suggest",
        "evaluate",
        "structure",
        "clarify",
    }
    if capability in forbidden:
        return False
    if capability in allowed:
        return True
    return False
