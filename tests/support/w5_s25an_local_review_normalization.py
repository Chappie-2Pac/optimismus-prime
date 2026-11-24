"""Independent S25AN oracle for the local review-normalization contract."""

from __future__ import annotations


REVIEW_STATUSES = {"pass", "fail", "blocked"}


def evaluate_local_review_normalization_case(
    review: dict[str, object],
) -> dict[str, object]:
    """Mirror the local review reduction for a JSON-built-in snapshot."""

    status = review.get("status")
    if status not in REVIEW_STATUSES:
        raise ValueError("Reviewstatus muss pass, fail oder blocked sein")
    findings = review.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("findings muss eine Liste sein")
    normalized = []
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or not finding.get("path")
            or not finding.get("reason")
        ):
            raise ValueError("Jeder Reviewbefund braucht path und reason")
        normalized.append(
            {"path": finding["path"], "reason": finding["reason"]}
        )
    if status == "fail" and not normalized:
        raise ValueError("fail benötigt mindestens einen konkreten Befund")
    return {
        "status": status,
        "findings": normalized,
        "summary": review.get("summary", ""),
    }
