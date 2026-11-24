"""Small, immutable result models for the W4-S0 evidence verifier."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class W4EvidenceError(ValueError):
    """The supplied W4 evidence is malformed or internally inconsistent."""


class W4IncompatibleSource(W4EvidenceError):
    """The bundle is from a source contract that W4-S0 does not interpret."""


@dataclass(frozen=True)
class VerificationResult:
    """Read-only outcome; no result is an acceptance or runtime transition."""

    status: str
    findings: tuple[str, ...] = ()
    review_preparation: Mapping[str, Any] | None = None
    receipt: Mapping[str, Any] | None = None
    checkpoint: Mapping[str, Any] | None = None
    progress: Mapping[str, Any] | None = None
    tool_circuit: Mapping[str, Any] | None = None

    @property
    def ready_for_review(self) -> bool:
        return self.status == "READY_FOR_REVIEW"

    @property
    def accepted(self) -> bool:
        # Kept explicit so callers cannot accidentally treat preparation as
        # acceptance. W4-S0 can never produce ACCEPTED/DONE.
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "findings": list(self.findings),
            "review_preparation": dict(self.review_preparation) if self.review_preparation is not None else None,
            "receipt": dict(self.receipt) if self.receipt is not None else None,
            "checkpoint": dict(self.checkpoint) if self.checkpoint is not None else None,
            "progress": dict(self.progress) if self.progress is not None else None,
            "tool_circuit": dict(self.tool_circuit) if self.tool_circuit is not None else None,
            "accepted": False,
        }
