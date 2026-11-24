"""Result models for the W5-S0 dispatch-bridge evidence verifier."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class W5EvidenceError(ValueError):
    """The supplied bridge evidence is malformed or contradictory."""


class W5IncompatibleSource(W5EvidenceError):
    """The source contract is not the W2.5-S0 contract understood by W5."""


@dataclass(frozen=True)
class DispatchBridgeResult:
    """Read-only W5 outcome; it never authorizes a process or next card."""

    status: str
    findings: tuple[str, ...] = ()
    bridge: Mapping[str, Any] | None = None
    replay: Mapping[str, Any] | None = None

    @property
    def verified(self) -> bool:
        return self.status == "BRIDGE_VERIFIED"

    @property
    def accepted(self) -> bool:
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "findings": list(self.findings),
            "bridge": dict(self.bridge) if self.bridge is not None else None,
            "replay": dict(self.replay) if self.replay is not None else None,
            "accepted": False,
        }
