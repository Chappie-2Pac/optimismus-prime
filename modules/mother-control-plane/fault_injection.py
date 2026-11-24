"""Deterministic crash injection for the W2.5-S0 fake executor.

The injector is intentionally process-local.  It never kills a process and
never touches a real worker; raising :class:`InjectedCrash` models the point
at which a mother session would have disappeared.  The control plane calls
all six hooks for every C0--C11 point, including points that P0 suppresses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional


COMMIT_POINTS = tuple(f"C{i}" for i in range(12))
HOOKS = (
    "before_prepare",
    "after_prepare",
    "before_replace",
    "after_replace",
    "before_commit_marker",
    "after_commit_marker",
)


class InjectedCrash(RuntimeError):
    """Raised exactly once when an armed fault point is reached."""

    def __init__(self, fault_id: str):
        super().__init__(f"injected crash at {fault_id}")
        self.fault_id = fault_id


@dataclass
class FaultPlan:
    """One-shot deterministic fault plan.

    ``target`` accepts either ``"C3.before_replace"`` or a ``(point, hook)``
    tuple.  With no target the plan is inert.  ``seen`` is useful evidence for
    tests: a recovered run must not need to pass the same hook again for an
    already committed operation.
    """

    target: Optional[str] = None
    seen: list[str] = field(default_factory=list)
    injected: list[str] = field(default_factory=list)
    _tripped: bool = False

    @classmethod
    def none(cls) -> "FaultPlan":
        return cls()

    @classmethod
    def for_fault(cls, commit_point: str, hook: str) -> "FaultPlan":
        return cls(target=f"{commit_point}.{hook}")

    @classmethod
    def from_fault_id(cls, fault_id: str) -> "FaultPlan":
        point, sep, hook = fault_id.partition(".")
        if not sep:
            raise ValueError(f"invalid fault id: {fault_id}")
        return cls.for_fault(point, hook)

    def validate(self) -> None:
        if self.target is None:
            return
        point, sep, hook = self.target.partition(".")
        if not sep or point not in COMMIT_POINTS or hook not in HOOKS:
            raise ValueError(f"invalid fault target: {self.target}")

    def trip(self, commit_point: str, hook: str) -> None:
        if commit_point not in COMMIT_POINTS:
            raise ValueError(f"unknown commit point: {commit_point}")
        if hook not in HOOKS:
            raise ValueError(f"unknown hook: {hook}")
        fault_id = f"{commit_point}.{hook}"
        self.seen.append(fault_id)
        if self.target == fault_id and not self._tripped:
            self._tripped = True
            self.injected.append(fault_id)
            raise InjectedCrash(fault_id)

    def saw_all(self, fault_ids: Iterable[str]) -> bool:
        return set(fault_ids).issubset(self.seen)
