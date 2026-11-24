"""Pure in-memory executor used by the W2.5-S0 proof harness.

There is deliberately no ``subprocess``, socket, model-server, filesystem or
network access here.  A fake process identity is a deterministic value tied to
the dispatch identity and is only accepted together with the run token,
command hash and fencing epoch supplied by the control plane.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any


def _canonical(value: Any) -> str:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class FakeProcessIdentity:
    pid: int
    starttime: str
    boot_id: str
    pidfd_ref: str
    cgroup_ref: str
    run_token: str
    fencing_epoch: int
    command_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "starttime": self.starttime,
            "boot_id": self.boot_id,
            "pidfd_ref": self.pidfd_ref,
            "cgroup_ref": self.cgroup_ref,
            "run_token": self.run_token,
            "fencing_epoch": self.fencing_epoch,
            "command_hash": self.command_hash,
        }


class FakeExecutor:
    """A deterministic single-spawn executor with explicit identity checks."""

    def __init__(self, *, boot_id: str = "fake-boot-w25-s0") -> None:
        self.boot_id = boot_id
        self.spawned: dict[str, FakeProcessIdentity] = {}
        self.spawn_requests: dict[str, int] = {}
        self.running: set[str] = set()
        self.exited: set[str] = set()

    @staticmethod
    def _digest(payload: dict[str, Any]) -> str:
        return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()

    def spawn(
        self,
        *,
        dispatch_id: str,
        run_token: str,
        fencing_epoch: int,
        command_hash: str,
    ) -> FakeProcessIdentity:
        self.spawn_requests[dispatch_id] = self.spawn_requests.get(dispatch_id, 0) + 1
        existing = self.spawned.get(dispatch_id)
        if existing is not None:
            if (
                existing.run_token != run_token
                or existing.fencing_epoch != fencing_epoch
                or existing.command_hash != command_hash
            ):
                raise ValueError("fake executor identity conflict on replay")
            return existing

        identity = self.derive_identity(
            dispatch_id=dispatch_id,
            run_token=run_token,
            fencing_epoch=fencing_epoch,
            command_hash=command_hash,
        )
        self.spawned[dispatch_id] = identity
        return identity

    def derive_identity(
        self,
        *,
        dispatch_id: str,
        run_token: str,
        fencing_epoch: int,
        command_hash: str,
    ) -> FakeProcessIdentity:
        """Reconstruct the deterministic fake identity without a spawn request."""

        digest = self._digest(
            {
                "dispatch_id": dispatch_id,
                "run_token": run_token,
                "fencing_epoch": fencing_epoch,
                "command_hash": command_hash,
            }
        )
        identity = FakeProcessIdentity(
            pid=40000 + int(digest[:8], 16) % 20000,
            starttime=digest[8:24],
            boot_id=self.boot_id,
            pidfd_ref=f"fake-pidfd:{digest[24:40]}",
            cgroup_ref=f"fake-cgroup:{digest[40:56]}",
            run_token=run_token,
            fencing_epoch=fencing_epoch,
            command_hash=command_hash,
        )
        return identity

    def adopt(self, dispatch_id: str, identity: FakeProcessIdentity) -> FakeProcessIdentity:
        """Restore a persisted fake identity without issuing a spawn request."""

        existing = self.spawned.get(dispatch_id)
        if existing is not None and existing != identity:
            raise ValueError("fake executor identity conflict on adoption")
        self.spawned[dispatch_id] = identity
        return identity

    def acknowledge(self, dispatch_id: str, identity: FakeProcessIdentity) -> None:
        if self.spawned.get(dispatch_id) != identity:
            raise ValueError("fake executor acknowledgement does not match spawn")

    def mark_running(self, dispatch_id: str, identity: FakeProcessIdentity) -> None:
        self.acknowledge(dispatch_id, identity)
        self.running.add(dispatch_id)

    def mark_exit(self, dispatch_id: str, identity: FakeProcessIdentity) -> int:
        self.acknowledge(dispatch_id, identity)
        if dispatch_id not in self.running:
            raise ValueError("fake executor exit before running")
        self.exited.add(dispatch_id)
        self.running.discard(dispatch_id)
        return 0

    def identity_for(self, dispatch_id: str) -> FakeProcessIdentity | None:
        return self.spawned.get(dispatch_id)

    def spawn_count(self, dispatch_id: str) -> int:
        return 1 if dispatch_id in self.spawned else 0

    def spawn_request_count(self, dispatch_id: str) -> int:
        """Count calls that could have requested a spawn from this executor."""

        return self.spawn_requests.get(dispatch_id, 0)
