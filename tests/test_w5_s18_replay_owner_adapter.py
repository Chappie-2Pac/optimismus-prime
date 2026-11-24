"""Integration tests for the S17-validated W5-S18 owner adapter."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from modules.w5_dispatch_bridge_s0 import cross_store_owner as s17  # noqa: E402
from modules.w5_dispatch_bridge_s0.replay_owner_adapter import (  # noqa: E402
    ReplayOwnerAdapterError,
    advance_from_s17_preflight,
)
from modules.w5_dispatch_bridge_s0.replay_owner_store import ReplayOwnerStore  # noqa: E402
from test_w5_s17_cross_store_owner import W5S17CrossStoreOwnerTests  # noqa: E402


SCOPE_ID = "adapter-s18-scope"
LEASE_TOKEN = "adapter-s18-lease-token-0123456789"
SCOPE_KEYS = (
    "replay_namespace",
    "registry_id",
    "registry_version",
    "registry_epoch",
    "registry_sha256",
    "profile_set_sha256",
    "source_set_sha256",
    "cohort_binding_sha256",
    "host_id",
    "host_instance_id",
    "worker_epoch",
)


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class W5S18ReplayOwnerAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = W5S17CrossStoreOwnerTests()
        fixture.setUp()
        self.fixture = fixture
        self.owner = s17.parse_owner_observation(fixture.owner)["payload"]
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / f"{SCOPE_ID}.sqlite3"
        self.clock = MutableClock(100)
        self.binding = {key: self.owner[key] for key in SCOPE_KEYS}
        with self._open() as store:
            store.create_scope(
                scope_id=SCOPE_ID,
                scope_binding=self.binding,
                owner_id=self.owner["owner_id"],
                owner_instance_id=self.owner["owner_instance_id"],
                owner_epoch=self.owner["owner_epoch"],
                fencing_epoch=self.owner["fencing_epoch"],
                lease_token=LEASE_TOKEN,
                lease_expires_at=1000,
                initial_state_version=self.owner["state_version"],
                initial_sequence=self.owner["last_sequence"],
                initial_attestation_set_sha256=self.owner["last_attestation_set_sha256"],
                initial_nonce_sha256=self.owner["last_nonce_sha256"],
                initial_head_sha256=self.owner["head_sha256"],
                initial_idempotency_index_sha256=self.owner["idempotency_index_sha256"],
            )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _open(self) -> ReplayOwnerStore:
        return ReplayOwnerStore(self.db_path, scope_id=SCOPE_ID, owner_root=self.temp.name, clock=self.clock)

    def _advance(self, *, owner_observation: object | None = None) -> dict:
        with self._open() as store:
            return advance_from_s17_preflight(
                store,
                worker_attestations=self.fixture.bundle["worker_attestations"],
                replay_observation=self.fixture.bundle["replay_observation"],
                replay_floor=self.fixture.bundle["replay_floor"],
                host_runtime_attestation=self.fixture.bundle["host_runtime_attestation"],
                s15_input=self.fixture.s15_input,
                owner_observation=self.fixture.owner if owner_observation is None else owner_observation,
                request=self.fixture.request,
                lease_token=LEASE_TOKEN,
            )

    def test_adapter_revalidates_s17_and_commits_only_derived_candidate(self) -> None:
        result = self._advance()
        self.assertEqual(result["status"], "OWNER_CAS_COMMITTED")
        self.assertEqual(result["state_version_before"], self.owner["state_version"])
        self.assertEqual(result["state_version_after"], self.owner["state_version"] + 1)
        self.assertEqual(result["sequence_after"], self.owner["last_sequence"] + 1)
        self.assertFalse(result["consume_allowed"])
        self.assertFalse(result["receipt_emitted"])
        with self._open() as store:
            state = store.read_state(SCOPE_ID)
        self.assertEqual(state["head_sha256"], result["head_after_sha256"])
        self.assertEqual(state["idempotency_index_sha256"], result["idempotency_index_sha256_after"])

    def test_invalid_signed_owner_is_rejected_before_store_mutation(self) -> None:
        invalid = copy.deepcopy(self.fixture.owner)
        invalid["authority_mac"] = "0" * 64
        with self.assertRaises(ReplayOwnerAdapterError):
            self._advance(owner_observation=invalid)
        with self._open() as store:
            state = store.read_state(SCOPE_ID)
        self.assertEqual(state["state_version"], self.owner["state_version"])
        self.assertEqual(state["sequence"], self.owner["last_sequence"])


if __name__ == "__main__":
    unittest.main()
