# Verification map

The test suite is deterministic and local. It uses temporary directories and SQLite databases; it does not require a model, network service, credential, Jetson host or external repository.

## Quick command

```bash
python3 -m pytest -q -p no:cacheprovider
```

The public snapshot contains 1,180 collected Python tests after removing the 43 tests that exercise host-specific cross-repository MCP adapters. The count is intentionally reported as collection scope; pass/fail remains the result of the command above.

## Contract groups

- W3: read-only project understanding, path policy, source verification, event streams and context bundles
- W4: small-loop authority, review preparation, tool circuits and receipt compatibility
- W5-S0–S9: dispatch evidence, Prime binding, external anchors, head checks and transaction preparation
- W5-S10–S16: transaction authority, cross-store fixtures, source and worker attestations
- W5-S17–S22: replay ownership, receipt provenance, intent witnesses, commit journals and projection preflight
- W5-S23–S25: queue writer, adversarial recovery, handoff fencing, quarantine, canonicalization and evidence closure

## Adversarial properties

The harnesses cover stale hashes, wrong owners, expired leases, monotonic fencing, idempotent replay, conflicting intents, crash points before and after commit, foreign writers, symlink paths, malformed receipts, source drift, incomplete manifests and recovery quarantine.

Green tests prove the stated contract under the fixture conditions. They do not by themselves prove OS isolation, production deployment safety or the security of an unreviewed host integration.
