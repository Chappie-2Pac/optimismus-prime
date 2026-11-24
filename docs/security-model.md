# Security model

Prime treats the model, tools and project files as potentially untrusted inputs. Prompt instructions are not a security boundary; authority is enforced by explicit contracts and, for higher-assurance deployments, by the operating system.

## Trust planes

| Plane | Responsibility | Default authority |
| --- | --- | --- |
| Control | goals, policy, budgets, leases and state transitions | protected |
| Execution | workers and tools | capability-limited |
| Data | source files, worktrees and outputs | mutable/untrusted |
| Audit | append-only events, receipts and hashes | evidence-only |
| Secret | credentials and key material | outside agent context |

## Default capability boundary

The public core allows only registered reads, Git observation, approved-source reads, bounded worktree writes, allowlisted local tests and artifact creation. Network access, secret reads, system writes, main-worktree writes, merge, publish, deployment, deletion, package installation and external messages are not default capabilities.

## Invariants

- Every mutation has an expected current hash.
- Every lease has an owner identity, epoch, fencing value and expiry.
- Every durable transaction has a prepare marker and a terminal outcome.
- An idempotent replay is distinguishable from an intent conflict.
- A stale or foreign writer cannot advance the authoritative state.
- A missing, changed or foreign receipt cannot produce acceptance.
- `BLOCKED`, `PAUSED`, `STALE`, `TIMEOUT` and `RECOVERY_REQUIRED` are never normalized to success.

## Failure posture

The safe result for ambiguity is no action. Path traversal, symlink traversal, queue drift, stale leases, malformed evidence, replay conflicts and incomplete recovery are rejected or quarantined. Recovery is bounded and revalidates the current evidence while the relevant lock or fence is held.
