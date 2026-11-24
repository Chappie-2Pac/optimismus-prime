# Architecture

Optimismus Prime separates intent, observation, authority, execution and evidence. The architecture is normative about ownership and transitions even when a later capability is still represented by a proposal or a read-only verifier.

## Sixteen-layer model

| Layer | Contract | Public implementation slice |
| --- | --- | --- |
| L0 | Mission, scope and non-goals | explicit scope and fail-closed decisions |
| L1 | Trust, provenance and versioning | source hashes, manifests and evidence references |
| L2 | Project registry and path boundaries | `understanding_s0` registry and path policy |
| L3 | Ingestion and scanners | read-only scanner and source snapshots |
| L4 | Event store and runtime state | SQLite control-plane proof harness |
| L5 | Typed knowledge objects | claims, decisions, conflicts and evidence contracts |
| L6 | Retrieval and project graph | source-bound retrieval interfaces |
| L7 | Context and long-term memory | versioned context bundles |
| L8 | Work and teaching units | lifecycle and quality contracts |
| L9 | Gap, task and opportunity discovery | proposal-only discovery boundary |
| L10 | Plan engine | immutable plan and postcondition validation |
| L11 | Scheduler and queue | deterministic selection and CAS preconditions |
| L12 | Mother supervisor and run FSM | explicit run/card/attempt transitions |
| L13 | Agent orchestration | grants, admission and bounded worker contracts |
| L14 | Capability, sandbox and execution | allowlisted commands and protected worktrees |
| L15 | Artifacts, receipts and review | evidence sealing, review and acceptance gates |

The public code concentrates on L2–L5, L10–L15 and their verification boundaries. W5 is staged as a sequence of independently testable contracts rather than one opaque executor.

## Control and data flow

1. A registered source is observed through a read-only path policy.
2. The observation is bound to hashes, identity and scope.
3. The control plane evaluates a state transition using CAS and lease fencing.
4. Dispatch is represented as intent, claim, spawn request and executor acknowledgement.
5. The executor produces artifacts in its bounded work area.
6. Validators and review produce evidence; transport completion alone never creates acceptance.
7. Crash, drift, replay or incomplete evidence routes the run to HOLD, BLOCK or recovery.
