# W5-S0: externalized dispatch bridge verifier

W5-S0 is a disjoint, read-only evidence sidecar for the existing W2.5-S0
controller. It verifies one bounded bridge:

```text
external Continue evidence
  -> W2.5 C1 dispatch intent
  -> W2.5 C2 controller lease claim
  -> W2.5 C3 spawn request
  -> external worker-claim evidence
  -> W2.5 C4 fake executor/process acknowledgement
```

It never starts a process, calls a controller method, opens a socket, writes a
database, creates a checkpoint, enters `RUNNING`, creates a receipt or starts
a following card.

## Important source boundary

The current W2.5-S0 implementation has no persisted canonical `CONTINUE`
event, no separate worker-claim entity and no public C1-C4-only entry point.
W5 therefore does not invent those semantics. `continue_intent` and
`worker_claim` are separate, HMAC-bound external evidence records. The result
labels C2 as `controller_claim` and labels the worker claim provenance as
`external-authority-only`. A future W2.5 contract may replace those records
with canonical events, but that is a separate schema/version change.

## W5-S1 source attestation and explicit BLOCKED contract

W5-S1 adds an independent local-source AND-gate through
`verify_dispatch_bridge_bundle_s1`. The pinned
`w5-w25-source-attestation.v1` contains the exact closure of the W2.5
controller, fake executor, fault injector and SQL schema. W5 reads those four
files and compares their bytes to a versioned baseline before delegating to
W5-S0. The S1 authority is a separate schema and binds both the source
closure hash and the S1 bundle schema. A source change is therefore
`INCOMPATIBLE_SOURCE` until a new source-contract version is deliberately
published.

The source closure proves which local implementation is present; it does not
prove that a compromised Authority key produced the runtime snapshot. That
remaining provenance boundary requires a future signed release, measured boot
or host/database attestation and is not silently claimed by W5-S1.

`verify_blocked_ack_bundle_s1` is a separate contract for a real pre-C4 wait,
not a mutated C4 bundle. It accepts only `Run=DISPATCHING`, `Card=CLAIMED`,
`Attempt=ADMITTED`, `Dispatch=SPAWN_REQUESTED`, exactly C0-C3 markers and the
14-event history. It requires no process identity, worker claim, process ack
or C4 marker, and carries explicit missing-evidence and idempotent-replay
records. `ACK_TIMEOUT`, `DISPATCH_UNCONFIRMED` and `RECONCILING` are not
silently folded into this first blocked contract.

The blocked observation signs the persisted ACK deadline and an observation
timestamp after the attested `SPAWN_REQUESTED` event and strictly before the
deadline. Marker rows are bound to the runtime run ID, their expected event
types and monotone event order. Its separate authority also binds the exact
blocked-bundle schema hash, so a compatible-looking payload cannot be replayed
under a different contract version.

The adapter must supply a process-startup-configured W2.5 trust root using the
shared W4 authority registry and freeze it before admitting bundles. The
authority binds the runtime projection, the ordered event chain, C0-C4 marker
commitments, Continue, worker claim, process acknowledgement and replay
evidence. It also binds executor identity and fencing epoch. The bundle must
carry the raw W2.5 SQL projections before and after every C0-C4 marker. W5
recomputes every marker state hash, requires adjacent phase projections to be
identical at their shared boundary, and requires the C4-after projection to
equal the final runtime snapshot. The authority separately binds that complete
state-witness set.

## Accepted boundary

The only verified terminal state is:

```text
Run       = DISPATCHING
Card      = CLAIMED
Attempt   = STARTING
Dispatch  = EXECUTOR_ACKED
```

No C5 or later event, checkpoint, receipt, review, acceptance transaction,
next-card intent or `Card.DONE` state is accepted. The fake executor identity
is reconstructed from the existing W2.5 deterministic formula, not merely
copied from input. The acknowledgement must be strictly before its persisted
deadline and within the W2.5 60-second admission window. W5-S0 deliberately
targets the default W2.5 fake-executor source contract
(`fake-boot-w25-s0`); a controller configured with another boot ID is
incompatible until a separately versioned source contract binds that setting.

The replay proof contains two actual test-adapter Continue invocations and
captures spawn/ack counts before and after the second invocation. It proves
one persisted dispatch and one fake spawn request for this sidecar contract;
it is not a claim that a production public Continue API already exists.

W5-S0 statuses are:

```text
BRIDGE_VERIFIED
INCOMPATIBLE_SOURCE
INVALID_EVIDENCE
```

`BRIDGE_VERIFIED` is evidence only. It never means process authorization,
acceptance or next-card permission.

Only the separate W5-S1 `verify_blocked_ack_bundle_s1` API returns `BLOCKED`,
and only after the complete C0-C3 blocked-ack contract has been verified.

## W5-S2: bounded Mother observation

The next layer is deliberately only a projection boundary. After a caller has
verified a W5-S1 `DispatchBridgeResult`, `build_mother_observation()` can
produce the strict `w5-local-mother-observation-v1` record. It contains the
bound run/card/attempt/dispatch identity, the one W5 state, findings and the
source-attestation hash. The serialized record is accepted only with
`permission=read_only`, `acceptance_status=pending`, `external_action=false`
and all four execution flags set to `false`.

`BRIDGE_VERIFIED` requires the source-attested W5 bridge shape, including the
source hash bound to the current W5-S1 source-attestation contract; a W5-S0
result without that hash cannot be projected as Mother context. Object input
accepts only the concrete `DispatchBridgeResult` type and reads its fields
directly; serialized Mapping input must pass the same exact result schema, so
an arbitrary object method cannot become an execution hook.
`BLOCKED` requires exactly `ACK_NOT_CONFIRMED` and the exact pre-C4 state. An
incompatible or invalid result carries no identity, state or source hash. Any
unknown field, state drift, C4/process-ack contamination, source-contract
hash drift or attempt to enable an execution flag is rejected.

The local Mother session may read an optional `w5-observation.json` from the
current run together with the matching `w5-result.json` snapshot and display
it in `cockpit.md` as background evidence. The reader recomputes the
projection from that exact result and rechecks the pinned W5 source closure
against the Prime tree. This is a consistency/provenance chain for the local
handoff, not a cryptographic replacement for W5-S1's authority evidence. It is never
added to the task binding, queue selection, resume gate or status transition.
The reader rejects symlinks, paths outside the managed runs root, oversized
files and unpinned loader/source files. No W5-S2 code starts a
worker, changes the controller, writes a queue/state store or authorizes the
next card; a later resume/reconciliation contract must be designed and tested
separately.

## W5-S3: evidence-gated HOLD/RECONCILE/RESUME decision

`evaluate_hrr()` is the next, still read-only boundary. It accepts the raw,
source-attested W5-S1 bundle and authority again, the exact W5-S2 observation,
an independently captured control snapshot and an optional observed process
identity. It rejects an observation-only input: the S2 projection is context,
not a runtime authority.

The control snapshot binds the run/card/attempt/dispatch identities, queue and
policy hashes, command and run tokens, lease owner/token/epoch/deadline,
single-spawn budget, process identity and a hash of the complete live runtime
projection. The gate checks these bindings against the authenticated W5
runtime before classifying the result:

```text
BLOCKED + ACK window open + no identity       → HOLD
BLOCKED + deadline reached / lease expired    → HOLD
BLOCKED + exact candidate before deadline    → RECONCILE
BRIDGE_VERIFIED + exact live C4 + live lease → RESUME
any drift, invalid evidence or stale fence   → HOLD
```

`RESUME` is only a decision for a later, separately implemented action. The
decision record is `w5-hrr-decision-v1`, always `permission=read_only`,
`external_action=false`, with mutation, spawn, lease-reclaim, acceptance,
next-card and network flags all set to `false`. The gate does not call
`reconcile_dispatch()`, the executor, `prime_reconcile_run.sh` or any other
mutating path. A future adapter may place this gate before
`prime_codex_resume_guard.sh`, but that integration is intentionally not part
of W5-S3. The control snapshot's `spawn_requested_at_epoch` is recomputed
against the authenticated `SPAWN_REQUESTED.created_at` event. A caller can
also pass the fresh HRR input to `verify_hrr_decision(..., input_value=...)`;
the decision is then recomputed instead of being trusted as stored JSON.

## W5-S4: Prime binding and coherent read-only capture

`evaluate_prime_binding_from_control_plane()` is the first Prime-facing
adapter, but it is still actionless. It captures the file-backed ControlPlane
through one SQLite `mode=ro`, `query_only` transaction and binds the runtime
projection to the current runtime anchor, append-only anchor-history tail,
marker commitments, integrity result and a trusted control-plane clock sample.
The normal `ControlPlane.snapshot()` method remains a useful diagnostic view;
it is not treated as an atomic authority source by S4.

The fresh Prime state uses `prime-resume-state-v1` and must contain the Prime
run, active task, deterministic Prime↔W5 `binding_id`, status, `next_action`,
resume gate and the byte-SHA-256 values for the resume packet, session, tasks,
queue, policy and writer lease. A `continue` gate is accepted only when the
Prime status is `in_progress`, the next action is exactly `continue` for the
same active task, all stop/hold reasons are empty and the W5 identity matches.
The binding also requires the HRR input and freshly recomputed decision hash,
control snapshot hash, source-attestation hash and fence.

The result is `w5-hrr-prime-binding-v1`:

```text
W5 HOLD          → HOLD
W5 RECONCILE     → BOUND_READ_ONLY only as evidence; no reconcile action
W5 RESUME + all Prime bindings exact → BOUND_READ_ONLY
any capture, clock, hash, identity, gate or schema drift → HOLD
```

`BOUND_READ_ONLY` is deliberately not an authorization token. Every result
has `permission=read_only`, `external_action=false` and false flags for
resume, reconcile, mutation and network. `verify_prime_binding()` is only a
shape/semantic validator without fresh inputs; authority use requires the
Prime state, HRR input and coherent control capture to be supplied again.
The adapter never calls `reconcile_dispatch()`, lease reclaim, `codex resume`,
the Prime resume guard, a process API or a transport. A later mutating
consume/CAS contract must re-read the same fence, anchor, dispatch revision,
lease and Prime hashes inside one exclusive transaction.

The current boundary is explicit: the Prime file reader, signed Prime
authority/MAC, host process identity and an atomic cross-filesystem
Prime↔SQLite capture are not silently simulated by self-asserted JSON. S4
accepts only a validated Prime snapshot and records those remaining provenance
requirements for the next layer.

## W5-S5: real Prime filesystem evidence

`capture_prime_evidence()` reads the canonical Prime ledgers into the
independent `prime-filesystem-evidence-v1` contract. The required source set is
the explicit run directory's `session_state.json`, `tasks.json`, `events.jsonl`
and `artifacts.jsonl`; queue, active card, policy manifest, writer lease and
resume packet are optional sidecars and are reported as missing when they are
not present. The moving `latest` pointer is never used as an authority.

Every source is opened through directory file descriptors with `O_NOFOLLOW`,
read twice, bounded by a byte limit and checked for device/inode/mode/size/
mtime/ctime drift. The complete source set is read again before finalization.
JSON rejects duplicate keys and non-finite constants. Artifact paths are
checked against the selected run, but artifact contents are not recursively
read or accepted. No lock, packet, event, process or network operation is
performed.

The capture exposes `root_binding_sha256`, raw-byte file hashes,
`source_set_sha256`, ledger high-watermark checks and a sanitized binding
projection. `build_prime_state_from_capture()` is a separate gate: it can
create the S4 `prime-resume-state-v1` mapping only when all required optional
proofs are present and the capture hash recomputes exactly. Missing or
contradictory evidence remains ineligible; it is never filled with a guessed
hash. `evaluate_prime_binding_from_prime_evidence()` then performs this
projection and the existing fresh S3 HRR evaluation, still with no action
flags.

The result is stable evidence, not an atomic cross-filesystem snapshot and not
a resume authorization. A cooperative writer-generation or fenced consume
contract remains necessary for a later mutating layer.

## W5-S6: cooperative writer snapshot manifest

`capture_prime_evidence_v2()` is an explicit opt-in extension. It keeps the
W5-S5 v1 contract unchanged and additionally requires the canonical
`runtime/runs/<run_id>/writer/snapshot-manifest.json` sidecar with schema
`prime-writer-manifest-v1`. The manifest is published last by a cooperating
writer and covers exactly the four canonical run ledgers. Its source entries
bind raw SHA-256, size, device/inode/mode and timestamps; the aggregate
`covered_source_set_sha256` intentionally hashes only logical name, relative
path, presence, size and raw SHA-256.

The v2 reader rechecks the S5 capture before and after the manifest, reads the
manifest through the same no-follow bounded reader, rejects duplicate keys,
root/run/source mismatches and manifest or ledger drift, and reports
`MATCHED`, `SOURCE_SET_MISMATCH` or a structured failure. The manifest itself
is not part of its covered source set. A `generation` number is required to
be positive but is not treated as historically monotonic: a single read-only
observer cannot prove replay or downgrade without an external anchor.

`writer_snapshot.trusted` is always `false` and its attestation is explicitly
`UNTRUSTED_SELF_ATTESTATION`. Therefore
`evaluate_prime_binding_from_prime_evidence_v2()` can never turn this manifest
into a resume authorization; even a hypothetical `resume_allowed=true` from
the existing evaluator is downgraded to an actionless HOLD. The v2 builder
projects into the unchanged S4 state shape only for a matched consistency
witness and may optionally require an explicit expected Prime run ID. No
writer, lock, process, network, Resume, Reconcile or CAS operation is called.

The next missing authority is consequently external: a signed/attested writer
anchor and, separately, a fenced mutating Consume/CAS transaction. W5-S6
does not claim either one.

## W5-S7: externally anchored writer evidence

`verify_prime_external_anchor()` adds a separate, opt-in
`prime-writer-anchor-v1` contract. The anchor is supplied by an external
caller; it is never loaded from the Prime run or generated by the reader. Its
payload binds the V2 evidence schema, complete capture hash, run/path, root
binding, writer generation/generation ID and covered source-set hash.

The anchor uses a host-configured, separately scoped HMAC trust root
(`prime-anchor-*`). Configuration is startup-only and must be frozen before
untrusted anchor data is admitted. The anchor cannot register or replace its
own key. This is an external MAC attestation, not proof of writer process
identity and not a public-key signature; a later deployment may replace the
trust mechanism with a public-key registry without changing S6.

The verifier requires an externally maintained `last_accepted_generation`.
Without that monotonic observation, a valid MAC remains replayable and the
result is `HOLD` with `PRIME_ANCHOR_REPLAY_UNPROVEN`. A valid, newer and
semantically matching anchor is reported as `MATCHED_CURRENT`, but still has
`permission=read_only`, `resume_allowed=false` and all execution flags false.
The existing Control-Plane `runtime_anchor` remains only control context: it
does not attest Prime ledgers or writer identity.

`evaluate_prime_external_anchor()` converts every malformed, unknown-key,
signature, binding, replay or missing-anchor case into an actionless `HOLD`.
The V2 `writer_snapshot.trusted=false` value is never changed by this
verifier, and no Resume, Reconcile, write, lock, process, network or CAS path
is introduced. A future fenced Consume/CAS contract must remain a separate
versioned authority layer.

## W5-S8: externally headed CAS precondition evidence

`verify_prime_writer_head()` is the next separate, opt-in boundary:
`prime-writer-head-v1` is an externally supplied signed head, while
`prime-writer-head-verification-v1` is the read-only result. S8 re-verifies the
S7 anchor at its boundary, requires an explicit Prime run, W5
run/card/attempt/dispatch identity and an independently supplied current-head
observation. A signed object that is merely newer than a caller-supplied
integer is not enough.

The head payload binds the S7 anchor hash, Prime V2 snapshot, root and generation,
Prime queue/policy/active-card/resume-packet/writer-lease bytes, the full W5
runtime/projection/capture hashes, W5 queue/policy/card references, and the
W5 lease claim, owner, expiry and fencing epoch. W5 queue/policy/card values
remain opaque controller-owned references from S3/S4 and are compared exactly;
they are not silently retyped as Prime SHA-256 values.

The S8 trust root is separately scoped as `prime-head-*` and frozen before
untrusted head input is admitted. A monotone external head sequence must be
the immediate successor of the accepted sequence and its parent hash must
match. Missing/current-head mismatch, generation replay, parent/fence/queue/
lease drift, expired lease, unknown key, duplicate JSON key or any schema
uncertainty becomes `HOLD`. A valid result is
`PRECONDITION_SATISFIED_READ_ONLY`, not a capability: `consume_allowed`,
`cas_authorized`, `resume_allowed` and every execution flag remain `false`.

The verifier never persists replay state, opens a lock, performs a CAS,
consumes a card, resumes or reconciles a run, writes a file, controls a
process or uses a network. The external replay state must later be advanced
atomically by a separate authoritative Consume/CAS transaction; S8 cannot
claim that atomicity on its own.

## W5-S9: read-only Consume/CAS preparation

`build_prime_consume_plan()` and `verify_prime_consume_plan()` add the
separate `prime-consume-preconditions-v1` and
`prime-consume-preconditions-verification-v1` contracts. S9 is explicitly a
`precondition_bundle_only`: it binds the fresh S8 head to Prime identity,
Replay-Parent and accepted replay state, Prime sidecar hashes, W5 runtime /
projection / capture, opaque Queue-/Policy-/Card- and dispatch references,
lease/fence, receipt/marker observations and the exact Card-/Attempt-/Dispatch
versions.

The plan carries machine-checkable safety markers:
`requires_commit_recheck=true`, `requires_queue_journal_recheck=true`,
`queue_journal_observed=false`, `reservation=false`, `lock_held=false`,
`mutation_performed=false` and `cross_store_atomicity=not_claimed`. A later
consumer must therefore re-read the queue journal, Prime writer state,
Replay-State, lease, fence and both stores inside its own atomic transaction;
S9 does not reserve anything and cannot authorize that transaction.

The inputs are isolated before S8 and a second copy is used for derivation,
so a caller- or verifier-side mutation cannot silently mix two observations.
This is a bounded pure-input consistency measure, not a claim of filesystem or
cross-store atomicity. S8 safety flags are checked in full, duplicate JSON
keys and exact schemas are enforced, and every failed path is actionless
`HOLD`. No DB, lock, journal, process, network, Resume, Reconcile, Consume or
CAS operation is called.

W5-S10 is now a separate participant/coordinator preview boundary. It does
not discover state itself: the caller supplies four read-only observations for
the Prime queue journal, Prime ledger transaction journal, W5 ControlPlane
transaction state and receipt/marker projection. The preview runs S9 freshly,
checks every participant's exact `before` projection against S9's expected
Prime head, anchor, root, task, run and sidecar values, W5 runtime/projection/capture,
lease claim/owner/expiry/fencing, receipt/marker hashes and Card/Attempt/
Dispatch versions, and binds the normalized observations through an explicit
`participant_observations_sha256`.

Each observation must report a clean, closed journal and explicit read-only
safety markers. `OPEN`, `DRIFT`, `RECOVERY_REQUIRED`, malformed or
unobservable journals become actionless `HOLD`; this layer never calls queue
recovery, Prime recovery, a ControlPlane transaction, a lock, a receipt writer,
Resume, Reconcile, Consume, CAS, process or network code. A positive result is
only `PARTICIPANT_PREVIEW_ONLY_READ_ONLY` with
`coordinator_state=PREPARED` and `required_next_state=COMMIT_RECHECK_REQUIRED`.
It claims no effect, reservation, idempotency slot, lock, mutation or
cross-store atomicity. The future authoritative coordinator must re-read all
participants, lease/fence, queue journal and receipt/marker state atomically;
S10 remains backward-compatible and does not promote S9 into write authority.

The next layer is intentionally still open: W5-S11 must design the
authoritative transaction/executor, idempotent receipt/marker commit and
`IN_DOUBT`/`RECOVERY_REQUIRED` handling as a new contract.

## W5-S10: read-only participant/coordinator preview

The separately versioned contracts are
`prime-transaction-participant-preview-v1` and
`prime-transaction-participant-preview-verification-v1`. S10 consumes caller-
supplied observations only and deliberately avoids the existing helpers that
acquire queue/ledger locks, write recovery markers or open ControlPlane
`BEGIN IMMEDIATE` transactions. The four participants are exact and cannot be
silently omitted or replaced.

The positive result is deterministic and explicitly deferred:
`PARTICIPANT_PREVIEW_ONLY_READ_ONLY`, `PREPARED`,
`COMMIT_RECHECK_REQUIRED`, `atomic_commit_required=true`, all participant /
queue-journal / lease / fencing / receipt rechecks required, and
`transaction_authority=DEFERRED_TO_ATOMIC_COORDINATOR`. It includes the S9
verification hash, plan hash, participant-observation hash and a deterministic
preview ID. `authoritative_prepared`, `idempotency_reserved`,
`mutation_window_open`, `consume_allowed` and `cas_authorized` remain false.

The evaluator fails closed with actionless `HOLD` for schema drift, duplicate
JSON keys, stale S9 evidence, participant drift, lease/fencing or receipt /
marker drift, unsafe safety flags and every non-clean/open/recovery journal.
No automatic repair is attempted: recovery is a future coordinator decision,
not a side effect of preview. S10 is therefore an additive compatibility layer
over S9, not the missing atomic executor.

## W5-S11: read-only authoritative contract v2

S11 adds `prime_transaction_authority.py` as a pure contract boundary after
S10. It binds the full semantic subject chain, repository/evidence
provenance, Knowledge-Ledger head, ContextPack loss/reconstruction, long-run
budget/heartbeat/checkpoint gates, P1 review/scheduler identity and the
zero-child/no-parallel P0/P1 boundary. The fifth `knowledge_ledger`
participant is intentionally distinct from the technical `prime_ledger`.

`verify_authoritative_transaction_contract()` returns only
`CONTRACT_VALIDATED_READ_ONLY`; `classify_authoritative_recovery()` returns a
classification, never a recovery action. The evaluator fails closed for
schema errors, context/provenance loss, stale fencing, effect/generation/
parent mismatch, P2 admission, P0 Acceptance and `PRIME_CONSUME`. No SQLite,
filesystem, lock, process, network, CAS, Consume, Resume or Reconcile path is
called.

Recovery is bound to the concrete contract: expected/observed contract,
subject, plan, participant, effect and marker digests plus the complete
before/after projections must match before `COMMITTED_PROVEN` is returned.
That label is only `COMMIT_EVIDENCE_SUFFICIENT_READ_ONLY`; it is never
authority. The effect policy excludes `knowledge_ledger` mutation, and
disabled P2 admission requires zero children, zero parallelism, depth zero and
zero cost/utility metadata.

## W5-S12: read-only Cross-Store fixture harness

`cross_store_fixture.py` adds the separately versioned
`prime-cross-store-fixture-v2` / `prime-cross-store-fixture-verification-v2`
boundary. It consumes isolated synthetic participant snapshots and a
canonical T0–T5 hook prefix. State-/Journal-material is bound to its hashes;
Before-/After projections bind monotone versions, generations, generation IDs
and parent hashes; the complete effect set covers all five participants; the
Lease/Fence uses a deterministic observation time; and each hook has a
parent/event digest chain.

Die Hook-After-State-Masken sind pro T-Level eingefroren; ein zu früher
All-After-Zustand kann nicht durch eine neu berechnete Event-Kette grün
werden. Das Fixture bindet zusätzlich die S11-v2-Contract-Rolle,
`PRIME_PROJECTION`/`project_queue`, Provenienz-/Context-Gates, die deaktivierte
P2-/Acceptance-Grenze und die nichtmutierende Knowledge-Ledger-Operation
`observe`. Ein unvollständiger Prefix erhält `PENDING`; `COMMITTED` ist nur
nach `T5.after_final_marker` zulässig.

`build_cross_store_hook_trace()` and `inject_cross_store_fault()` are fixture
helpers only. They do not execute a fault, acquire a lock, call recovery or
touch a live store. `classify_cross_store_fixture()` returns only
`PREPARED`, `COMMITTED`, `IN_DOUBT` (with `PROJECTION_PENDING` for the
SQLite-after/Prime-before split) or `RECOVERY_REQUIRED`. Malformed inputs are
actionless `HOLD`. Even `COMMITTED` is only internally consistent,
`READ_ONLY_CLASSIFICATION` evidence; no live-store truth, cross-store
atomicity, idempotency registry or mutation authority is implied.

The S12 tests cover the complete T0–T5 matrix, digest/material forgery,
effect-set omission, Lease/Fence and ABA drift, duplicate JSON and input
isolation. The next layer is an independently fenced read-only adapter for
live snapshots, not a hidden executor.

## W5-S13: read-only frozen-snapshot adapter

`cross_store_snapshot.py` adds the separate
`prime-cross-store-observation-v1` / `prime-cross-store-adapter-verification-v1`
boundary. It accepts only an already frozen caller-supplied envelope; it does
not read SQLite, Queue, Prime, Receipt or Marker sources itself.

The adapter binds an observer instance, five unique source identities, one
ten-event before/after capture cohort, source cursors to version/generation/
generation-id/journal content, two identical samples per participant, a
projection manifest, the complete S11-v2 contract, an independent worker
fence, a deterministic S12 lease and a conflict-free replay/idempotency
observation. It then projects the isolated observations into the S12 fixture
classifier.

The positive adapter status is only `ADAPTED_READ_ONLY` with
`BOUNDED_FROZEN_SNAPSHOT`; the S12 result remains separate as
`classification_status`. Source/TOCTOU/capture/fence/lease conflicts become
actionless `RECOVERY_REQUIRED`, while schema, duplicate-key and unsafe inputs
become `HOLD`. Mutation, lock, reservation, process, network, Resume,
Reconcile, Consume and CAS remain unavailable. S13 proves neither live-store
truth nor cross-store atomicity.

## Non-goals

- no change to W2.5/W0/W3 or dirty Prime files;
- no real worker, process, network or local-model access;
- no hidden Continue/worker-claim event invention;
- no multi-card loop, retry, review or self-accept;
- no claim that external worker evidence is canonical before W2.5 exposes it.
- no automatic Resume/Reconcile action; W5-S3 only classifies evidence.
- no claim that `BOUND_READ_ONLY` authorizes a later Prime action;
- no cross-filesystem atomicity or signed Prime-host attestation in S4.

## W5-S14: read-only source-capture producer

`cross_store_capture.py` is the orchestration boundary between explicit
source adapters and the S13 frozen-snapshot envelope. It accepts exactly five
caller-supplied readers (`control_plane`, `knowledge_ledger`, `prime_ledger`,
`prime_queue`, `receipt_projection`), requires an exact read-only capability
profile, calls every reader twice and compares identity, cursor, generation
and projection.

An injected read-only Clock and Cohort are observed before and after the two
passes. The Cohort binds a Fence, an S12 Lease and a per-participant
Generation/Generation-ID vector. Clock, Source, TOCTOU, Generation, Lease and
Fence drift fail closed; no retry or recovery is performed. S13 recovery
codes are preserved as `RECOVERY_REQUIRED`, while schema/unsafe/unobservable
cases remain `HOLD`.

S14 uses the public `build_cross_store_snapshot_envelope()` and passes both
actual sample passes through it. The builder validates Sample A/B equality and
then calls the complete S13 adapter, so S14 does not duplicate the S13 digest
formulas. A success is only `CAPTURED_READ_ONLY`; all execution, mutation,
resume, consume, CAS and authority flags remain false.

The module itself performs no file, database, process or transport I/O. The
capability profile and injected callbacks are a declarative boundary, not an
external attestation. Concrete source adapters still need separate Root-/Run-
/WAL-/Writer-/Host-proof, especially for Queue, Knowledge-Ledger and Receipt
Projection. S14 does not claim Cross-Store-Atomizität, ABA protection or live
truth and does not implement a W6/P1 executor.

## W5-S15: immutable source-profile and attestation gate

`cross_store_attestation.py` adds the separate
`prime-cross-store-source-attestation-v1` boundary in front of S14. It accepts
only the exact five S13/S14 participants and validates a frozen profile for
each adapter. The profile binds adapter version, source identity, root/binding
digest, adapter-code digest, cursor schema, frozen-snapshot mode and strict
boolean read-only capabilities.

The caller-supplied registry cannot provide its own trust key. A separately
configured and startup-frozen `source-attestation-*` HMAC root authenticates a
canonical attestation that binds transaction, observer, registry,
profile/source sets, capture context and the shared clock/generation/
lease/fence cohort. A `prime-cross-store-source-authorization-v1` core and
`authorization_sha256` make the validated provenance auditable and isolated.

`evaluate_attested_cross_store_capture()` invokes S14 only after this complete
preflight. Invalid MACs, unknown or unfrozen trust roots, profile/capability
drift, binding drift and schema uncertainty return actionless `HOLD` without a
reader callback. A later S14/S13 TOCTOU or cohort drift remains
`RECOVERY_REQUIRED`; S15 never performs recovery itself.

The module performs no source/file/database/queue/Prime I/O, process control,
network operation or mutation. The HMAC is only external MAC evidence, not
host/writer/callback identity proof. Persistent replay/nonce state, isolated
adapter workers, host attestation and cross-store atomicity remain future
contracts. Direct S14 calls remain low-level test/orchestration APIs; the
attested entrypoint is `evaluate_attested_cross_store_capture()`.

## W5-S16: immutable worker/host/replay gate

`cross_store_worker_attestation.py` is the read-only boundary after S15. It
accepts five already-serialised worker envelopes, one separately signed
host/runtime envelope, one replay-head observation and one separately signed
replay floor with its own trust root. Worker, host/runtime and replay/floor
trust scopes are distinct and frozen before verification. All claims share a
canonical transaction, observer, S15-authorization, profile/source/cohort,
host, nonce and worker-epoch binding.

The host envelope independently binds a strict read-only host policy and one
runtime binding for each of the five participants. Worker claims must match
those runtime IDs, binding digests and capability booleans. The replay floor
is checked for scope, parent, sequence, nonce and registry/worker-epoch
monotonicity; S16 never advances it. The result is
`EXTERNALLY_CHECKED_NOT_ADVANCED`, never a replay-protection or consume token.

Before S15 is called, serialised evidence and static S15 mappings are copied.
Only the five S14 readers, clock and cohort remain explicit callback
references; S14 performs the second observation and TOCTOU classification.
Invalid preflight is actionless `HOLD`; a later S14/S13 drift can remain
`RECOVERY_REQUIRED`. The module performs no source/file/database/queue/
Prime I/O, lock, recovery, CAS, consume, process or network action. A valid
MAC is external evidence, not host/kernel/TPM or worker-isolation proof.

## W5-S17: read-only replay/registry owner preflight

`cross_store_owner.py` verifies S16 again and then accepts one separately
authenticated `prime-cross-store-replay-owner-observation-v1` under the
independent `source-replay-owner-*` trust scope. The owner observation binds
owner instance, state version, owner/fencing epoch, current head, registry and
profile/source/cohort/host scope, journal state and an idempotency-index hash.
The owner head and observation digest are recomputed from normalized content.

The module derives a candidate for a future owner transaction: expected state
version, parent owner head, exact next sequence, worker-set digest, nonce,
registry scope, fencing epoch and S16 provenance. Caller input cannot inject a
target head or target sequence. The only positive status is
`OWNER_PREVIEW_ONLY` with `CAS_RECHECK_REQUIRED` and
`OWNER_OBSERVED_NOT_ADVANCED`.

S17 does not reserve an idempotency key, perform CAS/Consume, emit a receipt,
prove a commit or execute recovery. An open/active owner journal is only
reported as `RECOVERY_REQUIRED`. `REPLAYED`, `CONFLICT`, full nonce history and
the real persistent owner belong to separate later cards; all action and
authority flags remain false.
