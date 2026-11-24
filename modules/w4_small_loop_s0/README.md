# W4-S0: bounded small-loop verifier

W4-S0 is a disjoint, read-only evidence sidecar for one W2.5-S0 card. It
does not extend the SQLite controller, run a worker, access a model, read a
run directory, open a circuit gate, write a checkpoint, accept a review, set
`Card.DONE`, create `AcceptanceTxn.COMMITTED`, or create `next_card_intent`.

The entry point is:

```python
from modules.w4_small_loop_s0 import configure_trusted_authority, freeze_trusted_authorities, verify_small_loop_bundle

# Trusted startup/configuration, before untrusted bundles are admitted.
configure_trusted_authority(
    authority_id="w25-authority-production",
    key_id="w25-key-2026-01",
    key=trusted_w25_authority_key,
)
freeze_trusted_authorities()
result = verify_small_loop_bundle(bundle, authority=sealed_w25_authority)
```

The result is one of:

```text
READY_FOR_REVIEW
BLOCKED
INCOMPATIBLE_SOURCE
INVALID_EVIDENCE
```

## Contract

The bundle is explicitly sealed by its adapter and contains:

- a W2.5-S0 runtime projection with exactly one run/card/attempt/dispatch;
- the W2.5 execution and validation receipts;
- the W2.5 artifact manifest and artifact provenance rows;
- a W2.5 checkpoint plus a state witness allowing exact reconstruction of
  `canonical_attempt_state_hash`;
- a W4 loop policy with an admission budget, fixed failure thresholds and a
  budget epoch;
- an explicit `w4-tool-trace.v1` with run/attempt/capability/policy/budget
  bindings;
- a progress-history trace whose signatures use the exact W2.5 formula;
- a separate reviewer identity, session, backend and criteria list.

The separately supplied `sealed_w25_authority` and the process-startup trust
root are mandatory. `configure_trusted_authority` is called by deployment
code, followed by the one-way `freeze_trusted_authorities()` barrier, not by
the bundle adapter; a different reconfiguration is rejected and verification
before the freeze is rejected. The per-invocation verifier accepts no key
argument. The authority carries a
canonical SHA-256 commitment plus an HMAC-SHA-256 authentication tag; a
self-consistent runtime dictionary or a freely recomputed hash is not an
authority root. The authenticated authority binds the admitted budget and
epoch, immutable W2.5 marker commitments, the complete ordered event-chain
commitment, the canonical W4 tool-trace hash, the `ATTEMPT_RUNNING`
checkpoint state, the final `ATTEMPT_EVIDENCE_VERIFIED` state, the validation
receipt, the executor identity and the independent review domain. Without the
sealed authority or configured trust root the verifier returns
`INVALID_EVIDENCE`.

W2.5 identity values such as `queue_hash` and `card_hash` remain opaque
bindings; W4 does not silently reinterpret them as raw-file hashes. Derived
`canonical_state_hash`, `receipt_body_hash`, `progress_signature`,
`receipt_hash`, checkpoint hashes and policy hashes are reconstructed as
lowercase SHA-256 values using W2.5's canonical JSON rules.

The progress signature is exactly:

```text
(card_id, attempt_id, attempt_no=1, canonical_state_hash,
 artifact_hashes, validation_result, receipt_body_hash, next_state)
```

Logs, timestamps and token text are not progress. Repeated signatures can only
lead to `NO_PROGRESS`/`BLOCKED`; they cannot be projected as success.

The tool circuit is a pure trace verifier. It enforces two identical
`(command_sha256, error_class)` failures or six consecutive failures as the
immutable W4 thresholds, requires the matching gate evidence, and rejects any
call after the gate. A valid open circuit returns `BLOCKED`; missing or forged
gate evidence returns `INVALID_EVIDENCE`.

Review preparation is a pending handoff packet with `self_accept=false` and a
new W4-local `prep_id`. It is not a W2.5 `review_id`, contains no acceptance
decision, and requires a distinct reviewer identity/session from the worker.

## Non-goals

- no `ki --doctor` or `ki --quit` integration;
- no worker dispatch, process supervision or local-model communication;
- no retry creation, multi-card loop or autonomous replanning;
- no claims that a hash proves the truth of source content;
- no protection against a same-user attacker deliberately replacing all input
  evidence outside the sealed-bundle boundary or compromising the process
  trust-root configuration.

