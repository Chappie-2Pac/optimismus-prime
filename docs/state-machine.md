# State and authority model

SQLite is the authoritative runtime state for the public control-plane slice. Files such as `QUEUE.json` may be imported or projected, but they do not silently compete with the control plane as a second runtime truth.

## Dispatch sequence

```text
DISPATCH_INTENDED
  -> CLAIMED
  -> SPAWN_REQUESTED
  -> EXECUTOR_ACKED
  -> RUNNING
  -> EXIT_REPORTED
  -> COMPLETED
```

`COMPLETED` describes transport completion. It is not an acceptance decision.

## Attempt and review sequence

```text
CREATED -> ADMITTED -> STARTING -> RUNNING
  -> SUBMITTED -> EVIDENCE_VERIFIED -> REVIEW_PENDING
  -> ACCEPTED | REJECTED | RETRYABLE | BLOCKED
```

Only a valid review and acceptance transaction may mark a card as done. The public P0-style contracts deliberately stop at evidence verification where acceptance authority is not present.

## Recovery

An interrupted transaction is classified from durable markers and the current queue hash:

- current state equals the prepared `after` hash: recover as committed;
- current state equals the original `before` hash: abort without replay;
- neither hash matches: require manual recovery and preserve evidence.

No recovery path overwrites unexplained drift.
