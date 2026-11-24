# W2.5-S0 isolated mother control plane

This directory is a disjoint proof harness. It does not replace or modify
Prime's existing shell runtime.

The harness provides:

- a self-contained SQLite W0 entity schema;
- explicit Project, Run, Card, Attempt, Dispatch, Receipt, Review and
  AcceptanceTxn state records;
- a deterministic in-memory fake executor with no process, socket, port,
  `/proc`, model-server or network access;
- six injectable hooks at every C0--C11 commit point;
- deterministic receipt-body, progress and final receipt hash reconstruction;
- idempotent replay, Ack reconciliation, lease reclaim and fencing checks;
- a fail-closed P0 boundary: the proof ends at `Receipt.VERIFIED` and
  `Attempt.EVIDENCE_VERIFIED`, with `Card.SUBMITTED` and `Run.VERIFYING`.
  Review/Acceptance records are only disabled/prepared evidence;
  `Card.DONE`, committed AcceptanceTxn and `next_card_intent` remain
  unreachable.

Run the isolated acceptance suite from the repository root:

```text
python3 -m unittest tests.test_w25_single_card
```

The suite covers the complete 72-case matrix (`C0..C11` × six hooks), two
recovery replays per case, deterministic hashes, identity/fencing negatives,
and the no-real-worker boundary.
