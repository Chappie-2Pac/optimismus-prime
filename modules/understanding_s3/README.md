# W3-S3: semantic context binding

W3-S2 proves that a sealed event stream is internally ordered and bound to a
scope. W3-S3 adds the semantic edge to the source manifests without changing
W3-S0, W3-S1 or W3-S2.

`verify_contextual_stream_bundle` requires:

- one valid W3-S2 `EventStreamArtifact`;
- one valid `ScopeArtifact` and the corresponding profile/source context;
- a live `UnderstandingRegistry` passed as `authority=`; without it the
  result is never authoritative;
- a profile with exactly the selected source in `source_ids`; W3-S3 v1
  rejects multi-source profiles rather than misusing W3-S1's single-source
  verifier contract;
- a manifest catalog whose hashes are exactly the hashes referenced by the
  stream, with no duplicate, missing or unreferenced manifest;

Manifest order is intentionally irrelevant: hashes are the stable catalog
keys. Reusing one identical manifest hash for multiple events is allowed and
explicitly verified; each event is still checked independently. A future
one-to-one scan/manifest policy would be a separate schema version.

For every original S2 event, the verifier creates a non-mutating temporary
singleton projection with `sequence_no=1` and no predecessor. The projected
event hash is recomputed solely for the existing W3-S1 `verify_bundle` API.
The original event hash, sequence, predecessor and stream chain remain
verified independently by W3-S2. This avoids silently weakening either
contract.

The module is read-only: it starts no process, uses no network, writes no
receipt and does not materialize a second source of truth. It is a semantic
verifier sidecar; later waves can build a claims/gap ledger from its findings.
Supporting a complete multi-source registry catalog is intentionally reserved
for a later schema version with a dedicated source-catalog verifier.
