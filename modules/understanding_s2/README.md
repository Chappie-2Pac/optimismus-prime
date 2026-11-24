# W3-S2: self-describing evidence

W3-S0 scans an approved source read-only and emits a `scope_hash` inside a
manifest/event. W3-S1 verifies a caller-supplied scope and can check a
singleton event stream. W3-S2 adds the missing evidence container without
changing either earlier wave.

## Scope artifact

`ScopeArtifact` contains the exact W3-S0 `scan-scope.v1` object, its
`scope_hash`, and explicit registry provenance:

- project/source identity;
- `path_policy_hash` and `registry_snapshot_hash`;
- registered source relative root, device, and inode.

`artifact_hash` covers the complete envelope except its own hash. The old
`scope_hash` therefore remains compatible with W3-S1 while the new artifact
is independently self-describing. A positive authoritative result from
`verify_scope_artifact` requires canonical hashes, schema, the recomputed
path policy, and a valid profile/source binding. An explicit
`integrity_only=True` result is available for hash inspection, but is not an
authority or promotion decision. When available, passing the live
`UnderstandingRegistry` as `authority=` compares the supplied records with
the registry's in-memory project/source records before verification; this is
stronger than accepting a self-consistent caller-supplied dictionary.

## Event stream

`EventStreamBuilder` only permits append operations. It requires sequence
`1, 2, ...`, an exact predecessor hash, unique event hashes and unique
`scan_id` values. Every member must remain bound to one project, source,
registry snapshot and scope hash. The sealed `EventStreamArtifact` commits
the ordered events, count, head hash, state and stream hash.

This wrapper verifies the stream contract and capability/hash invariants of
each `scan-event.v1`. It does not pretend that an event's manifest is
semantically re-verified without the corresponding profile, source, manifest
and explicit scope bundle; that remains the W3-S1 `verify_event`/`verify_bundle`
responsibility.

## Output boundary

`ScopeArtifactStore` writes only to `scopes/<scope_hash>.json` and
`EventStreamStore` writes only to
`streams/<stream_id>/<stream_hash>.json`. Both hold an `O_NOFOLLOW` root FD,
reject protected roots and symlinks, use bounded reads, and publish complete
bytes from an anonymous `O_TMPFILE` inode through an FD-bound `linkat`
commit. Existing identical bytes are idempotent; different bytes are a
conflict. Reads re-verify the requested filename, full event chain and
authoritative scope context. No network, process start, source write or
background loop is part of this module.
