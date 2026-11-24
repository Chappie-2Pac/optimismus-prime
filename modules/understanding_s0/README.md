# W3-S0 Understanding Harness

This is a deliberately isolated, read-only understanding slice for
Optimismus Prime. It proves four contracts before any W3 integration:

1. a `ProjectProfile` admits only an explicitly allowed, component-verified
   project root;
2. a `SourceSpec` narrows that profile to one registered source scope;
3. `ReadOnlyScanner` reads regular files through `O_NOFOLLOW` descriptors and
   records provenance, denied entries, and source drift;
4. `SourceManifest` and `ScanEvent` make partial coverage visible and forbid
   absence claims when any remainder is unknown.

The only writes are append-only JSON artifacts below the caller-provided
`output_root`. The source tree, Prime queue, runtime, network, and process
table are outside this harness and are never touched. The package is a proof
boundary, not yet a production registry authority or a full-text index.

The current scanner is intentionally conservative. Symlinks, special files,
device boundaries, unreadable directories, budget exhaustion, and metadata
drift produce a partial or denied result. No result is promoted to a semantic
claim merely because a path was not observed.

The registration stores the project/source device and inode identities. Each
scan checks those identities before and after traversal, compares directory
entries twice, and reopens each regular file for an independent second hash.
The byte budget applies to both reads, so a growing file cannot silently turn a
bounded scan into an unbounded read. Output artifacts are opened relative to a
retained no-follow directory descriptor; replacing the configured output path
cannot redirect writes to a new location.

Protected system roots (`/proc`, `/sys`, `/dev`) and obvious secret/control
material (`.env*`, `.ssh`, `.network-pki`, `.git`, credentials, key/certificate
containers, and token directories) are rejected before content is opened.
