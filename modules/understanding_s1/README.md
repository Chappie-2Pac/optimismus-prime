# W3-S1 Artifact Verifier

W3-S1 verifies W3-S0 artifacts without changing them. A positive result needs
the expected `ProjectProfile`, `SourceSpec`, `SourceManifest`, `ScanEvent`, and
the explicit `scan-scope.v1` object. Repeating an untrusted `scope_hash` is not
enough to establish scope provenance.

The verifier rejects unknown fields, duplicate JSON keys, malformed hashes,
registry-/source-/scope mismatches, tampered manifest or event hashes,
inconsistent Coverage, partial scans that permit negative claims, invalid
event order, and forbidden side-effect markers. `verify_output_bundle` reads
only explicit relative paths below a no-follow output directory and has no
write, process, or network capability.

This is still a verification sidecar, not a Prime runtime authority. It does
not promote a source manifest into Claims, ContextPacks, Tasks, or Acceptance.
