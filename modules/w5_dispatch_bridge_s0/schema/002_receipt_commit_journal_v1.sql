CREATE TABLE IF NOT EXISTS receipt_journal_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receipt_journal_scopes (
    scope_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL,
    projection_manifest_sha256 TEXT NOT NULL,
    projection_set_sha256 TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    owner_instance_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    lease_token_sha256 TEXT NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    journal_status TEXT NOT NULL CHECK (journal_status IN ('CLEAN','IN_DOUBT','RECOVERY_REQUIRED','QUARANTINED')),
    event_seq INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS receipt_commit_journal (
    scope_id TEXT NOT NULL REFERENCES receipt_journal_scopes(scope_id),
    receipt_key TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    operation TEXT NOT NULL,
    receipt_intent_sha256 TEXT NOT NULL,
    provenance_sha256 TEXT NOT NULL,
    s18_commit_witness_sha256 TEXT NOT NULL,
    projection_manifest_sha256 TEXT NOT NULL,
    projection_set_sha256 TEXT NOT NULL,
    subject_binding_sha256 TEXT NOT NULL,
    effect_sha256 TEXT NOT NULL,
    participant_witness_sha256 TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    owner_instance_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PREPARED','PROJECTION_PENDING','IN_DOUBT','RECOVERY_REQUIRED','QUARANTINED','COMMITTED')),
    observed_effect_state TEXT NOT NULL CHECK (observed_effect_state IN ('NONE','OBSERVED','UNKNOWN')),
    receipt_emitted INTEGER NOT NULL CHECK (receipt_emitted IN (0,1)),
    receipt_committed INTEGER NOT NULL CHECK (receipt_committed IN (0,1)),
    consume_allowed INTEGER NOT NULL CHECK (consume_allowed IN (0,1)),
    mutation_performed INTEGER NOT NULL CHECK (mutation_performed IN (0,1)),
    intent_json TEXT NOT NULL,
    receipt_core_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scope_id, receipt_key),
    UNIQUE (scope_id, receipt_id),
    UNIQUE (scope_id, transaction_id),
    UNIQUE (scope_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS receipt_commit_participants (
    scope_id TEXT NOT NULL,
    receipt_key TEXT NOT NULL,
    participant_id TEXT NOT NULL,
    participant_role TEXT NOT NULL CHECK (participant_role IN ('WRITE','OBSERVATION')),
    participant_sha256 TEXT NOT NULL,
    participant_json TEXT NOT NULL,
    PRIMARY KEY (scope_id, receipt_key, participant_id),
    FOREIGN KEY (scope_id, receipt_key)
        REFERENCES receipt_commit_journal(scope_id, receipt_key)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS receipt_commit_events (
    scope_id TEXT NOT NULL REFERENCES receipt_journal_scopes(scope_id),
    event_seq INTEGER NOT NULL,
    receipt_key TEXT,
    event_type TEXT NOT NULL,
    parent_event_sha256 TEXT,
    event_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (scope_id, event_seq),
    UNIQUE (scope_id, event_sha256)
);

CREATE TABLE IF NOT EXISTS receipt_commit_markers (
    scope_id TEXT NOT NULL,
    receipt_key TEXT NOT NULL,
    marker_kind TEXT NOT NULL CHECK (marker_kind IN ('PREPARED','IN_DOUBT','RECOVERY_REQUIRED','QUARANTINED')),
    marker_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (scope_id, receipt_key, marker_kind),
    FOREIGN KEY (scope_id, receipt_key)
        REFERENCES receipt_commit_journal(scope_id, receipt_key)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_receipt_commit_events_receipt
    ON receipt_commit_events(scope_id, receipt_key, event_seq);

CREATE TRIGGER IF NOT EXISTS receipt_commit_markers_immutable_update
BEFORE UPDATE ON receipt_commit_markers
BEGIN
    SELECT RAISE(ABORT, 'receipt commit markers are immutable');
END;

CREATE TRIGGER IF NOT EXISTS receipt_commit_markers_immutable_delete
BEFORE DELETE ON receipt_commit_markers
BEGIN
    SELECT RAISE(ABORT, 'receipt commit markers are append-only');
END;
