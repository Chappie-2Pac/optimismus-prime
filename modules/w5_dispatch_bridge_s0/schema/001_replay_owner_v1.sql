PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS owner_store_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS replay_owner_scopes (
    scope_id TEXT PRIMARY KEY,
    scope_binding_json TEXT NOT NULL,
    scope_binding_sha256 TEXT NOT NULL,
    baseline_state_version INTEGER NOT NULL CHECK (baseline_state_version >= 0),
    state_version INTEGER NOT NULL CHECK (state_version >= 0),
    head_sha256 TEXT,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    attestation_set_sha256 TEXT,
    nonce_sha256 TEXT,
    owner_id TEXT NOT NULL,
    owner_instance_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL CHECK (owner_epoch >= 0),
    fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch >= 0),
    lease_token_sha256 TEXT NOT NULL,
    lease_expires_at INTEGER NOT NULL CHECK (lease_expires_at >= 0),
    idempotency_index_sha256 TEXT NOT NULL,
    journal_status TEXT NOT NULL CHECK (journal_status IN ('CLEAN','IN_DOUBT','RECOVERY_REQUIRED')),
    event_seq INTEGER NOT NULL DEFAULT 0 CHECK (event_seq >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0)
);

CREATE TABLE IF NOT EXISTS replay_owner_operations (
    scope_id TEXT NOT NULL REFERENCES replay_owner_scopes(scope_id),
    idempotency_key TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    intent_sha256 TEXT NOT NULL,
    state_version_before INTEGER NOT NULL,
    state_version_after INTEGER NOT NULL,
    sequence_before INTEGER NOT NULL,
    sequence_after INTEGER NOT NULL,
    head_before_sha256 TEXT,
    head_after_sha256 TEXT NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    idempotency_index_after_sha256 TEXT,
    operation_record_sha256 TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (scope_id, idempotency_key),
    UNIQUE (scope_id, transaction_id)
);

CREATE TABLE IF NOT EXISTS replay_owner_transitions (
    scope_id TEXT NOT NULL REFERENCES replay_owner_scopes(scope_id),
    after_state_version INTEGER NOT NULL,
    transaction_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    parent_head_sha256 TEXT,
    new_head_sha256 TEXT NOT NULL,
    before_state_version INTEGER NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    transition_sha256 TEXT NOT NULL,
    parent_transition_sha256 TEXT,
    committed_at INTEGER NOT NULL CHECK (committed_at >= 0),
    PRIMARY KEY (scope_id, after_state_version),
    UNIQUE (scope_id, transaction_id)
);

CREATE TABLE IF NOT EXISTS replay_owner_events (
    scope_id TEXT NOT NULL REFERENCES replay_owner_scopes(scope_id),
    event_seq INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    idempotency_key TEXT,
    state_version INTEGER NOT NULL,
    event_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (scope_id, event_seq),
    UNIQUE (scope_id, event_sha256)
);

CREATE INDEX IF NOT EXISTS idx_replay_owner_operations_intent
ON replay_owner_operations(scope_id, intent_sha256);
CREATE INDEX IF NOT EXISTS idx_replay_owner_events_scope
ON replay_owner_events(scope_id, event_seq);
CREATE INDEX IF NOT EXISTS idx_replay_owner_transitions_scope
ON replay_owner_transitions(scope_id, after_state_version);
