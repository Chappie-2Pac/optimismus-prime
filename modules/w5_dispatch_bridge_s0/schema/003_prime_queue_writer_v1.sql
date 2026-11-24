CREATE TABLE IF NOT EXISTS prime_queue_writer_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS prime_queue_writer_roots (
    root_binding_sha256 TEXT PRIMARY KEY,
    active_scope_id TEXT NOT NULL UNIQUE,
    active_fencing_epoch INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS prime_queue_writer_scopes (
    scope_id TEXT PRIMARY KEY,
    root_binding_sha256 TEXT NOT NULL UNIQUE,
    owner_id TEXT NOT NULL,
    owner_instance_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    lease_token_sha256 TEXT NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    scope_status TEXT NOT NULL CHECK (scope_status IN ('CLEAN','IN_DOUBT','RECOVERY_REQUIRED','QUARANTINED')),
    active_operation_id TEXT,
    active_phase TEXT NOT NULL CHECK (active_phase IN ('IDLE','PREPARED','EXECUTING','RECOVERY')),
    event_seq INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS prime_queue_writer_operations (
    scope_id TEXT NOT NULL REFERENCES prime_queue_writer_scopes(scope_id),
    idempotency_key TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    intent_sha256 TEXT NOT NULL,
    card_id TEXT NOT NULL,
    command TEXT NOT NULL,
    actor TEXT NOT NULL,
    expected_queue_sha256 TEXT NOT NULL,
    after_queue_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PREPARED','COMMITTED','ABORTED','IN_DOUBT','RECOVERY_REQUIRED','QUARANTINED')),
    queue_mutation_performed INTEGER NOT NULL CHECK (queue_mutation_performed IN (0,1)),
    queue_mutation_evidence TEXT NOT NULL CHECK (queue_mutation_evidence IN ('TRUE','FALSE','UNKNOWN')),
    operation_json TEXT NOT NULL,
    result_json TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scope_id, idempotency_key),
    UNIQUE (scope_id, transaction_id)
);

CREATE TABLE IF NOT EXISTS prime_queue_writer_events (
    scope_id TEXT NOT NULL REFERENCES prime_queue_writer_scopes(scope_id),
    event_seq INTEGER NOT NULL,
    idempotency_key TEXT,
    event_type TEXT NOT NULL,
    parent_event_sha256 TEXT,
    event_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (scope_id, event_seq),
    UNIQUE (scope_id, event_sha256)
);

CREATE TABLE IF NOT EXISTS prime_queue_writer_markers (
    scope_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    marker_kind TEXT NOT NULL CHECK (marker_kind IN ('PREPARED','COMMITTED','ABORTED','IN_DOUBT','RECOVERY_REQUIRED','QUARANTINED')),
    marker_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (scope_id, idempotency_key, marker_kind),
    FOREIGN KEY (scope_id, idempotency_key)
        REFERENCES prime_queue_writer_operations(scope_id, idempotency_key)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_prime_queue_writer_events_operation
    ON prime_queue_writer_events(scope_id, idempotency_key, event_seq);

CREATE TABLE IF NOT EXISTS prime_queue_writer_handoff_events (
    scope_id TEXT NOT NULL REFERENCES prime_queue_writer_scopes(scope_id),
    handoff_seq INTEGER NOT NULL,
    handoff_id TEXT NOT NULL UNIQUE,
    root_binding_sha256 TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    observation_sha256 TEXT NOT NULL,
    grant_sha256 TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    authority_epoch INTEGER NOT NULL,
    authority_proof_sha256 TEXT NOT NULL,
    old_owner_id TEXT NOT NULL,
    old_owner_instance_id TEXT NOT NULL,
    old_owner_epoch INTEGER NOT NULL,
    old_fencing_epoch INTEGER NOT NULL,
    old_lease_token_sha256 TEXT NOT NULL,
    old_lease_expires_at INTEGER NOT NULL,
    new_owner_id TEXT NOT NULL,
    new_owner_instance_id TEXT NOT NULL,
    new_owner_epoch INTEGER NOT NULL,
    new_fencing_epoch INTEGER NOT NULL,
    new_lease_token_sha256 TEXT NOT NULL,
    new_lease_expires_at INTEGER NOT NULL,
    handoff_kind TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type = 'HANDOFF_ACCEPTED_RECOVERY'),
    parent_event_sha256 TEXT,
    event_sha256 TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (scope_id, handoff_seq),
    UNIQUE (scope_id, idempotency_key),
    UNIQUE (scope_id, old_fencing_epoch),
    UNIQUE (scope_id, grant_sha256),
    UNIQUE (scope_id, event_sha256)
);

CREATE INDEX IF NOT EXISTS idx_prime_queue_writer_handoff_events_scope
    ON prime_queue_writer_handoff_events(scope_id, handoff_seq);

CREATE TRIGGER IF NOT EXISTS prime_queue_writer_events_immutable_update
BEFORE UPDATE ON prime_queue_writer_events
BEGIN
    SELECT RAISE(ABORT, 'prime queue writer events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS prime_queue_writer_events_immutable_delete
BEFORE DELETE ON prime_queue_writer_events
BEGIN
    SELECT RAISE(ABORT, 'prime queue writer events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS prime_queue_writer_handoff_events_immutable_update
BEFORE UPDATE ON prime_queue_writer_handoff_events
BEGIN
    SELECT RAISE(ABORT, 'prime queue handoff events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS prime_queue_writer_handoff_events_immutable_delete
BEFORE DELETE ON prime_queue_writer_handoff_events
BEGIN
    SELECT RAISE(ABORT, 'prime queue handoff events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS prime_queue_writer_markers_immutable_update
BEFORE UPDATE ON prime_queue_writer_markers
BEGIN
    SELECT RAISE(ABORT, 'prime queue writer markers are immutable');
END;

CREATE TRIGGER IF NOT EXISTS prime_queue_writer_markers_immutable_delete
BEFORE DELETE ON prime_queue_writer_markers
BEGIN
    SELECT RAISE(ABORT, 'prime queue writer markers are append-only');
END;
