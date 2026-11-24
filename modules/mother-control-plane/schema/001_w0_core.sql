-- W2.5-S0 / W0 core runtime schema.
--
-- This schema is deliberately self-contained.  It is used by the isolated
-- Python harness only; it does not attach to Prime's existing run ledgers or
-- start a worker.  State transitions are owned by control_plane.py, while
-- these tables keep the entities and their immutable evidence separate.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO meta(key, value) VALUES ('event_seq', '0');
INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', 'w25-s0');
INSERT OR IGNORE INTO meta(key, value) VALUES ('profile', 'W2.5-S0-P0');
INSERT OR IGNORE INTO meta(key, value) VALUES ('acceptance_enabled', '0');
INSERT OR IGNORE INTO meta(key, value) VALUES ('canonicalization_version', 'json-sortkeys-v1');

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    profile_version TEXT NOT NULL,
    canonical_root TEXT NOT NULL,
    discovery_root TEXT,
    path_policy_hash TEXT NOT NULL,
    autonomy_level TEXT NOT NULL CHECK (autonomy_level IN ('A0','A1','A2','A3','A4','A5')),
    status TEXT NOT NULL CHECK (status IN ('DISCOVERED','REGISTERED','READY','ACTIVE','WAITING','PAUSED','BLOCKED','RECOVERY_REQUIRED','QUARANTINED','ARCHIVED')),
    source_manifest_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    goal_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_version TEXT NOT NULL,
    mode TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('CREATED','PREFLIGHT','READY','DISPATCHING','RUNNING','VERIFYING','REVIEW_PENDING','ADVANCING','WAITING','PAUSED','BLOCKED','RECOVERY_REQUIRED','FAILED','ABORTED','COMPLETED')),
    queue_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    context_pack_hash TEXT,
    lease_token TEXT,
    lease_owner_id TEXT,
    lease_expires_at INTEGER,
    last_heartbeat_at TEXT,
    fencing_epoch INTEGER NOT NULL DEFAULT 1,
    last_committed_event_id TEXT,
    resume_point_id TEXT,
    active_dispatch_id TEXT,
    budget_json TEXT NOT NULL,
    next_action_json TEXT NOT NULL,
    input_spec_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- The anchor is the last control-plane projection committed through this
-- harness.  It lets replay detect direct SQL state drift even when later
-- commit markers or audit events exist.
CREATE TABLE IF NOT EXISTS runtime_anchors (
    run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
    projection_hash TEXT NOT NULL,
    last_committed_event_id TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_anchor_history (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    anchor_no INTEGER NOT NULL,
    projection_hash TEXT NOT NULL,
    last_committed_event_id TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY(run_id, anchor_no)
);

CREATE TABLE IF NOT EXISTS cards (
    card_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id),
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    goal_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    plan_version TEXT NOT NULL,
    card_hash TEXT NOT NULL,
    source_queue_hash TEXT NOT NULL,
    title TEXT NOT NULL,
    objective TEXT NOT NULL,
    non_goals_json TEXT NOT NULL,
    dependencies_json TEXT NOT NULL,
    postconditions_json TEXT NOT NULL,
    capability_set_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('DRAFT','WAITING','READY','CLAIMED','IN_PROGRESS','SUBMITTED','REVIEW_PENDING','RETRY_READY','PAUSED','BLOCKED','DONE','CANCELLED')),
    state_version INTEGER NOT NULL DEFAULT 0,
    active_attempt_id TEXT,
    attempt_ids_json TEXT NOT NULL,
    acceptance_txn_id TEXT,
    next_card_intent_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id, card_id)
);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    attempt_no INTEGER NOT NULL,
    card_id TEXT NOT NULL REFERENCES cards(card_id),
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    retry_of TEXT,
    state TEXT NOT NULL CHECK (state IN ('CREATED','ADMITTED','STARTING','RUNNING','CHECKPOINTED','SUBMITTED','EVIDENCE_VERIFIED','REVIEW_PENDING','ACCEPTED','REJECTED','RETRYABLE','FAILED','ABORTED','BLOCKED','UNCERTAIN')),
    result TEXT CHECK (result IS NULL OR result IN ('SUBMITTED','EVIDENCE_VERIFIED','NO_PROGRESS','TIMEOUT','FAILED','REJECTED','BLOCKED')),
    state_version INTEGER NOT NULL DEFAULT 0,
    last_transition_event_id TEXT,
    dispatch_id TEXT,
    input_snapshot_hash TEXT NOT NULL,
    context_pack_hash TEXT NOT NULL,
    worker_id TEXT,
    command_hash TEXT,
    progress_signature TEXT,
    progress_signature_count INTEGER NOT NULL DEFAULT 0,
    artifact_manifest_hash TEXT,
    receipt_id TEXT,
    review_id TEXT,
    deadline_at INTEGER,
    heartbeat_deadline_at INTEGER,
    last_heartbeat_at TEXT,
    deadline_policy_hash TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(card_id, attempt_no)
);

CREATE TABLE IF NOT EXISTS dispatches (
    dispatch_id TEXT PRIMARY KEY,
    dispatch_key TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    state TEXT NOT NULL CHECK (state IN ('DISPATCH_INTENDED','CLAIMED','SPAWN_REQUESTED','EXECUTOR_ACKED','RUNNING','EXIT_REPORTED','ACK_TIMEOUT','DISPATCH_UNCONFIRMED','RECONCILING','EXPIRED','FAILED','BLOCKED','CANCELLED','COMPLETED')),
    run_token TEXT NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    owner_id TEXT NOT NULL,
    command_hash TEXT NOT NULL,
    pid INTEGER,
    process_starttime TEXT,
    boot_id TEXT,
    pidfd_ref TEXT,
    cgroup_ref TEXT,
    ack_deadline_at INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    heartbeat_at TEXT,
    spawn_attempt_no INTEGER NOT NULL DEFAULT 0,
    max_spawn_attempts INTEGER NOT NULL DEFAULT 1,
    executor_kind TEXT NOT NULL DEFAULT 'fake',
    row_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id, idempotency_key),
    UNIQUE(run_id, dispatch_key)
);

CREATE TABLE IF NOT EXISTS artifact_manifests (
    artifact_manifest_hash TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    artifact_hashes_json TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    state_hash TEXT NOT NULL,
    receipt_id TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(attempt_id, checkpoint_id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    artifact_manifest_hash TEXT NOT NULL REFERENCES artifact_manifests(artifact_manifest_hash),
    artifact_hash TEXT NOT NULL,
    scope_ref TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    receipt_kind TEXT NOT NULL CHECK (receipt_kind IN ('execution','validation','review','shutdown','doctor','scan')),
    state TEXT NOT NULL CHECK (state IN ('EXPECTED','STAGED','SEALED','VERIFIED','REJECTED','STALE','SUPERSEDED','QUARANTINED')),
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    dispatch_id TEXT REFERENCES dispatches(dispatch_id),
    attempt_id TEXT REFERENCES attempts(attempt_id),
    card_id TEXT REFERENCES cards(card_id),
    parent_receipt_id TEXT REFERENCES receipts(receipt_id),
    plan_version TEXT,
    queue_hash TEXT,
    card_hash TEXT,
    input_snapshot_hash TEXT,
    review_id TEXT,
    policy_hash TEXT NOT NULL,
    capability_set_hash TEXT NOT NULL,
    command_hash TEXT,
    artifact_manifest_hash TEXT,
    validator_id TEXT,
    validator_version TEXT,
    result TEXT NOT NULL CHECK (result IN ('SUBMITTED','EVIDENCE_VERIFIED','NO_PROGRESS','TIMEOUT','ACCEPTED','REJECTED','BLOCKED','FAILED','PAUSED','CLEAN','REPAIRED','QUARANTINED')),
    next_action_json TEXT NOT NULL,
    artifact_hashes_json TEXT NOT NULL,
    validation_result_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    sealed_at TEXT,
    verified_at TEXT,
    commit_txn_id TEXT,
    receipt_body_hash TEXT,
    progress_signature TEXT,
    receipt_hash TEXT,
    core_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reviews (
    review_id TEXT PRIMARY KEY,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    card_id TEXT NOT NULL REFERENCES cards(card_id),
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    review_domain_id TEXT NOT NULL,
    input_manifest_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('NOT_REQUESTED','REQUESTED','CLAIMED','RUNNING','SUBMITTED','ACCEPTED','REJECTED','ABSTAINED','EXPIRED','BLOCKED')),
    decision TEXT CHECK (decision IS NULL OR decision IN ('ACCEPTED','REJECTED','ABSTAINED','EXPIRED','BLOCKED')),
    retryable INTEGER NOT NULL DEFAULT 0 CHECK (retryable IN (0,1)),
    expires_at INTEGER,
    heartbeat_at TEXT,
    deadline_policy_hash TEXT,
    criteria_hash TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    reviewer_identity TEXT NOT NULL,
    reviewer_process_identity TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acceptance_txns (
    acceptance_txn_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    card_id TEXT NOT NULL REFERENCES cards(card_id),
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
    receipt_id TEXT NOT NULL REFERENCES receipts(receipt_id),
    review_id TEXT NOT NULL REFERENCES reviews(review_id),
    next_card_intent_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('PREPARED','COMMITTED','ABORTED','QUARANTINED')),
    duplicate_outcome TEXT CHECK (duplicate_outcome IS NULL OR duplicate_outcome IN ('REPLAYED','CONFLICT')),
    acceptance_enabled INTEGER NOT NULL CHECK (acceptance_enabled IN (0,1)),
    before_card_state TEXT NOT NULL,
    before_attempt_state TEXT NOT NULL,
    before_run_state TEXT NOT NULL,
    after_card_state TEXT NOT NULL,
    after_attempt_state TEXT NOT NULL,
    after_run_state TEXT NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    before_state_hash TEXT NOT NULL,
    after_state_hash TEXT,
    commit_marker_hash TEXT,
    last_committed_event_id TEXT,
    created_at TEXT NOT NULL,
    committed_at TEXT
);

CREATE TABLE IF NOT EXISTS next_card_intents (
    next_card_intent_id TEXT PRIMARY KEY,
    acceptance_txn_id TEXT NOT NULL REFERENCES acceptance_txns(acceptance_txn_id),
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    card_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('INTENDED','DISPATCHED','CANCELLED')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    event_no INTEGER NOT NULL UNIQUE,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS commit_markers (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    commit_point TEXT NOT NULL,
    operation_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('COMMITTED','SUPPRESSED')),
    marker_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(run_id, operation_key)
);

-- A second, append-only commitment table prevents a caller from changing a
-- marker payload and recomputing the marker_hash in the same row.
CREATE TABLE IF NOT EXISTS marker_commitments (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    operation_key TEXT NOT NULL,
    marker_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(run_id, operation_key)
);

CREATE TABLE IF NOT EXISTS fault_observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    commit_point TEXT NOT NULL,
    hook TEXT NOT NULL,
    injected INTEGER NOT NULL CHECK (injected IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_run_no ON events(run_id, event_no);
CREATE INDEX IF NOT EXISTS idx_attempts_run ON attempts(run_id, state);
CREATE INDEX IF NOT EXISTS idx_dispatches_run ON dispatches(run_id, state);
CREATE INDEX IF NOT EXISTS idx_receipts_attempt ON receipts(attempt_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_run_per_project
    ON runs(project_id)
    WHERE state NOT IN ('FAILED','ABORTED','COMPLETED');
CREATE UNIQUE INDEX IF NOT EXISTS one_active_attempt_per_card
    ON attempts(card_id)
    WHERE state NOT IN ('RETRYABLE','FAILED','ABORTED','ACCEPTED','BLOCKED');
CREATE UNIQUE INDEX IF NOT EXISTS one_active_dispatch_per_run
    ON dispatches(run_id)
    WHERE state NOT IN ('CANCELLED','EXPIRED','FAILED','BLOCKED','COMPLETED');

-- P0 is fail-closed at the database boundary as well as in Python.  A future
-- W6 migration may flip meta.acceptance_enabled in a different schema.
CREATE TRIGGER IF NOT EXISTS p0_reject_acceptance_insert
BEFORE INSERT ON acceptance_txns
WHEN NEW.state = 'COMMITTED'
 AND COALESCE((SELECT value FROM meta WHERE key='acceptance_enabled'), '0') = '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: AcceptanceTxn.COMMITTED');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_acceptance_update
BEFORE UPDATE OF state ON acceptance_txns
WHEN NEW.state = 'COMMITTED'
 AND COALESCE((SELECT value FROM meta WHERE key='acceptance_enabled'), '0') = '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: AcceptanceTxn.COMMITTED');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_card_done
BEFORE INSERT ON cards
WHEN NEW.state = 'DONE'
 AND COALESCE((SELECT value FROM meta WHERE key='acceptance_enabled'), '0') = '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: Card.DONE');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_card_done_update
BEFORE UPDATE OF state ON cards
WHEN NEW.state = 'DONE'
 AND COALESCE((SELECT value FROM meta WHERE key='acceptance_enabled'), '0') = '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: Card.DONE');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_attempt_accepted
BEFORE INSERT ON attempts
WHEN NEW.state = 'ACCEPTED'
 AND COALESCE((SELECT value FROM meta WHERE key='acceptance_enabled'), '0') = '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: Attempt.ACCEPTED');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_attempt_accepted_update
BEFORE UPDATE OF state ON attempts
WHEN NEW.state = 'ACCEPTED'
 AND COALESCE((SELECT value FROM meta WHERE key='acceptance_enabled'), '0') = '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: Attempt.ACCEPTED');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_next_card_intent
BEFORE INSERT ON next_card_intents
WHEN COALESCE((SELECT value FROM meta WHERE key='acceptance_enabled'), '0') = '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: next_card_intent');
END;

-- The P0 harness has no SQL escape hatch for enabling W6 acceptance.  A
-- future schema must replace this trigger rather than mutating the flag in
-- place.
CREATE TRIGGER IF NOT EXISTS p0_reject_acceptance_enable_insert
BEFORE INSERT ON meta
WHEN NEW.key = 'acceptance_enabled' AND NEW.value <> '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: acceptance_enabled');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_acceptance_enable_update
BEFORE UPDATE OF value ON meta
WHEN NEW.key = 'acceptance_enabled' AND NEW.value <> '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: acceptance_enabled');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_acceptance_enable_key_update
BEFORE UPDATE OF key ON meta
WHEN NEW.key = 'acceptance_enabled' AND NEW.value <> '0'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: acceptance_enabled');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_acceptance_enable_delete
BEFORE DELETE ON meta
WHEN OLD.key = 'acceptance_enabled'
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: acceptance_enabled');
END;

CREATE TRIGGER IF NOT EXISTS marker_commitments_immutable_update
BEFORE UPDATE ON marker_commitments
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE: marker_commitments');
END;

CREATE TRIGGER IF NOT EXISTS marker_commitments_immutable_delete
BEFORE DELETE ON marker_commitments
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE: marker_commitments');
END;

CREATE TRIGGER IF NOT EXISTS runtime_anchor_history_immutable_update
BEFORE UPDATE ON runtime_anchor_history
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE: runtime_anchor_history');
END;

CREATE TRIGGER IF NOT EXISTS runtime_anchor_history_immutable_delete
BEFORE DELETE ON runtime_anchor_history
BEGIN
    SELECT RAISE(ABORT, 'IMMUTABLE: runtime_anchor_history');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_acceptance_flag_insert
BEFORE INSERT ON acceptance_txns
WHEN NEW.acceptance_enabled <> 0
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: acceptance_enabled');
END;

CREATE TRIGGER IF NOT EXISTS p0_reject_acceptance_flag_update
BEFORE UPDATE OF acceptance_enabled ON acceptance_txns
WHEN NEW.acceptance_enabled <> 0
BEGIN
    SELECT RAISE(ABORT, 'P0_DISABLED: acceptance_enabled');
END;
