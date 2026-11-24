#!/bin/sh
set -eu
umask 077

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
. "${PROJECT_ROOT}/lib/prime_core.sh"
. "${PROJECT_ROOT}/lib/prime_current_index.sh"

usage() {
  cat <<'EOF'
Usage:
  prime_mother_bootstrap.sh <goal text>

Environment:
  PROJECT_NAME        default: optimismus-prime
  RUNS_ROOT           default: <project-root>/runtime/runs
  ROLE                default: mother-session
  WAVE_ID             default: wave-a-foundation
EOF
}

if [ "$#" -lt 1 ]; then
  usage >&2
  exit 1
fi

prime_require_cmd jq
prime_require_cmd flock
prime_require_cmd ln
prime_require_cmd mkdir
prime_require_cmd mv
prime_require_cmd od
prime_require_cmd tr
prime_require_cmd date

PROJECT_NAME="${PROJECT_NAME:-optimismus-prime}"
RUNS_ROOT="${RUNS_ROOT:-${PROJECT_ROOT}/runtime/runs}"
ROLE="${ROLE:-mother-session}"
WAVE_ID="${WAVE_ID:-wave-a-foundation}"
GOAL="$*"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${RUNS_ROOT}"
chmod 700 "${RUNS_ROOT}"
while :; do
  RUN_NONCE="$(prime_random_hex 8)"
  RUN_ID="${TIMESTAMP}-${RUN_NONCE}-${PROJECT_NAME}"
  RUN_DIR="${RUNS_ROOT}/${RUN_ID}"
  if mkdir -m 700 "${RUN_DIR}" 2>/dev/null; then
    break
  fi
done
mkdir -m 700 "${RUN_DIR}/logs" "${RUN_DIR}/inbox" "${RUN_DIR}/out" "${RUN_DIR}/locks" "${RUN_DIR}/tx"
chmod 700 "${RUNS_ROOT}" "${RUN_DIR}" "${RUN_DIR}/logs" "${RUN_DIR}/inbox" "${RUN_DIR}/out" "${RUN_DIR}/locks" "${RUN_DIR}/tx"

SESSION_STATE="${RUN_DIR}/session_state.json"
TASKS_JSON="${RUN_DIR}/tasks.json"
EVENTS_JSONL="${RUN_DIR}/events.jsonl"
ARTIFACTS_JSONL="${RUN_DIR}/artifacts.jsonl"
SUMMARY_MD="${RUN_DIR}/summary.md"

TS_NOW="$(prime_now_utc)"

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg project "${PROJECT_NAME}" \
  --arg role "${ROLE}" \
  --arg goal "${GOAL}" \
  --arg wave "${WAVE_ID}" \
  --arg ts "${TS_NOW}" \
  '{
    state_schema_version: 2,
    run_id: $run_id,
    project: $project,
    role: $role,
    status: "in_progress",
    goal: $goal,
    current_wave: $wave,
    created_at: $ts,
    updated_at: $ts,
    open_agents: [],
    open_subsessions: [],
    latest_task_id: 0,
    latest_artifact_id: 0,
    latest_event_id: 1,
    continue_mode: "pending-until-real-stop",
    resume_gate: "open",
    resume_gate_reason: "",
    stop_reason: "",
    hold_reason: "",
    active_task_id: "",
    last_action: "",
    last_action_reason: "",
    blocked_reasons: [],
    last_verified_artifact: ""
    ,execution_complete: false
    ,evidence_complete: false
    ,objective_verified: false
    ,writer_authority: "lease-v1-required"
  }' > "${SESSION_STATE}"

printf '{\n  "tasks": []\n}\n' > "${TASKS_JSON}"
: > "${EVENTS_JSONL}"
: > "${ARTIFACTS_JSONL}"
chmod 600 "${SESSION_STATE}" "${TASKS_JSON}" "${EVENTS_JSONL}" "${ARTIFACTS_JSONL}"

jq -nc \
  --arg event_id "event-001" \
  --arg ts "${TS_NOW}" \
  --arg wave "${WAVE_ID}" \
  --arg message "mother session bootstrap complete" \
  '{event_id:$event_id,type:"run_started",ts:$ts,wave:$wave,message:$message}' \
  > "${EVENTS_JSONL}"

cat > "${SUMMARY_MD}" <<EOF
# Run Summary

run_id: \`${RUN_ID}\`
project: \`${PROJECT_NAME}\`
role: \`${ROLE}\`
wave: \`${WAVE_ID}\`

## Goal

${GOAL}

## Status

- run bootstrap complete
- no tasks yet
EOF
chmod 600 "${SUMMARY_MD}"

LATEST_LINK="${RUNS_ROOT}/latest"
ln -sfn "${RUN_DIR}" "${LATEST_LINK}"
prime_current_index_publish_run "${RUNS_ROOT}" "${RUN_DIR}" "${GOAL}" "${WAVE_ID}"

printf 'run_id=%s\n' "${RUN_ID}"
printf 'run_dir=%s\n' "${RUN_DIR}"
printf 'session_state=%s\n' "${SESSION_STATE}"
printf 'tasks_json=%s\n' "${TASKS_JSON}"
printf 'events_jsonl=%s\n' "${EVENTS_JSONL}"
printf 'artifacts_jsonl=%s\n' "${ARTIFACTS_JSONL}"
printf 'summary_md=%s\n' "${SUMMARY_MD}"
printf 'latest_link=%s\n' "${LATEST_LINK}"
