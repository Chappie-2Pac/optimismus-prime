#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
. "${PROJECT_ROOT}/lib/prime_core.sh"

usage() {
  cat <<'EOF'
Usage:
  prime_append_event.sh <run-dir-or-latest> <event-type> <message>

Environment:
  EVENT_TASK_ID       default: ""
  EVENT_ARTIFACT_ID   default: ""
  EVENT_WAVE          default: from session_state.current_wave
EOF
}

if [ "$#" -lt 3 ]; then
  usage >&2
  exit 1
fi

prime_require_cmd jq
prime_require_cmd mv
prime_require_cmd sha256sum
prime_require_cmd sync
STATE_TMP=""
LEDGER_TMP=""
trap 'rm -f "${STATE_TMP:-}" "${LEDGER_TMP:-}"; prime_release_run_lock' 0 HUP INT TERM

RUN_ARG="$1"
EVENT_TYPE="$2"
shift 2
MESSAGE="$*"

RUN_DIR="$(prime_resolve_run_dir "${PROJECT_ROOT}" "${RUN_ARG}")"
prime_acquire_run_lock "${RUN_DIR}" exclusive nonblock

SESSION_STATE="${RUN_DIR}/session_state.json"
EVENTS_JSONL="${RUN_DIR}/events.jsonl"

if [ ! -f "${SESSION_STATE}" ]; then
  echo "missing session state: ${SESSION_STATE}" >&2
  exit 111
fi
if [ ! -f "${EVENTS_JSONL}" ]; then
  echo "missing events ledger: ${EVENTS_JSONL}" >&2
  exit 111
fi
prime_recover_transactions "${RUN_DIR}"

EVENT_TASK_ID="${EVENT_TASK_ID:-}"
EVENT_ARTIFACT_ID="${EVENT_ARTIFACT_ID:-}"
EVENT_WAVE="${EVENT_WAVE:-}"

EVENT_HWM="$(prime_assert_ledger_state_hwm "${EVENTS_JSONL}" "${SESSION_STATE}" event_id event- latest_event_id)"
NEXT_EVENT_ID="$((EVENT_HWM + 1))"
EVENT_ID="$(printf 'event-%03d' "${NEXT_EVENT_ID}")"
TS="$(prime_now_utc)"

EVENT_WAVE="${EVENT_WAVE:-$(jq -r '.current_wave // ""' "${SESSION_STATE}")}"

EVENT_JSON="$(
  jq -nc \
    --arg event_id "${EVENT_ID}" \
    --arg type "${EVENT_TYPE}" \
    --arg ts "${TS}" \
    --arg wave "${EVENT_WAVE}" \
    --arg message "${MESSAGE}" \
    --arg task_id "${EVENT_TASK_ID}" \
    --arg artifact_id "${EVENT_ARTIFACT_ID}" \
    '
      {event_id: $event_id, type: $type, ts: $ts, wave: $wave, message: $message}
      + (if $task_id != "" then {task_id: $task_id} else {} end)
      + (if $artifact_id != "" then {artifact_id: $artifact_id} else {} end)
    '
)"

mkdir -p "${RUN_DIR}/tx"
chmod 700 "${RUN_DIR}/tx"
LEDGER_TMP="${RUN_DIR}/tx/.events.prepared.$$.$(prime_random_hex 3)"
STATE_TMP="${RUN_DIR}/tx/.state.prepared.$$.$(prime_random_hex 3)"
cp -- "${EVENTS_JSONL}" "${LEDGER_TMP}"
printf '%s\n' "${EVENT_JSON}" >> "${LEDGER_TMP}"
chmod 600 "${LEDGER_TMP}"
jq \
  --argjson latest_event_id "${NEXT_EVENT_ID}" \
  --arg ts "${TS}" \
  '
    .latest_event_id = $latest_event_id
    | .updated_at = $ts
  ' "${SESSION_STATE}" > "${STATE_TMP}"
chmod 600 "${STATE_TMP}"
prime_commit_ledger_state_transaction "${RUN_DIR}" event "${EVENTS_JSONL}" "${SESSION_STATE}" "${LEDGER_TMP}" "${STATE_TMP}"
prime_cleanup_committed_sources "${RUN_DIR}" "${STATE_TMP}" "${LEDGER_TMP}"
STATE_TMP=""
LEDGER_TMP=""

echo "event_id=${EVENT_ID}"
echo "run_dir=${RUN_DIR}"
echo "type=${EVENT_TYPE}"
