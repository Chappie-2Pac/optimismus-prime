#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
. "${PROJECT_ROOT}/lib/prime_core.sh"

usage() {
  cat <<'EOF'
Usage:
  prime_set_resume_gate.sh <run-dir-or-latest> <open|hold> [reason text]

Environment:
  PRIME_AUTO_RECONCILE default: true
EOF
}

if [ "$#" -lt 2 ]; then
  usage >&2
  exit 1
fi

prime_require_cmd jq
prime_require_cmd mv
STATE_TMP=""
trap 'rm -f "${STATE_TMP:-}"; prime_release_run_lock' 0 HUP INT TERM

RUN_ARG="$1"
RESUME_GATE="$2"
shift 2
RESUME_GATE_REASON="$*"
PRIME_AUTO_RECONCILE="${PRIME_AUTO_RECONCILE:-true}"

case "${RESUME_GATE}" in
  open|hold) ;;
  *)
    echo "invalid resume gate: ${RESUME_GATE}" >&2
    exit 111
    ;;
esac

if [ "${RESUME_GATE}" = "hold" ] && [ -z "${RESUME_GATE_REASON}" ]; then
  echo "hold resume gate requires a non-empty reason" >&2
  exit 111
fi

if [ "${RESUME_GATE}" = "open" ]; then
  RESUME_GATE_REASON=""
fi

RUN_DIR="$(prime_resolve_run_dir "${PROJECT_ROOT}" "${RUN_ARG}")"
prime_acquire_run_lock "${RUN_DIR}" exclusive nonblock

SESSION_STATE="${RUN_DIR}/session_state.json"
if [ ! -f "${SESSION_STATE}" ]; then
  echo "missing session state: ${SESSION_STATE}" >&2
  exit 111
fi

TS="$(prime_now_utc)"
STATE_TMP="${SESSION_STATE}.tmp.$$"

jq \
  --arg resume_gate "${RESUME_GATE}" \
  --arg resume_gate_reason "${RESUME_GATE_REASON}" \
  --arg ts "${TS}" \
  '
    .resume_gate = $resume_gate
    | .resume_gate_reason = $resume_gate_reason
    | .updated_at = $ts
  ' "${SESSION_STATE}" > "${STATE_TMP}"

mv "${STATE_TMP}" "${SESSION_STATE}"

PRIME_SKIP_RUN_LOCK=1 \
  "${SCRIPT_DIR}/prime_append_event.sh" "${RUN_DIR}" "resume_gate_changed" \
  "resume gate set to ${RESUME_GATE}${RESUME_GATE_REASON:+: ${RESUME_GATE_REASON}}" >/dev/null

if [ "${PRIME_AUTO_RECONCILE}" = "true" ]; then
  PRIME_SKIP_RUN_LOCK=1 "${SCRIPT_DIR}/prime_reconcile_run.sh" "${RUN_DIR}" >/dev/null
fi

printf 'run_dir=%s\n' "${RUN_DIR}"
printf 'resume_gate=%s\n' "${RESUME_GATE}"
printf 'resume_gate_reason=%s\n' "${RESUME_GATE_REASON}"
