#!/bin/sh

# Process identity and run-lock primitives. The caller must define PROJECT_ROOT.

prime_epoch_now() {
  date +%s
}

prime_boot_id() {
  prime_boot_id_path="/proc/sys/kernel/random/boot_id"
  [ -r "${prime_boot_id_path}" ] || {
    echo "missing boot id: ${prime_boot_id_path}" >&2
    return 111
  }
  sed -n '1p' "${prime_boot_id_path}"
}

prime_proc_starttime() {
  prime_proc_pid="$1"
  case "${prime_proc_pid}" in
    ''|*[!0-9]*|0|1) return 1 ;;
  esac
  [ -r "/proc/${prime_proc_pid}/stat" ] || return 1
  prime_proc_tail="$(sed 's/^.*) //' "/proc/${prime_proc_pid}/stat" 2>/dev/null)" || return 1
  printf '%s\n' "${prime_proc_tail}" | awk '{print $20}'
}

prime_process_identity_matches() {
  prime_identity_pid="$1"
  prime_identity_starttime="$2"
  prime_identity_boot_id="$3"
  prime_identity_expected_exe="${4:-}"

  [ -n "${prime_identity_starttime}" ] || return 1
  [ -n "${prime_identity_boot_id}" ] || return 1
  kill -0 "${prime_identity_pid}" 2>/dev/null || return 1
  [ "$(prime_proc_starttime "${prime_identity_pid}" 2>/dev/null || printf '')" = "${prime_identity_starttime}" ] || return 1
  [ "$(prime_boot_id 2>/dev/null || printf '')" = "${prime_identity_boot_id}" ] || return 1

  if [ -n "${prime_identity_expected_exe}" ]; then
    [ -e "/proc/${prime_identity_pid}/exe" ] || return 1
    prime_identity_live_exe="$(prime_canonical_path "/proc/${prime_identity_pid}/exe" 2>/dev/null || printf '')"
    prime_identity_wanted_exe="$(prime_canonical_path "${prime_identity_expected_exe}" 2>/dev/null || printf '')"
    [ -n "${prime_identity_live_exe}" ] || return 1
    [ "${prime_identity_live_exe}" = "${prime_identity_wanted_exe}" ] || return 1
  fi
}

prime_path_is_within() {
  prime_path_child="$(prime_canonical_path "$1" 2>/dev/null || printf '')"
  prime_path_parent="$(prime_canonical_path "$2" 2>/dev/null || printf '')"
  [ -n "${prime_path_child}" ] && [ -n "${prime_path_parent}" ] || return 1
  case "${prime_path_child}" in
    "${prime_path_parent}"|"${prime_path_parent}"/*) return 0 ;;
    *) return 1 ;;
  esac
}

prime_lock_metadata_valid() {
  prime_lock_path="$1"
  prime_lock_metadata="${prime_lock_path}/owner.json"
  [ -f "${prime_lock_metadata}" ] || return 1
  jq -e '
    (.schema_version == 1)
    and (.token | type == "string" and length >= 16)
    and (.pid | type == "number" and . > 0)
    and (.starttime | type == "string" and length > 0)
    and (.boot_id | type == "string" and length > 0)
    and (.run_dir | type == "string" and length > 0)
    and (.expires_at_epoch | type == "number" and . > 0)
  ' "${prime_lock_metadata}" >/dev/null 2>&1 || return 1

  prime_lock_pid="$(jq -r '.pid' "${prime_lock_metadata}")"
  prime_lock_starttime="$(jq -r '.starttime' "${prime_lock_metadata}")"
  prime_lock_boot_id="$(jq -r '.boot_id' "${prime_lock_metadata}")"
  prime_lock_expires="$(jq -r '.expires_at_epoch' "${prime_lock_metadata}")"
  [ "$(prime_epoch_now)" -lt "${prime_lock_expires}" ] || return 1
  prime_process_identity_matches "${prime_lock_pid}" "${prime_lock_starttime}" "${prime_lock_boot_id}"
}

prime_join_existing_run_lock() {
  prime_join_run_dir="$1"
  prime_join_lock_path="${prime_join_run_dir}/locks/run.lock.d"
  prime_join_metadata="${prime_join_lock_path}/owner.json"
  [ -n "${PRIME_RUN_LOCK_TOKEN:-}" ] || return 1
  prime_lock_metadata_valid "${prime_join_lock_path}" || return 1
  [ "$(jq -r '.token' "${prime_join_metadata}")" = "${PRIME_RUN_LOCK_TOKEN}" ] || return 1
  [ "$(jq -r '.run_dir' "${prime_join_metadata}")" = "${prime_join_run_dir}" ] || return 1
  export PRIME_RUN_LOCK_HELD=1
  export PRIME_RUN_LOCK_PATH="${prime_join_lock_path}"
  export PRIME_RUN_LOCK_JOINED=1
}

prime_lock_incomplete_is_stale() {
  prime_incomplete_lock="$1"
  prime_incomplete_grace="${PRIME_LOCK_INCOMPLETE_GRACE_SECS:-5}"
  prime_incomplete_mtime="$(stat -c %Y "${prime_incomplete_lock}" 2>/dev/null || printf '')"
  [ -n "${prime_incomplete_mtime}" ] || return 1
  [ $(( $(prime_epoch_now) - prime_incomplete_mtime )) -ge "${prime_incomplete_grace}" ]
}

prime_reclaim_stale_run_lock() {
  prime_reclaim_run_dir="$1"
  prime_reclaim_lock_path="${prime_reclaim_run_dir}/locks/run.lock.d"
  prime_reclaim_metadata="${prime_reclaim_lock_path}/owner.json"
  [ -d "${prime_reclaim_lock_path}" ] || return 0

  if [ -f "${prime_reclaim_metadata}" ]; then
    prime_lock_metadata_valid "${prime_reclaim_lock_path}" && return 1
    # Expiry alone never authorizes overlap with the same live process.
    prime_reclaim_pid="$(jq -r '.pid // empty' "${prime_reclaim_metadata}" 2>/dev/null || printf '')"
    prime_reclaim_starttime="$(jq -r '.starttime // empty' "${prime_reclaim_metadata}" 2>/dev/null || printf '')"
    prime_reclaim_boot_id="$(jq -r '.boot_id // empty' "${prime_reclaim_metadata}" 2>/dev/null || printf '')"
    if prime_process_identity_matches "${prime_reclaim_pid}" "${prime_reclaim_starttime}" "${prime_reclaim_boot_id}"; then
      return 1
    fi
    jq -e '.schema_version == 1 and (.token | type == "string") and (.pid | type == "number") and (.starttime | type == "string") and (.boot_id | type == "string")' "${prime_reclaim_metadata}" >/dev/null 2>&1 \
      || prime_lock_incomplete_is_stale "${prime_reclaim_lock_path}" || return 1
  else
    prime_lock_incomplete_is_stale "${prime_reclaim_lock_path}" || return 1
  fi

  prime_reclaim_parent="${prime_reclaim_run_dir}/locks"
  prime_reclaim_quarantine="${prime_reclaim_parent}/run.lock.stale.$$.$(prime_random_hex 3)"
  prime_path_is_within "${prime_reclaim_lock_path}" "${prime_reclaim_run_dir}" || return 111
  mv "${prime_reclaim_lock_path}" "${prime_reclaim_quarantine}" 2>/dev/null || return 1
  prime_path_is_within "${prime_reclaim_quarantine}" "${prime_reclaim_run_dir}" || return 111
  rm -rf -- "${prime_reclaim_quarantine}"
}

prime_write_run_lock_metadata() {
  prime_metadata_run_dir="$1"
  prime_metadata_lock_path="$2"
  prime_metadata_scope="$3"
  prime_metadata_token="$4"
  prime_metadata_lease_secs="${PRIME_LOCK_LEASE_SECS:-86400}"
  prime_metadata_now="$(prime_epoch_now)"
  prime_metadata_expires="$((prime_metadata_now + prime_metadata_lease_secs))"
  prime_metadata_starttime="$(prime_proc_starttime "$$")" || return 111
  prime_metadata_boot_id="$(prime_boot_id)" || return 111
  prime_metadata_tmp="${prime_metadata_lock_path}/owner.json.tmp.$$"

  jq -n \
    --arg token "${prime_metadata_token}" \
    --argjson pid "$$" \
    --arg starttime "${prime_metadata_starttime}" \
    --arg boot_id "${prime_metadata_boot_id}" \
    --arg run_dir "${prime_metadata_run_dir}" \
    --arg scope "${prime_metadata_scope}" \
    --arg created_at "$(prime_now_utc)" \
    --argjson created_at_epoch "${prime_metadata_now}" \
    --argjson expires_at_epoch "${prime_metadata_expires}" \
    '{schema_version:1,token:$token,pid:$pid,starttime:$starttime,boot_id:$boot_id,run_dir:$run_dir,scope:$scope,created_at:$created_at,created_at_epoch:$created_at_epoch,expires_at_epoch:$expires_at_epoch}' \
    > "${prime_metadata_tmp}" || return 111
  chmod 600 "${prime_metadata_tmp}"
  mv "${prime_metadata_tmp}" "${prime_metadata_lock_path}/owner.json"
}

prime_writer_metadata_valid() {
  prime_writer_path="$1"
  prime_writer_expected_run_dir="${2:-}"
  prime_writer_metadata="${prime_writer_path}/owner.json"
  [ -f "${prime_writer_metadata}" ] || return 1
  jq -e '
    (.schema_version == 1)
    and (.token | type == "string" and length >= 16)
    and (.pid | type == "number" and . > 0)
    and (.starttime | type == "string" and length > 0)
    and (.boot_id | type == "string" and length > 0)
    and (.run_dir | type == "string" and length > 0)
    and (.role | type == "string" and length > 0)
    and (.expires_at_epoch | type == "number" and . > 0)
  ' "${prime_writer_metadata}" >/dev/null 2>&1 || return 1
  prime_writer_pid="$(jq -r '.pid' "${prime_writer_metadata}")"
  prime_writer_starttime="$(jq -r '.starttime' "${prime_writer_metadata}")"
  prime_writer_boot_id="$(jq -r '.boot_id' "${prime_writer_metadata}")"
  prime_writer_expires="$(jq -r '.expires_at_epoch' "${prime_writer_metadata}")"
  if [ -n "${prime_writer_expected_run_dir}" ]; then
    prime_writer_metadata_run_dir="$(jq -r '.run_dir' "${prime_writer_metadata}")"
    prime_writer_expected_run_dir="$(prime_canonical_path "${prime_writer_expected_run_dir}" 2>/dev/null)" || return 1
    prime_writer_metadata_run_dir="$(prime_canonical_path "${prime_writer_metadata_run_dir}" 2>/dev/null)" || return 1
    [ "${prime_writer_metadata_run_dir}" = "${prime_writer_expected_run_dir}" ] || return 1
  fi
  [ "$(prime_epoch_now)" -lt "${prime_writer_expires}" ] || return 1
  prime_process_identity_matches "${prime_writer_pid}" "${prime_writer_starttime}" "${prime_writer_boot_id}"
}

prime_join_existing_writer_lease() {
  prime_join_writer_run_dir="$1"
  prime_join_writer_path="${prime_join_writer_run_dir}/writer/active.d"
  prime_join_writer_metadata="${prime_join_writer_path}/owner.json"
  [ -n "${PRIME_WRITER_TOKEN:-}" ] || return 1
  prime_writer_metadata_valid "${prime_join_writer_path}" "${prime_join_writer_run_dir}" || return 1
  [ "$(jq -r '.token' "${prime_join_writer_metadata}")" = "${PRIME_WRITER_TOKEN}" ] || return 1
  [ "$(jq -r '.run_dir' "${prime_join_writer_metadata}")" = "${prime_join_writer_run_dir}" ] || return 1
  export PRIME_WRITER_LEASE_HELD=1
  export PRIME_WRITER_LEASE_PATH="${prime_join_writer_path}"
  export PRIME_WRITER_LEASE_JOINED=1
}

prime_reclaim_stale_writer_lease() {
  prime_reclaim_writer_run_dir="$1"
  prime_reclaim_writer_path="${prime_reclaim_writer_run_dir}/writer/active.d"
  prime_reclaim_writer_metadata="${prime_reclaim_writer_path}/owner.json"
  [ -d "${prime_reclaim_writer_path}" ] || return 0
  if [ -f "${prime_reclaim_writer_metadata}" ]; then
    prime_writer_metadata_valid "${prime_reclaim_writer_path}" "${prime_reclaim_writer_run_dir}" && return 1
    prime_reclaim_writer_pid="$(jq -r '.pid // empty' "${prime_reclaim_writer_metadata}" 2>/dev/null || printf '')"
    prime_reclaim_writer_starttime="$(jq -r '.starttime // empty' "${prime_reclaim_writer_metadata}" 2>/dev/null || printf '')"
    prime_reclaim_writer_boot_id="$(jq -r '.boot_id // empty' "${prime_reclaim_writer_metadata}" 2>/dev/null || printf '')"
    if prime_process_identity_matches "${prime_reclaim_writer_pid}" "${prime_reclaim_writer_starttime}" "${prime_reclaim_writer_boot_id}"; then
      return 1
    fi
    jq -e '.schema_version == 1 and (.token | type == "string") and (.pid | type == "number") and (.starttime | type == "string") and (.boot_id | type == "string")' "${prime_reclaim_writer_metadata}" >/dev/null 2>&1 \
      || prime_lock_incomplete_is_stale "${prime_reclaim_writer_path}" || return 1
  else
    prime_lock_incomplete_is_stale "${prime_reclaim_writer_path}" || return 1
  fi
  prime_reclaim_writer_parent="${prime_reclaim_writer_run_dir}/writer"
  prime_reclaim_writer_quarantine="${prime_reclaim_writer_parent}/active.stale.$$.$(prime_random_hex 3)"
  prime_path_is_within "${prime_reclaim_writer_path}" "${prime_reclaim_writer_run_dir}" || return 111
  mv "${prime_reclaim_writer_path}" "${prime_reclaim_writer_quarantine}" 2>/dev/null || return 1
  prime_path_is_within "${prime_reclaim_writer_quarantine}" "${prime_reclaim_writer_run_dir}" || return 111
  rm -rf -- "${prime_reclaim_writer_quarantine}"
}

prime_write_writer_metadata() {
  prime_writer_run_dir="$1"
  prime_writer_path="$2"
  prime_writer_role="$3"
  prime_writer_token="$4"
  prime_writer_lease_secs="${PRIME_WRITER_LEASE_SECS:-300}"
  prime_writer_now="$(prime_epoch_now)"
  prime_writer_expires="$((prime_writer_now + prime_writer_lease_secs))"
  prime_writer_starttime="$(prime_proc_starttime "$$")" || return 111
  prime_writer_boot_id="$(prime_boot_id)" || return 111
  prime_writer_tmp="${prime_writer_path}/owner.json.tmp.$$"
  jq -n \
    --arg token "${prime_writer_token}" \
    --argjson pid "$$" \
    --arg starttime "${prime_writer_starttime}" \
    --arg boot_id "${prime_writer_boot_id}" \
    --arg run_dir "${prime_writer_run_dir}" \
    --arg role "${prime_writer_role}" \
    --arg acquired_at "$(prime_now_utc)" \
    --arg renewed_at "$(prime_now_utc)" \
    --argjson acquired_at_epoch "${prime_writer_now}" \
    --argjson expires_at_epoch "${prime_writer_expires}" \
    '{schema_version:1,token:$token,pid:$pid,starttime:$starttime,boot_id:$boot_id,run_dir:$run_dir,role:$role,acquired_at:$acquired_at,renewed_at:$renewed_at,acquired_at_epoch:$acquired_at_epoch,expires_at_epoch:$expires_at_epoch}' \
    > "${prime_writer_tmp}" || return 111
  chmod 600 "${prime_writer_tmp}"
  mv "${prime_writer_tmp}" "${prime_writer_path}/owner.json"
}

prime_acquire_writer_lease() {
  prime_acquire_writer_run_dir="$(prime_canonical_path "$1")" || return $?
  prime_acquire_writer_role="${2:-admin-once}"
  prime_acquire_writer_wait="${3:-nonblock}"
  prime_acquire_writer_root="${prime_acquire_writer_run_dir}/writer"
  prime_acquire_writer_path="${prime_acquire_writer_root}/active.d"
  prime_acquire_writer_started="$(prime_epoch_now)"
  prime_acquire_writer_timeout=""
  case "${prime_acquire_writer_role}" in ''|*[!a-zA-Z0-9._-]*) echo "invalid writer role: ${prime_acquire_writer_role}" >&2; return 111 ;; esac
  case "${prime_acquire_writer_wait}" in
    nonblock|block) ;;
    timeout:*) prime_acquire_writer_timeout="${prime_acquire_writer_wait#timeout:}"; case "${prime_acquire_writer_timeout}" in ''|*[!0-9]*) return 111 ;; esac ;;
    *) return 111 ;;
  esac
  # Re-entering in the lease-owning process is not a child join. Marking the
  # owner as joined would make the later release discard only its environment
  # and strand the live lease directory.
  if [ "${PRIME_WRITER_LEASE_OWNER_PID:-}" = "$$" ] \
    && [ "${PRIME_WRITER_LEASE_PATH:-}" = "${prime_acquire_writer_path}" ] \
    && prime_assert_write_authority "${prime_acquire_writer_run_dir}"; then
    return 0
  fi
  if prime_join_existing_writer_lease "${prime_acquire_writer_run_dir}"; then
    return 0
  fi
  mkdir -p "${prime_acquire_writer_root}"
  prime_path_is_within "${prime_acquire_writer_root}" "${prime_acquire_writer_run_dir}" || return 111
  chmod 700 "${prime_acquire_writer_root}"
  while :; do
    if mkdir -m 700 "${prime_acquire_writer_path}" 2>/dev/null; then
      prime_acquire_writer_token="$(prime_random_hex 16)"
      if ! prime_write_writer_metadata "${prime_acquire_writer_run_dir}" "${prime_acquire_writer_path}" "${prime_acquire_writer_role}" "${prime_acquire_writer_token}"; then
        rmdir "${prime_acquire_writer_path}" 2>/dev/null || true
        return 111
      fi
      export PRIME_WRITER_TOKEN="${prime_acquire_writer_token}"
      export PRIME_WRITER_LEASE_HELD=1
      export PRIME_WRITER_LEASE_PATH="${prime_acquire_writer_path}"
      export PRIME_WRITER_LEASE_OWNER_PID="$$"
      export PRIME_WRITER_ROLE="${prime_acquire_writer_role}"
      unset PRIME_WRITER_LEASE_JOINED
      return 0
    fi
    prime_reclaim_stale_writer_lease "${prime_acquire_writer_run_dir}" && continue
    case "${prime_acquire_writer_wait}" in
      nonblock) echo "writer lease busy: ${prime_acquire_writer_path}" >&2; return 75 ;;
      timeout:*) [ $(( $(prime_epoch_now) - prime_acquire_writer_started )) -lt "${prime_acquire_writer_timeout}" ] || { echo "writer lease busy: ${prime_acquire_writer_path}" >&2; return 75; } ;;
    esac
    sleep "${PRIME_LOCK_SLEEP_SECS:-1}"
  done
}

prime_refresh_writer_lease() {
  prime_refresh_writer_path="${PRIME_WRITER_LEASE_PATH:-}"
  [ -n "${prime_refresh_writer_path}" ] || return 111
  [ "${PRIME_WRITER_LEASE_JOINED:-0}" != "1" ] || return 111
  [ "${PRIME_WRITER_LEASE_OWNER_PID:-}" = "$$" ] || return 111
  prime_refresh_expected_run_dir="${prime_refresh_writer_path%/writer/active.d}"
  prime_writer_metadata_valid "${prime_refresh_writer_path}" "${prime_refresh_expected_run_dir}" || return 111
  [ "$(jq -r '.token' "${prime_refresh_writer_path}/owner.json")" = "${PRIME_WRITER_TOKEN:-}" ] || return 111
  prime_refresh_run_dir="$(jq -r '.run_dir' "${prime_refresh_writer_path}/owner.json")"
  prime_refresh_role="$(jq -r '.role' "${prime_refresh_writer_path}/owner.json")"
  prime_write_writer_metadata "${prime_refresh_run_dir}" "${prime_refresh_writer_path}" "${prime_refresh_role}" "${PRIME_WRITER_TOKEN}"
}

prime_assert_write_authority() {
  prime_assert_writer_run_dir="$(prime_canonical_path "$1")" || return $?
  prime_assert_writer_path="${prime_assert_writer_run_dir}/writer/active.d"
  [ -n "${PRIME_WRITER_TOKEN:-}" ] || return 77
  prime_writer_metadata_valid "${prime_assert_writer_path}" "${prime_assert_writer_run_dir}" || return 77
  [ "$(jq -r '.token' "${prime_assert_writer_path}/owner.json")" = "${PRIME_WRITER_TOKEN}" ] || return 77
  [ "$(jq -r '.run_dir' "${prime_assert_writer_path}/owner.json")" = "${prime_assert_writer_run_dir}" ] || return 77
}

prime_release_writer_lease() {
  prime_release_writer_path="${PRIME_WRITER_LEASE_PATH:-}"
  [ -n "${prime_release_writer_path}" ] || return 0
  if [ "${PRIME_WRITER_LEASE_JOINED:-0}" = "1" ]; then
    unset PRIME_WRITER_TOKEN PRIME_WRITER_LEASE_HELD PRIME_WRITER_LEASE_PATH PRIME_WRITER_LEASE_OWNER_PID PRIME_WRITER_ROLE PRIME_WRITER_LEASE_JOINED
    return 0
  fi
  [ "${PRIME_WRITER_LEASE_OWNER_PID:-}" = "$$" ] || return 0
  [ -n "${PRIME_WRITER_TOKEN:-}" ] || return 111
  prime_release_writer_metadata="${prime_release_writer_path}/owner.json"
  [ -f "${prime_release_writer_metadata}" ] || return 111
  [ "$(jq -r '.token' "${prime_release_writer_metadata}")" = "${PRIME_WRITER_TOKEN}" ] || return 111
  prime_release_writer_run_dir="$(jq -r '.run_dir' "${prime_release_writer_metadata}")"
  [ "${prime_release_writer_path}" = "${prime_release_writer_run_dir}/writer/active.d" ] || return 111
  prime_path_is_within "${prime_release_writer_path}" "${prime_release_writer_run_dir}" || return 111
  rm -rf -- "${prime_release_writer_path}"
  unset PRIME_WRITER_TOKEN PRIME_WRITER_LEASE_HELD PRIME_WRITER_LEASE_PATH PRIME_WRITER_LEASE_OWNER_PID PRIME_WRITER_ROLE PRIME_WRITER_LEASE_JOINED
}

prime_acquire_run_lock() {
  prime_acquire_run_dir="$(prime_canonical_path "$1")" || return $?
  prime_acquire_scope="${2:-exclusive}"
  prime_acquire_wait_mode="${3:-nonblock}"
  prime_acquire_lock_dir="${prime_acquire_run_dir}/locks"
  prime_acquire_lock_path="${prime_acquire_lock_dir}/run.lock.d"
  prime_acquire_sleep_step="${PRIME_LOCK_SLEEP_SECS:-1}"
  prime_acquire_timeout=""
  prime_acquire_started="$(prime_epoch_now)"

  case "${prime_acquire_scope}" in exclusive|shared|mutex) ;; *) echo "invalid lock scope: ${prime_acquire_scope}" >&2; return 111 ;; esac
  case "${prime_acquire_wait_mode}" in
    nonblock|block) ;;
    timeout:*) prime_acquire_timeout="${prime_acquire_wait_mode#timeout:}"; case "${prime_acquire_timeout}" in ''|*[!0-9]*) return 111 ;; esac ;;
    *) echo "invalid wait mode: ${prime_acquire_wait_mode}" >&2; return 111 ;;
  esac

  # Stateful run mutation is permitted only below the managed runs root.
  # Tests may opt into a separate root explicitly; mutexes protect other
  # bounded runtime objects and therefore do not use this policy.
  if [ "${prime_acquire_scope}" = "exclusive" ]; then
    prime_acquire_managed_root="$(prime_canonical_path "${PRIME_MANAGED_RUNS_ROOT:-${PROJECT_ROOT}/runtime/runs}")" || return $?
    prime_path_is_within "${prime_acquire_run_dir}" "${prime_acquire_managed_root}" || {
      echo "run is outside managed runs root: ${prime_acquire_run_dir}" >&2
      return 111
    }
  fi

  # A nested subprocess may join only by presenting the current lock token.
  # PRIME_SKIP_RUN_LOCK and PRIME_RUN_LOCK_HELD alone are never authority.
  if prime_join_existing_run_lock "${prime_acquire_run_dir}"; then
    if [ "${prime_acquire_scope}" = "exclusive" ] && command -v prime_recover_transactions >/dev/null 2>&1; then
      prime_recover_transactions "${prime_acquire_run_dir}" || { prime_release_run_lock || true; return 76; }
    fi
    return 0
  fi

  if [ "${prime_acquire_scope}" = "exclusive" ]; then
    prime_acquire_writer_lease "${prime_acquire_run_dir}" "${PRIME_WRITER_ROLE:-admin-once}" "${prime_acquire_wait_mode}" || return $?
  fi

  mkdir -p "${prime_acquire_lock_dir}"
  prime_path_is_within "${prime_acquire_lock_dir}" "${prime_acquire_run_dir}" || {
    echo "run lock directory escapes run: ${prime_acquire_lock_dir}" >&2
    return 111
  }
  chmod 700 "${prime_acquire_lock_dir}"
  while :; do
    if mkdir -m 700 "${prime_acquire_lock_path}" 2>/dev/null; then
      prime_acquire_token="$(prime_random_hex 16)"
      if ! prime_write_run_lock_metadata "${prime_acquire_run_dir}" "${prime_acquire_lock_path}" "${prime_acquire_scope}" "${prime_acquire_token}"; then
        rmdir "${prime_acquire_lock_path}" 2>/dev/null || true
        return 111
      fi
      export PRIME_RUN_LOCK_HELD=1
      export PRIME_RUN_LOCK_PATH="${prime_acquire_lock_path}"
      export PRIME_RUN_LOCK_SCOPE="${prime_acquire_scope}"
      export PRIME_RUN_LOCK_OWNER_PID="$$"
      export PRIME_RUN_LOCK_TOKEN="${prime_acquire_token}"
      unset PRIME_RUN_LOCK_JOINED
      if [ "${prime_acquire_scope}" = "exclusive" ] && command -v prime_recover_transactions >/dev/null 2>&1; then
        prime_recover_transactions "${prime_acquire_run_dir}" || { prime_release_run_lock || true; return 76; }
      fi
      return 0
    fi

    prime_reclaim_stale_run_lock "${prime_acquire_run_dir}" && continue
    case "${prime_acquire_wait_mode}" in
      nonblock) echo "run lock busy: ${prime_acquire_lock_path}" >&2; prime_release_writer_lease || true; return 75 ;;
      timeout:*)
        if [ $(( $(prime_epoch_now) - prime_acquire_started )) -ge "${prime_acquire_timeout}" ]; then
          echo "run lock busy: ${prime_acquire_lock_path}" >&2
          prime_release_writer_lease || true
          return 75
        fi
        ;;
    esac
    sleep "${prime_acquire_sleep_step}"
  done
}

prime_release_run_lock() {
  prime_release_lock_path="${PRIME_RUN_LOCK_PATH:-}"
  [ -n "${prime_release_lock_path}" ] || return 0

  if [ "${PRIME_RUN_LOCK_JOINED:-0}" = "1" ]; then
    unset PRIME_RUN_LOCK_HELD PRIME_RUN_LOCK_PATH PRIME_RUN_LOCK_SCOPE PRIME_RUN_LOCK_OWNER_PID PRIME_RUN_LOCK_TOKEN PRIME_RUN_LOCK_JOINED
    prime_release_writer_lease
    return 0
  fi
  [ "${PRIME_RUN_LOCK_OWNER_PID:-}" = "$$" ] || return 0
  [ -n "${PRIME_RUN_LOCK_TOKEN:-}" ] || return 111
  prime_release_metadata="${prime_release_lock_path}/owner.json"
  [ -f "${prime_release_metadata}" ] || return 111
  [ "$(jq -r '.token' "${prime_release_metadata}")" = "${PRIME_RUN_LOCK_TOKEN}" ] || return 111
  prime_release_run_dir="$(jq -r '.run_dir' "${prime_release_metadata}")"
  [ "${prime_release_lock_path}" = "${prime_release_run_dir}/locks/run.lock.d" ] || return 111
  prime_path_is_within "${prime_release_lock_path}" "${prime_release_run_dir}" || return 111
  rm -rf -- "${prime_release_lock_path}"
  unset PRIME_RUN_LOCK_HELD PRIME_RUN_LOCK_PATH PRIME_RUN_LOCK_SCOPE PRIME_RUN_LOCK_OWNER_PID PRIME_RUN_LOCK_TOKEN PRIME_RUN_LOCK_JOINED
  prime_release_writer_lease
}
