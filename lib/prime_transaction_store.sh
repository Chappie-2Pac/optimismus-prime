#!/bin/sh

prime_sha256_or_missing() {
  if [ -f "$1" ]; then
    sha256sum -- "$1" | awk '{print $1}'
  else
    printf 'missing\n'
  fi
}

prime_mode_or_missing() {
  if [ -f "$1" ]; then
    stat -c %a -- "$1"
  else
    printf 'missing\n'
  fi
}

prime_sync_path() {
  # GNU `sync -f PATH` calls syncfs(2) and flushes the entire containing
  # filesystem. A transaction needs fsync(2) semantics for this exact file or
  # directory; plain `sync PATH` provides that without stalling unrelated I/O.
  sync -- "$1"
}

prime_atomic_install() {
  prime_install_source="$1"
  prime_install_target="$2"
  prime_install_mode="${3:-600}"
  prime_install_parent="${prime_install_target%/*}"
  prime_install_tmp="${prime_install_target}.tmp.$$.$(prime_random_hex 3)"
  [ -f "${prime_install_source}" ] || return 111
  mkdir -p "${prime_install_parent}"
  cp -- "${prime_install_source}" "${prime_install_tmp}" || return 111
  chmod "${prime_install_mode}" "${prime_install_tmp}"
  prime_sync_path "${prime_install_tmp}"
  mv -- "${prime_install_tmp}" "${prime_install_target}"
  prime_sync_path "${prime_install_parent}"
}

prime_ledger_hwm() {
  prime_hwm_ledger="$1"
  prime_hwm_field="$2"
  prime_hwm_prefix="$3"
  [ -f "${prime_hwm_ledger}" ] || return 111
  jq -e -s 'all(.[]; type == "object")' "${prime_hwm_ledger}" >/dev/null 2>&1 || {
    echo "invalid JSONL ledger: ${prime_hwm_ledger}" >&2
    return 111
  }
  jq -r --arg field "${prime_hwm_field}" '.[$field] // ""' "${prime_hwm_ledger}" \
    | awk -v prefix="${prime_hwm_prefix}" '
      BEGIN { n=0 }
      {
        n++
        expected=sprintf("%s%03d", prefix, n)
        if ($0 != expected) {
          printf "ledger id drift at row %d: expected %s got %s\n", n, expected, $0 > "/dev/stderr"
          exit 111
        }
      }
      END { if (n >= 0) print n }
    '
}

prime_assert_ledger_state_hwm() {
  prime_assert_hwm_ledger="$1"
  prime_assert_hwm_state="$2"
  prime_assert_hwm_field="$3"
  prime_assert_hwm_prefix="$4"
  prime_assert_hwm_state_field="$5"
  prime_assert_ledger_value="$(prime_ledger_hwm "${prime_assert_hwm_ledger}" "${prime_assert_hwm_field}" "${prime_assert_hwm_prefix}")" || return $?
  prime_assert_state_value="$(jq -er --arg field "${prime_assert_hwm_state_field}" '.[$field] // 0 | if type == "number" then . else error("invalid state hwm") end' "${prime_assert_hwm_state}")" || return 111
  [ "${prime_assert_ledger_value}" = "${prime_assert_state_value}" ] || {
    echo "ledger/state hwm drift: ledger=${prime_assert_ledger_value} state=${prime_assert_state_value} field=${prime_assert_hwm_state_field}" >&2
    return 76
  }
  printf '%s\n' "${prime_assert_ledger_value}"
}

prime_assert_task_state_hwm() {
  prime_task_file="$1"
  prime_task_state="$2"
  jq -e '(.tasks | type == "array") and all(.tasks[]; type == "object")' "${prime_task_file}" >/dev/null 2>&1 || return 111
  prime_task_count="$({ jq -r '.tasks[] | .task_id // ""' "${prime_task_file}" \
    | awk '
      BEGIN { n=0 }
      {
        n++
        expected=sprintf("task-%03d", n)
        if ($0 != expected) { printf "task id drift at row %d: expected %s got %s\n", n, expected, $0 > "/dev/stderr"; exit 111 }
      }
      END { if (n >= 0) print n }
    '; } )" || return $?
  prime_task_state_hwm="$(jq -er '.latest_task_id // 0 | if type == "number" then . else error("invalid task hwm") end' "${prime_task_state}")" || return 111
  [ "${prime_task_count}" = "${prime_task_state_hwm}" ] || {
    echo "task/state hwm drift: tasks=${prime_task_count} state=${prime_task_state_hwm}" >&2
    return 76
  }
  printf '%s\n' "${prime_task_count}"
}

prime_tx_remove_dir() {
  prime_remove_tx_dir="$1"
  prime_remove_run_dir="$2"
  prime_path_is_within "${prime_remove_tx_dir}" "${prime_remove_run_dir}/tx" || return 111
  rm -rf -- "${prime_remove_tx_dir}"
}

prime_cleanup_committed_sources() {
  if [ "$#" -lt 1 ]; then
    echo "warning: transaction committed but caller temp cleanup received no run directory" >&2
    return 0
  fi
  prime_cleanup_run_dir="$(prime_canonical_path "$1" 2>/dev/null || printf '')"
  shift
  if [ -z "${prime_cleanup_run_dir}" ]; then
    echo "warning: transaction committed but caller temp cleanup could not resolve the run directory" >&2
    return 0
  fi
  prime_cleanup_tx_root="${prime_cleanup_run_dir}/tx"

  for prime_cleanup_source in "$@"; do
    [ -n "${prime_cleanup_source}" ] || continue
    [ -e "${prime_cleanup_source}" ] || [ -L "${prime_cleanup_source}" ] || continue
    if ! prime_path_is_within "${prime_cleanup_source}" "${prime_cleanup_tx_root}"; then
      echo "warning: transaction committed but caller temp cleanup escaped tx root: ${prime_cleanup_source}" >&2
      continue
    fi
    if [ -L "${prime_cleanup_source}" ] || [ ! -f "${prime_cleanup_source}" ]; then
      echo "warning: transaction committed but caller temp cleanup found an unexpected path type: ${prime_cleanup_source}" >&2
      continue
    fi
    if ! rm -f -- "${prime_cleanup_source}"; then
      echo "warning: transaction committed but caller temp cleanup failed: ${prime_cleanup_source}" >&2
    fi
  done

  # Once the durable commit returned successfully, cleanup failure must not
  # turn that committed mutation into a retryable mutation failure.
  return 0
}

prime_recover_file_set_transaction() {
  prime_file_set_tx_dir="$1"
  prime_file_set_run_dir="$2"
  prime_file_set_manifest="${prime_file_set_tx_dir}/manifest.json"
  jq -e '
    (.schema_version == 1)
    and (.targets | type == "array" and length > 0)
    and ([.targets[].index] == [range(1; (.targets | length) + 1)])
    and ([.targets[].name] | length == (unique | length))
    and ([.targets[].target] | length == (unique | length))
    and all(.targets[];
      (.name | type == "string" and test("^[A-Za-z0-9._-]+$"))
      and (.target | type == "string" and length > 0)
      and (.mode | type == "string" and test("^[0-7]{3}$"))
      and ((.old_mode == "missing") or (.old_mode | type == "string" and test("^[0-7]{3,4}$")))
      and ((.old_sha256 == "missing") or (.old_sha256 | type == "string" and test("^[0-9a-f]{64}$")))
      and (.new_sha256 | type == "string" and test("^[0-9a-f]{64}$")))
  ' "${prime_file_set_manifest}" >/dev/null 2>&1 || return 111

  prime_file_set_rows="$(
    jq -r '.targets[] | [.index,.name,.target,.mode,.old_mode,.old_sha256,.new_sha256] | @tsv' \
      "${prime_file_set_manifest}"
  )" || return 111
  prime_file_set_installed="false"
  while IFS="$(printf '\t')" read -r prime_file_index prime_file_name prime_file_target prime_file_mode prime_file_old_mode prime_file_old prime_file_new; do
    [ -n "${prime_file_index}" ] || continue
    prime_target_path_is_within "${prime_file_target}" "${prime_file_set_run_dir}" || return 111
    [ ! -L "${prime_file_target}" ] || return 111
    if [ -e "${prime_file_target}" ] && [ ! -f "${prime_file_target}" ]; then
      return 111
    fi
    prime_file_prepared="${prime_file_set_tx_dir}/target-${prime_file_index}.prepared"
    [ -f "${prime_file_prepared}" ] && [ ! -L "${prime_file_prepared}" ] || return 111
    [ "$(prime_sha256_or_missing "${prime_file_prepared}")" = "${prime_file_new}" ] || return 76
    prime_file_live="$(prime_sha256_or_missing "${prime_file_target}")"
    prime_file_live_mode="$(prime_mode_or_missing "${prime_file_target}")"
    if [ "${prime_file_live}" = "${prime_file_new}" ] && [ "${prime_file_live_mode}" = "${prime_file_mode}" ]; then
      if [ "${prime_file_old}" != "${prime_file_new}" ] || [ "${prime_file_old_mode}" != "${prime_file_mode}" ]; then
        prime_file_set_installed="true"
      fi
    elif [ "${prime_file_live}" != "${prime_file_old}" ] || [ "${prime_file_live_mode}" != "${prime_file_old_mode}" ]; then
      echo "file-set transaction target hash drift: ${prime_file_name}" >&2
      return 76
    fi
  done <<EOF
${prime_file_set_rows}
EOF

  if [ "${prime_file_set_installed}" != "true" ]; then
    prime_tx_remove_dir "${prime_file_set_tx_dir}" "${prime_file_set_run_dir}"
    return 0
  fi

  while IFS="$(printf '\t')" read -r prime_file_index prime_file_name prime_file_target prime_file_mode prime_file_old_mode prime_file_old prime_file_new; do
    [ -n "${prime_file_index}" ] || continue
    prime_file_live="$(prime_sha256_or_missing "${prime_file_target}")"
    prime_file_live_mode="$(prime_mode_or_missing "${prime_file_target}")"
    if [ "${prime_file_live}" = "${prime_file_old}" ] && [ "${prime_file_live_mode}" = "${prime_file_old_mode}" ]; then
      prime_atomic_install "${prime_file_set_tx_dir}/target-${prime_file_index}.prepared" "${prime_file_target}" "${prime_file_mode}"
    elif [ "${prime_file_live}" != "${prime_file_new}" ] || [ "${prime_file_live_mode}" != "${prime_file_mode}" ]; then
      echo "file-set transaction recovery hash drift: ${prime_file_name}" >&2
      return 76
    fi
  done <<EOF
${prime_file_set_rows}
EOF
  prime_tx_remove_dir "${prime_file_set_tx_dir}" "${prime_file_set_run_dir}"
}

prime_commit_file_set_transaction() {
  prime_file_set_run_dir="$(prime_canonical_path "$1")" || return $?
  prime_file_set_kind="$2"
  prime_file_set_mapping_json="$3"
  prime_file_set_metadata_json="${PRIME_TX_METADATA_JSON:-}"
  [ -n "${prime_file_set_metadata_json}" ] || prime_file_set_metadata_json='{}'
  prime_file_set_mapping_json="$(
    printf '%s\n' "${prime_file_set_mapping_json}" \
      | jq -ce '
          if type == "array" and length > 0
             and all(.[];
               (.name | type == "string" and test("^[A-Za-z0-9._-]+$"))
               and (.source | type == "string" and length > 0 and (test("[\\\\\\t\\n]") | not))
               and (.target | type == "string" and length > 0 and (test("[\\\\\\t\\n]") | not))
               and ((.mode // "600") | type == "string" and test("^[0-7]{3}$")))
             and ([.[].name] | length == (unique | length))
             and ([.[].target] | length == (unique | length))
          then . else error("invalid or duplicate file-set transaction mapping") end
        '
  )" || return 111
  prime_file_set_metadata_json="$(
    printf '%s\n' "${prime_file_set_metadata_json}" \
      | jq -ce 'if type == "object" then . else error("PRIME_TX_METADATA_JSON must be a JSON object") end'
  )" || return 111

  prime_file_set_tx_id="tx-$(date -u +%Y%m%dT%H%M%SZ)-$$-$(prime_random_hex 4)"
  prime_file_set_tx_root="${prime_file_set_run_dir}/tx"
  prime_file_set_tx_dir="${prime_file_set_tx_root}/${prime_file_set_tx_id}.d"
  mkdir -p "${prime_file_set_tx_root}"
  chmod 700 "${prime_file_set_tx_root}"
  mkdir -m 700 "${prime_file_set_tx_dir}"
  prime_file_set_rows="$(
    printf '%s\n' "${prime_file_set_mapping_json}" \
      | jq -r 'to_entries[] | [(.key + 1),.value.name,.value.source,.value.target,(.value.mode // "600")] | @tsv'
  )" || return 111

  : > "${prime_file_set_tx_dir}/targets.jsonl"
  while IFS="$(printf '\t')" read -r prime_file_index prime_file_name prime_file_source prime_file_target prime_file_mode; do
    [ -n "${prime_file_index}" ] || continue
    [ -f "${prime_file_source}" ] && [ ! -L "${prime_file_source}" ] || return 111
    prime_file_source="$(prime_canonical_path "${prime_file_source}")" || return $?
    prime_path_is_within "${prime_file_source}" "${prime_file_set_tx_root}" || return 111
    [ ! -L "${prime_file_target}" ] || return 111
    prime_file_target="$(prime_canonical_target_path "${prime_file_target}")" || return $?
    prime_target_path_is_within "${prime_file_target}" "${prime_file_set_run_dir}" || return 111
    [ ! -L "${prime_file_target}" ] || return 111
    if [ -e "${prime_file_target}" ] && [ ! -f "${prime_file_target}" ]; then
      return 111
    fi
    prime_file_prepared="${prime_file_set_tx_dir}/target-${prime_file_index}.prepared"
    cp -- "${prime_file_source}" "${prime_file_prepared}"
    chmod "${prime_file_mode}" "${prime_file_prepared}"
    jq -nc \
      --argjson index "${prime_file_index}" \
      --arg name "${prime_file_name}" \
      --arg target "${prime_file_target}" \
      --arg mode "${prime_file_mode}" \
      --arg old_mode "$(prime_mode_or_missing "${prime_file_target}")" \
      --arg old_sha256 "$(prime_sha256_or_missing "${prime_file_target}")" \
      --arg new_sha256 "$(prime_sha256_or_missing "${prime_file_prepared}")" \
      '{index:$index,name:$name,target:$target,mode:$mode,old_mode:$old_mode,old_sha256:$old_sha256,new_sha256:$new_sha256}' \
      >> "${prime_file_set_tx_dir}/targets.jsonl"
  done <<EOF
${prime_file_set_rows}
EOF

  jq -n \
    --arg tx_id "${prime_file_set_tx_id}" \
    --arg kind "${prime_file_set_kind}" \
    --arg created_at "$(prime_now_utc)" \
    --argjson metadata "${prime_file_set_metadata_json}" \
    --slurpfile targets "${prime_file_set_tx_dir}/targets.jsonl" \
    '{schema_version:1,tx_id:$tx_id,kind:$kind,created_at:$created_at,metadata:$metadata,targets:$targets}' \
    > "${prime_file_set_tx_dir}/manifest.json"
  rm -f -- "${prime_file_set_tx_dir}/targets.jsonl"
  if ! jq -e '
    ([.targets[].target] | length == (unique | length))
    and ([.targets[].name] | length == (unique | length))
  ' "${prime_file_set_tx_dir}/manifest.json" >/dev/null; then
    prime_tx_remove_dir "${prime_file_set_tx_dir}" "${prime_file_set_run_dir}"
    return 111
  fi
  chmod 600 "${prime_file_set_tx_dir}"/target-*.prepared "${prime_file_set_tx_dir}/manifest.json"
  for prime_file_prepared in "${prime_file_set_tx_dir}"/target-*.prepared; do
    prime_sync_path "${prime_file_prepared}"
  done
  prime_sync_path "${prime_file_set_tx_dir}/manifest.json"
  prime_sync_path "${prime_file_set_tx_dir}"
  [ "${PRIME_TX_FAIL_AFTER:-}" != "prepared" ] || return 99

  prime_file_set_manifest_rows="$(
    jq -r '.targets[] | [.index,.target,.mode] | @tsv' "${prime_file_set_tx_dir}/manifest.json"
  )" || return 111
  while IFS="$(printf '\t')" read -r prime_file_index prime_file_target prime_file_mode; do
    [ -n "${prime_file_index}" ] || continue
    prime_atomic_install "${prime_file_set_tx_dir}/target-${prime_file_index}.prepared" "${prime_file_target}" "${prime_file_mode}"
    [ "${PRIME_TX_FAIL_AFTER:-}" != "target-${prime_file_index}" ] || return 99
  done <<EOF
${prime_file_set_manifest_rows}
EOF
  prime_tx_remove_dir "${prime_file_set_tx_dir}" "${prime_file_set_run_dir}"
}

prime_recover_pre_manifest_transaction() {
  prime_pre_manifest_tx_dir="$1"
  prime_pre_manifest_run_dir="$2"
  [ -d "${prime_pre_manifest_tx_dir}" ] && [ ! -L "${prime_pre_manifest_tx_dir}" ] || return 111
  prime_path_is_within "${prime_pre_manifest_tx_dir}" "${prime_pre_manifest_run_dir}/tx" || return 111
  for prime_pre_manifest_entry in \
    "${prime_pre_manifest_tx_dir}"/* \
    "${prime_pre_manifest_tx_dir}"/.[!.]* \
    "${prime_pre_manifest_tx_dir}"/..?*; do
    [ -e "${prime_pre_manifest_entry}" ] || [ -L "${prime_pre_manifest_entry}" ] || continue
    [ -f "${prime_pre_manifest_entry}" ] && [ ! -L "${prime_pre_manifest_entry}" ] || return 111
    prime_pre_manifest_name="${prime_pre_manifest_entry##*/}"
    case "${prime_pre_manifest_name}" in
      targets.jsonl|ledger.prepared|state.prepared|extra.prepared|third.prepared) ;;
      target-*.prepared)
        prime_pre_manifest_index="${prime_pre_manifest_name#target-}"
        prime_pre_manifest_index="${prime_pre_manifest_index%.prepared}"
        case "${prime_pre_manifest_index}" in
          ""|*[!0-9]*) return 111 ;;
        esac
        ;;
      *) return 111 ;;
    esac
  done
  prime_tx_remove_dir "${prime_pre_manifest_tx_dir}" "${prime_pre_manifest_run_dir}"
}

prime_recover_one_transaction() {
  prime_recover_tx_dir="$1"
  prime_recover_run_dir="$2"
  prime_recover_manifest="${prime_recover_tx_dir}/manifest.json"
  if [ ! -f "${prime_recover_manifest}" ]; then
    [ ! -L "${prime_recover_manifest}" ] || return 111
    prime_recover_pre_manifest_transaction "${prime_recover_tx_dir}" "${prime_recover_run_dir}"
    return $?
  fi
  if jq -e '(.targets | type == "array")' "${prime_recover_manifest}" >/dev/null 2>&1; then
    prime_recover_file_set_transaction "${prime_recover_tx_dir}" "${prime_recover_run_dir}"
    return $?
  fi
  prime_recover_ledger_target="$(jq -er '.ledger.target' "${prime_recover_manifest}")" || return 111
  prime_recover_state_target="$(jq -er '.state.target' "${prime_recover_manifest}")" || return 111
  prime_recover_state_prepared="${prime_recover_tx_dir}/state.prepared"
  prime_recover_ledger_old="$(jq -er '.ledger.old_sha256' "${prime_recover_manifest}")" || return 111
  prime_recover_ledger_new="$(jq -er '.ledger.new_sha256' "${prime_recover_manifest}")" || return 111
  prime_recover_state_old="$(jq -er '.state.old_sha256' "${prime_recover_manifest}")" || return 111
  prime_recover_state_new="$(jq -er '.state.new_sha256' "${prime_recover_manifest}")" || return 111
  prime_path_is_within "${prime_recover_ledger_target}" "${prime_recover_run_dir}" || return 111
  prime_path_is_within "${prime_recover_state_target}" "${prime_recover_run_dir}" || return 111
  prime_recover_live_ledger="$(prime_sha256_or_missing "${prime_recover_ledger_target}")"
  prime_recover_live_state="$(prime_sha256_or_missing "${prime_recover_state_target}")"
  prime_recover_third_target="$(jq -r '.third.target // ""' "${prime_recover_manifest}")"
  prime_recover_live_third=""
  prime_recover_third_old=""
  prime_recover_third_new=""
  if [ -n "${prime_recover_third_target}" ]; then
    prime_path_is_within "${prime_recover_third_target}" "${prime_recover_run_dir}" || return 111
    prime_recover_third_old="$(jq -r '.third.old_sha256' "${prime_recover_manifest}")"
    prime_recover_third_new="$(jq -r '.third.new_sha256' "${prime_recover_manifest}")"
    prime_recover_live_third="$(prime_sha256_or_missing "${prime_recover_third_target}")"
  fi

  if [ "${prime_recover_live_ledger}" = "${prime_recover_ledger_old}" ]; then
    [ "${prime_recover_live_state}" = "${prime_recover_state_old}" ] || return 76
    [ -z "${prime_recover_third_target}" ] || [ "${prime_recover_live_third}" = "${prime_recover_third_old}" ] || return 76
    prime_recover_extra_target="$(jq -r '.extra.target // ""' "${prime_recover_manifest}")"
    if [ -n "${prime_recover_extra_target}" ] && [ -f "${prime_recover_extra_target}" ]; then
      prime_recover_extra_new="$(jq -r '.extra.new_sha256' "${prime_recover_manifest}")"
      [ "$(prime_sha256_or_missing "${prime_recover_extra_target}")" = "${prime_recover_extra_new}" ] || return 76
      prime_path_is_within "${prime_recover_extra_target}" "${prime_recover_run_dir}" || return 111
      rm -f -- "${prime_recover_extra_target}"
    fi
    prime_tx_remove_dir "${prime_recover_tx_dir}" "${prime_recover_run_dir}"
    return 0
  fi

  [ "${prime_recover_live_ledger}" = "${prime_recover_ledger_new}" ] || return 76
  if [ -n "${prime_recover_third_target}" ]; then
    if [ "${prime_recover_live_third}" = "${prime_recover_third_old}" ]; then
      [ "$(prime_sha256_or_missing "${prime_recover_tx_dir}/third.prepared")" = "${prime_recover_third_new}" ] || return 76
      prime_atomic_install "${prime_recover_tx_dir}/third.prepared" "${prime_recover_third_target}" 600
    elif [ "${prime_recover_live_third}" != "${prime_recover_third_new}" ]; then
      return 76
    fi
  fi
  if [ "${prime_recover_live_state}" = "${prime_recover_state_old}" ]; then
    [ "$(prime_sha256_or_missing "${prime_recover_state_prepared}")" = "${prime_recover_state_new}" ] || return 76
    prime_atomic_install "${prime_recover_state_prepared}" "${prime_recover_state_target}" 600
  elif [ "${prime_recover_live_state}" != "${prime_recover_state_new}" ]; then
    return 76
  fi

  prime_recover_extra_target="$(jq -r '.extra.target // ""' "${prime_recover_manifest}")"
  if [ -n "${prime_recover_extra_target}" ]; then
    prime_recover_extra_new="$(jq -r '.extra.new_sha256' "${prime_recover_manifest}")"
    prime_recover_extra_prepared="${prime_recover_tx_dir}/extra.prepared"
    if [ "$(prime_sha256_or_missing "${prime_recover_extra_target}")" != "${prime_recover_extra_new}" ]; then
      [ "$(prime_sha256_or_missing "${prime_recover_extra_prepared}")" = "${prime_recover_extra_new}" ] || return 76
      prime_path_is_within "${prime_recover_extra_target%/*}" "${prime_recover_run_dir}" || return 111
      prime_atomic_install "${prime_recover_extra_prepared}" "${prime_recover_extra_target}" 600
    fi
  fi
  prime_tx_remove_dir "${prime_recover_tx_dir}" "${prime_recover_run_dir}"
}

prime_recover_transactions() {
  prime_recover_run_dir="$(prime_canonical_path "$1")" || return $?
  prime_recover_root="${prime_recover_run_dir}/tx"
  [ -d "${prime_recover_root}" ] || return 0
  for prime_recover_candidate in "${prime_recover_root}"/tx-*.d; do
    [ -d "${prime_recover_candidate}" ] || continue
    prime_recover_one_transaction "${prime_recover_candidate}" "${prime_recover_run_dir}" || {
      echo "transaction recovery blocked: ${prime_recover_candidate}" >&2
      return 76
    }
  done
}

prime_commit_ledger_state_transaction() {
  prime_commit_run_dir="$(prime_canonical_path "$1")" || return $?
  prime_commit_kind="$2"
  prime_commit_ledger_target="$3"
  prime_commit_state_target="$4"
  prime_commit_ledger_source="$5"
  prime_commit_state_source="$6"
  prime_commit_extra_source="${7:-}"
  prime_commit_extra_target="${8:-}"
  prime_commit_third_source="${9:-}"
  prime_commit_third_target="${10:-}"
  prime_commit_metadata_json="${PRIME_TX_METADATA_JSON:-}"
  [ -n "${prime_commit_metadata_json}" ] || prime_commit_metadata_json='{}'
  prime_commit_metadata_json="$(
    printf '%s\n' "${prime_commit_metadata_json}" \
      | jq -ce 'if type == "object" then . else error("PRIME_TX_METADATA_JSON must be a JSON object") end'
  )" || return 111
  prime_commit_tx_id="tx-$(date -u +%Y%m%dT%H%M%SZ)-$$-$(prime_random_hex 4)"
  prime_commit_tx_root="${prime_commit_run_dir}/tx"
  prime_commit_tx_dir="${prime_commit_tx_root}/${prime_commit_tx_id}.d"
  mkdir -p "${prime_commit_tx_root}"
  chmod 700 "${prime_commit_tx_root}"
  mkdir -m 700 "${prime_commit_tx_dir}"
  cp -- "${prime_commit_ledger_source}" "${prime_commit_tx_dir}/ledger.prepared"
  cp -- "${prime_commit_state_source}" "${prime_commit_tx_dir}/state.prepared"
  chmod 600 "${prime_commit_tx_dir}/ledger.prepared" "${prime_commit_tx_dir}/state.prepared"
  if [ -n "${prime_commit_extra_source}" ]; then
    [ -n "${prime_commit_extra_target}" ] || return 111
    cp -- "${prime_commit_extra_source}" "${prime_commit_tx_dir}/extra.prepared"
    chmod 600 "${prime_commit_tx_dir}/extra.prepared"
  fi
  if [ -n "${prime_commit_third_source}" ]; then
    [ -n "${prime_commit_third_target}" ] || return 111
    cp -- "${prime_commit_third_source}" "${prime_commit_tx_dir}/third.prepared"
    chmod 600 "${prime_commit_tx_dir}/third.prepared"
    prime_path_is_within "${prime_commit_third_target}" "${prime_commit_run_dir}" || return 111
  fi
  prime_path_is_within "${prime_commit_ledger_target}" "${prime_commit_run_dir}" || return 111
  prime_path_is_within "${prime_commit_state_target}" "${prime_commit_run_dir}" || return 111
  if [ -n "${prime_commit_extra_target}" ]; then
    prime_path_is_within "${prime_commit_extra_target%/*}" "${prime_commit_run_dir}" || return 111
  fi
  prime_commit_extra_new=""
  prime_commit_third_old=""
  prime_commit_third_new=""
  [ -z "${prime_commit_extra_source}" ] || prime_commit_extra_new="$(prime_sha256_or_missing "${prime_commit_tx_dir}/extra.prepared")"
  if [ -n "${prime_commit_third_source}" ]; then
    prime_commit_third_old="$(prime_sha256_or_missing "${prime_commit_third_target}")"
    prime_commit_third_new="$(prime_sha256_or_missing "${prime_commit_tx_dir}/third.prepared")"
  fi
  jq -n \
    --arg tx_id "${prime_commit_tx_id}" \
    --arg kind "${prime_commit_kind}" \
    --arg created_at "$(prime_now_utc)" \
    --arg ledger_target "${prime_commit_ledger_target}" \
    --arg ledger_old "$(prime_sha256_or_missing "${prime_commit_ledger_target}")" \
    --arg ledger_new "$(prime_sha256_or_missing "${prime_commit_tx_dir}/ledger.prepared")" \
    --arg state_target "${prime_commit_state_target}" \
    --arg state_old "$(prime_sha256_or_missing "${prime_commit_state_target}")" \
    --arg state_new "$(prime_sha256_or_missing "${prime_commit_tx_dir}/state.prepared")" \
    --arg extra_target "${prime_commit_extra_target}" \
    --arg extra_new "${prime_commit_extra_new}" \
    --arg third_target "${prime_commit_third_target}" \
    --arg third_old "${prime_commit_third_old}" \
    --arg third_new "${prime_commit_third_new}" \
    --argjson metadata "${prime_commit_metadata_json}" \
    '{schema_version:1,tx_id:$tx_id,kind:$kind,created_at:$created_at,ledger:{target:$ledger_target,old_sha256:$ledger_old,new_sha256:$ledger_new},state:{target:$state_target,old_sha256:$state_old,new_sha256:$state_new},metadata:$metadata}
     + (if $extra_target != "" then {extra:{target:$extra_target,new_sha256:$extra_new}} else {} end)
     + (if $third_target != "" then {third:{target:$third_target,old_sha256:$third_old,new_sha256:$third_new}} else {} end)' \
    > "${prime_commit_tx_dir}/manifest.json"
  chmod 600 "${prime_commit_tx_dir}/manifest.json"
  prime_sync_path "${prime_commit_tx_dir}/ledger.prepared"
  prime_sync_path "${prime_commit_tx_dir}/state.prepared"
  [ -z "${prime_commit_extra_source}" ] || prime_sync_path "${prime_commit_tx_dir}/extra.prepared"
  [ -z "${prime_commit_third_source}" ] || prime_sync_path "${prime_commit_tx_dir}/third.prepared"
  prime_sync_path "${prime_commit_tx_dir}/manifest.json"
  prime_sync_path "${prime_commit_tx_dir}"
  [ "${PRIME_TX_FAIL_AFTER:-}" != "prepared" ] || return 99
  if [ -n "${prime_commit_extra_source}" ]; then
    prime_atomic_install "${prime_commit_tx_dir}/extra.prepared" "${prime_commit_extra_target}" 600
  fi
  prime_atomic_install "${prime_commit_tx_dir}/ledger.prepared" "${prime_commit_ledger_target}" 600
  [ "${PRIME_TX_FAIL_AFTER:-}" != "ledger" ] || return 99
  if [ -n "${prime_commit_third_source}" ]; then
    prime_atomic_install "${prime_commit_tx_dir}/third.prepared" "${prime_commit_third_target}" 600
  fi
  [ "${PRIME_TX_FAIL_AFTER:-}" != "third" ] || return 99
  prime_atomic_install "${prime_commit_tx_dir}/state.prepared" "${prime_commit_state_target}" 600
  [ "${PRIME_TX_FAIL_AFTER:-}" != "state" ] || return 99
  prime_tx_remove_dir "${prime_commit_tx_dir}" "${prime_commit_run_dir}"
}
