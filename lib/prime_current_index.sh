#!/bin/sh

# Derived runtime pointers for operator hot paths. These references are never
# authority: every consumer validates containment and the referenced truth
# file. Missing or corrupt indexes fail closed and can be rebuilt explicitly.

prime_current_index_root() {
  printf '%s/index\n' "$1"
}

prime_current_index_key() {
  index_goal=$1
  index_wave=$2
  index_digest="$(printf '%s\0%s' "${index_goal}" "${index_wave}" | sha256sum)"
  printf '%s\n' "${index_digest%% *}"
}

prime_current_index_atomic_ref() {
  runs_root=$1
  ref_rel=$2
  target_dir=$3
  index_root="$(prime_current_index_root "${runs_root}")"
  ref_path="${index_root}/${ref_rel}"
  ref_parent="$(dirname -- "${ref_path}")"
  ref_tmp="${ref_parent}/.tmp-$(prime_random_hex 8)"
  force_publish=${4:-0}

  mkdir -p "${ref_parent}"
  chmod 700 "${index_root}" "${ref_parent}"
  : > "${index_root}/.publish.lock"
  chmod 600 "${index_root}/.publish.lock"
  (
    flock -x 9
    if [ "${force_publish}" != 1 ] && [ -L "${ref_path}" ]; then
      current_target="$(prime_canonical_path "${ref_path}" 2>/dev/null || true)"
      canonical_runs_root="$(prime_canonical_path "${runs_root}" 2>/dev/null || true)"
      current_basename="$(basename -- "${current_target}")"
      target_basename="$(basename -- "${target_dir}")"
      greatest_basename="$(printf '%s\n%s\n' "${current_basename}" "${target_basename}" | LC_ALL=C sort | tail -n 1)"
      if [ -n "${current_target}" ] \
        && [ "$(dirname -- "${current_target}")" = "${canonical_runs_root}" ] \
        && [ "${current_basename}" = "${greatest_basename}" ]; then
        exit 0
      fi
    fi
    ln -s "${target_dir}" "${ref_tmp}"
    mv -Tf "${ref_tmp}" "${ref_path}"
  ) 9>"${index_root}/.publish.lock"
  rm -f -- "${ref_tmp}"
}

prime_current_index_publish_run() {
  runs_root=$1
  run_dir=$2
  run_goal=$3
  run_wave=$4
  force_publish=${5:-0}
  run_key="$(prime_current_index_key "${run_goal}" "${run_wave}")"

  prime_current_index_atomic_ref "${runs_root}" "by-goal-wave/${run_key}" "${run_dir}" "${force_publish}"
  prime_current_index_atomic_ref "${runs_root}" latest-run "${run_dir}" "${force_publish}"
  case "${run_goal}" in
    optimismus-prime\ *\ wave)
      prime_current_index_atomic_ref "${runs_root}" latest-child-wave "${run_dir}" "${force_publish}"
      ;;
  esac
}

prime_current_index_resolve_ref() {
  runs_root=$1
  ref_rel=$2
  expected_goal=${3:-}
  expected_wave=${4:-}
  index_root="$(prime_current_index_root "${runs_root}")"
  ref_path="${index_root}/${ref_rel}"

  [ -L "${ref_path}" ] || return 1
  canonical_runs_root="$(prime_canonical_path "${runs_root}" 2>/dev/null)" || return 1
  resolved_run_dir="$(prime_canonical_path "${ref_path}" 2>/dev/null)" || return 1
  [ "${resolved_run_dir%/*}" = "${canonical_runs_root}" ] || return 1
  [ -d "${resolved_run_dir}" ] || return 1
  [ -f "${resolved_run_dir}/session_state.json" ] || return 1
  [ ! -L "${resolved_run_dir}/session_state.json" ] || return 1

  jq -e \
    --arg run_id "${resolved_run_dir##*/}" \
    --arg expected_goal "${expected_goal}" \
    --arg expected_wave "${expected_wave}" '
      (.run_id == $run_id)
      and ($expected_goal == "" or .goal == $expected_goal)
      and ($expected_wave == "" or .current_wave == $expected_wave)
    ' "${resolved_run_dir}/session_state.json" >/dev/null 2>&1 || return 1

  printf '%s\n' "${resolved_run_dir}"
}

prime_current_index_resolve_goal_wave() {
  runs_root=$1
  expected_goal=$2
  expected_wave=$3
  run_key="$(prime_current_index_key "${expected_goal}" "${expected_wave}")"
  prime_current_index_resolve_ref \
    "${runs_root}" "by-goal-wave/${run_key}" "${expected_goal}" "${expected_wave}"
}

prime_current_index_resolve_child_wave() {
  runs_root=$1
  resolved_run_dir="$(prime_current_index_resolve_ref "${runs_root}" latest-child-wave)" || return 1
  child_goal="$(jq -r '.goal // ""' "${resolved_run_dir}/session_state.json" 2>/dev/null)"
  case "${child_goal}" in
    optimismus-prime\ *\ wave)
      printf '%s\n' "${resolved_run_dir}"
      ;;
    *) return 1 ;;
  esac
}
