#!/bin/sh

prime_require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    return 111
  }
}

prime_now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

prime_random_hex() {
  byte_count="${1:-3}"
  od -An -N "${byte_count}" -tx1 /dev/urandom | tr -d ' \n'
}

prime_make_temp_file() {
  prime_tmp_root="${TMPDIR:-/tmp}"
  prime_tmp_prefix="${1:-prime}"
  prime_tmp_suffix="${2:-tmp}"
  prime_tmp_try=0

  [ -d "${prime_tmp_root}" ] || {
    echo "missing temp root: ${prime_tmp_root}" >&2
    return 111
  }

  while [ "${prime_tmp_try}" -lt 32 ]; do
    prime_tmp_path="${prime_tmp_root}/${prime_tmp_prefix}.$$.$(prime_random_hex 3).${prime_tmp_suffix}"
    if (umask 077 && set -C && : > "${prime_tmp_path}") 2>/dev/null; then
      printf '%s\n' "${prime_tmp_path}"
      return 0
    fi
    prime_tmp_try=$((prime_tmp_try + 1))
  done

  echo "failed to create temp file in ${prime_tmp_root}" >&2
  return 111
}

prime_slugify() {
  printf '%s' "${1:-}" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9][^a-z0-9]*/-/g; s/^-//; s/-$//'
}

prime_canonical_path() {
  input_path="$1"
  path_name=""
  path_dir=""
  dir_abs=""
  absolute_path=""
  link_target=""

  [ -n "${input_path}" ] || {
    echo "missing path" >&2
    return 111
  }

  if [ -d "${input_path}" ]; then
    (
      cd "${input_path}" 2>/dev/null && pwd -P
    ) || {
      echo "cannot resolve directory: ${input_path}" >&2
      return 111
    }
    return 0
  fi

  if [ ! -e "${input_path}" ] && [ ! -L "${input_path}" ]; then
    echo "missing path: ${input_path}" >&2
    return 111
  fi

  path_name="${input_path##*/}"
  path_dir="${input_path%/*}"
  if [ "${path_dir}" = "${input_path}" ]; then
    path_dir="."
  fi

  dir_abs="$(
    cd "${path_dir}" 2>/dev/null && pwd -P
  )" || {
    echo "cannot resolve parent directory: ${input_path}" >&2
    return 111
  }
  absolute_path="${dir_abs}/${path_name}"

  if [ -L "${absolute_path}" ] && command -v readlink >/dev/null 2>&1; then
    link_target="$(readlink "${absolute_path}")" || link_target=""
    if [ -n "${link_target}" ]; then
      case "${link_target}" in
        /*) prime_canonical_path "${link_target}" && return 0 ;;
        *) prime_canonical_path "${dir_abs}/${link_target}" && return 0 ;;
      esac
    fi
  fi

  printf '%s\n' "${absolute_path}"
}

prime_canonical_target_path() {
  prime_target_input="$1"
  prime_target_name=""
  prime_target_parent=""
  prime_target_parent_abs=""

  [ -n "${prime_target_input}" ] || {
    echo "missing target path" >&2
    return 111
  }
  if [ -e "${prime_target_input}" ] || [ -L "${prime_target_input}" ]; then
    prime_canonical_path "${prime_target_input}"
    return $?
  fi

  prime_target_name="${prime_target_input##*/}"
  prime_target_parent="${prime_target_input%/*}"
  [ -n "${prime_target_name}" ] || {
    echo "missing target basename: ${prime_target_input}" >&2
    return 111
  }
  if [ "${prime_target_parent}" = "${prime_target_input}" ]; then
    prime_target_parent="."
  fi
  prime_target_parent_abs="$(prime_canonical_path "${prime_target_parent}")" || {
    echo "cannot resolve target parent: ${prime_target_input}" >&2
    return 111
  }
  [ -d "${prime_target_parent_abs}" ] || {
    echo "target parent is not a directory: ${prime_target_parent_abs}" >&2
    return 111
  }
  printf '%s/%s\n' "${prime_target_parent_abs}" "${prime_target_name}"
}

prime_target_path_is_within() {
  prime_target_child="$(prime_canonical_target_path "$1" 2>/dev/null || printf '')"
  prime_target_root="$(prime_canonical_path "$2" 2>/dev/null || printf '')"
  [ -n "${prime_target_child}" ] && [ -n "${prime_target_root}" ] || return 1
  case "${prime_target_child}" in
    "${prime_target_root}"|"${prime_target_root}"/*) return 0 ;;
    *) return 1 ;;
  esac
}

prime_resolve_run_dir() {
  project_root="$1"
  run_arg="$2"

  if [ "${run_arg}" = "latest" ]; then
    prime_canonical_path "${project_root}/runtime/runs/latest"
  else
    prime_canonical_path "${run_arg}"
  fi
}

prime_resolve_workloop_dir() {
  project_root="$1"
  loop_arg="$2"
  loop_root="${3:-${project_root}/runtime/workloops}"

  if [ "${loop_arg}" = "latest" ] || [ "${loop_arg}" = "latest-chappie-until" ]; then
    prime_canonical_path "${loop_root}/latest-chappie-until"
  elif [ "${loop_arg#latest-}" != "${loop_arg}" ]; then
    prime_canonical_path "${loop_root}/${loop_arg}"
  else
    prime_canonical_path "${loop_arg}"
  fi
}

if [ -n "${PROJECT_ROOT:-}" ] && [ -f "${PROJECT_ROOT}/lib/prime_runtime_guard.sh" ]; then
  . "${PROJECT_ROOT}/lib/prime_runtime_guard.sh"
fi
if [ -n "${PROJECT_ROOT:-}" ] && [ -f "${PROJECT_ROOT}/lib/prime_delegation_store.sh" ]; then
  . "${PROJECT_ROOT}/lib/prime_delegation_store.sh"
fi
if [ -n "${PROJECT_ROOT:-}" ] && [ -f "${PROJECT_ROOT}/lib/prime_transaction_store.sh" ]; then
  . "${PROJECT_ROOT}/lib/prime_transaction_store.sh"
fi
