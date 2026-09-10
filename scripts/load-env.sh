#!/usr/bin/env bash

# This file is sourced by local entry-point scripts. .env intentionally uses
# Bash assignment syntax. Values already present in the calling environment win
# over values in the file, so one-off invocations remain possible.
mongodb_dam_load_env() {
  local helper_dir repo_root env_file env_file_was_explicit allexport_was_set
  local name index
  local -a names=() was_set=() previous_values=()

  helper_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  repo_root="$(cd "$helper_dir/.." && pwd)"
  env_file_was_explicit=false
  if [[ -n "${ENV_FILE:-}" ]]; then
    env_file="$ENV_FILE"
    env_file_was_explicit=true
  else
    env_file="$repo_root/.env"
  fi

  if [[ ! -e "$env_file" ]]; then
    if [[ "$env_file_was_explicit" == true ]]; then
      printf 'ENV_FILE does not exist: %s\n' "$env_file" >&2
      return 1
    fi
    return 0
  fi

  mapfile -t names < <(
    sed -nE 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=.*/\2/p' \
      "$env_file" | awk '!seen[$0]++'
  )

  for index in "${!names[@]}"; do
    name="${names[$index]}"
    if [[ -v "$name" ]]; then
      was_set[$index]=true
      previous_values[$index]="${!name}"
    else
      was_set[$index]=false
      previous_values[$index]=''
    fi
  done

  allexport_was_set=false
  if [[ $- == *a* ]]; then
    allexport_was_set=true
  else
    set -a
  fi

  # shellcheck disable=SC1090
  source "$env_file"

  if [[ "$allexport_was_set" == false ]]; then
    set +a
  fi

  for index in "${!names[@]}"; do
    if [[ "${was_set[$index]}" == true ]]; then
      name="${names[$index]}"
      printf -v "$name" '%s' "${previous_values[$index]}"
      export "$name"
    fi
  done
}

mongodb_dam_load_env
unset -f mongodb_dam_load_env
