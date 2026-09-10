#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
template="$repo_root/.env.example"
output="${1:-$repo_root/.env}"

if [[ -e "$output" ]]; then
  printf 'Refusing to overwrite existing secret file: %s\n' "$output" >&2
  exit 1
fi

umask 077
mkdir -p "$(dirname "$output")"
observer_token="$(openssl rand -hex 32)"
bearer_token="$(openssl rand -hex 32)"
principal_salt="$(openssl rand -hex 32)"
mongodb_password="$(openssl rand -base64 32 | tr -d '\n')"

while IFS= read -r line || [[ -n "$line" ]]; do
  case "$line" in
    OBSERVER_INTERNAL_TOKEN=*)
      printf 'OBSERVER_INTERNAL_TOKEN=%q\n' "$observer_token"
      ;;
    BEARER_TOKEN=*)
      printf 'BEARER_TOKEN=%q\n' "$bearer_token"
      ;;
    PRINCIPAL_HASH_SALT=*)
      printf 'PRINCIPAL_HASH_SALT=%q\n' "$principal_salt"
      ;;
    MONGODB_ROOT_PASSWORD=*)
      printf 'MONGODB_ROOT_PASSWORD=%q\n' "$mongodb_password"
      ;;
    *)
      printf '%s\n' "$line"
      ;;
  esac
done < "$template" > "$output"

chmod 600 "$output"
printf 'Wrote complete local environment file (mode 0600): %s\n' "$output"
printf '%s\n' 'Fill the blank target-account, registry, S3, and IAM-principal values before deploying.'
printf '%s\n' 'Local entry-point scripts load this file automatically; no source/export step is required.'
