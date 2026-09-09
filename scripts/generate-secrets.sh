#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-$repo_root/deploy/examples/secrets.local.env}"

if [[ -e "$output" ]]; then
  printf 'Refusing to overwrite existing secret file: %s\n' "$output" >&2
  exit 1
fi

umask 077
mkdir -p "$(dirname "$output")"
observer_token="$(openssl rand -hex 32)"
collect_token="$(openssl rand -hex 32)"
principal_salt="$(openssl rand -hex 32)"
mongodb_password="$(openssl rand -base64 32 | tr -d '\n')"

{
  printf 'OBSERVER_INTERNAL_TOKEN=%q\n' "$observer_token"
  printf 'COLLECT_TOKEN=%q\n' "$collect_token"
  printf 'PRINCIPAL_HASH_SALT=%q\n' "$principal_salt"
  printf 'MONGODB_ROOT_USERNAME=%q\n' 'dam-admin'
  printf 'MONGODB_ROOT_PASSWORD=%q\n' "$mongodb_password"
} > "$output"

chmod 600 "$output"
printf 'Wrote local secret environment file (mode 0600): %s\n' "$output"
printf '%s\n' 'The generated COLLECT_TOKEN must also be provisioned in the regional cell.'
