#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=load-env.sh
source "$repo_root/scripts/load-env.sh"

for command_name in curl jq; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

api_port="${DIRECT_USER_API_LOCAL_PORT:-18082}"
curl --fail-with-body --silent --show-error \
  --request DELETE \
  "http://127.0.0.1:$api_port/v1/customer-records?demo_batch=iam-bulk-delete" \
  | jq .
