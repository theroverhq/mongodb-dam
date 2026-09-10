#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

grep -Eq '^/?\.env$' "$repo_root/.gitignore" || {
  printf '%s\n' 'Root .env is not excluded from Git.' >&2
  exit 1
}
grep -qxF '.env' "$repo_root/.dockerignore" || {
  printf '%s\n' 'Root .env is not excluded from the Docker build context.' >&2
  exit 1
}

test_env="$tmp_dir/test.env"
generated_env="$tmp_dir/generated.env"
printf '%s\n' \
  'MONGODB_DAM_TEST_FROM_FILE="value with spaces"' \
  'MONGODB_DAM_TEST_OVERRIDE=from-file' \
  'MONGODB_DAM_TEST_EMPTY=' >"$test_env"

MONGODB_DAM_TEST_OVERRIDE=from-caller \
ENV_FILE="$test_env" \
bash -ceu '
  source "$1/scripts/load-env.sh"
  [[ "$MONGODB_DAM_TEST_FROM_FILE" == "value with spaces" ]]
  [[ "$MONGODB_DAM_TEST_OVERRIDE" == from-caller ]]
  [[ -v MONGODB_DAM_TEST_EMPTY ]]
  bash -ceu '\''[[ "$MONGODB_DAM_TEST_FROM_FILE" == "value with spaces" ]]'\''
' _ "$repo_root"

if ENV_FILE="$tmp_dir/missing.env" bash -ceu \
  'source "$1/scripts/load-env.sh"' _ "$repo_root" >/dev/null 2>&1; then
  printf '%s\n' 'load-env accepted an explicitly selected missing file.' >&2
  exit 1
fi

"$repo_root/scripts/generate-secrets.sh" "$generated_env" >/dev/null
for variable_name in \
  EXPECTED_KUBE_CONTEXT CUSTOMER_ID TENANT_ID SOURCE_ID REGIONAL_CELL_ID \
  CLUSTER_NAME OUTPOST_DESTINATION OUTPOST_S3_BUCKET OUTPOST_S3_PREFIX \
  AWS_REGION OUTPOST_AWS_ACCESS_KEY_ID OUTPOST_EXPORT_INTERVAL_SECONDS \
  OBSERVER_ENABLED_EVENT_TYPES OBSERVER_ENABLED_MONGODB_COMMANDS \
  OBSERVER_BATCH_FLUSH_MILLISECONDS \
  OBSERVER_BATCH_MAX_EVENTS OBSERVER_CPU_PROFILE_HZ \
  OBSERVER_LOCK_PROFILING OBSERVER_TLS_UPROBES \
  AWS_PROFILE DIRECT_USER_AWS_PROFILE \
  DIRECT_USER_AWS_ACCESS_KEY_ID DIRECT_USER_API_LOCAL_PORT \
  OBSERVER_INTERNAL_TOKEN PRINCIPAL_HASH_SALT \
  MONGODB_ROOT_USERNAME MONGODB_ROOT_PASSWORD DEMO_IAM_PRINCIPAL_ARN; do
  grep -q "^${variable_name}=" "$generated_env" || {
    printf 'Generated .env is missing %s.\n' "$variable_name" >&2
    exit 1
  }
done
if grep -Eq \
  '^(OBSERVER_INTERNAL_TOKEN|BEARER_TOKEN|PRINCIPAL_HASH_SALT|MONGODB_ROOT_PASSWORD)=generate-me$' \
  "$generated_env"; then
  printf '%s\n' 'Generated .env retained a secret placeholder.' >&2
  exit 1
fi
if [[ "$(stat -c '%a' "$generated_env")" != 600 ]]; then
  printf '%s\n' 'Generated .env is not mode 0600.' >&2
  exit 1
fi

printf '%s\n' '.env loading, override precedence, and generation tests passed.'
