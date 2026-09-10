#!/usr/bin/env bash
set -euo pipefail

for command_name in jq mktemp; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verifier="$repo_root/scripts/verify-direct-user-secret-revoked.sh"
mock_aws="$repo_root/tests/fixtures/mock-aws.sh"
expected_principal='arn:aws:iam::111122223333:user/dam-demo-alice'
output_file="$(mktemp)"
profile_env="$(mktemp)"
cleanup() {
  rm -f -- "$output_file" "$profile_env"
}
trap cleanup EXIT

printf '%s\n' \
  'AWS_REGION=ap-south-1' \
  'DEMO_IAM_PRINCIPAL_ARN=arn:aws:iam::111122223333:user/dam-demo-alice' \
  'DIRECT_USER_AWS_PROFILE=dam-user' \
  'AWS_ACCESS_KEY_ID=demo-admin-access-key' \
  'AWS_SECRET_ACCESS_KEY=demo-admin-secret-key' \
  'AWS_SESSION_TOKEN=demo-admin-session-token' >"$profile_env"

AWS_CLI_BIN="$mock_aws" \
ENV_FILE="$profile_env" \
MOCK_AWS_SECRET_RESULT=denied \
MOCK_EXPECT_PROFILE=dam-user \
MOCK_EXPECT_NO_STATIC_CREDENTIALS=true \
  "$verifier" >"$output_file"
jq -e --arg principal "$expected_principal" '
  .status == "verified"
  and .iam_principal_arn == $principal
  and .secret_access == "denied"
' "$output_file" >/dev/null

printf '%s\n' \
  'AWS_REGION=ap-south-1' \
  'DEMO_IAM_PRINCIPAL_ARN=arn:aws:iam::111122223333:user/dam-demo-alice' \
  'AWS_ACCESS_KEY_ID=demo-admin-access-key' \
  'AWS_SECRET_ACCESS_KEY=demo-admin-secret-key' \
  'DIRECT_USER_AWS_PROFILE=' \
  'DIRECT_USER_AWS_ACCESS_KEY_ID=demo-user-access-key' \
  'DIRECT_USER_AWS_SECRET_ACCESS_KEY=demo-user-secret-key' \
  'DIRECT_USER_AWS_SESSION_TOKEN=demo-user-session-token' >"$profile_env"

AWS_CLI_BIN="$mock_aws" \
ENV_FILE="$profile_env" \
MOCK_AWS_SECRET_RESULT=denied \
MOCK_EXPECT_ACCESS_KEY_ID=demo-user-access-key \
MOCK_EXPECT_SESSION_TOKEN=demo-user-session-token \
  "$verifier" >"$output_file"
jq -e '.status == "verified" and .secret_access == "denied"' \
  "$output_file" >/dev/null

AWS_CLI_BIN="$mock_aws" \
ENV_FILE=/dev/null \
AWS_REGION=ap-south-1 \
DEMO_IAM_PRINCIPAL_ARN="$expected_principal" \
MOCK_AWS_SECRET_RESULT=denied \
  "$verifier" >"$output_file"
jq -e --arg principal "$expected_principal" '
  .status == "verified"
  and .iam_principal_arn == $principal
  and .aws_secret_id == "mongodb-dam/demo/direct-user"
  and .secret_access == "denied"
' "$output_file" >/dev/null

if AWS_CLI_BIN="$mock_aws" \
  ENV_FILE=/dev/null \
  AWS_REGION=ap-south-1 \
  DEMO_IAM_PRINCIPAL_ARN="$expected_principal" \
  MOCK_AWS_SECRET_RESULT=allowed \
    "$verifier" >/dev/null 2>&1; then
  printf '%s\n' 'Verifier accepted a user that could still retrieve the secret.' >&2
  exit 1
fi

if AWS_CLI_BIN="$mock_aws" \
  ENV_FILE=/dev/null \
  AWS_REGION=ap-south-1 \
  DEMO_IAM_PRINCIPAL_ARN="$expected_principal" \
  MOCK_AWS_CALLER_ARN='arn:aws:iam::111122223333:user/not-the-demo-user' \
  MOCK_AWS_SECRET_RESULT=denied \
    "$verifier" >/dev/null 2>&1; then
  printf '%s\n' 'Verifier accepted the wrong AWS caller.' >&2
  exit 1
fi

if AWS_CLI_BIN="$mock_aws" \
  ENV_FILE=/dev/null \
  AWS_REGION=ap-south-1 \
  DEMO_IAM_PRINCIPAL_ARN="$expected_principal" \
  MOCK_AWS_SECRET_RESULT=error \
    "$verifier" >/dev/null 2>&1; then
  printf '%s\n' 'Verifier treated an unrelated AWS error as access denial.' >&2
  exit 1
fi

printf '%s\n' 'Direct-user Secrets Manager denial verification tests passed.'
