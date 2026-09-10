#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=load-env.sh
source "$repo_root/scripts/load-env.sh"

aws_cli="${AWS_CLI_BIN:-aws}"
for command_name in "$aws_cli" jq mktemp; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

: "${AWS_REGION:?Set AWS_REGION to the AWS Secrets Manager region}"
: "${DEMO_IAM_PRINCIPAL_ARN:?Set DEMO_IAM_PRINCIPAL_ARN to the IAM user expected to be denied}"

if [[ ! "$DEMO_IAM_PRINCIPAL_ARN" =~ ^arn:[^:]+:iam::[0-9]{12}:user/.+$ ]]; then
  printf '%s\n' 'DEMO_IAM_PRINCIPAL_ARN must be an IAM user ARN for this response demo.' >&2
  exit 1
fi

aws_secret_id="${DEMO_AWS_SECRET_ID:-mongodb-dam/demo/direct-user}"
direct_user_aws=("$aws_cli")
if [[ -n "${DIRECT_USER_AWS_ACCESS_KEY_ID:-}" \
  || -n "${DIRECT_USER_AWS_SECRET_ACCESS_KEY:-}" ]]; then
  : "${DIRECT_USER_AWS_ACCESS_KEY_ID:?Set DIRECT_USER_AWS_ACCESS_KEY_ID with its matching secret key}"
  : "${DIRECT_USER_AWS_SECRET_ACCESS_KEY:?Set DIRECT_USER_AWS_SECRET_ACCESS_KEY with its matching access key}"
  direct_user_aws=(
    env
    -u AWS_ACCESS_KEY_ID
    -u AWS_SECRET_ACCESS_KEY
    -u AWS_SESSION_TOKEN
    -u AWS_PROFILE
    -u AWS_DEFAULT_PROFILE
    "AWS_ACCESS_KEY_ID=$DIRECT_USER_AWS_ACCESS_KEY_ID"
    "AWS_SECRET_ACCESS_KEY=$DIRECT_USER_AWS_SECRET_ACCESS_KEY"
  )
  if [[ -n "${DIRECT_USER_AWS_SESSION_TOKEN:-}" ]]; then
    direct_user_aws+=("AWS_SESSION_TOKEN=$DIRECT_USER_AWS_SESSION_TOKEN")
  fi
  direct_user_aws+=("$aws_cli")
elif [[ -n "${DIRECT_USER_AWS_SESSION_TOKEN:-}" ]]; then
  printf '%s\n' 'DIRECT_USER_AWS_SESSION_TOKEN requires matching direct-user access and secret keys.' >&2
  exit 1
elif [[ -n "${DIRECT_USER_AWS_PROFILE:-}" ]]; then
  direct_user_aws=(
    env
    -u AWS_ACCESS_KEY_ID
    -u AWS_SECRET_ACCESS_KEY
    -u AWS_SESSION_TOKEN
    -u AWS_DEFAULT_PROFILE
    "$aws_cli" --profile "$DIRECT_USER_AWS_PROFILE"
  )
fi
caller_arn="$("${direct_user_aws[@]}" --region "$AWS_REGION" \
  sts get-caller-identity --query Arn --output text)"
if [[ "$caller_arn" != "$DEMO_IAM_PRINCIPAL_ARN" ]]; then
  printf 'Wrong AWS caller. Expected %s, current %s.\n' \
    "$DEMO_IAM_PRINCIPAL_ARN" "$caller_arn" >&2
  exit 1
fi

error_file="$(mktemp)"
cleanup() {
  rm -f -- "$error_file"
}
trap cleanup EXIT

if secret_arn="$("${direct_user_aws[@]}" --region "$AWS_REGION" secretsmanager get-secret-value \
  --secret-id "$aws_secret_id" --query ARN --output text 2>"$error_file")"; then
  printf 'FAIL: %s can still retrieve %s (%s).\n' \
    "$caller_arn" "$aws_secret_id" "$secret_arn" >&2
  exit 1
fi

if ! grep -Eqi 'AccessDenied|not authorized|explicit deny' "$error_file"; then
  printf '%s\n' 'FAIL: Secrets Manager failed for a reason other than access denial:' >&2
  sed -n '1,5p' "$error_file" >&2
  exit 1
fi

jq -n \
  --arg status verified \
  --arg iam_principal_arn "$caller_arn" \
  --arg aws_secret_id "$aws_secret_id" \
  --arg secret_access denied \
  '{
    status: $status,
    iam_principal_arn: $iam_principal_arn,
    aws_secret_id: $aws_secret_id,
    secret_access: $secret_access
  }'
