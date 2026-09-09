#!/usr/bin/env bash
set -euo pipefail

for command_name in aws docker jq kubectl mktemp; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

: "${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT to the customer/demo cluster context}"
: "${AWS_REGION:?Set AWS_REGION to the AWS Secrets Manager region}"

current_context="$(kubectl config current-context)"
if [[ "$current_context" != "$EXPECTED_KUBE_CONTEXT" ]]; then
  printf 'Wrong Kubernetes context. Expected %s, current %s.\n' \
    "$EXPECTED_KUBE_CONTEXT" "$current_context" >&2
  exit 1
fi

canonical_iam_arn() {
  local value="$1"
  local arn partition service unused account resource role_path
  IFS=: read -r arn partition service unused account resource <<<"$value"
  if [[ "$arn" == arn && "$service" == sts && "$resource" == assumed-role/*/* ]]; then
    role_path="${resource#assumed-role/}"
    role_path="${role_path%/*}"
    printf 'arn:%s:iam::%s:role/%s\n' "$partition" "$account" "$role_path"
  else
    printf '%s\n' "$value"
  fi
}

namespace="${NAMESPACE:-mongodb-dam}"
release="${RELEASE:-mongodb-dam}"
aws_secret_id="${DEMO_AWS_SECRET_ID:-mongodb-dam/demo/direct-user}"
local_port="${MONGODB_LOCAL_PORT:-27018}"
mongodb_client_image="${MONGODB_CLIENT_IMAGE:-mongo:8.0.29-noble}"
use_existing_forward="${USE_EXISTING_MONGODB_FORWARD:-false}"
if [[ "$use_existing_forward" != true && "$use_existing_forward" != false ]]; then
  printf '%s\n' 'USE_EXISTING_MONGODB_FORWARD must be true or false.' >&2
  exit 1
fi
caller_arn="$(aws --region "$AWS_REGION" sts get-caller-identity --query Arn --output text)"
caller_principal="$(canonical_iam_arn "$caller_arn")"
credential="$(aws --region "$AWS_REGION" secretsmanager get-secret-value \
  --secret-id "$aws_secret_id" --query SecretString --output text)"
stored_principal="$(jq -er '.iam_principal_arn' <<<"$credential")"
if [[ "$caller_principal" != "$stored_principal" ]]; then
  printf 'Identity mismatch. AWS caller maps to %s, credential maps to %s.\n' \
    "$caller_principal" "$stored_principal" >&2
  exit 1
fi
mongo_username="$(jq -er '.mongo_username' <<<"$credential")"
mongo_password="$(jq -er '.mongo_password' <<<"$credential")"
auth_database="$(jq -er '.auth_database' <<<"$credential")"
database="$(jq -er '.database' <<<"$credential")"
unset credential

tmp_dir="$(mktemp -d)"
forward_pid=''
cleanup() {
  if [[ -n "$forward_pid" ]]; then
    kill "$forward_pid" >/dev/null 2>&1 || true
    wait "$forward_pid" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

if [[ "$use_existing_forward" == false ]]; then
  kubectl -n "$namespace" port-forward \
    "service/${release}-mongodb" "$local_port:27017" >"$tmp_dir/port-forward.log" 2>&1 &
  forward_pid=$!
  ready=false
  for _ in $(seq 1 80); do
    if grep -q 'Forwarding from' "$tmp_dir/port-forward.log"; then
      ready=true
      break
    fi
    if ! kill -0 "$forward_pid" >/dev/null 2>&1; then
      sed -n '1,80p' "$tmp_dir/port-forward.log" >&2
      exit 1
    fi
    sleep 0.25
  done
  if [[ "$ready" != true ]]; then
    sed -n '1,80p' "$tmp_dir/port-forward.log" >&2
    printf '%s\n' 'MongoDB port-forward did not become ready.' >&2
    exit 1
  fi
fi

set +e
docker_output="$(docker run --rm --network host \
  -e DAM_DEMO_MONGO_USERNAME="$mongo_username" \
  -e DAM_DEMO_MONGO_PASSWORD="$mongo_password" \
  -e DAM_DEMO_AUTH_DATABASE="$auth_database" \
  -e DAM_DEMO_DATABASE="$database" \
  -e DAM_DEMO_MONGO_PORT="$local_port" \
  "$mongodb_client_image" \
  sh -ceu '
    mongosh --quiet --host 127.0.0.1 --port "$DAM_DEMO_MONGO_PORT" \
      --username "$DAM_DEMO_MONGO_USERNAME" \
      --password "$DAM_DEMO_MONGO_PASSWORD" \
      --authenticationDatabase "$DAM_DEMO_AUTH_DATABASE" \
      --eval '\''
        db.getSiblingDB(process.env.DAM_DEMO_DATABASE)
          .customer_records.findOne({demo_batch: "iam-bulk-delete"});
      '\''
  ' 2>&1)"
exit_code=$?
set -e
unset mongo_password

if [[ "$exit_code" -eq 0 ]]; then
  printf '%s\n' 'Block verification failed: the mapped user could still query dam_demo.' >&2
  exit 1
fi
if ! grep -Eqi 'unauthorized|not authorized|requires authentication' <<<"$docker_output"; then
  printf '%s\n' 'The query failed, but not with the expected authorization error:' >&2
  printf '%s\n' "$docker_output" >&2
  exit 1
fi

printf 'PASS: MongoDB rejected the mapped user query after containment for %s.\n%s\n' \
  "$caller_arn" "$docker_output"
