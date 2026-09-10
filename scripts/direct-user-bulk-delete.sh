#!/usr/bin/env bash
set -euo pipefail

for command_name in aws date docker jq kubectl mktemp; do
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
run_marker_file="${DIRECT_USER_RUN_MARKER_FILE:-/tmp/mongodb-dam-direct-user-last-run-$UID}"
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
if [[ "$(jq -er '.status' <<<"$credential")" != active ]]; then
  printf '%s\n' 'The direct-user credential is not active.' >&2
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

printf 'AWS caller %s retrieved its mapped credential and is connecting directly to MongoDB.\n' \
  "$caller_arn"
run_started_epoch="$(date -u +%s)"
umask 077
printf '%s\n' "$run_started_epoch" >"$run_marker_file"
docker run --rm --network host \
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
        const target = db.getSiblingDB(process.env.DAM_DEMO_DATABASE).customer_records;
        const before = target.countDocuments({demo_batch: "iam-bulk-delete"});
        if (before < 10) {
          throw new Error(`Expected at least 10 seeded records, found ${before}. Run POST /demo/seed first.`);
        }
        const result = target.deleteMany({demo_batch: "iam-bulk-delete"});
        print(JSON.stringify({
          command: "deleteMany",
          database: process.env.DAM_DEMO_DATABASE,
          collection: "customer_records",
          matchingBeforeDelete: before,
          deletedCount: result.deletedCount
        }));
      '\''
  '

unset mongo_password
printf 'Activity correlation marker: %s (epoch %s)\n' "$run_marker_file" "$run_started_epoch"
printf '%s\n' 'The delete has completed. Run show-direct-user-activity.sh to display the activity delivered by Outpost.'
