#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=load-env.sh
source "$repo_root/scripts/load-env.sh"

destination_mode="${OUTPOST_DESTINATION:-}"
if [[ -z "$destination_mode" ]]; then
  if [[ -n "${OUTPOST_S3_BUCKET:-}" || -n "${OUTPOST_S3_PREFIX:-}" ]]; then
    destination_mode="s3"
  else
    destination_mode="http"
  fi
fi
if [[ "$destination_mode" != "http" && "$destination_mode" != "s3" ]]; then
  printf '%s\n' 'OUTPOST_DESTINATION must be http or s3.' >&2
  exit 1
fi

required_commands=(base64 jq kubectl mktemp)
if [[ "$destination_mode" == "s3" ]]; then
  required_commands+=(aws gzip)
  : "${OUTPOST_S3_BUCKET:?Set OUTPOST_S3_BUCKET}"
  : "${OUTPOST_S3_PREFIX:?Set OUTPOST_S3_PREFIX}"
  : "${AWS_REGION:?Set AWS_REGION}"
else
  required_commands+=(curl)
  : "${BEARER_TOKEN:?Set BEARER_TOKEN to the demo receiver token}"
fi
for command_name in "${required_commands[@]}"; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

: "${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT to the customer/demo cluster context}"

current_context="$(kubectl config current-context)"
if [[ "$current_context" != "$EXPECTED_KUBE_CONTEXT" ]]; then
  printf 'Wrong Kubernetes context. Expected %s, current %s.\n' \
    "$EXPECTED_KUBE_CONTEXT" "$current_context" >&2
  exit 1
fi

namespace="${NAMESPACE:-mongodb-dam}"
mapping_secret="${DIRECT_USER_MAPPING_SECRET:-mongodb-dam-demo-direct-user}"
receiver_service="${DEMO_RECEIVER_SERVICE:-mock-endpoint}"
receiver_port="${DEMO_RECEIVER_LOCAL_PORT:-18088}"
run_marker_file="${DIRECT_USER_RUN_MARKER_FILE:-/tmp/mongodb-dam-direct-user-last-run-$UID}"
not_before_epoch="${DIRECT_USER_NOT_BEFORE_EPOCH:-}"
if [[ -z "$not_before_epoch" ]]; then
  if [[ ! -f "$run_marker_file" ]]; then
    printf 'Run marker not found: %s. Run the direct-user bulk-delete curl first or set DIRECT_USER_NOT_BEFORE_EPOCH.\n' \
      "$run_marker_file" >&2
    exit 1
  fi
  not_before_epoch="$(<"$run_marker_file")"
fi
if [[ ! "$not_before_epoch" =~ ^[0-9]+$ ]]; then
  printf '%s\n' 'The direct-user run marker must contain Unix epoch seconds.' >&2
  exit 1
fi

read_mapping_field() {
  kubectl -n "$namespace" get secret "$mapping_secret" \
    -o "jsonpath={.data.$1}" | base64 --decode
}

iam_principal="$(read_mapping_field iam-principal-arn)"
principal_hash="$(read_mapping_field principal-hash)"
database="$(read_mapping_field database)"
aws_account_id="$(read_mapping_field aws-account-id)"
principal_type="$(read_mapping_field principal-type)"
secret_arn="$(read_mapping_field aws-secret-arn)"

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

if [[ "$destination_mode" == "http" ]]; then
  kubectl -n "$namespace" port-forward "service/$receiver_service" \
    "$receiver_port:8088" >"$tmp_dir/port-forward.log" 2>&1 &
  forward_pid=$!
fi

events_file="$tmp_dir/events.ndjson"
activity_file="$tmp_dir/activity.json"
keys_file="$tmp_dir/keys"
s3_prefix="${OUTPOST_S3_PREFIX:-}"
s3_prefix="${s3_prefix#/}"
s3_prefix="${s3_prefix%/}/"

collect_events() {
  : >"$events_file"
  if [[ "$destination_mode" == "http" ]]; then
    curl --fail --silent \
      --header "authorization: Bearer $BEARER_TOKEN" \
      "http://127.0.0.1:$receiver_port/v1/batches?limit=250" 2>/dev/null \
      | jq -c '.batches[].events[]' >"$events_file"
    return
  fi

  aws s3api list-objects-v2 \
    --region "$AWS_REGION" \
    --bucket "$OUTPOST_S3_BUCKET" \
    --prefix "$s3_prefix" \
    --max-items "${SHOW_S3_MAX_OBJECTS:-250}" \
    --output json \
    | jq -r '(.Contents // []) | sort_by(.LastModified) | reverse | .[].Key | select(endswith(".ndjson.gz"))' \
    >"$keys_file"

  local object_index=0
  local key
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    object_index=$((object_index + 1))
    local object_file="$tmp_dir/object-$object_index.ndjson.gz"
    aws s3api get-object \
      --region "$AWS_REGION" \
      --bucket "$OUTPOST_S3_BUCKET" \
      --key "$key" \
      "$object_file" >/dev/null
    gzip -dc "$object_file" >>"$events_file"
  done <"$keys_file"
}

select_activity() {
  jq -s --arg principal "$principal_hash" --arg iam "$iam_principal" \
    --arg account "$aws_account_id" --arg principal_type "$principal_type" \
    --arg secret "$secret_arn" --arg database "$database" \
    --argjson not_before "$not_before_epoch" '
      def event_epoch:
        (.observed_at | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601);
      [.[]
        | select(
            .event_type == "mongodb_activity"
            and .details.command == "delete"
            and .details.database == $database
            and .details.collection == "customer_records"
            and .details.principal == $principal
            and .details.principal_hashed == true
            and .details.delete_scope == "multi"
            and .identity.provider == "aws"
            and .identity.principal_type == $principal_type
            and .identity.principal_arn == $iam
            and .identity.account_id == $account
            and .identity.credential_source == "aws_secrets_manager"
            and .identity.credential_resource == $secret
            and event_epoch >= $not_before
          )]
      | unique_by(.event_id)
      | sort_by(.observed_at)
      | last
      | if . == null then empty else {
          observed_at,
          iam_principal_arn: .identity.principal_arn,
          aws_account_id: .identity.account_id,
          credential_source: .identity.credential_source,
          credential_secret_arn: .identity.credential_resource,
          mongodb_principal_hash: .details.principal,
          command: .details.command,
          database: .details.database,
          collection: .details.collection,
          delete_scope: .details.delete_scope,
          delete_statements: .details.delete_statements,
          affected_documents: .details.affected_documents,
          query: .details.query,
          succeeded: .details.succeeded,
          error_code: .details.error_code,
          error_name: .details.error_name,
          duration_us: .details.duration_us,
          request_bytes: .details.request_bytes,
          response_bytes: .details.response_bytes,
          connection_id: .details.connection.connection_id,
          remote: .details.connection.remote,
          capture_source: .capture.source,
          pod: .kubernetes.pod_name,
          node: .capture.node_name
        } end
    ' "$events_file" >"$activity_file"
}

found=false
for _ in $(seq 1 60); do
  if collect_events && [[ -s "$events_file" ]] && select_activity; then
    if [[ -s "$activity_file" ]]; then
      found=true
      break
    fi
  fi
  if [[ -n "$forward_pid" ]] && ! kill -0 "$forward_pid" >/dev/null 2>&1; then
    sed -n '1,80p' "$tmp_dir/port-forward.log" >&2
    exit 1
  fi
  sleep 1
done

if [[ "$found" != true ]]; then
  printf '%s\n' 'Timed out waiting for the mapped user bulk-delete activity at the Outpost destination.' >&2
  exit 1
fi

printf 'Outpost-delivered MongoDB activity from the %s destination, enriched with the protected demo IAM mapping:\n' \
  "$destination_mode"
jq . "$activity_file"
