#!/usr/bin/env bash
set -euo pipefail

for command_name in base64 curl jq kubectl mktemp; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

: "${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT to the customer/demo cluster context}"
: "${BEARER_TOKEN:?Set BEARER_TOKEN to the demo receiver token}"

current_context="$(kubectl config current-context)"
if [[ "$current_context" != "$EXPECTED_KUBE_CONTEXT" ]]; then
  printf 'Wrong Kubernetes context. Expected %s, current %s.\n' \
    "$EXPECTED_KUBE_CONTEXT" "$current_context" >&2
  exit 1
fi

namespace="${NAMESPACE:-mongodb-dam}"
mapping_secret="${DIRECT_USER_MAPPING_SECRET:-mongodb-dam-demo-direct-user}"
receiver_port="${DEMO_RECEIVER_LOCAL_PORT:-18088}"
run_marker_file="${DIRECT_USER_RUN_MARKER_FILE:-/tmp/mongodb-dam-direct-user-last-run-$UID}"
not_before_epoch="${DIRECT_USER_NOT_BEFORE_EPOCH:-}"
if [[ -z "$not_before_epoch" ]]; then
  if [[ ! -f "$run_marker_file" ]]; then
    printf 'Run marker not found: %s. Run direct-user-bulk-delete.sh first or set DIRECT_USER_NOT_BEFORE_EPOCH.\n' \
      "$run_marker_file" >&2
    exit 1
  fi
  not_before_epoch="$(<"$run_marker_file")"
fi
if [[ ! "$not_before_epoch" =~ ^[0-9]+$ ]]; then
  printf '%s\n' 'The direct-user run marker must contain Unix epoch seconds.' >&2
  exit 1
fi
iam_principal="$(kubectl -n "$namespace" get secret "$mapping_secret" \
  -o jsonpath='{.data.iam-principal-arn}' | base64 --decode)"
principal_hash="$(kubectl -n "$namespace" get secret "$mapping_secret" \
  -o jsonpath='{.data.principal-hash}' | base64 --decode)"

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

kubectl -n "$namespace" port-forward service/mock-endpoint \
  "$receiver_port:8088" >"$tmp_dir/port-forward.log" 2>&1 &
forward_pid=$!

finding_file="$tmp_dir/finding.json"
found=false
for _ in $(seq 1 120); do
  if curl --fail --silent \
    --header "authorization: Bearer $BEARER_TOKEN" \
    "http://127.0.0.1:$receiver_port/v1/batches?limit=250" 2>/dev/null \
    | jq --arg principal "$principal_hash" --arg iam "$iam_principal" \
      --argjson not_before "$not_before_epoch" '
        def event_epoch:
          (.observed_at | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601);
        [.batches[].events[]
          | select(
              .event_type == "security_finding"
              and .details.rule_id == "mongodb.bulk_delete"
              and .details.principal == $principal
              and event_epoch >= $not_before
            )]
        | sort_by(.observed_at)
        | last
        | if . == null then empty else {
            observed_at,
            severity: .details.severity,
            rule_id: .details.rule_id,
            title: .details.title,
            iam_principal_arn: $iam,
            mongodb_principal_hash: .details.principal,
            database: .details.database,
            collection: .details.collection,
            delete_scope: .details.delete_scope,
            affected_documents: .details.affected_documents,
            threshold_documents: .details.threshold_documents,
            action: .details.action,
            connection_id: .details.connection_id,
            source: .capture.source,
            pod: .kubernetes.pod_name
          } end
      ' >"$finding_file"; then
    if [[ -s "$finding_file" ]]; then
      found=true
      break
    fi
  fi
  if ! kill -0 "$forward_pid" >/dev/null 2>&1; then
    sed -n '1,80p' "$tmp_dir/port-forward.log" >&2
    exit 1
  fi
  sleep 0.25
done

if [[ "$found" != true ]]; then
  printf '%s\n' 'Timed out waiting for the mapped user bulk-delete finding.' >&2
  exit 1
fi

printf '%s\n' 'DAM finding (clear IAM identity is joined locally from the protected mapping):'
jq . "$finding_file"
