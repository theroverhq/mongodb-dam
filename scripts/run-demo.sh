#!/usr/bin/env bash
set -euo pipefail

for command_name in kubectl curl jq grep mktemp; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

: "${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT to the demo cluster context}"
: "${BEARER_TOKEN:?Set BEARER_TOKEN to the value configured on Outpost and the demo receiver}"

current_context="$(kubectl config current-context)"
if [[ "$current_context" != "$EXPECTED_KUBE_CONTEXT" ]]; then
  printf 'Wrong Kubernetes context. Expected %s, current %s.\n' "$EXPECTED_KUBE_CONTEXT" "$current_context" >&2
  exit 1
fi

namespace="${NAMESPACE:-mongodb-dam}"
release="${RELEASE:-mongodb-dam}"
api_port="${DEMO_API_LOCAL_PORT:-18080}"
receiver_port="${DEMO_RECEIVER_LOCAL_PORT:-18088}"
outpost_port="${DEMO_OUTPOST_LOCAL_PORT:-18090}"
observer_port="${DEMO_OBSERVER_LOCAL_PORT:-18091}"
tmp_dir="$(mktemp -d)"
forward_pids=()

cleanup() {
  for pid in "${forward_pids[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  done
  rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

start_forward() {
  local name="$1"
  local target="$2"
  local ports="$3"
  local ready_url="$4"
  local log_file="$tmp_dir/$name.log"
  kubectl -n "$namespace" port-forward "$target" "$ports" >"$log_file" 2>&1 &
  local pid=$!
  forward_pids+=("$pid")
  for _ in $(seq 1 60); do
    if curl --fail --silent "$ready_url" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      printf 'Port-forward for %s stopped unexpectedly:\n' "$name" >&2
      sed -n '1,80p' "$log_file" >&2
      return 1
    fi
    sleep 0.25
  done
  printf 'Timed out waiting for %s through %s.\n' "$name" "$ports" >&2
  sed -n '1,80p' "$log_file" >&2
  return 1
}

mongodb_node="$(kubectl -n "$namespace" get pods \
  -l "app.kubernetes.io/instance=$release,app.kubernetes.io/component=mongodb" \
  -o jsonpath='{.items[0].spec.nodeName}')"
observer_pod="$(kubectl -n "$namespace" get pods \
  -l "app.kubernetes.io/instance=$release,app.kubernetes.io/component=observer" \
  --field-selector "spec.nodeName=$mongodb_node" \
  -o jsonpath='{.items[0].metadata.name}')"
if [[ -z "$mongodb_node" || -z "$observer_pod" ]]; then
  printf '%s\n' 'Could not find MongoDB and its node-local Observer. Is the demo rollout ready?' >&2
  exit 1
fi

start_forward api "service/${release}-demo-api" "$api_port:8080" "http://127.0.0.1:$api_port/health"
start_forward receiver "service/mock-endpoint" "$receiver_port:8088" "http://127.0.0.1:$receiver_port/health"
start_forward outpost "service/${release}-outpost" "$outpost_port:8090" "http://127.0.0.1:$outpost_port/ready"
start_forward observer "pod/$observer_pod" "$observer_port:8091" "http://127.0.0.1:$observer_port/ready"

printf '%s\n' '1/3 Seeding deterministic dummy customers and orders through the demo API...'
curl --fail --silent --show-error \
  --request POST "http://127.0.0.1:$api_port/demo/seed" | jq .

printf '%s\n' '2/3 Running find, insert, update, aggregate, and delete from this client machine...'
curl --fail --silent --show-error \
  "http://127.0.0.1:$api_port/customers?email=aarav%40example.test" | jq .
curl --fail --silent --show-error \
  --request POST "http://127.0.0.1:$api_port/demo/workload" | jq .

events_file="$tmp_dir/batches.json"
captured=false
for _ in $(seq 1 80); do
  if curl --fail --silent --show-error \
    --header "authorization: Bearer $BEARER_TOKEN" \
    "http://127.0.0.1:$receiver_port/v1/batches?limit=250" >"$events_file"; then
    captured=true
    for command_name in find insert update aggregate delete; do
      if ! jq -e --arg command "$command_name" \
        '[.batches[].events[] | select(.event_type == "mongodb_activity" and .details.database == "dam_demo" and .details.command == $command)] | length > 0' \
        "$events_file" >/dev/null; then
        captured=false
        break
      fi
    done
    if [[ "$captured" == "true" ]]; then
      break
    fi
  fi
  sleep 0.25
done

if [[ "$captured" != "true" ]]; then
  printf '%s\n' 'Timed out waiting for all five MongoDB command types at the demo receiver.' >&2
  printf '%s\n' 'Observer metrics:' >&2
  curl --fail --silent "http://127.0.0.1:$observer_port/metrics" \
    | grep '^mongodb_dam_observer_' >&2 || true
  printf '%s\n' 'Outpost metrics:' >&2
  curl --fail --silent "http://127.0.0.1:$outpost_port/metrics" \
    | grep '^mongodb_dam_outpost_' >&2 || true
  exit 1
fi

printf '%s\n' '3/3 Observer captured and Outpost delivered these sanitized DAM activities:'
printf 'OBSERVED_AT\tCOMMAND\tDATABASE\tCOLLECTION\tDURATION_US\tSUCCEEDED\tSOURCE\tPOD\n'
jq -r '
  [.batches[].events[]
    | select(.event_type == "mongodb_activity" and .details.database == "dam_demo")]
  | sort_by(.observed_at)
  | .[]
  | [
      .observed_at,
      .details.command,
      (.details.database // "-"),
      (.details.collection // "-"),
      (.details.duration_us // "-"),
      (.details.succeeded // "-"),
      .capture.source,
      (.kubernetes.pod_name // "-")
    ]
  | @tsv
' "$events_file"

printf '\nObserver counters on MongoDB node %s:\n' "$mongodb_node"
curl --fail --silent "http://127.0.0.1:$observer_port/metrics" \
  | grep -E '^mongodb_dam_observer_(metadata_events|batches_delivered|parse_errors|bpf_dropped_events)_total ' || true
printf '\nOutpost counters:\n'
curl --fail --silent "http://127.0.0.1:$outpost_port/metrics" \
  | grep -E '^mongodb_dam_outpost_(accepted_batches|delivered_batches|delivery_failures)_total ' || true
printf '\nDemo complete. Query values and document bodies are absent from the DAM rows above.\n'
