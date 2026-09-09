#!/usr/bin/env bash
set -euo pipefail

for command_name in docker curl grep jq; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="$$"
network="mongodb-dam-contract-$run_id"
mock="mongodb-dam-endpoint-$run_id"
reject_mock="mongodb-dam-endpoint-reject-$run_id"
outpost="mongodb-dam-outpost-$run_id"

cleanup() {
  docker rm --force "$outpost" "$mock" "$reject_mock" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build --file "$repo_root/Dockerfile.outpost" --target outpost \
  --tag mongodb-dam-outpost:dev "$repo_root" >/dev/null
docker build --file "$repo_root/Dockerfile.outpost" --target mock-endpoint \
  --tag mongodb-dam-mock-endpoint:dev "$repo_root" >/dev/null

docker network create "$network" >/dev/null
docker run --detach --rm \
  --name "$mock" \
  --network "$network" \
  --network-alias mock-endpoint \
  --publish 127.0.0.1::8088 \
  -e MOCK_ENDPOINT_BEARER_TOKEN=integration-bearer-token \
  mongodb-dam-mock-endpoint:dev >/dev/null

docker run --detach --rm \
  --name "$outpost" \
  --network "$network" \
  --publish 127.0.0.1::8090 \
  --tmpfs /var/lib/mongodb-dam/outpost:rw,uid=65532,gid=65532,size=67108864 \
  --mount "type=bind,src=$repo_root/tests/fixtures/bearer-token.txt,dst=/run/secrets/bearer-token,readonly" \
  --mount "type=bind,src=$repo_root/tests/fixtures/internal-token.txt,dst=/run/secrets/internal-token,readonly" \
  -e DAM_CUSTOMER_ID=integration-customer \
  -e DAM_TENANT_ID=integration-tenant \
  -e DAM_SOURCE_ID=integration-source \
  -e DAM_REGIONAL_CELL_ID=integration-cell \
  -e DAM_CLUSTER_NAME=integration-cluster \
  -e OUTPOST_INTERNAL_TOKEN_FILE=/run/secrets/internal-token \
  -e OUTPOST_ENDPOINT=http://mock-endpoint:8088/v1/ingest/mongodb-dam \
  -e OUTPOST_BEARER_TOKEN_FILE=/run/secrets/bearer-token \
  -e OUTPOST_EXPORT_INTERVAL_SECONDS=1 \
  mongodb-dam-outpost:dev >/dev/null

mapped="$(docker port "$outpost" 8090/tcp)"
port="${mapped##*:}"
mock_mapped="$(docker port "$mock" 8088/tcp)"
mock_port="${mock_mapped##*:}"
for _ in $(seq 1 50); do
  if curl --fail --silent "http://127.0.0.1:$port/ready" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl --fail --silent "http://127.0.0.1:$port/ready" >/dev/null

curl --fail --silent \
  --request POST \
  --header 'authorization: Bearer integration-internal-token' \
  --header 'content-type: application/json' \
  --data-binary "@$repo_root/tests/fixtures/dam-batch.json" \
  "http://127.0.0.1:$port/v1/observer/batches" >/dev/null

for _ in $(seq 1 50); do
  metrics="$(curl --fail --silent "http://127.0.0.1:$port/metrics")"
  if grep -q '^mongodb_dam_outpost_delivered_batches_total 1$' <<<"$metrics"; then
    delivered=true
    break
  fi
  sleep 0.2
done
if [[ "${delivered:-false}" != true ]]; then
  printf '%s\n' 'Timed out waiting for Outpost delivery.' >&2
  exit 1
fi
received="$(curl --fail --silent \
  --header 'authorization: Bearer integration-bearer-token' \
  "http://127.0.0.1:$mock_port/v1/batches?limit=10")"
jq -e '.count == 1 and .batches[0].batch_id == "integration-batch-0001"' \
  <<<"$received" >/dev/null
if curl --fail --silent "http://127.0.0.1:$mock_port/v1/batches" >/dev/null 2>&1; then
  printf '%s\n' 'Mock endpoint exposed batches without bearer authentication.' >&2
  exit 1
fi

docker stop "$mock" >/dev/null
docker run --detach --rm \
  --name "$reject_mock" \
  --network "$network" \
  --network-alias mock-endpoint \
  -e MOCK_ENDPOINT_BEARER_TOKEN=reject-this-outpost-token \
  mongodb-dam-mock-endpoint:dev >/dev/null

curl --fail --silent \
  --request POST \
  --header 'authorization: Bearer integration-internal-token' \
  --header 'content-type: application/json' \
  --data-binary "@$repo_root/tests/fixtures/dam-batch.json" \
  "http://127.0.0.1:$port/v1/observer/batches" >/dev/null

for _ in $(seq 1 50); do
  metrics="$(curl --fail --silent "http://127.0.0.1:$port/metrics")"
  if grep -q '^mongodb_dam_outpost_quarantine_items 1$' <<<"$metrics" \
    && grep -q '^mongodb_dam_outpost_spool_items 0$' <<<"$metrics"; then
    printf '%s\n' 'Outpost HTTP-push delivery and permanent-rejection quarantine tests passed.'
    exit 0
  fi
  sleep 0.2
done

printf '%s\n' 'Timed out waiting for Outpost quarantine handling.' >&2
exit 1
