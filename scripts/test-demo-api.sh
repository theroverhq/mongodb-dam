#!/usr/bin/env bash
set -euo pipefail

for command_name in docker curl jq; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="$$"
network="mongodb-dam-demo-api-$run_id"
mongodb="mongodb-dam-demo-mongodb-$run_id"
api="mongodb-dam-demo-api-$run_id"
mongodb_image="${MONGODB_TEST_IMAGE:-mongo:7.0.40-jammy}"

cleanup() {
  docker rm --force "$api" "$mongodb" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker build --file "$repo_root/Dockerfile.demo-api" \
  --tag mongodb-dam-demo-api:dev "$repo_root" >/dev/null
docker network create "$network" >/dev/null
docker run --detach --rm \
  --name "$mongodb" \
  --network "$network" \
  --network-alias mongodb \
  "$mongodb_image" mongod --bind_ip_all --port 27017 >/dev/null

mongodb_ready=false
for _ in $(seq 1 100); do
  if docker exec "$mongodb" mongosh --quiet --eval 'db.runCommand({ping: 1})' \
    mongodb://127.0.0.1:27017 >/dev/null 2>&1; then
    mongodb_ready=true
    break
  fi
  sleep 0.2
done
if [[ "$mongodb_ready" != "true" ]]; then
  docker logs "$mongodb" >&2 || true
  printf '%s\n' 'MongoDB did not become ready for the demo API test.' >&2
  exit 1
fi

docker run --detach --rm \
  --name "$api" \
  --network "$network" \
  --publish 127.0.0.1::8080 \
  --read-only \
  --tmpfs /tmp:rw,uid=65532,gid=65532 \
  -e MONGODB_HOST=mongodb \
  -e MONGODB_DATABASE=dam_demo \
  mongodb-dam-demo-api:dev >/dev/null

mapped="$(docker port "$api" 8080/tcp)"
port="${mapped##*:}"
for _ in $(seq 1 100); do
  if curl --fail --silent "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl --fail --silent "http://127.0.0.1:$port/health" >/dev/null

seed="$(curl --fail --silent --request POST "http://127.0.0.1:$port/demo/seed")"
jq -e '.status == "seeded" and .customers == 5 and .orders == 8' <<<"$seed" >/dev/null
customers="$(curl --fail --silent "http://127.0.0.1:$port/customers?email=aarav%40example.test")"
jq -e '.customers | length == 1' <<<"$customers" >/dev/null
workload="$(curl --fail --silent --request POST "http://127.0.0.1:$port/demo/workload")"
jq -e '.status == "completed" and .operations == ["find", "insert", "update", "aggregate", "delete"]' \
  <<<"$workload" >/dev/null

printf '%s\n' 'Demo API seed and workload tests passed.'
