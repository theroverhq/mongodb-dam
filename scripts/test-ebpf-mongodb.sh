#!/usr/bin/env bash
set -euo pipefail

for command_name in docker grep mktemp python3 sha256sum; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_id="$$"
network="mongodb-dam-ebpf-$run_id"
mock="mongodb-dam-ebpf-endpoint-$run_id"
outpost="mongodb-dam-ebpf-outpost-$run_id"
observer="mongodb-dam-ebpf-observer-$run_id"
mongodb="mongodb-dam-ebpf-mongodb-$run_id"
output_dir="$(mktemp -d)"
mongodb_image="${MONGODB_TEST_IMAGE:-mongo:8.0.29-noble}"
secret_value="private-value-that-must-not-leave-node"
mongodb_root_user="dam-admin"
mongodb_root_password="integration-root-password"
direct_user="integration-direct-user"
direct_password="integration-direct-password"
principal_salt="$(tr -d '\r\n' <"$repo_root/tests/fixtures/internal-token.txt")"
principal_digest="$(
  {
    printf '%s' "$principal_salt"
    printf '\0'
    printf '%s' "$direct_user"
  } | sha256sum
)"
principal_digest="${principal_digest%% *}"
expected_principal="sha256:$principal_digest"

cleanup() {
  docker rm --force "$observer" "$outpost" "$mock" "$mongodb" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  if [[ "${KEEP_TEST_OUTPUT:-false}" == true ]]; then
    printf 'Preserved test endpoint output: %s\n' "$output_dir" >&2
  elif [[ -n "$output_dir" && -d "$output_dir" ]]; then
    rm -rf -- "$output_dir"
  fi
}
trap cleanup EXIT

diagnostics() {
  printf '%s\n' 'Observer diagnostics:' >&2
  docker logs "$observer" >&2 || true
  printf '%s\n' 'Outpost diagnostics:' >&2
  docker logs "$outpost" >&2 || true
  printf '%s\n' 'MongoDB diagnostics:' >&2
  docker logs --tail 40 "$mongodb" >&2 || true
  printf '%s\n' 'Captured MongoDB commands and connection states:' >&2
  grep -RohE '"(command|state)":"[^"]+"' "$output_dir" 2>/dev/null | sort -u >&2 || true
}

docker build --file "$repo_root/Dockerfile.observer" \
  --tag mongodb-dam-observer:dev "$repo_root" >/dev/null
docker build --file "$repo_root/Dockerfile.outpost" --target outpost \
  --tag mongodb-dam-outpost:dev "$repo_root" >/dev/null
docker build --file "$repo_root/Dockerfile.outpost" --target mock-endpoint \
  --tag mongodb-dam-mock-endpoint:dev "$repo_root" >/dev/null

chmod 0777 "$output_dir"
docker network create "$network" >/dev/null

docker run --detach --rm \
  --name "$mock" \
  --network "$network" \
  --network-alias mock-endpoint \
  --mount "type=bind,src=$output_dir,dst=/output" \
  -e MOCK_ENDPOINT_BEARER_TOKEN=integration-bearer-token \
  -e MOCK_ENDPOINT_OUTPUT_DIR=/output \
  mongodb-dam-mock-endpoint:dev >/dev/null

docker run --detach --rm \
  --name "$outpost" \
  --network "$network" \
  --network-alias outpost \
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

docker run --detach --rm \
  --name "$mongodb" \
  --network "$network" \
  -e MONGO_INITDB_ROOT_USERNAME="$mongodb_root_user" \
  -e MONGO_INITDB_ROOT_PASSWORD="$mongodb_root_password" \
  "$mongodb_image" mongod --bind_ip_all --port 27017 >/dev/null

mongodb_ready=false
for _ in $(seq 1 100); do
  if docker exec "$mongodb" mongosh --quiet --eval 'db.runCommand({ping: 1})' \
    --username "$mongodb_root_user" --password "$mongodb_root_password" \
    --authenticationDatabase admin \
    mongodb://127.0.0.1:27017 >/dev/null 2>&1; then
    mongodb_ready=true
    break
  fi
  sleep 0.2
done
if [[ "$mongodb_ready" != true ]]; then
  diagnostics
  printf 'MongoDB test container did not become ready: %s\n' "$mongodb_image" >&2
  exit 1
fi

docker run --detach --rm \
  --name "$observer" \
  --network "$network" \
  --privileged \
  --pid=host \
  --mount type=bind,src=/proc,dst=/host/proc,readonly \
  --mount type=bind,src=/sys/kernel/tracing,dst=/sys/kernel/tracing,readonly \
  --mount type=bind,src=/sys/kernel/debug,dst=/sys/kernel/debug,readonly \
  --mount type=bind,src=/sys/kernel/btf,dst=/sys/kernel/btf,readonly \
  --mount "type=bind,src=$repo_root/tests/fixtures/internal-token.txt,dst=/run/secrets/internal-token,readonly" \
  --mount "type=bind,src=$repo_root/tests/fixtures/internal-token.txt,dst=/run/secrets/principal-salt,readonly" \
  --tmpfs /var/lib/mongodb-dam/observer:rw,size=67108864 \
  -e DAM_CUSTOMER_ID=integration-customer \
  -e DAM_TENANT_ID=integration-tenant \
  -e DAM_SOURCE_ID=integration-source \
  -e DAM_REGIONAL_CELL_ID=integration-cell \
  -e DAM_CLUSTER_NAME=integration-cluster \
  -e NODE_NAME=integration-node \
  -e OBSERVER_OUTPOST_URL=http://outpost:8090/v1/observer/batches \
  -e OBSERVER_INTERNAL_TOKEN_FILE=/run/secrets/internal-token \
  -e OBSERVER_PRINCIPAL_HASH_SALT_FILE=/run/secrets/principal-salt \
  -e OBSERVER_CPU_PROFILE_HZ=0 \
  mongodb-dam-observer:dev >/dev/null

observer_ready=false
for _ in $(seq 1 50); do
  if docker logs "$observer" 2>&1 | grep -q 'MongoDB DAM Observer ready'; then
    observer_ready=true
    break
  fi
  sleep 0.2
done
if [[ "$observer_ready" != true ]]; then
  diagnostics
  printf '%s\n' 'Observer did not become ready.' >&2
  exit 1
fi

mongodb_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$mongodb")"
python3 -c '
import socket
import struct
import sys
import time

connection = socket.create_connection((sys.argv[1], 27017))
time.sleep(0.2)
connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
connection.close()
' "$mongodb_ip"

docker exec "$mongodb" mongosh --quiet mongodb://127.0.0.1:27017 --eval "
db.getSiblingDB('admin').createUser({
  user: '$direct_user',
  pwd: '$direct_password',
  roles: [{role: 'readWrite', db: 'dam_e2e'}]
});
" --username "$mongodb_root_user" --password "$mongodb_root_password" \
  --authenticationDatabase admin >/dev/null

docker exec "$mongodb" mongosh --quiet mongodb://127.0.0.1:27017 --eval "
const monitored = db.getSiblingDB('dam_e2e');
monitored.orders.insertOne({classification: '$secret_value'});
monitored.orders.findOne({classification: '$secret_value'});
monitored.orders.updateOne({classification: '$secret_value'}, {\$set: {status: 'updated'}});
monitored.orders.aggregate([{\$match: {classification: '$secret_value'}}]).toArray();
monitored.orders.deleteOne({classification: '$secret_value'});
monitored.customer_records.drop();
monitored.customer_records.insertMany(Array.from({length: 35}, (_, index) => ({
  demo_batch: 'integration-bulk-delete',
  record_number: index
})));
monitored.customer_records.deleteMany({demo_batch: 'integration-bulk-delete'});
" --username "$direct_user" --password "$direct_password" \
  --authenticationDatabase admin >/dev/null

captured=false
for _ in $(seq 1 100); do
  if grep -Rqs '"command":"insert"' "$output_dir" \
    && grep -Rqs '"command":"find"' "$output_dir" \
    && grep -Rqs '"command":"aggregate"' "$output_dir" \
    && grep -Rqs '"command":"update"' "$output_dir" \
    && grep -Rqs '"command":"delete"' "$output_dir" \
    && grep -Rqs '"event_type":"security_finding"' "$output_dir" \
    && grep -Rqs '"rule_id":"mongodb.bulk_delete"' "$output_dir" \
    && grep -Rqs "\"rule_id\":\"mongodb.bulk_delete\".*\"principal\":\"$expected_principal\"" "$output_dir" \
    && grep -Rqs '"affected_documents":35' "$output_dir" \
    && grep -Rqs '"state":"handshake_established"' "$output_dir" \
    && grep -Rqs '"reason":"peer_reset"' "$output_dir"; then
    captured=true
    break
  fi
  sleep 0.2
done

if [[ "$captured" != true ]]; then
  diagnostics
  printf '%s\n' 'Timed out waiting for MongoDB activity, handshake, and reset metadata.' >&2
  exit 1
fi
if grep -Rqs "$secret_value" "$output_dir"; then
  diagnostics
  printf '%s\n' 'Privacy failure: a MongoDB query value crossed the endpoint boundary.' >&2
  exit 1
fi
if grep -Rqs "$direct_user" "$output_dir"; then
  diagnostics
  printf '%s\n' 'Privacy failure: a clear MongoDB principal crossed the endpoint boundary.' >&2
  exit 1
fi

docker exec "$mongodb" mongosh --quiet mongodb://127.0.0.1:27017 --eval "
const admin = db.getSiblingDB('admin');
admin.revokeRolesFromUser('$direct_user', [{role: 'readWrite', db: 'dam_e2e'}]);
const killed = admin.runCommand({killAllSessions: [{user: '$direct_user', db: 'admin'}]});
if (killed.ok !== 1) throw new Error('killAllSessions failed');
" --username "$mongodb_root_user" --password "$mongodb_root_password" \
  --authenticationDatabase admin >/dev/null

set +e
blocked_output="$(docker exec "$mongodb" mongosh --quiet mongodb://127.0.0.1:27017 --eval "
db.getSiblingDB('dam_e2e').customer_records.findOne({demo_batch: 'integration-bulk-delete'});
" --username "$direct_user" --password "$direct_password" \
  --authenticationDatabase admin 2>&1)"
blocked_exit=$?
set -e
if [[ "$blocked_exit" -eq 0 ]] || ! grep -Eqi 'unauthorized|not authorized' <<<"$blocked_output"; then
  diagnostics
  printf '%s\n' 'Containment failure: the direct user was not denied after role revocation.' >&2
  printf '%s\n' "$blocked_output" >&2
  exit 1
fi

denied_captured=false
for _ in $(seq 1 100); do
  if grep -Rqs "\"command\":\"find\".*\"principal\":\"$expected_principal\".*\"succeeded\":false.*\"error_code\":13" \
    "$output_dir"; then
    denied_captured=true
    break
  fi
  sleep 0.2
done
if [[ "$denied_captured" != true ]]; then
  diagnostics
  printf '%s\n' 'Timed out waiting for the principal-attributed denied query event.' >&2
  exit 1
fi

printf '%s\n' 'Live eBPF MongoDB metadata, SCRAM attribution, bulk-delete finding, containment, denied-query evidence, TCP lifecycle, and redaction tests passed.'
