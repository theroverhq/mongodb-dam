# DAM demo walkthrough

This mode is disposable presentation infrastructure. It adds:

- a constrained HTTP API that uses the official PyMongo driver to query MongoDB;
- the normal node-local Observer and Outpost pipeline;
- an in-memory HTTP receiver that accepts Outpost batches and exposes them for inspection.

MongoDB Community does not provide a general-purpose REST query API. The bundled demo API is the application layer that a client machine calls. Observer captures the resulting MongoDB wire-protocol activity at `mongod`; Outpost validates, enriches, spools, and forwards the sanitized metadata to the demo receiver. The separate direct-user flow can additionally mount a protected demo mapping so Outpost exports the IAM user and Secrets Manager ARN associated with a salted MongoDB principal.

## Deploy demo mode

Run all commands from the repository root. Build and push all four demo images from your local machine:

```bash
export REGISTRY=111122223333.dkr.ecr.ap-south-1.amazonaws.com
export TAG=v0.1.0-demo

BUILD_DEMO=true PUSH_IMAGES=true ./scripts/build-images.sh
```

Generate and load local secrets if you have not already done so:

```bash
./scripts/generate-secrets.sh
set -a
source deploy/examples/secrets.local.env
set +a
```

Deploy only after selecting the other-account Kubernetes context deliberately:

```bash
export EXPECTED_KUBE_CONTEXT=customer-demo
export CUSTOMER_ID=customer-demo
export TENANT_ID=tenant-demo
export SOURCE_ID=mongodb-demo
export REGIONAL_CELL_ID=cell-demo
export CLUSTER_NAME=customer-demo-cluster

export DEMO_MODE=true
export ENDPOINT=http://mock-endpoint:8088/v1/ingest/mongodb-dam
export VALUES_FILE=deploy/examples/demo-values.yaml
export OBSERVER_IMAGE_REPOSITORY="$REGISTRY/mongodb-dam-observer"
export OUTPOST_IMAGE_REPOSITORY="$REGISTRY/mongodb-dam-outpost"
export DEMO_API_IMAGE_REPOSITORY="$REGISTRY/mongodb-dam-demo-api"
export DEMO_RECEIVER_IMAGE_REPOSITORY="$REGISTRY/mongodb-dam-mock-endpoint"

./scripts/deploy.sh
```

The deploy script accepts that cleartext endpoint only when `DEMO_MODE=true` and only for the exact in-cluster hostname `mock-endpoint`. All other non-HTTPS destinations remain rejected.

## 1. Put dummy data in MongoDB

Keep this port-forward running in terminal 1:

```bash
kubectl -n mongodb-dam port-forward service/mongodb-dam-demo-api 8080:8080
```

From terminal 2, reset and seed the `dam_demo` database with five customers, eight orders, and 35 disposable records for the direct-user bulk-delete scenario:

```bash
curl --fail --silent --show-error \
  --request POST http://127.0.0.1:8080/demo/seed | jq .
```

Expected summary:

```json
{"status":"seeded","database":"dam_demo","customers":5,"orders":8,"customer_records":35}
```

The dummy values use the reserved `.test` domain and are not real customer data.

For the AWS IAM-mapped direct `mongosh` scenario and proof that its attributed bulk-delete activity reached the Outpost destination, follow the complete final section of the repository [README](../README.md#exact-aws-iam-user--direct-mongodb-activity-capture-demo).

## 2. Execute queries over HTTP from the client machine

The port-forward keeps the API private while making it available on the client machine. These calls generate common MongoDB command types:

```bash
# find
curl --fail --silent \
  'http://127.0.0.1:8080/customers?email=aarav%40example.test' | jq .

# insert
curl --fail --silent \
  --request POST \
  --header 'content-type: application/json' \
  --data '{"order_id":"order-live-001","customer_id":"cust-001","product":"live-demo","amount":42.50}' \
  http://127.0.0.1:8080/orders | jq .

# update
curl --fail --silent \
  --request PATCH \
  --header 'content-type: application/json' \
  --data '{"status":"paid"}' \
  http://127.0.0.1:8080/orders/order-live-001 | jq .

# aggregate
curl --fail --silent \
  http://127.0.0.1:8080/analytics/revenue-by-status | jq .

# delete
curl --fail --silent \
  --request DELETE \
  http://127.0.0.1:8080/orders/order-live-001 | jq .
```

For a single call that runs the recognizable five-command sequence:

```bash
curl --fail --silent --request POST \
  http://127.0.0.1:8080/demo/workload | jq .
```

The API intentionally exposes fixed demo operations instead of accepting arbitrary MongoDB queries.

## 3. See what Observer captured and Outpost delivered

Observer is the capture component. Outpost receives those batches, adds Kubernetes metadata and any explicitly configured demo identity mapping, durably spools them, and pushes them to the configured endpoint.

Keep a receiver port-forward running in terminal 3:

```bash
kubectl -n mongodb-dam port-forward service/mock-endpoint 8088:8088
```

Read the most recent delivered batches using the same bearer token configured on Outpost:

```bash
curl --fail --silent \
  --header "authorization: Bearer $BEARER_TOKEN" \
  'http://127.0.0.1:8088/v1/batches?limit=250' \
  | jq '[.batches[].events[]
      | select(.event_type == "mongodb_activity" and .details.database == "dam_demo")
      | {
          observed_at,
          command: .details.command,
          database: .details.database,
          collection: .details.collection,
          duration_us: .details.duration_us,
          succeeded: .details.succeeded,
          capture_source: .capture.source,
          pod: .kubernetes.pod_name
        }]'
```

You should see `find`, `insert`, `update`, `aggregate`, and `delete`. You should not see email addresses, order IDs, products, amounts, filters, or document bodies: the exported contract is metadata-only.

To show the complete three-step flow and counters automatically:

```bash
EXPECTED_KUBE_CONTEXT=customer-demo \
BEARER_TOKEN="$BEARER_TOKEN" \
./scripts/run-demo.sh
```

The final command prints:

- the seed response;
- the HTTP workload response;
- a table of sanitized MongoDB activities;
- Observer capture/delivery counters from the MongoDB node;
- Outpost accepted/delivered/failure counters.

The demo receiver retains only the latest configured number of batches in memory. Restarting its pod clears the presentation history; it is not the regional product datastore.

## Troubleshooting

```bash
kubectl -n mongodb-dam get pods -o wide
kubectl -n mongodb-dam logs daemonset/mongodb-dam-observer --tail=100 --prefix
kubectl -n mongodb-dam logs deployment/mongodb-dam-outpost --tail=100
kubectl -n mongodb-dam logs deployment/mongodb-dam-demo-api --tail=100
kubectl -n mongodb-dam logs deployment/mongodb-dam-demo-receiver --tail=100
```

If API calls work but no MongoDB activity appears, first confirm that the Observer pod on the MongoDB node is ready and that `mongodb_dam_observer_target_processes` is nonzero. Then inspect parse-error and dropped-event counters. If Outpost accepted counters increase but receiver history does not, inspect Outpost delivery failures and verify that its endpoint is exactly the demo receiver URL.
