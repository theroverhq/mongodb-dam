#!/usr/bin/env bash
set -euo pipefail

for command_name in base64 kubectl mktemp; do
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
release="${RELEASE:-mongodb-dam}"
mapping_secret="${DIRECT_USER_MAPPING_SECRET:-mongodb-dam-demo-direct-user}"
mongo_username="$(kubectl -n "$namespace" get secret "$mapping_secret" \
  -o jsonpath='{.data.mongo-username}' | base64 --decode)"
database="$(kubectl -n "$namespace" get secret "$mapping_secret" \
  -o jsonpath='{.data.database}' | base64 --decode)"
iam_principal="$(kubectl -n "$namespace" get secret "$mapping_secret" \
  -o jsonpath='{.data.iam-principal-arn}' | base64 --decode)"
principal_hash="$(kubectl -n "$namespace" get secret "$mapping_secret" \
  -o jsonpath='{.data.principal-hash}' | base64 --decode)"
aws_secret_id="$(kubectl -n "$namespace" get secret "$mapping_secret" \
  -o jsonpath='{.data.aws-secret-id}' | base64 --decode)"
mongodb_pod="$(kubectl -n "$namespace" get pods \
  -l "app.kubernetes.io/instance=$release,app.kubernetes.io/component=mongodb" \
  -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "$namespace" exec "$mongodb_pod" -- \
  env DAM_DEMO_USERNAME="$mongo_username" DAM_DEMO_DATABASE="$database" \
  sh -ceu '
    mongosh --quiet --host 127.0.0.1 --port 27017 \
      --username "$MONGO_INITDB_ROOT_USERNAME" \
      --password "$MONGO_INITDB_ROOT_PASSWORD" \
      --authenticationDatabase admin \
      --eval '\''
        const username = process.env.DAM_DEMO_USERNAME;
        const database = process.env.DAM_DEMO_DATABASE;
        const admin = db.getSiblingDB("admin");
        if (!admin.getUser(username)) {
          throw new Error(`MongoDB user ${username} does not exist`);
        }
        admin.revokeRolesFromUser(username, [{role: "readWrite", db: database}]);
        const killed = admin.runCommand({killAllSessions: [{user: username, db: "admin"}]});
        print(JSON.stringify({
          status: "blocked",
          username,
          revokedRole: `readWrite@${database}`,
          killAllSessionsOk: killed.ok
        }));
      '\''
  '

tmp_file="$(mktemp)"
trap 'rm -f -- "$tmp_file"' EXIT
kubectl -n "$namespace" create secret generic "$mapping_secret" \
  --from-literal="iam-principal-arn=$iam_principal" \
  --from-literal="mongo-username=$mongo_username" \
  --from-literal="principal-hash=$principal_hash" \
  --from-literal="aws-secret-id=$aws_secret_id" \
  --from-literal="database=$database" \
  --from-literal='status=blocked' \
  --dry-run=client -o yaml >"$tmp_file"
kubectl apply -f "$tmp_file" >/dev/null

printf 'Contained IAM principal %s by revoking MongoDB role readWrite@%s and killing its sessions.\n' \
  "$iam_principal" "$database"
printf '%s\n' 'This blocks subsequent database operations; it does not undo the initial delete.'
