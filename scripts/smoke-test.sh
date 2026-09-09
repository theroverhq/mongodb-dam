#!/usr/bin/env bash
set -euo pipefail

: "${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT}"
current_context="$(kubectl config current-context)"
if [[ "$current_context" != "$EXPECTED_KUBE_CONTEXT" ]]; then
  printf 'Wrong Kubernetes context. Expected %s, current %s.\n' "$EXPECTED_KUBE_CONTEXT" "$current_context" >&2
  exit 1
fi

namespace="${NAMESPACE:-mongodb-dam}"
release="${RELEASE:-mongodb-dam}"
mongodb_pod="$(kubectl -n "$namespace" get pods \
  -l "app.kubernetes.io/instance=$release,app.kubernetes.io/component=mongodb" \
  -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "$namespace" exec "$mongodb_pod" -- sh -c \
  'mongosh --quiet --username "$MONGO_INITDB_ROOT_USERNAME" --password "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --eval '\''db.getSiblingDB("dam_smoke").events.insertOne({kind:"wire-protocol-check",at:new Date()}); db.getSiblingDB("dam_smoke").events.findOne({kind:"wire-protocol-check"})'\'' localhost:27017'

printf '%s\n' 'MongoDB query completed. Recent Observer and Outpost status:'
kubectl -n "$namespace" get pods -l "app.kubernetes.io/instance=$release" -o wide
kubectl -n "$namespace" logs "daemonset/${release}-observer" --tail=20 --prefix
kubectl -n "$namespace" logs "deployment/${release}-outpost" --tail=20 --prefix
