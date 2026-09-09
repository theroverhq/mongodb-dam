#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT}"
: "${CUSTOMER_ID:?Set CUSTOMER_ID}"
: "${TENANT_ID:?Set TENANT_ID}"
: "${SOURCE_ID:?Set SOURCE_ID}"
: "${REGIONAL_CELL_ID:?Set REGIONAL_CELL_ID}"
: "${CLUSTER_NAME:?Set CLUSTER_NAME}"
: "${COLLECT_URL:?Set COLLECT_URL to the regional HTTPS receiver}"
: "${COLLECT_TOKEN:?Set COLLECT_TOKEN}"
: "${OBSERVER_INTERNAL_TOKEN:?Set OBSERVER_INTERNAL_TOKEN}"
: "${PRINCIPAL_HASH_SALT:?Set PRINCIPAL_HASH_SALT}"
: "${MONGODB_ROOT_USERNAME:?Set MONGODB_ROOT_USERNAME}"
: "${MONGODB_ROOT_PASSWORD:?Set MONGODB_ROOT_PASSWORD}"

if [[ "$COLLECT_URL" != https://* ]]; then
  printf '%s\n' 'COLLECT_URL must use HTTPS.' >&2
  exit 1
fi

"$repo_root/scripts/preflight.sh"

namespace="${NAMESPACE:-mongodb-dam}"
release="${RELEASE:-mongodb-dam}"
tag="${TAG:-dev}"
observer_repository="${OBSERVER_IMAGE_REPOSITORY:-mongodb-dam-observer}"
outpost_repository="${OUTPOST_IMAGE_REPOSITORY:-mongodb-dam-outpost}"
mongodb_image_tag="${MONGODB_IMAGE_TAG:-}"
secret_name="${SECRET_NAME:-mongodb-dam-secrets}"
values_file="${VALUES_FILE:-}"

namespace_manifest="$(mktemp)"
kubectl create namespace "$namespace" --dry-run=client -o yaml > "$namespace_manifest"
kubectl apply -f "$namespace_manifest"
rm -f -- "$namespace_manifest"
kubectl label namespace "$namespace" pod-security.kubernetes.io/enforce=privileged --overwrite

secret_dir="$(mktemp -d)"
trap 'rm -rf -- "$secret_dir"' EXIT
chmod 700 "$secret_dir"
printf '%s' "$OBSERVER_INTERNAL_TOKEN" > "$secret_dir/observer-internal-token"
printf '%s' "$COLLECT_TOKEN" > "$secret_dir/collect-token"
printf '%s' "$PRINCIPAL_HASH_SALT" > "$secret_dir/principal-hash-salt"
printf '%s' "$MONGODB_ROOT_USERNAME" > "$secret_dir/mongodb-root-username"
printf '%s' "$MONGODB_ROOT_PASSWORD" > "$secret_dir/mongodb-root-password"
secret_manifest="$secret_dir/secret.yaml"
kubectl -n "$namespace" create secret generic "$secret_name" \
  --from-file="$secret_dir/observer-internal-token" \
  --from-file="$secret_dir/collect-token" \
  --from-file="$secret_dir/principal-hash-salt" \
  --from-file="$secret_dir/mongodb-root-username" \
  --from-file="$secret_dir/mongodb-root-password" \
  --dry-run=client -o yaml > "$secret_manifest"
kubectl apply -f "$secret_manifest"

collect_ca_secret=""
if [[ -n "${COLLECT_CA_FILE:-}" ]]; then
  [[ -f "$COLLECT_CA_FILE" ]] || {
    printf 'COLLECT_CA_FILE does not exist: %s\n' "$COLLECT_CA_FILE" >&2
    exit 1
  }
  collect_ca_secret="${COLLECT_CA_SECRET_NAME:-mongodb-dam-collect-ca}"
  ca_manifest="$secret_dir/collect-ca-secret.yaml"
  kubectl -n "$namespace" create secret generic "$collect_ca_secret" \
    --from-file="collect-ca.pem=$COLLECT_CA_FILE" \
    --dry-run=client -o yaml > "$ca_manifest"
  kubectl apply -f "$ca_manifest"
fi

helm_args=(
  upgrade --install "$release" "$repo_root/deploy/helm/mongodb-dam"
  --namespace "$namespace"
  --wait --timeout "${DEPLOY_TIMEOUT:-10m}"
  --set-string "fullnameOverride=$release"
  --set-string "secrets.existingSecret=$secret_name"
  --set-string "assignment.customerId=$CUSTOMER_ID"
  --set-string "assignment.tenantId=$TENANT_ID"
  --set-string "assignment.sourceId=$SOURCE_ID"
  --set-string "assignment.regionalCellId=$REGIONAL_CELL_ID"
  --set-string "assignment.clusterName=$CLUSTER_NAME"
  --set-string "collect.url=$COLLECT_URL"
  --set-string "images.observer.repository=$observer_repository"
  --set-string "images.observer.tag=$tag"
  --set-string "images.outpost.repository=$outpost_repository"
  --set-string "images.outpost.tag=$tag"
)
if [[ -n "$values_file" ]]; then
  helm_args+=(--values "$values_file")
fi
if [[ -n "$collect_ca_secret" ]]; then
  helm_args+=(--set-string "collect.caSecretName=$collect_ca_secret")
fi
if [[ -n "$mongodb_image_tag" ]]; then
  helm_args+=(--set-string "mongodb.image.tag=$mongodb_image_tag")
fi
helm "${helm_args[@]}"

kubectl -n "$namespace" rollout status "daemonset/${release}-observer" --timeout="${DEPLOY_TIMEOUT:-10m}"
kubectl -n "$namespace" rollout status "deployment/${release}-outpost" --timeout="${DEPLOY_TIMEOUT:-10m}"
kubectl -n "$namespace" rollout status "statefulset/${release}-mongodb" --timeout="${DEPLOY_TIMEOUT:-10m}"
