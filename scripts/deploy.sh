#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT}"
: "${CUSTOMER_ID:?Set CUSTOMER_ID}"
: "${TENANT_ID:?Set TENANT_ID}"
: "${SOURCE_ID:?Set SOURCE_ID}"
: "${REGIONAL_CELL_ID:?Set REGIONAL_CELL_ID}"
: "${CLUSTER_NAME:?Set CLUSTER_NAME}"
: "${ENDPOINT:?Set ENDPOINT to the regional HTTPS receiver}"
: "${BEARER_TOKEN:?Set BEARER_TOKEN}"
: "${OBSERVER_INTERNAL_TOKEN:?Set OBSERVER_INTERNAL_TOKEN}"
: "${PRINCIPAL_HASH_SALT:?Set PRINCIPAL_HASH_SALT}"
: "${MONGODB_ROOT_USERNAME:?Set MONGODB_ROOT_USERNAME}"
: "${MONGODB_ROOT_PASSWORD:?Set MONGODB_ROOT_PASSWORD}"

demo_mode="${DEMO_MODE:-false}"
if [[ "$demo_mode" != "true" && "$demo_mode" != "false" ]]; then
  printf '%s\n' 'DEMO_MODE must be true or false.' >&2
  exit 1
fi
if [[ "$demo_mode" == "true" \
  && ! "${DIRECT_USER_MAPPING_KEY:-identity-mapping.json}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  printf '%s\n' 'DIRECT_USER_MAPPING_KEY must be a single Kubernetes Secret data key.' >&2
  exit 1
fi
if [[ "$ENDPOINT" != https://* \
  && !( "$demo_mode" == "true" \
    && "$ENDPOINT" == "http://mock-endpoint:8088/v1/ingest/mongodb-dam" ) ]]; then
  printf '%s\n' 'ENDPOINT must use HTTPS. Demo mode permits only the bundled http://mock-endpoint endpoint.' >&2
  exit 1
fi

"$repo_root/scripts/preflight.sh"

namespace="${NAMESPACE:-mongodb-dam}"
release="${RELEASE:-mongodb-dam}"
tag="${TAG:-dev}"
observer_repository="${OBSERVER_IMAGE_REPOSITORY:-mongodb-dam-observer}"
outpost_repository="${OUTPOST_IMAGE_REPOSITORY:-mongodb-dam-outpost}"
demo_api_repository="${DEMO_API_IMAGE_REPOSITORY:-mongodb-dam-demo-api}"
demo_receiver_repository="${DEMO_RECEIVER_IMAGE_REPOSITORY:-mongodb-dam-mock-endpoint}"
mongodb_image_tag="${MONGODB_IMAGE_TAG:-}"
secret_name="${SECRET_NAME:-mongodb-dam-secrets}"
identity_mapping_secret="${DIRECT_USER_MAPPING_SECRET:-mongodb-dam-demo-direct-user}"
identity_mapping_key="${DIRECT_USER_MAPPING_KEY:-identity-mapping.json}"
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
printf '%s' "$BEARER_TOKEN" > "$secret_dir/bearer-token"
printf '%s' "$PRINCIPAL_HASH_SALT" > "$secret_dir/principal-hash-salt"
printf '%s' "$MONGODB_ROOT_USERNAME" > "$secret_dir/mongodb-root-username"
printf '%s' "$MONGODB_ROOT_PASSWORD" > "$secret_dir/mongodb-root-password"
secret_manifest="$secret_dir/secret.yaml"
kubectl -n "$namespace" create secret generic "$secret_name" \
  --from-file="$secret_dir/observer-internal-token" \
  --from-file="$secret_dir/bearer-token" \
  --from-file="$secret_dir/principal-hash-salt" \
  --from-file="$secret_dir/mongodb-root-username" \
  --from-file="$secret_dir/mongodb-root-password" \
  --dry-run=client -o yaml > "$secret_manifest"
kubectl apply -f "$secret_manifest"

destination_ca_secret=""
if [[ -n "${ENDPOINT_CA_FILE:-}" ]]; then
  [[ -f "$ENDPOINT_CA_FILE" ]] || {
    printf 'ENDPOINT_CA_FILE does not exist: %s\n' "$ENDPOINT_CA_FILE" >&2
    exit 1
  }
  destination_ca_secret="${ENDPOINT_CA_SECRET_NAME:-mongodb-dam-destination-ca}"
  ca_manifest="$secret_dir/destination-ca-secret.yaml"
  kubectl -n "$namespace" create secret generic "$destination_ca_secret" \
    --from-file="destination-ca.pem=$ENDPOINT_CA_FILE" \
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
  --set-string "destination.endpoint=$ENDPOINT"
  --set-string "images.observer.repository=$observer_repository"
  --set-string "images.observer.tag=$tag"
  --set-string "images.outpost.repository=$outpost_repository"
  --set-string "images.outpost.tag=$tag"
)
if [[ -n "$values_file" ]]; then
  helm_args+=(--values "$values_file")
fi
if [[ -n "$destination_ca_secret" ]]; then
  helm_args+=(--set-string "destination.caSecretName=$destination_ca_secret")
fi
if [[ -n "$mongodb_image_tag" ]]; then
  helm_args+=(--set-string "mongodb.image.tag=$mongodb_image_tag")
fi
if [[ "$demo_mode" == "true" ]]; then
  helm_args+=(
    --set "demo.enabled=true"
    --set-string "demo.api.image.repository=$demo_api_repository"
    --set-string "demo.api.image.tag=$tag"
    --set-string "demo.receiver.image.repository=$demo_receiver_repository"
    --set-string "demo.receiver.image.tag=$tag"
    --set "outpost.identityMapping.enabled=true"
    --set-string "outpost.identityMapping.secretName=$identity_mapping_secret"
    --set-string "outpost.identityMapping.key=$identity_mapping_key"
  )
fi
helm "${helm_args[@]}"

kubectl -n "$namespace" rollout status "daemonset/${release}-observer" --timeout="${DEPLOY_TIMEOUT:-10m}"
kubectl -n "$namespace" rollout status "deployment/${release}-outpost" --timeout="${DEPLOY_TIMEOUT:-10m}"
kubectl -n "$namespace" rollout status "statefulset/${release}-mongodb" --timeout="${DEPLOY_TIMEOUT:-10m}"
if [[ "$demo_mode" == "true" ]]; then
  kubectl -n "$namespace" rollout status "deployment/${release}-demo-api" --timeout="${DEPLOY_TIMEOUT:-10m}"
  kubectl -n "$namespace" rollout status "deployment/${release}-demo-receiver" --timeout="${DEPLOY_TIMEOUT:-10m}"
fi
