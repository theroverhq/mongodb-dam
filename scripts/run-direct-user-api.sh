#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=load-env.sh
source "$repo_root/scripts/load-env.sh"

for command_name in aws kubectl python3 grep mktemp; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

: "${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT}"
: "${AWS_REGION:?Set AWS_REGION}"
: "${DEMO_IAM_PRINCIPAL_ARN:?Set DEMO_IAM_PRINCIPAL_ARN}"
export AWS_PAGER=''

current_context="$(kubectl config current-context)"
if [[ "$current_context" != "$EXPECTED_KUBE_CONTEXT" ]]; then
  printf 'Wrong Kubernetes context. Expected %s, current %s.\n' \
    "$EXPECTED_KUBE_CONTEXT" "$current_context" >&2
  exit 1
fi

if [[ -n "${DIRECT_USER_AWS_ACCESS_KEY_ID:-}" \
  || -n "${DIRECT_USER_AWS_SECRET_ACCESS_KEY:-}" ]]; then
  : "${DIRECT_USER_AWS_ACCESS_KEY_ID:?Set the matching direct-user access key}"
  : "${DIRECT_USER_AWS_SECRET_ACCESS_KEY:?Set the matching direct-user secret key}"
  export AWS_ACCESS_KEY_ID="$DIRECT_USER_AWS_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$DIRECT_USER_AWS_SECRET_ACCESS_KEY"
  if [[ -n "${DIRECT_USER_AWS_SESSION_TOKEN:-}" ]]; then
    export AWS_SESSION_TOKEN="$DIRECT_USER_AWS_SESSION_TOKEN"
  else
    unset AWS_SESSION_TOKEN || true
  fi
  unset AWS_PROFILE AWS_DEFAULT_PROFILE || true
elif [[ -n "${DIRECT_USER_AWS_SESSION_TOKEN:-}" ]]; then
  printf '%s\n' 'DIRECT_USER_AWS_SESSION_TOKEN requires matching direct-user access and secret keys.' >&2
  exit 1
elif [[ -n "${DIRECT_USER_AWS_PROFILE:-}" ]]; then
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_PROFILE || true
  export AWS_PROFILE="$DIRECT_USER_AWS_PROFILE"
else
  printf '%s\n' 'Set DIRECT_USER_AWS_PROFILE or the DIRECT_USER_AWS_* credential fields in .env.' >&2
  exit 1
fi

# Do not expose unrelated customer-side secrets to the local gateway process.
unset \
  OUTPOST_AWS_ACCESS_KEY_ID OUTPOST_AWS_SECRET_ACCESS_KEY OUTPOST_AWS_SESSION_TOKEN \
  DIRECT_USER_AWS_ACCESS_KEY_ID DIRECT_USER_AWS_SECRET_ACCESS_KEY \
  DIRECT_USER_AWS_SESSION_TOKEN OBSERVER_INTERNAL_TOKEN BEARER_TOKEN \
  PRINCIPAL_HASH_SALT MONGODB_ROOT_PASSWORD || true

caller_arn="$(aws --region "$AWS_REGION" sts get-caller-identity --query Arn --output text)"
canonical_caller="$caller_arn"
if [[ "$caller_arn" =~ ^arn:([^:]+):sts::([0-9]{12}):assumed-role/(.+)/[^/]+$ ]]; then
  canonical_caller="arn:${BASH_REMATCH[1]}:iam::${BASH_REMATCH[2]}:role/${BASH_REMATCH[3]}"
fi
if [[ "$canonical_caller" != "$DEMO_IAM_PRINCIPAL_ARN" ]]; then
  printf 'Wrong AWS caller. Expected %s, current %s.\n' \
    "$DEMO_IAM_PRINCIPAL_ARN" "$caller_arn" >&2
  exit 1
fi

namespace="${NAMESPACE:-mongodb-dam}"
release="${RELEASE:-mongodb-dam}"
mongodb_port="${MONGODB_LOCAL_PORT:-27018}"
use_existing_forward="${USE_EXISTING_MONGODB_FORWARD:-false}"
if [[ "$use_existing_forward" != true && "$use_existing_forward" != false ]]; then
  printf '%s\n' 'USE_EXISTING_MONGODB_FORWARD must be true or false.' >&2
  exit 1
fi

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

if [[ "$use_existing_forward" == false ]]; then
  kubectl -n "$namespace" port-forward \
    "service/${release}-mongodb" "$mongodb_port:27017" \
    >"$tmp_dir/mongodb-port-forward.log" 2>&1 &
  forward_pid=$!
  ready=false
  for ((attempt = 1; attempt <= 80; attempt++)); do
    if grep -q 'Forwarding from' "$tmp_dir/mongodb-port-forward.log"; then
      ready=true
      break
    fi
    if ! kill -0 "$forward_pid" >/dev/null 2>&1; then
      sed -n '1,80p' "$tmp_dir/mongodb-port-forward.log" >&2
      exit 1
    fi
    sleep 0.25
  done
  if [[ "$ready" != true ]]; then
    sed -n '1,80p' "$tmp_dir/mongodb-port-forward.log" >&2
    printf '%s\n' 'MongoDB port-forward did not become ready.' >&2
    exit 1
  fi
fi

if [[ "${DIRECT_USER_MONGOSH_MODE:-auto}" == docker \
  || ( "${DIRECT_USER_MONGOSH_MODE:-auto}" == auto \
    && -z "$(command -v "${MONGOSH_BIN:-mongosh}" 2>/dev/null)" ) ]]; then
  command -v docker >/dev/null || {
    printf '%s\n' 'docker is required because a local mongosh was not found.' >&2
    exit 1
  }
fi

export MONGODB_HOST=127.0.0.1
export MONGODB_PORT="$mongodb_port"
export DEMO_AWS_SECRET_ID="${DEMO_AWS_SECRET_ID:-mongodb-dam/demo/direct-user}"
export MONGODB_CLIENT_IMAGE="${MONGODB_CLIENT_IMAGE:-mongo:8.0.29-noble}"
export DIRECT_USER_API_LOCAL_PORT="${DIRECT_USER_API_LOCAL_PORT:-18082}"
export DIRECT_USER_MONGOSH_MODE="${DIRECT_USER_MONGOSH_MODE:-auto}"
export DIRECT_USER_RUN_MARKER_FILE="${DIRECT_USER_RUN_MARKER_FILE:-}"

printf 'AWS caller verified: %s\n' "$caller_arn"
printf 'Direct-user curl API: http://127.0.0.1:%s\n' "$DIRECT_USER_API_LOCAL_PORT"
printf '%s\n' 'Keep this process running while issuing curl commands. Press Ctrl-C to stop.'
python3 "$repo_root/demo/client-api/server.py"
