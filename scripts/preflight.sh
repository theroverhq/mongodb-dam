#!/usr/bin/env bash
set -euo pipefail

for command_name in kubectl helm docker; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

expected_context="${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT to the target customer-cluster context}"
current_context="$(kubectl config current-context)"
if [[ "$current_context" != "$expected_context" ]]; then
  printf 'Wrong Kubernetes context. Expected %s, current %s.\n' "$expected_context" "$current_context" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helm lint "$repo_root/deploy/helm/mongodb-dam" >/dev/null
kubectl auth can-i create daemonsets.apps --all-namespaces | grep -qx yes || {
  printf '%s\n' 'Current identity cannot create DaemonSets.' >&2
  exit 1
}
kubectl auth can-i create clusterroles.rbac.authorization.k8s.io | grep -qx yes || {
  printf '%s\n' 'Current identity cannot create the Outpost ClusterRole.' >&2
  exit 1
}

non_linux="$(kubectl get nodes -o jsonpath='{range .items[?(@.status.nodeInfo.operatingSystem!="linux")]}{.metadata.name}{"\n"}{end}')"
if [[ -n "$non_linux" ]]; then
  printf 'Non-Linux nodes will not run Observer:\n%s\n' "$non_linux"
fi

node_kernels="$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.nodeInfo.kernelVersion}{"\n"}{end}')"
old_kernels="$(printf '%s\n' "$node_kernels" | awk '
  NF >= 2 {
    version = $2
    sub(/-.*/, "", version)
    split(version, part, ".")
    major = part[1] + 0
    minor = part[2] + 0
    if (major < 5 || (major == 5 && minor < 8)) print $0
  }
' || true)"
if [[ -n "$old_kernels" ]]; then
  printf 'Nodes that may be older than the required Linux 5.8 baseline:\n%s\n' "$old_kernels" >&2
  exit 1
fi

mongodb_image_tag="${MONGODB_IMAGE_TAG:-8.0.29-noble}"
if [[ "$mongodb_image_tag" == 8.* ]]; then
  incompatible_kernels="$(printf '%s\n' "$node_kernels" | awk '
    NF >= 2 {
      version = $2
      sub(/-.*/, "", version)
      split(version, part, ".")
      major = part[1] + 0
      minor = part[2] + 0
      patch = part[3] + 0
      if ((major == 6 && minor >= 19) || (major == 7 && minor == 0 && patch <= 13)) print $0
    }
  ' || true)"
  if [[ -n "$incompatible_kernels" ]]; then
    printf 'MongoDB 8.x cannot start on Linux kernels 6.19 through 7.0.13. Incompatible nodes:\n%s\n' "$incompatible_kernels" >&2
    printf '%s\n' 'Use supported node kernels below 6.19 or kernel 7.0.14+, then rerun preflight.' >&2
    exit 1
  fi
fi

printf 'Preflight passed for Kubernetes context: %s\n' "$current_context"
printf '%s\n' 'BTF and tracefs are verified by Observer startup because Kubernetes does not expose them through the Node API.'
