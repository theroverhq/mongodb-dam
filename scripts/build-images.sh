#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="${TAG:-dev}"
registry="${REGISTRY:-}"
push_images="${PUSH_IMAGES:-false}"
build_mock="${BUILD_MOCK:-false}"

prefix=""
if [[ -n "$registry" ]]; then
  prefix="${registry%/}/"
fi

observer_image="${prefix}mongodb-dam-observer:${tag}"
outpost_image="${prefix}mongodb-dam-outpost:${tag}"
mock_image="${prefix}mongodb-dam-mock-collect:${tag}"

docker build --file "$repo_root/Dockerfile.observer" --tag "$observer_image" "$repo_root"
docker build --file "$repo_root/Dockerfile.outpost" --target outpost --tag "$outpost_image" "$repo_root"
if [[ "$build_mock" == "true" ]]; then
  docker build --file "$repo_root/Dockerfile.outpost" --target mock-collect --tag "$mock_image" "$repo_root"
fi

if [[ "$push_images" == "true" ]]; then
  if [[ -z "$registry" ]]; then
    printf '%s\n' 'REGISTRY is required when PUSH_IMAGES=true' >&2
    exit 1
  fi
  docker push "$observer_image"
  docker push "$outpost_image"
  if [[ "$build_mock" == "true" ]]; then
    docker push "$mock_image"
  fi
fi

printf 'Observer image: %s\nOutpost image: %s\n' "$observer_image" "$outpost_image"
if [[ "$build_mock" == "true" ]]; then
  printf 'Mock Collect image: %s\n' "$mock_image"
fi
