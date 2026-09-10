#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=load-env.sh
source "$repo_root/scripts/load-env.sh"

for command_name in aws gzip jq mktemp; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

: "${OUTPOST_S3_BUCKET:?Set OUTPOST_S3_BUCKET}"
: "${OUTPOST_S3_PREFIX:?Set OUTPOST_S3_PREFIX}"
: "${AWS_REGION:?Set AWS_REGION}"

event_type="${EVENT_TYPE:-mongodb_activity}"
database="${DATABASE:-}"
max_objects="${MAX_OBJECTS:-100}"
if [[ ! "$max_objects" =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' 'MAX_OBJECTS must be a positive integer.' >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
keys_file="$tmp_dir/keys"
events_file="$tmp_dir/events.ndjson"
s3_prefix="${OUTPOST_S3_PREFIX#/}"
s3_prefix="${s3_prefix%/}/"

aws s3api list-objects-v2 \
  --region "$AWS_REGION" \
  --bucket "$OUTPOST_S3_BUCKET" \
  --prefix "$s3_prefix" \
  --max-items "$max_objects" \
  --output json \
  | jq -r '(.Contents // []) | sort_by(.LastModified) | reverse | .[].Key | select(endswith(".ndjson.gz"))' \
  >"$keys_file"

if [[ ! -s "$keys_file" ]]; then
  printf 'No objects found under s3://%s/%s\n' \
    "$OUTPOST_S3_BUCKET" "$s3_prefix" >&2
  exit 1
fi

object_index=0
while IFS= read -r key; do
  object_index=$((object_index + 1))
  object_file="$tmp_dir/object-$object_index.ndjson.gz"
  aws s3api get-object \
    --region "$AWS_REGION" \
    --bucket "$OUTPOST_S3_BUCKET" \
    --key "$key" \
    "$object_file" >/dev/null
  gzip -dc "$object_file" >>"$events_file"
done <"$keys_file"

jq -s \
  --arg event_type "$event_type" \
  --arg database "$database" '
    [.[]
      | select($event_type == "all" or .event_type == $event_type)
      | select($database == "" or .details.database == $database)]
    | unique_by(.event_id)
    | sort_by(.observed_at)
  ' "$events_file"
