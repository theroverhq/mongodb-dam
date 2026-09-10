# S3 gzip-NDJSON export contract

Outpost can upload captured DAM events directly to an S3 bucket. Events are metadata-only by default; the demoware can opt into bounded MongoDB query content with `OBSERVER_CAPTURE_QUERY_CONTENT=true`. Set:

```text
OUTPOST_DESTINATION=s3
OUTPOST_S3_BUCKET=<bucket name>
OUTPOST_S3_PREFIX=<non-empty object prefix>
AWS_REGION=<bucket region>
```

`OUTPOST_S3_BUCKET` and `OUTPOST_S3_PREFIX` are read by the Outpost process itself. The Helm chart exposes the equivalent values under `destination.s3` and `scripts/deploy.sh` copies the shell environment into those chart values.

All local entry-point scripts load the ignored root `.env`; [.env.example](../.env.example) is the complete field reference. The AWS SDK uses its normal credential provider chain inside Kubernetes. This can be EKS Pod Identity, IRSA, a node role, or standard `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional `AWS_SESSION_TOKEN` container variables.

For this disposable demo, put the static values in `.env` as `OUTPOST_AWS_ACCESS_KEY_ID`, `OUTPOST_AWS_SECRET_ACCESS_KEY`, and optional `OUTPOST_AWS_SESSION_TOKEN`. `scripts/deploy.sh` copies them into a Kubernetes Secret under the standard names expected by the SDK. This keeps Outpost credentials separate from the local administrator profile/keys used to provision the IAM demo and inspect S3. The deploy script still accepts legacy standard `AWS_*` values only when the scoped variables are not defined. Do not use this static-global-credential path for production.

The principal needs `s3:PutObject` on:

```text
arn:aws:s3:::<bucket>/<prefix>/*
```

The administrator running the viewer scripts separately needs `s3:ListBucket` on the bucket and `s3:GetObject` under the prefix. A cross-account bucket also needs a bucket policy granting the Outpost credential access. Add the relevant KMS permissions if the bucket policy requires SSE-KMS. Outpost does not create the bucket or change its policy.

## Object layout

Outpost writes one object for every accepted Observer batch:

```text
s3://<bucket>/<prefix>/customer_id=<customer>/tenant_id=<tenant>/regional_cell_id=<cell>/source_id=<source>/date=YYYY-MM-DD/hour=HH/<batch-id>.ndjson.gz
```

Unsafe bytes in identity and batch-ID path segments are percent-encoded. Leading and trailing `/` characters are removed from the configured prefix.

Each upload uses:

```text
Content-Type: application/x-ndjson
Content-Encoding: gzip
```

Every decompressed line is one complete JSON event. Batch fields required for replay and provenance are copied onto every line as `batch_schema_version`, `batch_id`, and `batch_created_at`; the remaining fields are the versioned `DamEvent` schema.

The object key is deterministic for a batch. Outpost retains the original batch in its durable PVC spool until `PutObject` succeeds. A retry uploads the same bytes to the same key, so it does not create a second logical object name. All S3 failures are retryable from Outpost's perspective; unlike the HTTP exporter, S3 errors are not quarantined automatically.

## Inspect an object

The repository viewer scripts load `.env` automatically. If you use the raw AWS CLI examples below, load it into that shell first:

```bash
set -a
source .env
set +a
```

```bash
aws s3 cp "s3://$OUTPOST_S3_BUCKET/<object-key>" - \
  | gzip -dc \
  | jq .
```

List the newest objects under the configured prefix:

```bash
aws s3api list-objects-v2 \
  --bucket "$OUTPOST_S3_BUCKET" \
  --prefix "${OUTPOST_S3_PREFIX%/}/" \
  --query 'reverse(sort_by(Contents,&LastModified))[:10].[LastModified,Key,Size]' \
  --output table
```

See [S3 NDJSON examples](S3_NDJSON_EXAMPLES.md) for every event type.

## Optional local S3-compatible endpoint

These variables exist for local integration testing only:

```text
OUTPOST_S3_ENDPOINT_URL=http://localhost:9000
OUTPOST_S3_FORCE_PATH_STYLE=true
```

Non-local endpoint overrides must use HTTPS. Leave both unset when writing to AWS S3.
