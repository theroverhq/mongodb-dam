# Optional regional endpoint HTTP-push contract

S3 gzip-NDJSON is now the deployment path for the DAM demo; see [S3_EXPORT_CONTRACT.md](S3_EXPORT_CONTRACT.md). This HTTP exporter remains supported for the bundled in-cluster receiver and compatibility testing.

Outpost treats the destination as an opaque regional ingress endpoint. It does not address Collect directly and has no dependency on the eventual regional routing implementation. The current Foundry, Command, Collect, and connector-catalog repositories have not been modified.

## Request

`POST <the exact configured OUTPOST_ENDPOINT>`

The examples use `/v1/ingest/mongodb-dam`, but the customer-side code does not append or assume a path. Redirects are deliberately not followed so a bearer token cannot be forwarded to another origin.

Headers:

- `content-type: application/json`
- `authorization: Bearer <source credential>`
- `idempotency-key: <batch_id>`

Body: one `DamBatch` from `crates/schema`, with `schema_version: 1`. Assignment fields are repeated on the batch and every event so the regional ingress can reject cross-customer or cross-source injection before persistence or forwarding.

MongoDB activity may include an optional salted `principal`, `delete_scope`, `delete_statements`, `affected_documents`, and `query`. These are capture facts, not customer-side findings: Outpost forwards them so Collect can make them available to Sentinel for downstream rule evaluation. `query` is present only when the customer explicitly enables query-content capture and the complete supported command fits the bounded capture prefix. Clear MongoDB usernames, authentication payloads, secret values, and AWS credentials are never part of the HTTP-push contract.

The opt-in direct-user demo can add this root-level identity metadata to a MongoDB activity/auth event whose salted principal matches the protected Outpost mapping:

```json
{
  "identity": {
    "provider": "aws",
    "principal_type": "iam_user",
    "principal_arn": "arn:aws:iam::111122223333:user/dam-demo-alice",
    "account_id": "111122223333",
    "credential_source": "aws_secrets_manager",
    "credential_resource": "arn:aws:secretsmanager:ap-south-1:111122223333:secret:mongodb-dam-demo-AbCdEf"
  }
}
```

Outpost never trusts an `identity` supplied by Observer input: it clears unmatched identity and replaces matched identity from its read-only mapping file. This clear IAM/secret-ARN export is explicitly demoware. Production identity governance and mapping lifecycle belong in the regional product design.

## Required receiver behavior

1. Authenticate the source credential and resolve it to exactly one customer, tenant, source, and regional cell assignment.
2. Enforce a compressed and uncompressed request-size limit. Outpost defaults to 5 MiB per Observer-to-Outpost batch.
3. Parse with unknown-field rejection and validate every repeated customer/tenant/source/cell assignment against the source credential.
4. Use `(source_id, batch_id)` as the idempotency key before producing downstream records.
5. Return `202 Accepted` only after the regional durability boundary is crossed. Internal forwarding to Collect or another service happens behind this endpoint.
6. Return `409 Conflict` for an already accepted idempotency key; Outpost treats that as acknowledged.
7. Return `429` or `5xx` for retryable failures. Outpost retains and retries the batch.
8. Return other `4xx` statuses for permanent contract/auth failures. Outpost retains these for operator review rather than deleting them.

Suggested success body:

```json
{
  "status": "accepted",
  "receipt_id": "rcpt_...",
  "ingest_batch_id": "batch-..."
}
```

## Command/source model additions

The source contract needs a new `http_push` collection mode alongside the existing pull/drop modes, with at least:

- source type `mongodb_dam`;
- immutable customer/tenant/regional-cell assignment;
- credential lifecycle and rotation metadata;
- enabled event schema versions;
- maximum request and event counts;
- optional IP/private-link policy;
- replay/idempotency retention window;
- health fields for last accepted batch, last event time, and rejection counts.

Credential material should be stored through the existing secret-management boundary, never returned by read APIs after creation, and independently rotatable from a source definition.

## Mock

`mock-endpoint` implements the success, bearer authentication, schema validation, and duplicate response behavior. It is deliberately not a production receiver and keeps idempotency state only in memory.
