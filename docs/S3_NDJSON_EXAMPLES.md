# S3 NDJSON event examples

The `.ndjson.gz` object decompresses into one compact JSON object per line. The examples below are pretty-printed only for readability. Optional fields appear when the relevant probe and correlation data are available. With `OBSERVER_CAPTURE_QUERY_CONTENT=true`, complete bounded `find`, `aggregate`, `insert`, `update`, and `delete` commands appear in `details.query`; passwords, authentication payloads, tokens, and AWS credentials are never included.

## MongoDB bulk-delete activity

```json
{
  "batch_schema_version": 1,
  "batch_id": "batch-018f6f6e",
  "batch_created_at": "2026-09-10T10:15:31Z",
  "schema_version": 1,
  "event_id": "event-delete-001",
  "observed_at": "2026-09-10T10:15:30.412Z",
  "monotonic_timestamp_ns": 481923410001,
  "customer_id": "customer-demo",
  "tenant_id": "tenant-demo",
  "source_id": "mongodb-demo",
  "regional_cell_id": "cell-ap-south-1",
  "capture": {
    "sensor_id": "observer-ip-10-0-1-10",
    "node_name": "ip-10-0-1-10",
    "source": "cleartext_syscall",
    "confidence": "complete",
    "metadata_only": false,
    "truncated": false
  },
  "kubernetes": {
    "cluster_name": "customer-demo-eks",
    "namespace": "mongodb-dam",
    "pod_name": "mongodb-dam-mongodb-0",
    "pod_uid": "0b45b516-994d-4eba-a2fc-3a559c3ef3f1",
    "container_name": "mongodb"
  },
  "process": {
    "pid": 8124,
    "tgid": 8124,
    "uid": 999,
    "gid": 999,
    "cgroup_id": 72340172839,
    "command": "mongod",
    "executable": "/usr/bin/mongod"
  },
  "identity": {
    "provider": "aws",
    "principal_type": "iam_user",
    "principal_arn": "arn:aws:iam::111122223333:user/dam-demo-alice",
    "account_id": "111122223333",
    "credential_source": "aws_secrets_manager",
    "credential_resource": "arn:aws:secretsmanager:ap-south-1:111122223333:secret:mongodb-dam/demo/direct-user-AbCdEf"
  },
  "event_type": "mongodb_activity",
  "details": {
    "command": "delete",
    "database": "dam_demo",
    "collection": "customer_records",
    "principal": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "principal_hashed": true,
    "delete_scope": "multi",
    "delete_statements": 1,
    "affected_documents": 35,
    "query": {
      "delete": "customer_records",
      "deletes": [{"q": {"demo_batch": "iam-bulk-delete"}, "limit": 0}],
      "$db": "dam_demo"
    },
    "request_id": 4321,
    "response_id": 4321,
    "request_bytes": 156,
    "response_bytes": 45,
    "duration_us": 1874,
    "succeeded": true,
    "expects_response": true,
    "compressed": false,
    "connection": {
      "connection_id": "8124:17",
      "fd": 17,
      "local": {"address": "10.0.1.10", "port": 27017},
      "remote": {"address": "10.0.1.25", "port": 41862},
      "tcp_srtt_us": 312,
      "retransmits": 0,
      "tls": false
    }
  }
}
```

## MongoDB authentication

```json
{
  "batch_schema_version": 1,
  "batch_id": "batch-018f6f6e",
  "batch_created_at": "2026-09-10T10:15:31Z",
  "schema_version": 1,
  "event_id": "event-auth-001",
  "observed_at": "2026-09-10T10:15:27.110Z",
  "monotonic_timestamp_ns": 481920108111,
  "customer_id": "customer-demo",
  "tenant_id": "tenant-demo",
  "source_id": "mongodb-demo",
  "regional_cell_id": "cell-ap-south-1",
  "capture": {"sensor_id": "observer-ip-10-0-1-10", "node_name": "ip-10-0-1-10", "source": "cleartext_syscall", "confidence": "complete", "metadata_only": true, "truncated": false},
  "identity": {"provider": "aws", "principal_type": "iam_user", "principal_arn": "arn:aws:iam::111122223333:user/dam-demo-alice", "account_id": "111122223333", "credential_source": "aws_secrets_manager", "credential_resource": "arn:aws:secretsmanager:ap-south-1:111122223333:secret:mongodb-dam/demo/direct-user-AbCdEf"},
  "event_type": "mongodb_auth",
  "details": {"mechanism": "SCRAM-SHA-256", "principal": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "principal_hashed": true, "succeeded": true, "connection_id": "8124:17"}
}
```

## MongoDB connection lifecycle

```json
{
  "batch_schema_version": 1,
  "batch_id": "batch-018f6f6e",
  "batch_created_at": "2026-09-10T10:15:31Z",
  "schema_version": 1,
  "event_id": "event-connection-001",
  "observed_at": "2026-09-10T10:15:26.901Z",
  "monotonic_timestamp_ns": 481919899001,
  "customer_id": "customer-demo",
  "tenant_id": "tenant-demo",
  "source_id": "mongodb-demo",
  "regional_cell_id": "cell-ap-south-1",
  "capture": {"sensor_id": "observer-ip-10-0-1-10", "node_name": "ip-10-0-1-10", "source": "kernel_tracepoint", "confidence": "complete", "metadata_only": true, "truncated": false},
  "event_type": "mongodb_connection",
  "details": {"state": "established", "connection": {"connection_id": "8124:17", "fd": 17, "local": {"address": "10.0.1.10", "port": 27017}, "remote": {"address": "10.0.1.25", "port": 41862}, "tcp_srtt_us": 312, "retransmits": 0, "tls": false}, "duration_us": 844}
}
```

## DNS activity

```json
{
  "batch_schema_version": 1,
  "batch_id": "batch-dns-001",
  "batch_created_at": "2026-09-10T10:16:01Z",
  "schema_version": 1,
  "event_id": "event-dns-001",
  "observed_at": "2026-09-10T10:16:00.250Z",
  "monotonic_timestamp_ns": 481953248991,
  "customer_id": "customer-demo",
  "tenant_id": "tenant-demo",
  "source_id": "mongodb-demo",
  "regional_cell_id": "cell-ap-south-1",
  "capture": {"sensor_id": "observer-ip-10-0-1-10", "node_name": "ip-10-0-1-10", "source": "cleartext_syscall", "confidence": "complete", "metadata_only": true, "truncated": false},
  "event_type": "dns_activity",
  "details": {"operation": "response", "transport": "udp", "query_id": 18422, "name": "mongodb-dam-mongodb.mongodb-dam.svc.cluster.local", "record_type": "A", "response_code": 0, "answer_count": 1, "duration_us": 590, "connection": {"connection_id": "8124:22", "fd": 22, "remote": {"address": "10.0.0.10", "port": 53}}}
}
```

## Host I/O latency

```json
{
  "batch_schema_version": 1,
  "batch_id": "batch-io-001",
  "batch_created_at": "2026-09-10T10:17:01Z",
  "schema_version": 1,
  "event_id": "event-io-001",
  "observed_at": "2026-09-10T10:17:00.004Z",
  "monotonic_timestamp_ns": 482013002331,
  "customer_id": "customer-demo",
  "tenant_id": "tenant-demo",
  "source_id": "mongodb-demo",
  "regional_cell_id": "cell-ap-south-1",
  "capture": {"sensor_id": "observer-ip-10-0-1-10", "node_name": "ip-10-0-1-10", "source": "kernel_tracepoint", "confidence": "complete", "metadata_only": true, "truncated": false},
  "process": {"pid": 8124, "tgid": 8124, "uid": 999, "gid": 999, "cgroup_id": 72340172839, "command": "mongod", "executable": "/usr/bin/mongod"},
  "event_type": "host_io",
  "details": {"operation": "fsync", "duration_us": 18340, "fd": 42, "result": 0}
}
```

## CPU/off-CPU/lock profile sample

```json
{
  "batch_schema_version": 1,
  "batch_id": "batch-profile-001",
  "batch_created_at": "2026-09-10T10:18:01Z",
  "schema_version": 1,
  "event_id": "event-profile-001",
  "observed_at": "2026-09-10T10:18:00.501Z",
  "monotonic_timestamp_ns": 482073499000,
  "customer_id": "customer-demo",
  "tenant_id": "tenant-demo",
  "source_id": "mongodb-demo",
  "regional_cell_id": "cell-ap-south-1",
  "capture": {"sensor_id": "observer-ip-10-0-1-10", "node_name": "ip-10-0-1-10", "source": "perf_event", "confidence": "complete", "metadata_only": true, "truncated": false},
  "process": {"pid": 8124, "tgid": 8124, "uid": 999, "gid": 999, "cgroup_id": 72340172839, "command": "mongod", "executable": "/usr/bin/mongod"},
  "event_type": "profile",
  "details": {"profile_type": "off_cpu", "period_hz": 49, "count": 1, "user_stack_id": 18, "kernel_stack_id": 7, "duration_us": 6200, "user_stack_addresses": [140122849120304, 140122849121991], "kernel_stack_addresses": [18446744071579869184]}
}
```

## Process lifecycle

```json
{
  "batch_schema_version": 1,
  "batch_id": "batch-process-001",
  "batch_created_at": "2026-09-10T10:19:01Z",
  "schema_version": 1,
  "event_id": "event-process-001",
  "observed_at": "2026-09-10T10:19:00Z",
  "monotonic_timestamp_ns": 482132998000,
  "customer_id": "customer-demo",
  "tenant_id": "tenant-demo",
  "source_id": "mongodb-demo",
  "regional_cell_id": "cell-ap-south-1",
  "capture": {"sensor_id": "observer-ip-10-0-1-10", "node_name": "ip-10-0-1-10", "source": "kernel_tracepoint", "confidence": "complete", "metadata_only": true, "truncated": false},
  "process": {"pid": 8124, "tgid": 8124, "uid": 999, "gid": 999, "cgroup_id": 72340172839, "command": "mongod", "executable": "/usr/bin/mongod"},
  "event_type": "process_lifecycle",
  "details": {"state": "exec", "executable": "/usr/bin/mongod"}
}
```

## Sensor health

```json
{
  "batch_schema_version": 1,
  "batch_id": "batch-health-001",
  "batch_created_at": "2026-09-10T10:20:01Z",
  "schema_version": 1,
  "event_id": "event-health-001",
  "observed_at": "2026-09-10T10:20:00Z",
  "monotonic_timestamp_ns": 482192998000,
  "customer_id": "customer-demo",
  "tenant_id": "tenant-demo",
  "source_id": "mongodb-demo",
  "regional_cell_id": "cell-ap-south-1",
  "capture": {"sensor_id": "observer-ip-10-0-1-10", "node_name": "ip-10-0-1-10", "source": "sensor", "confidence": "complete", "metadata_only": true, "truncated": false},
  "event_type": "sensor_health",
  "details": {"status": "degraded", "component": "ring_buffer", "reason": "consumer lag", "dropped_events": 12, "parse_errors": 1, "spool_bytes": 8388608}
}
```
