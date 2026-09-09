# Known gaps and accuracy boundaries

## Collection gaps

- DNS query decoding is not implemented. MongoDB TCP activity is covered, but DNS packets and resolver calls are not emitted.
- Packet-level SYN/SYN-ACK timestamps, TCP reset causes, zero-window events, and keep-alive probe reasons are not decoded. The current lifecycle layer emits connect-started, accepted, close, retransmit, and sampled SRTT events.
- OpenSSL uprobes cover `SSL_read`, `SSL_write`, their `_ex` forms, `SSL_set_fd`, and `SSL_free`. Other TLS libraries and some BIO configurations cannot be decrypted by this sensor.
- `OP_MSG` is the activity protocol. Legacy `OP_QUERY` command decoding is not implemented.
- A truncated compressed frame cannot be decoded because arbitrary partial decompression is unsafe. It is counted as a parse gap; no bytes are exported.
- Metadata located beyond the 1 KiB privacy prefix is intentionally unavailable. For example, a large write can still report `insert` and its collection while `$db` may be absent if the driver places it after a large inline document.
- SCRAM usernames generally reside inside SASL payloads. Those payloads are intentionally not decoded, so mechanism/status may be present while principal is absent.

## Interpretation limits

- Request/response delta is application-observed latency, not pure server execution time.
- TCP SRTT is the kernel's smoothed estimate, not the exact RTT of a specific MongoDB request.
- `pread`/`pwrite`/sync timing is process syscall latency associated with `mongod`; it is not a direct WiredTiger internal span or block-device completion trace.
- Only page faults slower than the eBPF threshold are emitted individually to avoid a telemetry storm.
- Off-CPU intervals below 1 ms are suppressed to bound profiling volume; on-CPU sampling remains continuous at the configured frequency.
- CPU stacks are raw addresses. Symbolization, aggregation, retention, and flamegraph rendering are not in this customer-side repository.
- `pthread_mutex_lock` probes describe libc mutex waits. They do not label MongoDB/WiredTiger lock objects by source-level name.

## Platform gaps

- The shipped probe source supports x86_64 and arm64 syscall ABIs. Every target kernel/image combination still needs qualification.
- MongoDB 8 currently refuses to start on Linux kernels 6.19 through 7.0.13 because of an [upstream TCMalloc incompatibility documented by MongoDB](https://www.mongodb.com/docs/manual/release-notes/8.0/#mongodb-is-incompatible-with-linux-kernel-6.19-through-7.0.13). Preflight blocks that combination; use a supported node kernel.
- Privileged DaemonSets, host PID, tracefs, and BTF are hard requirements. Restricted managed/serverless nodes cannot run it.
- The Outpost file spool is single-writer, so the Helm chart intentionally requires one replica. Regional high availability begins after Collect accepts the batch.
- Kubernetes NetworkPolicy cannot safely allow an HTTPS FQDN by itself. Enforce the regional hostname/private endpoint using the cloud firewall, egress gateway, or CNI FQDN policy in the customer account.

## Product gaps for the next phase

- Command does not yet model `http_push` or `mongodb_dam` sources.
- Collect does not yet expose the production ingest route, credential validation, durable idempotency store, or downstream event mapping.
- Regional querying, alert rules, retention, RBAC, audit evidence, dashboards, symbol storage, and flamegraph construction remain to be built.
- There is no operator-managed MongoDB topology here. The bundled Community database is one standalone StatefulSet for product validation, not a production replica set, backup, restore, or upgrade solution.
