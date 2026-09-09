# Coverage gaps and accuracy boundaries

## Gaps closed in this revision

- Destination coupling was removed. Outpost now accepts one opaque endpoint and one bearer token; no Collect route, header, or credential model is assumed.
- Bounded legacy `OP_QUERY`/`OP_REPLY` parsing now complements `OP_MSG` and compressed-wrapper decoding.
- SCRAM client-first usernames are extracted only long enough to produce a salted hash. The clear username and the remainder of the SCRAM exchange never enter an event.
- Plaintext UDP DNS queries and responses from MongoDB processes now produce metadata-only events with correlation latency.
- TCP lifecycle coverage now includes handshake-established events and duration when a start transition is observable, peer versus active reset direction, zero-window signals, and state-derived `ETIMEDOUT` events in addition to connect, accept, close, retransmit, and sampled SRTT.
- TLS discovery now checks both OpenSSL and BoringSSL mappings and falls back to exported `SSL_*` symbols in the MongoDB executable for compatible static linking.
- SCRAM identities, including modern speculative authentication in `hello`, are correlated to later commands on the same physical connection as salted hashes.
- Delete command arrays and OP_MSG document sequences are classified as single, multi, or mixed; response counts can produce the node-local `mongodb.bulk_delete` finding.

## Remaining capture boundaries

- A truncated compressed frame cannot be decoded safely. Compression destroys field locality, and retaining a full arbitrary body would violate the bounded-capture privacy design. The frame is counted as a parse gap and no payload bytes are exported.
- Metadata beyond the 1 KiB prefix copied from an individual I/O operation is intentionally unavailable. For example, a large write can report `insert` and its collection while `$db` may be absent if a driver places it after a large inline document.
- TLS plaintext is unavailable when `SSL_*` functions are stripped, hidden, inlined, ABI-incompatible, bypassed by a custom BIO path, or replaced by kTLS. Socket metadata remains available. Closing this universally would require library-specific probes or application instrumentation.
- DNS-over-TCP, DoT, DoH, and resolver calls using `sendmmsg`/`recvmmsg` are not decoded. Encrypted DNS has the same plaintext-boundary limitation as application TLS; support for batched and TCP DNS can be added if observed in a qualified target image.
- Connection handshakes are observed from kernel TCP state transitions rather than individual packet timestamps. Outbound duration is available from connect start; a server-side accepted socket may expose only the established event because Linux represents the SYN queue with request sockets. Reset direction is portable, but detailed reset-reason enums and keep-alive probe reasons vary by kernel. Exact packet sequence/timing requires a TC/XDP sensor plus socket-to-process correlation, which is a distinct higher-volume collection mode.

## Interpretation limits

- Request/response delta is application-observed latency, not pure server execution time.
- TCP SRTT is the kernel's smoothed estimate, not the exact RTT of a specific MongoDB request.
- A server-only Observer cannot derive exact network transit and exact database execution from a single elapsed request interval. Those components require synchronized client-side/server-side spans or explicit MongoDB execution telemetry.
- `pread`/`pwrite`/sync timing is process syscall latency associated with `mongod`; it is not a direct WiredTiger internal span or block-device completion trace.
- Only page faults slower than the eBPF threshold are emitted individually to avoid a telemetry storm.
- Off-CPU intervals below 1 ms are suppressed to bound profiling volume; on-CPU sampling remains continuous at the configured frequency.
- CPU stacks are raw addresses. Symbolization, aggregation, retention, and flamegraph rendering are not in this customer-side repository.
- `pthread_mutex_lock` probes describe libc mutex waits. They do not label MongoDB/WiredTiger lock objects by source-level name.

## Platform gaps

- The shipped probe source supports x86_64 and arm64 syscall ABIs. Every target kernel/image combination still needs qualification.
- Observer currently targets every process named exactly `mongod` or `mongos` visible on its node. That is appropriate for a dedicated customer database cluster; a shared cluster needs a control-plane-supplied pod/cgroup allow-list before this can provide per-source isolation.
- MongoDB 8 currently refuses to start on Linux kernels 6.19 through 7.0.13 because of an [upstream TCMalloc incompatibility documented by MongoDB](https://www.mongodb.com/docs/manual/release-notes/8.0/#mongodb-is-incompatible-with-linux-kernel-6.19-through-7.0.13). Preflight blocks that combination; use a supported node kernel.
- Privileged DaemonSets, host PID, tracefs, and BTF are hard requirements. Restricted managed/serverless nodes cannot run it.
- The Outpost file spool is single-writer, so the Helm chart intentionally requires one replica. Its PVC survives pod restarts, but customer-cluster high availability requires a shared durable queue or partitioned spool design. Regional high availability begins after the configured endpoint durably accepts a batch.
- Kubernetes NetworkPolicy cannot safely allow an HTTPS FQDN by itself. Enforce the regional hostname/private endpoint using the cloud firewall, egress gateway, or CNI FQDN policy in the customer account.

## Deployment and security boundaries

- Observer-to-Outpost traffic is bearer-authenticated but uses cluster-internal HTTP. Run the components in a dedicated namespace and apply CNI isolation; environments that require encryption for all east-west traffic need a service-mesh or mTLS termination layer.
- The file spools do not implement application-level encryption. Use encrypted Kubernetes volumes and encrypted node disks, and enable Kubernetes Secret encryption at rest in the customer account.
- Outpost reads its destination bearer token at startup. Rotate the Kubernetes Secret together with an Outpost rollout; in-flight and already-spooled batches keep their stable idempotency keys.
- Kubernetes pod labels are enrichment metadata and can cross the endpoint boundary. Do not place secrets in labels; a deployment needing stricter minimization should remove or allow-list labels before production qualification.

## Product gaps for the next phase

- Command does not yet model `http_push` or `mongodb_dam` sources.
- The configured regional endpoint does not yet provide the production credential assignment, durable idempotency store, or downstream mapping into Collect. That integration is deliberately outside this customer-side repository and is the next phase.
- Regional querying, configurable rule management beyond the built-in bulk-delete demo rule, retention, RBAC, audit evidence, dashboards, symbol storage, and flamegraph construction remain to be built.
- The direct-user demo maps an AWS IAM ARN to a MongoDB Community SCRAM credential through Secrets Manager. It is not native `MONGODB-AWS`, its clear identity join remains demo-local, and containment is operator-triggered after the destructive operation.
- There is no operator-managed MongoDB topology here. The bundled Community database is one standalone StatefulSet for product validation, not a production replica set, backup, restore, or upgrade solution.
- Generic HTTP/1.1, HTTP/2, gRPC, AI-service signature matching, and vector-database protocol classification are not part of this MongoDB DAM sensor. Adding them would be a separate source type with separate privacy and protocol contracts.
