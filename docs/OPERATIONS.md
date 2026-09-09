# Operations

## Startup and readiness

Observer exits if its required raw-syscall/scheduler programs cannot load. Its `/ready` endpoint becomes healthy only after the eBPF object and ring buffer are active. Optional kernel probes log a structured warning when a symbol is unavailable.

Outpost `/ready` verifies access to its spool. Regional endpoint availability does not make it unready: temporary regional loss is absorbed by the PVC and exposed through spool and delivery-failure metrics.

## Metrics

Observer serves port 8091; Outpost serves port 8090. Both expose `/health`, `/ready`, and `/metrics`. Important alerts:

- Observer or Outpost not ready;
- `mongodb_dam_observer_bpf_dropped_events_total`, `mongodb_dam_observer_userspace_dropped_events_total`, or `mongodb_dam_observer_spool_dropped_events_total` increasing;
- parse errors increasing abruptly after a MongoDB/driver upgrade;
- either spool approaching its configured byte cap;
- Outpost delivery failures increasing or delivered batches no longer moving;
- TLS-required installations with zero TLS uprobe processes.

## Failure and retry behavior

Observer writes a content-addressed, fsync-backed file before sending a batch to Outpost. Outpost acknowledges Observer only after writing its own fsync-backed copy. Outpost deletes that copy only after regional `2xx` or duplicate `409` acknowledgment. A permanent `4xx` moves the file to the spool's `quarantine/` directory so it is retained for operator review without being retried continuously.

At each boundary delivery is at least once. `batch_id` is the deduplication identity. Deleting a spool/PVC discards unacknowledged monitoring data and should be treated as a destructive operation.

## Capacity

Default caps are 256 MiB per node for Observer and 1 GiB for Outpost. Size them from peak metadata rate and the longest regional outage you intend to tolerate. When a spool is full, new batches are rejected and counters/logs expose the condition; existing data is retained. Observer reports the affected event count through `mongodb_dam_observer_spool_dropped_events_total`.

## TLS mode

- `auto` (default): attach OpenSSL symbols when available and continue with encrypted socket metadata otherwise.
- `required`: stop Observer once a MongoDB target exists but no OpenSSL symbols can be attached.
- `off`: do not attempt TLS uprobes.

Do not silently use `auto` for a compliance policy that requires command visibility over TLS. Alert on `mongodb_dam_observer_tls_uprobe_processes` and qualify the exact MongoDB image.

## Destination credential rotation

Update the `bearer-token` key in the configured Kubernetes Secret, then restart the Outpost Deployment so it reads the new value. The endpoint is posted exactly as configured and redirects are not followed. A private endpoint CA may be supplied through `destination.caSecretName`.

## Upgrades

1. Build immutable image tags and scan them in the customer account's registry.
2. Render and review the Helm diff against the explicit customer kubecontext.
3. Upgrade Outpost first if an event schema changes; it accepts the currently supported schema before Observers roll.
4. Roll Observer one node at a time and watch drop/parse/spool metrics.
5. Upgrade MongoDB under a separate database maintenance and backup procedure.

The chart's MongoDB tag is pinned, but production MongoDB lifecycle management is outside this MVP.
