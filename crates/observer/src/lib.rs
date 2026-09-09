use dam_schema::{
    CaptureConfidence, CaptureMetadata, CaptureSource, ConnectionMetadata, DamEvent, DnsActivity,
    EventPayload, HostIo, KubernetesMetadata, MongodbActivity, MongodbAuth, MongodbConnection,
    NetworkEndpoint, ProcessLifecycle, ProcessMetadata, ProfileSample, SecurityFinding,
    EVENT_SCHEMA_VERSION,
};
use mongo_protocol::{DecodedMessage, DecoderConfig, DeleteScope, MongoCommand, StreamDecoder};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use time::OffsetDateTime;

pub const MAX_CAPTURE_BYTES: usize = 1024;
const MAX_PENDING_REQUESTS: usize = 32_768;
const PENDING_REQUEST_TTL_NS: u64 = 300_000_000_000;

pub const EVENT_IO_CHUNK: u8 = 1;
pub const EVENT_SYSCALL_LATENCY: u8 = 2;
pub const EVENT_CONNECTION: u8 = 3;
pub const EVENT_PROFILE: u8 = 4;
pub const EVENT_PROCESS: u8 = 5;
pub const EVENT_DNS_CHUNK: u8 = 6;

pub const OP_PREAD: u8 = 1;
pub const OP_PWRITE: u8 = 2;
pub const OP_FSYNC: u8 = 3;
pub const OP_OPENAT: u8 = 4;
pub const OP_OFFCPU: u8 = 5;
pub const OP_TCP_CONNECT: u8 = 6;
pub const OP_TCP_ACCEPT: u8 = 7;
pub const OP_TCP_CLOSE: u8 = 8;
pub const OP_TCP_RTT: u8 = 9;
pub const OP_TCP_RETRANSMIT: u8 = 10;
pub const OP_CPU_SAMPLE: u8 = 11;
pub const OP_FDATASYNC: u8 = 12;
pub const OP_LOCK_WAIT: u8 = 13;
pub const OP_PAGE_FAULT: u8 = 14;
pub const OP_PROCESS_EXEC: u8 = 15;
pub const OP_PROCESS_EXIT: u8 = 16;
pub const OP_TCP_HANDSHAKE: u8 = 17;
pub const OP_TCP_RESET_RECEIVED: u8 = 18;
pub const OP_TCP_RESET_SENT: u8 = 19;
pub const OP_TCP_ZERO_WINDOW: u8 = 20;
pub const OP_TCP_TIMEOUT: u8 = 21;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct KernelEvent {
    pub timestamp_ns: u64,
    pub connection_key: u64,
    pub cgroup_id: u64,
    pub duration_ns: u64,
    pub bytes: u64,
    pub result: i64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub fd: i32,
    pub original_len: u32,
    pub captured_len: u32,
    pub event_type: u8,
    pub direction: u8,
    pub source: u8,
    pub operation: u8,
    pub comm: [u8; 16],
    pub data: [u8; MAX_CAPTURE_BYTES],
}

impl KernelEvent {
    pub fn from_ring_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != std::mem::size_of::<Self>() {
            return None;
        }
        // The C and Rust representations are both repr(C), and the eBPF ring
        // buffer may not align records for this Rust type.
        Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<Self>()) })
    }

    fn command(&self) -> String {
        let end = self
            .comm
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.comm.len());
        String::from_utf8_lossy(&self.comm[..end]).into_owned()
    }
}

#[derive(Clone, Debug)]
pub struct CapturedKernelEvent {
    pub raw: KernelEvent,
    pub user_stack_addresses: Vec<u64>,
    pub kernel_stack_addresses: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct ProcessorConfig {
    pub customer_id: String,
    pub tenant_id: String,
    pub source_id: String,
    pub regional_cell_id: String,
    pub sensor_id: String,
    pub node_name: String,
    pub cluster_name: String,
    pub host_proc: PathBuf,
    pub max_message_bytes: usize,
    pub cpu_profile_hz: u32,
    pub principal_hash_salt: Option<String>,
    pub bulk_delete_threshold: u64,
}

#[derive(Clone)]
struct EventSeed {
    observed_at: OffsetDateTime,
    monotonic_timestamp_ns: u64,
    capture: CaptureMetadata,
    kubernetes: Option<KubernetesMetadata>,
    process: Option<ProcessMetadata>,
}

#[derive(Clone)]
struct PendingRequest {
    command: MongoCommand,
    target_principal_hash: Option<String>,
    actor_principal_hash: Option<String>,
    connection_state_key: (u32, u64),
    request_id: i32,
    request_bytes: u32,
    compressed: bool,
    expects_response: bool,
    seed: EventSeed,
    connection: ConnectionMetadata,
}

struct PendingDnsQuery {
    timestamp_ns: u64,
    name: Option<String>,
    record_type: Option<String>,
}

#[derive(Default)]
struct ConnectionState {
    tcp_srtt_us: Option<u32>,
    retransmits: u32,
    authenticated_principal_hash: Option<String>,
    pending_auth_principal_hash: Option<String>,
}

struct EndpointCacheEntry {
    inserted_at: Instant,
    local: NetworkEndpoint,
    remote: NetworkEndpoint,
}

pub struct EventProcessor {
    config: ProcessorConfig,
    streams: HashMap<(u32, u64, u8), StreamDecoder>,
    pending: HashMap<(u32, u64, i32), PendingRequest>,
    pending_dns: HashMap<(u32, u64, u16), PendingDnsQuery>,
    connections: HashMap<(u32, u64), ConnectionState>,
    endpoint_cache: HashMap<(u32, i32), EndpointCacheEntry>,
    sequence: u64,
}

impl EventProcessor {
    pub fn new(config: ProcessorConfig) -> Self {
        Self {
            config,
            streams: HashMap::new(),
            pending: HashMap::new(),
            pending_dns: HashMap::new(),
            connections: HashMap::new(),
            endpoint_cache: HashMap::new(),
            sequence: 0,
        }
    }

    pub fn process(&mut self, captured: CapturedKernelEvent) -> Result<Vec<DamEvent>, String> {
        match captured.raw.event_type {
            EVENT_IO_CHUNK => self.process_io_chunk(captured),
            EVENT_SYSCALL_LATENCY => Ok(self.process_latency(captured)),
            EVENT_CONNECTION => Ok(self.process_connection(captured)),
            EVENT_PROFILE => Ok(self.process_profile(captured)),
            EVENT_PROCESS => Ok(self.process_lifecycle(captured)),
            EVENT_DNS_CHUNK => self.process_dns(captured),
            other => Err(format!("unsupported kernel event type {other}")),
        }
    }

    fn process_io_chunk(&mut self, captured: CapturedKernelEvent) -> Result<Vec<DamEvent>, String> {
        let raw = captured.raw;
        let captured_len = usize::try_from(raw.captured_len)
            .unwrap_or(usize::MAX)
            .min(MAX_CAPTURE_BYTES);
        if captured_len == 0 {
            return Ok(Vec::new());
        }
        let key = (raw.tgid, raw.connection_key, raw.direction);
        let decoder_config = DecoderConfig {
            max_message_bytes: self.config.max_message_bytes,
            max_buffer_bytes: MAX_CAPTURE_BYTES.saturating_mul(2),
        };
        let truncated = raw.bytes > raw.captured_len as u64;
        let decoded = if truncated {
            let decoder = self
                .streams
                .entry(key)
                .or_insert_with(|| StreamDecoder::new(decoder_config));
            let remaining = MAX_CAPTURE_BYTES.saturating_sub(decoder.buffered_bytes());
            let result = decoder.push_truncated(&raw.data[..captured_len.min(remaining)]);
            self.streams.remove(&key);
            vec![result.map_err(|error| error.to_string())?]
        } else {
            self.streams
                .entry(key)
                .or_insert_with(|| StreamDecoder::new(decoder_config))
                .push_bounded_prefix(&raw.data[..captured_len], MAX_CAPTURE_BYTES)
                .map_err(|error| {
                    self.streams.remove(&key);
                    error.to_string()
                })?
        };

        let mut events = Vec::new();
        for message in decoded {
            events.extend(self.process_message(raw, truncated, message));
        }
        Ok(events)
    }

    fn process_dns(&mut self, captured: CapturedKernelEvent) -> Result<Vec<DamEvent>, String> {
        let raw = captured.raw;
        let captured_len = usize::try_from(raw.captured_len)
            .unwrap_or(usize::MAX)
            .min(MAX_CAPTURE_BYTES);
        let message = decode_dns_message(&raw.data[..captured_len])?;
        let key = (raw.tgid, raw.connection_key, message.query_id);
        let truncated = raw.bytes > raw.captured_len as u64;

        let (operation, name, record_type, duration_us) = if message.response {
            let pending = self.pending_dns.remove(&key);
            let duration = pending
                .as_ref()
                .map(|pending| raw.timestamp_ns.saturating_sub(pending.timestamp_ns) / 1_000);
            (
                "response",
                message
                    .name
                    .or_else(|| pending.as_ref().and_then(|value| value.name.clone())),
                message
                    .record_type
                    .or_else(|| pending.as_ref().and_then(|value| value.record_type.clone())),
                duration,
            )
        } else {
            if self.pending_dns.len() >= 4_096 {
                let cutoff = raw.timestamp_ns.saturating_sub(30_000_000_000);
                self.pending_dns
                    .retain(|_, pending| pending.timestamp_ns >= cutoff);
                if self.pending_dns.len() >= 4_096 {
                    self.pending_dns.clear();
                }
            }
            self.pending_dns.insert(
                key,
                PendingDnsQuery {
                    timestamp_ns: raw.timestamp_ns,
                    name: message.name.clone(),
                    record_type: message.record_type.clone(),
                },
            );
            ("query", message.name, message.record_type, None)
        };

        let connection = self.connection_metadata(&raw);
        Ok(vec![self.event(
            &raw,
            truncated,
            EventPayload::DnsActivity(DnsActivity {
                operation: operation.into(),
                transport: "udp".into(),
                query_id: message.query_id,
                name,
                record_type,
                response_code: message.response.then_some(message.response_code),
                answer_count: message.response.then_some(message.answer_count),
                duration_us,
                connection,
            }),
        )])
    }

    fn process_message(
        &mut self,
        raw: KernelEvent,
        truncated: bool,
        message: DecodedMessage,
    ) -> Vec<DamEvent> {
        let connection_key = (raw.tgid, raw.connection_key);
        if message.response_to == 0 {
            let Some(mut command) = message.command else {
                return Vec::new();
            };
            // Do not retain a clear authentication principal while waiting for
            // the matching response. Hash it at the first userspace boundary.
            let target_principal_hash =
                take_hashed_principal(&mut command, self.config.principal_hash_salt.as_deref());
            let actor_principal_hash = {
                let state = self.connections.entry(connection_key).or_default();
                if command_carries_authentication(&command) {
                    if let Some(principal) = target_principal_hash.as_ref() {
                        state.pending_auth_principal_hash = Some(principal.clone());
                    }
                }
                state.authenticated_principal_hash.clone()
            };
            let request = PendingRequest {
                command,
                target_principal_hash,
                actor_principal_hash,
                connection_state_key: connection_key,
                request_id: message.request_id,
                request_bytes: message.wire_bytes,
                compressed: message.compressed,
                expects_response: !message.more_to_come,
                seed: self.seed(&raw, truncated),
                connection: self.connection_metadata(&raw),
            };
            if request.expects_response {
                self.prune_pending_requests(raw.timestamp_ns);
                self.pending.insert(
                    (connection_key.0, connection_key.1, request.request_id),
                    request,
                );
                Vec::new()
            } else {
                self.events_for_completed_request(request, None, None, None)
            }
        } else {
            let Some(request) =
                self.pending
                    .remove(&(connection_key.0, connection_key.1, message.response_to))
            else {
                return Vec::new();
            };
            let duration_us = raw
                .timestamp_ns
                .saturating_sub(request.seed.monotonic_timestamp_ns)
                / 1_000;
            self.events_for_completed_request(
                request,
                Some((&message, duration_us)),
                Some(message.request_id),
                Some(message.wire_bytes),
            )
        }
    }

    fn events_for_completed_request(
        &mut self,
        request: PendingRequest,
        response: Option<(&DecodedMessage, u64)>,
        response_id: Option<i32>,
        response_bytes: Option<u32>,
    ) -> Vec<DamEvent> {
        let (duration_us, succeeded, error_code, error_name, affected_documents, auth_done) =
            match response {
                Some((message, duration)) => (
                    Some(duration),
                    message.status.as_ref().and_then(|status| status.ok),
                    message.status.as_ref().and_then(|status| status.code),
                    message
                        .status
                        .as_ref()
                        .and_then(|status| status.code_name.clone()),
                    message
                        .status
                        .as_ref()
                        .and_then(|status| status.affected_count),
                    message.status.as_ref().and_then(|status| status.auth_done),
                ),
                None => (None, None, None, None, None, None),
            };

        let session_auth_principal = if command_carries_authentication(&request.command) {
            let state = self
                .connections
                .entry(request.connection_state_key)
                .or_default();
            let principal = request
                .target_principal_hash
                .clone()
                .or_else(|| state.pending_auth_principal_hash.clone());
            if succeeded == Some(false) {
                state.pending_auth_principal_hash = None;
            } else if succeeded == Some(true)
                && authentication_exchange_completed(&request.command, auth_done)
            {
                state.authenticated_principal_hash = principal.clone();
                state.pending_auth_principal_hash = None;
            }
            principal
        } else {
            None
        };

        let delete_scope = request.command.delete_scope.map(delete_scope_name);
        let mut result = vec![self.event_from_seed(
            request.seed.clone(),
            EventPayload::MongodbActivity(MongodbActivity {
                command: request.command.name.clone(),
                database: request.command.database.clone(),
                collection: request.command.collection.clone(),
                principal: request.actor_principal_hash.clone(),
                principal_hashed: request.actor_principal_hash.is_some(),
                delete_scope: delete_scope.map(str::to_string),
                delete_statements: request.command.delete_statements,
                affected_documents,
                request_id: request.request_id,
                response_id,
                request_bytes: request.request_bytes,
                response_bytes,
                duration_us,
                succeeded,
                error_code,
                error_name,
                expects_response: request.expects_response,
                compressed: request.compressed,
                connection: request.connection.clone(),
            }),
        )];

        if succeeded == Some(true)
            && affected_documents.is_some_and(|count| count >= self.config.bulk_delete_threshold)
            && matches!(
                request.command.delete_scope,
                Some(DeleteScope::Multi | DeleteScope::Mixed)
            )
        {
            result.push(self.event_from_seed(
                request.seed.clone(),
                EventPayload::SecurityFinding(SecurityFinding {
                    rule_id: "mongodb.bulk_delete".into(),
                    severity: "critical".into(),
                    title: "Bulk MongoDB delete completed".into(),
                    action: "flagged; containment required".into(),
                    principal: request.actor_principal_hash.clone(),
                    principal_hashed: request.actor_principal_hash.is_some(),
                    command: request.command.name.clone(),
                    database: request.command.database.clone(),
                    collection: request.command.collection.clone(),
                    delete_scope: delete_scope.map(str::to_string),
                    affected_documents,
                    threshold_documents: self.config.bulk_delete_threshold,
                    connection_id: request.connection.connection_id.clone(),
                }),
            ));
        }

        if is_auth_command(&request.command.name) || request.command.speculative_auth {
            let default_mechanism = if is_user_management_command(&request.command.name) {
                "user_management"
            } else {
                "unknown"
            };
            result.push(
                self.event_from_seed(
                    request.seed,
                    EventPayload::MongodbAuth(MongodbAuth {
                        mechanism: request
                            .command
                            .auth_mechanism
                            .clone()
                            .unwrap_or_else(|| default_mechanism.into()),
                        principal: if command_carries_authentication(&request.command) {
                            session_auth_principal
                        } else {
                            request.target_principal_hash
                        },
                        principal_hashed: true,
                        succeeded,
                        connection_id: request.connection.connection_id,
                    }),
                ),
            );
        }
        result
    }

    fn process_latency(&mut self, captured: CapturedKernelEvent) -> Vec<DamEvent> {
        let raw = captured.raw;
        if raw.operation == OP_OFFCPU {
            return vec![self.event(
                &raw,
                false,
                EventPayload::Profile(ProfileSample {
                    profile_type: "off_cpu".into(),
                    period_hz: 0,
                    count: 1,
                    user_stack_id: -1,
                    kernel_stack_id: -1,
                    duration_us: Some(raw.duration_ns / 1_000),
                    user_stack_addresses: Vec::new(),
                    kernel_stack_addresses: Vec::new(),
                }),
            )];
        }
        let operation = match raw.operation {
            OP_PREAD => "pread",
            OP_PWRITE => "pwrite",
            OP_FSYNC => "fsync",
            OP_FDATASYNC => "fdatasync",
            OP_OPENAT => "openat",
            OP_PAGE_FAULT => "page_fault",
            _ => return Vec::new(),
        };
        vec![self.event(
            &raw,
            false,
            EventPayload::HostIo(HostIo {
                operation: operation.into(),
                duration_us: raw.duration_ns / 1_000,
                bytes: (raw.bytes > 0).then_some(raw.bytes),
                fd: (raw.fd >= 0).then_some(raw.fd),
                result: raw.result,
            }),
        )]
    }

    fn process_connection(&mut self, captured: CapturedKernelEvent) -> Vec<DamEvent> {
        let raw = captured.raw;
        let key = (raw.tgid, raw.connection_key);
        let state = self.connections.entry(key).or_default();
        let (name, duration_us, reason) = match raw.operation {
            OP_TCP_CONNECT => ("connect_started", None, None),
            OP_TCP_ACCEPT => ("accepted", None, None),
            OP_TCP_CLOSE => ("closed", None, None),
            OP_TCP_RTT => {
                state.tcp_srtt_us = Some((raw.duration_ns / 1_000).min(u32::MAX as u64) as u32);
                ("rtt_sample", Some(raw.duration_ns / 1_000), None)
            }
            OP_TCP_RETRANSMIT => {
                state.retransmits = state.retransmits.saturating_add(1);
                ("retransmit", None, None)
            }
            OP_TCP_HANDSHAKE => (
                "handshake_established",
                (raw.duration_ns > 0).then_some(raw.duration_ns / 1_000),
                None,
            ),
            OP_TCP_RESET_RECEIVED => ("reset", None, Some("peer_reset".into())),
            OP_TCP_RESET_SENT => ("reset", None, Some("active_reset".into())),
            OP_TCP_ZERO_WINDOW => (
                "zero_window",
                None,
                Some("peer_advertised_zero_window".into()),
            ),
            OP_TCP_TIMEOUT => (
                "timeout",
                (raw.duration_ns > 0).then_some(raw.duration_ns / 1_000),
                Some("connect_or_retransmission_timeout".into()),
            ),
            _ => return Vec::new(),
        };
        let connection = self.connection_metadata(&raw);
        if raw.operation == OP_TCP_CLOSE {
            self.connections.remove(&key);
            self.streams
                .retain(|(tgid, connection_key, _), _| (*tgid, *connection_key) != key);
            self.pending
                .retain(|(tgid, connection_key, _), _| (*tgid, *connection_key) != key);
            self.pending_dns
                .retain(|(tgid, connection_key, _), _| (*tgid, *connection_key) != key);
        }
        vec![self.event(
            &raw,
            false,
            EventPayload::MongodbConnection(MongodbConnection {
                state: name.into(),
                connection,
                duration_us,
                reason,
            }),
        )]
    }

    fn process_profile(&mut self, captured: CapturedKernelEvent) -> Vec<DamEvent> {
        let raw = captured.raw;
        let (profile_type, duration_us, user_stack_id, kernel_stack_id) = match raw.operation {
            OP_CPU_SAMPLE => (
                "on_cpu",
                None,
                i32::try_from(raw.result).unwrap_or(-1),
                raw.fd,
            ),
            OP_LOCK_WAIT => ("pthread_mutex_wait", Some(raw.duration_ns / 1_000), -1, -1),
            _ => return Vec::new(),
        };
        vec![self.event(
            &raw,
            false,
            EventPayload::Profile(ProfileSample {
                profile_type: profile_type.into(),
                period_hz: if raw.operation == OP_CPU_SAMPLE {
                    self.config.cpu_profile_hz
                } else {
                    0
                },
                count: 1,
                user_stack_id,
                kernel_stack_id,
                duration_us,
                user_stack_addresses: captured.user_stack_addresses,
                kernel_stack_addresses: captured.kernel_stack_addresses,
            }),
        )]
    }

    fn process_lifecycle(&mut self, captured: CapturedKernelEvent) -> Vec<DamEvent> {
        let raw = captured.raw;
        let state = match raw.operation {
            OP_PROCESS_EXEC => "exec",
            OP_PROCESS_EXIT => "exit",
            _ => return Vec::new(),
        };
        if raw.operation == OP_PROCESS_EXIT {
            self.streams.retain(|(tgid, _, _), _| *tgid != raw.tgid);
            self.pending.retain(|(tgid, _, _), _| *tgid != raw.tgid);
            self.pending_dns.retain(|(tgid, _, _), _| *tgid != raw.tgid);
            self.connections.retain(|(tgid, _), _| *tgid != raw.tgid);
            self.endpoint_cache.retain(|(tgid, _), _| *tgid != raw.tgid);
        }
        let executable = process_executable(&self.config.host_proc, raw.tgid);
        vec![self.event(
            &raw,
            false,
            EventPayload::ProcessLifecycle(ProcessLifecycle {
                state: state.into(),
                executable,
            }),
        )]
    }

    fn seed(&mut self, raw: &KernelEvent, truncated: bool) -> EventSeed {
        let scheduler_handoff =
            raw.event_type == EVENT_SYSCALL_LATENCY && raw.operation == OP_OFFCPU;
        let foreign_kernel_context = scheduler_handoff || raw.event_type == EVENT_CONNECTION;
        let credentials = if foreign_kernel_context {
            process_credentials(&self.config.host_proc, raw.tgid)
        } else {
            Some((raw.uid, raw.gid))
        };
        let command = if foreign_kernel_context {
            process_command(&self.config.host_proc, raw.tgid).unwrap_or_else(|| raw.command())
        } else {
            raw.command()
        };
        EventSeed {
            observed_at: OffsetDateTime::now_utc(),
            monotonic_timestamp_ns: raw.timestamp_ns,
            capture: CaptureMetadata {
                sensor_id: self.config.sensor_id.clone(),
                node_name: self.config.node_name.clone(),
                source: capture_source(raw.source),
                confidence: if truncated {
                    CaptureConfidence::Partial
                } else if raw.event_type == EVENT_IO_CHUNK {
                    CaptureConfidence::Complete
                } else {
                    CaptureConfidence::Inferred
                },
                metadata_only: true,
                truncated,
            },
            kubernetes: pod_metadata(&self.config.host_proc, raw.tgid, &self.config.cluster_name),
            process: Some(ProcessMetadata {
                pid: raw.pid,
                tgid: raw.tgid,
                uid: credentials.map(|value| value.0),
                gid: credentials.map(|value| value.1),
                cgroup_id: (!foreign_kernel_context).then_some(raw.cgroup_id),
                command,
                executable: process_executable(&self.config.host_proc, raw.tgid),
            }),
        }
    }

    fn event(&mut self, raw: &KernelEvent, truncated: bool, payload: EventPayload) -> DamEvent {
        let seed = self.seed(raw, truncated);
        self.event_from_seed(seed, payload)
    }

    fn event_from_seed(&mut self, seed: EventSeed, payload: EventPayload) -> DamEvent {
        self.sequence = self.sequence.wrapping_add(1);
        let mut digest = Sha256::new();
        digest.update(self.config.sensor_id.as_bytes());
        digest.update(seed.monotonic_timestamp_ns.to_le_bytes());
        digest.update(self.sequence.to_le_bytes());
        let event_id = format!("evt-{}", hex::encode(&digest.finalize()[..16]));
        DamEvent {
            schema_version: EVENT_SCHEMA_VERSION,
            event_id,
            observed_at: seed.observed_at,
            monotonic_timestamp_ns: seed.monotonic_timestamp_ns,
            customer_id: self.config.customer_id.clone(),
            tenant_id: self.config.tenant_id.clone(),
            source_id: self.config.source_id.clone(),
            regional_cell_id: self.config.regional_cell_id.clone(),
            capture: seed.capture,
            kubernetes: seed.kubernetes,
            process: seed.process,
            payload,
        }
    }

    fn prune_pending_requests(&mut self, now_ns: u64) {
        if self.pending.len() < MAX_PENDING_REQUESTS {
            return;
        }
        let cutoff = now_ns.saturating_sub(PENDING_REQUEST_TTL_NS);
        self.pending
            .retain(|_, request| request.seed.monotonic_timestamp_ns >= cutoff);
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            if let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, request)| request.seed.monotonic_timestamp_ns)
                .map(|(key, _)| *key)
            {
                self.pending.remove(&oldest);
            }
        }
    }

    fn connection_metadata(&mut self, raw: &KernelEvent) -> ConnectionMetadata {
        let state = self
            .connections
            .entry((raw.tgid, raw.connection_key))
            .or_default();
        let tcp_srtt_us = state.tcp_srtt_us;
        let retransmits = (state.retransmits > 0).then_some(state.retransmits);
        let endpoints = (raw.fd >= 0)
            .then(|| self.socket_endpoints(raw.tgid, raw.fd))
            .flatten();
        ConnectionMetadata {
            connection_id: format!(
                "{}:{}:{:016x}",
                self.config.node_name, raw.tgid, raw.connection_key
            ),
            fd: raw.fd,
            local: endpoints.as_ref().map(|value| value.0.clone()),
            remote: endpoints.map(|value| value.1),
            tcp_srtt_us,
            retransmits,
            tls: match raw.source {
                2 => Some(true),
                1 => Some(false),
                _ => None,
            },
        }
    }

    fn socket_endpoints(
        &mut self,
        tgid: u32,
        fd: i32,
    ) -> Option<(NetworkEndpoint, NetworkEndpoint)> {
        let key = (tgid, fd);
        if let Some(cached) = self.endpoint_cache.get(&key) {
            if cached.inserted_at.elapsed() < Duration::from_secs(5) {
                return Some((cached.local.clone(), cached.remote.clone()));
            }
        }
        let endpoints = resolve_socket_endpoints(&self.config.host_proc, tgid, fd)?;
        self.endpoint_cache.insert(
            key,
            EndpointCacheEntry {
                inserted_at: Instant::now(),
                local: endpoints.0.clone(),
                remote: endpoints.1.clone(),
            },
        );
        Some(endpoints)
    }
}

struct DecodedDnsMessage {
    query_id: u16,
    response: bool,
    response_code: u8,
    answer_count: u16,
    name: Option<String>,
    record_type: Option<String>,
}

fn decode_dns_message(bytes: &[u8]) -> Result<DecodedDnsMessage, String> {
    if bytes.len() < 12 {
        return Err("truncated DNS header".into());
    }
    let query_id = read_network_u16(bytes, 0)?;
    let flags = read_network_u16(bytes, 2)?;
    let question_count = read_network_u16(bytes, 4)?;
    let answer_count = read_network_u16(bytes, 6)?;
    let (name, record_type) = if question_count > 0 {
        let (name, after_name) = parse_dns_name(bytes, 12)?;
        let record_type = read_network_u16(bytes, after_name)?;
        let _record_class = read_network_u16(bytes, after_name + 2)?;
        (Some(name), Some(dns_record_type(record_type)))
    } else {
        (None, None)
    };
    Ok(DecodedDnsMessage {
        query_id,
        response: flags & 0x8000 != 0,
        response_code: (flags & 0x000f) as u8,
        answer_count,
        name,
        record_type,
    })
}

fn parse_dns_name(bytes: &[u8], offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut after_name = None;
    let mut jumps = 0usize;
    let mut decoded_bytes = 0usize;
    loop {
        let length = *bytes
            .get(cursor)
            .ok_or_else(|| "truncated DNS name".to_string())?;
        if length & 0xc0 == 0xc0 {
            let second = *bytes
                .get(cursor + 1)
                .ok_or_else(|| "truncated DNS compression pointer".to_string())?;
            after_name.get_or_insert(cursor + 2);
            cursor = ((((length & 0x3f) as u16) << 8) | second as u16) as usize;
            jumps += 1;
            if jumps > 16 {
                return Err("DNS compression pointer loop".into());
            }
            continue;
        }
        if length & 0xc0 != 0 {
            return Err("invalid DNS label type".into());
        }
        cursor += 1;
        if length == 0 {
            let end = after_name.unwrap_or(cursor);
            return Ok((labels.join(".").to_ascii_lowercase(), end));
        }
        if length > 63 {
            return Err("invalid DNS label length".into());
        }
        let end = cursor
            .checked_add(length as usize)
            .ok_or_else(|| "invalid DNS label length".to_string())?;
        let label = bytes
            .get(cursor..end)
            .ok_or_else(|| "truncated DNS label".to_string())?;
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("DNS label contains unsupported bytes".into());
        }
        decoded_bytes = decoded_bytes.saturating_add(label.len() + 1);
        if decoded_bytes > 254 {
            return Err("DNS name exceeds protocol limit".into());
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        cursor = end;
    }
}

fn read_network_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated DNS integer".to_string())?
        .try_into()
        .map(u16::from_be_bytes)
        .map_err(|_| "truncated DNS integer".to_string())
}

fn dns_record_type(value: u16) -> String {
    match value {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        255 => "ANY".into(),
        other => other.to_string(),
    }
}

fn capture_source(source: u8) -> CaptureSource {
    match source {
        1 => CaptureSource::CleartextSyscall,
        2 => CaptureSource::OpenSslUprobe,
        3 => CaptureSource::KernelTracepoint,
        4 => CaptureSource::PerfEvent,
        5 => CaptureSource::UserUprobe,
        _ => CaptureSource::Sensor,
    }
}

fn is_auth_command(command: &str) -> bool {
    is_session_auth_command(command) || is_user_management_command(command)
}

fn is_session_auth_command(command: &str) -> bool {
    matches!(
        command.to_ascii_lowercase().as_str(),
        "saslstart" | "saslcontinue" | "authenticate" | "getnonce"
    )
}

fn command_carries_authentication(command: &MongoCommand) -> bool {
    command.speculative_auth || is_session_auth_command(&command.name)
}

fn authentication_exchange_completed(command: &MongoCommand, auth_done: Option<bool>) -> bool {
    if command.speculative_auth {
        return auth_done == Some(true);
    }
    match command.name.to_ascii_lowercase().as_str() {
        "saslstart" | "saslcontinue" => auth_done == Some(true),
        "authenticate" => true,
        _ => false,
    }
}

fn delete_scope_name(scope: DeleteScope) -> &'static str {
    match scope {
        DeleteScope::Single => "single",
        DeleteScope::Multi => "multi",
        DeleteScope::Mixed => "mixed",
    }
}

fn is_user_management_command(command: &str) -> bool {
    matches!(
        command.to_ascii_lowercase().as_str(),
        "createuser"
            | "dropuser"
            | "grantrolestouser"
            | "revokerolesfromuser"
            | "updateuser"
            | "usersinfo"
    )
}

fn hash_principal(salt: &str, principal: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(salt.as_bytes());
    digest.update([0]);
    digest.update(principal.as_bytes());
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn take_hashed_principal(command: &mut MongoCommand, salt: Option<&str>) -> Option<String> {
    command
        .principal
        .take()
        .and_then(|principal| salt.map(|salt| hash_principal(salt, &principal)))
}

fn process_executable(host_proc: &Path, tgid: u32) -> Option<String> {
    fs::read_link(host_proc.join(tgid.to_string()).join("exe"))
        .ok()
        .map(|path| {
            path.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
}

fn process_credentials(host_proc: &Path, tgid: u32) -> Option<(u32, u32)> {
    let status = fs::read_to_string(host_proc.join(tgid.to_string()).join("status")).ok()?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let gid = status
        .lines()
        .find_map(|line| line.strip_prefix("Gid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((uid, gid))
}

fn process_command(host_proc: &Path, tgid: u32) -> Option<String> {
    fs::read_to_string(host_proc.join(tgid.to_string()).join("comm"))
        .ok()
        .map(|command| command.trim_end().to_string())
        .filter(|command| !command.is_empty())
}

fn pod_metadata(host_proc: &Path, tgid: u32, cluster_name: &str) -> Option<KubernetesMetadata> {
    let cgroup = fs::read_to_string(host_proc.join(tgid.to_string()).join("cgroup")).ok()?;
    let pod_uid = extract_pod_uid(&cgroup)?;
    Some(KubernetesMetadata {
        cluster_name: Some(cluster_name.to_string()),
        pod_uid: Some(pod_uid),
        ..Default::default()
    })
}

pub fn extract_pod_uid(cgroup: &str) -> Option<String> {
    for marker in cgroup.match_indices("pod") {
        let suffix = &cgroup[marker.0 + 3..];
        let candidate: String = suffix
            .chars()
            .take_while(|character| {
                character.is_ascii_hexdigit() || *character == '-' || *character == '_'
            })
            .collect();
        let normalized = candidate.replace('_', "-");
        if normalized.len() >= 36 {
            let uid = &normalized[..36];
            if uid.chars().enumerate().all(|(index, character)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    character == '-'
                } else {
                    character.is_ascii_hexdigit()
                }
            }) {
                return Some(uid.to_ascii_lowercase());
            }
        }
    }
    None
}

fn resolve_socket_endpoints(
    host_proc: &Path,
    tgid: u32,
    fd: i32,
) -> Option<(NetworkEndpoint, NetworkEndpoint)> {
    let link = fs::read_link(
        host_proc
            .join(tgid.to_string())
            .join("fd")
            .join(fd.to_string()),
    )
    .ok()?;
    let link = link.to_string_lossy();
    let inode = link.strip_prefix("socket:[")?.strip_suffix(']')?;
    for (name, ipv6) in [
        ("tcp", false),
        ("tcp6", true),
        ("udp", false),
        ("udp6", true),
    ] {
        let table =
            fs::read_to_string(host_proc.join(tgid.to_string()).join("net").join(name)).ok()?;
        if let Some(value) = parse_proc_net_tcp(&table, inode, ipv6) {
            return Some(value);
        }
    }
    None
}

fn parse_proc_net_tcp(
    table: &str,
    wanted_inode: &str,
    ipv6: bool,
) -> Option<(NetworkEndpoint, NetworkEndpoint)> {
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 || fields[9] != wanted_inode {
            continue;
        }
        return Some((
            parse_endpoint(fields[1], ipv6)?,
            parse_endpoint(fields[2], ipv6)?,
        ));
    }
    None
}

fn parse_endpoint(value: &str, ipv6: bool) -> Option<NetworkEndpoint> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = if ipv6 {
        if address.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (word_index, word) in address.as_bytes().chunks_exact(8).enumerate() {
            let word = std::str::from_utf8(word).ok()?;
            let decoded = u32::from_str_radix(word, 16).ok()?.to_le_bytes();
            bytes[word_index * 4..word_index * 4 + 4].copy_from_slice(&decoded);
        }
        Ipv6Addr::from(bytes).to_string()
    } else {
        let encoded = u32::from_str_radix(address, 16).ok()?;
        Ipv4Addr::from(encoded.to_le_bytes()).to_string()
    };
    Some(NetworkEndpoint {
        address: Some(address),
        port: Some(port),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_processor() -> EventProcessor {
        EventProcessor::new(ProcessorConfig {
            customer_id: "customer".into(),
            tenant_id: "tenant".into(),
            source_id: "source".into(),
            regional_cell_id: "cell".into(),
            sensor_id: "sensor".into(),
            node_name: "node".into(),
            cluster_name: "cluster".into(),
            host_proc: PathBuf::from("/definitely-not-proc"),
            max_message_bytes: 1024 * 1024,
            cpu_profile_hz: 0,
            principal_hash_salt: Some("customer-salt".into()),
            bulk_delete_threshold: 10,
        })
    }

    fn test_raw(timestamp_ns: u64) -> KernelEvent {
        let mut comm = [0u8; 16];
        comm[..6].copy_from_slice(b"mongod");
        KernelEvent {
            timestamp_ns,
            connection_key: 77,
            cgroup_id: 88,
            duration_ns: 0,
            bytes: 0,
            result: 0,
            pid: 42,
            tgid: 42,
            uid: 999,
            gid: 999,
            fd: 9,
            original_len: 0,
            captured_len: 0,
            event_type: EVENT_IO_CHUNK,
            direction: 0,
            source: 1,
            operation: 0,
            comm,
            data: [0; MAX_CAPTURE_BYTES],
        }
    }

    fn request_message(request_id: i32, command: MongoCommand) -> DecodedMessage {
        DecodedMessage {
            request_id,
            response_to: 0,
            wire_bytes: 128,
            flags: 0,
            more_to_come: false,
            compressed: false,
            command: Some(command),
            status: None,
        }
    }

    fn response_message(
        request_id: i32,
        response_to: i32,
        affected_count: Option<u64>,
        auth_done: Option<bool>,
    ) -> DecodedMessage {
        DecodedMessage {
            request_id,
            response_to,
            wire_bytes: 96,
            flags: 0,
            more_to_come: false,
            compressed: false,
            command: None,
            status: Some(mongo_protocol::ResponseStatus {
                ok: Some(true),
                code: None,
                code_name: None,
                affected_count,
                auth_done,
            }),
        }
    }

    #[test]
    fn kernel_event_layout_matches_bpf_structure() {
        assert_eq!(std::mem::size_of::<KernelEvent>(), 1120);
    }

    #[test]
    fn extracts_systemd_and_cgroupfs_pod_uids() {
        let uid = "08f20c35-9ab0-4a41-94b8-2e19e20c14c8";
        assert_eq!(
            extract_pod_uid(&format!(
                "0::/kubepods.slice/kubepods-burstable-pod{}.slice/cri-containerd-deadbeef.scope",
                uid.replace('-', "_")
            )),
            Some(uid.into())
        );
        assert_eq!(
            extract_pod_uid(&format!("0::/kubepods/burstable/pod{uid}/deadbeef")),
            Some(uid.into())
        );
    }

    #[test]
    fn parses_proc_ipv4_endpoint() {
        let endpoint = parse_endpoint("0100007F:6989", false).unwrap();
        assert_eq!(endpoint.address.as_deref(), Some("127.0.0.1"));
        assert_eq!(endpoint.port, Some(27017));
    }

    #[test]
    fn user_management_principals_are_treated_as_auth_and_hashed() {
        assert!(is_auth_command("createUser"));
        let mut command = MongoCommand {
            name: "createUser".into(),
            database: Some("admin".into()),
            collection: None,
            auth_mechanism: None,
            principal: Some("alice@example.com".into()),
            speculative_auth: false,
            delete_scope: None,
            delete_statements: None,
        };
        let hashed = take_hashed_principal(&mut command, Some("customer-salt")).unwrap();
        assert!(hashed.starts_with("sha256:"));
        assert!(!hashed.contains("alice"));
        assert!(command.principal.is_none());
    }

    #[test]
    fn attributes_bulk_delete_to_scram_principal_and_emits_finding() {
        let mut processor = test_processor();
        let speculative_hello = MongoCommand {
            name: "hello".into(),
            database: Some("admin".into()),
            collection: None,
            auth_mechanism: Some("SCRAM-SHA-256".into()),
            principal: Some("alice".into()),
            speculative_auth: true,
            delete_scope: None,
            delete_statements: None,
        };
        assert!(processor
            .process_message(
                test_raw(1_000),
                false,
                request_message(10, speculative_hello)
            )
            .is_empty());
        processor.process_message(
            test_raw(2_000),
            false,
            response_message(11, 10, None, Some(false)),
        );

        let sasl_continue = MongoCommand {
            name: "saslContinue".into(),
            database: Some("admin".into()),
            collection: None,
            auth_mechanism: None,
            principal: None,
            speculative_auth: false,
            delete_scope: None,
            delete_statements: None,
        };
        processor.process_message(test_raw(3_000), false, request_message(12, sasl_continue));
        processor.process_message(
            test_raw(4_000),
            false,
            response_message(13, 12, None, Some(true)),
        );

        let delete = MongoCommand {
            name: "delete".into(),
            database: Some("dam_demo".into()),
            collection: Some("customer_records".into()),
            auth_mechanism: None,
            principal: None,
            speculative_auth: false,
            delete_scope: Some(DeleteScope::Multi),
            delete_statements: Some(1),
        };
        processor.process_message(test_raw(5_000), false, request_message(14, delete));
        let events = processor.process_message(
            test_raw(10_005_000),
            false,
            response_message(15, 14, Some(35), None),
        );

        assert_eq!(events.len(), 2);
        let expected_principal = hash_principal("customer-salt", "alice");
        let activity = events.iter().find_map(|event| match &event.payload {
            EventPayload::MongodbActivity(activity) => Some(activity),
            _ => None,
        });
        let activity = activity.expect("MongoDB activity event");
        assert_eq!(
            activity.principal.as_deref(),
            Some(expected_principal.as_str())
        );
        assert_eq!(activity.delete_scope.as_deref(), Some("multi"));
        assert_eq!(activity.affected_documents, Some(35));

        let finding = events.iter().find_map(|event| match &event.payload {
            EventPayload::SecurityFinding(finding) => Some(finding),
            _ => None,
        });
        let finding = finding.expect("bulk-delete security finding");
        assert_eq!(finding.rule_id, "mongodb.bulk_delete");
        assert_eq!(
            finding.principal.as_deref(),
            Some(expected_principal.as_str())
        );
        assert_eq!(finding.affected_documents, Some(35));
        assert_eq!(finding.threshold_documents, 10);
    }

    #[test]
    fn decodes_dns_srv_query_and_response_metadata() {
        let mut query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in ["_mongodb", "_tcp", "example", "com"] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 33, 0, 1]);

        let decoded = decode_dns_message(&query).unwrap();
        assert_eq!(decoded.query_id, 0x1234);
        assert!(!decoded.response);
        assert_eq!(decoded.name.as_deref(), Some("_mongodb._tcp.example.com"));
        assert_eq!(decoded.record_type.as_deref(), Some("SRV"));

        query[2] = 0x81;
        query[3] = 0x83;
        let decoded = decode_dns_message(&query).unwrap();
        assert!(decoded.response);
        assert_eq!(decoded.response_code, 3);
    }
}
