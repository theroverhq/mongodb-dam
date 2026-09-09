use dam_schema::{
    CaptureConfidence, CaptureMetadata, CaptureSource, ConnectionMetadata, DamEvent, EventPayload,
    HostIo, KubernetesMetadata, MongodbActivity, MongodbAuth, MongodbConnection, NetworkEndpoint,
    ProcessLifecycle, ProcessMetadata, ProfileSample, EVENT_SCHEMA_VERSION,
};
use mongo_protocol::{DecodedMessage, DecoderConfig, MongoCommand, StreamDecoder};
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

pub const EVENT_IO_CHUNK: u8 = 1;
pub const EVENT_SYSCALL_LATENCY: u8 = 2;
pub const EVENT_CONNECTION: u8 = 3;
pub const EVENT_PROFILE: u8 = 4;
pub const EVENT_PROCESS: u8 = 5;

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
    request_id: i32,
    request_bytes: u32,
    compressed: bool,
    expects_response: bool,
    seed: EventSeed,
    connection: ConnectionMetadata,
}

#[derive(Default)]
struct ConnectionState {
    tcp_srtt_us: Option<u32>,
    retransmits: u32,
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
            max_buffer_bytes: self.config.max_message_bytes.saturating_mul(2),
        };
        let truncated = raw.bytes > raw.captured_len as u64;
        let decoded = if truncated {
            let result = self
                .streams
                .entry(key)
                .or_insert_with(|| StreamDecoder::new(decoder_config))
                .push_truncated(&raw.data[..captured_len]);
            self.streams.remove(&key);
            vec![result.map_err(|error| error.to_string())?]
        } else {
            self.streams
                .entry(key)
                .or_insert_with(|| StreamDecoder::new(decoder_config))
                .push(&raw.data[..captured_len])
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

    fn process_message(
        &mut self,
        raw: KernelEvent,
        truncated: bool,
        message: DecodedMessage,
    ) -> Vec<DamEvent> {
        let connection_key = (raw.tgid, raw.connection_key);
        if message.response_to == 0 {
            let Some(command) = message.command else {
                return Vec::new();
            };
            let request = PendingRequest {
                command,
                request_id: message.request_id,
                request_bytes: message.wire_bytes,
                compressed: message.compressed,
                expects_response: !message.more_to_come,
                seed: self.seed(&raw, truncated),
                connection: self.connection_metadata(&raw),
            };
            if request.expects_response {
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
        let (duration_us, succeeded, error_code, error_name) = match response {
            Some((message, duration)) => (
                Some(duration),
                message.status.as_ref().and_then(|status| status.ok),
                message.status.as_ref().and_then(|status| status.code),
                message
                    .status
                    .as_ref()
                    .and_then(|status| status.code_name.clone()),
            ),
            None => (None, None, None, None),
        };
        let mut result = vec![self.event_from_seed(
            request.seed.clone(),
            EventPayload::MongodbActivity(MongodbActivity {
                command: request.command.name.clone(),
                database: request.command.database.clone(),
                collection: request.command.collection.clone(),
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

        if is_auth_command(&request.command.name) {
            let default_mechanism = if is_user_management_command(&request.command.name) {
                "user_management"
            } else {
                "unknown"
            };
            let principal = request.command.principal.as_deref().and_then(|principal| {
                self.config
                    .principal_hash_salt
                    .as_deref()
                    .map(|salt| hash_principal(salt, principal))
            });
            result.push(
                self.event_from_seed(
                    request.seed,
                    EventPayload::MongodbAuth(MongodbAuth {
                        mechanism: request
                            .command
                            .auth_mechanism
                            .unwrap_or_else(|| default_mechanism.into()),
                        principal,
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
        let (name, duration_us) = match raw.operation {
            OP_TCP_CONNECT => ("connect_started", None),
            OP_TCP_ACCEPT => ("accepted", None),
            OP_TCP_CLOSE => ("closed", None),
            OP_TCP_RTT => {
                state.tcp_srtt_us = Some((raw.duration_ns / 1_000).min(u32::MAX as u64) as u32);
                ("rtt_sample", Some(raw.duration_ns / 1_000))
            }
            OP_TCP_RETRANSMIT => {
                state.retransmits = state.retransmits.saturating_add(1);
                ("retransmit", None)
            }
            _ => return Vec::new(),
        };
        let connection = self.connection_metadata(&raw);
        if raw.operation == OP_TCP_CLOSE {
            self.connections.remove(&key);
            self.streams
                .retain(|(tgid, connection_key, _), _| (*tgid, *connection_key) != key);
            self.pending
                .retain(|(tgid, connection_key, _), _| (*tgid, *connection_key) != key);
        }
        vec![self.event(
            &raw,
            false,
            EventPayload::MongodbConnection(MongodbConnection {
                state: name.into(),
                connection,
                duration_us,
                reason: None,
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
            tls: Some(raw.source == 2),
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
    matches!(
        command.to_ascii_lowercase().as_str(),
        "saslstart" | "saslcontinue" | "authenticate" | "getnonce"
    ) || is_user_management_command(command)
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
    for (name, ipv6) in [("tcp", false), ("tcp6", true)] {
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
        let hashed = hash_principal("customer-salt", "alice@example.com");
        assert!(hashed.starts_with("sha256:"));
        assert!(!hashed.contains("alice"));
    }
}
