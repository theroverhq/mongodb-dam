use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const EVENT_SCHEMA_VERSION: u16 = 1;
pub const BATCH_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DamBatch {
    pub schema_version: u16,
    pub batch_id: String,
    pub customer_id: String,
    pub tenant_id: String,
    pub source_id: String,
    pub regional_cell_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub events: Vec<DamEvent>,
}

impl DamBatch {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != BATCH_SCHEMA_VERSION {
            return Err("unsupported batch schema_version");
        }
        if self.batch_id.trim().is_empty()
            || self.customer_id.trim().is_empty()
            || self.tenant_id.trim().is_empty()
            || self.source_id.trim().is_empty()
            || self.regional_cell_id.trim().is_empty()
        {
            return Err("batch identity fields must not be empty");
        }
        if self.events.is_empty() {
            return Err("batch must contain at least one event");
        }
        if self
            .events
            .iter()
            .any(|event| event.schema_version != EVENT_SCHEMA_VERSION)
        {
            return Err("unsupported event schema_version");
        }
        if self.events.iter().any(|event| {
            event.event_id.trim().is_empty()
                || event.capture.sensor_id.trim().is_empty()
                || event.capture.node_name.trim().is_empty()
        }) {
            return Err("event identity fields must not be empty");
        }
        if self.events.iter().any(|event| {
            event.customer_id != self.customer_id
                || event.tenant_id != self.tenant_id
                || event.source_id != self.source_id
                || event.regional_cell_id != self.regional_cell_id
        }) {
            return Err("event identity does not match batch identity");
        }
        if self.events.iter().any(|event| !event.capture.metadata_only) {
            return Err("event violates the metadata-only contract");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DamEvent {
    pub schema_version: u16,
    pub event_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    pub monotonic_timestamp_ns: u64,
    pub customer_id: String,
    pub tenant_id: String,
    pub source_id: String,
    pub regional_cell_id: String,
    pub capture: CaptureMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessMetadata>,
    #[serde(flatten)]
    pub payload: EventPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaptureMetadata {
    pub sensor_id: String,
    pub node_name: String,
    pub source: CaptureSource,
    pub confidence: CaptureConfidence,
    pub metadata_only: bool,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSource {
    CleartextSyscall,
    OpenSslUprobe,
    UserUprobe,
    KernelTracepoint,
    PerfEvent,
    Sensor,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureConfidence {
    Complete,
    Partial,
    Inferred,
    Unknown,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KubernetesMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProcessMetadata {
    pub pid: u32,
    pub tgid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup_id: Option<u64>,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event_type", content = "details", rename_all = "snake_case")]
pub enum EventPayload {
    MongodbActivity(MongodbActivity),
    MongodbConnection(MongodbConnection),
    MongodbAuth(MongodbAuth),
    HostIo(HostIo),
    Profile(ProfileSample),
    ProcessLifecycle(ProcessLifecycle),
    SensorHealth(SensorHealth),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionMetadata {
    pub connection_id: String,
    pub fd: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<NetworkEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<NetworkEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_srtt_us: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retransmits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MongodbActivity {
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    pub request_id: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_id: Option<i32>,
    pub request_bytes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub succeeded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_name: Option<String>,
    pub expects_response: bool,
    pub compressed: bool,
    pub connection: ConnectionMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MongodbConnection {
    pub state: String,
    pub connection: ConnectionMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MongodbAuth {
    pub mechanism: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    pub principal_hashed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub succeeded: Option<bool>,
    pub connection_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostIo {
    pub operation: String,
    pub duration_us: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,
    pub result: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProfileSample {
    pub profile_type: String,
    pub period_hz: u32,
    pub count: u64,
    pub user_stack_id: i32,
    pub kernel_stack_id: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_stack_addresses: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kernel_stack_addresses: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProcessLifecycle {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SensorHealth {
    pub status: String,
    pub component: String,
    pub reason: String,
    pub dropped_events: u64,
    pub parse_errors: u64,
    pub spool_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_activity_has_no_raw_body_field() {
        let event = DamEvent {
            schema_version: EVENT_SCHEMA_VERSION,
            event_id: "evt-1".into(),
            observed_at: OffsetDateTime::UNIX_EPOCH,
            monotonic_timestamp_ns: 1,
            customer_id: "customer".into(),
            tenant_id: "tenant".into(),
            source_id: "source".into(),
            regional_cell_id: "cell".into(),
            capture: CaptureMetadata {
                sensor_id: "sensor".into(),
                node_name: "node".into(),
                source: CaptureSource::OpenSslUprobe,
                confidence: CaptureConfidence::Complete,
                metadata_only: true,
                truncated: false,
            },
            kubernetes: None,
            process: None,
            payload: EventPayload::MongodbActivity(MongodbActivity {
                command: "find".into(),
                database: Some("sales".into()),
                collection: Some("orders".into()),
                request_id: 7,
                response_id: Some(8),
                request_bytes: 64,
                response_bytes: Some(32),
                duration_us: Some(100),
                succeeded: Some(true),
                error_code: None,
                error_name: None,
                expects_response: true,
                compressed: false,
                connection: ConnectionMetadata {
                    connection_id: "1:4".into(),
                    fd: 4,
                    ..Default::default()
                },
            }),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("filter"));
        assert!(!json.contains("document"));
        assert!(!json.contains("raw_body"));
        assert!(json.contains("mongodb_activity"));
    }

    #[test]
    fn batch_rejects_cross_tenant_or_non_metadata_events() {
        let activity = DamEvent {
            schema_version: EVENT_SCHEMA_VERSION,
            event_id: "evt-1".into(),
            observed_at: OffsetDateTime::UNIX_EPOCH,
            monotonic_timestamp_ns: 1,
            customer_id: "other-customer".into(),
            tenant_id: "tenant".into(),
            source_id: "source".into(),
            regional_cell_id: "cell".into(),
            capture: CaptureMetadata {
                sensor_id: "sensor".into(),
                node_name: "node".into(),
                source: CaptureSource::CleartextSyscall,
                confidence: CaptureConfidence::Complete,
                metadata_only: true,
                truncated: false,
            },
            kubernetes: None,
            process: None,
            payload: EventPayload::SensorHealth(SensorHealth {
                status: "ok".into(),
                component: "observer".into(),
                reason: "test".into(),
                dropped_events: 0,
                parse_errors: 0,
                spool_bytes: 0,
            }),
        };
        let mut batch = DamBatch {
            schema_version: BATCH_SCHEMA_VERSION,
            batch_id: "batch-1".into(),
            customer_id: "customer".into(),
            tenant_id: "tenant".into(),
            source_id: "source".into(),
            regional_cell_id: "cell".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            events: vec![activity],
        };

        assert_eq!(
            batch.validate(),
            Err("event identity does not match batch identity")
        );
        batch.events[0].customer_id = "customer".into();
        batch.events[0].capture.metadata_only = false;
        assert_eq!(
            batch.validate(),
            Err("event violates the metadata-only contract")
        );
    }
}
