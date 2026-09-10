use anyhow::{Context, Result};
use aws_sdk_s3::{primitives::ByteStream, Client as S3Client};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dam_schema::{DamBatch, EventPayload, ExternalIdentity, KubernetesMetadata};
use dam_spool::DurableSpool;
use flate2::{write::GzEncoder, Compression};
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use reqwest::{redirect::Policy, Certificate, Client, Url};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Notify, RwLock};
use tracing::{error, info, warn};

#[derive(Clone, Debug)]
pub struct OutpostConfig {
    pub customer_id: String,
    pub tenant_id: String,
    pub source_id: String,
    pub regional_cell_id: String,
    pub cluster_name: String,
    pub internal_token: Option<String>,
    pub destination: DestinationConfig,
    pub spool_dir: PathBuf,
    pub spool_max_bytes: u64,
    pub max_request_bytes: usize,
    pub export_interval: Duration,
    pub kubernetes_api_url: Option<String>,
    pub kubernetes_token_path: PathBuf,
    pub kubernetes_ca_path: PathBuf,
    pub kubernetes_refresh_interval: Duration,
    pub identity_mapping_file: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub enum DestinationConfig {
    Http(HttpDestinationConfig),
    S3(S3DestinationConfig),
}

#[derive(Clone, Debug)]
pub struct HttpDestinationConfig {
    pub endpoint: String,
    pub bearer_token: String,
    pub ca_file: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct S3DestinationConfig {
    pub bucket: String,
    pub prefix: String,
    /// Optional S3-compatible endpoint used only for local integration tests.
    pub endpoint_url: Option<String>,
    pub force_path_style: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityMappingDocument {
    schema_version: u16,
    mappings: Vec<IdentityMappingEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityMappingEntry {
    mongodb_principal_hash: String,
    provider: String,
    principal_type: String,
    principal_arn: String,
    account_id: String,
    credential_source: String,
    credential_resource: String,
}

#[derive(Clone)]
pub struct AppState {
    config: Arc<OutpostConfig>,
    spool: DurableSpool,
    metrics: Arc<Metrics>,
    notify: Arc<Notify>,
    kubernetes: Arc<RwLock<HashMap<String, KubernetesMetadata>>>,
}

struct Metrics {
    registry: Registry,
    accepted_batches: IntCounter,
    rejected_batches: IntCounter,
    delivered_batches: IntCounter,
    delivery_failures: IntCounter,
    quarantined_batches: IntCounter,
    spool_items: IntGauge,
    spool_bytes: IntGauge,
    quarantine_items: IntGauge,
    quarantine_bytes: IntGauge,
    kubernetes_cache_entries: IntGauge,
}

impl Metrics {
    fn new() -> Result<Self> {
        let registry = Registry::new();
        let accepted_batches = IntCounter::new(
            "mongodb_dam_outpost_accepted_batches_total",
            "Observer batches durably accepted by Outpost",
        )?;
        let rejected_batches = IntCounter::new(
            "mongodb_dam_outpost_rejected_batches_total",
            "Observer batches rejected before spooling",
        )?;
        let delivered_batches = IntCounter::new(
            "mongodb_dam_outpost_delivered_batches_total",
            "Batches successfully delivered to the configured destination",
        )?;
        let delivery_failures = IntCounter::new(
            "mongodb_dam_outpost_delivery_failures_total",
            "Destination delivery attempts that failed",
        )?;
        let quarantined_batches = IntCounter::new(
            "mongodb_dam_outpost_quarantined_batches_total",
            "Permanently rejected HTTP batches retained in the spool",
        )?;
        let spool_items = IntGauge::new(
            "mongodb_dam_outpost_spool_items",
            "Metadata batches awaiting destination delivery",
        )?;
        let spool_bytes = IntGauge::new(
            "mongodb_dam_outpost_spool_bytes",
            "Metadata bytes awaiting regional delivery",
        )?;
        let quarantine_items = IntGauge::new(
            "mongodb_dam_outpost_quarantine_items",
            "Permanently rejected metadata batches retained for review",
        )?;
        let quarantine_bytes = IntGauge::new(
            "mongodb_dam_outpost_quarantine_bytes",
            "Permanently rejected metadata bytes retained for review",
        )?;
        let kubernetes_cache_entries = IntGauge::new(
            "mongodb_dam_outpost_kubernetes_cache_entries",
            "Pods available for event enrichment",
        )?;
        for collector in [
            Box::new(accepted_batches.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(rejected_batches.clone()),
            Box::new(delivered_batches.clone()),
            Box::new(delivery_failures.clone()),
            Box::new(quarantined_batches.clone()),
            Box::new(spool_items.clone()),
            Box::new(spool_bytes.clone()),
            Box::new(quarantine_items.clone()),
            Box::new(quarantine_bytes.clone()),
            Box::new(kubernetes_cache_entries.clone()),
        ] {
            registry.register(collector)?;
        }
        Ok(Self {
            registry,
            accepted_batches,
            rejected_batches,
            delivered_batches,
            delivery_failures,
            quarantined_batches,
            spool_items,
            spool_bytes,
            quarantine_items,
            quarantine_bytes,
            kubernetes_cache_entries,
        })
    }
}

#[derive(Serialize)]
struct HealthResponse<'a> {
    service: &'a str,
    status: &'a str,
    regional_cell_id: &'a str,
    spool_items: u64,
    spool_bytes: u64,
    quarantine_items: u64,
    quarantine_bytes: u64,
}

#[derive(Serialize)]
struct AcceptedResponse {
    status: &'static str,
    batch_id: String,
    receipt_id: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub fn build_state(config: OutpostConfig) -> Result<AppState> {
    validate_config(&config)?;
    let spool = DurableSpool::open(&config.spool_dir, config.spool_max_bytes)?;
    let state = AppState {
        config: Arc::new(config),
        spool,
        metrics: Arc::new(Metrics::new()?),
        notify: Arc::new(Notify::new()),
        kubernetes: Arc::new(RwLock::new(HashMap::new())),
    };
    refresh_spool_metrics(&state);
    Ok(state)
}

fn validate_config(config: &OutpostConfig) -> Result<()> {
    for (name, value) in [
        ("customer_id", config.customer_id.as_str()),
        ("tenant_id", config.tenant_id.as_str()),
        ("source_id", config.source_id.as_str()),
        ("regional_cell_id", config.regional_cell_id.as_str()),
        ("cluster_name", config.cluster_name.as_str()),
    ] {
        anyhow::ensure!(!value.trim().is_empty(), "{name} must not be empty");
    }
    match &config.destination {
        DestinationConfig::Http(destination) => validate_http_destination(destination)?,
        DestinationConfig::S3(destination) => validate_s3_destination(destination)?,
    }
    anyhow::ensure!(
        config.max_request_bytes > 0,
        "max_request_bytes must be positive"
    );
    Ok(())
}

fn validate_http_destination(destination: &HttpDestinationConfig) -> Result<()> {
    anyhow::ensure!(
        !destination.endpoint.trim().is_empty(),
        "HTTP endpoint must not be empty"
    );
    anyhow::ensure!(
        !destination.bearer_token.trim().is_empty(),
        "HTTP bearer token must not be empty"
    );
    let endpoint = Url::parse(&destination.endpoint).context("HTTP endpoint is invalid")?;
    let is_local_mock = endpoint.scheme() == "http"
        && matches!(
            endpoint.host_str(),
            Some("127.0.0.1" | "localhost" | "mock-endpoint")
        );
    anyhow::ensure!(
        endpoint.scheme() == "https" || is_local_mock,
        "HTTP endpoint must use HTTPS except for the bundled local mock"
    );
    anyhow::ensure!(
        endpoint.username().is_empty() && endpoint.password().is_none(),
        "HTTP endpoint must not contain credentials"
    );
    Ok(())
}

fn validate_s3_destination(destination: &S3DestinationConfig) -> Result<()> {
    let bucket = destination.bucket.trim();
    let prefix = normalized_s3_prefix(&destination.prefix);
    anyhow::ensure!(!bucket.is_empty(), "S3 bucket must not be empty");
    anyhow::ensure!(
        bucket == destination.bucket,
        "S3 bucket must not have leading or trailing whitespace"
    );
    anyhow::ensure!(
        !bucket.chars().any(char::is_control),
        "S3 bucket must not contain control characters"
    );
    anyhow::ensure!(!prefix.is_empty(), "S3 prefix must not be empty");
    anyhow::ensure!(
        !prefix.chars().any(char::is_control),
        "S3 prefix must not contain control characters"
    );
    if let Some(value) = destination.endpoint_url.as_deref() {
        let endpoint = Url::parse(value).context("S3 endpoint URL is invalid")?;
        let is_local = endpoint.scheme() == "http"
            && matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost"));
        anyhow::ensure!(
            endpoint.scheme() == "https" || is_local,
            "S3 endpoint URL must use HTTPS except for localhost"
        );
        anyhow::ensure!(
            endpoint.username().is_empty() && endpoint.password().is_none(),
            "S3 endpoint URL must not contain credentials"
        );
    }
    Ok(())
}

pub fn router(state: AppState) -> Router {
    let limit = state.config.max_request_bytes;
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/observer/batches", post(accept_batch))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Response {
    match (state.spool.stats(), state.spool.quarantine_stats()) {
        (Ok(stats), Ok(quarantine)) => Json(HealthResponse {
            service: "mongodb-dam-outpost",
            status: "ok",
            regional_cell_id: &state.config.regional_cell_id,
            spool_items: stats.items,
            spool_bytes: stats.bytes,
            quarantine_items: quarantine.items,
            quarantine_bytes: quarantine.bytes,
        })
        .into_response(),
        (Err(error), _) | (_, Err(error)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn metrics(State(state): State<AppState>) -> Response {
    refresh_spool_metrics(&state);
    let families = state.metrics.registry.gather();
    let mut encoded = Vec::new();
    match TextEncoder::new().encode(&families, &mut encoded) {
        Ok(()) => (
            [("content-type", TextEncoder::new().format_type().to_string())],
            encoded,
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn accept_batch(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Some(expected) = &state.config.internal_token {
        let provided = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        if provided != Some(expected.as_str()) {
            state.metrics.rejected_batches.inc();
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "missing or invalid Observer credential".into(),
                }),
            )
                .into_response();
        }
    }

    let mut batch: DamBatch = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(error) => {
            state.metrics.rejected_batches.inc();
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid DAM batch: {error}"),
                }),
            )
                .into_response();
        }
    };
    if let Err(error) = batch.validate() {
        state.metrics.rejected_batches.inc();
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: error.into(),
            }),
        )
            .into_response();
    }
    if batch.customer_id != state.config.customer_id
        || batch.tenant_id != state.config.tenant_id
        || batch.source_id != state.config.source_id
        || batch.regional_cell_id != state.config.regional_cell_id
    {
        state.metrics.rejected_batches.inc();
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "batch identity does not match this Outpost assignment".into(),
            }),
        )
            .into_response();
    }

    enrich_batch(&state, &mut batch).await;
    let encoded = match serde_json::to_vec(&batch) {
        Ok(encoded) => encoded,
        Err(error) => {
            state.metrics.rejected_batches.inc();
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    };
    let receipt_id = match state.spool.enqueue(&encoded) {
        Ok(receipt) => receipt,
        Err(error) => {
            state.metrics.rejected_batches.inc();
            refresh_spool_metrics(&state);
            return (
                StatusCode::INSUFFICIENT_STORAGE,
                Json(ErrorResponse {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    };
    state.metrics.accepted_batches.inc();
    refresh_spool_metrics(&state);
    state.notify.notify_one();
    (
        StatusCode::ACCEPTED,
        Json(AcceptedResponse {
            status: "accepted",
            batch_id: batch.batch_id,
            receipt_id,
        }),
    )
        .into_response()
}

async fn enrich_batch(state: &AppState, batch: &mut DamBatch) {
    let identities = match state.config.identity_mapping_file.as_deref() {
        Some(path) => match load_identity_mappings(path) {
            Ok(identities) => identities,
            Err(error) => {
                warn!(error = ?error, path = %path.display(), "failed to load external identity mapping; forwarding activity without external identity");
                HashMap::new()
            }
        },
        None => HashMap::new(),
    };
    enrich_external_identities(batch, &identities);

    let cache = state.kubernetes.read().await;
    for event in &mut batch.events {
        let existing = event.kubernetes.get_or_insert_with(Default::default);
        if existing.cluster_name.is_none() {
            existing.cluster_name = Some(state.config.cluster_name.clone());
        }
        let Some(uid) = existing.pod_uid.as_deref() else {
            continue;
        };
        if let Some(enriched) = cache.get(uid) {
            let pod_uid = existing.pod_uid.clone();
            let container_name = existing.container_name.clone();
            *existing = enriched.clone();
            existing.pod_uid = pod_uid;
            if container_name.is_some() {
                existing.container_name = container_name;
            }
        }
    }
}

fn load_identity_mappings(path: &Path) -> Result<HashMap<String, ExternalIdentity>> {
    let encoded = match fs::read(path) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("reading identity mapping {}", path.display()))
        }
    };
    parse_identity_mappings(&encoded)
        .with_context(|| format!("parsing identity mapping {}", path.display()))
}

fn parse_identity_mappings(encoded: &[u8]) -> Result<HashMap<String, ExternalIdentity>> {
    let document: IdentityMappingDocument = serde_json::from_slice(encoded)?;
    anyhow::ensure!(
        document.schema_version == 1,
        "unsupported identity mapping schema_version"
    );
    anyhow::ensure!(
        document.mappings.len() <= 1_000,
        "identity mapping exceeds 1000 entries"
    );

    let mut identities = HashMap::new();
    for mapping in document.mappings {
        validate_identity_mapping(&mapping)?;
        let identity = ExternalIdentity {
            provider: mapping.provider,
            principal_type: mapping.principal_type,
            principal_arn: mapping.principal_arn,
            account_id: mapping.account_id,
            credential_source: mapping.credential_source,
            credential_resource: mapping.credential_resource,
        };
        anyhow::ensure!(
            identities
                .insert(mapping.mongodb_principal_hash, identity)
                .is_none(),
            "identity mapping contains a duplicate MongoDB principal hash"
        );
    }
    Ok(identities)
}

fn validate_identity_mapping(mapping: &IdentityMappingEntry) -> Result<()> {
    anyhow::ensure!(
        mapping.mongodb_principal_hash.starts_with("sha256:")
            && mapping.mongodb_principal_hash.len() == 71
            && mapping.mongodb_principal_hash[7..]
                .bytes()
                .all(|value| value.is_ascii_hexdigit()),
        "MongoDB principal hash must be sha256 followed by 64 hexadecimal characters"
    );
    anyhow::ensure!(mapping.provider == "aws", "identity provider must be aws");
    anyhow::ensure!(
        matches!(mapping.principal_type.as_str(), "iam_user" | "iam_role"),
        "principal_type must be iam_user or iam_role"
    );
    anyhow::ensure!(
        mapping.account_id.len() == 12
            && mapping
                .account_id
                .bytes()
                .all(|value| value.is_ascii_digit()),
        "AWS account_id must contain 12 digits"
    );
    anyhow::ensure!(
        valid_iam_principal_arn(
            &mapping.principal_arn,
            &mapping.account_id,
            &mapping.principal_type
        ),
        "principal_arn does not match account_id and principal_type"
    );
    anyhow::ensure!(
        mapping.credential_source == "aws_secrets_manager",
        "credential_source must be aws_secrets_manager"
    );
    anyhow::ensure!(
        valid_secrets_manager_arn(&mapping.credential_resource, &mapping.account_id),
        "credential_resource must be a Secrets Manager ARN in account_id"
    );
    Ok(())
}

fn valid_iam_principal_arn(value: &str, account_id: &str, principal_type: &str) -> bool {
    let parts: Vec<_> = value.splitn(6, ':').collect();
    let expected_resource = if principal_type == "iam_user" {
        "user/"
    } else {
        "role/"
    };
    parts.len() == 6
        && parts[0] == "arn"
        && !parts[1].is_empty()
        && parts[2] == "iam"
        && parts[3].is_empty()
        && parts[4] == account_id
        && parts[5].starts_with(expected_resource)
        && parts[5].len() > expected_resource.len()
}

fn valid_secrets_manager_arn(value: &str, account_id: &str) -> bool {
    let parts: Vec<_> = value.splitn(6, ':').collect();
    parts.len() == 6
        && parts[0] == "arn"
        && !parts[1].is_empty()
        && parts[2] == "secretsmanager"
        && !parts[3].is_empty()
        && parts[4] == account_id
        && parts[5].starts_with("secret:")
        && parts[5].len() > "secret:".len()
}

fn enrich_external_identities(
    batch: &mut DamBatch,
    identities: &HashMap<String, ExternalIdentity>,
) {
    for event in &mut batch.events {
        let principal = match &event.payload {
            EventPayload::MongodbActivity(activity) if activity.principal_hashed => {
                activity.principal.as_deref()
            }
            EventPayload::MongodbAuth(auth) if auth.principal_hashed => auth.principal.as_deref(),
            _ => None,
        };
        event.identity = principal.and_then(|value| identities.get(value)).cloned();
    }
}

fn refresh_spool_metrics(state: &AppState) {
    if let Ok(stats) = state.spool.stats() {
        state.metrics.spool_items.set(stats.items as i64);
        state.metrics.spool_bytes.set(stats.bytes as i64);
    }
    if let Ok(stats) = state.spool.quarantine_stats() {
        state.metrics.quarantine_items.set(stats.items as i64);
        state.metrics.quarantine_bytes.set(stats.bytes as i64);
    }
}

pub fn spawn_background_tasks(state: AppState) {
    tokio::spawn(run_exporter(state.clone()));
    if state.config.kubernetes_api_url.is_some() {
        tokio::spawn(run_kubernetes_cache(state));
    }
}

async fn run_exporter(state: AppState) {
    let client = match destination_client(&state.config).await {
        Ok(client) => client,
        Err(error) => {
            error!(error = ?error, "failed to build destination client");
            return;
        }
    };

    loop {
        if let Err(error) = deliver_pending(&state, &client).await {
            state.metrics.delivery_failures.inc();
            warn!(error = ?error, "destination batch delivery pass failed");
        }
        refresh_spool_metrics(&state);
        tokio::select! {
            _ = state.notify.notified() => {}
            _ = tokio::time::sleep(state.config.export_interval) => {}
        }
    }
}

enum DestinationClient {
    Http(Client),
    S3(S3Client),
}

async fn destination_client(config: &OutpostConfig) -> Result<DestinationClient> {
    match &config.destination {
        DestinationConfig::Http(destination) => {
            Ok(DestinationClient::Http(regional_client(destination)?))
        }
        DestinationConfig::S3(destination) => {
            let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .load()
                .await;
            let mut builder = aws_sdk_s3::config::Builder::from(&shared_config);
            if let Some(endpoint_url) = destination.endpoint_url.as_deref() {
                builder = builder.endpoint_url(endpoint_url);
            }
            if destination.force_path_style {
                builder = builder.force_path_style(true);
            }
            Ok(DestinationClient::S3(S3Client::from_conf(builder.build())))
        }
    }
}

fn regional_client(destination: &HttpDestinationConfig) -> Result<Client> {
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        // Never forward the source bearer credential to a redirected origin.
        .redirect(Policy::none());
    if let Some(path) = &destination.ca_file {
        let pem =
            fs::read(path).with_context(|| format!("reading destination CA {}", path.display()))?;
        builder = builder
            .add_root_certificate(Certificate::from_pem(&pem).context("parsing destination CA")?);
    }
    builder.build().context("building regional HTTP client")
}

async fn deliver_pending(state: &AppState, client: &DestinationClient) -> Result<()> {
    for item in state.spool.pending()? {
        let body = state.spool.read(&item)?;
        let batch: DamBatch = serde_json::from_slice(&body)
            .with_context(|| format!("spooled batch {} is invalid", item.id))?;
        let delivered = match (&state.config.destination, client) {
            (DestinationConfig::Http(destination), DestinationClient::Http(client)) => {
                if deliver_http_batch(client, destination, &batch, body).await? {
                    state.spool.acknowledge(&item)?;
                    true
                } else {
                    state.spool.quarantine(&item)?;
                    state.metrics.quarantined_batches.inc();
                    false
                }
            }
            (DestinationConfig::S3(destination), DestinationClient::S3(client)) => {
                deliver_s3_batch(client, destination, &batch).await?;
                state.spool.acknowledge(&item)?;
                true
            }
            _ => anyhow::bail!("destination configuration and client do not match"),
        };
        if delivered {
            state.metrics.delivered_batches.inc();
        }
    }
    Ok(())
}

/// Returns true when the spool item can be acknowledged and false when a
/// permanent response requires quarantine.
async fn deliver_http_batch(
    client: &Client,
    destination: &HttpDestinationConfig,
    batch: &DamBatch,
    body: Vec<u8>,
) -> Result<bool> {
    let response = client
        .post(&destination.endpoint)
        .header("content-type", "application/json")
        .bearer_auth(&destination.bearer_token)
        .header("idempotency-key", &batch.batch_id)
        .body(body)
        .send()
        .await
        .with_context(|| format!("delivery request for batch {} failed", batch.batch_id))?;

    let status = response.status();
    if status.is_success() || status == reqwest::StatusCode::CONFLICT {
        info!(batch_id = %batch.batch_id, status = %status, "regional receiver acknowledged DAM batch");
        return Ok(true);
    }
    if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
        warn!(batch_id = %batch.batch_id, status = %status, "regional receiver permanently rejected DAM batch; retaining it for operator review");
        return Ok(false);
    }
    anyhow::bail!("regional receiver returned retryable HTTP {status}")
}

async fn deliver_s3_batch(
    client: &S3Client,
    destination: &S3DestinationConfig,
    batch: &DamBatch,
) -> Result<()> {
    let key = s3_object_key(destination, batch);
    let body = encode_s3_ndjson(batch)?;
    client
        .put_object()
        .bucket(&destination.bucket)
        .key(&key)
        .content_type("application/x-ndjson")
        .content_encoding("gzip")
        .body(ByteStream::from(body))
        .send()
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "S3 PutObject failed for batch {} at s3://{}/{}: {error}",
                batch.batch_id,
                destination.bucket,
                key
            )
        })?;
    info!(
        batch_id = %batch.batch_id,
        bucket = %destination.bucket,
        key = %key,
        "uploaded compressed DAM NDJSON batch"
    );
    Ok(())
}

#[derive(Serialize)]
struct S3NdjsonRecord<'a> {
    batch_schema_version: u16,
    batch_id: &'a str,
    #[serde(with = "time::serde::rfc3339")]
    batch_created_at: time::OffsetDateTime,
    #[serde(flatten)]
    event: &'a dam_schema::DamEvent,
}

fn encode_s3_ndjson(batch: &DamBatch) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    for event in &batch.events {
        let record = S3NdjsonRecord {
            batch_schema_version: batch.schema_version,
            batch_id: &batch.batch_id,
            batch_created_at: batch.created_at,
            event,
        };
        serde_json::to_writer(&mut encoder, &record).context("serializing S3 NDJSON record")?;
        encoder
            .write_all(b"\n")
            .context("writing S3 NDJSON delimiter")?;
    }
    encoder.finish().context("finishing S3 gzip payload")
}

fn s3_object_key(destination: &S3DestinationConfig, batch: &DamBatch) -> String {
    let timestamp = batch.created_at;
    format!(
        "{}/customer_id={}/tenant_id={}/regional_cell_id={}/source_id={}/date={:04}-{:02}-{:02}/hour={:02}/{}.ndjson.gz",
        normalized_s3_prefix(&destination.prefix),
        encode_s3_key_segment(&batch.customer_id),
        encode_s3_key_segment(&batch.tenant_id),
        encode_s3_key_segment(&batch.regional_cell_id),
        encode_s3_key_segment(&batch.source_id),
        timestamp.year(),
        u8::from(timestamp.month()),
        timestamp.day(),
        timestamp.hour(),
        encode_s3_key_segment(&batch.batch_id),
    )
}

fn normalized_s3_prefix(prefix: &str) -> &str {
    prefix.trim().trim_matches('/')
}

fn encode_s3_key_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

#[derive(Deserialize)]
struct PodList {
    items: Vec<Pod>,
}

#[derive(Deserialize)]
struct Pod {
    metadata: PodMetadata,
}

#[derive(Deserialize)]
struct PodMetadata {
    uid: Option<String>,
    name: Option<String>,
    namespace: Option<String>,
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "ownerReferences")]
    owner_references: Option<Vec<OwnerReference>>,
}

#[derive(Deserialize)]
struct OwnerReference {
    kind: String,
    name: String,
    #[serde(default)]
    controller: bool,
}

async fn run_kubernetes_cache(state: AppState) {
    let client = match kubernetes_client(&state.config) {
        Ok(client) => client,
        Err(error) => {
            error!(error = ?error, "Kubernetes enrichment is disabled");
            return;
        }
    };
    loop {
        if let Err(error) = refresh_kubernetes_cache(&state, &client).await {
            warn!(error = ?error, "failed to refresh Kubernetes pod metadata");
        }
        tokio::time::sleep(state.config.kubernetes_refresh_interval).await;
    }
}

fn kubernetes_client(config: &OutpostConfig) -> Result<Client> {
    let ca = fs::read(&config.kubernetes_ca_path)
        .with_context(|| format!("reading {}", config.kubernetes_ca_path.display()))?;
    let certificate = Certificate::from_pem(&ca).context("parsing Kubernetes service CA")?;
    Client::builder()
        .add_root_certificate(certificate)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
        .context("building Kubernetes API client")
}

async fn refresh_kubernetes_cache(state: &AppState, client: &Client) -> Result<()> {
    let api_url = state
        .config
        .kubernetes_api_url
        .as_deref()
        .context("Kubernetes API URL missing")?;
    let token = read_secret(&state.config.kubernetes_token_path)?;
    let response = client
        .get(format!("{}/api/v1/pods", api_url.trim_end_matches('/')))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json::<PodList>()
        .await?;
    let mut next = HashMap::new();
    for pod in response.items {
        let Some(uid) = pod.metadata.uid else {
            continue;
        };
        let owner = pod
            .metadata
            .owner_references
            .unwrap_or_default()
            .into_iter()
            .find(|owner| owner.controller);
        next.insert(
            uid,
            KubernetesMetadata {
                cluster_name: Some(state.config.cluster_name.clone()),
                namespace: pod.metadata.namespace,
                pod_name: pod.metadata.name,
                pod_uid: None,
                container_name: None,
                workload_kind: owner.as_ref().map(|value| value.kind.clone()),
                workload_name: owner.map(|value| value.name),
                labels: pod.metadata.labels,
            },
        );
    }
    state
        .metrics
        .kubernetes_cache_entries
        .set(next.len() as i64);
    *state.kubernetes.write().await = next;
    Ok(())
}

pub fn read_secret(path: &Path) -> Result<String> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("reading secret file {}", path.display()))?;
    let value = value.trim().to_string();
    anyhow::ensure!(!value.is_empty(), "secret file {} is empty", path.display());
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(destination: DestinationConfig) -> OutpostConfig {
        OutpostConfig {
            customer_id: "customer".into(),
            tenant_id: "tenant".into(),
            source_id: "source".into(),
            regional_cell_id: "cell".into(),
            cluster_name: "cluster".into(),
            internal_token: None,
            destination,
            spool_dir: PathBuf::from("/tmp/not-used"),
            spool_max_bytes: 1024,
            max_request_bytes: 1024,
            export_interval: Duration::from_secs(1),
            kubernetes_api_url: None,
            kubernetes_token_path: PathBuf::new(),
            kubernetes_ca_path: PathBuf::new(),
            kubernetes_refresh_interval: Duration::from_secs(60),
            identity_mapping_file: None,
        }
    }

    #[test]
    fn rejects_non_tls_remote_endpoint() {
        let config = test_config(DestinationConfig::Http(HttpDestinationConfig {
            endpoint: "http://remote.example/ingest".into(),
            bearer_token: "token".into(),
            ca_file: None,
        }));
        assert!(validate_config(&config).is_err());

        let mut prefixed_mock = config;
        let DestinationConfig::Http(destination) = &mut prefixed_mock.destination else {
            unreachable!();
        };
        destination.endpoint = "http://mock-endpoint.attacker.example/v1/ingest/mongodb-dam".into();
        assert!(validate_config(&prefixed_mock).is_err());
    }

    #[test]
    fn validates_s3_destination() {
        let config = test_config(DestinationConfig::S3(S3DestinationConfig {
            bucket: "dam-demo-events".into(),
            prefix: "/mongodb-dam/events/".into(),
            endpoint_url: None,
            force_path_style: false,
        }));
        assert!(validate_config(&config).is_ok());

        let invalid = test_config(DestinationConfig::S3(S3DestinationConfig {
            bucket: "dam-demo-events".into(),
            prefix: "///".into(),
            endpoint_url: None,
            force_path_style: false,
        }));
        assert!(validate_config(&invalid).is_err());
    }

    #[test]
    fn creates_deterministic_partitioned_s3_key() {
        let batch: DamBatch =
            serde_json::from_slice(include_bytes!("../../../tests/fixtures/dam-batch.json"))
                .unwrap();
        let destination = S3DestinationConfig {
            bucket: "dam-demo-events".into(),
            prefix: "/mongodb-dam/events/".into(),
            endpoint_url: None,
            force_path_style: false,
        };
        assert_eq!(
            s3_object_key(&destination, &batch),
            "mongodb-dam/events/customer_id=integration-customer/tenant_id=integration-tenant/regional_cell_id=integration-cell/source_id=integration-source/date=2026-01-01/hour=00/integration-batch-0001.ndjson.gz"
        );
    }

    #[test]
    fn encodes_one_self_contained_json_record_per_event() {
        use std::io::Read;

        let batch: DamBatch =
            serde_json::from_slice(include_bytes!("../../../tests/fixtures/dam-batch.json"))
                .unwrap();
        let compressed = encode_s3_ndjson(&batch).unwrap();
        assert_eq!(&compressed[0..2], &[0x1f, 0x8b]);
        assert_eq!(compressed, encode_s3_ndjson(&batch).unwrap());

        let mut decoded = String::new();
        flate2::read::GzDecoder::new(compressed.as_slice())
            .read_to_string(&mut decoded)
            .unwrap();
        let records: Vec<serde_json::Value> = decoded
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), batch.events.len());
        assert_eq!(records[0]["batch_schema_version"], 1);
        assert_eq!(records[0]["batch_id"], "integration-batch-0001");
        assert_eq!(records[0]["batch_created_at"], "2026-01-01T00:00:00Z");
        assert_eq!(records[0]["event_type"], "sensor_health");
        assert_eq!(records[1]["event_type"], "mongodb_activity");
        assert_eq!(records[1]["details"]["command"], "delete");
    }

    #[test]
    fn documented_s3_examples_match_the_event_schema() {
        let markdown = include_str!("../../../docs/S3_NDJSON_EXAMPLES.md");
        let examples: Vec<_> = markdown
            .split("```json\n")
            .skip(1)
            .map(|remainder| remainder.split("\n```").next().unwrap())
            .collect();
        assert_eq!(examples.len(), 8);

        for example in examples {
            let mut value: serde_json::Value = serde_json::from_str(example).unwrap();
            let object = value.as_object_mut().unwrap();
            assert_eq!(object.remove("batch_schema_version").unwrap(), 1);
            assert!(object.remove("batch_id").unwrap().is_string());
            assert!(object.remove("batch_created_at").unwrap().is_string());
            let event: dam_schema::DamEvent = serde_json::from_value(value).unwrap();
            assert!(event.capture.metadata_only);
        }
    }

    #[tokio::test]
    async fn uploads_batch_to_the_deterministic_s3_object() {
        use axum::{http::Uri, routing::put};
        use std::sync::Mutex;

        let captured = Arc::new(Mutex::new(None));
        let capture = captured.clone();
        let app = Router::new().route(
            "/*key",
            put(move |uri: Uri, headers: HeaderMap, body: Bytes| {
                let capture = capture.clone();
                async move {
                    *capture.lock().unwrap() = Some((uri, headers, body));
                    StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = aws_sdk_s3::Config::builder()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test-access-key",
                "test-secret-key",
                None,
                None,
                "outpost-test",
            ))
            .endpoint_url(format!("http://{address}"))
            .force_path_style(true)
            .build();
        let client = S3Client::from_conf(config);
        let destination = S3DestinationConfig {
            bucket: "dam-demo-events".into(),
            prefix: "mongodb-dam/events".into(),
            endpoint_url: Some(format!("http://{address}")),
            force_path_style: true,
        };
        let batch: DamBatch =
            serde_json::from_slice(include_bytes!("../../../tests/fixtures/dam-batch.json"))
                .unwrap();

        deliver_s3_batch(&client, &destination, &batch)
            .await
            .unwrap();
        server.abort();

        let captured = captured.lock().unwrap();
        let (uri, headers, body) = captured.as_ref().expect("mock S3 did not receive a PUT");
        assert_eq!(
            uri.path(),
            "/dam-demo-events/mongodb-dam/events/customer_id%3Dintegration-customer/tenant_id%3Dintegration-tenant/regional_cell_id%3Dintegration-cell/source_id%3Dintegration-source/date%3D2026-01-01/hour%3D00/integration-batch-0001.ndjson.gz"
        );
        assert_eq!(headers.get("content-type").unwrap(), "application/x-ndjson");
        assert!(headers
            .get("content-encoding")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("gzip"));
        assert!(!body.is_empty());
    }

    #[test]
    fn validates_and_parses_identity_mapping() {
        let encoded = br#"{
          "schema_version": 1,
          "mappings": [{
            "mongodb_principal_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "provider": "aws",
            "principal_type": "iam_user",
            "principal_arn": "arn:aws:iam::111122223333:user/dam-demo-alice",
            "account_id": "111122223333",
            "credential_source": "aws_secrets_manager",
            "credential_resource": "arn:aws:secretsmanager:ap-south-1:111122223333:secret:mongodb-dam-demo-AbCdEf"
          }]
        }"#;
        let identities = parse_identity_mappings(encoded).unwrap();
        let identity = identities
            .get("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        assert_eq!(identity.provider, "aws");
        assert_eq!(identity.principal_type, "iam_user");
        assert_eq!(
            identity.principal_arn,
            "arn:aws:iam::111122223333:user/dam-demo-alice"
        );
    }

    #[test]
    fn rejects_identity_mapping_with_mismatched_account() {
        let encoded = br#"{
          "schema_version": 1,
          "mappings": [{
            "mongodb_principal_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "provider": "aws",
            "principal_type": "iam_user",
            "principal_arn": "arn:aws:iam::999900001111:user/dam-demo-alice",
            "account_id": "111122223333",
            "credential_source": "aws_secrets_manager",
            "credential_resource": "arn:aws:secretsmanager:ap-south-1:111122223333:secret:mongodb-dam-demo-AbCdEf"
          }]
        }"#;
        assert!(parse_identity_mappings(encoded).is_err());
    }
}
