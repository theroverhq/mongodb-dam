use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dam_schema::{DamBatch, KubernetesMetadata};
use dam_spool::DurableSpool;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use reqwest::{Certificate, Client, Url};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
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
    pub collect_url: String,
    pub collect_token: String,
    pub collect_ca_file: Option<PathBuf>,
    pub collect_token_header: String,
    pub idempotency_header: String,
    pub spool_dir: PathBuf,
    pub spool_max_bytes: u64,
    pub max_request_bytes: usize,
    pub export_interval: Duration,
    pub kubernetes_api_url: Option<String>,
    pub kubernetes_token_path: PathBuf,
    pub kubernetes_ca_path: PathBuf,
    pub kubernetes_refresh_interval: Duration,
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
            "Batches acknowledged by the regional receiver",
        )?;
        let delivery_failures = IntCounter::new(
            "mongodb_dam_outpost_delivery_failures_total",
            "Regional delivery attempts that failed",
        )?;
        let quarantined_batches = IntCounter::new(
            "mongodb_dam_outpost_quarantined_batches_total",
            "Permanently rejected batches retained in the spool",
        )?;
        let spool_items = IntGauge::new(
            "mongodb_dam_outpost_spool_items",
            "Metadata batches awaiting regional delivery",
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
        ("collect_url", config.collect_url.as_str()),
        ("collect_token", config.collect_token.as_str()),
    ] {
        anyhow::ensure!(!value.trim().is_empty(), "{name} must not be empty");
    }
    let collect_url = Url::parse(&config.collect_url).context("collect_url is invalid")?;
    let is_local_mock = collect_url.scheme() == "http"
        && matches!(
            collect_url.host_str(),
            Some("127.0.0.1" | "localhost" | "mock-collect")
        );
    anyhow::ensure!(
        collect_url.scheme() == "https" || is_local_mock,
        "collect_url must use HTTPS except for the bundled local mock"
    );
    anyhow::ensure!(
        collect_url.username().is_empty() && collect_url.password().is_none(),
        "collect_url must not contain credentials"
    );
    anyhow::ensure!(
        config.max_request_bytes > 0,
        "max_request_bytes must be positive"
    );
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
    let client = match regional_client(&state.config) {
        Ok(client) => client,
        Err(error) => {
            error!(error = ?error, "failed to build regional HTTP client");
            return;
        }
    };

    loop {
        if let Err(error) = deliver_pending(&state, &client).await {
            state.metrics.delivery_failures.inc();
            warn!(error = ?error, "regional batch delivery pass failed");
        }
        refresh_spool_metrics(&state);
        tokio::select! {
            _ = state.notify.notified() => {}
            _ = tokio::time::sleep(state.config.export_interval) => {}
        }
    }
}

fn regional_client(config: &OutpostConfig) -> Result<Client> {
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30));
    if let Some(path) = &config.collect_ca_file {
        let pem = fs::read(path)
            .with_context(|| format!("reading regional Collect CA {}", path.display()))?;
        builder = builder.add_root_certificate(
            Certificate::from_pem(&pem).context("parsing regional Collect CA")?,
        );
    }
    builder.build().context("building regional HTTP client")
}

async fn deliver_pending(state: &AppState, client: &Client) -> Result<()> {
    for item in state.spool.pending()? {
        let body = state.spool.read(&item)?;
        let batch: DamBatch = serde_json::from_slice(&body)
            .with_context(|| format!("spooled batch {} is invalid", item.id))?;
        let response = client
            .post(&state.config.collect_url)
            .header("content-type", "application/json")
            .header(
                &state.config.collect_token_header,
                &state.config.collect_token,
            )
            .header(&state.config.idempotency_header, &batch.batch_id)
            .body(body)
            .send()
            .await
            .with_context(|| format!("delivery request for batch {} failed", batch.batch_id))?;

        let status = response.status();
        if status.is_success() || status == reqwest::StatusCode::CONFLICT {
            state.spool.acknowledge(&item)?;
            state.metrics.delivered_batches.inc();
            info!(batch_id = %batch.batch_id, status = %status, "regional receiver acknowledged DAM batch");
            continue;
        }
        if status.is_client_error() && status != reqwest::StatusCode::TOO_MANY_REQUESTS {
            state.spool.quarantine(&item)?;
            state.metrics.quarantined_batches.inc();
            warn!(batch_id = %batch.batch_id, status = %status, "regional receiver permanently rejected DAM batch; retaining it for operator review");
            continue;
        }
        anyhow::bail!("regional receiver returned retryable HTTP {status}");
    }
    Ok(())
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

    #[test]
    fn rejects_non_tls_remote_collect_url() {
        let config = OutpostConfig {
            customer_id: "customer".into(),
            tenant_id: "tenant".into(),
            source_id: "source".into(),
            regional_cell_id: "cell".into(),
            cluster_name: "cluster".into(),
            internal_token: None,
            collect_url: "http://remote.example/ingest".into(),
            collect_token: "token".into(),
            collect_ca_file: None,
            collect_token_header: "x-rover-collect-token".into(),
            idempotency_header: "idempotency-key".into(),
            spool_dir: PathBuf::from("/tmp/not-used"),
            spool_max_bytes: 1024,
            max_request_bytes: 1024,
            export_interval: Duration::from_secs(1),
            kubernetes_api_url: None,
            kubernetes_token_path: PathBuf::new(),
            kubernetes_ca_path: PathBuf::new(),
            kubernetes_refresh_interval: Duration::from_secs(60),
        };
        assert!(validate_config(&config).is_err());

        let mut prefixed_mock = config;
        prefixed_mock.collect_url =
            "http://mock-collect.attacker.example/v1/ingest/mongodb-dam".into();
        assert!(validate_config(&prefixed_mock).is_err());
    }
}
